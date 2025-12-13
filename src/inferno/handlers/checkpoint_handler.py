"""
Checkpoint handling for Inferno.

This module provides handlers for checkpoint management, progress tracking,
and budget monitoring during agent execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from inferno.handlers.base import Event, EventHandler, EventType

logger = structlog.get_logger(__name__)


@dataclass
class Checkpoint:
    """A checkpoint in the assessment execution."""

    id: str
    percent_complete: float
    timestamp: datetime
    findings_count: int
    tokens_used: int
    turns_completed: int
    summary: str
    recommendations: list[str] = field(default_factory=list)


class CheckpointHandler(EventHandler):
    """
    Handler for checkpoint management and progress tracking.

    Responsibilities:
    - Create and store checkpoints
    - Track progress metrics
    - Monitor budget consumption
    - Provide progress summaries
    """

    def __init__(
        self,
        checkpoint_thresholds: list[int] | None = None,
        warn_at_percent: int = 80,
    ) -> None:
        """
        Initialize the checkpoint handler.

        Args:
            checkpoint_thresholds: Percentages at which to checkpoint.
            warn_at_percent: Percentage at which to emit budget warning.
        """
        self._thresholds = checkpoint_thresholds or [20, 40, 60, 80, 90]
        self._warn_at = warn_at_percent
        self._checkpoints: list[Checkpoint] = []
        self._current_metrics: dict[str, Any] = {}
        self._warnings_issued: set[int] = set()

    @property
    def name(self) -> str:
        return "checkpoint_handler"

    @property
    def handles(self) -> list[EventType]:
        return [
            EventType.CHECKPOINT_REACHED,
            EventType.TURN_COMPLETE,
            EventType.BUDGET_WARNING,
        ]

    async def handle(self, event: Event) -> None:
        """Process checkpoint and progress events."""
        if event.type == EventType.CHECKPOINT_REACHED:
            await self._handle_checkpoint(event)
        elif event.type == EventType.TURN_COMPLETE:
            await self._update_metrics(event)
        elif event.type == EventType.BUDGET_WARNING:
            await self._handle_budget_warning(event)

    async def _handle_checkpoint(self, event: Event) -> None:
        """Create a checkpoint from the event data."""
        checkpoint_id = f"cp_{len(self._checkpoints) + 1}"
        percent = event.data.get("percent", 0)

        checkpoint = Checkpoint(
            id=checkpoint_id,
            percent_complete=percent,
            timestamp=datetime.now(UTC),
            findings_count=event.data.get("findings_count", 0),
            tokens_used=event.data.get("tokens_used", 0),
            turns_completed=event.data.get("turns", 0),
            summary=event.data.get("summary", "Checkpoint created"),
            recommendations=event.data.get("recommendations", []),
        )

        self._checkpoints.append(checkpoint)

        logger.info(
            "checkpoint_created",
            checkpoint_id=checkpoint_id,
            percent=percent,
            findings=checkpoint.findings_count,
        )

    async def _update_metrics(self, event: Event) -> None:
        """Update current metrics from turn completion."""
        self._current_metrics.update({
            "turns": event.data.get("turns", 0),
            "tokens": event.data.get("tokens", 0),
            "findings": event.data.get("findings", 0),
            "last_update": datetime.now(UTC).isoformat(),
        })

        # Check for budget warning
        budget_used = event.data.get("budget_percent", 0)
        if budget_used >= self._warn_at and self._warn_at not in self._warnings_issued:
            self._warnings_issued.add(self._warn_at)
            logger.warning(
                "budget_warning",
                percent_used=budget_used,
                threshold=self._warn_at,
            )

    async def _handle_budget_warning(self, event: Event) -> None:
        """Handle budget warning events."""
        percent = event.data.get("percent", 0)

        logger.warning(
            "budget_warning_received",
            percent=percent,
            message=event.data.get("message", "Budget threshold reached"),
        )

    def get_checkpoints(self) -> list[Checkpoint]:
        """Get all checkpoints."""
        return self._checkpoints.copy()

    def get_latest_checkpoint(self) -> Checkpoint | None:
        """Get the most recent checkpoint."""
        return self._checkpoints[-1] if self._checkpoints else None

    def get_progress_summary(self) -> dict[str, Any]:
        """Get a summary of progress."""
        latest = self.get_latest_checkpoint()

        return {
            "checkpoints_created": len(self._checkpoints),
            "current_metrics": self._current_metrics,
            "latest_checkpoint": {
                "id": latest.id if latest else None,
                "percent": latest.percent_complete if latest else 0,
                "findings": latest.findings_count if latest else 0,
            } if latest else None,
            "warnings_issued": list(self._warnings_issued),
        }

    def should_checkpoint(self, current_percent: float) -> bool:
        """
        Check if a checkpoint should be created.

        Args:
            current_percent: Current progress percentage.

        Returns:
            True if checkpoint should be created.
        """
        for threshold in self._thresholds:
            if current_percent >= threshold:
                # Check if we already have a checkpoint near this threshold
                if not any(
                    abs(cp.percent_complete - threshold) < 5
                    for cp in self._checkpoints
                ):
                    return True
        return False


class ProgressTracker(EventHandler):
    """
    Handler for tracking overall assessment progress.

    Provides real-time progress updates and estimates.
    """

    def __init__(self) -> None:
        """Initialize the progress tracker."""
        self._start_time: datetime | None = None
        self._phases_completed: list[str] = []
        self._current_phase: str | None = None
        self._estimated_completion: float | None = None

    @property
    def name(self) -> str:
        return "progress_tracker"

    @property
    def handles(self) -> list[EventType]:
        return [EventType.TURN_START, EventType.TURN_COMPLETE]

    async def handle(self, event: Event) -> None:
        """Track progress events."""
        if self._start_time is None:
            self._start_time = datetime.now(UTC)

        if event.type == EventType.TURN_START:
            phase = event.data.get("phase")
            if phase and phase != self._current_phase:
                if self._current_phase:
                    self._phases_completed.append(self._current_phase)
                self._current_phase = phase

        elif event.type == EventType.TURN_COMPLETE:
            # Update estimated completion based on progress
            percent = event.data.get("percent_complete", 0)
            if percent > 0 and self._start_time:
                elapsed = (datetime.now(UTC) - self._start_time).total_seconds()
                self._estimated_completion = elapsed / (percent / 100) - elapsed

    def get_progress(self) -> dict[str, Any]:
        """Get current progress information."""
        elapsed = 0.0
        if self._start_time:
            elapsed = (datetime.now(UTC) - self._start_time).total_seconds()

        return {
            "started_at": self._start_time.isoformat() if self._start_time else None,
            "elapsed_seconds": elapsed,
            "current_phase": self._current_phase,
            "phases_completed": self._phases_completed,
            "estimated_remaining_seconds": self._estimated_completion,
        }
