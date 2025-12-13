"""
Checkpoint persistence and recovery for Inferno.

This module provides the ability to save agent state to disk and recover
from checkpoints, enabling:
- Resumption after crashes or interruptions
- Long-running assessments that span sessions
- Debugging and analysis of agent behavior
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CheckpointData:
    """Data stored in a checkpoint."""

    # Identification
    checkpoint_id: str
    operation_id: str
    target: str
    created_at: str

    # Execution state
    turn: int
    total_turns: int
    budget_percent: float

    # Token tracking
    total_input_tokens: int
    total_output_tokens: int
    max_total_tokens: int

    # Conversation state
    messages: list[dict[str, Any]]
    system_prompt: str

    # Findings and context
    findings_count: int
    findings_summary: str | None = None
    confidence: int | None = None

    # Configuration
    model: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    # Metadata
    version: str = "1.0"
    reason: str = "manual"  # "manual", "auto", "error", "budget_warning"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CheckpointData":
        """Create from dictionary."""
        return cls(**data)


class CheckpointManager:
    """
    Manages checkpoint persistence and recovery.

    Features:
    - Automatic checkpointing at configurable intervals
    - Manual checkpoint creation
    - Recovery from latest or specific checkpoint
    - Checkpoint pruning to manage disk space
    """

    def __init__(
        self,
        checkpoint_dir: Path | str | None = None,
        max_checkpoints: int = 10,
        auto_save: bool = True,
    ) -> None:
        """
        Initialize the checkpoint manager.

        Args:
            checkpoint_dir: Directory for checkpoint storage.
            max_checkpoints: Maximum checkpoints to retain per operation.
            auto_save: Enable automatic checkpoint saving.
        """
        if checkpoint_dir is None:
            # Use default from settings or fallback
            try:
                from inferno.config.settings import InfernoSettings
                settings = InfernoSettings()
                checkpoint_dir = settings.output.base_dir / "checkpoints"
            except Exception:
                checkpoint_dir = Path("./outputs/checkpoints")

        self._checkpoint_dir = Path(checkpoint_dir)
        self._max_checkpoints = max_checkpoints
        self._auto_save = auto_save

        # Ensure directory exists
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "checkpoint_manager_initialized",
            dir=str(self._checkpoint_dir),
            max_checkpoints=max_checkpoints,
        )

    def _get_operation_dir(self, operation_id: str) -> Path:
        """Get the checkpoint directory for an operation."""
        return self._checkpoint_dir / operation_id

    def _generate_checkpoint_id(self, turn: int) -> str:
        """Generate a unique checkpoint ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"checkpoint_{turn:04d}_{timestamp}"

    async def save(
        self,
        operation_id: str,
        target: str,
        turn: int,
        total_turns: int,
        messages: list[dict[str, Any]],
        system_prompt: str,
        metrics: dict[str, Any],
        findings_count: int = 0,
        findings_summary: str | None = None,
        confidence: int | None = None,
        model: str = "",
        config: dict[str, Any] | None = None,
        reason: str = "auto",
    ) -> str:
        """
        Save a checkpoint.

        Args:
            operation_id: Unique operation identifier.
            target: Assessment target.
            turn: Current turn number.
            total_turns: Maximum turns configured.
            messages: Conversation history.
            system_prompt: System prompt.
            metrics: Current metrics dictionary.
            findings_count: Number of findings.
            findings_summary: Summary of findings.
            confidence: Confidence level.
            model: Model being used.
            config: Configuration dictionary.
            reason: Reason for checkpoint.

        Returns:
            Checkpoint ID.
        """
        checkpoint_id = self._generate_checkpoint_id(turn)
        operation_dir = self._get_operation_dir(operation_id)
        operation_dir.mkdir(parents=True, exist_ok=True)

        # Calculate budget percent
        total_tokens = metrics.get("total_input_tokens", 0) + metrics.get("total_output_tokens", 0)
        max_tokens = metrics.get("max_total_tokens", 1_000_000)
        budget_percent = (total_tokens / max_tokens * 100) if max_tokens > 0 else 0

        checkpoint = CheckpointData(
            checkpoint_id=checkpoint_id,
            operation_id=operation_id,
            target=target,
            created_at=datetime.now(timezone.utc).isoformat(),
            turn=turn,
            total_turns=total_turns,
            budget_percent=budget_percent,
            total_input_tokens=metrics.get("total_input_tokens", 0),
            total_output_tokens=metrics.get("total_output_tokens", 0),
            max_total_tokens=max_tokens,
            messages=messages,
            system_prompt=system_prompt,
            findings_count=findings_count,
            findings_summary=findings_summary,
            confidence=confidence,
            model=model,
            config=config or {},
            reason=reason,
        )

        # Save checkpoint file
        checkpoint_file = operation_dir / f"{checkpoint_id}.json"
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint.to_dict(), f, indent=2, default=str)

        # Also save a "latest" symlink/copy for easy recovery
        latest_file = operation_dir / "latest.json"
        shutil.copy(checkpoint_file, latest_file)

        logger.info(
            "checkpoint_saved",
            checkpoint_id=checkpoint_id,
            operation_id=operation_id,
            turn=turn,
            reason=reason,
            file=str(checkpoint_file),
        )

        # Prune old checkpoints
        await self._prune_checkpoints(operation_id)

        return checkpoint_id

    async def load(
        self,
        operation_id: str,
        checkpoint_id: str | None = None,
    ) -> CheckpointData | None:
        """
        Load a checkpoint.

        Args:
            operation_id: Operation identifier.
            checkpoint_id: Specific checkpoint ID, or None for latest.

        Returns:
            CheckpointData or None if not found.
        """
        operation_dir = self._get_operation_dir(operation_id)

        if not operation_dir.exists():
            logger.warning("no_checkpoints_found", operation_id=operation_id)
            return None

        # Determine which checkpoint file to load
        if checkpoint_id:
            checkpoint_file = operation_dir / f"{checkpoint_id}.json"
        else:
            checkpoint_file = operation_dir / "latest.json"

        if not checkpoint_file.exists():
            logger.warning(
                "checkpoint_not_found",
                operation_id=operation_id,
                checkpoint_id=checkpoint_id,
            )
            return None

        try:
            with open(checkpoint_file) as f:
                data = json.load(f)

            checkpoint = CheckpointData.from_dict(data)

            logger.info(
                "checkpoint_loaded",
                checkpoint_id=checkpoint.checkpoint_id,
                operation_id=operation_id,
                turn=checkpoint.turn,
            )

            return checkpoint

        except Exception as e:
            logger.error(
                "checkpoint_load_failed",
                operation_id=operation_id,
                error=str(e),
            )
            return None

    async def list_checkpoints(self, operation_id: str) -> list[dict[str, Any]]:
        """
        List all checkpoints for an operation.

        Args:
            operation_id: Operation identifier.

        Returns:
            List of checkpoint metadata.
        """
        operation_dir = self._get_operation_dir(operation_id)

        if not operation_dir.exists():
            return []

        checkpoints = []
        for checkpoint_file in sorted(operation_dir.glob("checkpoint_*.json")):
            try:
                with open(checkpoint_file) as f:
                    data = json.load(f)
                checkpoints.append({
                    "checkpoint_id": data.get("checkpoint_id"),
                    "turn": data.get("turn"),
                    "created_at": data.get("created_at"),
                    "budget_percent": data.get("budget_percent"),
                    "reason": data.get("reason"),
                    "findings_count": data.get("findings_count"),
                })
            except Exception:
                continue

        return checkpoints

    async def delete_checkpoint(
        self,
        operation_id: str,
        checkpoint_id: str,
    ) -> bool:
        """
        Delete a specific checkpoint.

        Args:
            operation_id: Operation identifier.
            checkpoint_id: Checkpoint to delete.

        Returns:
            True if deleted, False otherwise.
        """
        operation_dir = self._get_operation_dir(operation_id)
        checkpoint_file = operation_dir / f"{checkpoint_id}.json"

        if checkpoint_file.exists():
            checkpoint_file.unlink()
            logger.info(
                "checkpoint_deleted",
                operation_id=operation_id,
                checkpoint_id=checkpoint_id,
            )
            return True

        return False

    async def delete_all_checkpoints(self, operation_id: str) -> int:
        """
        Delete all checkpoints for an operation.

        Args:
            operation_id: Operation identifier.

        Returns:
            Number of checkpoints deleted.
        """
        operation_dir = self._get_operation_dir(operation_id)

        if not operation_dir.exists():
            return 0

        count = 0
        for checkpoint_file in operation_dir.glob("*.json"):
            checkpoint_file.unlink()
            count += 1

        # Remove the directory if empty
        try:
            operation_dir.rmdir()
        except OSError:
            pass

        logger.info(
            "all_checkpoints_deleted",
            operation_id=operation_id,
            count=count,
        )

        return count

    async def _prune_checkpoints(self, operation_id: str) -> int:
        """
        Prune old checkpoints to stay within limit.

        Args:
            operation_id: Operation identifier.

        Returns:
            Number of checkpoints pruned.
        """
        operation_dir = self._get_operation_dir(operation_id)

        checkpoint_files = sorted(
            operation_dir.glob("checkpoint_*.json"),
            key=lambda f: f.stat().st_mtime,
        )

        # Keep only the most recent checkpoints
        to_delete = checkpoint_files[:-self._max_checkpoints] if len(checkpoint_files) > self._max_checkpoints else []

        for checkpoint_file in to_delete:
            checkpoint_file.unlink()

        if to_delete:
            logger.debug(
                "checkpoints_pruned",
                operation_id=operation_id,
                count=len(to_delete),
            )

        return len(to_delete)

    def get_latest_operation(self) -> str | None:
        """
        Get the most recently updated operation ID.

        Returns:
            Operation ID or None if no checkpoints exist.
        """
        if not self._checkpoint_dir.exists():
            return None

        latest_time = 0
        latest_op = None

        for op_dir in self._checkpoint_dir.iterdir():
            if op_dir.is_dir():
                latest_file = op_dir / "latest.json"
                if latest_file.exists():
                    mtime = latest_file.stat().st_mtime
                    if mtime > latest_time:
                        latest_time = mtime
                        latest_op = op_dir.name

        return latest_op


class CheckpointRecovery:
    """
    Handles recovery from checkpoints.

    Provides methods to restore agent state from a checkpoint
    and resume execution.
    """

    def __init__(self, checkpoint_manager: CheckpointManager) -> None:
        """
        Initialize checkpoint recovery.

        Args:
            checkpoint_manager: Checkpoint manager instance.
        """
        self._manager = checkpoint_manager

    async def can_resume(self, operation_id: str) -> bool:
        """
        Check if an operation can be resumed.

        Args:
            operation_id: Operation identifier.

        Returns:
            True if resumable checkpoint exists.
        """
        checkpoint = await self._manager.load(operation_id)
        return checkpoint is not None

    async def get_resume_info(self, operation_id: str) -> dict[str, Any] | None:
        """
        Get information about resuming an operation.

        Args:
            operation_id: Operation identifier.

        Returns:
            Resume information or None.
        """
        checkpoint = await self._manager.load(operation_id)

        if not checkpoint:
            return None

        return {
            "checkpoint_id": checkpoint.checkpoint_id,
            "target": checkpoint.target,
            "turn": checkpoint.turn,
            "total_turns": checkpoint.total_turns,
            "budget_percent": checkpoint.budget_percent,
            "created_at": checkpoint.created_at,
            "findings_count": checkpoint.findings_count,
            "confidence": checkpoint.confidence,
            "model": checkpoint.model,
            "can_resume": True,
        }

    async def restore_state(
        self,
        operation_id: str,
        checkpoint_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], str, dict[str, Any]] | None:
        """
        Restore agent state from a checkpoint.

        Args:
            operation_id: Operation identifier.
            checkpoint_id: Specific checkpoint or None for latest.

        Returns:
            Tuple of (messages, system_prompt, metrics) or None.
        """
        checkpoint = await self._manager.load(operation_id, checkpoint_id)

        if not checkpoint:
            return None

        metrics = {
            "turns": checkpoint.turn,
            "total_input_tokens": checkpoint.total_input_tokens,
            "total_output_tokens": checkpoint.total_output_tokens,
            "max_total_tokens": checkpoint.max_total_tokens,
            "max_turns": checkpoint.total_turns,
        }

        logger.info(
            "state_restored",
            operation_id=operation_id,
            checkpoint_id=checkpoint.checkpoint_id,
            turn=checkpoint.turn,
        )

        return (
            checkpoint.messages,
            checkpoint.system_prompt,
            metrics,
        )


# Global checkpoint manager instance
_checkpoint_manager: CheckpointManager | None = None


def get_checkpoint_manager() -> CheckpointManager:
    """Get the global checkpoint manager instance."""
    global _checkpoint_manager
    if _checkpoint_manager is None:
        _checkpoint_manager = CheckpointManager()
    return _checkpoint_manager


async def save_checkpoint(
    operation_id: str,
    target: str,
    turn: int,
    total_turns: int,
    messages: list[dict[str, Any]],
    system_prompt: str,
    metrics: dict[str, Any],
    **kwargs: Any,
) -> str:
    """Convenience function to save a checkpoint."""
    manager = get_checkpoint_manager()
    return await manager.save(
        operation_id=operation_id,
        target=target,
        turn=turn,
        total_turns=total_turns,
        messages=messages,
        system_prompt=system_prompt,
        metrics=metrics,
        **kwargs,
    )


async def load_checkpoint(
    operation_id: str,
    checkpoint_id: str | None = None,
) -> CheckpointData | None:
    """Convenience function to load a checkpoint."""
    manager = get_checkpoint_manager()
    return await manager.load(operation_id, checkpoint_id)


async def resume_from_checkpoint(
    operation_id: str,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]] | None:
    """Convenience function to resume from latest checkpoint."""
    manager = get_checkpoint_manager()
    recovery = CheckpointRecovery(manager)
    return await recovery.restore_state(operation_id)
