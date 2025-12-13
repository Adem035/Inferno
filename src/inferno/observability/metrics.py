"""
Metrics collection for Inferno.

This module provides metrics collection and export for
monitoring assessment performance and resource usage.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ToolMetrics:
    """Metrics for a single tool."""

    name: str
    call_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_duration_ms: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.call_count == 0:
            return 0.0
        return (self.success_count / self.call_count) * 100

    @property
    def avg_duration_ms(self) -> float:
        """Calculate average duration."""
        if self.call_count == 0:
            return 0.0
        return self.total_duration_ms / self.call_count

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "call_count": self.call_count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "total_duration_ms": self.total_duration_ms,
            "success_rate": self.success_rate,
            "avg_duration_ms": self.avg_duration_ms,
        }


@dataclass
class OperationMetrics:
    """Metrics for an entire operation."""

    operation_id: str
    target: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: datetime | None = None

    # API metrics
    api_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    api_errors: int = 0

    # Tool metrics
    tool_metrics: dict[str, ToolMetrics] = field(default_factory=dict)

    # Agent metrics
    turns: int = 0
    checkpoints: int = 0
    subagents_spawned: int = 0

    # Findings
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0

    @property
    def total_tokens(self) -> int:
        """Total tokens used."""
        return self.total_input_tokens + self.total_output_tokens

    @property
    def total_findings(self) -> int:
        """Total findings count."""
        return (
            self.findings_critical
            + self.findings_high
            + self.findings_medium
            + self.findings_low
            + self.findings_info
        )

    @property
    def duration_seconds(self) -> float:
        """Operation duration in seconds."""
        end = self.ended_at or datetime.now(timezone.utc)
        return (end - self.started_at).total_seconds()

    @property
    def tokens_per_minute(self) -> float:
        """Calculate tokens per minute rate."""
        if self.duration_seconds == 0:
            return 0.0
        return (self.total_tokens / self.duration_seconds) * 60

    def record_api_call(
        self,
        input_tokens: int,
        output_tokens: int,
        success: bool = True,
    ) -> None:
        """Record an API call."""
        self.api_calls += 1
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        if not success:
            self.api_errors += 1

    def record_tool_call(
        self,
        tool_name: str,
        success: bool,
        duration_ms: float,
    ) -> None:
        """Record a tool call."""
        if tool_name not in self.tool_metrics:
            self.tool_metrics[tool_name] = ToolMetrics(name=tool_name)

        metrics = self.tool_metrics[tool_name]
        metrics.call_count += 1
        metrics.total_duration_ms += duration_ms

        if success:
            metrics.success_count += 1
        else:
            metrics.error_count += 1

    def record_finding(self, severity: str) -> None:
        """Record a finding."""
        severity_lower = severity.lower()
        if severity_lower == "critical":
            self.findings_critical += 1
        elif severity_lower == "high":
            self.findings_high += 1
        elif severity_lower == "medium":
            self.findings_medium += 1
        elif severity_lower == "low":
            self.findings_low += 1
        else:
            self.findings_info += 1

    def complete(self) -> None:
        """Mark operation as complete."""
        self.ended_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operation_id": self.operation_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "api": {
                "calls": self.api_calls,
                "input_tokens": self.total_input_tokens,
                "output_tokens": self.total_output_tokens,
                "total_tokens": self.total_tokens,
                "errors": self.api_errors,
                "tokens_per_minute": self.tokens_per_minute,
            },
            "agent": {
                "turns": self.turns,
                "checkpoints": self.checkpoints,
                "subagents_spawned": self.subagents_spawned,
            },
            "tools": {name: m.to_dict() for name, m in self.tool_metrics.items()},
            "findings": {
                "critical": self.findings_critical,
                "high": self.findings_high,
                "medium": self.findings_medium,
                "low": self.findings_low,
                "info": self.findings_info,
                "total": self.total_findings,
            },
        }


class MetricsCollector:
    """
    Centralized metrics collection for Inferno.

    Collects and exports metrics for monitoring and analysis.
    """

    def __init__(
        self,
        operation_id: str,
        target: str,
        output_dir: Path | None = None,
    ) -> None:
        """
        Initialize the metrics collector.

        Args:
            operation_id: Operation identifier.
            target: Target being assessed.
            output_dir: Directory for metrics output.
        """
        self._metrics = OperationMetrics(
            operation_id=operation_id,
            target=target,
        )
        self._output_dir = output_dir
        self._tool_timers: dict[str, float] = {}

        logger.debug(
            "metrics_collector_initialized",
            operation_id=operation_id,
            target=target,
        )

    @property
    def metrics(self) -> OperationMetrics:
        """Get current metrics."""
        return self._metrics

    def record_api_call(
        self,
        input_tokens: int,
        output_tokens: int,
        success: bool = True,
    ) -> None:
        """Record an API call."""
        self._metrics.record_api_call(input_tokens, output_tokens, success)
        self._metrics.turns += 1

    def start_tool_timer(self, tool_name: str) -> None:
        """Start timing a tool call."""
        self._tool_timers[tool_name] = time.time() * 1000

    def stop_tool_timer(self, tool_name: str, success: bool) -> None:
        """Stop timing a tool call and record metrics."""
        if tool_name in self._tool_timers:
            start_time = self._tool_timers.pop(tool_name)
            duration_ms = (time.time() * 1000) - start_time
            self._metrics.record_tool_call(tool_name, success, duration_ms)

    def record_checkpoint(self) -> None:
        """Record a checkpoint."""
        self._metrics.checkpoints += 1

    def record_subagent(self) -> None:
        """Record subagent spawn."""
        self._metrics.subagents_spawned += 1

    def record_finding(self, severity: str) -> None:
        """Record a finding."""
        self._metrics.record_finding(severity)

    def complete(self) -> None:
        """Mark collection as complete."""
        self._metrics.complete()
        logger.info(
            "metrics_collection_complete",
            operation_id=self._metrics.operation_id,
            duration=self._metrics.duration_seconds,
            total_tokens=self._metrics.total_tokens,
        )

    def export_json(self, path: Path | None = None) -> str:
        """
        Export metrics as JSON.

        Args:
            path: Optional file path to write to.

        Returns:
            JSON string of metrics.
        """
        data = self._metrics.to_dict()
        json_str = json.dumps(data, indent=2)

        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_str, encoding="utf-8")
            logger.info("metrics_exported", path=str(path))

        return json_str

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of key metrics."""
        return {
            "operation_id": self._metrics.operation_id,
            "duration_seconds": self._metrics.duration_seconds,
            "turns": self._metrics.turns,
            "total_tokens": self._metrics.total_tokens,
            "tool_calls": sum(m.call_count for m in self._metrics.tool_metrics.values()),
            "findings": self._metrics.total_findings,
        }


# Global metrics collector
_collector: MetricsCollector | None = None


def get_metrics_collector() -> MetricsCollector | None:
    """Get the global metrics collector."""
    return _collector


def init_metrics_collector(
    operation_id: str,
    target: str,
    output_dir: Path | None = None,
) -> MetricsCollector:
    """Initialize the global metrics collector."""
    global _collector
    _collector = MetricsCollector(operation_id, target, output_dir)
    return _collector
