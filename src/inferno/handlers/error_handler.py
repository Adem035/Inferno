"""
Error handling for Inferno.

This module provides handlers for error recovery, retry logic,
and graceful degradation during agent execution.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from inferno.handlers.base import Event, EventHandler, EventType

logger = structlog.get_logger(__name__)


@dataclass
class ErrorRecord:
    """Record of an error occurrence."""

    error_type: str
    message: str
    tool_name: str | None
    timestamp: datetime
    context: dict[str, Any] = field(default_factory=dict)
    recovered: bool = False
    recovery_action: str | None = None


class ErrorRecoveryHandler(EventHandler):
    """
    Handler for error recovery and resilience.

    Responsibilities:
    - Track error patterns
    - Suggest recovery actions
    - Implement retry logic
    - Escalate persistent issues
    """

    def __init__(
        self,
        max_retries: int | None = None,
        error_threshold: int | None = None,
    ) -> None:
        """
        Initialize the error recovery handler.

        Args:
            max_retries: Maximum retry attempts per tool (from settings if None).
            error_threshold: Errors before escalation (from settings if None).
        """
        # Load from settings or use defaults
        try:
            from inferno.config.settings import InfernoSettings
            settings = InfernoSettings()
            self._max_retries = max_retries if max_retries is not None else settings.error_recovery.max_tool_retries
            self._error_threshold = error_threshold if error_threshold is not None else settings.error_recovery.error_threshold
            self._enable_auto_recovery = settings.error_recovery.enable_auto_recovery
            self._backoff_multiplier = settings.error_recovery.backoff_multiplier
            self._max_backoff = settings.error_recovery.max_backoff_seconds
        except Exception:
            self._max_retries = max_retries if max_retries is not None else 3
            self._error_threshold = error_threshold if error_threshold is not None else 5
            self._enable_auto_recovery = True
            self._backoff_multiplier = 2.0
            self._max_backoff = 60.0

        self._errors: list[ErrorRecord] = []
        self._retry_counts: dict[str, int] = defaultdict(int)
        self._suppressed_tools: set[str] = set()
        self._backoff_delays: dict[str, float] = defaultdict(lambda: 1.0)

    @property
    def name(self) -> str:
        return "error_recovery_handler"

    @property
    def handles(self) -> list[EventType]:
        return [EventType.TOOL_ERROR]

    async def handle(self, event: Event) -> None:
        """Process error events and attempt recovery."""
        tool_name = event.data.get("tool_name", "unknown")
        error_message = event.data.get("error", "Unknown error")
        error_type = event.data.get("error_type", "unknown")

        # Record the error
        record = ErrorRecord(
            error_type=error_type,
            message=error_message,
            tool_name=tool_name,
            timestamp=datetime.now(UTC),
            context=event.data,
        )
        self._errors.append(record)

        logger.warning(
            "error_recorded",
            tool=tool_name,
            error_type=error_type,
            message=error_message[:200],
        )

        # Check if tool should be suppressed
        if tool_name in self._suppressed_tools:
            logger.info("tool_suppressed", tool=tool_name)
            event.data["suppress"] = True
            return

        # Increment retry count
        self._retry_counts[tool_name] += 1

        # Determine recovery action
        recovery = self._determine_recovery(tool_name, error_type, error_message)
        record.recovery_action = recovery["action"]
        record.recovered = recovery["can_recover"]

        event.data["recovery"] = recovery

        # Check for threshold breach
        tool_errors = sum(1 for e in self._errors if e.tool_name == tool_name)
        if tool_errors >= self._error_threshold:
            self._suppressed_tools.add(tool_name)
            logger.warning(
                "tool_suppressed_threshold",
                tool=tool_name,
                errors=tool_errors,
            )

    def _determine_recovery(
        self,
        tool_name: str,
        error_type: str,
        message: str,
    ) -> dict[str, Any]:
        """Determine the appropriate recovery action."""
        retry_count = self._retry_counts[tool_name]

        # Check if auto recovery is disabled
        if not self._enable_auto_recovery:
            return {
                "action": "skip",
                "can_recover": False,
                "reason": "Auto recovery disabled",
            }

        # Check if we can retry
        if retry_count > self._max_retries:
            return {
                "action": "skip",
                "can_recover": False,
                "reason": f"Max retries ({self._max_retries}) exceeded",
            }

        # Calculate current backoff delay
        current_backoff = self._backoff_delays[tool_name]

        # Error-specific recovery strategies
        recovery_strategies = {
            "timeout": {
                "action": "retry_with_longer_timeout",
                "can_recover": True,
                "suggestion": f"Increase timeout and retry (backoff: {current_backoff:.1f}s)",
                "delay": current_backoff,
            },
            "connection": {
                "action": "retry_with_delay",
                "can_recover": True,
                "suggestion": f"Wait {current_backoff:.1f}s and retry connection",
                "delay": current_backoff,
            },
            "authentication": {
                "action": "check_credentials",
                "can_recover": False,
                "suggestion": "Verify authentication credentials",
            },
            "permission": {
                "action": "skip",
                "can_recover": False,
                "suggestion": "Insufficient permissions - skip this check",
            },
            "rate_limit": {
                "action": "backoff",
                "can_recover": True,
                "suggestion": f"Rate limited - exponential backoff ({current_backoff:.1f}s)",
                "delay": current_backoff,
            },
            "dns": {
                "action": "retry_with_delay",
                "can_recover": True,
                "suggestion": f"DNS resolution failed - retry after {current_backoff:.1f}s",
                "delay": current_backoff,
            },
            "ssl": {
                "action": "retry_without_ssl_verify",
                "can_recover": True,
                "suggestion": "SSL verification failed - consider disabling for this request",
            },
            "404": {
                "action": "skip",
                "can_recover": False,
                "suggestion": "Resource not found - try alternative endpoints",
            },
        }

        # Match error type and update backoff
        for key, strategy in recovery_strategies.items():
            if key in error_type.lower() or key in message.lower():
                # Update backoff delay for next retry
                self._backoff_delays[tool_name] = min(
                    current_backoff * self._backoff_multiplier,
                    self._max_backoff
                )
                return strategy

        # Default: retry with increasing delay
        if retry_count < 2:
            self._backoff_delays[tool_name] = min(
                current_backoff * self._backoff_multiplier,
                self._max_backoff
            )
            return {
                "action": "retry",
                "can_recover": True,
                "suggestion": f"Retry the operation (attempt {retry_count + 1}/{self._max_retries})",
                "delay": current_backoff,
            }

        return {
            "action": "alternative",
            "can_recover": True,
            "suggestion": "Try alternative approach or tool",
        }

    def get_error_summary(self) -> dict[str, Any]:
        """Get a summary of errors."""
        by_tool: dict[str, int] = defaultdict(int)
        by_type: dict[str, int] = defaultdict(int)
        recovered = 0

        for error in self._errors:
            if error.tool_name:
                by_tool[error.tool_name] += 1
            by_type[error.error_type] += 1
            if error.recovered:
                recovered += 1

        return {
            "total_errors": len(self._errors),
            "recovered": recovered,
            "recovery_rate": recovered / len(self._errors) if self._errors else 0,
            "by_tool": dict(by_tool),
            "by_type": dict(by_type),
            "suppressed_tools": list(self._suppressed_tools),
        }

    def is_tool_suppressed(self, tool_name: str) -> bool:
        """Check if a tool is suppressed due to errors."""
        return tool_name in self._suppressed_tools

    def reset_tool(self, tool_name: str) -> None:
        """Reset error state for a tool."""
        self._retry_counts[tool_name] = 0
        self._suppressed_tools.discard(tool_name)


class ErrorLoggingHandler(EventHandler):
    """
    Handler for comprehensive error logging.

    Logs all errors with full context for debugging and analysis.
    """

    def __init__(self, log_context: bool = True) -> None:
        """
        Initialize the error logging handler.

        Args:
            log_context: Whether to log full error context.
        """
        self._log_context = log_context

    @property
    def name(self) -> str:
        return "error_logging_handler"

    @property
    def handles(self) -> list[EventType]:
        return [EventType.TOOL_ERROR]

    async def handle(self, event: Event) -> None:
        """Log error with full context."""
        tool_name = event.data.get("tool_name", "unknown")
        error = event.data.get("error", "Unknown error")

        log_data = {
            "tool": tool_name,
            "error": error,
            "timestamp": event.timestamp,
        }

        if self._log_context:
            # Add relevant context, excluding sensitive data
            context_keys = ["input", "command", "url", "target"]
            for key in context_keys:
                if key in event.data:
                    value = event.data[key]
                    # Truncate long values
                    if isinstance(value, str) and len(value) > 500:
                        value = value[:500] + "..."
                    log_data[key] = value

        logger.error("tool_error_logged", **log_data)
