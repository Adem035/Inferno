"""
Inferno Handlers Package.

This module exports event handlers for tool results, errors,
checkpoints, progress tracking, and dynamic prompt optimization
during agent execution.
"""

from inferno.handlers.base import (
    Event,
    EventDispatcher,
    EventHandler,
    EventType,
    get_dispatcher,
)
from inferno.handlers.checkpoint_handler import (
    Checkpoint,
    CheckpointHandler,
    ProgressTracker,
)
from inferno.handlers.error_handler import (
    ErrorLoggingHandler,
    ErrorRecord,
    ErrorRecoveryHandler,
)
from inferno.handlers.tool_handler import (
    ToolMetricsHandler,
    ToolResultHandler,
)

# NOTE: prompt_rebuild_hook removed (depended on deleted prompt_optimizer module)


def create_default_handlers(
    artifacts_dir: str | None = None,
) -> list[EventHandler]:
    """
    Create a default set of event handlers.

    Args:
        artifacts_dir: Directory for saving artifacts.

    Returns:
        List of configured event handlers.
    """
    from pathlib import Path

    handlers: list[EventHandler] = [
        ToolResultHandler(
            artifacts_dir=Path(artifacts_dir) if artifacts_dir else None,
        ),
        ToolMetricsHandler(),
        ErrorRecoveryHandler(),
        ErrorLoggingHandler(),
        CheckpointHandler(),
        ProgressTracker(),
    ]

    return handlers


def setup_default_dispatcher(
    artifacts_dir: str | None = None,
) -> EventDispatcher:
    """
    Set up the event dispatcher with default handlers.

    Args:
        artifacts_dir: Directory for saving artifacts.

    Returns:
        Configured EventDispatcher instance.
    """
    dispatcher = get_dispatcher()

    for handler in create_default_handlers(artifacts_dir):
        dispatcher.register(handler)

    return dispatcher


__all__ = [
    # Base classes
    "Event",
    "EventDispatcher",
    "EventHandler",
    "EventType",
    "get_dispatcher",
    # Tool handlers
    "ToolMetricsHandler",
    "ToolResultHandler",
    # Error handlers
    "ErrorLoggingHandler",
    "ErrorRecord",
    "ErrorRecoveryHandler",
    # Checkpoint handlers
    "Checkpoint",
    "CheckpointHandler",
    "ProgressTracker",
    # Factory functions
    "create_default_handlers",
    "setup_default_dispatcher",
]
