"""
Base handler classes for Inferno.

This module provides the foundation for event handlers that process
tool results, errors, and agent state changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

import structlog

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


class EventType(str, Enum):
    """Types of events that can be handled."""

    # Tool events
    TOOL_START = "tool_start"
    TOOL_COMPLETE = "tool_complete"
    TOOL_ERROR = "tool_error"

    # Agent events
    TURN_START = "turn_start"
    TURN_COMPLETE = "turn_complete"
    MESSAGE_RECEIVED = "message_received"

    # State events
    CHECKPOINT_REACHED = "checkpoint_reached"
    BUDGET_WARNING = "budget_warning"
    STOP_REQUESTED = "stop_requested"

    # Finding events
    FINDING_DISCOVERED = "finding_discovered"
    FLAG_CAPTURED = "flag_captured"


@dataclass
class Event:
    """An event that occurred during agent execution."""

    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        """Set timestamp if not provided."""
        if self.timestamp is None:
            import time
            self.timestamp = time.time()


class EventHandler(ABC):
    """
    Abstract base class for event handlers.

    Event handlers process events emitted during agent execution,
    allowing for logging, metrics, notifications, and custom logic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Handler name for identification."""
        ...

    @property
    def handles(self) -> list[EventType]:
        """
        Event types this handler processes.

        Returns:
            List of event types, or empty for all events.
        """
        return []  # Empty means handle all

    @abstractmethod
    async def handle(self, event: Event) -> None:
        """
        Process an event.

        Args:
            event: The event to process.
        """
        ...

    async def on_error(self, event: Event, error: Exception) -> None:
        """
        Called when handler fails to process an event.

        Args:
            event: The event that caused the error.
            error: The exception that was raised.
        """
        logger.error(
            "handler_error",
            handler=self.name,
            event_type=event.type.value,
            error=str(error),
        )


class EventDispatcher:
    """
    Dispatches events to registered handlers.

    The dispatcher manages a collection of handlers and routes
    events to the appropriate handlers based on their configuration.
    """

    def __init__(self) -> None:
        """Initialize the event dispatcher."""
        self._handlers: list[EventHandler] = []
        self._callbacks: dict[EventType, list[Callable[[Event], None]]] = {}

    def register(self, handler: EventHandler) -> None:
        """
        Register an event handler.

        Args:
            handler: The handler to register.
        """
        self._handlers.append(handler)
        logger.debug("handler_registered", handler=handler.name)

    def on(
        self,
        event_type: EventType,
        callback: Callable[[Event], None],
    ) -> None:
        """
        Register a callback for a specific event type.

        Args:
            event_type: The event type to listen for.
            callback: The callback function.
        """
        if event_type not in self._callbacks:
            self._callbacks[event_type] = []
        self._callbacks[event_type].append(callback)

    async def dispatch(self, event: Event) -> None:
        """
        Dispatch an event to all relevant handlers.

        Args:
            event: The event to dispatch.
        """
        logger.debug("dispatching_event", event_type=event.type.value)

        # Call registered handlers
        for handler in self._handlers:
            # Check if handler handles this event type
            if handler.handles and event.type not in handler.handles:
                continue

            try:
                await handler.handle(event)
            except Exception as e:
                await handler.on_error(event, e)

        # Call registered callbacks
        if event.type in self._callbacks:
            for callback in self._callbacks[event.type]:
                try:
                    callback(event)
                except Exception as e:
                    logger.error(
                        "callback_error",
                        event_type=event.type.value,
                        error=str(e),
                    )

    def emit(self, event_type: EventType, **data: Any) -> Event:
        """
        Create and dispatch an event.

        Args:
            event_type: The type of event.
            **data: Event data.

        Returns:
            The created event.
        """
        event = Event(type=event_type, data=data)
        # Note: This is synchronous, use dispatch for async
        return event

    def clear(self) -> None:
        """Clear all handlers and callbacks."""
        self._handlers.clear()
        self._callbacks.clear()


# Global dispatcher instance
_dispatcher: EventDispatcher | None = None


def get_dispatcher() -> EventDispatcher:
    """Get the global event dispatcher."""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = EventDispatcher()
    return _dispatcher
