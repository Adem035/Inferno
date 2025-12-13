"""
MessageBus for inter-agent communication.

This module provides real-time communication between subagents
in the coordinated assessment architecture.

Features:
- Publish/subscribe messaging
- Direct agent-to-agent messages
- Priority-based message delivery
- Message history for late subscribers
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

import structlog

logger = structlog.get_logger(__name__)


class MessageType(str, Enum):
    """Types of messages that can be sent on the bus."""

    # Discovery messages
    FINDING = "finding"  # New vulnerability discovered
    ENDPOINT = "endpoint"  # New endpoint discovered
    TECHNOLOGY = "technology"  # Technology identified
    PARAMETER = "parameter"  # Parameter discovered

    # Coordination messages
    CONTEXT = "context"  # Share context/state
    REQUEST = "request"  # Request help from another agent
    RESPONSE = "response"  # Response to a request

    # Status messages
    STATUS = "status"  # Agent status update
    PROGRESS = "progress"  # Progress update
    COMPLETE = "complete"  # Task complete
    ERROR = "error"  # Error occurred

    # Validation messages
    VALIDATE = "validate"  # Request validation
    VALIDATED = "validated"  # Validation result

    # Attack chain messages
    CHAIN = "chain"  # Attack chain discovered
    ESCALATE = "escalate"  # Escalation opportunity


class MessagePriority(int, Enum):
    """Priority levels for messages."""

    LOW = 1
    NORMAL = 5
    HIGH = 10
    CRITICAL = 20


@dataclass
class Message:
    """A message on the bus."""

    message_id: str
    message_type: MessageType
    sender: str  # Agent ID
    content: dict[str, Any]
    priority: MessagePriority = MessagePriority.NORMAL
    recipient: str | None = None  # None = broadcast
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    requires_ack: bool = False
    acknowledged_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "message_id": self.message_id,
            "type": self.message_type.value,
            "sender": self.sender,
            "content": self.content,
            "priority": self.priority.value,
            "recipient": self.recipient,
            "timestamp": self.timestamp.isoformat(),
        }


# Type for message handlers
MessageHandler = Callable[[Message], Awaitable[None]]


class MessageBus:
    """
    Central message bus for inter-agent communication.

    Supports:
    - Broadcast messages (all agents receive)
    - Direct messages (specific agent)
    - Topic-based subscriptions
    - Message history for late subscribers
    - Priority-based delivery
    """

    def __init__(self, max_history: int = 1000) -> None:
        """
        Initialize the message bus.

        Args:
            max_history: Maximum messages to keep in history
        """
        self._max_history = max_history
        self._message_counter = 0

        # Subscriptions: message_type -> list of (agent_id, handler)
        self._subscriptions: dict[MessageType, list[tuple[str, MessageHandler]]] = defaultdict(list)

        # All-message subscribers (receive everything)
        self._global_subscribers: list[tuple[str, MessageHandler]] = []

        # Message history for replay
        self._history: list[Message] = []

        # Agent registry
        self._agents: set[str] = set()

        # Pending messages for offline agents
        self._pending: dict[str, list[Message]] = defaultdict(list)

        # Lock for thread safety
        self._lock = asyncio.Lock()

        logger.info("message_bus_initialized", max_history=max_history)

    def _generate_message_id(self) -> str:
        """Generate unique message ID."""
        self._message_counter += 1
        return f"msg_{self._message_counter:06d}"

    async def register_agent(self, agent_id: str) -> None:
        """
        Register an agent with the bus.

        Args:
            agent_id: Unique agent identifier
        """
        async with self._lock:
            self._agents.add(agent_id)

            # Deliver any pending messages
            if agent_id in self._pending:
                pending = self._pending.pop(agent_id)
                logger.info(
                    "delivering_pending_messages",
                    agent_id=agent_id,
                    count=len(pending),
                )
                # Messages will be delivered through subscriptions

        logger.debug("agent_registered", agent_id=agent_id)

    async def unregister_agent(self, agent_id: str) -> None:
        """
        Unregister an agent from the bus.

        Args:
            agent_id: Agent to unregister
        """
        async with self._lock:
            self._agents.discard(agent_id)

            # Remove subscriptions
            for msg_type in self._subscriptions:
                self._subscriptions[msg_type] = [
                    (aid, handler)
                    for aid, handler in self._subscriptions[msg_type]
                    if aid != agent_id
                ]

            self._global_subscribers = [
                (aid, handler)
                for aid, handler in self._global_subscribers
                if aid != agent_id
            ]

        logger.debug("agent_unregistered", agent_id=agent_id)

    async def subscribe(
        self,
        agent_id: str,
        message_type: MessageType,
        handler: MessageHandler,
    ) -> None:
        """
        Subscribe to a specific message type.

        Args:
            agent_id: Subscribing agent
            message_type: Type of messages to receive
            handler: Async function to handle messages
        """
        async with self._lock:
            self._subscriptions[message_type].append((agent_id, handler))

        logger.debug(
            "agent_subscribed",
            agent_id=agent_id,
            message_type=message_type.value,
        )

    async def subscribe_all(
        self,
        agent_id: str,
        handler: MessageHandler,
    ) -> None:
        """
        Subscribe to all messages.

        Args:
            agent_id: Subscribing agent
            handler: Async function to handle messages
        """
        async with self._lock:
            self._global_subscribers.append((agent_id, handler))

        logger.debug("agent_subscribed_all", agent_id=agent_id)

    async def publish(
        self,
        sender: str,
        message_type: MessageType,
        content: dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
        recipient: str | None = None,
        requires_ack: bool = False,
    ) -> Message:
        """
        Publish a message to the bus.

        Args:
            sender: Sending agent ID
            message_type: Type of message
            content: Message content
            priority: Message priority
            recipient: Specific recipient (None = broadcast)
            requires_ack: Whether acknowledgment is required

        Returns:
            The published message
        """
        message = Message(
            message_id=self._generate_message_id(),
            message_type=message_type,
            sender=sender,
            content=content,
            priority=priority,
            recipient=recipient,
            requires_ack=requires_ack,
        )

        async with self._lock:
            # Add to history
            self._history.append(message)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

        logger.debug(
            "message_published",
            message_id=message.message_id,
            type=message_type.value,
            sender=sender,
            recipient=recipient,
        )

        # Deliver message
        await self._deliver(message)

        return message

    async def _deliver(self, message: Message) -> None:
        """Deliver a message to subscribers."""
        handlers_to_call: list[tuple[str, MessageHandler]] = []

        async with self._lock:
            # If direct message, only deliver to recipient
            if message.recipient:
                # Find recipient's handlers
                for msg_type in [message.message_type]:
                    for agent_id, handler in self._subscriptions.get(msg_type, []):
                        if agent_id == message.recipient:
                            handlers_to_call.append((agent_id, handler))

                for agent_id, handler in self._global_subscribers:
                    if agent_id == message.recipient:
                        handlers_to_call.append((agent_id, handler))

                # If recipient not found/subscribed, store as pending
                if not handlers_to_call and message.recipient not in self._agents:
                    self._pending[message.recipient].append(message)
                    logger.debug(
                        "message_pending",
                        message_id=message.message_id,
                        recipient=message.recipient,
                    )
                    return
            else:
                # Broadcast to all subscribers of this type
                for agent_id, handler in self._subscriptions.get(message.message_type, []):
                    if agent_id != message.sender:  # Don't send to self
                        handlers_to_call.append((agent_id, handler))

                # Also send to global subscribers
                for agent_id, handler in self._global_subscribers:
                    if agent_id != message.sender:
                        handlers_to_call.append((agent_id, handler))

        # Call handlers (outside lock to prevent deadlocks)
        for agent_id, handler in handlers_to_call:
            try:
                await handler(message)
            except Exception as e:
                logger.error(
                    "message_handler_error",
                    message_id=message.message_id,
                    agent_id=agent_id,
                    error=str(e),
                )

    async def get_history(
        self,
        message_type: MessageType | None = None,
        sender: str | None = None,
        limit: int = 100,
    ) -> list[Message]:
        """
        Get message history.

        Args:
            message_type: Filter by type
            sender: Filter by sender
            limit: Maximum messages to return

        Returns:
            List of messages (newest first)
        """
        async with self._lock:
            messages = self._history.copy()

        # Apply filters
        if message_type:
            messages = [m for m in messages if m.message_type == message_type]
        if sender:
            messages = [m for m in messages if m.sender == sender]

        # Sort by timestamp descending and limit
        messages.sort(key=lambda m: m.timestamp, reverse=True)
        return messages[:limit]

    async def acknowledge(self, message_id: str, agent_id: str) -> bool:
        """
        Acknowledge receipt of a message.

        Args:
            message_id: Message to acknowledge
            agent_id: Acknowledging agent

        Returns:
            True if acknowledged, False if message not found
        """
        async with self._lock:
            for message in self._history:
                if message.message_id == message_id:
                    if agent_id not in message.acknowledged_by:
                        message.acknowledged_by.append(agent_id)
                    return True
        return False

    def get_agent_count(self) -> int:
        """Get number of registered agents."""
        return len(self._agents)

    def get_message_count(self) -> int:
        """Get total messages in history."""
        return len(self._history)


# Global message bus instance
_message_bus: MessageBus | None = None


def get_message_bus() -> MessageBus:
    """Get or create the global message bus."""
    global _message_bus
    if _message_bus is None:
        _message_bus = MessageBus()
    return _message_bus


def reset_message_bus() -> None:
    """Reset the global message bus (for testing)."""
    global _message_bus
    _message_bus = None


# Convenience functions for common message types

async def publish_finding(
    bus: MessageBus,
    sender: str,
    vuln_type: str,
    severity: str,
    title: str,
    evidence: str,
    target: str,
) -> Message:
    """Publish a finding to the bus."""
    return await bus.publish(
        sender=sender,
        message_type=MessageType.FINDING,
        content={
            "vuln_type": vuln_type,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "target": target,
        },
        priority=MessagePriority.HIGH if severity in ("critical", "high") else MessagePriority.NORMAL,
    )


async def publish_endpoint(
    bus: MessageBus,
    sender: str,
    url: str,
    method: str = "GET",
    parameters: list[str] | None = None,
) -> Message:
    """Publish a discovered endpoint."""
    return await bus.publish(
        sender=sender,
        message_type=MessageType.ENDPOINT,
        content={
            "url": url,
            "method": method,
            "parameters": parameters or [],
        },
    )


async def request_validation(
    bus: MessageBus,
    sender: str,
    finding_id: str,
    vuln_type: str,
    evidence: str,
) -> Message:
    """Request validation of a finding."""
    return await bus.publish(
        sender=sender,
        message_type=MessageType.VALIDATE,
        content={
            "finding_id": finding_id,
            "vuln_type": vuln_type,
            "evidence": evidence,
        },
        priority=MessagePriority.HIGH,
    )


async def publish_chain(
    bus: MessageBus,
    sender: str,
    chain_name: str,
    steps: list[str],
    impact: str,
) -> Message:
    """Publish an attack chain discovery."""
    return await bus.publish(
        sender=sender,
        message_type=MessageType.CHAIN,
        content={
            "chain_name": chain_name,
            "steps": steps,
            "impact": impact,
        },
        priority=MessagePriority.HIGH,
    )
