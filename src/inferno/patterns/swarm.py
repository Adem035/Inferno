"""
Swarm pattern for Inferno.

This module provides the SWARM pattern implementation for cyclic
agent collaboration with dynamic handoffs. Agents can transfer
context to each other based on their specialized capabilities.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from inferno.patterns.pattern import Pattern, PatternType, swarm_pattern

if TYPE_CHECKING:
    from inferno.swarm.message_bus import MessageBus

logger = structlog.get_logger(__name__)


@dataclass
class Handoff:
    """
    Represents a handoff between agents in a swarm.

    A handoff enables one agent to transfer execution context
    to another agent when appropriate.
    """

    target_agent: Any
    agent_name: str
    tool_description: str
    condition: Callable[..., bool] | None = None
    on_invoke_handoff: Callable[..., Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize the handoff with an invocation function."""
        if self.on_invoke_handoff is None:
            # Create default invocation that returns the target agent
            agent = self.target_agent

            def default_invoke(*args: Any, **kwargs: Any) -> Any:
                return agent

            self.on_invoke_handoff = default_invoke


@dataclass
class SwarmAgent:
    """
    An agent configured for swarm collaboration.

    SwarmAgent wraps a base agent configuration with swarm-specific
    properties like handoffs and pattern marking.
    """

    name: str
    config: Any  # SubAgentConfig or similar
    handoffs: list[Handoff] = field(default_factory=list)
    pattern: str = "swarm"
    description: str = ""
    instructions: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_handoff(self, handoff: Handoff) -> SwarmAgent:
        """
        Add a handoff to another agent.

        Args:
            handoff: The handoff configuration.

        Returns:
            Self for method chaining.
        """
        self.handoffs.append(handoff)
        return self

    def clone(self) -> SwarmAgent:
        """
        Create a copy of this agent with empty handoffs.

        Returns:
            New SwarmAgent instance.
        """
        return SwarmAgent(
            name=self.name,
            config=self.config,
            handoffs=[],  # Clear handoffs for the clone
            pattern=self.pattern,
            description=self.description,
            instructions=self.instructions,
            metadata=self.metadata.copy(),
        )

    def append_instructions(self, additional: str) -> SwarmAgent:
        """
        Append additional instructions to the agent.

        Args:
            additional: Instructions to append.

        Returns:
            Self for method chaining.
        """
        self.instructions = f"{self.instructions}\n{additional}".strip()
        return self


def handoff(
    agent: SwarmAgent,
    tool_description_override: str | None = None,
    condition: Callable[..., bool] | None = None,
) -> Handoff:
    """
    Create a handoff to another agent.

    This function creates a Handoff object that enables one agent
    to transfer execution context to another agent in the swarm.

    Args:
        agent: The target agent for the handoff.
        tool_description_override: Custom description for the handoff tool.
        condition: Optional condition that must be true for handoff.

    Returns:
        Configured Handoff instance.

    Example:
        >>> recon_handoff = handoff(
        ...     agent=recon_agent,
        ...     tool_description_override="Transfer to recon for enumeration"
        ... )
        >>> exploit_agent.handoffs.append(recon_handoff)
    """
    description = tool_description_override or (
        f"Transfer to {agent.name} for specialized handling"
    )

    return Handoff(
        target_agent=agent,
        agent_name=agent.name,
        tool_description=description,
        condition=condition,
    )


@dataclass
class SwarmExecutionContext:
    """Context passed between agents during swarm execution."""

    current_agent: str
    message_history: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    target: str | None = None
    operation_id: str | None = None
    handoff_count: int = 0
    max_handoffs: int = 20
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_message(
        self,
        role: str,
        content: str,
        agent: str | None = None,
    ) -> None:
        """Add a message to the history."""
        self.message_history.append({
            "role": role,
            "content": content,
            "agent": agent or self.current_agent,
        })

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a security finding."""
        finding["discovered_by"] = self.current_agent
        self.findings.append(finding)

    def can_handoff(self) -> bool:
        """Check if more handoffs are allowed."""
        return self.handoff_count < self.max_handoffs


@dataclass
class SwarmExecutionResult:
    """Result from swarm pattern execution."""

    pattern_name: str
    entry_agent: str
    final_agent: str
    total_handoffs: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    agent_sequence: list[str] = field(default_factory=list)
    success: bool = True
    error: str | None = None
    duration_seconds: float = 0.0


class SwarmExecutor:
    """
    Executor for swarm patterns.

    Manages the execution flow of a swarm pattern, handling
    handoffs between agents and maintaining shared context.
    """

    def __init__(
        self,
        max_handoffs: int = 20,
        message_bus: MessageBus | None = None,
    ) -> None:
        """
        Initialize the swarm executor.

        Args:
            max_handoffs: Maximum handoffs before stopping.
            message_bus: Optional message bus for inter-agent communication.
        """
        self._max_handoffs = max_handoffs
        self._message_bus = message_bus
        self._agents: dict[str, SwarmAgent] = {}

    def register_agent(self, agent: SwarmAgent) -> None:
        """Register an agent with the executor."""
        self._agents[agent.name] = agent
        logger.debug("agent_registered_in_swarm", agent=agent.name)

    async def execute_pattern(
        self,
        pattern: Pattern,
        agent_executor: Callable[[SwarmAgent, SwarmExecutionContext], Any],
        initial_task: str,
        target: str | None = None,
        operation_id: str | None = None,
    ) -> SwarmExecutionResult:
        """
        Execute a swarm pattern.

        Args:
            pattern: The swarm pattern to execute.
            agent_executor: Async callable that executes a single agent.
            initial_task: The initial task to send to the entry agent.
            target: Target URL/host.
            operation_id: Operation ID for memory sharing.

        Returns:
            SwarmExecutionResult with execution details.

        Raises:
            ValueError: If pattern is not SWARM type.
        """
        if pattern.type != PatternType.SWARM:
            raise ValueError(
                f"SwarmExecutor only handles SWARM patterns, "
                f"got {pattern.type.value}"
            )

        import time
        start_time = time.time()

        # Initialize context
        entry_agent = pattern.entry_agent
        if isinstance(entry_agent, SwarmAgent):
            entry_name = entry_agent.name
        else:
            entry_name = getattr(entry_agent, "name", str(entry_agent))

        context = SwarmExecutionContext(
            current_agent=entry_name,
            target=target,
            operation_id=operation_id,
            max_handoffs=self._max_handoffs,
        )

        # Add initial task to context
        context.add_message("user", initial_task)

        logger.info(
            "starting_swarm_execution",
            pattern=pattern.name,
            entry_agent=entry_name,
            max_handoffs=self._max_handoffs,
        )

        agent_sequence = [entry_name]
        current_agent = entry_agent
        final_agent = entry_name

        try:
            while context.can_handoff():
                # Execute current agent
                result = await agent_executor(current_agent, context)

                # Check for handoff in result
                next_agent = self._check_for_handoff(result, current_agent)

                if next_agent is None:
                    # No handoff, execution complete
                    break

                # Perform handoff
                context.handoff_count += 1
                context.current_agent = next_agent.name
                agent_sequence.append(next_agent.name)
                final_agent = next_agent.name
                current_agent = next_agent

                logger.debug(
                    "swarm_handoff",
                    from_agent=agent_sequence[-2],
                    to_agent=next_agent.name,
                    handoff_count=context.handoff_count,
                )

            duration = time.time() - start_time

            return SwarmExecutionResult(
                pattern_name=pattern.name,
                entry_agent=entry_name,
                final_agent=final_agent,
                total_handoffs=context.handoff_count,
                findings=context.findings,
                agent_sequence=agent_sequence,
                success=True,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "swarm_execution_error",
                pattern=pattern.name,
                error=str(e),
            )
            return SwarmExecutionResult(
                pattern_name=pattern.name,
                entry_agent=entry_name,
                final_agent=final_agent,
                total_handoffs=context.handoff_count,
                findings=context.findings,
                agent_sequence=agent_sequence,
                success=False,
                error=str(e),
                duration_seconds=duration,
            )

    def _check_for_handoff(
        self,
        result: Any,
        current_agent: SwarmAgent,
    ) -> SwarmAgent | None:
        """
        Check if the result indicates a handoff.

        Args:
            result: Execution result to check.
            current_agent: The agent that produced the result.

        Returns:
            Target agent if handoff requested, None otherwise.
        """
        # Check if result explicitly requests handoff
        if hasattr(result, "handoff_to"):
            target_name = result.handoff_to
            if isinstance(current_agent, SwarmAgent):
                for h in current_agent.handoffs:
                    if h.agent_name == target_name:
                        return h.target_agent
            return self._agents.get(target_name)

        # Check if result contains a handoff indicator
        if isinstance(result, dict) and "handoff" in result:
            target_name = result["handoff"]
            if isinstance(current_agent, SwarmAgent):
                for h in current_agent.handoffs:
                    if h.agent_name == target_name:
                        return h.target_agent
            return self._agents.get(target_name)

        return None


def create_swarm_agent(
    name: str,
    config: Any,
    description: str = "",
) -> SwarmAgent:
    """
    Create a SwarmAgent from a configuration.

    Args:
        name: Agent name.
        config: Agent configuration (SubAgentConfig or similar).
        description: Optional description.

    Returns:
        Configured SwarmAgent.
    """
    return SwarmAgent(
        name=name,
        config=config,
        description=description or getattr(config, "description", ""),
    )


def setup_bidirectional_handoffs(
    agent_a: SwarmAgent,
    agent_b: SwarmAgent,
    description_a_to_b: str | None = None,
    description_b_to_a: str | None = None,
) -> tuple[SwarmAgent, SwarmAgent]:
    """
    Set up bidirectional handoffs between two agents.

    This creates handoffs in both directions, enabling both agents
    to transfer to each other.

    Args:
        agent_a: First agent.
        agent_b: Second agent.
        description_a_to_b: Description for A->B handoff.
        description_b_to_a: Description for B->A handoff.

    Returns:
        Tuple of (agent_a, agent_b) with handoffs configured.

    Example:
        >>> recon, exploit = setup_bidirectional_handoffs(
        ...     recon_agent,
        ...     exploit_agent,
        ...     description_a_to_b="Transfer to exploiter for attack",
        ...     description_b_to_a="Transfer back to recon for more info",
        ... )
    """
    # A -> B handoff
    a_to_b = handoff(
        agent=agent_b,
        tool_description_override=description_a_to_b,
    )
    agent_a.handoffs.append(a_to_b)

    # B -> A handoff
    b_to_a = handoff(
        agent=agent_a,
        tool_description_override=description_b_to_a,
    )
    agent_b.handoffs.append(b_to_a)

    return agent_a, agent_b


# Pre-defined swarm patterns for common pentest workflows


def create_pentest_swarm(
    recon_agent: SwarmAgent,
    scanner_agent: SwarmAgent,
    exploiter_agent: SwarmAgent,
    validator_agent: SwarmAgent,
) -> Pattern:
    """
    Create a standard penetration testing swarm pattern.

    Sets up a cyclic swarm where:
    - Recon can hand off to Scanner
    - Scanner can hand off to Exploiter
    - Exploiter can hand off to Validator
    - Validator can hand off back to Recon or Exploiter

    Args:
        recon_agent: Reconnaissance agent.
        scanner_agent: Vulnerability scanner agent.
        exploiter_agent: Exploitation agent.
        validator_agent: Validation agent.

    Returns:
        Configured swarm Pattern.
    """
    # Clone agents to avoid modifying originals
    recon = recon_agent.clone()
    scanner = scanner_agent.clone()
    exploiter = exploiter_agent.clone()
    validator = validator_agent.clone()

    # Set up handoffs
    # Recon -> Scanner
    recon.add_handoff(handoff(
        scanner,
        "Transfer to vulnerability scanner for security testing",
    ))

    # Scanner -> Exploiter
    scanner.add_handoff(handoff(
        exploiter,
        "Transfer to exploiter for vulnerability exploitation",
    ))

    # Exploiter -> Validator
    exploiter.add_handoff(handoff(
        validator,
        "Transfer to validator for finding verification",
    ))

    # Validator -> Recon (for more info) or Exploiter (to re-test)
    validator.add_handoff(handoff(
        recon,
        "Transfer to recon for additional enumeration",
    ))
    validator.add_handoff(handoff(
        exploiter,
        "Transfer to exploiter for re-exploitation attempt",
    ))

    # Add handoff instructions
    recon.append_instructions(
        "\n\nWhen you have discovered enough attack surface, "
        "transfer to the vulnerability scanner."
    )
    scanner.append_instructions(
        "\n\nWhen you find exploitable vulnerabilities, "
        "transfer to the exploiter agent."
    )
    exploiter.append_instructions(
        "\n\nAfter exploitation attempts, transfer to the validator "
        "for finding verification."
    )
    validator.append_instructions(
        "\n\nAfter validation, transfer back to recon if more enumeration "
        "is needed, or to exploiter if re-testing is required."
    )

    return swarm_pattern(
        name="pentest_swarm",
        entry_agent=recon,
        description="Coordinated penetration testing with dynamic handoffs",
        agents=[recon, scanner, exploiter, validator],
    )


def create_bug_bounty_triage_swarm(
    hunter_agent: SwarmAgent,
    validator_agent: SwarmAgent,
) -> Pattern:
    """
    Create a bug bounty triage swarm pattern.

    Simple two-agent swarm where:
    - Hunter finds bugs and hands off to Validator
    - Validator confirms and hands back to Hunter

    Args:
        hunter_agent: Bug hunting agent.
        validator_agent: Finding validation agent.

    Returns:
        Configured swarm Pattern.
    """
    # Clone to avoid modifying originals
    hunter = hunter_agent.clone()
    validator = validator_agent.clone()

    # Set up bidirectional handoffs
    setup_bidirectional_handoffs(
        hunter,
        validator,
        description_a_to_b="Transfer to validator for bug confirmation",
        description_b_to_a="Transfer back to hunter for more bug discovery",
    )

    # Add instructions
    hunter.append_instructions(
        "\n\nWhen you discover potential vulnerabilities, "
        "transfer to the validator for confirmation."
    )
    validator.append_instructions(
        "\n\nAfter completing verification, transfer back to the hunter "
        "to continue bug discovery."
    )

    # Mark as swarm pattern
    hunter.pattern = "swarm"
    validator.pattern = "swarm"

    return swarm_pattern(
        name="bug_bounty_triage_swarm",
        entry_agent=hunter,
        description="Bug bounty triage with hunter and validator agents",
        agents=[hunter, validator],
    )
