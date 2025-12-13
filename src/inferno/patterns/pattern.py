"""
Unified Pattern class with type-based behavior.

This module provides a single Pattern class that adapts its behavior
based on the pattern type (parallel, swarm, hierarchical, etc.).
Designed for Inferno's penetration testing agent coordination.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PatternType(Enum):
    """Enumeration of available pattern types for agent coordination."""

    PARALLEL = "parallel"
    SWARM = "swarm"
    HIERARCHICAL = "hierarchical"
    SEQUENTIAL = "sequential"
    CONDITIONAL = "conditional"

    @classmethod
    def from_string(cls, value: str) -> PatternType:
        """
        Convert string to PatternType.

        Args:
            value: String representation of the pattern type.

        Returns:
            Corresponding PatternType enum value.

        Raises:
            ValueError: If the value is not a valid pattern type.
        """
        try:
            return cls(value.lower())
        except ValueError:
            valid_types = [t.value for t in cls]
            raise ValueError(
                f"Invalid pattern type: {value}. Valid types: {valid_types}"
            )


@dataclass
class ParallelAgentConfig:
    """Configuration for an agent in a parallel execution pattern."""

    agent_name: str
    unified_context: bool = True
    timeout: float | None = None
    priority: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.agent_name:
            raise ValueError("agent_name cannot be empty")


@dataclass
class Pattern:
    """
    Unified pattern class that adapts behavior based on type.

    This class uses the type attribute to determine how to handle
    configurations and execution flow for different agent coordination
    patterns used in penetration testing operations.

    Attributes:
        name: Unique identifier for the pattern.
        type: The type of pattern (parallel, swarm, etc.).
        description: Human-readable description of the pattern.
        configs: Agent configurations for parallel execution.
        entry_agent: Starting agent for swarm patterns.
        agents: List of agents involved in the pattern.
        root_agent: Root coordinator for hierarchical patterns.
        sequence: Ordered list of agents for sequential execution.
        conditions: Conditional branches for conditional patterns.
        max_concurrent: Maximum concurrent agents for parallel execution.
        unified_context: Whether agents share context.
        timeout: Maximum execution time in seconds.
        retry_on_failure: Whether to retry failed agents.
        metadata: Additional pattern-specific data.
    """

    name: str
    type: PatternType | str
    description: str = ""

    # Type-specific attributes
    configs: list[ParallelAgentConfig] = field(default_factory=list)
    entry_agent: Any | None = None
    agents: list[Any] = field(default_factory=list)
    root_agent: Any | None = None
    sequence: list[dict[str, Any]] = field(default_factory=list)
    conditions: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Common configuration options
    max_concurrent: int | None = None
    unified_context: bool = True
    timeout: float | None = None
    retry_on_failure: bool = False

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Initialize pattern type and validate."""
        if isinstance(self.type, str):
            self.type = PatternType.from_string(self.type)

        # Initialize type-specific defaults
        self._initialize_for_type()

    def _initialize_for_type(self) -> None:
        """Initialize attributes based on pattern type."""
        if self.type == PatternType.PARALLEL:
            if not hasattr(self, "_parallel_initialized"):
                self._parallel_initialized = True

        elif self.type == PatternType.SWARM:
            if not hasattr(self, "_swarm_initialized"):
                self._swarm_initialized = True

        elif self.type == PatternType.HIERARCHICAL:
            if not hasattr(self, "_hierarchical_initialized"):
                self._hierarchical_initialized = True

        elif self.type == PatternType.SEQUENTIAL:
            if not hasattr(self, "_sequential_initialized"):
                self._sequential_initialized = True

        elif self.type == PatternType.CONDITIONAL:
            if not hasattr(self, "_conditional_initialized"):
                self._conditional_initialized = True

    def add_parallel_agent(
        self,
        agent: str | ParallelAgentConfig,
    ) -> Pattern:
        """
        Add an agent for parallel execution.

        Args:
            agent: Agent name or ParallelAgentConfig instance.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If pattern is not PARALLEL type.
        """
        if self.type != PatternType.PARALLEL:
            raise ValueError(
                f"add_parallel_agent only works for PARALLEL patterns, "
                f"not {self.type.value}"
            )

        if isinstance(agent, str):
            agent = ParallelAgentConfig(
                agent_name=agent,
                unified_context=self.unified_context,
            )

        self.configs.append(agent)
        return self

    def set_entry_agent(self, agent: Any) -> Pattern:
        """
        Set the entry agent for swarm patterns.

        The entry agent is the first agent that receives the task
        and can hand off to other agents in the swarm.

        Args:
            agent: The entry agent instance or configuration.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If pattern is not SWARM type.
        """
        if self.type != PatternType.SWARM:
            raise ValueError(
                f"set_entry_agent only works for SWARM patterns, "
                f"not {self.type.value}"
            )

        self.entry_agent = agent
        if agent not in self.agents:
            self.agents.append(agent)
        return self

    def set_root_agent(self, agent: Any) -> Pattern:
        """
        Set the root agent for hierarchical patterns.

        The root agent coordinates child agents and aggregates results.

        Args:
            agent: The root coordinator agent.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If pattern is not HIERARCHICAL type.
        """
        if self.type != PatternType.HIERARCHICAL:
            raise ValueError(
                f"set_root_agent only works for HIERARCHICAL patterns, "
                f"not {self.type.value}"
            )

        self.root_agent = agent
        if agent not in self.agents:
            self.agents.append(agent)
        return self

    def add_sequence_step(
        self,
        agent: Any,
        wait_for_previous: bool = True,
    ) -> Pattern:
        """
        Add a step to sequential execution.

        Args:
            agent: Agent to add to the sequence.
            wait_for_previous: Whether to wait for previous step to complete.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If pattern is not SEQUENTIAL type.
        """
        if self.type != PatternType.SEQUENTIAL:
            raise ValueError(
                f"add_sequence_step only works for SEQUENTIAL patterns, "
                f"not {self.type.value}"
            )

        self.sequence.append({
            "agent": agent,
            "wait_for_previous": wait_for_previous,
        })
        return self

    def add_condition(
        self,
        condition_name: str,
        agent: Any,
        predicate: Callable[..., bool] | None = None,
    ) -> Pattern:
        """
        Add a conditional branch.

        Args:
            condition_name: Name identifying the condition.
            agent: Agent to execute if condition is met.
            predicate: Optional callable that returns True if condition is met.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If pattern is not CONDITIONAL type.
        """
        if self.type != PatternType.CONDITIONAL:
            raise ValueError(
                f"add_condition only works for CONDITIONAL patterns, "
                f"not {self.type.value}"
            )

        self.conditions[condition_name] = {
            "agent": agent,
            "predicate": predicate,
        }
        return self

    def add(self, item: Any) -> Pattern:
        """
        Generic add method that works based on pattern type.

        Args:
            item: Item to add (agent, config, or condition tuple).

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If item format is invalid for pattern type.
        """
        if self.type == PatternType.PARALLEL:
            return self.add_parallel_agent(item)
        elif self.type == PatternType.SWARM or self.type == PatternType.HIERARCHICAL:
            self.agents.append(item)
            return self
        elif self.type == PatternType.SEQUENTIAL:
            return self.add_sequence_step(item)
        elif self.type == PatternType.CONDITIONAL:
            if isinstance(item, tuple) and len(item) >= 2:
                return self.add_condition(
                    item[0],
                    item[1],
                    item[2] if len(item) > 2 else None,
                )
            raise ValueError(
                "Conditional patterns expect (name, agent, predicate) tuples"
            )

        return self

    def validate(self) -> bool:
        """
        Validate pattern based on its type.

        Returns:
            True if pattern is valid, False otherwise.
        """
        if not self.name or not self.type:
            return False

        if self.type == PatternType.PARALLEL:
            return len(self.configs) > 0

        elif self.type == PatternType.SWARM:
            return self.entry_agent is not None

        elif self.type == PatternType.HIERARCHICAL:
            return self.root_agent is not None and len(self.agents) > 0

        elif self.type == PatternType.SEQUENTIAL:
            return len(self.sequence) > 0

        elif self.type == PatternType.CONDITIONAL:
            return len(self.conditions) > 0

        return True

    def to_dict(self) -> dict[str, Any]:
        """
        Convert pattern to dictionary representation.

        Returns:
            Dictionary containing pattern configuration.
        """
        base: dict[str, Any] = {
            "name": self.name,
            "type": self.type.value,
            "description": self.description,
            "metadata": self.metadata,
        }

        if self.type == PatternType.PARALLEL:
            base["configs"] = [
                {
                    "agent_name": c.agent_name,
                    "unified_context": c.unified_context,
                    "timeout": c.timeout,
                    "priority": c.priority,
                }
                for c in self.configs
            ]
            base["max_concurrent"] = self.max_concurrent
            base["unified_context"] = self.unified_context

        elif self.type == PatternType.SWARM:
            base["entry_agent"] = getattr(
                self.entry_agent, "name", str(self.entry_agent)
            )
            base["agents"] = [
                getattr(a, "name", str(a)) for a in self.agents
            ]

        elif self.type == PatternType.HIERARCHICAL:
            base["root_agent"] = getattr(
                self.root_agent, "name", str(self.root_agent)
            )
            base["agents"] = [
                getattr(a, "name", str(a)) for a in self.agents
            ]

        elif self.type == PatternType.SEQUENTIAL:
            base["sequence"] = [
                {
                    "agent": getattr(s["agent"], "name", str(s["agent"])),
                    "wait_for_previous": s.get("wait_for_previous", True),
                }
                for s in self.sequence
            ]

        elif self.type == PatternType.CONDITIONAL:
            base["conditions"] = {
                name: {
                    "agent": getattr(cond["agent"], "name", str(cond["agent"])),
                    "has_predicate": cond.get("predicate") is not None,
                }
                for name, cond in self.conditions.items()
            }

        return base

    def get_agents(self) -> list[Any]:
        """
        Get all agents involved in this pattern.

        Returns:
            List of agents (format depends on pattern type).
        """
        if self.type == PatternType.PARALLEL:
            return [c.agent_name for c in self.configs]

        elif self.type == PatternType.SWARM or self.type == PatternType.HIERARCHICAL:
            return self.agents

        elif self.type == PatternType.SEQUENTIAL:
            return [s["agent"] for s in self.sequence]

        elif self.type == PatternType.CONDITIONAL:
            return [cond["agent"] for cond in self.conditions.values()]

        return []

    def __repr__(self) -> str:
        """String representation of the pattern."""
        agent_count = len(self.get_agents())
        return (
            f"Pattern(name='{self.name}', type={self.type.value}, "
            f"agents={agent_count})"
        )


# Factory functions for creating patterns


def parallel_pattern(
    name: str,
    description: str = "",
    agents: list[str] | None = None,
    **kwargs: Any,
) -> Pattern:
    """
    Create a parallel execution pattern.

    Parallel patterns execute multiple agents simultaneously,
    useful for running independent security tests in parallel.

    Args:
        name: Pattern name.
        description: Pattern description.
        agents: List of agent names to run in parallel.
        **kwargs: Additional pattern configuration.

    Returns:
        Configured Pattern instance.

    Example:
        >>> pattern = parallel_pattern(
        ...     "recon_parallel",
        ...     description="Run all recon tools in parallel",
        ...     agents=["port_scanner", "subdomain_enum", "tech_detector"]
        ... )
    """
    pattern = Pattern(
        name=name,
        type=PatternType.PARALLEL,
        description=description,
        **kwargs,
    )

    if agents:
        for agent in agents:
            pattern.add_parallel_agent(agent)

    return pattern


def swarm_pattern(
    name: str,
    entry_agent: Any,
    description: str = "",
    agents: list[Any] | None = None,
    **kwargs: Any,
) -> Pattern:
    """
    Create a swarm collaboration pattern.

    Swarm patterns enable agents to hand off tasks to each other
    dynamically based on the current context and findings.

    Args:
        name: Pattern name.
        entry_agent: The starting agent for the swarm.
        description: Pattern description.
        agents: Additional agents in the swarm.
        **kwargs: Additional pattern configuration.

    Returns:
        Configured Pattern instance.

    Example:
        >>> pattern = swarm_pattern(
        ...     "pentest_swarm",
        ...     entry_agent=recon_agent,
        ...     description="Coordinated pentest with dynamic handoffs",
        ...     agents=[scanner_agent, exploiter_agent, validator_agent]
        ... )
    """
    pattern = Pattern(
        name=name,
        type=PatternType.SWARM,
        description=description,
        **kwargs,
    )
    pattern.set_entry_agent(entry_agent)

    if agents:
        pattern.agents.extend(agents)

    return pattern


def hierarchical_pattern(
    name: str,
    root_agent: Any,
    description: str = "",
    children: list[Any] | None = None,
    **kwargs: Any,
) -> Pattern:
    """
    Create a hierarchical pattern.

    Hierarchical patterns have a root coordinator that delegates
    tasks to child agents and aggregates their results.

    Args:
        name: Pattern name.
        root_agent: The root coordinator agent.
        description: Pattern description.
        children: Child agents under the root.
        **kwargs: Additional pattern configuration.

    Returns:
        Configured Pattern instance.

    Example:
        >>> pattern = hierarchical_pattern(
        ...     "coordinated_assessment",
        ...     root_agent=meta_coordinator,
        ...     description="Coordinator delegates to specialized workers",
        ...     children=[recon_worker, exploit_worker, report_worker]
        ... )
    """
    pattern = Pattern(
        name=name,
        type=PatternType.HIERARCHICAL,
        description=description,
        **kwargs,
    )
    pattern.set_root_agent(root_agent)

    if children:
        pattern.agents.extend(children)

    return pattern


def sequential_pattern(
    name: str,
    steps: list[Any],
    description: str = "",
    **kwargs: Any,
) -> Pattern:
    """
    Create a sequential execution pattern.

    Sequential patterns execute agents in order, passing results
    from each step to the next.

    Args:
        name: Pattern name.
        steps: Ordered list of agents to execute.
        description: Pattern description.
        **kwargs: Additional pattern configuration.

    Returns:
        Configured Pattern instance.

    Example:
        >>> pattern = sequential_pattern(
        ...     "standard_pentest",
        ...     steps=[recon_agent, scanner_agent, exploiter_agent, reporter_agent],
        ...     description="Standard penetration testing workflow"
        ... )
    """
    pattern = Pattern(
        name=name,
        type=PatternType.SEQUENTIAL,
        description=description,
        **kwargs,
    )

    for step in steps:
        pattern.add_sequence_step(step)

    return pattern


def conditional_pattern(
    name: str,
    conditions: dict[str, Any],
    description: str = "",
    **kwargs: Any,
) -> Pattern:
    """
    Create a conditional execution pattern.

    Conditional patterns select agents based on runtime conditions,
    enabling dynamic workflow branching.

    Args:
        name: Pattern name.
        conditions: Dictionary mapping condition names to agents.
        description: Pattern description.
        **kwargs: Additional pattern configuration.

    Returns:
        Configured Pattern instance.

    Example:
        >>> pattern = conditional_pattern(
        ...     "adaptive_exploit",
        ...     conditions={
        ...         "web_vuln": web_exploiter,
        ...         "network_vuln": network_exploiter,
        ...         "auth_bypass": auth_exploiter,
        ...     },
        ...     description="Select exploiter based on vulnerability type"
        ... )
    """
    pattern = Pattern(
        name=name,
        type=PatternType.CONDITIONAL,
        description=description,
        **kwargs,
    )

    for cond_name, agent in conditions.items():
        pattern.add_condition(cond_name, agent)

    return pattern
