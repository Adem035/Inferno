"""
Utility functions for working with patterns.

Provides helper functions for pattern management, validation,
and integration with the Inferno execution system.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from inferno.patterns.pattern import Pattern

logger = structlog.get_logger(__name__)


def is_swarm_pattern(agent: Any) -> bool:
    """
    Check if an agent is part of a swarm pattern.

    Detects swarm participation by checking:
    1. If the agent has a 'pattern' attribute set to 'swarm'
    2. If the agent has bidirectional handoffs (characteristic of swarms)

    Args:
        agent: The agent instance to check.

    Returns:
        True if the agent is part of a swarm pattern, False otherwise.

    Example:
        >>> from inferno.patterns.swarm import SwarmAgent, handoff
        >>> agent = SwarmAgent(name="test", config={})
        >>> agent.pattern = "swarm"
        >>> is_swarm_pattern(agent)
        True
    """
    # Check if the agent has a pattern attribute set to 'swarm'
    if hasattr(agent, "pattern") and agent.pattern == "swarm":
        return True

    # Check if the agent has bidirectional handoffs
    if hasattr(agent, "handoffs") and agent.handoffs:
        for handoff_obj in agent.handoffs:
            if not hasattr(handoff_obj, "agent_name"):
                continue

            # Get the target agent name from the handoff
            target_agent_name = handoff_obj.agent_name

            # Check if the target agent has a handoff back to this agent
            # by examining the handoff's on_invoke_handoff closure
            if hasattr(handoff_obj, "on_invoke_handoff"):
                closure_vars = getattr(
                    handoff_obj.on_invoke_handoff,
                    "__closure__",
                    None,
                )
                if closure_vars:
                    for cell in closure_vars:
                        try:
                            cell_contents = cell.cell_contents
                            # Check if this is an agent with handoffs
                            if (
                                hasattr(cell_contents, "name")
                                and hasattr(cell_contents, "handoffs")
                            ):
                                # Check if target has handoff back to this agent
                                for target_handoff in cell_contents.handoffs:
                                    if (
                                        hasattr(target_handoff, "agent_name")
                                        and hasattr(agent, "name")
                                        and target_handoff.agent_name == agent.name
                                    ):
                                        return True
                        except (ValueError, AttributeError):
                            continue

    return False


def handoff(
    agent: Any,
    tool_description_override: str | None = None,
    condition: Any | None = None,
) -> Any:
    """
    Create a handoff to another agent.

    This is a convenience function that creates a Handoff object
    for enabling agent-to-agent transfers in swarm patterns.

    Args:
        agent: The target agent for the handoff.
        tool_description_override: Custom description for the handoff tool.
        condition: Optional condition that must be true for handoff.

    Returns:
        Configured Handoff instance.

    Example:
        >>> from inferno.patterns.swarm import SwarmAgent
        >>> recon = SwarmAgent(name="recon", config={})
        >>> exploit = SwarmAgent(name="exploit", config={})
        >>> h = handoff(exploit, "Transfer to exploiter for attack")
        >>> recon.handoffs.append(h)
    """
    # Import here to avoid circular imports
    from inferno.patterns.swarm import Handoff

    description = tool_description_override or (
        f"Transfer to {getattr(agent, 'name', str(agent))} for specialized handling"
    )

    return Handoff(
        target_agent=agent,
        agent_name=getattr(agent, "name", str(agent)),
        tool_description=description,
        condition=condition,
    )


def validate_pattern(pattern: Pattern) -> list[str]:
    """
    Validate a pattern and return any issues found.

    Args:
        pattern: The pattern to validate.

    Returns:
        List of validation error messages (empty if valid).

    Example:
        >>> from inferno.patterns import parallel_pattern
        >>> p = parallel_pattern("test", agents=[])
        >>> errors = validate_pattern(p)
        >>> print(errors)
        ['PARALLEL pattern must have at least one agent config']
    """
    from inferno.patterns.pattern import PatternType

    errors: list[str] = []

    if not pattern.name:
        errors.append("Pattern name is required")

    if not pattern.type:
        errors.append("Pattern type is required")

    if pattern.type == PatternType.PARALLEL:
        if not pattern.configs:
            errors.append("PARALLEL pattern must have at least one agent config")

    elif pattern.type == PatternType.SWARM:
        if pattern.entry_agent is None:
            errors.append("SWARM pattern must have an entry agent")

    elif pattern.type == PatternType.HIERARCHICAL:
        if pattern.root_agent is None:
            errors.append("HIERARCHICAL pattern must have a root agent")
        if not pattern.agents:
            errors.append("HIERARCHICAL pattern must have at least one agent")

    elif pattern.type == PatternType.SEQUENTIAL:
        if not pattern.sequence:
            errors.append("SEQUENTIAL pattern must have at least one step")

    elif pattern.type == PatternType.CONDITIONAL:
        if not pattern.conditions:
            errors.append("CONDITIONAL pattern must have at least one condition")

    return errors


def list_pattern_agents(pattern: Pattern | str) -> list[str]:
    """
    Get a list of agent names from a pattern.

    Args:
        pattern: Pattern instance or pattern name.

    Returns:
        List of agent names in the pattern.

    Example:
        >>> from inferno.patterns import parallel_pattern
        >>> p = parallel_pattern("test", agents=["recon", "scanner"])
        >>> list_pattern_agents(p)
        ['recon', 'scanner']
    """
    from inferno.patterns.pattern import PatternType

    if isinstance(pattern, str):
        # Try to get pattern from registry
        from inferno.patterns import get_pattern
        resolved = get_pattern(pattern)
        if resolved is None:
            return []
        pattern = resolved

    if pattern.type == PatternType.PARALLEL:
        return [config.agent_name for config in pattern.configs]

    elif pattern.type == PatternType.SWARM or pattern.type == PatternType.HIERARCHICAL:
        return [getattr(agent, "name", str(agent)) for agent in pattern.agents]

    elif pattern.type == PatternType.SEQUENTIAL:
        return [
            getattr(s["agent"], "name", str(s["agent"]))
            for s in pattern.sequence
        ]

    elif pattern.type == PatternType.CONDITIONAL:
        return [
            getattr(cond["agent"], "name", str(cond["agent"]))
            for cond in pattern.conditions.values()
        ]

    return []


def get_pattern_description(pattern: Pattern) -> str:
    """
    Get a detailed description of a pattern.

    Args:
        pattern: The pattern to describe.

    Returns:
        Formatted description string.
    """
    from inferno.patterns.pattern import PatternType

    lines = [
        f"Pattern: {pattern.name}",
        f"Type: {pattern.type.value}",
        f"Description: {pattern.description or 'No description'}",
    ]

    agents = list_pattern_agents(pattern)
    if agents:
        lines.append(f"Agents ({len(agents)}): {', '.join(agents)}")

    if pattern.type == PatternType.SWARM:
        entry = getattr(pattern.entry_agent, "name", str(pattern.entry_agent))
        lines.append(f"Entry Agent: {entry}")

    elif pattern.type == PatternType.HIERARCHICAL:
        root = getattr(pattern.root_agent, "name", str(pattern.root_agent))
        lines.append(f"Root Agent: {root}")

    elif pattern.type == PatternType.SEQUENTIAL:
        lines.append(f"Steps: {len(pattern.sequence)}")

    elif pattern.type == PatternType.CONDITIONAL:
        lines.append(f"Conditions: {len(pattern.conditions)}")
        for name in pattern.conditions:
            lines.append(f"  - {name}")

    return "\n".join(lines)


def merge_patterns(
    name: str,
    patterns: list[Pattern],
    description: str = "",
) -> Pattern:
    """
    Merge multiple parallel patterns into one.

    Only works with PARALLEL patterns.

    Args:
        name: Name for the merged pattern.
        patterns: List of parallel patterns to merge.
        description: Description for the merged pattern.

    Returns:
        New merged Pattern instance.

    Raises:
        ValueError: If any pattern is not PARALLEL type.

    Example:
        >>> recon = parallel_pattern("recon", agents=["nmap", "gobuster"])
        >>> scan = parallel_pattern("scan", agents=["nuclei", "nikto"])
        >>> merged = merge_patterns("full", [recon, scan])
    """
    from inferno.patterns.pattern import Pattern, PatternType

    for p in patterns:
        if p.type != PatternType.PARALLEL:
            raise ValueError(
                f"Can only merge PARALLEL patterns, got {p.type.value}"
            )

    # Collect all configs
    all_configs = []
    for p in patterns:
        all_configs.extend(p.configs)

    return Pattern(
        name=name,
        type=PatternType.PARALLEL,
        description=description,
        configs=all_configs,
    )


def clone_pattern(pattern: Pattern, new_name: str) -> Pattern:
    """
    Create a copy of a pattern with a new name.

    Args:
        pattern: Pattern to clone.
        new_name: Name for the clone.

    Returns:
        New Pattern instance with copied configuration.

    Example:
        >>> original = parallel_pattern("recon", agents=["nmap"])
        >>> copy = clone_pattern(original, "recon_copy")
    """
    from inferno.patterns.pattern import Pattern

    return Pattern(
        name=new_name,
        type=pattern.type,
        description=pattern.description,
        configs=list(pattern.configs),
        entry_agent=pattern.entry_agent,
        agents=list(pattern.agents),
        root_agent=pattern.root_agent,
        sequence=list(pattern.sequence),
        conditions=dict(pattern.conditions),
        max_concurrent=pattern.max_concurrent,
        unified_context=pattern.unified_context,
        timeout=pattern.timeout,
        retry_on_failure=pattern.retry_on_failure,
        metadata=dict(pattern.metadata),
    )


def pattern_to_dict(pattern: Pattern) -> dict[str, Any]:
    """
    Convert a pattern to a serializable dictionary.

    Args:
        pattern: Pattern to convert.

    Returns:
        Dictionary representation of the pattern.
    """
    return pattern.to_dict()


def dict_to_pattern(data: dict[str, Any]) -> Pattern:
    """
    Create a pattern from a dictionary.

    Args:
        data: Dictionary containing pattern configuration.

    Returns:
        Pattern instance.

    Example:
        >>> data = {
        ...     "name": "test",
        ...     "type": "parallel",
        ...     "description": "Test pattern"
        ... }
        >>> p = dict_to_pattern(data)
    """
    from inferno.patterns.pattern import ParallelAgentConfig, Pattern

    pattern_type = data.get("type", "parallel")

    pattern = Pattern(
        name=data.get("name", ""),
        type=pattern_type,
        description=data.get("description", ""),
        max_concurrent=data.get("max_concurrent"),
        unified_context=data.get("unified_context", True),
        timeout=data.get("timeout"),
        retry_on_failure=data.get("retry_on_failure", False),
        metadata=data.get("metadata", {}),
    )

    # Handle type-specific data
    if pattern_type == "parallel" and "configs" in data:
        for config_data in data["configs"]:
            if isinstance(config_data, dict):
                pattern.configs.append(
                    ParallelAgentConfig(
                        agent_name=config_data.get("agent_name", ""),
                        unified_context=config_data.get("unified_context", True),
                        timeout=config_data.get("timeout"),
                        priority=config_data.get("priority", 0),
                    )
                )
            else:
                pattern.configs.append(
                    ParallelAgentConfig(agent_name=str(config_data))
                )

    return pattern
