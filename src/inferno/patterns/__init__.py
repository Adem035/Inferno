"""
Inferno Patterns Package.

This module provides coordination patterns for multi-agent execution
in penetration testing operations. Ported from CAI's proven patterns.

Pattern Types:
- PARALLEL: Execute multiple agents concurrently
- SWARM: Handoff-based agent coordination with state transfer
- HIERARCHICAL: Parent-child agent relationships
- SEQUENTIAL: Ordered agent execution
- CONDITIONAL: Rule-based agent selection

Example:
    from inferno.patterns import Pattern, PatternType, is_swarm_pattern, handoff

    # Create a parallel pattern
    pattern = Pattern(
        name="recon_parallel",
        type=PatternType.PARALLEL,
        description="Parallel reconnaissance",
    )

    # Check if an agent uses swarm pattern
    if is_swarm_pattern(agent):
        next_agent = handoff(target_agent)
"""

from inferno.patterns.pattern import (
    ParallelAgentConfig,
    Pattern,
    PatternType,
)
from inferno.patterns.utils import (
    clone_pattern,
    dict_to_pattern,
    get_pattern_description,
    handoff,
    is_swarm_pattern,
    list_pattern_agents,
    merge_patterns,
    pattern_to_dict,
    validate_pattern,
)

__all__ = [
    # Core pattern types
    "Pattern",
    "PatternType",
    "ParallelAgentConfig",
    # Utility functions
    "is_swarm_pattern",
    "handoff",
    "validate_pattern",
    "list_pattern_agents",
    "get_pattern_description",
    "merge_patterns",
    "clone_pattern",
    "pattern_to_dict",
    "dict_to_pattern",
]
