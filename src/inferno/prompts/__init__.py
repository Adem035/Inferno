"""
Inferno Prompts Package.

This module provides a modular prompt system for assembling
context-aware system prompts for the penetration testing agent.

ARCHITECTURE:
- engine.py: Dynamic prompt assembly from markdown templates
- templates/: Core identity and report templates
- behaviors/: Composable behavior modules (exploitation, cognitive loop, etc.)
- phases/: Phase-specific guidance (recon, enumeration, exploitation)
- contexts/: Target-type specific guidance (web, API, network, CTF)
- tools/: Tool usage protocols
- techniques/: Detailed technique guides (exploitation, API security, etc.)
- swarm/: Swarm agent role prompts
- strategic/: Strategic context templates (Mako-based)
"""

from inferno.prompts.base import (
    AgentPersona,
    PromptContext,
    PromptModule,
    PromptPriority,
)

# Main prompt engine (primary system)
from inferno.prompts.engine import (
    SWARM_ROLE_FILES,
    PromptEngine,
    build_continuation_prompt,
    build_coordinator_prompt,
    build_report_prompt,
    # Swarm agent prompts
    build_swarm_agent_prompt,
    build_system_prompt,
    detect_context_type,
    get_checkpoint_prompt,
    get_engine,
)

# Mako template engine (advanced dynamic prompts)
from inferno.prompts.mako_engine import (
    MakoPromptEngine,
    SystemPromptRenderer,
    TemplateContext,
    create_system_prompt_renderer,
    get_mako_engine,
    render_prompt,
)

__all__ = [
    # Engine-based system (primary)
    "PromptEngine",
    "get_engine",
    "build_system_prompt",
    "build_report_prompt",
    "build_continuation_prompt",
    "get_checkpoint_prompt",
    "detect_context_type",
    # Swarm agent prompts
    "build_swarm_agent_prompt",
    "build_coordinator_prompt",
    "SWARM_ROLE_FILES",
    # Mako template engine
    "MakoPromptEngine",
    "TemplateContext",
    "SystemPromptRenderer",
    "create_system_prompt_renderer",
    "get_mako_engine",
    "render_prompt",
    # Base classes (for type hints)
    "AgentPersona",
    "PromptContext",
    "PromptModule",
    "PromptPriority",
]
