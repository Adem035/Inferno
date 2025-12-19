"""
Inferno Dynamic Prompts Package.

SIMPLIFIED ARCHITECTURE (Dec 2025):
- dynamic_generator.py: Task-specific prompt generation with context awareness
- NO static templates - everything is generated dynamically based on:
  - Task type (recon, exploit, validate, report)
  - Detected technology stack
  - MITRE ATT&CK technique mapping
  - Previous findings and failed attempts
  - Scope constraints

Philosophy:
- Less is more - smaller prompts = better focus
- Task-specific > general methodology lectures
- Tool hints > academic security theory
- Runtime context > static boilerplate
"""

from enum import Enum

from inferno.prompts.dynamic_generator import (
    EXPLOIT_TOOLS,
    RECON_TOOLS,
    VALIDATION_APPROACHES,
    DynamicPromptGenerator,
    TaskContext,
    TaskType,
    TechStack,
    generate_prompt,
    get_generator,
)


class AgentPersona(str, Enum):
    """Agent persona types for prompt generation."""

    THOROUGH = "thorough"  # Comprehensive assessment
    AGGRESSIVE = "aggressive"  # Aggressive, fast exploitation
    STEALTH = "stealth"  # Quiet, avoid detection
    BUG_BOUNTY = "bug_bounty"  # Impact-focused


__all__ = [
    # Core generator
    "DynamicPromptGenerator",
    "get_generator",
    "generate_prompt",
    # Context classes
    "TaskContext",
    "TaskType",
    "TechStack",
    # Persona
    "AgentPersona",
    # Tool hints (for direct access)
    "EXPLOIT_TOOLS",
    "RECON_TOOLS",
    "VALIDATION_APPROACHES",
]
