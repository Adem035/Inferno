"""
Inferno Agent Package.

This module exports the main agent classes and execution loop
for the Inferno pentesting agent.
"""

from inferno.agent.prompts import (
    ObjectiveInfo,
    SystemPromptBuilder,
    TargetInfo,
    build_ctf_prompt,
    build_default_prompt,
)
from inferno.agent.sdk_executor import AssessmentConfig, ExecutionResult, SDKAgentExecutor

# Re-export AgentPersona from prompts for convenience
from inferno.prompts import AgentPersona

# Import the new unified Runner (CAI-inspired architecture)
from inferno.runner import (
    Agent,
    Handoff,
    InfernoRunner,
    NextStep,
    NextStepFinalOutput,
    NextStepHandoff,
    NextStepRunAgain,
    RunConfig,
    RunResult,
    handoff,
)

__all__ = [
    # New unified Runner (primary)
    "InfernoRunner",
    "RunConfig",
    "RunResult",
    "NextStep",
    "NextStepFinalOutput",
    "NextStepHandoff",
    "NextStepRunAgain",
    "Agent",
    "Handoff",
    "handoff",
    # Legacy executor (will be deprecated)
    "SDKAgentExecutor",
    "AssessmentConfig",
    "ExecutionResult",
    # Prompts
    "AgentPersona",
    "ObjectiveInfo",
    "SystemPromptBuilder",
    "TargetInfo",
    "build_ctf_prompt",
    "build_default_prompt",
]
