"""
Inferno Swarm Package.

This module exports the swarm-as-tool pattern for spawning
specialized sub-agents, and the MetaCoordinator for subagent-driven
assessments.

Architecture:
- SwarmTool: Spawn individual subagents on demand
- MetaCoordinator: Orchestrate full assessment via worker subagents
  - Coordinator ONLY plans, validates, and synthesizes
  - Worker subagents do ALL actual work (recon, exploit, report)

Communication:
- Memory: Subagents share Mem0/Qdrant memory (same operation_id)
- MessageBus: Real-time inter-agent communication
  - Broadcast findings, endpoints, attack chains
  - Request/response between specific agents
"""

from inferno.swarm.agents import SubAgentConfig, SubAgentType
from inferno.swarm.message_bus import (
    Message,
    MessageBus,
    MessagePriority,
    MessageType,
    get_message_bus,
    publish_chain,
    publish_endpoint,
    publish_finding,
    request_validation,
    reset_message_bus,
)
from inferno.swarm.meta_coordinator import (
    AssessmentPhase,
    AssessmentState,
    Finding,
    FindingStatus,
    MetaCoordinator,
    WorkerTask,
    WorkerType,
)
from inferno.swarm.tool import SwarmTool

__all__ = [
    # Swarm tool (original)
    "SwarmTool",
    "SubAgentType",
    "SubAgentConfig",
    # MetaCoordinator (new subagent-driven architecture)
    "MetaCoordinator",
    "AssessmentPhase",
    "WorkerType",
    "WorkerTask",
    "Finding",
    "FindingStatus",
    "AssessmentState",
    # MessageBus (inter-agent communication)
    "MessageBus",
    "MessageType",
    "MessagePriority",
    "Message",
    "get_message_bus",
    "reset_message_bus",
    "publish_finding",
    "publish_endpoint",
    "publish_chain",
    "request_validation",
]
