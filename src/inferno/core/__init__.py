"""
Inferno Core Package.

Core functionality including:
- Scope management for authorized testing
- Shared Knowledge Graph for cross-agent context sharing
- Network Manager for global rate limiting and proxy coordination
- Branch tracking with response pattern detection
- Guardrails for security policies
- Intelligent Exploitation Engine (NEW):
  - HintExtractor: Extract hints from responses
  - ResponseAnalyzer: WAF/filter detection
  - DifferentialAnalyzer: Blind injection detection
  - PayloadMutator: Auto-bypass generation
  - AttackSelector: Technology-to-attack mapping

NOTE: Simplified in rebuild.
- CDN/Geo detection, credential manager, response cache removed
- Diminishing returns, CTF mode features removed
- CORS models removed
"""

from inferno.core.knowledge import (
    KnowledgeEntry,
    KnowledgeGraph,
    KnowledgeType,
    Severity,
    get_knowledge_graph,
)
from inferno.core.network import (
    NetworkManager,
    ProxyConfig,
    ProxyRotator,
    RateLimitConfig,
    RateLimitStrategy,
    UserAgentRotator,
    get_network_manager,
)
from inferno.core.scope import (
    ScopeAction,
    ScopeConfig,
    ScopeManager,
    ScopeRule,
    ScopeViolation,
    check_scope,
    configure_scope,
    get_scope_manager,
)
from inferno.core.branch_tracker import (
    BranchTracker,
    BranchOption,
    ExplorationResult,
    ResponsePatternTracker,
)
# Intelligent Exploitation Engine
from inferno.core.hint_extractor import (
    Hint,
    HintExtractor,
    HintPriority,
    HintType,
    get_hint_extractor,
)
from inferno.core.response_analyzer import (
    BlockAnalysis,
    BlockType,
    ResponseAnalyzer,
    WAFType,
    get_response_analyzer,
)
from inferno.core.differential_analyzer import (
    Difference,
    DifferenceType,
    DifferentialAnalyzer,
    DifferentialResult,
    ResponseFingerprint,
    VulnerabilityIndicator,
    get_differential_analyzer,
)
from inferno.core.payload_mutator import (
    Mutation,
    MutationResult,
    MutationType,
    PayloadMutator,
    get_payload_mutator,
)
from inferno.core.attack_selector import (
    AttackCategory,
    AttackPlan,
    AttackSelector,
    AttackVector,
    get_attack_selector,
)

__all__ = [
    # Scope Management
    "ScopeAction",
    "ScopeConfig",
    "ScopeManager",
    "ScopeRule",
    "ScopeViolation",
    "check_scope",
    "configure_scope",
    "get_scope_manager",
    # Knowledge Graph
    "KnowledgeGraph",
    "KnowledgeEntry",
    "KnowledgeType",
    "Severity",
    "get_knowledge_graph",
    # Network Manager
    "NetworkManager",
    "RateLimitConfig",
    "RateLimitStrategy",
    "ProxyConfig",
    "ProxyRotator",
    "UserAgentRotator",
    "get_network_manager",
    # Branch Tracking
    "BranchTracker",
    "BranchOption",
    "ExplorationResult",
    "ResponsePatternTracker",
    # Intelligent Exploitation Engine
    "Hint",
    "HintExtractor",
    "HintPriority",
    "HintType",
    "get_hint_extractor",
    "BlockAnalysis",
    "BlockType",
    "ResponseAnalyzer",
    "WAFType",
    "get_response_analyzer",
    "Difference",
    "DifferenceType",
    "DifferentialAnalyzer",
    "DifferentialResult",
    "ResponseFingerprint",
    "VulnerabilityIndicator",
    "get_differential_analyzer",
    "Mutation",
    "MutationResult",
    "MutationType",
    "PayloadMutator",
    "get_payload_mutator",
    "AttackCategory",
    "AttackPlan",
    "AttackSelector",
    "AttackVector",
    "get_attack_selector",
]
