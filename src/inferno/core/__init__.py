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

from inferno.core.attack_selector import (
    AttackCategory,
    AttackPlan,
    AttackSelector,
    AttackVector,
    get_attack_selector,
)
from inferno.core.branch_tracker import (
    BranchOption,
    BranchTracker,
    ExplorationResult,
    ResponsePatternTracker,
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

# Guardrails (security policies)
from inferno.core.guardrails import (
    GuardrailAction,
    GuardrailEngine,
    GuardrailPolicy,
    GuardrailResult,
    GuardrailType,
    GuardrailViolation,
    GuardrailViolationError,
    check_encoded_payload,
    detect_homograph_bypass,
    detect_injection_patterns,
    get_guardrail_engine,
    get_security_guardrails,
    guarded_tool,
    input_guardrail,
    normalize_unicode_homographs,
    output_guardrail,
    sanitize_external_content,
)

# Intelligent Exploitation Engine
from inferno.core.hint_extractor import (
    Hint,
    HintExtractor,
    HintPriority,
    HintType,
    get_hint_extractor,
)
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
from inferno.core.payload_mutator import (
    Mutation,
    MutationResult,
    MutationType,
    PayloadMutator,
    get_payload_mutator,
)
from inferno.core.response_analyzer import (
    BlockAnalysis,
    BlockType,
    ResponseAnalyzer,
    WAFType,
    get_response_analyzer,
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
    # Guardrails
    "GuardrailType",
    "GuardrailAction",
    "GuardrailPolicy",
    "GuardrailResult",
    "GuardrailViolation",
    "GuardrailEngine",
    "GuardrailViolationError",
    "get_guardrail_engine",
    "guarded_tool",
    "input_guardrail",
    "output_guardrail",
    "normalize_unicode_homographs",
    "detect_homograph_bypass",
    "check_encoded_payload",
    "sanitize_external_content",
    "detect_injection_patterns",
    "get_security_guardrails",
]
