"""
Agent executor using Claude Agent SDK.

This module provides the Inferno agent executor using the official
Claude Agent SDK, which supports OAuth authentication and has
built-in tools (Bash, Read, Write, etc.).

SIMPLIFIED ARCHITECTURE:
- ONE unified execute_command tool instead of 81 specialized tools
- Let the LLM decide what commands to run - it knows pentest tools
- Keep only: execute_command, HTTP, memory, think
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    PermissionResultAllow,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolPermissionContext,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from inferno.agent.mcp_tools import (
    configure_memory,
    create_inferno_mcp_server,
    set_operation_id,
    set_target,
)
from inferno.config.settings import InfernoSettings

# Memory tool (kept)
try:
    from inferno.tools.memory import MemoryToolWithFallback
    MEMORY_TOOL_AVAILABLE = True
except ImportError:
    MEMORY_TOOL_AVAILABLE = False

# Branch tracker (kept - unique, useful feature)
# System prompt builder (kept)
from inferno.agent.prompts import SystemPromptBuilder
from inferno.core.branch_tracker import BranchTracker

# Session trace for user visibility
from inferno.observability.session_trace import (
    SessionTrace,
    init_session_trace,
)
from inferno.prompts import AgentPersona

# Algorithm learning integration (wiring dead code into execution)
try:
    from inferno.algorithms.integration import (
        LoopIntegration,
        get_loop_integration,
    )
    ALGORITHM_LEARNING_AVAILABLE = True
except ImportError:
    ALGORITHM_LEARNING_AVAILABLE = False

# Attack intelligence for smarter exploitation
try:
    from inferno.core.attack_selector import AttackSelector, get_attack_selector
    from inferno.core.hint_extractor import HintExtractor, get_hint_extractor
    ATTACK_INTELLIGENCE_AVAILABLE = True
except ImportError:
    ATTACK_INTELLIGENCE_AVAILABLE = False

# Guardrails (kept - security critical)
try:
    from inferno.core.guardrails import (
        GuardrailAction,
        GuardrailEngine,
        GuardrailResult,
        get_guardrail_engine,
    )
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False

# Strategic planning - generates attack plans before execution
try:
    from inferno.agent.strategic_planner import (
        AttackPlan,
        StrategicPlanner,
    )
    STRATEGIC_PLANNING_AVAILABLE = True
except ImportError:
    STRATEGIC_PLANNING_AVAILABLE = False

# NOTE: Other advanced features removed in rebuild:
# - DiminishingReturnsTracker, FlagDetector, CTFPayloadBlaster
# - ChainEnumerator, ValidationOrchestrator
# - ApplicationModel, ParameterRoleAnalyzer (integrated into StrategicPlanner)
# - VulnerabilityScorer, MLScoringEngine, QualityGatePipeline

VULNERABILITY_SCORER_AVAILABLE = False
ML_SCORING_AVAILABLE = False
QUALITY_GATES_AVAILABLE = False

logger = structlog.get_logger(__name__)


def sanitize_bracket_tags(text: str) -> str:
    """
    Sanitize bracket tags that might be parsed as XML/BBCode.

    Some tools output text with square bracket tags like [OPT], [/OPT]
    which can be misinterpreted by parsers. This replaces them with
    parentheses to prevent parsing errors.
    """
    import re
    # Replace [TAG] and [/TAG] style markers with (TAG) and (/TAG)
    # Matches: [TAG], [/TAG], [22], [DATA], [OPT], etc.
    return re.sub(r'\[(/?)([A-Za-z0-9_]{1,20})\]', r'(\1\2)', text)


@dataclass
class ExecutionResult:
    """Result of an agent execution."""

    operation_id: str
    objective_met: bool
    findings_summary: str | None
    confidence: int | None
    stop_reason: str
    turns: int
    total_cost_usd: float
    total_tokens: int
    duration_seconds: float
    artifacts_dir: str
    started_at: datetime
    ended_at: datetime
    error: str | None = None
    final_message: str | None = None
    continuations: int = 0
    flags_found: list[str] = field(default_factory=list)  # CTF mode
    trace_json_path: str | None = None  # Path to session trace JSON
    trace_html_path: str | None = None  # Path to session trace HTML

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operation_id": self.operation_id,
            "objective_met": self.objective_met,
            "findings_summary": self.findings_summary,
            "confidence": self.confidence,
            "stop_reason": self.stop_reason,
            "turns": self.turns,
            "total_cost_usd": self.total_cost_usd,
            "total_tokens": self.total_tokens,
            "duration_seconds": self.duration_seconds,
            "artifacts_dir": self.artifacts_dir,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "error": self.error,
            "final_message": self.final_message,
            "continuations": self.continuations,
            "flags_found": self.flags_found,
            "trace_json_path": self.trace_json_path,
            "trace_html_path": self.trace_html_path,
        }


@dataclass
class AssessmentConfig:
    """Configuration for a security assessment."""

    target: str
    objective: str
    scope: str = "as provided"
    target_type: str = "unknown"
    success_criteria: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    max_turns: int = 500  # High default - let token limit be the real constraint
    model: str | None = None
    working_dir: str | None = None
    permission_mode: str = "default"  # "default", "acceptEdits", "plan", "bypassPermissions"

    # Mode options
    mode: str = "web"  # "web", "api", "network", "ctf", "cloud"
    auto_continue: bool = True  # Continue if objectives not met
    max_continuations: int = 5  # Max times to continue after max_turns
    scope_config: dict[str, Any] | None = None  # Scope configuration
    enable_waf_detection: bool = True  # Auto-detect WAF
    ctf_mode: bool = False  # CTF mode (more aggressive)

    # Advanced features (Vulnetic-inspired improvements)
    enable_branch_tracking: bool = True  # Track decision points for backtracking
    enable_chain_enumeration: bool = True  # Systematic attack chain enumeration
    auto_validate_findings: bool = False  # Validate findings (requires API key, uses extra tokens)

    # Subagent spawning thresholds (faster than defaults for Vulnetic-like performance)
    subagent_trigger_interval: int = 5  # Trigger subagent every N turns without progress
    subagent_error_threshold: int = 2  # Spawn error-handling subagent after N consecutive errors
    subagent_no_findings_threshold: int = 8  # Spawn exploration subagent if no findings after N turns

    # Persona selection
    persona: str = "thorough"  # "thorough", "ctf", "stealth"

    # ML & AI-enhanced features (ALL ENABLED BY DEFAULT)
    enable_ml_scoring: bool = True  # ML-enhanced vulnerability classification
    enable_performance_optimizer: bool = True  # Connection pooling, request batching
    enable_security_hardening: bool = True  # Prompt injection, SSRF protection
    enable_parallel_execution: bool = True  # 3x faster tool execution

    # Diminishing returns tracking
    enable_diminishing_returns: bool = True  # Track and detect diminishing returns
    diminishing_returns_window: int = 10  # Window size for trend analysis
    diminishing_returns_threshold: float = 0.3  # Success rate decline threshold

    # Parallel initial reconnaissance (CTF optimization)
    enable_parallel_initial_recon: bool = True  # Auto-spawn parallel recon at start
    parallel_recon_agents: list[str] = field(default_factory=lambda: ["reconnaissance", "scanner"])

    # Guardrails - CAI-inspired security policies
    enable_guardrails: bool = True  # Enable security guardrails
    guardrail_block_on_violation: bool = True  # Block on critical violations
    guardrail_log_violations: bool = True  # Log all violations

    # Strategic planning features (NEW)
    enable_strategic_planning: bool = True  # Enable strategic planning phase
    strategic_budget_allocation: dict[str, float] | None = None  # Custom budget allocation per phase

    # Session trace for visibility into what Inferno does
    enable_session_trace: bool = True  # Enable detailed session trace logging
    session_trace_output_dir: Path | None = None  # Custom output dir for traces


class SDKAgentExecutor:
    """
    Agent executor using Claude Agent SDK with advanced features.

    This executor uses the official Claude Agent SDK which:
    - Supports OAuth authentication (uses Claude Max subscription)
    - Has built-in tools (Bash, Read, Write, Edit, Glob, Grep, etc.)
    - Supports custom MCP tools
    - Handles conversation state automatically

    Advanced features (ported from AgentExecutor):
    - Branch tracking for systematic exploration and backtracking
    - Attack chain enumeration for comprehensive exploitation
    - Diminishing returns tracking to avoid wasted effort
    - CTF-optimized aggressive mode for speed
    - Faster subagent spawning thresholds
    - SystemPromptBuilder with personas
    - Strategic planning for proactive assessment
    """

    def __init__(
        self,
        settings: InfernoSettings | None = None,
        output_dir: Path | None = None,
    ) -> None:
        """
        Initialize the SDK agent executor.

        Args:
            settings: Inferno settings.
            output_dir: Base directory for output artifacts.
        """
        self._settings = settings or InfernoSettings()
        self._output_dir = output_dir or self._settings.output.base_dir

        # Callbacks
        self._on_message: Callable[[str], None] | None = None
        self._on_tool_call: Callable[[str, dict], None] | None = None
        self._on_tool_result: Callable[[str, str, bool], None] | None = None
        self._on_thinking: Callable[[str], None] | None = None
        self._on_complete: Callable[[ExecutionResult], None] | None = None
        # Dashboard-specific callbacks
        self._on_turn: Callable[[int, int, float], None] | None = None  # turn, tokens, cost
        self._on_finding: Callable[[str, str, str], None] | None = None  # title, severity, location
        self._on_subagent_spawn: Callable[[str, str], None] | None = None  # id, type
        self._on_subagent_complete: Callable[[str], None] | None = None  # id
        self._on_validation: Callable[[str, str, int], None] | None = None  # title, result, confidence

        # Branch tracker (kept - unique, useful feature)
        self._branch_tracker: BranchTracker | None = None

        # CTF mode flag (simplified)
        self._ctf_mode: bool = False

        # Guardrails engine for security policy enforcement (kept - security critical)
        self._guardrail_engine: GuardrailEngine | None = None
        if GUARDRAILS_AVAILABLE:
            try:
                self._guardrail_engine = get_guardrail_engine()
                logger.info("guardrail_engine_initialized")
            except Exception as e:
                logger.warning("guardrail_engine_init_failed", error=str(e))

        # Agent ID for tracking
        self._agent_id: str = f"main_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}"

        # NOTE: Features removed in rebuild - set to None for compatibility
        # These checks are still in the codebase but will be no-ops
        self._chain_enumerator = None
        self._validation_orchestrator = None
        self._vulnerability_scorer = None
        self._ml_engine = None
        self._diminishing_tracker = None
        self._flag_detector = None
        self._payload_blaster = None
        self._quality_pipeline = None
        self._app_model = None
        self._param_analyzer = None
        self._planner = None
        self._coordinator = None

        # Progress tracking for subagent spawning decisions
        self._turns_without_progress: int = 0
        self._consecutive_errors: int = 0
        self._turns_without_findings: int = 0
        self._last_finding_turn: int = 0
        self._findings_count: int = 0

        # Current attack category tracking (for diminishing returns)
        self._current_category: str = "reconnaissance"
        self._last_tool_category_map: dict[str, str] = {
            "sqlmap": "sqli",
            "gobuster": "enumeration",
            "nmap": "reconnaissance",
            "nikto": "web_scan",
            "nuclei": "vulnerability_scan",
            "http_request": "web_test",
        }

        # Validation tracking (simplified - no longer using ValidatedFinding class)
        self._pending_validations: list[dict] = []
        self._validated_findings: list[dict] = []

        # CAI-inspired: Memory tool for auto-search
        self._memory_tool: MemoryToolWithFallback | None = None
        if MEMORY_TOOL_AVAILABLE:
            try:
                self._memory_tool = MemoryToolWithFallback()
                logger.info("memory_tool_initialized_for_auto_search")
            except Exception as e:
                logger.warning("memory_tool_init_failed", error=str(e))

        # CAI-inspired: Context compaction tracking
        self._compaction_threshold: int = 50  # Trigger compaction after this many turns
        self._last_compaction_turn: int = 0

        # Session trace for user visibility
        self._session_trace: SessionTrace | None = None

        # Algorithm learning integration - makes Inferno smarter over time
        self._loop_integration: LoopIntegration | None = None
        if ALGORITHM_LEARNING_AVAILABLE:
            try:
                self._loop_integration = get_loop_integration()
                logger.info("algorithm_learning_initialized")
            except Exception as e:
                logger.warning("algorithm_learning_init_failed", error=str(e))

        # Attack intelligence for prioritized exploitation
        self._attack_selector: AttackSelector | None = None
        self._hint_extractor: HintExtractor | None = None
        if ATTACK_INTELLIGENCE_AVAILABLE:
            try:
                self._attack_selector = get_attack_selector()
                self._hint_extractor = get_hint_extractor()
                logger.info("attack_intelligence_initialized")
            except Exception as e:
                logger.warning("attack_intelligence_init_failed", error=str(e))

        # Detected technologies and hints (populated during assessment)
        self._detected_technologies: set[str] = set()
        self._detected_hints: list = []
        self._waf_detected: bool = False

    def on_message(self, callback: Callable[[str], None]) -> SDKAgentExecutor:
        """Set callback for assistant messages."""
        self._on_message = callback
        return self

    def on_tool_call(self, callback: Callable[[str, dict], None]) -> SDKAgentExecutor:
        """Set callback for tool calls."""
        self._on_tool_call = callback
        return self

    def on_tool_result(self, callback: Callable[[str, str, bool], None]) -> SDKAgentExecutor:
        """Set callback for tool results (name, output, is_error)."""
        self._on_tool_result = callback
        return self

    def on_thinking(self, callback: Callable[[str], None]) -> SDKAgentExecutor:
        """Set callback for thinking blocks."""
        self._on_thinking = callback
        return self

    def on_complete(self, callback: Callable[[ExecutionResult], None]) -> SDKAgentExecutor:
        """Set callback for execution completion."""
        self._on_complete = callback
        return self

    def on_turn(self, callback: Callable[[int, int, float], None]) -> SDKAgentExecutor:
        """Set callback for turn updates (turn_number, tokens_used, cost_usd)."""
        self._on_turn = callback
        return self

    def on_finding(self, callback: Callable[[str, str, str], None]) -> SDKAgentExecutor:
        """Set callback for findings (title, severity, location)."""
        self._on_finding = callback
        return self

    def on_subagent_spawn(self, callback: Callable[[str, str], None]) -> SDKAgentExecutor:
        """Set callback for subagent spawn (agent_id, agent_type)."""
        self._on_subagent_spawn = callback
        return self

    def on_subagent_complete(self, callback: Callable[[str], None]) -> SDKAgentExecutor:
        """Set callback for subagent completion (agent_id)."""
        self._on_subagent_complete = callback
        return self

    def on_validation(self, callback: Callable[[str, str, int], None]) -> SDKAgentExecutor:
        """Set callback for validation results (finding_title, result, confidence)."""
        self._on_validation = callback
        return self

    def _get_current_attack_category(self) -> str:
        """Get current attack category from context."""
        return self._current_category

    def _update_attack_category(self, tool_name: str) -> None:
        """Update current attack category based on tool used."""
        # Map tool names to categories
        for tool_pattern, category in self._last_tool_category_map.items():
            if tool_pattern in tool_name.lower():
                self._current_category = category
                return

        # Default categories based on tool name patterns
        if "sql" in tool_name.lower():
            self._current_category = "sqli"
        elif "xss" in tool_name.lower():
            self._current_category = "xss"
        elif "ssrf" in tool_name.lower():
            self._current_category = "ssrf"
        elif "lfi" in tool_name.lower() or "path" in tool_name.lower():
            self._current_category = "path_traversal"
        elif "upload" in tool_name.lower():
            self._current_category = "file_upload"

    def _check_guardrails_input(self, content: str, context: dict | None = None) -> GuardrailResult | None:
        """
        Check input content against guardrails.

        Returns None if guardrails disabled or no violation, otherwise returns result.
        """
        if not self._guardrail_engine or not GUARDRAILS_AVAILABLE:
            return None

        result = self._guardrail_engine.check_input(content, context=context or {})

        if not result.allowed:
            logger.warning(
                "guardrail_input_violation",
                policy=result.policy_name,
                action=result.action_taken.value if result.action_taken else None,
                severity=result.severity.value if result.severity else None,
                message=result.message,
            )
            return result

        return None

    def _check_guardrails_output(self, content: str, context: dict | None = None) -> GuardrailResult | None:
        """
        Check output content against guardrails.

        Returns None if guardrails disabled or no violation, otherwise returns result.
        """
        if not self._guardrail_engine or not GUARDRAILS_AVAILABLE:
            return None

        result = self._guardrail_engine.check_output(content, context=context or {})

        if not result.allowed:
            logger.warning(
                "guardrail_output_violation",
                policy=result.policy_name,
                action=result.action_taken.value if result.action_taken else None,
                severity=result.severity.value if result.severity else None,
                message=result.message,
            )
            return result

        return None

    def _check_guardrails_tool(self, tool_name: str, tool_input: dict) -> GuardrailResult | None:
        """
        Check tool call against guardrails.

        Returns None if guardrails disabled or no violation, otherwise returns result.
        """
        if not self._guardrail_engine or not GUARDRAILS_AVAILABLE:
            return None

        # Convert tool_input dict to string for guardrail check
        import json
        tool_input_str = json.dumps(tool_input) if tool_input else ""
        result = self._guardrail_engine.check_tool(tool_name, tool_input_str)

        if not result.allowed:
            logger.warning(
                "guardrail_tool_violation",
                tool=tool_name,
                policy=result.policy_name,
                action=result.action_taken.value if result.action_taken else None,
                severity=result.severity.value if result.severity else None,
                message=result.message,
            )
            return result

        return None

    def _check_and_inject_diminishing_returns(self) -> str | None:
        """Check for diminishing returns and generate warning if needed."""
        if not self._diminishing_tracker:
            return None

        category = self._get_current_attack_category()
        if not category:
            return None

        result = self._diminishing_tracker.check_diminishing_returns(category)

        if result.diminishing:
            blocked = self._diminishing_tracker.get_blocked_categories()
            recommended = self._diminishing_tracker.get_recommended_categories()

            warning = f"""
## DIMINISHING RETURNS DETECTED

**Category**: {category}
**Reason**: {result.reason}
**Overall Success Rate**: {result.overall_rate:.1%}
**Recent Success Rate**: {result.recent_rate:.1%}
**Attempts Analyzed**: {result.attempts_analyzed}

**Recommendation**: {result.recommendation}

**Blocked Categories**: {', '.join(blocked) if blocked else 'None'}
**Effective Categories**: {', '.join(recommended[:3]) if recommended else 'Try new approach'}

**PIVOT NOW** - Don't waste more time on {category}! Try:
1. Switch to a different attack vector entirely
2. Focus on one of the effective categories above
3. Look for completely unexplored attack surfaces
"""
            logger.warning(
                "diminishing_returns_detected",
                category=category,
                reason=result.reason,
                overall_rate=result.overall_rate,
                recent_rate=result.recent_rate,
            )
            return warning

        return None

    def _build_system_prompt(self, config: AssessmentConfig, artifacts_dir: Path) -> str:
        """Build the system prompt for the assessment using SystemPromptBuilder."""
        from inferno.config.environment import discover_security_tools, setup_operation_context
        from inferno.config.settings import InfernoSettings

        # CTF mode - use aggressive prompt with creative exploitation
        # NOTE: build_ctf_system_prompt removed in rebuild, using inline CTF prompt
        if self._ctf_mode:
            ctf_prompt = f"""# CTF SECURITY ASSESSMENT

## Target
{config.target}

## Challenge Type
{config.target_type or "web"}

## Mode
**CTF MODE ENABLED** - Be aggressive, think creatively!

## The 3-Try Rule (CRITICAL)
When a payload is BLOCKED, do NOT give up. Try 3 different approaches:
1. **Try 1**: Standard payload
2. **Try 2**: Encoded/obfuscated version (URL, double-URL, Unicode, mixed case)
3. **Try 3**: Different technique (HPP, different content-type, different endpoint)
**Only after 3 different approaches fail, pivot to a new vector.**

## Bypass Techniques (Use When Blocked)
- WAF Bypass: URL encode, double encode, mixed case (SeLeCt), comments (SEL/**/ECT), HPP (?id=1&id=payload)
- Auth Bypass: JWT none algorithm, X-Forwarded-For: 127.0.0.1, path traversal (/admin/../user)
- Rate Limit Bypass: X-Forwarded-For rotation, mobile API (/api/mobile/), legacy API (/api/v1/)

## Advanced Techniques to Try
- Race conditions: Simultaneous requests to coupon/vote/balance endpoints
- SSTI: {{{{7*7}}}}, ${{{{7*7}}}}, <%=7*7%> - escalate to RCE
- Prototype pollution: {{"__proto__": {{"admin": true}}}}
- HTTP smuggling: CL.TE, TE.CL when behind CDN/proxy
- Second-order vulns: XSS in profile -> admin views -> steal admin session

## Business Logic (High Value, No WAF Detection)
Ask "What If?":
- What if I do it twice? (coupon, vote, redeem)
- What if I use negative numbers? (quantity, price, transfer)
- What if I skip steps? (jump to checkout without payment)
- What if I'm faster than the server? (race conditions)

## Standard Approach
1. Use `execute_command` to run: nmap, sqlmap, gobuster, nikto, etc.
2. Check common paths: robots.txt, .git, .env, backup files
3. Look for flags: flag{{...}}, HTB{{...}}, CTF{{...}}
4. Chain vulnerabilities for maximum impact
5. Check /etc/passwd, environment variables, config files

## SWARM WORKERS - Use Them Aggressively!
You have access to the `swarm` tool to spawn specialized workers. USE IT OFTEN:

**When to spawn workers:**
- After initial recon: spawn `scanner` for vulnerability scanning
- When you find a potential vuln: spawn `analyzer` for deep analysis
- When stuck: spawn `exploiter` with specific attack focus
- For validation: spawn `validator` to confirm findings independently
- For WAF bypass: spawn `waf_bypass` specialist

**Worker types available:**
- `reconnaissance` - Fast enumeration
- `scanner` - Vulnerability scanning
- `exploiter` - Deep exploitation
- `analyzer` - Analyze specific attack vectors (SSTI, SQLi, etc.)
- `validator` - Independent finding validation
- `waf_bypass` - WAF evasion specialist
- `business_logic` - Logic flaw hunting

**Example swarm calls:**
```
swarm(agent_type="analyzer", task="Deep analyze SSTI in /template endpoint. Test Jinja2, Twig, Freemarker payloads.")
swarm(agent_type="exploiter", task="Exploit SQLi in /api/users?id=. Try boolean and time-based blind.")
swarm(agent_type="waf_bypass", task="Bypass CloudFlare WAF blocking SQLi on /search")
```

**IMPORTANT:** Don't do everything yourself! Spawn workers for parallel work.

## Tools Available
```bash
nmap -sV -sC {config.target}
gobuster dir -u http://{config.target} -w /usr/share/wordlists/dirb/common.txt
sqlmap -u "http://{config.target}/page?id=1" --batch --dbs --tamper=space2comment
nikto -h {config.target}
curl, wget, nc, python scripts, etc.
```

## Remember
- Standard attacks often fail because targets are protected
- Creative thinking beats brute force
- Chain low-severity vulns into high-impact exploits

START NOW - enumerate, bypass protections, and exploit!
"""
            return ctf_prompt

        # Determine persona
        persona_map = {
            "thorough": AgentPersona.THOROUGH,
            "ctf": AgentPersona.CTF,
            "stealth": AgentPersona.THOROUGH,  # Use THOROUGH as fallback
        }
        persona = persona_map.get(config.persona, AgentPersona.THOROUGH)

        # Override persona for CTF mode
        if config.ctf_mode or config.mode == "ctf":
            persona = AgentPersona.CTF

        # Create operation context using the helper function
        try:
            settings = self._settings or InfernoSettings()
            operation_context = setup_operation_context(
                settings=settings,
                target=config.target,
                objective=config.objective,
            )
        except Exception as e:
            # Fallback: don't use operation context if it fails
            logger.warning("failed_to_create_operation_context", error=str(e))
            operation_context = None

        # Get available security tools
        available_tools = discover_security_tools()
        tool_names = [name for name, tool in available_tools.items() if tool.available]

        # Build prompt using SystemPromptBuilder
        builder = SystemPromptBuilder(persona)
        builder.set_target(config.target, scope=config.scope, target_type=config.target_type)
        builder.set_objective(config.objective, success_criteria=config.success_criteria)
        if operation_context:
            builder.set_operation_context(operation_context)
        builder.set_available_tools(tool_names)
        builder.set_rules(config.rules)
        builder.update_budget(
            current_turns=0,
            max_turns=config.max_turns,
            current_tokens=0,
            max_tokens=1_000_000,
        )

        base_prompt = builder.build()

        # Add branch tracking and chain enumeration info if enabled
        advanced_section = self._build_advanced_features_section(config)

        return base_prompt + "\n\n" + advanced_section

    def _build_attack_intelligence(self, target: str, mode: str) -> str:
        """
        Build attack intelligence section for system prompt.

        Uses AttackSelector to generate prioritized attack recommendations
        based on any detected technologies, hints, and historical success rates.

        This makes Inferno smarter by injecting attack priorities learned from
        previous assessments and technology fingerprints.

        Args:
            target: The target URL/IP
            mode: Assessment mode (web, api, ctf)

        Returns:
            Formatted attack intelligence section, or empty string if unavailable
        """
        if not self._attack_selector or not ATTACK_INTELLIGENCE_AVAILABLE:
            return ""

        try:
            # Get attack plan based on current knowledge
            # Initially we have no technologies detected, but we can still
            # get default prioritization and learning from history
            attack_plan = self._attack_selector.select_attacks(
                technologies=list(self._detected_technologies),
                hints=self._detected_hints,
                waf_detected=self._waf_detected,
                context=mode,
            )

            if not attack_plan.vectors:
                return ""

            # Build the intelligence section
            lines = [
                "## ATTACK INTELLIGENCE (Algorithm-Learned Priorities)",
                "",
                f"**Rationale**: {attack_plan.rationale}",
                f"**Estimated Coverage**: {attack_plan.estimated_coverage:.0%} of common vulnerabilities",
                "",
                "### Prioritized Attack Vectors (try in this order):",
            ]

            for i, vector in enumerate(attack_plan.vectors[:10], 1):
                priority_pct = int(vector.priority * 100)
                lines.append(f"{i}. **{vector.name}** (priority: {priority_pct}%)")
                lines.append(f"   - {vector.description}")
                if vector.techniques:
                    lines.append(f"   - Techniques: {', '.join(vector.techniques[:5])}")
                if vector.tools:
                    lines.append(f"   - Tools: {', '.join(vector.tools)}")

            # Add algorithm learning stats if available
            if self._loop_integration:
                try:
                    stats = self._loop_integration.get_statistics()
                    if stats:
                        lines.append("")
                        lines.append("### Learning Statistics:")
                        total_triggers = stats.get("total_trigger_selections", 0)
                        if total_triggers > 0:
                            lines.append(f"- Total learned selections: {total_triggers}")
                            best_trigger = stats.get("best_trigger")
                            if best_trigger:
                                lines.append(f"- Most successful trigger: {best_trigger}")
                except Exception:
                    pass  # Statistics are optional enhancement

            lines.append("")
            lines.append("**Note**: These priorities are learned from historical success. Update priorities as you discover technologies.")

            return "\n".join(lines)

        except Exception as e:
            logger.warning("attack_intelligence_build_failed", error=str(e))
            return ""

    async def _auto_search_memory_for_target(self, target: str) -> str:
        """
        CAI-inspired: Auto-search memory for similar targets before assessment.

        This feature automatically recalls relevant findings and context from
        previous assessments on similar targets, enabling knowledge transfer.

        Args:
            target: The target URL/IP to search for.

        Returns:
            A formatted string with relevant memories, or empty string if none found.
        """
        if not self._memory_tool or not MEMORY_TOOL_AVAILABLE:
            return ""

        try:
            memories = []

            # Extract domain for search queries
            import re
            domain_match = re.search(r'https?://(?:www\.)?([^/:]+)', target)
            domain = domain_match.group(1) if domain_match else target

            # Search for findings related to this target
            # Note: Use "finding" (singular) to match stored user_id="inferno_finding"
            # Use enriched query and lower threshold for better semantic matching
            result = await self._memory_tool.execute(
                operation="search",
                content=f"{domain} vulnerability security assessment",
                memory_type="finding",
                limit=5,
                threshold=0.35,  # Lower threshold for URL/domain queries
            )
            if result.success and result.output and "No memories found" not in result.output:
                memories.append(f"### Previous Findings for Similar Targets:\n{result.output}")

            # Search for context related to this target
            result = await self._memory_tool.execute(
                operation="search",
                content=f"TARGET {domain} security",
                memory_type="context",
                limit=3,
                threshold=0.35,
            )
            if result.success and result.output and "No memories found" not in result.output:
                memories.append(f"### Previous Context:\n{result.output}")

            # Search for checkpoints (may contain valuable intel)
            result = await self._memory_tool.execute(
                operation="search",
                content=f"{domain} assessment progress",
                memory_type="checkpoint",
                limit=3,
                threshold=0.35,
            )
            if result.success and result.output and "No memories found" not in result.output:
                memories.append(f"### Previous Assessment Progress:\n{result.output}")

            if memories:
                logger.info(
                    "auto_memory_search_found",
                    target=target,
                    memories_count=len(memories),
                )
                return f"""## AUTO-RECALLED MEMORY (CAI-Inspired Feature)

The system automatically searched for relevant memories from previous assessments.
Use this intelligence to skip redundant testing and focus on proven attack vectors.

{chr(10).join(memories)}

**IMPORTANT**: This memory recall is automatic. Use these findings to inform your approach.
"""
            else:
                logger.debug("auto_memory_search_empty", target=target)
                return ""

        except Exception as e:
            logger.warning("auto_memory_search_failed", error=str(e))
            return ""

    def _build_context_compaction_prompt(self, turn_count: int, findings_count: int) -> str:
        """
        CAI-inspired: Generate context compaction prompt for long sessions.

        When conversation exceeds threshold turns, this creates a summary prompt
        to help the agent maintain context while reducing token usage.

        Args:
            turn_count: Current turn number.
            findings_count: Number of findings discovered.

        Returns:
            Compaction reminder prompt.
        """
        if turn_count < self._compaction_threshold:
            return ""

        if turn_count - self._last_compaction_turn < 20:
            # Don't compact too frequently
            return ""

        self._last_compaction_turn = turn_count

        return f"""
## CONTEXT COMPACTION REMINDER (Turn {turn_count})

You've been working for {turn_count} turns. To maintain effectiveness:

1. **SAVE KEY FINDINGS TO MEMORY** - Use memory_store for all important discoveries
2. **SUMMARIZE PROGRESS** - What attack vectors have you tried?
3. **PRIORITIZE REMAINING WORK** - What's most likely to succeed?

Current Stats:
- Turns: {turn_count}
- Findings: {findings_count}

**Focus on high-impact actions from here.**
"""

    def _build_advanced_features_section(self, config: AssessmentConfig) -> str:
        """Build section describing advanced features available to the agent."""
        sections = []

        if config.enable_branch_tracking:
            sections.append("""# Branch Tracking (Systematic Exploration)

You have access to branch tracking for systematic exploration of attack paths.
When you identify multiple possible approaches:

1. **Record the decision point** - Note which approaches exist
2. **Try the highest priority first** - But remember the alternatives
3. **If stuck, backtrack** - Return to unexplored branches
4. **Mark results** - Track what worked and what didn't

This prevents getting stuck on one approach when alternatives might succeed.
The system tracks your exploration automatically via the memory tools.""")

        if config.enable_chain_enumeration:
            sections.append("""# Attack Chain Enumeration

When you discover multiple vulnerabilities, consider how they can be COMBINED:

**Common High-Impact Chains:**
- SQLi → Credential Dump → Admin Access → RCE
- LFI → Config Leak → Database Creds → Full Compromise
- SSRF → Cloud Metadata → IAM Keys → AWS Takeover
- File Upload + LFI → Webshell → RCE
- XSS → Session Theft → Account Takeover

**IMPORTANT:** Don't stop at single findings. Always consider:
1. Can this finding enable access to something else?
2. Can I combine this with another weakness?
3. What's the maximum impact chain possible?

Use the memory tools to track findings and systematically explore chains.""")

        if config.enable_diminishing_returns:
            sections.append(f"""# Diminishing Returns Detection

The system tracks your attack attempts and warns when you're wasting time:

**Automatic Detection:**
- **Identical Responses**: If the last 5 responses are identical → You're blocked
- **Declining Success**: If success rate drops below 30% of overall → Approach is failing
- **Complete Failure**: If recent attempts all fail after initial success → Defenses adapted
- **Never Succeeded**: If 10+ attempts with zero success → Wrong approach

**When You Get a Warning:**
1. **STOP** the current attack vector immediately
2. **PIVOT** to a different technique or attack surface
3. **CHECK** recommended effective categories
4. **AVOID** blocked/ineffective approaches

This feature saves time by preventing you from repeatedly trying failed approaches.
The system analyzes {config.diminishing_returns_window} recent attempts with a {config.diminishing_returns_threshold:.0%} threshold.""")

        sections.append(f"""# Subagent Spawning Thresholds

The system automatically monitors progress and can suggest when to try different approaches:
- If stuck for {config.subagent_trigger_interval}+ turns: Try a completely different attack vector
- After {config.subagent_error_threshold}+ consecutive errors: Re-examine the target
- No findings after {config.subagent_no_findings_threshold}+ turns: Consider scope/approach changes

**IMPORTANT:** If you're not making progress, STOP and think:
1. Am I repeating the same failed approach?
2. Are there unexplored attack surfaces?
3. Should I try a completely different technique?""")

        return "\n\n".join(sections)

    async def _run_parallel_initial_recon(
        self,
        config: AssessmentConfig,
        artifacts_dir: Path,
        operation_id: str,
    ) -> dict[str, str]:
        """
        Run parallel initial reconnaissance sub-agents at assessment start.

        This is a CTF optimization that spawns multiple specialized recon
        agents simultaneously to rapidly gather initial intelligence about
        the target before the main assessment begins.

        Args:
            config: Assessment configuration.
            artifacts_dir: Directory for artifacts.
            operation_id: Operation identifier.

        Returns:
            Dict of agent_type -> findings summary.
        """
        if not config.enable_parallel_initial_recon:
            return {}

        if not (self._ctf_mode or config.ctf_mode):
            # Only in CTF mode by default
            return {}

        logger.info(
            "parallel_initial_recon_starting",
            target=config.target,
            agents=config.parallel_recon_agents,
        )

        # Import swarm tool for direct spawning
        try:
            from inferno.swarm.tool import SwarmTool

            # Create swarm tool - uses Claude SDK internally (supports OAuth)
            swarm_tool = SwarmTool(
                model="claude-opus-4-5-20251101",  # Use Opus for better analysis
                operation_id=operation_id,
                target=config.target,
            )

            # Define parallel recon tasks
            recon_tasks = []
            for agent_type in config.parallel_recon_agents:
                if agent_type == "reconnaissance":
                    task = f"Perform rapid reconnaissance on {config.target}. Focus on: 1) Technology stack identification, 2) Subdomain/endpoint discovery, 3) Authentication mechanisms. Be fast and thorough."
                elif agent_type == "scanner":
                    task = f"Quickly scan {config.target} for common vulnerabilities. Focus on: 1) OWASP Top 10, 2) Exposed endpoints, 3) Input validation issues. Prioritize speed over exhaustive testing."
                else:
                    task = f"Analyze {config.target} for security issues relevant to {agent_type} expertise."

                recon_tasks.append((agent_type, task))

            # Spawn all recon agents in parallel
            async def run_recon_agent(agent_type: str, task: str) -> tuple[str, str]:
                """Run a single recon agent and return results."""
                try:
                    result = await swarm_tool.execute(
                        agent_type=agent_type,
                        task=task,
                        context=f"Target: {config.target}\nObjective: {config.objective}\nMode: CTF - Speed is critical!",
                        max_turns=10,  # Quick recon
                    )
                    if result.success:
                        return (agent_type, result.output)
                    else:
                        return (agent_type, f"Error: {result.error}")
                except Exception as e:
                    logger.error("recon_agent_failed", agent_type=agent_type, error=str(e))
                    return (agent_type, f"Error: {e!s}")

            # Run all recon agents in parallel
            tasks = [run_recon_agent(agent_type, task) for agent_type, task in recon_tasks]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Collect results
            findings: dict[str, str] = {}
            for result in results:
                if isinstance(result, tuple):
                    agent_type, output = result
                    findings[agent_type] = output
                    logger.info(
                        "recon_agent_complete",
                        agent_type=agent_type,
                        output_length=len(output),
                    )
                elif isinstance(result, Exception):
                    logger.error("recon_agent_exception", error=str(result))

            # Fire subagent callbacks
            if self._on_subagent_spawn:
                for agent_type in findings:
                    self._on_subagent_spawn(f"initial_recon_{agent_type}", agent_type)
            if self._on_subagent_complete:
                for agent_type in findings:
                    self._on_subagent_complete(f"initial_recon_{agent_type}")

            logger.info(
                "parallel_initial_recon_complete",
                agents_run=len(findings),
                total_findings_chars=sum(len(v) for v in findings.values()),
            )

            return findings

        except ImportError as e:
            logger.warning("parallel_recon_import_error", error=str(e))
            return {}
        except Exception as e:
            logger.error("parallel_recon_failed", error=str(e))
            return {}

    async def _build_initial_model(self, recon_results: dict[str, str]) -> None:
        """
        Build initial application model from reconnaissance results.

        Args:
            recon_results: Dictionary of agent_type -> findings.
        """
        if not self._app_model or not recon_results:
            return

        logger.info("building_initial_app_model", sources=list(recon_results.keys()))

        # Extract endpoints, parameters, and other intelligence from recon
        for agent_type, findings in recon_results.items():
            try:
                # Parse findings for structured data
                # This is a simple implementation - could be enhanced with AI-powered extraction
                import re

                # Extract URLs/endpoints
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', findings)
                for url in urls[:20]:  # Limit to avoid overload
                    try:
                        from urllib.parse import parse_qs, urlparse
                        parsed = urlparse(url)
                        endpoint_path = parsed.path or "/"

                        # Add endpoint to model
                        self._app_model.add_endpoint(
                            method="GET",  # Assume GET for discovered URLs
                            path=endpoint_path,
                            source=f"recon_{agent_type}",
                        )

                        # Extract parameters if present
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param_name, values in params.items():
                                self._app_model.add_parameter(
                                    endpoint=endpoint_path,
                                    name=param_name,
                                    param_type="query",
                                    sample_values=values[:3],  # Limit samples
                                )

                    except Exception as e:
                        logger.debug("url_parsing_failed", url=url, error=str(e))

                logger.info(
                    "recon_parsed",
                    agent_type=agent_type,
                    urls_found=len(urls),
                )

            except Exception as e:
                logger.warning("recon_parsing_failed", agent_type=agent_type, error=str(e))

        logger.info(
            "initial_model_built",
            endpoints=len(self._app_model.endpoints),
            parameters=len(self._app_model.parameters),
        )

    def _build_strategic_context(self, attack_plan: AttackPlan) -> str:
        """
        Build strategic context section for system prompt from attack plan.

        Args:
            attack_plan: The generated attack plan.

        Returns:
            Formatted strategic context string.
        """
        sections = []

        sections.append("# STRATEGIC ATTACK PLAN")
        sections.append(f"\nPlan ID: {attack_plan.plan_id}")
        sections.append(f"Mode: {attack_plan.mode}")
        sections.append(f"Total Estimated Tokens: {attack_plan.total_estimated_tokens:,}")

        # High-value targets
        if attack_plan.high_value_targets:
            sections.append("\n## High-Value Targets (Priority Testing)")
            for target in attack_plan.high_value_targets[:5]:
                sections.append(f"- {target}")

        # Skip list
        if attack_plan.skip_list:
            sections.append("\n## Skip These Attacks (Low Probability)")
            for skip_item in attack_plan.skip_list[:5]:
                sections.append(f"- {skip_item}")

        # Budget allocation
        if attack_plan.phases_budget:
            sections.append("\n## Token Budget Allocation by Phase")
            for phase, percentage in attack_plan.phases_budget.items():
                tokens = int(attack_plan.total_estimated_tokens * percentage)
                sections.append(f"- {phase.title()}: {percentage:.0%} ({tokens:,} tokens)")

        # Top priority steps
        all_steps = attack_plan.get_all_steps()
        critical_steps = [s for s in all_steps if s.priority.value == "critical"]
        high_steps = [s for s in all_steps if s.priority.value == "high"]

        if critical_steps:
            sections.append("\n## CRITICAL Priority Steps (Execute First)")
            for step in critical_steps[:3]:
                sections.append(f"\n### {step.description}")
                sections.append(f"- **Attack Type**: {step.attack_type.value}")
                sections.append(f"- **Target**: {step.target}")
                sections.append(f"- **Rationale**: {step.rationale}")
                if step.tools_needed:
                    sections.append(f"- **Tools**: {', '.join(step.tools_needed)}")

        if high_steps:
            sections.append("\n## HIGH Priority Steps")
            for step in high_steps[:5]:
                sections.append(f"- **{step.description}** ({step.attack_type.value}) - {step.rationale[:100]}")

        # Attack chains
        if attack_plan.attack_chains:
            sections.append("\n## Recommended Attack Chains")
            for chain in attack_plan.attack_chains[:3]:
                sections.append(f"\n### {chain.name} (Impact: {chain.expected_impact})")
                sections.append(f"**Rationale**: {chain.rationale}")
                sections.append("**Steps**:")
                for i, step in enumerate(chain.steps, 1):
                    sections.append(f"  {i}. {step.description} ({step.attack_type.value})")

        sections.append("\n## Execution Instructions")
        sections.append("1. **Start with CRITICAL priority steps** - These have highest success probability")
        sections.append("2. **Track progress** - Mark steps complete using memory_store")
        sections.append("3. **Follow attack chains** - When you find vulnerabilities, check if they enable chains")
        sections.append("4. **Stay within budget** - Monitor token usage per phase")
        sections.append("5. **Skip low-probability attacks** - Focus on high-value targets identified in plan")

        return "\n".join(sections)

    async def _handle_finding(self, finding: dict[str, Any]) -> None:
        """
        Handle a finding and update strategic planning state.

        Args:
            finding: Finding data dictionary.
        """
        # Update planner progress if available
        if self._planner:
            # Try to match finding to a step
            step_id = finding.get("related_step_id")
            if step_id:
                self._planner.mark_step_complete(
                    step_id=step_id,
                    success=True,
                    findings=[finding],
                )
                logger.info("strategic_step_completed", step_id=step_id)

        # Update coordinator if available
        if self._coordinator:
            await self._coordinator.handle_finding(
                agent_id=self._agent_id,
                finding=finding,
            )

    async def run(
        self,
        config: AssessmentConfig,
        initial_message: str | None = None,
    ) -> ExecutionResult:
        """
        Run a security assessment.

        Args:
            config: Assessment configuration.
            initial_message: Optional initial user message.

        Returns:
            ExecutionResult with assessment outcome.
        """
        started_at = datetime.now(UTC)
        operation_id = f"OP_{started_at.strftime('%Y%m%d_%H%M%S')}"

        # Create output directory with sanitized target name
        artifacts_dir = self._settings.get_artifacts_dir(config.target, operation_id)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Auto-detect target type if not specified
        if config.target_type == "unknown":
            from inferno.prompts import detect_context_type
            config.target_type = detect_context_type(config.target, config.objective)
            logger.info("target_type_auto_detected", target_type=config.target_type)

        # Enable CTF mode if configured
        self._ctf_mode = config.ctf_mode or config.mode == "ctf"

        logger.info(
            "assessment_started",
            operation_id=operation_id,
            target=config.target,
            target_type=config.target_type,
            objective=config.objective[:100],
            enable_branch_tracking=config.enable_branch_tracking,
            enable_chain_enumeration=config.enable_chain_enumeration,
            enable_diminishing_returns=config.enable_diminishing_returns,
            enable_strategic_planning=config.enable_strategic_planning,
            ctf_mode=self._ctf_mode,
            persona=config.persona,
        )

        # Initialize session trace for user visibility
        if config.enable_session_trace:
            trace_dir = config.session_trace_output_dir or artifacts_dir
            self._session_trace = init_session_trace(
                target=config.target,
                objective=config.objective,
                operation_id=operation_id,
                output_dir=trace_dir,
            )
            logger.info("session_trace_initialized", output_dir=str(trace_dir))

        # Initialize advanced features
        if config.enable_branch_tracking:
            self._branch_tracker = BranchTracker(
                operation_dir=artifacts_dir,
                max_depth=10,
                max_branches=100,
            )
            logger.info("branch_tracker_initialized", operation_dir=str(artifacts_dir))

        # NOTE: Removed in rebuild:
        # - ChainEnumerator (config.enable_chain_enumeration)
        # - DiminishingReturnsTracker (config.enable_diminishing_returns)
        # - FlagDetector, CTFPayloadBlaster (CTF mode)
        # - ValidationOrchestrator (config.auto_validate_findings)
        # - MLScoringEngine (config.enable_ml_scoring)
        #
        # The new philosophy: Let the LLM use execute_command to run any tool.
        # These features added cognitive overhead without proven value.

        if self._ctf_mode:
            logger.info("ctf_mode_enabled", note="using simplified approach")

        # Log enabled AI features
        logger.info(
            "ai_features_configured",
            ml_scoring=config.enable_ml_scoring and ML_SCORING_AVAILABLE,
            performance_optimizer=config.enable_performance_optimizer,
            security_hardening=config.enable_security_hardening,
            parallel_execution=config.enable_parallel_execution,
        )

        # Reset progress tracking
        self._turns_without_progress = 0
        self._consecutive_errors = 0
        self._turns_without_findings = 0
        self._last_finding_turn = 0
        self._findings_count = 0
        self._pending_validations = []
        self._validated_findings = []

        # Reset attack intelligence state
        self._detected_technologies = set()
        self._detected_hints = []
        self._waf_detected = False

        # Initialize algorithm learning context for this assessment
        if self._loop_integration:
            try:
                self._loop_integration.set_context(
                    target=config.target,
                    tech_stack=[],  # Will be populated as we discover technologies
                    endpoints=[],  # Will be populated during recon
                    phase="reconnaissance",
                )
                logger.info("algorithm_learning_context_set", target=config.target)
            except Exception as e:
                logger.warning("algorithm_learning_context_failed", error=str(e))

        # Configure Mem0/Qdrant memory backend EARLY (needed for auto-search)
        # This ensures auto-memory search uses the same Qdrant instance as the rest of the system
        set_operation_id(operation_id)
        set_target(config.target)  # Set target for episodic memory scoping
        api_key = None
        if self._settings:
            provider = self._settings.memory.embedding_provider.value
            if provider == "openai" and self._settings.openai_api_key:
                api_key = self._settings.openai_api_key.get_secret_value()
            elif provider == "voyage" and self._settings.voyage_api_key:
                api_key = self._settings.voyage_api_key.get_secret_value()
            elif provider == "cohere" and self._settings.cohere_api_key:
                api_key = self._settings.cohere_api_key.get_secret_value()

            configure_memory(
                qdrant_host=self._settings.memory.qdrant_host,
                qdrant_port=self._settings.memory.qdrant_port,
                qdrant_collection=self._settings.memory.qdrant_collection,
                embedding_provider=provider,
                embedding_model=self._settings.memory.get_embedding_model(),
                ollama_host=self._settings.memory.ollama_host,
                api_key=api_key,
            )

            # Re-initialize memory tool with correct settings for auto-search
            if MEMORY_TOOL_AVAILABLE:
                try:
                    self._memory_tool = MemoryToolWithFallback(
                        operation_id=operation_id,
                        qdrant_host=self._settings.memory.qdrant_host,
                        qdrant_port=self._settings.memory.qdrant_port,
                        qdrant_collection=self._settings.memory.qdrant_collection,
                        embedding_provider=provider,
                        embedding_model=self._settings.memory.get_embedding_model(),
                        ollama_host=self._settings.memory.ollama_host,
                        api_key=api_key,
                    )
                    self._memory_tool.set_target(config.target)  # Set target for episodic memory
                    logger.info("memory_tool_configured_for_auto_search",
                        qdrant_host=self._settings.memory.qdrant_host,
                        collection=self._settings.memory.qdrant_collection,
                        target=config.target)
                except Exception as e:
                    logger.warning("memory_tool_reconfig_failed", error=str(e))

        # STRATEGIC PLANNING PHASE
        strategic_context = ""
        if config.enable_strategic_planning and STRATEGIC_PLANNING_AVAILABLE:
            logger.info("strategic_planning_phase_starting")

            try:
                # Get API key for planner
                planner_api_key = None
                if self._settings and self._settings.anthropic_api_key:
                    planner_api_key = self._settings.anthropic_api_key.get_secret_value()
                if not planner_api_key:
                    import os
                    planner_api_key = os.environ.get("ANTHROPIC_API_KEY")

                if planner_api_key:
                    from anthropic import Anthropic
                    planner_client = Anthropic(api_key=planner_api_key)
                    planner = StrategicPlanner(
                        client=planner_client,
                        operation_dir=artifacts_dir,
                    )

                    # Generate attack plan
                    attack_plan = await planner.create_plan(
                        target=config.target,
                        objective=config.objective,
                        mode=config.persona,
                        max_tokens=config.max_turns * 2000,  # Rough estimate
                    )

                    logger.info(
                        "strategic_plan_created",
                        plan_id=attack_plan.plan_id,
                        total_steps=len(attack_plan.get_all_steps()),
                        critical_steps=len([s for s in attack_plan.get_all_steps() if s.priority.value == "critical"]),
                        attack_chains=len(attack_plan.attack_chains),
                    )

                    # Build strategic context for injection into system prompt
                    strategic_context = self._build_strategic_context(attack_plan)
                    self._planner = planner
                else:
                    logger.warning("strategic_planner_skipped", reason="No API key available")

            except Exception as e:
                logger.error("strategic_planning_phase_failed", error=str(e))
                # Continue without strategic planning
                strategic_context = ""

        # Build system prompt and sanitize bracket tags to prevent XML parsing errors
        system_prompt = sanitize_bracket_tags(self._build_system_prompt(config, artifacts_dir))

        # CAI-inspired: Auto-search memory for similar targets before assessment
        auto_memory_context = await self._auto_search_memory_for_target(config.target)
        if auto_memory_context:
            system_prompt += "\n\n" + auto_memory_context
            logger.info("auto_memory_context_injected", target=config.target)

        # Inject strategic context if available
        if strategic_context:
            system_prompt += "\n\n" + strategic_context
            logger.info("strategic_context_injected", length=len(strategic_context))

        # Inject attack intelligence recommendations from memory and historical success
        attack_intelligence = self._build_attack_intelligence(config.target, config.mode)
        if attack_intelligence:
            system_prompt += "\n\n" + attack_intelligence
            logger.info("attack_intelligence_injected", length=len(attack_intelligence))

        # Run parallel initial reconnaissance in CTF mode (if not already done)
        initial_recon_results: dict[str, str] = {}
        if self._ctf_mode and config.enable_parallel_initial_recon and not strategic_context:
            # Only run if we didn't already run it in strategic planning phase
            initial_recon_results = await self._run_parallel_initial_recon(config, artifacts_dir, operation_id)

        # Build initial prompt
        if initial_message:
            prompt = initial_message
        else:
            prompt = f"""Begin the security assessment of {config.target}.

**Objective**: {config.objective}
**Mode**: {config.mode}

IMPORTANT: Start by searching memory for any previous findings on this target using memory_search and memory_list. Then proceed with the assessment."""

        # Inject parallel recon results into prompt if available
        if initial_recon_results:
            recon_summary = "\n\n## PARALLEL INITIAL RECONNAISSANCE RESULTS\n\n"
            recon_summary += "The following intelligence was gathered by parallel recon agents:\n\n"
            for agent_type, findings in initial_recon_results.items():
                recon_summary += f"### {agent_type.upper()} Agent Findings:\n{findings[:2000]}...\n\n" if len(findings) > 2000 else f"### {agent_type.upper()} Agent Findings:\n{findings}\n\n"
            recon_summary += "**Use this intelligence to focus your exploitation efforts. Skip basic recon and go straight to vulnerability exploitation!**"
            prompt += recon_summary
            logger.info(
                "recon_injected_into_prompt",
                agents=list(initial_recon_results.keys()),
                total_chars=len(recon_summary),
            )

        # Memory already configured above for auto-search

        # Configure swarm tool with OAuth credentials for subagent spawning
        # This enables the meta-agent pattern where main agent can spawn workers
        try:
            from inferno.agent.mcp_tools import configure_swarm

            # Configure swarm for MCP tool - uses Claude SDK internally (supports OAuth)
            configure_swarm(
                model=config.model or "claude-opus-4-5-20251101",
                target=config.target,
            )
            logger.info("swarm_tool_configured_for_mcp", target=config.target)

        except Exception as e:
            logger.error("swarm_configuration_failed", error=str(e))

        # Create Inferno MCP server with semantic memory tools and swarm
        inferno_mcp = create_inferno_mcp_server()

        # Auto-approve all tools for pentesting
        async def auto_approve_tools(
            tool_name: str,
            tool_input: dict[str, Any],
            context: ToolPermissionContext,
        ) -> PermissionResultAllow:
            """Auto-approve all tools for pentesting operations."""
            # Always allow all tools - this is a pentesting agent
            return PermissionResultAllow()

        # Configure SDK options
        options = ClaudeAgentOptions(
            max_turns=config.max_turns,
            system_prompt=system_prompt,
            permission_mode=config.permission_mode,
            cwd=str(config.working_dir or artifacts_dir),
            mcp_servers={"inferno": inferno_mcp},
            can_use_tool=auto_approve_tools,
        )

        if config.model:
            options.model = config.model

        # Extended thinking - ENABLED BY DEFAULT for all modes
        # Critical for complex security reasoning (SQLi technique selection, bypass strategies, etc.)
        thinking_enabled = True
        thinking_only_output = False
        thinking_budget = 64000  # High budget for complex security analysis

        # Override with settings if available
        if self._settings:
            thinking_enabled = self._settings.execution.thinking_enabled
            thinking_only_output = self._settings.execution.thinking_only_output
            thinking_budget = self._settings.execution.thinking_budget

        # Higher budget for Opus models (they use thinking more effectively)
        model_name = (config.model or "").lower()
        is_opus = "opus" in model_name
        if is_opus:
            thinking_budget = max(thinking_budget, 64000)

        if thinking_enabled:
            options.max_thinking_tokens = thinking_budget
            logger.info(
                "extended_thinking_enabled",
                model=config.model,
                budget=thinking_budget,
                thinking_only=thinking_only_output,
                mode=config.mode,
            )

        # Parallel tool execution - enabled by default
        # When Claude requests multiple tools in one turn, MCP can execute them concurrently
        parallel_tools = True
        max_parallel = 5
        if self._settings:
            parallel_tools = self._settings.execution.parallel_tools
            max_parallel = self._settings.execution.max_parallel_tools

        if parallel_tools:
            logger.info(
                "parallel_tools_enabled",
                max_concurrent=max_parallel,
                mode=config.mode,
            )

        turns = 0
        total_cost = 0.0
        total_tokens = 0
        final_message = None
        error = None
        objective_met = False
        findings_summary = None
        stop_reason = "unknown"
        continuation_count = 0
        flags_found: list[str] = []

        # Track pending tool calls for result matching
        pending_tools: dict[str, str] = {}  # tool_use_id -> tool_name

        async def process_response_stream(client: ClaudeSDKClient) -> tuple[str, bool, str | None]:
            """Process the response stream and return (stop_reason, objective_met, error)."""
            nonlocal turns, total_cost, total_tokens, final_message, findings_summary, pending_tools, flags_found

            local_stop_reason = "unknown"
            local_objective_met = False
            local_error = None

            async for message in client.receive_response():
                if isinstance(message, SystemMessage):
                    if message.subtype == "init":
                        logger.debug(
                            "sdk_session_initialized",
                            session_id=message.data.get("session_id"),
                            model=message.data.get("model"),
                            tools=message.data.get("tools"),
                        )

                elif isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            final_message = block.text

                            # Guardrails: check output for security violations
                            guardrail_result = self._check_guardrails_output(
                                block.text,
                                context={"source": "assistant_message", "turn": turns}
                            )
                            if guardrail_result and guardrail_result.action_taken == GuardrailAction.BLOCK:
                                logger.error(
                                    "guardrail_blocked_output",
                                    policy=guardrail_result.policy_name,
                                    message=guardrail_result.message,
                                )
                                # Continue processing but flag the message
                                final_message = f"[GUARDRAIL: {guardrail_result.message}] " + final_message[:500]

                            # Only show text output if thinking_only_output is disabled
                            if self._on_message and not thinking_only_output:
                                self._on_message(block.text)

                            # CTF mode: scan for flags in all text
                            if self._ctf_mode and self._flag_detector:
                                found_flags = self._flag_detector.scan_for_flags(
                                    block.text, source="assistant_message"
                                )
                                if found_flags:
                                    for flag_info in found_flags:
                                        if flag_info.confidence > 0.7:
                                            flags_found.append(flag_info.flag)
                                            logger.info(
                                                "flag_found_in_message",
                                                flag=flag_info.flag[:50],
                                                confidence=flag_info.confidence,
                                            )

                        elif isinstance(block, ThinkingBlock):
                            # Always show thinking blocks when extended thinking is enabled
                            if self._on_thinking:
                                self._on_thinking(block.thinking)
                            # Also output thinking to message callback if thinking_only mode
                            elif thinking_only_output and self._on_message:
                                self._on_message(f"[THINKING]\n{block.thinking}\n[/THINKING]")

                            # Session trace: log thinking
                            if self._session_trace and block.thinking:
                                self._session_trace.log_thinking(block.thinking[:1000])

                        elif isinstance(block, ToolUseBlock):
                            # Track tool call for result matching
                            pending_tools[block.id] = block.name

                            # Guardrails: check tool call for security violations
                            tool_input = block.input if isinstance(block.input, dict) else {}
                            guardrail_tool_result = self._check_guardrails_tool(
                                block.name, tool_input
                            )
                            if guardrail_tool_result and guardrail_tool_result.action_taken == GuardrailAction.BLOCK:
                                logger.error(
                                    "guardrail_blocked_tool",
                                    tool=block.name,
                                    policy=guardrail_tool_result.policy_name,
                                    message=guardrail_tool_result.message,
                                )
                                # Log but continue - SDK handles tool execution

                            # Update attack category based on tool
                            if self._diminishing_tracker:
                                self._update_attack_category(block.name)

                            if self._on_tool_call:
                                self._on_tool_call(block.name, block.input)

                            # Session trace: log tool call
                            if self._session_trace:
                                self._session_trace.log_tool_call(
                                    block.name,
                                    block.input if isinstance(block.input, dict) else {"input": str(block.input)}
                                )

                            # Check for finding via store_evidence (explicit vulnerability storage)
                            if block.name in ("store_evidence", "mcp__inferno__store_evidence"):
                                inp = block.input
                                if isinstance(inp, dict):
                                    vuln_type = inp.get("vulnerability_type", "unknown")
                                    severity = inp.get("severity", "medium")
                                    endpoint = inp.get("endpoint", "unknown")
                                    evidence = inp.get("evidence", "")
                                    title = f"{vuln_type.upper()} at {endpoint}"

                                    # Fire finding callback
                                    if self._on_finding:
                                        self._on_finding(title, severity, endpoint)

                                    # Session trace: log finding
                                    if self._session_trace:
                                        self._session_trace.log_finding(
                                            vuln_type=vuln_type,
                                            severity=severity,
                                            endpoint=endpoint,
                                            evidence=evidence[:500] if evidence else None,
                                        )

                                    # Track for progress monitoring
                                    self._findings_count += 1
                                    self._last_finding_turn = turns
                                    self._turns_without_findings = 0
                                    self._turns_without_progress = 0

                                    # Record successful attack for algorithm learning
                                    if self._loop_integration and ALGORITHM_LEARNING_AVAILABLE:
                                        try:
                                            self._loop_integration.record_attack_outcome(
                                                attack_type=vuln_type,
                                                target=endpoint,
                                                success=True,
                                                severity=severity,
                                            )
                                        except Exception:
                                            pass  # Learning is optional

                                    # Record for AttackSelector historical learning
                                    if self._attack_selector:
                                        try:
                                            self._attack_selector.record_result(vuln_type, success=True)
                                        except Exception:
                                            pass

                                    logger.info(
                                        "finding_via_store_evidence",
                                        vuln_type=vuln_type,
                                        severity=severity,
                                        endpoint=endpoint,
                                    )

                            # Check for finding via memory_store
                            if block.name in ("memory_store", "mcp__inferno__memory_store"):
                                inp = block.input
                                if isinstance(inp, dict):
                                    # Extract finding info from memory store call
                                    content = inp.get("content", inp.get("value", ""))
                                    memory_type = inp.get("type", inp.get("memory_type", ""))
                                    severity = inp.get("severity", "")
                                    # Detect findings by type OR by severity presence
                                    is_finding = (
                                        memory_type in ("vulnerability", "finding", "exploit") or
                                        (severity and severity.lower() in ("critical", "high", "medium", "low")) or
                                        any(kw in content.lower() for kw in ["vulnerability", "vulnerable", "exploit", "injection", "xss", "sqli", "rce", "ssrf", "idor"])
                                    )
                                    if is_finding:
                                        severity = inp.get("severity", "medium")
                                        title = content[:100] if content else "Finding"
                                        # Handle metadata safely - it could be a string or dict
                                        metadata = inp.get("metadata", {})
                                        if isinstance(metadata, dict):
                                            location = metadata.get("url", "unknown")
                                        else:
                                            location = str(metadata) if metadata else "unknown"

                                        # Fire finding callback
                                        if self._on_finding:
                                            self._on_finding(title, severity, location)

                                        # Track for progress monitoring
                                        self._findings_count += 1
                                        self._last_finding_turn = turns
                                        self._turns_without_findings = 0
                                        self._turns_without_progress = 0

                                        # Extract vulnerability type for chain enumeration and validation
                                        vuln_type = inp.get("vuln_type", inp.get("vulnerability_type", ""))
                                        if not vuln_type:
                                            # Try to extract from content
                                            for vt in ["sqli", "xss", "ssrf", "lfi", "rce", "idor", "ssti", "xxe"]:
                                                if vt in content.lower():
                                                    vuln_type = vt
                                                    break

                                        finding_data = {
                                            "vuln_type": vuln_type or "unknown",
                                            "target": location,
                                            "evidence": content,
                                            "severity": severity,
                                            "title": title,
                                        }

                                        # Record successful attack for algorithm learning
                                        if vuln_type and self._loop_integration and ALGORITHM_LEARNING_AVAILABLE:
                                            try:
                                                self._loop_integration.record_attack_outcome(
                                                    attack_type=vuln_type,
                                                    target=location,
                                                    success=True,
                                                    severity=severity,
                                                )
                                            except Exception:
                                                pass  # Learning is optional

                                        # Record for AttackSelector historical learning
                                        if vuln_type and self._attack_selector:
                                            try:
                                                self._attack_selector.record_result(vuln_type, success=True)
                                            except Exception:
                                                pass

                                        # Score finding using AI-powered vulnerability scorer
                                        if self._vulnerability_scorer:
                                            try:
                                                score_result = self._vulnerability_scorer.score_finding(finding_data)
                                                finding_data["ai_score"] = score_result.get("score", 0)
                                                finding_data["ai_confidence"] = score_result.get("confidence", 0)
                                                finding_data["false_positive_likelihood"] = score_result.get("false_positive_likelihood", 0)
                                                logger.info(
                                                    "finding_scored",
                                                    score=finding_data["ai_score"],
                                                    confidence=finding_data["ai_confidence"],
                                                    fp_likelihood=finding_data["false_positive_likelihood"],
                                                )
                                            except Exception as e:
                                                logger.debug("finding_scoring_failed", error=str(e))

                                        # Enhanced ML classification for vulnerability type verification
                                        if self._ml_engine:
                                            try:
                                                # Get ML engine metrics for logging
                                                ml_metrics = self._ml_engine.get_metrics()
                                                finding_data["ml_precision"] = ml_metrics.get("precision", 0)
                                                finding_data["ml_recall"] = ml_metrics.get("recall", 0)
                                                finding_data["ml_f1_score"] = ml_metrics.get("f1_score", 0)
                                                logger.info(
                                                    "ml_enhanced_scoring",
                                                    vuln_type=vuln_type,
                                                    ml_precision=ml_metrics.get("precision"),
                                                    ml_recall=ml_metrics.get("recall"),
                                                )
                                            except Exception as e:
                                                logger.debug("ml_scoring_failed", error=str(e))

                                        # Add to chain enumerator if enabled
                                        if self._chain_enumerator and vuln_type:
                                            # Don't await - just add to queue
                                            asyncio.create_task(
                                                self._chain_enumerator.execute(
                                                    action="add_finding",
                                                    finding=finding_data,
                                                )
                                            )
                                            logger.info(
                                                "finding_added_to_chain_enumerator",
                                                vuln_type=vuln_type,
                                                target=location,
                                            )

                                        # Queue for validation if enabled
                                        if self._validation_orchestrator:
                                            self._pending_validations.append(finding_data)
                                            logger.info(
                                                "finding_queued_for_validation",
                                                vuln_type=vuln_type,
                                                target=location,
                                                queue_size=len(self._pending_validations),
                                            )

                                        # Handle finding for strategic planning
                                        await self._handle_finding(finding_data)

                            # Check for subagent spawn via swarm tool
                            if block.name == "swarm" and self._on_subagent_spawn:
                                inp = block.input
                                if isinstance(inp, dict):
                                    agent_type = inp.get("agent_type", inp.get("type", "scanner"))
                                    agent_id = f"{agent_type}_{turns}"
                                    self._on_subagent_spawn(agent_id, agent_type)

                elif isinstance(message, UserMessage):
                    # Handle tool results which come in UserMessage
                    if isinstance(message.content, list):
                        for block in message.content:
                            if isinstance(block, ToolResultBlock):
                                # Match result to tool call
                                tool_name = pending_tools.pop(block.tool_use_id, "unknown")

                                # Get result content
                                output = ""
                                if block.content:
                                    if isinstance(block.content, str):
                                        output = block.content
                                    elif isinstance(block.content, list):
                                        for content in block.content:
                                            if isinstance(content, dict) and "text" in content:
                                                output += content["text"]
                                            elif hasattr(content, "text"):
                                                output += content.text

                                # Track errors for progress monitoring
                                is_error = block.is_error or False
                                if is_error:
                                    self._consecutive_errors += 1
                                    self._turns_without_progress += 1

                                    # Record failed attempt for diminishing returns
                                    if self._diminishing_tracker:
                                        category = self._get_current_attack_category()
                                        import hashlib
                                        signature = hashlib.md5(output[:500].encode()).hexdigest()
                                        self._diminishing_tracker.record_attempt(
                                            category=category,
                                            success=False,
                                            response_signature=signature,
                                            details={"tool": tool_name, "error": True},
                                        )
                                else:
                                    self._consecutive_errors = 0  # Reset on success

                                    # Record successful attempt for diminishing returns
                                    if self._diminishing_tracker:
                                        category = self._get_current_attack_category()
                                        import hashlib
                                        signature = hashlib.md5(output[:500].encode()).hexdigest()
                                        # Consider it a success if output is substantial and not an error
                                        success = len(output) > 100 and "error" not in output.lower()[:200]
                                        self._diminishing_tracker.record_attempt(
                                            category=category,
                                            success=success,
                                            response_signature=signature,
                                            details={"tool": tool_name, "output_length": len(output)},
                                        )

                                # CTF mode: scan tool results for flags
                                if self._ctf_mode and self._flag_detector and output:
                                    found_flags_in_output = self._flag_detector.scan_for_flags(
                                        output, source=f"tool_result:{tool_name}"
                                    )
                                    if found_flags_in_output:
                                        for flag_info in found_flags_in_output:
                                            if flag_info.confidence > 0.7:
                                                flags_found.append(flag_info.flag)
                                                logger.info(
                                                    "flag_found_in_tool_result",
                                                    tool=tool_name,
                                                    flag=flag_info.flag[:50],
                                                    confidence=flag_info.confidence,
                                                )

                                if self._on_tool_result:
                                    self._on_tool_result(tool_name, output, is_error)

                elif isinstance(message, ResultMessage):
                    turns = message.num_turns
                    total_cost = message.total_cost_usd

                    # Track turns without findings
                    self._turns_without_findings = turns - self._last_finding_turn

                    # Estimate tokens from cost (rough: $3/1M input, $15/1M output for Opus)
                    total_tokens = int(total_cost / 0.000015) if total_cost > 0 else 0

                    # Fire turn callback for dashboard updates
                    if self._on_turn:
                        self._on_turn(turns, total_tokens, total_cost)

                    # Check for diminishing returns and inject warning if needed
                    if self._diminishing_tracker and turns % 5 == 0:  # Check every 5 turns
                        warning = self._check_and_inject_diminishing_returns()
                        if warning and self._on_message:
                            self._on_message(warning)

                    # CAI-inspired: Auto-trigger context compaction at high turn counts
                    compaction_prompt = self._build_context_compaction_prompt(turns, self._findings_count)
                    if compaction_prompt and self._on_message:
                        self._on_message(compaction_prompt)
                        logger.info("context_compaction_triggered", turn=turns)

                    # Determine stop reason from subtype
                    if message.subtype == "success":
                        local_stop_reason = "success"
                    elif message.subtype in ("max_turns", "error_max_turns"):
                        local_stop_reason = "max_turns"
                    elif message.subtype == "error_max_budget":
                        local_stop_reason = "max_budget"
                    elif message.is_error:
                        local_stop_reason = "error"
                    else:
                        local_stop_reason = message.subtype or "unknown"

                    if message.is_error:
                        local_error = str(message.result)
                    else:
                        # Check if objective was met based on result
                        result_text = str(message.result).lower()
                        local_objective_met = (
                            "objective met" in result_text or
                            "assessment complete" in result_text or
                            "completed successfully" in result_text or
                            "flag" in result_text or
                            "all vulnerabilities" in result_text or
                            len(flags_found) > 0  # CTF mode: finding flag = objective met
                        )
                        findings_summary = message.result

                    logger.info(
                        "assessment_segment_completed",
                        operation_id=operation_id,
                        turns=turns,
                        cost_usd=total_cost,
                        stop_reason=local_stop_reason,
                        objective_met=local_objective_met,
                        flags_found=len(flags_found),
                    )

            return local_stop_reason, local_objective_met, local_error

        try:
            async with ClaudeSDKClient(options=options) as client:
                # Send initial prompt
                await client.query(prompt)

                # Process initial response
                stop_reason, objective_met, error = await process_response_stream(client)

                # Auto-continue loop: if we hit max_turns but objective not met, continue
                while (
                    config.auto_continue
                    and stop_reason == "max_turns"
                    and not objective_met
                    and continuation_count < config.max_continuations
                    and error is None
                ):
                    continuation_count += 1

                    logger.info(
                        "auto_continuing",
                        operation_id=operation_id,
                        continuation=continuation_count,
                        max_continuations=config.max_continuations,
                        turns_so_far=turns,
                    )

                    # Build continuation prompt with memory recall and backtrack suggestions
                    continuation_prompt = self._build_continuation_prompt(
                        config=config,
                        continuation_count=continuation_count,
                        turns=turns,
                        total_cost=total_cost,
                    )

                    if self._on_message:
                        self._on_message(f"\n[Auto-continuing: {continuation_count}/{config.max_continuations}]")

                    # Clear pending tools to avoid concurrency issues
                    pending_tools.clear()

                    # Longer delay to ensure previous response is fully processed
                    # The API needs time to finalize the previous turn
                    await asyncio.sleep(5.0)

                    # Use a NEW client for continuation to avoid session concurrency issues
                    # The previous session may have pending tool calls that conflict
                    async with ClaudeSDKClient(options=options) as continuation_client:
                        # Retry loop for concurrency errors
                        max_retries = 3
                        for retry in range(max_retries):
                            try:
                                await continuation_client.query(continuation_prompt)
                                # Process continuation response
                                stop_reason, objective_met, error = await process_response_stream(continuation_client)

                                # Check if we got a concurrency error in the response
                                if error and ("concurrency" in error.lower() or "400" in str(error)):
                                    if retry < max_retries - 1:
                                        logger.warning(
                                            "continuation_concurrency_error_response",
                                            retry=retry + 1,
                                            error=error,
                                        )
                                        pending_tools.clear()
                                        await asyncio.sleep(5.0 * (retry + 1))  # Exponential backoff
                                        error = None  # Clear error for retry
                                        continue
                                break  # Success or non-retryable error

                            except Exception as cont_error:
                                error_str = str(cont_error)
                                if ("concurrency" in error_str.lower() or "400" in error_str) and retry < max_retries - 1:
                                    logger.warning(
                                        "continuation_concurrency_error_exception",
                                        retry=retry + 1,
                                        error=error_str,
                                    )
                                    pending_tools.clear()
                                    await asyncio.sleep(5.0 * (retry + 1))
                                    continue
                                else:
                                    error = error_str
                                    stop_reason = "error"
                                    break

                        # If we exhausted retries with error, break the continuation loop
                        if error and stop_reason == "error":
                            break

                logger.info(
                    "assessment_completed",
                    operation_id=operation_id,
                    total_turns=turns,
                    total_cost_usd=total_cost,
                    continuations=continuation_count,
                    objective_met=objective_met,
                    stop_reason=stop_reason,
                    flags_found=len(flags_found),
                )

        except Exception as e:
            error = str(e)
            stop_reason = "error"
            logger.error(
                "assessment_failed",
                operation_id=operation_id,
                error=error,
            )

        ended_at = datetime.now(UTC)
        duration = (ended_at - started_at).total_seconds()

        # Run pending validations if enabled
        validation_summary = None
        if self._validation_orchestrator and self._pending_validations:
            try:
                logger.info("running_final_validations", pending=len(self._pending_validations))
                await self._run_pending_validations(config)
                validation_summary = self.get_validation_summary()
                logger.info("validation_complete", summary=validation_summary)
            except Exception as e:
                logger.error("final_validation_failed", error=str(e))

        # Calculate confidence from validation if available
        confidence = None
        if validation_summary and validation_summary.get("total", 0) > 0:
            confidence = int(validation_summary.get("average_confidence", 0))

        # Log diminishing returns statistics
        if self._diminishing_tracker:
            stats = self._diminishing_tracker.get_all_stats()
            logger.info("diminishing_returns_stats", **stats)

        # Log CTF mode statistics
        if self._ctf_mode and self._flag_detector:
            flag_stats = self._flag_detector.get_statistics()
            logger.info("ctf_flag_detection_stats", **flag_stats)

        result = ExecutionResult(
            operation_id=operation_id,
            objective_met=objective_met,
            findings_summary=findings_summary,
            confidence=confidence,
            stop_reason=stop_reason,
            turns=turns,
            total_cost_usd=total_cost,
            total_tokens=total_tokens,
            duration_seconds=duration,
            artifacts_dir=str(artifacts_dir),
            started_at=started_at,
            ended_at=ended_at,
            error=error,
            final_message=final_message,
            continuations=continuation_count,
            flags_found=list(set(flags_found)),  # Deduplicate
        )

        if self._on_complete:
            self._on_complete(result)

        # End and save session trace
        if self._session_trace:
            self._session_trace.end_session(
                summary=f"Objective {'met' if objective_met else 'not met'}. "
                        f"Found {self._findings_count} findings in {turns} turns."
            )
            json_path = self._session_trace.save_json()
            html_path = self._session_trace.save_html()
            logger.info(
                "session_trace_saved",
                json_path=str(json_path),
                html_path=str(html_path),
            )
            # Add trace paths to result for user reference
            result.trace_json_path = str(json_path)
            result.trace_html_path = str(html_path)

        # Cleanup temp files
        self._cleanup_temp_files()

        return result

    def _build_continuation_prompt(
        self,
        config: AssessmentConfig,
        continuation_count: int,
        turns: int,
        total_cost: float,
    ) -> str:
        """Build continuation prompt with memory recall and backtrack suggestions."""
        sections = [
            f"""[SEGMENT {continuation_count + 1}/{config.max_continuations + 1} STARTING]

CRITICAL: Previous conversation context has been reset. You MUST recall your findings from memory.

## FIRST ACTION REQUIRED:
Execute these memory commands IMMEDIATELY to recover your findings:
```
memory_list(memory_type="finding")
memory_list(memory_type="context")
memory_search(query="{config.target}")
```

## Assessment Status:
- **Target**: {config.target}
- **Objective**: {config.objective}
- **Turns used so far**: {turns}
- **Cost so far**: ${total_cost:.4f}
- **Findings discovered**: {self._findings_count}
- **Objective NOT yet met** - continue working"""
        ]

        # Add backtrack suggestion if branch tracking is enabled
        if self._branch_tracker:
            suggestion = self._branch_tracker.suggest_next_action()
            if suggestion:
                sections.append(f"""
## BACKTRACK SUGGESTION

The branch tracker has identified an **unexplored attack path** you should try:

**Decision Point**: {suggestion.get('context', 'Unknown')[:100]}
**Suggested Action**: {suggestion.get('option_description', 'Unknown')}
**Priority**: {suggestion.get('priority', 50)}

Consider trying this alternative approach before repeating failed techniques.""")

            # Add exploration summary
            summary = self._branch_tracker.get_exploration_summary()
            if summary.get('unexplored', 0) > 0:
                sections.append(f"""
## Exploration Progress
- **Paths explored**: {summary.get('explored', 0)}/{summary.get('total_options', 0)}
- **Unexplored paths**: {summary.get('unexplored', 0)}
- **Successful paths**: {summary.get('successful', 0)}
- **Dead ends**: {summary.get('dead_ends', 0)}""")

        # Add diminishing returns guidance
        if self._diminishing_tracker:
            pivot_suggestion = self._diminishing_tracker.generate_pivot_suggestion()
            if pivot_suggestion:
                sections.append(f"""
## DIMINISHING RETURNS ANALYSIS

{pivot_suggestion}

**IMPORTANT**: Don't repeat approaches that have been failing. Try completely different attack vectors.""")

        # Add chain enumeration suggestions if enabled
        if self._chain_enumerator and self._findings_count > 1:
            sections.append("""
## ATTACK CHAIN OPPORTUNITIES

You have multiple findings - consider COMBINING them:
1. After recalling memory, run chain enumeration to see all possible chains
2. Try the highest-priority chain that hasn't been attempted
3. Record results of each chain attempt""")

        sections.append("""
## After Memory Recall:
1. List ALL findings recovered from memory
2. Identify which attack vectors you were pursuing
3. Check for any vulnerability chains you haven't tried
4. **IMPORTANT**: If you've been trying the same approach repeatedly, SWITCH to a different vector

## Common Issues After Segment Reset:
- You may have extracted hashes but not tried to crack/bypass them
- You may have found file upload + LFI but not combined them
- You may have discovered user IDs but not tried them in token forgery
- You may have been stuck on one approach - try a DIFFERENT vector now

## IMPORTANT:
- If you discover NEW findings, save them with `memory_store` immediately
- Don't repeat failed approaches from previous segment
- If hash cracking failed, try SQLi bypass instead
- If one vulnerability type is blocked, try a completely different attack

Continue the assessment now. Start by recalling memories.""")

        return "\n".join(sections)

    def _create_quality_pipeline(self) -> None:
        """
        Create quality gate pipeline for finding validation.

        NOTE: Quality gates were removed in the rebuild. The LLM now validates
        findings directly through its reasoning process.

        Returns:
            None - quality gates disabled.
        """
        # Quality gates removed in rebuild - let the LLM validate findings
        return None

    def _create_validation_orchestrator(self, config: AssessmentConfig) -> None:
        """
        Create validation orchestrator with appropriate client.

        NOTE: Removed in rebuild. ValidationOrchestrator added complexity without proven value.
        The new philosophy: Let the LLM use execute_command to validate findings.
        """
        return None

    async def _run_pending_validations(self, config: AssessmentConfig) -> list[dict]:
        """
        Run validation on all pending findings.

        NOTE: Simplified in rebuild - just returns empty list.
        """
        return []

    def get_validation_summary(self) -> dict:
        """Get summary of validation results."""
        return {
            "total": len(self._validated_findings),
            "pending": len(self._pending_validations),
            "by_result": {},
            "average_confidence": 0.0,
            "confirmed_count": 0,
            "false_positive_count": 0,
        }

    def _cleanup_temp_files(self) -> None:
        """
        Clean up temporary files created during the assessment.

        Removes Python scripts, cookie files, and other temp files
        that may contain sensitive information.
        """
        import fnmatch
        import os
        import shutil

        tmp_dir = "/tmp"
        deleted_count = 0

        # Patterns to delete (files)
        file_patterns = [
            "sqli_*",
            "exploit_*",
            "payload_*",
            "fuzz_*",
            "scan_*",
            "cookies*.txt",
            "*_sqlmap*",
            "inferno_*.py",
            "inferno_*.jsonl",
        ]

        # Patterns to delete (directories)
        dir_patterns = [
            "gavel*",
            "inferno_*",
        ]

        try:
            # Clean up files
            for filename in os.listdir(tmp_dir):
                filepath = os.path.join(tmp_dir, filename)

                # Check file patterns
                if os.path.isfile(filepath):
                    for pattern in file_patterns:
                        if fnmatch.fnmatch(filename, pattern):
                            try:
                                os.remove(filepath)
                                deleted_count += 1
                            except (PermissionError, OSError):
                                pass
                            break

                # Check directory patterns
                elif os.path.isdir(filepath):
                    for pattern in dir_patterns:
                        if fnmatch.fnmatch(filename, pattern):
                            try:
                                shutil.rmtree(filepath)
                                deleted_count += 1
                            except (PermissionError, OSError):
                                pass
                            break

            logger.debug("temp_files_cleanup_complete", deleted=deleted_count)
        except Exception as e:
            logger.debug("temp_files_cleanup_error", error=str(e))

    async def chat(
        self,
        message: str,
        config: AssessmentConfig,
        system_prompt: str | None = None,
    ) -> str:
        """
        Send a follow-up message to the agent after assessment completion.

        This allows users to ask questions, request new scripts, or continue
        testing after the main assessment is complete. The agent retains
        full context of the assessment.

        Args:
            message: User's follow-up message/question.
            config: Original assessment configuration.
            system_prompt: Optional override for system prompt.

        Returns:
            Agent's response as a string.
        """
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
        from claude_agent_sdk.types import (
            AssistantMessage,
            ResultMessage,
            TextBlock,
            ThinkingBlock,
            ToolUseBlock,
        )

        # Build context-aware prompt
        chat_prompt = f"""You are continuing a security assessment conversation. The user wants to interact with you after the assessment report.

CONTEXT:
- Target: {config.target}
- Original Objective: {config.objective}
- Mode: {config.mode}

The assessment has completed and findings have been reported. You still have access to all tools.
You can:
1. Answer questions about the findings
2. Create new exploit scripts or PoCs
3. Continue testing specific areas
4. Explain vulnerabilities in detail
5. Generate reports in different formats

USER REQUEST:
{message}

Respond helpfully while maintaining security assessment context."""

        # Configure SDK options for chat
        artifacts_dir = self._settings.get_artifacts_dir(config.target, "chat")
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Create Inferno MCP server
        from inferno.agent.mcp_tools import create_inferno_mcp_server
        inferno_mcp = create_inferno_mcp_server()

        options = ClaudeAgentOptions(
            max_turns=50,  # Limited turns for chat
            system_prompt=system_prompt or self._build_chat_system_prompt(config),
            permission_mode="default",
            cwd=str(artifacts_dir),
            mcp_servers={"inferno": inferno_mcp},
        )

        if config.model:
            options.model = config.model

        response_text = ""

        async with ClaudeSDKClient(options) as client:
            await client.send_user_message(chat_prompt)

            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, TextBlock):
                            response_text += block.text
                            if self._on_message:
                                self._on_message(block.text)
                        elif isinstance(block, ThinkingBlock):
                            if self._on_thinking:
                                self._on_thinking(block.thinking)
                        elif isinstance(block, ToolUseBlock):
                            if self._on_tool_call:
                                self._on_tool_call(block.name, block.input)

                elif isinstance(msg, ResultMessage):
                    for result in msg.content:
                        if self._on_tool_result:
                            is_error = getattr(result, 'is_error', False)
                            output = getattr(result, 'content', str(result))
                            self._on_tool_result("tool", output, is_error)

        return response_text

    def _build_chat_system_prompt(self, config: AssessmentConfig) -> str:
        """Build system prompt for interactive chat mode."""
        return f"""You are Inferno, an autonomous AI-powered penetration testing agent in INTERACTIVE CHAT MODE.

## CONTEXT
You have just completed a security assessment. The user wants to interact with you to:
- Ask questions about findings
- Request new exploit scripts or PoCs
- Continue testing specific areas
- Get detailed explanations
- Generate custom reports

## TARGET INFORMATION
- **Target**: {config.target}
- **Original Objective**: {config.objective}
- **Assessment Mode**: {config.mode}

## AVAILABLE TOOLS
You have access to all Inferno tools including:
- `execute_command` - Run any command (nmap, sqlmap, curl, python scripts, etc.)
- `http_request` - Make HTTP requests with advanced features
- `memory` - Recall findings from the assessment
- `think` - Structured reasoning for complex requests

## GUIDELINES
1. **Be helpful** - Answer questions thoroughly and create requested scripts
2. **Maintain context** - Reference findings from the completed assessment
3. **Create working code** - When asked for scripts, provide complete, working code
4. **Continue testing** - If asked to test more, proceed with full capability
5. **Use memory** - Search memory for relevant findings when answering questions

## RESPONSE STYLE
- Be direct and technical
- Provide code when requested
- Reference specific findings when relevant
- Offer to continue testing if appropriate"""


# Convenience function for simple assessments
async def run_assessment(
    target: str,
    objective: str = "Perform a comprehensive security assessment",
    max_turns: int = 500,
    on_message: Callable[[str], None] | None = None,
) -> ExecutionResult:
    """
    Run a simple security assessment.

    Args:
        target: Target URL or IP.
        objective: Assessment objective.
        max_turns: Maximum conversation turns.
        on_message: Callback for assistant messages.

    Returns:
        ExecutionResult with assessment outcome.
    """
    config = AssessmentConfig(
        target=target,
        objective=objective,
        max_turns=max_turns,
    )

    executor = SDKAgentExecutor()
    if on_message:
        executor.on_message(on_message)

    return await executor.run(config)


# ============================================================================
# Minimal Executor for Container-Based Execution (3-Tool Architecture)
# ============================================================================

@dataclass
class MinimalConfig:
    """Configuration for minimal container-based execution."""

    target: str
    objective: str
    max_turns: int = 100
    timeout: int = 3600  # 1 hour default


class MinimalSDKExecutor:
    """
    Minimal agent executor for container-based execution.

    This executor uses:
    - Minimal system prompt (~500 tokens instead of ~96k)
    - Only 3 tools: generic_linux_command, execute_code, web_request
    - Execution in Kali Docker container
    - No complex features (no branch tracking, no memory, no guardrails)

    Design Philosophy:
    - Let the LLM use its knowledge of security tools
    - Don't overwhelm with tool hints
    - Execute in isolated container for security
    """

    def __init__(self, settings: InfernoSettings | None = None) -> None:
        """Initialize the minimal executor."""
        self._settings = settings or InfernoSettings()

        # Simple callbacks
        self._on_message: Callable[[str], None] | None = None
        self._on_tool_call: Callable[[str, dict], None] | None = None
        self._on_tool_result: Callable[[str, str, bool], None] | None = None

        # Docker manager for container execution
        from inferno.setup.docker_manager import DockerManager
        self._docker = DockerManager()

    def on_message(self, callback: Callable[[str], None]) -> MinimalSDKExecutor:
        """Set callback for assistant messages."""
        self._on_message = callback
        return self

    def on_tool_call(self, callback: Callable[[str, dict], None]) -> MinimalSDKExecutor:
        """Set callback for tool calls."""
        self._on_tool_call = callback
        return self

    def on_tool_result(self, callback: Callable[[str, str, bool], None]) -> MinimalSDKExecutor:
        """Set callback for tool results."""
        self._on_tool_result = callback
        return self

    async def run(self, config: MinimalConfig) -> ExecutionResult:
        """
        Run a minimal security assessment in Docker container.

        Args:
            config: Minimal configuration.

        Returns:
            ExecutionResult with assessment outcome.
        """
        from inferno.agent.prompts import build_minimal_prompt

        started_at = datetime.now(UTC)
        operation_id = f"MIN_{started_at.strftime('%Y%m%d_%H%M%S')}"

        logger.info(
            "minimal_assessment_started",
            operation_id=operation_id,
            target=config.target,
            objective=config.objective[:100],
        )

        # Ensure Kali container is running
        if not self._docker.ensure_kali_running():
            return ExecutionResult(
                operation_id=operation_id,
                objective_met=False,
                findings_summary=None,
                confidence=None,
                stop_reason="error",
                turns=0,
                total_cost_usd=0.0,
                total_tokens=0,
                duration_seconds=0.0,
                artifacts_dir="/workspace",
                started_at=started_at,
                ended_at=datetime.now(UTC),
                error="Failed to start Kali container",
            )

        # Build minimal prompt
        system_prompt = build_minimal_prompt(config.target, config.objective)

        # Create MCP server with only 3 tools
        from mcp import Server
        from mcp.types import TextContent

        minimal_mcp = Server(name="inferno-minimal")

        @minimal_mcp.tool()
        async def generic_linux_command(
            command: str,
            timeout: int = 300,
            workdir: str = "/workspace",
        ) -> list[TextContent]:
            """Execute any Linux command in the Kali container."""
            if self._on_tool_call:
                self._on_tool_call("generic_linux_command", {"command": command})

            result = await self._docker.execute_in_kali(command, timeout=timeout, workdir=workdir)

            output = result["stdout"]
            if result["stderr"]:
                output += f"\n\nSTDERR:\n{result['stderr']}" if output else result["stderr"]

            is_error = not result["success"]
            if self._on_tool_result:
                self._on_tool_result("generic_linux_command", output, is_error)

            return [TextContent(type="text", text=output)]

        @minimal_mcp.tool()
        async def execute_code(
            code: str,
            language: str = "python",
            timeout: int = 300,
        ) -> list[TextContent]:
            """Execute Python or Bash code in the Kali container."""
            if self._on_tool_call:
                self._on_tool_call("execute_code", {"code": code[:100], "language": language})

            # Build execution command
            if language in ("python", "python3"):
                cmd = f"python3 << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"
            else:
                cmd = f"bash << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"

            result = await self._docker.execute_in_kali(cmd, timeout=timeout, workdir="/workspace")

            output = result["stdout"]
            if result["stderr"]:
                output += f"\n\nSTDERR:\n{result['stderr']}" if output else result["stderr"]

            is_error = not result["success"]
            if self._on_tool_result:
                self._on_tool_result("execute_code", output, is_error)

            return [TextContent(type="text", text=output)]

        @minimal_mcp.tool()
        async def web_request(
            url: str,
            method: str = "GET",
            headers: dict | None = None,
            body: str | None = None,
            timeout: int = 30,
        ) -> list[TextContent]:
            """Make HTTP request with full control."""
            if self._on_tool_call:
                self._on_tool_call("web_request", {"url": url, "method": method})

            import httpx

            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                    response = await client.request(
                        method=method,
                        url=url,
                        headers=headers,
                        content=body,
                    )

                output = f"Status: {response.status_code}\n\nHeaders:\n"
                for name, value in response.headers.items():
                    output += f"  {name}: {value}\n"
                output += f"\nBody:\n{response.text[:50000]}"

                if self._on_tool_result:
                    self._on_tool_result("web_request", output, False)

                return [TextContent(type="text", text=output)]

            except Exception as e:
                error_msg = f"Error: {e}"
                if self._on_tool_result:
                    self._on_tool_result("web_request", error_msg, True)
                return [TextContent(type="text", text=error_msg)]

        # Auto-approve all tools
        async def auto_approve_tools(
            tool_name: str,
            tool_input: dict[str, Any],
            context: ToolPermissionContext,
        ) -> PermissionResultAllow:
            return PermissionResultAllow()

        # Configure SDK options with minimal settings
        options = ClaudeAgentOptions(
            max_turns=config.max_turns,
            system_prompt=system_prompt,
            permission_mode="bypassPermissions",
            mcp_servers={"inferno-minimal": minimal_mcp},
            can_use_tool=auto_approve_tools,
        )

        turns = 0
        total_cost = 0.0
        total_tokens = 0
        final_message = None
        error = None
        stop_reason = "unknown"
        objective_met = False

        try:
            async with ClaudeSDKClient(options=options) as client:
                # Send initial prompt
                await client.query(f"Begin assessment of {config.target}. Objective: {config.objective}")

                async for message in client.receive_response():
                    if isinstance(message, AssistantMessage):
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                final_message = block.text
                                if self._on_message:
                                    self._on_message(block.text)

                    elif isinstance(message, ResultMessage):
                        turns = message.num_turns
                        total_cost = message.total_cost_usd
                        total_tokens = int(total_cost / 0.000015) if total_cost > 0 else 0

                        if message.subtype == "success":
                            stop_reason = "success"
                            objective_met = True
                        elif message.subtype in ("max_turns", "error_max_turns"):
                            stop_reason = "max_turns"
                        elif message.is_error:
                            stop_reason = "error"
                            error = str(message.result)
                        else:
                            stop_reason = message.subtype or "unknown"

        except Exception as e:
            error = str(e)
            stop_reason = "error"
            logger.error("minimal_assessment_failed", error=error)

        ended_at = datetime.now(UTC)
        duration = (ended_at - started_at).total_seconds()

        logger.info(
            "minimal_assessment_completed",
            operation_id=operation_id,
            turns=turns,
            cost_usd=total_cost,
            duration_seconds=duration,
        )

        return ExecutionResult(
            operation_id=operation_id,
            objective_met=objective_met,
            findings_summary=final_message,
            confidence=None,
            stop_reason=stop_reason,
            turns=turns,
            total_cost_usd=total_cost,
            total_tokens=total_tokens,
            duration_seconds=duration,
            artifacts_dir="/workspace",
            started_at=started_at,
            ended_at=ended_at,
            error=error,
            final_message=final_message,
        )


# Convenience function for minimal assessments
async def run_minimal_assessment(
    target: str,
    objective: str = "Perform security assessment and find vulnerabilities",
    max_turns: int = 100,
    on_message: Callable[[str], None] | None = None,
) -> ExecutionResult:
    """
    Run a minimal container-based security assessment.

    Uses only 3 tools and a ~500 token system prompt.
    Executes in an isolated Kali Docker container.

    Args:
        target: Target URL or IP.
        objective: Assessment objective.
        max_turns: Maximum conversation turns.
        on_message: Callback for assistant messages.

    Returns:
        ExecutionResult with assessment outcome.
    """
    config = MinimalConfig(
        target=target,
        objective=objective,
        max_turns=max_turns,
    )

    executor = MinimalSDKExecutor()
    if on_message:
        executor.on_message(on_message)

    return await executor.run(config)
