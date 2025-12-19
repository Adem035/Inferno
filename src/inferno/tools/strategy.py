"""
Strategic decision-making tools using Q-Learning and failure tracking.

This module provides tools that integrate the reinforcement learning
algorithms to guide the agent's decision-making:

1. get_strategy - Get Q-learning based action recommendations
2. record_failure - Track failures to avoid repeating mistakes
3. record_success - Track successes to reinforce good strategies
4. get_swarm_plan - Generate a parallel swarm execution plan

These tools enable the agent to:
- Learn from failures and avoid repeating them
- Make data-driven decisions about which attacks to try
- Maximize coverage through parallel sub-agent spawning
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from inferno.algorithms.integration import get_loop_integration
from inferno.algorithms.qlearning import (
    ActionType,
    PentestPhase,
    create_state_from_metrics,
)
from inferno.tools.base import CoreTool, ToolCategory, ToolExample, ToolResult

logger = structlog.get_logger(__name__)


# Global failure tracker for learning from mistakes
class FailureTracker:
    """Track failures to avoid repeating the same mistakes."""

    def __init__(self):
        self._failures: dict[str, list[dict]] = {}  # endpoint -> list of failure info
        self._blocked_patterns: set[str] = set()
        self._consecutive_failures: dict[str, int] = {}  # pattern -> count

    def record_failure(
        self,
        endpoint: str,
        attack_type: str,
        reason: str,
        payload: str | None = None,
    ) -> str:
        """Record a failure and return guidance."""
        key = f"{endpoint}:{attack_type}"

        if endpoint not in self._failures:
            self._failures[endpoint] = []

        self._failures[endpoint].append({
            "attack_type": attack_type,
            "reason": reason,
            "payload": payload,
            "timestamp": datetime.now(UTC).isoformat(),
        })

        # Track consecutive failures
        self._consecutive_failures[key] = self._consecutive_failures.get(key, 0) + 1

        # Block pattern after 3 consecutive failures
        if self._consecutive_failures[key] >= 3:
            self._blocked_patterns.add(key)
            return f"BLOCKED: Pattern {key} blocked after 3 consecutive failures. Try different approach."

        return f"Failure recorded ({self._consecutive_failures[key]}/3). Consider: {self._get_alternative(attack_type, reason)}"

    def is_blocked(self, endpoint: str, attack_type: str) -> bool:
        """Check if a pattern is blocked."""
        return f"{endpoint}:{attack_type}" in self._blocked_patterns

    def get_failures_for_endpoint(self, endpoint: str) -> list[dict]:
        """Get all failures for an endpoint."""
        return self._failures.get(endpoint, [])

    def _get_alternative(self, attack_type: str, reason: str) -> str:
        """Suggest alternative approaches based on failure type."""
        alternatives = {
            "sqli": "Try different injection points, encoding, or bypass techniques",
            "xss": "Try different contexts (attribute, script, href), encoding",
            "ssti": "Try different template engine syntax, escaping",
            "lfi": "Try different wrappers (php://, data://), encoding",
            "ssrf": "Try different protocols, IP formats, redirects",
            "auth_bypass": "Try different headers, cookies, parameter manipulation",
        }

        if "waf" in reason.lower() or "blocked" in reason.lower():
            return "WAF detected - spawn waf_bypass agent"
        if "timeout" in reason.lower():
            return "Request timeout - target may be rate limiting"
        if "403" in reason.lower():
            return "Access forbidden - try different path or authentication"

        return alternatives.get(attack_type, "Try alternative techniques or different endpoint")

    def reset_pattern(self, endpoint: str, attack_type: str) -> None:
        """Reset a blocked pattern (after successful bypass)."""
        key = f"{endpoint}:{attack_type}"
        self._blocked_patterns.discard(key)
        self._consecutive_failures[key] = 0

    def get_statistics(self) -> dict[str, Any]:
        """Get failure statistics."""
        return {
            "total_failures": sum(len(f) for f in self._failures.values()),
            "blocked_patterns": list(self._blocked_patterns),
            "endpoints_tested": len(self._failures),
            "consecutive_failures": dict(self._consecutive_failures),
        }


# Global instance
_failure_tracker = FailureTracker()


def get_failure_tracker() -> FailureTracker:
    """Get the global failure tracker."""
    return _failure_tracker


class GetStrategyTool(CoreTool):
    """
    Get Q-learning based strategic recommendations.

    This tool uses the reinforcement learning algorithm to recommend
    the best next action based on current pentest state.
    """

    @property
    def name(self) -> str:
        return "get_strategy"

    @property
    def description(self) -> str:
        return (
            "Get AI-powered strategic recommendations for next actions based on "
            "Q-learning algorithm. Provides ranked list of actions with confidence "
            "scores. Use this BEFORE deciding what to do next to make data-driven "
            "decisions instead of random testing."
        )

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.CORE

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "current_phase": {
                    "type": "string",
                    "enum": ["reconnaissance", "scanning", "exploitation", "post_exploitation", "reporting"],
                    "description": "Current phase of the assessment",
                },
                "endpoints_found": {
                    "type": "integer",
                    "description": "Number of endpoints discovered",
                    "default": 0,
                },
                "vulns_found": {
                    "type": "integer",
                    "description": "Number of vulnerabilities found",
                    "default": 0,
                },
                "shell_obtained": {
                    "type": "boolean",
                    "description": "Whether shell access has been obtained",
                    "default": False,
                },
                "tech_stack": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Detected technologies (php, java, python, node, etc)",
                    "default": [],
                },
            },
            "required": ["current_phase"],
        }

    @property
    def examples(self) -> list[ToolExample]:
        return [
            ToolExample(
                description="Get strategy after reconnaissance",
                input={
                    "current_phase": "scanning",
                    "endpoints_found": 15,
                    "vulns_found": 2,
                    "tech_stack": ["php", "mysql"],
                },
            ),
        ]

    async def execute(
        self,
        current_phase: str,
        endpoints_found: int = 0,
        vulns_found: int = 0,
        shell_obtained: bool = False,
        tech_stack: list[str] | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Get strategic recommendations."""
        try:
            integration = get_loop_integration()

            # Build state from inputs
            metrics = {
                "endpoints_found": endpoints_found,
                "vulns_medium": vulns_found,
                "shell_obtained": shell_obtained,
                "turns": 0,
                "consecutive_errors": 0,
            }

            state = create_state_from_metrics(metrics, tech_stack or [])

            # Get phase enum
            phase_map = {
                "reconnaissance": PentestPhase.RECONNAISSANCE,
                "scanning": PentestPhase.SCANNING,
                "exploitation": PentestPhase.EXPLOITATION,
                "post_exploitation": PentestPhase.POST_EXPLOITATION,
                "reporting": PentestPhase.REPORTING,
            }
            state.phase = phase_map.get(current_phase, PentestPhase.RECONNAISSANCE)

            # Get recommendations from Q-learning
            from inferno.algorithms.qlearning import QLearningAgent
            qlearning = QLearningAgent()
            recommendations = qlearning.get_action_recommendations(state, top_k=5)

            # Get failure statistics
            failure_stats = _failure_tracker.get_statistics()

            # Build output
            output_lines = [
                "## Strategic Recommendations (Q-Learning)",
                "",
                f"**Current Phase**: {current_phase}",
                f"**Endpoints**: {endpoints_found} | **Vulns**: {vulns_found}",
                f"**Blocked Patterns**: {len(failure_stats['blocked_patterns'])}",
                "",
                "### Recommended Actions (by Q-value)",
                "",
            ]

            for i, (action, q_value) in enumerate(recommendations, 1):
                action_name = action.value if hasattr(action, 'value') else str(action)
                swarm_mapping = self._get_swarm_mapping(action)
                output_lines.append(
                    f"{i}. **{action_name}** (Q={q_value:.2f})"
                )
                if swarm_mapping:
                    output_lines.append(f"   → Spawn: `swarm(agent_type=\"{swarm_mapping['agent_type']}\", task=\"{swarm_mapping['task']}\")`")
                output_lines.append("")

            # Add blocked patterns warning
            if failure_stats['blocked_patterns']:
                output_lines.append("### Blocked Patterns (3+ failures)")
                for pattern in failure_stats['blocked_patterns']:
                    output_lines.append(f"- {pattern}")
                output_lines.append("")

            output_lines.append("### Action Guidance")
            output_lines.append("")
            output_lines.append("1. **ALWAYS spawn sub-agents** for parallel execution")
            output_lines.append("2. Record failures with `record_failure` tool")
            output_lines.append("3. Exploit findings - don't just detect!")

            return ToolResult(
                success=True,
                output="\n".join(output_lines),
                metadata={
                    "recommendations": [(a.value, q) for a, q in recommendations],
                    "blocked_patterns": failure_stats['blocked_patterns'],
                },
            )

        except Exception as e:
            logger.error("get_strategy_error", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"Strategy calculation failed: {e}",
            )

    def _get_swarm_mapping(self, action: ActionType) -> dict[str, str] | None:
        """Map Q-learning action to swarm agent type."""
        mappings = {
            ActionType.NMAP_SCAN: {"agent_type": "reconnaissance", "task": "Run comprehensive nmap scan"},
            ActionType.SUBDOMAIN_ENUM: {"agent_type": "reconnaissance", "task": "Enumerate subdomains"},
            ActionType.DIRBUSTING: {"agent_type": "reconnaissance", "task": "Directory brute-force"},
            ActionType.VULN_SCAN: {"agent_type": "scanner", "task": "Vulnerability scanning"},
            ActionType.NUCLEI_SCAN: {"agent_type": "scanner", "task": "Nuclei vulnerability templates"},
            ActionType.SQLI_TEST: {"agent_type": "exploiter", "task": "SQL injection testing and exploitation"},
            ActionType.XSS_TEST: {"agent_type": "exploiter", "task": "XSS testing and exploitation"},
            ActionType.RCE_TEST: {"agent_type": "exploiter", "task": "Remote code execution testing"},
            ActionType.SSTI_TEST: {"agent_type": "exploiter", "task": "SSTI testing and exploitation"},
            ActionType.AUTH_BYPASS: {"agent_type": "exploiter", "task": "Authentication bypass testing"},
            ActionType.PRIV_ESC: {"agent_type": "post_exploitation", "task": "Privilege escalation"},
            ActionType.SPAWN_SUBAGENT: {"agent_type": "scanner", "task": "General purpose scanning"},
        }
        return mappings.get(action)


class RecordFailureTool(CoreTool):
    """
    Record a failure to learn from mistakes.

    This tool tracks failed attacks so the agent doesn't repeat
    the same mistakes. After 3 consecutive failures of the same
    type on the same endpoint, that pattern is blocked.
    """

    @property
    def name(self) -> str:
        return "record_failure"

    @property
    def description(self) -> str:
        return (
            "Record a failed attack attempt to learn from mistakes. "
            "CRITICAL: Call this EVERY time an attack fails! "
            "After 3 consecutive failures on same endpoint/attack_type, "
            "that pattern is blocked and you must try different approach."
        )

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.CORE

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "The endpoint that was tested (URL path)",
                },
                "attack_type": {
                    "type": "string",
                    "enum": ["sqli", "xss", "ssti", "lfi", "rfi", "ssrf", "auth_bypass", "rce", "xxe", "other"],
                    "description": "Type of attack that failed",
                },
                "reason": {
                    "type": "string",
                    "description": "Why it failed (waf_blocked, timeout, 403, no_vuln, etc)",
                },
                "payload": {
                    "type": "string",
                    "description": "The payload that was used (optional)",
                },
            },
            "required": ["endpoint", "attack_type", "reason"],
        }

    @property
    def examples(self) -> list[ToolExample]:
        return [
            ToolExample(
                description="Record SQLi failure due to WAF",
                input={
                    "endpoint": "/login",
                    "attack_type": "sqli",
                    "reason": "waf_blocked",
                    "payload": "' OR 1=1--",
                },
            ),
        ]

    async def execute(
        self,
        endpoint: str,
        attack_type: str,
        reason: str,
        payload: str | None = None,
        **kwargs: Any,
    ) -> ToolResult:
        """Record a failure."""
        guidance = _failure_tracker.record_failure(endpoint, attack_type, reason, payload)

        # Record in algorithm integration
        integration = get_loop_integration()
        integration.record_attack_outcome(
            attack_type=attack_type,
            target=endpoint,
            success=False,
            severity=None,
        )

        return ToolResult(
            success=True,
            output=guidance,
            metadata={
                "endpoint": endpoint,
                "attack_type": attack_type,
                "is_blocked": _failure_tracker.is_blocked(endpoint, attack_type),
            },
        )


class RecordSuccessTool(CoreTool):
    """
    Record a successful attack to reinforce good strategies.
    """

    @property
    def name(self) -> str:
        return "record_success"

    @property
    def description(self) -> str:
        return (
            "Record a successful attack to reinforce the learning algorithm. "
            "Call this when a vulnerability is CONFIRMED or EXPLOITED. "
            "This helps the agent learn which techniques work."
        )

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.CORE

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "The vulnerable endpoint",
                },
                "attack_type": {
                    "type": "string",
                    "enum": ["sqli", "xss", "ssti", "lfi", "rfi", "ssrf", "auth_bypass", "rce", "xxe", "other"],
                    "description": "Type of successful attack",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity of the finding",
                },
                "exploited": {
                    "type": "boolean",
                    "description": "Whether it was fully exploited (not just detected)",
                    "default": False,
                },
            },
            "required": ["endpoint", "attack_type", "severity"],
        }

    @property
    def examples(self) -> list[ToolExample]:
        return [
            ToolExample(
                description="Record successful SQLi exploitation",
                input={
                    "endpoint": "/search",
                    "attack_type": "sqli",
                    "severity": "high",
                    "exploited": True,
                },
            ),
        ]

    async def execute(
        self,
        endpoint: str,
        attack_type: str,
        severity: str,
        exploited: bool = False,
        **kwargs: Any,
    ) -> ToolResult:
        """Record a success."""
        # Reset any blocked pattern for this endpoint/attack
        _failure_tracker.reset_pattern(endpoint, attack_type)

        # Record in algorithm integration
        integration = get_loop_integration()
        integration.record_attack_outcome(
            attack_type=attack_type,
            target=endpoint,
            success=True,
            severity=severity,
        )

        status = "EXPLOITED" if exploited else "CONFIRMED"
        return ToolResult(
            success=True,
            output=f"Success recorded: {attack_type} on {endpoint} - {status} ({severity})\n"
                   f"Q-learning weights updated to reinforce this approach.",
            metadata={
                "endpoint": endpoint,
                "attack_type": attack_type,
                "severity": severity,
                "exploited": exploited,
            },
        )


class GetSwarmPlanTool(CoreTool):
    """
    Generate a parallel swarm execution plan.

    This tool analyzes the current state and generates a plan
    for spawning multiple sub-agents in parallel.
    """

    @property
    def name(self) -> str:
        return "get_swarm_plan"

    @property
    def description(self) -> str:
        return (
            "Generate a comprehensive plan for spawning multiple sub-agents "
            "in parallel. Use this when you have multiple targets, endpoints, "
            "or vulnerabilities to test. Returns executable swarm commands."
        )

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.CORE

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "endpoints": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of endpoints to test",
                },
                "vulns_to_exploit": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of confirmed vulnerabilities to exploit",
                },
                "subdomains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of subdomains to enumerate",
                },
                "max_parallel": {
                    "type": "integer",
                    "description": "Maximum parallel agents (default 5)",
                    "default": 5,
                },
            },
            "required": [],
        }

    @property
    def examples(self) -> list[ToolExample]:
        return [
            ToolExample(
                description="Plan for multiple endpoints",
                input={
                    "endpoints": ["/login", "/api/users", "/search", "/upload"],
                    "vulns_to_exploit": ["SQLi in /search?q="],
                    "max_parallel": 5,
                },
            ),
        ]

    async def execute(
        self,
        endpoints: list[str] | None = None,
        vulns_to_exploit: list[str] | None = None,
        subdomains: list[str] | None = None,
        max_parallel: int = 5,
        **kwargs: Any,
    ) -> ToolResult:
        """Generate swarm plan."""
        endpoints = endpoints or []
        vulns_to_exploit = vulns_to_exploit or []
        subdomains = subdomains or []

        plan_lines = [
            "## Swarm Execution Plan",
            "",
            f"**Max Parallel Agents**: {max_parallel}",
            "",
        ]

        swarm_commands = []

        # Phase 1: Exploitation (highest priority)
        if vulns_to_exploit:
            plan_lines.append("### Phase 1: Exploitation (Priority)")
            for vuln in vulns_to_exploit[:max_parallel]:
                cmd = f'swarm(agent_type="exploiter", task="Fully exploit: {vuln}")'
                swarm_commands.append(cmd)
                plan_lines.append(f"- `{cmd}`")
            plan_lines.append("")

        # Phase 2: Endpoint scanning
        if endpoints:
            plan_lines.append("### Phase 2: Endpoint Scanning")
            for endpoint in endpoints[:max_parallel]:
                # Skip blocked patterns
                if not _failure_tracker.is_blocked(endpoint, "scanner"):
                    cmd = f'swarm(agent_type="scanner", task="Deep scan {endpoint} for all vuln types")'
                    swarm_commands.append(cmd)
                    plan_lines.append(f"- `{cmd}`")
            plan_lines.append("")

        # Phase 3: Subdomain enumeration
        if subdomains:
            plan_lines.append("### Phase 3: Subdomain Enumeration")
            for subdomain in subdomains[:max_parallel]:
                cmd = f'swarm(agent_type="reconnaissance", task="Enumerate and scan {subdomain}")'
                swarm_commands.append(cmd)
                plan_lines.append(f"- `{cmd}`")
            plan_lines.append("")

        # Execution instructions
        plan_lines.extend([
            "### Execution Instructions",
            "",
            "**IMPORTANT**: Execute these swarm commands NOW!",
            "Don't just read the plan - spawn the agents immediately.",
            "",
            "Copy and execute each command above, or use this batch:",
            "```",
        ])
        plan_lines.extend(swarm_commands[:max_parallel])
        plan_lines.append("```")

        return ToolResult(
            success=True,
            output="\n".join(plan_lines),
            metadata={
                "swarm_commands": swarm_commands,
                "total_agents": len(swarm_commands),
            },
        )


# Register tools
STRATEGY_TOOLS = [
    GetStrategyTool(),
    RecordFailureTool(),
    RecordSuccessTool(),
    GetSwarmPlanTool(),
]


def get_strategy_tools() -> list[CoreTool]:
    """Get all strategy tools."""
    return STRATEGY_TOOLS
