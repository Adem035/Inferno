"""
Conditional pattern for Inferno.

This module provides the CONDITIONAL pattern implementation for
dynamic agent selection based on runtime conditions. Enables
adaptive workflows that choose different paths based on findings.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from inferno.patterns.pattern import Pattern, PatternType, conditional_pattern

if TYPE_CHECKING:
    from inferno.swarm.message_bus import MessageBus

logger = structlog.get_logger(__name__)


# Type alias for condition predicates
ConditionPredicate = Callable[[dict[str, Any]], bool]


@dataclass
class Condition:
    """
    A condition that determines which agent to execute.

    Conditions are evaluated in priority order, and the first
    matching condition determines the agent to run.
    """

    name: str
    agent: Any
    predicate: ConditionPredicate | None = None
    priority: int = 0
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def evaluate(self, context: dict[str, Any]) -> bool:
        """
        Evaluate this condition against the context.

        Args:
            context: Execution context to evaluate against.

        Returns:
            True if condition is met, False otherwise.
        """
        if self.predicate is None:
            # No predicate means always true (default/fallback)
            return True
        try:
            return self.predicate(context)
        except Exception as e:
            logger.warning(
                "condition_evaluation_error",
                condition=self.name,
                error=str(e),
            )
            return False


@dataclass
class ConditionalBranch:
    """
    A branch in conditional execution.

    Represents a path that may be taken based on condition evaluation.
    """

    condition: Condition
    agent_name: str
    selected: bool = False
    result: Any | None = None
    error: str | None = None


@dataclass
class ConditionalExecutionContext:
    """Context for conditional pattern execution."""

    target: str | None = None
    operation_id: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    context_data: dict[str, Any] = field(default_factory=dict)
    evaluated_conditions: list[str] = field(default_factory=list)
    selected_branch: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def set_data(self, key: str, value: Any) -> None:
        """Set context data used for condition evaluation."""
        self.context_data[key] = value

    def get_data(self, key: str, default: Any = None) -> Any:
        """Get context data."""
        return self.context_data.get(key, default)

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a security finding."""
        self.findings.append(finding)


@dataclass
class ConditionalExecutionResult:
    """Result from conditional pattern execution."""

    pattern_name: str
    total_conditions: int
    selected_condition: str | None
    selected_agent: str | None
    branches_evaluated: int
    agent_result: Any | None = None
    success: bool = True
    error: str | None = None
    duration_seconds: float = 0.0
    fallback_used: bool = False


class ConditionalExecutor:
    """
    Executor for conditional patterns.

    Evaluates conditions and executes the appropriate agent based
    on the first matching condition.
    """

    def __init__(
        self,
        default_timeout: float = 300.0,
        evaluate_all: bool = False,
        message_bus: MessageBus | None = None,
    ) -> None:
        """
        Initialize the conditional executor.

        Args:
            default_timeout: Default timeout for agent execution.
            evaluate_all: Whether to evaluate all conditions (for debugging).
            message_bus: Optional message bus for communication.
        """
        self._default_timeout = default_timeout
        self._evaluate_all = evaluate_all
        self._message_bus = message_bus

    async def execute_pattern(
        self,
        pattern: Pattern,
        agent_executor: Callable[[Any, ConditionalExecutionContext], Any],
        context_data: dict[str, Any] | None = None,
        target: str | None = None,
        operation_id: str | None = None,
    ) -> ConditionalExecutionResult:
        """
        Execute a conditional pattern.

        Args:
            pattern: The conditional pattern to execute.
            agent_executor: Async callable that executes a single agent.
            context_data: Data used for condition evaluation.
            target: Target URL/host.
            operation_id: Operation ID for memory sharing.

        Returns:
            ConditionalExecutionResult with execution details.

        Raises:
            ValueError: If pattern is not CONDITIONAL type.
        """
        if pattern.type != PatternType.CONDITIONAL:
            raise ValueError(
                f"ConditionalExecutor only handles CONDITIONAL patterns, "
                f"got {pattern.type.value}"
            )

        import time
        start_time = time.time()

        # Build conditions
        conditions = self._build_conditions(pattern)

        # Initialize context
        context = ConditionalExecutionContext(
            target=target,
            operation_id=operation_id,
            context_data=context_data or {},
        )

        logger.info(
            "starting_conditional_execution",
            pattern=pattern.name,
            total_conditions=len(conditions),
        )

        # Evaluate conditions and select agent
        selected_condition, selected_agent = self._evaluate_conditions(
            conditions,
            context,
        )

        if selected_condition is None:
            duration = time.time() - start_time
            logger.warning(
                "no_condition_matched",
                pattern=pattern.name,
            )
            return ConditionalExecutionResult(
                pattern_name=pattern.name,
                total_conditions=len(conditions),
                selected_condition=None,
                selected_agent=None,
                branches_evaluated=len(context.evaluated_conditions),
                success=False,
                error="No condition matched",
                duration_seconds=duration,
            )

        context.selected_branch = selected_condition.name

        logger.info(
            "condition_selected",
            pattern=pattern.name,
            condition=selected_condition.name,
            agent=getattr(selected_agent, "name", str(selected_agent)),
        )

        # Execute selected agent
        try:
            result = await asyncio.wait_for(
                agent_executor(selected_agent, context),
                timeout=self._default_timeout,
            )

            duration = time.time() - start_time

            return ConditionalExecutionResult(
                pattern_name=pattern.name,
                total_conditions=len(conditions),
                selected_condition=selected_condition.name,
                selected_agent=getattr(selected_agent, "name", str(selected_agent)),
                branches_evaluated=len(context.evaluated_conditions),
                agent_result=result,
                success=True,
                duration_seconds=duration,
                fallback_used=selected_condition.predicate is None,
            )

        except TimeoutError:
            duration = time.time() - start_time
            return ConditionalExecutionResult(
                pattern_name=pattern.name,
                total_conditions=len(conditions),
                selected_condition=selected_condition.name,
                selected_agent=getattr(selected_agent, "name", str(selected_agent)),
                branches_evaluated=len(context.evaluated_conditions),
                success=False,
                error=f"Timeout after {self._default_timeout}s",
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "conditional_execution_error",
                pattern=pattern.name,
                condition=selected_condition.name,
                error=str(e),
            )
            return ConditionalExecutionResult(
                pattern_name=pattern.name,
                total_conditions=len(conditions),
                selected_condition=selected_condition.name,
                selected_agent=getattr(selected_agent, "name", str(selected_agent)),
                branches_evaluated=len(context.evaluated_conditions),
                success=False,
                error=str(e),
                duration_seconds=duration,
            )

    def _build_conditions(self, pattern: Pattern) -> list[Condition]:
        """Build conditions from pattern."""
        conditions: list[Condition] = []

        for name, cond_data in pattern.conditions.items():
            agent = cond_data.get("agent")
            predicate = cond_data.get("predicate")

            condition = Condition(
                name=name,
                agent=agent,
                predicate=predicate,
                priority=cond_data.get("priority", 0),
                description=cond_data.get("description", ""),
            )
            conditions.append(condition)

        # Sort by priority (higher first)
        conditions.sort(key=lambda c: c.priority, reverse=True)

        return conditions

    def _evaluate_conditions(
        self,
        conditions: list[Condition],
        context: ConditionalExecutionContext,
    ) -> tuple[Condition | None, Any | None]:
        """
        Evaluate conditions and return the matching one.

        Returns:
            Tuple of (condition, agent) or (None, None) if no match.
        """
        fallback: Condition | None = None

        for condition in conditions:
            context.evaluated_conditions.append(condition.name)

            if condition.predicate is None:
                # This is a fallback (default) condition
                fallback = condition
                if not self._evaluate_all:
                    continue  # Check other conditions first
            else:
                if condition.evaluate(context.context_data):
                    return condition, condition.agent

        # No condition matched, use fallback if available
        if fallback:
            return fallback, fallback.agent

        return None, None


# Condition builder functions for common security scenarios


def vuln_type_condition(vuln_type: str) -> ConditionPredicate:
    """
    Create a condition that matches a specific vulnerability type.

    Args:
        vuln_type: Vulnerability type to match (e.g., "sqli", "xss").

    Returns:
        Predicate function.

    Example:
        >>> sqli_condition = vuln_type_condition("sqli")
        >>> cond = Condition("sqli_found", sqli_agent, sqli_condition)
    """
    def predicate(context: dict[str, Any]) -> bool:
        detected_type = context.get("vuln_type", "").lower()
        return vuln_type.lower() in detected_type

    return predicate


def technology_condition(technology: str) -> ConditionPredicate:
    """
    Create a condition that matches a specific technology.

    Args:
        technology: Technology to match (e.g., "wordpress", "nginx").

    Returns:
        Predicate function.
    """
    def predicate(context: dict[str, Any]) -> bool:
        detected_tech = context.get("technologies", [])
        if isinstance(detected_tech, str):
            detected_tech = [detected_tech]
        return any(
            technology.lower() in t.lower()
            for t in detected_tech
        )

    return predicate


def port_open_condition(port: int) -> ConditionPredicate:
    """
    Create a condition that checks if a specific port is open.

    Args:
        port: Port number to check.

    Returns:
        Predicate function.
    """
    def predicate(context: dict[str, Any]) -> bool:
        open_ports = context.get("open_ports", [])
        return port in open_ports

    return predicate


def service_condition(service: str) -> ConditionPredicate:
    """
    Create a condition that matches a specific service.

    Args:
        service: Service name to match (e.g., "ssh", "http").

    Returns:
        Predicate function.
    """
    def predicate(context: dict[str, Any]) -> bool:
        services = context.get("services", [])
        if isinstance(services, str):
            services = [services]
        return any(
            service.lower() in s.lower()
            for s in services
        )

    return predicate


def severity_condition(min_severity: str) -> ConditionPredicate:
    """
    Create a condition that matches minimum severity level.

    Args:
        min_severity: Minimum severity (critical, high, medium, low).

    Returns:
        Predicate function.
    """
    severity_order = ["low", "medium", "high", "critical"]

    def predicate(context: dict[str, Any]) -> bool:
        severity = context.get("severity", "low").lower()
        try:
            detected_idx = severity_order.index(severity)
            required_idx = severity_order.index(min_severity.lower())
            return detected_idx >= required_idx
        except ValueError:
            return False

    return predicate


def has_finding_condition(finding_type: str | None = None) -> ConditionPredicate:
    """
    Create a condition that checks if findings exist.

    Args:
        finding_type: Optional specific finding type to match.

    Returns:
        Predicate function.
    """
    def predicate(context: dict[str, Any]) -> bool:
        findings = context.get("findings", [])
        if not findings:
            return False
        if finding_type is None:
            return True
        return any(
            finding_type.lower() in f.get("type", "").lower()
            for f in findings
        )

    return predicate


# Pre-defined conditional patterns for pentest workflows


adaptive_exploit_pattern = conditional_pattern(
    name="adaptive_exploit",
    conditions={
        "sqli_detected": {
            "agent": "exploiter",
            "predicate": vuln_type_condition("sqli"),
            "priority": 10,
            "description": "SQL injection detected, use DB exploiter",
        },
        "xss_detected": {
            "agent": "exploiter",
            "predicate": vuln_type_condition("xss"),
            "priority": 9,
            "description": "XSS detected, use browser exploiter",
        },
        "auth_bypass_detected": {
            "agent": "token_forgery",
            "predicate": vuln_type_condition("auth"),
            "priority": 8,
            "description": "Auth issue detected, use token forger",
        },
        "default": {
            "agent": "scanner",
            "predicate": None,  # Fallback
            "priority": 0,
            "description": "No specific vuln, continue scanning",
        },
    },
    description="Select exploitation strategy based on vulnerability type",
)


technology_based_scan = conditional_pattern(
    name="technology_based_scan",
    conditions={
        "wordpress": {
            "agent": "scanner",
            "predicate": technology_condition("wordpress"),
            "priority": 10,
            "description": "WordPress detected, use WP scanner",
        },
        "api_detected": {
            "agent": "api_flow",
            "predicate": technology_condition("api"),
            "priority": 9,
            "description": "API detected, use API scanner",
        },
        "default": {
            "agent": "scanner",
            "predicate": None,
            "priority": 0,
            "description": "Default scanner",
        },
    },
    description="Select scanner based on detected technology",
)


severity_based_response = conditional_pattern(
    name="severity_based_response",
    conditions={
        "critical_found": {
            "agent": "validator",
            "predicate": severity_condition("critical"),
            "priority": 10,
            "description": "Critical finding - immediate validation",
        },
        "high_found": {
            "agent": "exploiter",
            "predicate": severity_condition("high"),
            "priority": 8,
            "description": "High severity - attempt exploitation",
        },
        "continue_scan": {
            "agent": "scanner",
            "predicate": None,
            "priority": 0,
            "description": "Lower severity - continue scanning",
        },
    },
    description="Response strategy based on finding severity",
)
