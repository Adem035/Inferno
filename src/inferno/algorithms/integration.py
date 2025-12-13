"""
Integration layer for Inferno algorithms with agent loop.

Provides hooks and wrappers for integrating learning algorithms
with the existing agent infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog

from inferno.algorithms.manager import AttackRecommendation, get_algorithm_manager

logger = structlog.get_logger(__name__)


@dataclass
class SpawnDecision:
    """Decision about whether to spawn a subagent."""

    should_spawn: bool
    agent_type: str | None
    task: str | None
    trigger_name: str | None
    confidence: float
    rationale: str


class LoopIntegration:
    """Integration layer between algorithms and agent loop.

    Provides methods for:
    - Learned trigger selection
    - Outcome recording
    - Budget allocation
    - Attack recommendations
    """

    def __init__(self):
        """Initialize integration layer."""
        self._manager = get_algorithm_manager()
        self._pending_trigger: dict[str, Any] | None = None
        self._spawn_start_time: datetime | None = None

    def set_context(
        self,
        target: str,
        tech_stack: list[str] | None = None,
        endpoints: list[str] | None = None,
        phase: str = "reconnaissance",
    ) -> None:
        """Update context for all algorithms.

        Args:
            target: Target URL or IP
            tech_stack: Detected technologies
            endpoints: Discovered endpoints
            phase: Current assessment phase
        """
        self._manager.set_context(target, tech_stack, endpoints, phase)

    def should_spawn_subagent(
        self,
        available_triggers: list[str],
        metrics: dict[str, Any],
    ) -> SpawnDecision:
        """Determine if a subagent should be spawned using learned algorithms.

        Args:
            available_triggers: List of trigger names that could fire
            metrics: Current loop metrics

        Returns:
            SpawnDecision with recommendation
        """
        context = {
            "turns": metrics.get("turns", 0),
            "consecutive_errors": metrics.get("consecutive_errors", 0),
            "turns_since_finding": metrics.get("turns_since_finding", 0),
            "low_confidence_turns": metrics.get("low_confidence_turns", 0),
            "tech_stack": list(metrics.get("detected_technologies", set())),
            "budget_remaining": 1.0 - metrics.get("budget_used_percent", 0) / 100,
        }

        # Use algorithm to select best trigger
        if not available_triggers:
            return SpawnDecision(
                should_spawn=False,
                agent_type=None,
                task=None,
                trigger_name=None,
                confidence=0.0,
                rationale="No available triggers",
            )

        selected_trigger = self._manager.select_trigger(available_triggers, context)

        # Check if trigger conditions are actually met
        # (this is a filter - the loop still checks conditions)
        trigger_confidence = self._estimate_trigger_confidence(selected_trigger, metrics)

        if trigger_confidence < 0.3:
            return SpawnDecision(
                should_spawn=False,
                agent_type=None,
                task=None,
                trigger_name=selected_trigger,
                confidence=trigger_confidence,
                rationale=f"Trigger {selected_trigger} confidence too low ({trigger_confidence:.0%})",
            )

        # Select agent type
        available_agents = self._get_agents_for_trigger(selected_trigger, metrics)
        if not available_agents:
            available_agents = ["reconnaissance", "scanner", "exploiter"]

        selected_agent = self._manager.select_agent_type(available_agents, context)

        # Generate task
        task = self._generate_task(selected_trigger, selected_agent, metrics)

        # Store pending trigger for outcome recording
        self._pending_trigger = {
            "trigger_name": selected_trigger,
            "agent_type": selected_agent,
            "context": context,
        }
        self._spawn_start_time = datetime.now(UTC)

        return SpawnDecision(
            should_spawn=True,
            agent_type=selected_agent,
            task=task,
            trigger_name=selected_trigger,
            confidence=trigger_confidence,
            rationale=f"Algorithm selected {selected_trigger} -> {selected_agent}",
        )

    def _estimate_trigger_confidence(self, trigger: str, metrics: dict[str, Any]) -> float:
        """Estimate confidence that trigger should fire based on metrics."""
        confidence = 0.5  # Base confidence

        if trigger == "error_triggered":
            errors = metrics.get("consecutive_errors", 0)
            confidence = min(1.0, errors / 3.0)

        elif trigger == "no_findings_triggered":
            turns = metrics.get("turns_since_finding", 0)
            confidence = min(1.0, turns / 10.0)

        elif trigger == "confidence_triggered":
            low_conf_turns = metrics.get("low_confidence_turns", 0)
            confidence = min(1.0, low_conf_turns / 3.0)

        elif trigger == "finding_triggered":
            # Finding triggers always have high confidence
            confidence = 0.8

        elif trigger == "phase_triggered":
            confidence = 0.7

        elif trigger == "target_triggered":
            confidence = 0.6

        return confidence

    def _get_agents_for_trigger(self, trigger: str, metrics: dict[str, Any]) -> list[str]:
        """Get appropriate agent types for a trigger."""
        trigger_agents = {
            "finding_triggered": ["exploiter", "validator"],
            "error_triggered": ["analyzer", "reconnaissance"],
            "no_findings_triggered": ["scanner", "reconnaissance"],
            "confidence_triggered": ["scanner", "exploiter"],
            "phase_triggered": ["scanner", "exploiter", "post_exploitation"],
            "target_triggered": ["scanner", "exploiter"],
        }
        return trigger_agents.get(trigger, ["reconnaissance"])

    def _generate_task(self, trigger: str, agent_type: str, metrics: dict[str, Any]) -> str:
        """Generate task description based on trigger and agent."""
        tasks = {
            ("finding_triggered", "exploiter"): "Exploit discovered vulnerabilities with advanced techniques",
            ("finding_triggered", "validator"): "Validate discovered findings and eliminate false positives",
            ("error_triggered", "analyzer"): "Analyze errors and identify alternative approaches",
            ("error_triggered", "reconnaissance"): "Re-enumerate the target with different techniques",
            ("no_findings_triggered", "scanner"): "Deep scan using alternative vulnerability detection methods",
            ("no_findings_triggered", "reconnaissance"): "Broaden reconnaissance to discover new attack surface",
            ("confidence_triggered", "scanner"): "Focused scanning on most promising endpoints",
            ("confidence_triggered", "exploiter"): "Try exploitation on medium-confidence findings",
        }

        key = (trigger, agent_type)
        return tasks.get(key, f"Perform {agent_type} analysis on current target")

    def record_spawn_outcome(
        self,
        success: bool,
        findings_count: int,
        turns_used: int,
        tokens_used: int,
        severity_counts: dict[str, int] | None = None,
    ) -> None:
        """Record the outcome of a spawned subagent.

        Should be called after subagent completes.

        Args:
            success: Whether the subagent achieved its objective
            findings_count: Number of findings produced
            turns_used: Turns consumed
            tokens_used: Tokens consumed
            severity_counts: Counts by severity
        """
        if not self._pending_trigger:
            logger.warning("record_spawn_outcome called without pending trigger")
            return

        trigger_info = self._pending_trigger
        self._pending_trigger = None

        # Record trigger outcome
        self._manager.record_trigger_outcome(
            trigger_name=trigger_info["trigger_name"],
            agent_type=trigger_info["agent_type"],
            success=success,
            findings_count=findings_count,
            context=trigger_info["context"],
        )

        # Record agent outcome
        self._manager.record_agent_outcome(
            agent_type=trigger_info["agent_type"],
            success=success,
            findings_count=findings_count,
            turns_used=turns_used,
            tokens_used=tokens_used,
            severity_counts=severity_counts,
            context=trigger_info["context"],
        )

        logger.info(
            "spawn_outcome_recorded",
            trigger=trigger_info["trigger_name"],
            agent_type=trigger_info["agent_type"],
            success=success,
            findings=findings_count,
        )

    def record_attack_outcome(
        self,
        attack_type: str,
        target: str,
        success: bool,
        severity: str | None = None,
    ) -> None:
        """Record attack outcome for learning.

        Args:
            attack_type: Type of attack (sqli, xss, etc.)
            target: Target endpoint
            success: Whether attack succeeded
            severity: Severity of finding if successful
        """
        self._manager.record_attack_outcome(
            attack_type=attack_type,
            target=target,
            success=success,
            severity=severity,
        )

    def get_attack_recommendation(
        self,
        endpoints: list[str] | None = None,
        phase: str = "reconnaissance",
    ) -> AttackRecommendation | None:
        """Get algorithm-recommended attack.

        Args:
            endpoints: Available endpoints
            phase: Current phase

        Returns:
            Attack recommendation or None
        """
        return self._manager.recommend_attack(endpoints, phase)

    def get_budget_allocation(
        self,
        agent_type: str,
        phase: str,
        remaining_turns: int,
    ) -> int:
        """Get learned budget allocation for subagent.

        Args:
            agent_type: Type of subagent
            phase: Current phase
            remaining_turns: Remaining turns in assessment

        Returns:
            Recommended turns allocation
        """
        decision = self._manager.get_budget_allocation(agent_type, phase)
        # Scale to remaining turns
        return min(decision.allocated_turns, remaining_turns // 2)

    def get_statistics(self) -> dict[str, Any]:
        """Get algorithm statistics for display."""
        return self._manager.get_statistics()

    def save_state(self) -> None:
        """Save all algorithm states."""
        self._manager.save_all_states()

    def reset(self) -> None:
        """Reset all learned state (use with caution)."""
        self._manager.reset_learning()


# Singleton instance
_integration: LoopIntegration | None = None


def get_loop_integration() -> LoopIntegration:
    """Get the singleton loop integration instance."""
    global _integration
    if _integration is None:
        _integration = LoopIntegration()
    return _integration


# Convenience functions for use in agent loop
def learned_trigger_select(
    available_triggers: list[str],
    metrics: dict[str, Any],
) -> SpawnDecision:
    """Select trigger using learned algorithms."""
    return get_loop_integration().should_spawn_subagent(available_triggers, metrics)


def record_subagent_outcome(
    success: bool,
    findings_count: int,
    turns_used: int,
    tokens_used: int,
    severity_counts: dict[str, int] | None = None,
) -> None:
    """Record subagent outcome for learning."""
    get_loop_integration().record_spawn_outcome(
        success, findings_count, turns_used, tokens_used, severity_counts
    )
