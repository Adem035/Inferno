"""
Algorithm Manager for Inferno.

Integrates all learning algorithms into a unified interface
that can be used by the agent loop and other components.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from inferno.algorithms.bandits import (
    ContextualBandit,
    ThompsonSampling,
    UCB1Selector,
)
from inferno.algorithms.base import OutcomeType, compute_reward
from inferno.algorithms.bayesian import (
    BayesianConfidence,
    EvidenceObservation,
    VulnerabilityType,
)
from inferno.algorithms.budget import (
    BudgetDecision,
    DynamicBudgetAllocator,
)
from inferno.algorithms.mcts import (
    MCTSEngine,
)
from inferno.algorithms.metrics import (
    AttackOutcome,
    MetricsCollector,
    TriggerOutcome,
)
from inferno.algorithms.qlearning import (
    ActionType,
    QLearningAgent,
    create_state_from_metrics,
)
from inferno.algorithms.state import get_state_manager

logger = structlog.get_logger(__name__)


@dataclass
class AttackRecommendation:
    """A recommendation from the algorithm manager."""

    attack_type: str
    target: str
    confidence: float
    expected_value: float
    rationale: str
    sources: list[str]  # Which algorithms contributed


class AlgorithmManager:
    """Central manager coordinating all learning algorithms.

    Provides a unified interface for:
    - Getting attack recommendations
    - Recording outcomes for learning
    - Managing algorithm state
    """

    _instance: AlgorithmManager | None = None

    def __new__(cls) -> AlgorithmManager:
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize algorithm manager."""
        if getattr(self, '_initialized', False):
            return

        # State manager
        self._state_manager = get_state_manager()

        # Metrics collector
        self._metrics = MetricsCollector()

        # Initialize algorithms
        self._trigger_selector = UCB1Selector(exploration_factor=2.0)
        self._agent_selector = ThompsonSampling()
        self._attack_selector = ContextualBandit(feature_dim=15)
        self._branch_selector = ThompsonSampling()

        self._bayesian = BayesianConfidence()
        self._qlearning = QLearningAgent(reward_mode="ctf")
        self._mcts = MCTSEngine()
        self._budget = DynamicBudgetAllocator()

        # Load persisted state
        self._load_all_states()

        # Context
        self._target: str = ""
        self._tech_stack: list[str] = []
        self._endpoints: list[str] = []
        self._phase: str = "reconnaissance"

        self._initialized = True

        logger.info("algorithm_manager_initialized")

    def _load_all_states(self) -> None:
        """Load all algorithm states from persistence."""
        # Trigger selector
        state = self._state_manager.get_trigger_state()
        if state:
            self._trigger_selector.load_state(state)

        # Agent selector
        state = self._state_manager.get_agent_state()
        if state:
            self._agent_selector.load_state(state)

        # Attack selector
        state = self._state_manager.get_attack_state()
        if state:
            self._attack_selector.load_state(state)

        # Branch selector
        state = self._state_manager.get_branch_state()
        if state:
            self._branch_selector.load_state(state)

        # Bayesian
        state = self._state_manager.get_bayesian_state()
        if state:
            self._bayesian.load_state(state)

        # Q-Learning
        state = self._state_manager.get_qlearning_state()
        if state:
            self._qlearning.load_state(state)

        # MCTS
        state = self._state_manager.get_mcts_state()
        if state:
            self._mcts.load_state(state)

        # Budget
        state = self._state_manager.get_budget_state()
        if state:
            self._budget.load_state(state)

    def save_all_states(self) -> None:
        """Save all algorithm states to persistence."""
        self._state_manager.update_trigger_state(self._trigger_selector.get_state())
        self._state_manager.update_agent_state(self._agent_selector.get_state())
        self._state_manager.update_attack_state(self._attack_selector.get_state())
        self._state_manager.update_branch_state(self._branch_selector.get_state())
        self._state_manager.update_bayesian_state(self._bayesian.get_state())
        self._state_manager.update_qlearning_state(self._qlearning.get_state())
        self._state_manager.update_mcts_state(self._mcts.get_state())
        self._state_manager.update_budget_state(self._budget.get_state())
        self._state_manager.save()

    def set_context(
        self,
        target: str,
        tech_stack: list[str] | None = None,
        endpoints: list[str] | None = None,
        phase: str = "reconnaissance",
    ) -> None:
        """Set current assessment context.

        Args:
            target: Target URL or IP
            tech_stack: Detected technologies
            endpoints: Discovered endpoints
            phase: Current assessment phase
        """
        self._target = target
        self._tech_stack = tech_stack or []
        self._endpoints = endpoints or []
        self._phase = phase

        # Update Bayesian with tech stack
        self._bayesian.set_tech_stack(self._tech_stack)

        logger.debug(
            "algorithm_context_set",
            target=target,
            tech_stack=self._tech_stack,
            phase=phase,
        )

    def select_trigger(
        self,
        available_triggers: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select best spawn trigger using learned algorithm.

        Args:
            available_triggers: List of available trigger names
            context: Optional context features

        Returns:
            Selected trigger name
        """
        if not available_triggers:
            return "finding_triggered"  # Default

        ctx = context or self._build_context()
        selected = self._trigger_selector.select(available_triggers, ctx)

        logger.debug("trigger_selected", trigger=selected)
        return selected

    def select_agent_type(
        self,
        available_agents: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select best agent type using learned algorithm.

        Args:
            available_agents: List of available agent types
            context: Optional context features

        Returns:
            Selected agent type
        """
        if not available_agents:
            return "reconnaissance"  # Default

        ctx = context or self._build_context()
        selected = self._agent_selector.select(available_agents, ctx)

        logger.debug("agent_selected", agent_type=selected)
        return selected

    def select_attack(
        self,
        available_attacks: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select best attack type using contextual bandit.

        Args:
            available_attacks: List of available attack types
            context: Optional context features

        Returns:
            Selected attack type
        """
        if not available_attacks:
            return "sqli"  # Default

        ctx = context or self._build_context()
        selected = self._attack_selector.select(available_attacks, ctx)

        logger.debug("attack_selected", attack_type=selected)
        return selected

    def select_branch_option(
        self,
        options: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select branch option using Thompson Sampling.

        Args:
            options: List of option IDs
            context: Optional context

        Returns:
            Selected option ID
        """
        if not options:
            raise ValueError("No options to select from")

        ctx = context or self._build_context()
        selected = self._branch_selector.select(options, ctx)

        logger.debug("branch_option_selected", option=selected)
        return selected

    def recommend_attack(
        self,
        endpoints: list[str] | None = None,
        phase: str | None = None,
    ) -> AttackRecommendation | None:
        """Get comprehensive attack recommendation.

        Combines signals from multiple algorithms:
        - Thompson Sampling for attack type
        - Bayesian confidence for vulnerability likelihood
        - Q-Learning for optimal sequencing
        - MCTS for path planning (if enough compute)

        Args:
            endpoints: Available endpoints
            phase: Current phase

        Returns:
            Attack recommendation or None
        """
        endpoints = endpoints or self._endpoints
        phase = phase or self._phase

        if not endpoints:
            return None

        # Build context
        context = self._build_context()

        # Get scores from different algorithms
        sources = []
        scores: dict[str, float] = {}

        # 1. Thompson Sampling for attack type
        attack_types = ["sqli", "xss", "rce", "lfi", "ssrf", "ssti", "idor"]
        ts_probs = self._attack_selector.get_action_scores(attack_types)

        for attack_type, prob in ts_probs.items():
            if attack_type not in scores:
                scores[attack_type] = 0.0
            scores[attack_type] += prob * 0.3  # 30% weight
        sources.append("thompson_sampling")

        # 2. Bayesian confidence
        for endpoint in endpoints[:5]:  # Limit to first 5
            hypotheses = self._bayesian.get_top_hypotheses(min_confidence=0.3)
            for hyp in hypotheses:
                attack_type = hyp.vuln_type.value
                if attack_type not in scores:
                    scores[attack_type] = 0.0
                scores[attack_type] += hyp.posterior * 0.3  # 30% weight
        if hypotheses:
            sources.append("bayesian_confidence")

        # 3. Q-Learning recommendation
        pentest_state = create_state_from_metrics(
            {"turns": 0, "consecutive_errors": 0},
            self._tech_stack
        )
        pentest_state.phase = self._phase_to_enum(phase)

        q_recommendations = self._qlearning.get_action_recommendations(pentest_state, top_k=5)
        for action, q_value in q_recommendations:
            attack_type = self._action_to_attack_type(action)
            if attack_type and attack_type not in scores:
                scores[attack_type] = 0.0
            if attack_type:
                scores[attack_type] += max(0, q_value) * 0.4  # 40% weight
        sources.append("qlearning")

        if not scores:
            return None

        # Select best attack
        best_attack = max(scores, key=scores.get)
        best_score = scores[best_attack]

        # Select target endpoint (prioritize discovered vulnerabilities)
        target = endpoints[0]  # Simple for now

        # Build rationale
        rationale_parts = []
        if "thompson_sampling" in sources:
            ts_score = ts_probs.get(best_attack, 0)
            rationale_parts.append(f"Thompson: {ts_score:.0%}")
        if "bayesian_confidence" in sources:
            rationale_parts.append("Bayesian: high posterior")
        if "qlearning" in sources:
            for action, q_value in q_recommendations:
                if self._action_to_attack_type(action) == best_attack:
                    rationale_parts.append(f"Q-value: {q_value:.2f}")
                    break

        return AttackRecommendation(
            attack_type=best_attack,
            target=target,
            confidence=min(1.0, best_score),
            expected_value=best_score,
            rationale="; ".join(rationale_parts),
            sources=sources,
        )

    def get_budget_allocation(
        self,
        agent_type: str,
        phase: str | None = None,
        discovered_vulns: list[str] | None = None,
    ) -> BudgetDecision:
        """Get budget allocation for a subagent.

        Args:
            agent_type: Type of subagent
            phase: Current phase
            discovered_vulns: Discovered vulnerabilities

        Returns:
            Budget allocation decision
        """
        phase = phase or self._phase
        return self._budget.allocate(agent_type, phase, discovered_vulns)

    def record_trigger_outcome(
        self,
        trigger_name: str,
        agent_type: str,
        success: bool,
        findings_count: int = 0,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Record trigger activation outcome for learning.

        Args:
            trigger_name: Name of trigger that fired
            agent_type: Agent type that was spawned
            success: Whether the spawn was successful
            findings_count: Number of findings from spawned agent
            context: Context at trigger time
        """
        ctx = context or self._build_context()

        # Calculate reward
        if success and findings_count > 0:
            reward = 1.0
            outcome = OutcomeType.SUCCESS
        elif success:
            reward = 0.5
            outcome = OutcomeType.PARTIAL
        else:
            reward = 0.0
            outcome = OutcomeType.FAILURE

        # Update trigger selector
        self._trigger_selector.update(trigger_name, reward, ctx)

        # Record metrics
        trigger_outcome = TriggerOutcome(
            trigger_name=trigger_name,
            agent_type=agent_type,
            context_features=ctx,
            spawned=True,
            outcome=outcome,
            reward=reward,
        )
        self._metrics.record_trigger_outcome(trigger_outcome)

        # Save state
        self._state_manager.update_trigger_state(self._trigger_selector.get_state())
        self._state_manager.increment_operations()
        self._state_manager.save_if_dirty()

    def record_agent_outcome(
        self,
        agent_type: str,
        success: bool,
        findings_count: int = 0,
        turns_used: int = 0,
        tokens_used: int = 0,
        severity_counts: dict[str, int] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Record subagent outcome for learning.

        Args:
            agent_type: Type of agent
            success: Whether successful
            findings_count: Number of findings
            turns_used: Turns consumed
            tokens_used: Tokens consumed
            severity_counts: Counts by severity
            context: Execution context
        """
        ctx = context or self._build_context()
        severity_counts = severity_counts or {}

        # Calculate reward
        reward = compute_reward(
            outcome=OutcomeType.SUCCESS if success else OutcomeType.FAILURE,
            findings_count=findings_count,
            turns_used=turns_used,
        )

        # Calculate finding value
        finding_value = (
            severity_counts.get("critical", 0) * 10.0 +
            severity_counts.get("high", 0) * 5.0 +
            severity_counts.get("medium", 0) * 2.0 +
            severity_counts.get("low", 0) * 0.5
        )

        # Update agent selector
        normalized_reward = min(1.0, max(0.0, (reward + 10) / 110))  # Normalize
        self._agent_selector.update(agent_type, normalized_reward, ctx)

        # Update budget allocator
        self._budget.record_usage(
            agent_type=agent_type,
            turns_used=turns_used,
            tokens_used=tokens_used,
            success=success,
            findings_count=findings_count,
            finding_value=finding_value,
            critical_count=severity_counts.get("critical", 0),
            high_count=severity_counts.get("high", 0),
        )

        # Save states
        self._state_manager.update_agent_state(self._agent_selector.get_state())
        self._state_manager.update_budget_state(self._budget.get_state())
        self._state_manager.increment_findings(findings_count)
        self._state_manager.save_if_dirty()

    def record_attack_outcome(
        self,
        attack_type: str,
        target: str,
        success: bool,
        severity: str | None = None,
        evidence: list[EvidenceObservation] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Record attack outcome for learning.

        Args:
            attack_type: Type of attack
            target: Target endpoint
            success: Whether successful
            severity: Finding severity
            evidence: Evidence observations
            context: Attack context
        """
        ctx = context or self._build_context()

        # Calculate reward
        reward = compute_reward(
            outcome=OutcomeType.SUCCESS if success else OutcomeType.FAILURE,
            severity=severity,
        )

        # Normalize for bandit
        normalized_reward = min(1.0, max(0.0, (reward + 1) / 12))

        # Update attack selector
        self._attack_selector.update(attack_type, normalized_reward, ctx)

        # Update Bayesian with evidence
        if evidence:
            try:
                vuln_type = VulnerabilityType(attack_type)
                for ev in evidence:
                    self._bayesian.update_with_evidence(vuln_type, target, ev)
            except ValueError:
                pass  # Unknown vuln type

        # Record metrics
        attack_outcome = AttackOutcome(
            attack_type=attack_type,
            target=target,
            parameter="",
            payload_class="",
            target_type=ctx.get("target_type", "web"),
            tech_stack=ctx.get("tech_stack", []),
            outcome=OutcomeType.SUCCESS if success else OutcomeType.FAILURE,
            severity=severity,
            confidence=1.0 if success else 0.0,
            reward=reward,
        )
        self._metrics.record_attack_outcome(attack_outcome)

        # Save states
        self._state_manager.update_attack_state(self._attack_selector.get_state())
        self._state_manager.update_bayesian_state(self._bayesian.get_state())
        self._state_manager.save_if_dirty()

    def record_branch_outcome(
        self,
        branch_id: str,
        option_id: str,
        success: bool,
        findings_count: int = 0,
    ) -> None:
        """Record branch exploration outcome.

        Args:
            branch_id: Branch ID
            option_id: Selected option ID
            success: Whether successful
            findings_count: Findings discovered
        """
        reward = 1.0 if success else 0.0
        self._branch_selector.update(option_id, reward)

        self._state_manager.update_branch_state(self._branch_selector.get_state())
        self._state_manager.save_if_dirty()

    def _build_context(self) -> dict[str, Any]:
        """Build context dictionary for algorithm selection."""
        return {
            "target": self._target,
            "target_type": self._infer_target_type(),
            "tech_stack": self._tech_stack,
            "phase": self._phase,
            "endpoints_count": len(self._endpoints),
            "budget_remaining": self._budget.remaining_turns / self._budget.total_turns,
        }

    def _infer_target_type(self) -> str:
        """Infer target type from context."""
        if "api" in self._target.lower():
            return "api"
        if any(cms in self._target.lower() for cms in ["wordpress", "drupal", "joomla"]):
            return "cms"
        return "web"

    def _phase_to_enum(self, phase: str):
        """Convert phase string to enum."""
        from inferno.algorithms.qlearning import PentestPhase
        phase_map = {
            "reconnaissance": PentestPhase.RECONNAISSANCE,
            "scanning": PentestPhase.SCANNING,
            "exploitation": PentestPhase.EXPLOITATION,
            "post_exploitation": PentestPhase.POST_EXPLOITATION,
            "reporting": PentestPhase.REPORTING,
        }
        return phase_map.get(phase, PentestPhase.RECONNAISSANCE)

    def _action_to_attack_type(self, action: ActionType) -> str | None:
        """Convert ActionType to attack type string."""
        action_map = {
            ActionType.SQLI_TEST: "sqli",
            ActionType.XSS_TEST: "xss",
            ActionType.RCE_TEST: "rce",
            ActionType.LFI_TEST: "lfi",
            ActionType.SSRF_TEST: "ssrf",
            ActionType.SSTI_TEST: "ssti",
            ActionType.AUTH_BYPASS: "auth_bypass",
        }
        return action_map.get(action)

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive statistics from all algorithms."""
        return {
            "state": self._state_manager.get_summary(),
            "metrics": self._metrics.get_summary(),
            "budget": self._budget.get_allocation_summary(),
            "bayesian_hypotheses": len(self._bayesian.get_top_hypotheses(min_confidence=0.3)),
            "qlearning_episodes": self._qlearning._episodes,
        }

    def reset_learning(self) -> None:
        """Reset all learned state (use with caution)."""
        self._state_manager.reset()
        self._metrics.clear()
        self._load_all_states()
        logger.warning("algorithm_learning_reset")


# Singleton accessor
_manager: AlgorithmManager | None = None


def get_algorithm_manager() -> AlgorithmManager:
    """Get the singleton algorithm manager instance."""
    global _manager
    if _manager is None:
        _manager = AlgorithmManager()
    return _manager


# Convenience functions
def recommend_attack(
    target: str,
    tech_stack: list[str] | None = None,
    endpoints: list[str] | None = None,
    phase: str = "reconnaissance",
) -> AttackRecommendation | None:
    """Convenience function to get attack recommendation."""
    manager = get_algorithm_manager()
    manager.set_context(target, tech_stack, endpoints, phase)
    return manager.recommend_attack()


def record_finding(
    attack_type: str,
    target: str,
    severity: str,
    tech_stack: list[str] | None = None,
) -> None:
    """Convenience function to record a finding."""
    manager = get_algorithm_manager()
    manager.set_context(target, tech_stack)
    manager.record_attack_outcome(attack_type, target, True, severity)
