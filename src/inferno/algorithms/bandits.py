"""
Multi-Armed Bandit algorithms for Inferno.

Implements UCB1 and Thompson Sampling for intelligent attack vector
selection, balancing exploration of new attacks vs exploitation of
known-effective techniques.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any

import structlog

from inferno.algorithms.base import AlgorithmState, SelectionAlgorithm

logger = structlog.get_logger(__name__)


@dataclass
class ArmStats:
    """Statistics for a single bandit arm (attack type)."""

    pulls: int = 0
    total_reward: float = 0.0
    successes: int = 0
    failures: int = 0
    last_reward: float = 0.0

    # Tech-stack specific tracking
    tech_successes: dict[str, int] = field(default_factory=dict)
    tech_failures: dict[str, int] = field(default_factory=dict)

    @property
    def mean_reward(self) -> float:
        """Average reward for this arm."""
        return self.total_reward / self.pulls if self.pulls > 0 else 0.0

    @property
    def success_rate(self) -> float:
        """Success rate for binary outcomes."""
        total = self.successes + self.failures
        return self.successes / total if total > 0 else 0.5

    @property
    def beta_alpha(self) -> float:
        """Alpha parameter for Beta distribution (Thompson Sampling)."""
        return self.successes + 1

    @property
    def beta_beta(self) -> float:
        """Beta parameter for Beta distribution (Thompson Sampling)."""
        return self.failures + 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "pulls": self.pulls,
            "total_reward": self.total_reward,
            "successes": self.successes,
            "failures": self.failures,
            "last_reward": self.last_reward,
            "tech_successes": self.tech_successes,
            "tech_failures": self.tech_failures,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArmStats:
        """Create from dictionary."""
        return cls(
            pulls=data.get("pulls", 0),
            total_reward=data.get("total_reward", 0.0),
            successes=data.get("successes", 0),
            failures=data.get("failures", 0),
            last_reward=data.get("last_reward", 0.0),
            tech_successes=data.get("tech_successes", {}),
            tech_failures=data.get("tech_failures", {}),
        )


class UCB1Selector(SelectionAlgorithm[str]):
    """Upper Confidence Bound algorithm for action selection.

    UCB1 balances exploration (trying less-used options) vs exploitation
    (using options that have worked well) using the formula:

        UCB(a) = Q(a) + c * sqrt(ln(N) / n(a))

    where:
        Q(a) = average reward for action a
        N = total number of pulls
        n(a) = number of pulls for action a
        c = exploration factor (default 2.0)

    Good for: Subagent type selection, trigger priority ordering.
    """

    def __init__(self, exploration_factor: float = 2.0):
        """Initialize UCB1 selector.

        Args:
            exploration_factor: Controls exploration vs exploitation.
                               Higher = more exploration. Default 2.0.
        """
        self._exploration_factor = exploration_factor
        self._arms: dict[str, ArmStats] = {}
        self._total_pulls = 0

    def select(
        self,
        available_actions: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select action using UCB1 formula.

        Args:
            available_actions: List of available action names
            context: Optional context (not used in basic UCB1)

        Returns:
            Selected action name
        """
        if not available_actions:
            raise ValueError("No available actions to select from")

        # Initialize any new arms
        for action in available_actions:
            if action not in self._arms:
                self._arms[action] = ArmStats()

        # If any arm hasn't been pulled, pull it (exploration)
        for action in available_actions:
            if self._arms[action].pulls == 0:
                logger.debug("ucb1_exploring_new_arm", action=action)
                return action

        # Calculate UCB scores
        best_action = None
        best_score = float("-inf")

        for action in available_actions:
            arm = self._arms[action]
            exploitation = arm.mean_reward
            exploration = math.sqrt(
                self._exploration_factor * math.log(self._total_pulls) / arm.pulls
            )
            score = exploitation + exploration

            if score > best_score:
                best_score = score
                best_action = action

        logger.debug(
            "ucb1_selected",
            action=best_action,
            score=best_score,
            exploration_term=exploration,
        )
        return best_action

    def update(
        self,
        action: str,
        reward: float,
        context: dict[str, Any] | None = None
    ) -> None:
        """Update arm statistics with observed reward.

        Args:
            action: The action that was taken
            reward: The reward received (normalized to ~0-1)
            context: Optional context with 'tech_stack' for tech-specific tracking
        """
        if action not in self._arms:
            self._arms[action] = ArmStats()

        arm = self._arms[action]
        arm.pulls += 1
        arm.total_reward += reward
        arm.last_reward = reward

        # Binary success/failure for Beta distribution compatibility
        if reward > 0.5:
            arm.successes += 1
        else:
            arm.failures += 1

        # Tech-stack specific tracking
        if context and "tech_stack" in context:
            for tech in context["tech_stack"]:
                tech_key = tech.lower()
                if reward > 0.5:
                    arm.tech_successes[tech_key] = arm.tech_successes.get(tech_key, 0) + 1
                else:
                    arm.tech_failures[tech_key] = arm.tech_failures.get(tech_key, 0) + 1

        self._total_pulls += 1

        logger.debug(
            "ucb1_updated",
            action=action,
            reward=reward,
            total_pulls=arm.pulls,
            mean_reward=arm.mean_reward,
        )

    def get_action_scores(
        self,
        available_actions: list[str]
    ) -> dict[str, float]:
        """Get UCB scores for all actions."""
        if self._total_pulls == 0:
            return dict.fromkeys(available_actions, 1.0)

        scores = {}
        for action in available_actions:
            if action not in self._arms:
                scores[action] = float("inf")  # Unexplored = highest priority
            else:
                arm = self._arms[action]
                if arm.pulls == 0:
                    scores[action] = float("inf")
                else:
                    exploitation = arm.mean_reward
                    exploration = math.sqrt(
                        self._exploration_factor * math.log(self._total_pulls) / arm.pulls
                    )
                    scores[action] = exploitation + exploration

        return scores

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        return AlgorithmState(
            algorithm_name="UCB1",
            parameters={
                "exploration_factor": self._exploration_factor,
                "total_pulls": self._total_pulls,
            },
            history=[
                {"action": k, **v.to_dict()}
                for k, v in self._arms.items()
            ],
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        self._exploration_factor = state.parameters.get("exploration_factor", 2.0)
        self._total_pulls = state.parameters.get("total_pulls", 0)
        self._arms = {}
        for item in state.history:
            action = item.pop("action", None)
            if action:
                self._arms[action] = ArmStats.from_dict(item)


class ThompsonSampling(SelectionAlgorithm[str]):
    """Thompson Sampling for action selection.

    Uses Bayesian approach - samples from posterior distribution
    of success probability for each arm. Naturally balances
    exploration and exploitation.

    For each arm, maintains Beta(alpha, beta) distribution where:
        alpha = successes + 1
        beta = failures + 1

    Good for: Branch option selection, attack vector prioritization.
    """

    def __init__(self, prior_successes: int = 1, prior_failures: int = 1):
        """Initialize Thompson Sampling.

        Args:
            prior_successes: Prior successes (Bayesian prior alpha - 1)
            prior_failures: Prior failures (Bayesian prior beta - 1)
        """
        self._prior_successes = prior_successes
        self._prior_failures = prior_failures
        self._arms: dict[str, ArmStats] = {}

    def select(
        self,
        available_actions: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select action by sampling from Beta distributions.

        Args:
            available_actions: List of available action names
            context: Optional context with 'tech_stack' for contextual priors

        Returns:
            Selected action name
        """
        if not available_actions:
            raise ValueError("No available actions to select from")

        # Initialize any new arms
        for action in available_actions:
            if action not in self._arms:
                self._arms[action] = ArmStats(
                    successes=self._prior_successes,
                    failures=self._prior_failures,
                )

        # Sample from each arm's Beta distribution
        best_action = None
        best_sample = float("-inf")

        tech_stack = []
        if context and "tech_stack" in context:
            tech_stack = [t.lower() for t in context["tech_stack"]]

        for action in available_actions:
            arm = self._arms[action]

            # Adjust alpha/beta based on tech-stack specific data
            alpha = arm.beta_alpha
            beta = arm.beta_beta

            if tech_stack:
                for tech in tech_stack:
                    tech_successes = arm.tech_successes.get(tech, 0)
                    tech_failures = arm.tech_failures.get(tech, 0)
                    # Weight tech-specific data more heavily
                    alpha += tech_successes * 2
                    beta += tech_failures * 2

            # Sample from Beta(alpha, beta)
            try:
                sample = random.betavariate(alpha, beta)
            except ValueError:
                sample = 0.5  # Fallback for edge cases

            if sample > best_sample:
                best_sample = sample
                best_action = action

        logger.debug(
            "thompson_selected",
            action=best_action,
            sample=best_sample,
        )
        return best_action

    def update(
        self,
        action: str,
        reward: float,
        context: dict[str, Any] | None = None
    ) -> None:
        """Update arm with binary outcome.

        Args:
            action: The action that was taken
            reward: The reward received (>0.5 = success, <=0.5 = failure)
            context: Optional context with 'tech_stack'
        """
        if action not in self._arms:
            self._arms[action] = ArmStats(
                successes=self._prior_successes,
                failures=self._prior_failures,
            )

        arm = self._arms[action]
        arm.pulls += 1
        arm.total_reward += reward
        arm.last_reward = reward

        # Binary outcome for Beta distribution
        if reward > 0.5:
            arm.successes += 1
        else:
            arm.failures += 1

        # Tech-stack specific tracking
        if context and "tech_stack" in context:
            for tech in context["tech_stack"]:
                tech_key = tech.lower()
                if reward > 0.5:
                    arm.tech_successes[tech_key] = arm.tech_successes.get(tech_key, 0) + 1
                else:
                    arm.tech_failures[tech_key] = arm.tech_failures.get(tech_key, 0) + 1

        logger.debug(
            "thompson_updated",
            action=action,
            reward=reward,
            alpha=arm.beta_alpha,
            beta=arm.beta_beta,
        )

    def get_action_probabilities(
        self,
        available_actions: list[str],
        context: dict[str, Any] | None = None
    ) -> dict[str, float]:
        """Get estimated success probabilities for each action.

        Args:
            available_actions: List of available actions
            context: Optional context

        Returns:
            Dict mapping action -> estimated success probability
        """
        probs = {}
        for action in available_actions:
            if action in self._arms:
                arm = self._arms[action]
                # Expected value of Beta distribution
                probs[action] = arm.beta_alpha / (arm.beta_alpha + arm.beta_beta)
            else:
                # Uninformative prior
                total_prior = self._prior_successes + self._prior_failures + 2
                probs[action] = (self._prior_successes + 1) / total_prior
        return probs

    def get_action_scores(
        self,
        available_actions: list[str]
    ) -> dict[str, float]:
        """Get success probabilities as scores."""
        return self.get_action_probabilities(available_actions)

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        return AlgorithmState(
            algorithm_name="ThompsonSampling",
            parameters={
                "prior_successes": self._prior_successes,
                "prior_failures": self._prior_failures,
            },
            history=[
                {"action": k, **v.to_dict()}
                for k, v in self._arms.items()
            ],
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        self._prior_successes = state.parameters.get("prior_successes", 1)
        self._prior_failures = state.parameters.get("prior_failures", 1)
        self._arms = {}
        for item in state.history:
            action = item.pop("action", None)
            if action:
                self._arms[action] = ArmStats.from_dict(item)


class ContextualBandit(SelectionAlgorithm[str]):
    """Contextual bandit using linear regression on context features.

    Uses LinUCB algorithm for context-aware selection. The expected
    reward for each action is modeled as a linear function of context.

    Good for: Decisions that depend on target type, tech stack,
    current phase, remaining budget, etc.
    """

    def __init__(self, feature_dim: int = 15, alpha: float = 1.0):
        """Initialize contextual bandit.

        Args:
            feature_dim: Dimension of context feature vector
            alpha: Exploration parameter (higher = more exploration)
        """
        self._feature_dim = feature_dim
        self._alpha = alpha
        self._arms: dict[str, dict[str, Any]] = {}

    def _init_arm(self, action: str) -> None:
        """Initialize arm parameters for LinUCB."""
        if action not in self._arms:
            import numpy as np
            self._arms[action] = {
                "A": np.eye(self._feature_dim),  # d x d identity
                "b": np.zeros(self._feature_dim),  # d x 1 zero vector
                "pulls": 0,
            }

    def _get_context_vector(self, context: dict[str, Any] | None) -> Any:
        """Convert context dict to feature vector.

        Features:
        - Target type (one-hot, 5 dims)
        - Tech stack indicators (5 dims)
        - Budget remaining (1 dim)
        - Findings count (1 dim, log-scaled)
        - Turns elapsed (1 dim, normalized)
        - Phase (one-hot, 2 dims for exploration/exploitation)
        """
        import numpy as np

        if context is None:
            return np.ones(self._feature_dim) / self._feature_dim

        features = []

        # Target type features (5 dims)
        target_types = ["web", "api", "cms", "mobile", "internal"]
        target_type = context.get("target_type", "web").lower()
        features.extend([1.0 if t == target_type else 0.0 for t in target_types])

        # Tech stack features (5 dims)
        tech_categories = ["php", "python", "java", "node", "dotnet"]
        tech_stack = [t.lower() for t in context.get("tech_stack", [])]
        features.extend([
            1.0 if any(tc in " ".join(tech_stack) for tc in [cat]) else 0.0
            for cat in tech_categories
        ])

        # Numeric features (3 dims)
        features.append(context.get("budget_remaining", 0.5))
        findings = context.get("findings_count", 0)
        features.append(min(1.0, math.log1p(findings) / 3.0))  # Log-scaled, capped
        features.append(min(1.0, context.get("turns_elapsed", 0) / 100))

        # Phase features (2 dims)
        phase = context.get("phase", "reconnaissance").lower()
        features.append(1.0 if phase in ["reconnaissance", "scanning"] else 0.0)
        features.append(1.0 if phase in ["exploitation", "post_exploitation"] else 0.0)

        # Pad or truncate to feature_dim
        features = features[:self._feature_dim]
        while len(features) < self._feature_dim:
            features.append(0.0)

        return np.array(features)

    def select(
        self,
        available_actions: list[str],
        context: dict[str, Any] | None = None
    ) -> str:
        """Select action using LinUCB.

        Args:
            available_actions: List of available actions
            context: Context features

        Returns:
            Selected action
        """
        import numpy as np

        if not available_actions:
            raise ValueError("No available actions")

        x = self._get_context_vector(context)

        best_action = None
        best_ucb = float("-inf")

        for action in available_actions:
            self._init_arm(action)
            arm = self._arms[action]

            try:
                A_inv = np.linalg.inv(arm["A"])
                theta = A_inv @ arm["b"]

                # UCB = theta^T * x + alpha * sqrt(x^T * A^-1 * x)
                exploitation = float(theta @ x)
                exploration = self._alpha * math.sqrt(float(x @ A_inv @ x))
                ucb = exploitation + exploration
            except np.linalg.LinAlgError:
                ucb = 1.0  # Fallback for singular matrix

            if ucb > best_ucb:
                best_ucb = ucb
                best_action = action

        logger.debug(
            "contextual_selected",
            action=best_action,
            ucb=best_ucb,
        )
        return best_action

    def update(
        self,
        action: str,
        reward: float,
        context: dict[str, Any] | None = None
    ) -> None:
        """Update arm parameters with observed reward.

        Args:
            action: Action taken
            reward: Reward received
            context: Context features
        """
        import numpy as np

        self._init_arm(action)
        x = self._get_context_vector(context)

        arm = self._arms[action]
        arm["A"] = arm["A"] + np.outer(x, x)
        arm["b"] = arm["b"] + reward * x
        arm["pulls"] += 1

        logger.debug(
            "contextual_updated",
            action=action,
            reward=reward,
            pulls=arm["pulls"],
        )

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        history = []
        for action, arm in self._arms.items():
            history.append({
                "action": action,
                "A": arm["A"].tolist(),
                "b": arm["b"].tolist(),
                "pulls": arm["pulls"],
            })

        return AlgorithmState(
            algorithm_name="ContextualBandit",
            parameters={
                "feature_dim": self._feature_dim,
                "alpha": self._alpha,
            },
            history=history,
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        import numpy as np

        self._feature_dim = state.parameters.get("feature_dim", 15)
        self._alpha = state.parameters.get("alpha", 1.0)
        self._arms = {}

        for item in state.history:
            action = item.get("action")
            if action:
                self._arms[action] = {
                    "A": np.array(item["A"]),
                    "b": np.array(item["b"]),
                    "pulls": item.get("pulls", 0),
                }


# Convenience factory functions
def create_attack_selector(
    algorithm: str = "thompson",
    **kwargs
) -> SelectionAlgorithm[str]:
    """Create an attack selection algorithm.

    Args:
        algorithm: Algorithm name ("ucb1", "thompson", "contextual")
        **kwargs: Algorithm-specific parameters

    Returns:
        Configured selection algorithm
    """
    algorithms = {
        "ucb1": UCB1Selector,
        "thompson": ThompsonSampling,
        "contextual": ContextualBandit,
    }

    if algorithm not in algorithms:
        raise ValueError(f"Unknown algorithm: {algorithm}. Choose from {list(algorithms.keys())}")

    return algorithms[algorithm](**kwargs)
