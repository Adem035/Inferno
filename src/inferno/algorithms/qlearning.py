"""
Q-Learning for Action Sequencing in Inferno.

Implements Q-Learning with function approximation for learning
optimal attack sequences. State representation captures the
current pentest context, and the agent learns to select actions
that maximize cumulative reward.
"""

from __future__ import annotations

import math
import random
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from inferno.algorithms.base import AlgorithmState, OutcomeType, ReinforcementLearner

logger = structlog.get_logger(__name__)


class PentestPhase(str, Enum):
    """Phases of a penetration test."""

    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class ActionType(str, Enum):
    """Types of pentest actions."""

    # Reconnaissance
    NMAP_SCAN = "nmap_scan"
    SUBDOMAIN_ENUM = "subdomain_enum"
    TECH_DETECT = "tech_detect"
    DIRBUSTING = "dirbusting"

    # Scanning
    VULN_SCAN = "vuln_scan"
    NIKTO_SCAN = "nikto_scan"
    NUCLEI_SCAN = "nuclei_scan"
    PARAM_DISCOVERY = "param_discovery"

    # Exploitation
    SQLI_TEST = "sqli_test"
    XSS_TEST = "xss_test"
    RCE_TEST = "rce_test"
    LFI_TEST = "lfi_test"
    AUTH_BYPASS = "auth_bypass"
    SSRF_TEST = "ssrf_test"
    SSTI_TEST = "ssti_test"

    # Post-exploitation
    PRIV_ESC = "priv_esc"
    CRED_HARVEST = "cred_harvest"
    PIVOT = "pivot"
    DATA_EXFIL = "data_exfil"

    # Generic
    SPAWN_SUBAGENT = "spawn_subagent"
    BACKTRACK = "backtrack"
    REPORT = "report"


@dataclass
class PentestState:
    """State representation for Q-Learning.

    Captures all relevant information about current pentest progress.
    """
    # Discovery counts
    ports_open: int = 0
    services_found: int = 0
    endpoints_found: int = 0
    parameters_found: int = 0

    # Vulnerability state
    vulns_low: int = 0
    vulns_medium: int = 0
    vulns_high: int = 0
    vulns_critical: int = 0

    # Access state
    shell_obtained: bool = False
    root_obtained: bool = False
    credentials_found: int = 0

    # Progress state
    phase: PentestPhase = PentestPhase.RECONNAISSANCE
    turns_elapsed: int = 0
    turns_since_finding: int = 0
    consecutive_failures: int = 0

    # Tech stack (simplified to flags)
    has_php: bool = False
    has_java: bool = False
    has_python: bool = False
    has_node: bool = False
    has_database: bool = False

    def to_feature_vector(self) -> list[float]:
        """Convert state to normalized feature vector for function approximation.

        Returns:
            18-dimensional feature vector
        """
        features = []

        # Discovery features (4 dims, log-scaled and normalized)
        features.append(min(1.0, math.log1p(self.ports_open) / 4.0))
        features.append(min(1.0, math.log1p(self.services_found) / 3.0))
        features.append(min(1.0, math.log1p(self.endpoints_found) / 5.0))
        features.append(min(1.0, math.log1p(self.parameters_found) / 4.0))

        # Vulnerability features (4 dims, log-scaled)
        features.append(min(1.0, math.log1p(self.vulns_low) / 3.0))
        features.append(min(1.0, math.log1p(self.vulns_medium) / 2.0))
        features.append(min(1.0, math.log1p(self.vulns_high) / 2.0))
        features.append(min(1.0, math.log1p(self.vulns_critical) / 1.5))

        # Access features (3 dims, binary)
        features.append(1.0 if self.shell_obtained else 0.0)
        features.append(1.0 if self.root_obtained else 0.0)
        features.append(min(1.0, self.credentials_found / 5.0))

        # Progress features (3 dims)
        phase_progress = {
            PentestPhase.RECONNAISSANCE: 0.0,
            PentestPhase.SCANNING: 0.25,
            PentestPhase.EXPLOITATION: 0.5,
            PentestPhase.POST_EXPLOITATION: 0.75,
            PentestPhase.REPORTING: 1.0,
        }
        features.append(phase_progress.get(self.phase, 0.0))
        features.append(min(1.0, self.turns_since_finding / 20.0))
        features.append(min(1.0, self.consecutive_failures / 5.0))

        # Tech stack features (5 dims, binary)
        features.append(1.0 if self.has_php else 0.0)
        features.append(1.0 if self.has_java else 0.0)
        features.append(1.0 if self.has_python else 0.0)
        features.append(1.0 if self.has_node else 0.0)
        features.append(1.0 if self.has_database else 0.0)

        return features

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "ports_open": self.ports_open,
            "services_found": self.services_found,
            "endpoints_found": self.endpoints_found,
            "parameters_found": self.parameters_found,
            "vulns_low": self.vulns_low,
            "vulns_medium": self.vulns_medium,
            "vulns_high": self.vulns_high,
            "vulns_critical": self.vulns_critical,
            "shell_obtained": self.shell_obtained,
            "root_obtained": self.root_obtained,
            "credentials_found": self.credentials_found,
            "phase": self.phase.value,
            "turns_elapsed": self.turns_elapsed,
            "turns_since_finding": self.turns_since_finding,
            "consecutive_failures": self.consecutive_failures,
            "has_php": self.has_php,
            "has_java": self.has_java,
            "has_python": self.has_python,
            "has_node": self.has_node,
            "has_database": self.has_database,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PentestState:
        """Create from dictionary."""
        phase = data.get("phase", "reconnaissance")
        if isinstance(phase, str):
            phase = PentestPhase(phase)

        return cls(
            ports_open=data.get("ports_open", 0),
            services_found=data.get("services_found", 0),
            endpoints_found=data.get("endpoints_found", 0),
            parameters_found=data.get("parameters_found", 0),
            vulns_low=data.get("vulns_low", 0),
            vulns_medium=data.get("vulns_medium", 0),
            vulns_high=data.get("vulns_high", 0),
            vulns_critical=data.get("vulns_critical", 0),
            shell_obtained=data.get("shell_obtained", False),
            root_obtained=data.get("root_obtained", False),
            credentials_found=data.get("credentials_found", 0),
            phase=phase,
            turns_elapsed=data.get("turns_elapsed", 0),
            turns_since_finding=data.get("turns_since_finding", 0),
            consecutive_failures=data.get("consecutive_failures", 0),
            has_php=data.get("has_php", False),
            has_java=data.get("has_java", False),
            has_python=data.get("has_python", False),
            has_node=data.get("has_node", False),
            has_database=data.get("has_database", False),
        )


@dataclass
class PentestAction:
    """Action in the pentest environment."""

    action_type: ActionType
    target: str = ""  # Endpoint or IP
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_key(self) -> str:
        """Convert to hashable key for Q-table."""
        return self.action_type.value


@dataclass
class Experience:
    """Single experience for replay buffer."""

    state: PentestState
    action: PentestAction
    reward: float
    next_state: PentestState
    done: bool


class RewardFunction:
    """Reward function for penetration testing.

    Implements potential-based reward shaping to reduce sparse reward problem:

        R'(s, a, s') = R(s, a, s') + γ * Φ(s') - Φ(s)

    where Φ(s) is a potential function based on pentest progress.
    """

    def __init__(
        self,
        mode: str = "ctf",  # "ctf" or "bug_bounty"
        gamma: float = 0.99,
    ):
        """Initialize reward function.

        Args:
            mode: Reward mode - "ctf" (binary objectives) or "bug_bounty" (finding-based)
            gamma: Discount factor for potential-based shaping
        """
        self.mode = mode
        self.gamma = gamma

        # Severity rewards
        self.severity_rewards = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5,
            "info": 0.1,
        }

        # Access progression rewards
        self.access_rewards = {
            "credentials": 5.0,
            "shell": 50.0,
            "root": 100.0,
        }

        # CTF-specific rewards
        self.ctf_rewards = {
            "user_flag": 75.0,
            "root_flag": 150.0,
        }

    def potential(self, state: PentestState) -> float:
        """Calculate potential function Φ(s) for reward shaping.

        Higher potential = more progress toward objective.
        """
        phi = 0.0

        # Discovery potential
        phi += math.log1p(state.ports_open) * 0.5
        phi += math.log1p(state.services_found) * 1.0
        phi += math.log1p(state.endpoints_found) * 1.5
        phi += math.log1p(state.parameters_found) * 0.5

        # Vulnerability potential
        phi += state.vulns_low * 1.0
        phi += state.vulns_medium * 3.0
        phi += state.vulns_high * 8.0
        phi += state.vulns_critical * 15.0

        # Access potential
        phi += state.credentials_found * 5.0
        if state.shell_obtained:
            phi += 50.0
        if state.root_obtained:
            phi += 100.0

        return phi

    def compute(
        self,
        state: PentestState,
        action: PentestAction,
        next_state: PentestState,
        outcome: OutcomeType,
        severity: str | None = None,
        gained_access: str | None = None,  # "credentials", "shell", "root"
        flag_captured: str | None = None,  # "user", "root"
    ) -> float:
        """Compute reward for transition.

        Args:
            state: State before action
            action: Action taken
            next_state: State after action
            outcome: Action outcome
            severity: Severity of finding (if any)
            gained_access: Access level gained (if any)
            flag_captured: Flag captured (if any, CTF mode)

        Returns:
            Shaped reward value
        """
        reward = 0.0

        # Base outcome rewards/penalties
        if outcome == OutcomeType.SUCCESS:
            reward += 0.5
        elif outcome == OutcomeType.PARTIAL:
            reward += 0.2
        elif outcome == OutcomeType.FAILURE:
            reward -= 0.1
        elif outcome == OutcomeType.BLOCKED:
            reward -= 0.2
        elif outcome == OutcomeType.ERROR:
            reward -= 0.3
        elif outcome == OutcomeType.TIMEOUT:
            reward -= 0.5

        # Severity-based rewards
        if severity:
            reward += self.severity_rewards.get(severity.lower(), 0.0)

        # Access progression
        if gained_access:
            reward += self.access_rewards.get(gained_access.lower(), 0.0)

        # CTF mode: flag capture
        if self.mode == "ctf" and flag_captured:
            reward += self.ctf_rewards.get(f"{flag_captured.lower()}_flag", 0.0)

        # Step penalty to encourage efficiency
        reward -= 0.05

        # Potential-based reward shaping
        shaping = self.gamma * self.potential(next_state) - self.potential(state)
        reward += shaping

        return reward


class QLearningAgent(ReinforcementLearner):
    """Q-Learning agent for action sequencing.

    Uses linear function approximation over state features
    to generalize across similar states.

    Q(s, a) = θ_a · φ(s)

    where θ_a are weights for action a and φ(s) is state feature vector.
    """

    def __init__(
        self,
        learning_rate: float = 0.1,
        discount_factor: float = 0.99,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.1,
        replay_buffer_size: int = 10000,
        batch_size: int = 32,
        reward_mode: str = "ctf",
    ):
        """Initialize Q-Learning agent.

        Args:
            learning_rate: Learning rate (alpha)
            discount_factor: Discount factor (gamma)
            epsilon: Initial exploration rate
            epsilon_decay: Epsilon decay per episode
            epsilon_min: Minimum epsilon value
            replay_buffer_size: Size of experience replay buffer
            batch_size: Batch size for replay learning
            reward_mode: "ctf" or "bug_bounty"
        """
        self.alpha = learning_rate
        self.gamma = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.batch_size = batch_size

        # Feature dimension (from PentestState.to_feature_vector)
        self.feature_dim = 18

        # Action set
        self.actions = list(ActionType)

        # Weights for each action (linear function approximation)
        # θ_a is a weight vector of size feature_dim for each action
        self._weights: dict[str, list[float]] = {
            action.value: [0.0] * self.feature_dim
            for action in self.actions
        }

        # Experience replay buffer
        self._replay_buffer: deque[Experience] = deque(maxlen=replay_buffer_size)

        # Reward function
        self._reward_fn = RewardFunction(mode=reward_mode, gamma=discount_factor)

        # Training statistics
        self._episodes = 0
        self._total_updates = 0

    def get_q_value(self, state: PentestState, action: ActionType) -> float:
        """Compute Q-value for state-action pair.

        Q(s, a) = θ_a · φ(s)
        """
        features = state.to_feature_vector()
        weights = self._weights[action.value]
        return sum(w * f for w, f in zip(weights, features))

    def get_all_q_values(self, state: PentestState) -> dict[ActionType, float]:
        """Get Q-values for all actions in state."""
        return {action: self.get_q_value(state, action) for action in self.actions}

    def get_action(
        self,
        state: PentestState,
        available_actions: list[ActionType] | None = None
    ) -> ActionType:
        """Select action using epsilon-greedy policy.

        Args:
            state: Current state
            available_actions: Restrict to these actions (optional)

        Returns:
            Selected action
        """
        if available_actions is None:
            available_actions = self.actions

        # Epsilon-greedy exploration
        if random.random() < self.epsilon:
            action = random.choice(available_actions)
            action_str = action.value if hasattr(action, 'value') else str(action)
            logger.debug("qlearning_explore", action=action_str, epsilon=self.epsilon)
            return action

        # Greedy action selection
        q_values = {
            action: self.get_q_value(state, action)
            for action in available_actions
        }
        best_action = max(q_values, key=q_values.get)

        action_str = best_action.value if hasattr(best_action, 'value') else str(best_action)
        logger.debug(
            "qlearning_exploit",
            action=action_str,
            q_value=q_values[best_action],
        )
        return best_action

    def get_best_action(
        self,
        state: PentestState,
        available_actions: list[ActionType] | None = None
    ) -> ActionType:
        """Get best action without exploration."""
        if available_actions is None:
            available_actions = self.actions

        q_values = {
            action: self.get_q_value(state, action)
            for action in available_actions
        }
        return max(q_values, key=q_values.get)

    def update(
        self,
        state: PentestState,
        action: PentestAction,
        reward: float,
        next_state: PentestState,
        done: bool = False
    ) -> None:
        """Update Q-values with observed transition.

        Q(s, a) ← Q(s, a) + α [r + γ max_a' Q(s', a') - Q(s, a)]
        """
        # Store experience
        self._replay_buffer.append(Experience(
            state=state,
            action=action,
            reward=reward,
            next_state=next_state,
            done=done,
        ))

        # Online update
        self._update_weights(state, action.action_type, reward, next_state, done)

        # Experience replay
        if len(self._replay_buffer) >= self.batch_size:
            self._replay_batch()

        self._total_updates += 1

        # Decay epsilon
        if done:
            self._episodes += 1
            self.epsilon = max(
                self.epsilon_min,
                self.epsilon * self.epsilon_decay
            )
            logger.debug(
                "qlearning_episode_end",
                episodes=self._episodes,
                epsilon=self.epsilon,
            )

    def _update_weights(
        self,
        state: PentestState,
        action: ActionType,
        reward: float,
        next_state: PentestState,
        done: bool
    ) -> None:
        """Update weights for a single transition."""
        features = state.to_feature_vector()
        current_q = self.get_q_value(state, action)

        # Target Q-value
        if done:
            target = reward
        else:
            next_q_values = self.get_all_q_values(next_state)
            max_next_q = max(next_q_values.values())
            target = reward + self.gamma * max_next_q

        # TD error
        td_error = target - current_q

        # Gradient descent update
        # ∂Q/∂θ = φ(s), so θ ← θ + α * δ * φ(s)
        weights = self._weights[action.value]
        for i in range(self.feature_dim):
            weights[i] += self.alpha * td_error * features[i]

    def _replay_batch(self) -> None:
        """Learn from a batch of experiences."""
        batch = random.sample(list(self._replay_buffer), self.batch_size)

        for exp in batch:
            self._update_weights(
                exp.state,
                exp.action.action_type,
                exp.reward,
                exp.next_state,
                exp.done,
            )

    def compute_reward(
        self,
        state: PentestState,
        action: PentestAction,
        next_state: PentestState,
        outcome: OutcomeType,
        **kwargs
    ) -> float:
        """Compute reward using the reward function."""
        return self._reward_fn.compute(state, action, next_state, outcome, **kwargs)

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        return AlgorithmState(
            algorithm_name="QLearning",
            parameters={
                "alpha": self.alpha,
                "gamma": self.gamma,
                "epsilon": self.epsilon,
                "epsilon_decay": self.epsilon_decay,
                "epsilon_min": self.epsilon_min,
                "episodes": self._episodes,
                "total_updates": self._total_updates,
            },
            history=[
                {"action": k, "weights": v}
                for k, v in self._weights.items()
            ],
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        self.alpha = state.parameters.get("alpha", 0.1)
        self.gamma = state.parameters.get("gamma", 0.99)
        self.epsilon = state.parameters.get("epsilon", 0.1)
        self.epsilon_decay = state.parameters.get("epsilon_decay", 0.995)
        self.epsilon_min = state.parameters.get("epsilon_min", 0.1)
        self._episodes = state.parameters.get("episodes", 0)
        self._total_updates = state.parameters.get("total_updates", 0)

        for item in state.history:
            action = item.get("action")
            weights = item.get("weights", [])
            if action and len(weights) == self.feature_dim:
                self._weights[action] = weights

    def get_action_recommendations(
        self,
        state: PentestState,
        top_k: int = 5
    ) -> list[tuple[ActionType, float]]:
        """Get top-k action recommendations with Q-values.

        Args:
            state: Current state
            top_k: Number of recommendations

        Returns:
            List of (action, q_value) tuples sorted by Q-value
        """
        q_values = self.get_all_q_values(state)
        sorted_actions = sorted(q_values.items(), key=lambda x: x[1], reverse=True)
        return sorted_actions[:top_k]


def create_state_from_metrics(
    metrics: dict[str, Any],
    tech_stack: list[str] | None = None
) -> PentestState:
    """Create PentestState from agent loop metrics.

    Args:
        metrics: Metrics dictionary from AgentLoop
        tech_stack: Detected technologies

    Returns:
        PentestState instance
    """
    tech_stack = tech_stack or []
    tech_lower = [t.lower() for t in tech_stack]

    return PentestState(
        ports_open=metrics.get("ports_open", 0),
        services_found=metrics.get("services_found", 0),
        endpoints_found=metrics.get("endpoints_found", 0),
        parameters_found=metrics.get("parameters_found", 0),
        vulns_low=metrics.get("vulns_low", 0),
        vulns_medium=metrics.get("vulns_medium", 0),
        vulns_high=metrics.get("vulns_high", 0),
        vulns_critical=metrics.get("vulns_critical", 0),
        shell_obtained=metrics.get("shell_obtained", False),
        root_obtained=metrics.get("root_obtained", False),
        credentials_found=metrics.get("credentials_found", 0),
        turns_elapsed=metrics.get("turns", 0),
        turns_since_finding=metrics.get("turns_since_finding", 0),
        consecutive_failures=metrics.get("consecutive_errors", 0),
        has_php=any("php" in t for t in tech_lower),
        has_java=any("java" in t for t in tech_lower),
        has_python=any("python" in t for t in tech_lower),
        has_node=any("node" in t or "express" in t for t in tech_lower),
        has_database=any(db in " ".join(tech_lower) for db in ["mysql", "postgres", "mongo", "sql"]),
    )
