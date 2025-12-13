"""
Base classes for Inferno learning algorithms.

Provides abstract interfaces and common utilities for all algorithm implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Generic, TypeVar

import structlog

logger = structlog.get_logger(__name__)

ActionT = TypeVar("ActionT")
ContextT = TypeVar("ContextT")


class OutcomeType(str, Enum):
    """Outcome types for tracking algorithm performance."""

    SUCCESS = "success"      # Found vulnerability, achieved objective
    PARTIAL = "partial"      # Made progress but not complete
    FAILURE = "failure"      # No progress made
    BLOCKED = "blocked"      # WAF, rate limit, access denied
    TIMEOUT = "timeout"      # Ran out of turns/tokens
    ERROR = "error"          # Technical error during execution


@dataclass
class AlgorithmState:
    """Persistable state for any algorithm."""

    algorithm_name: str
    parameters: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)
    version: int = 1
    last_updated: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    total_updates: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "algorithm_name": self.algorithm_name,
            "parameters": self.parameters,
            "history": self.history,
            "version": self.version,
            "last_updated": self.last_updated,
            "total_updates": self.total_updates,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlgorithmState:
        """Create from dictionary."""
        return cls(
            algorithm_name=data.get("algorithm_name", "unknown"),
            parameters=data.get("parameters", {}),
            history=data.get("history", []),
            version=data.get("version", 1),
            last_updated=data.get("last_updated", ""),
            total_updates=data.get("total_updates", 0),
        )


class SelectionAlgorithm(ABC, Generic[ActionT]):
    """Abstract base class for action selection algorithms.

    Implements the exploration-exploitation tradeoff for choosing
    which action to take given available options.
    """

    @abstractmethod
    def select(
        self,
        available_actions: list[ActionT],
        context: dict[str, Any] | None = None
    ) -> ActionT:
        """Select an action from available options.

        Args:
            available_actions: List of actions to choose from
            context: Optional context features for contextual selection

        Returns:
            The selected action
        """
        pass

    @abstractmethod
    def update(
        self,
        action: ActionT,
        reward: float,
        context: dict[str, Any] | None = None
    ) -> None:
        """Update algorithm state based on observed reward.

        Args:
            action: The action that was taken
            reward: The reward received (typically 0-1)
            context: Optional context features
        """
        pass

    @abstractmethod
    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        pass

    @abstractmethod
    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        pass

    def get_action_scores(
        self,
        available_actions: list[ActionT]
    ) -> dict[ActionT, float]:
        """Get scores for all available actions.

        Default implementation returns empty dict.
        Override in subclasses that support scoring.
        """
        return {}


class ThresholdOptimizer(ABC):
    """Abstract base class for threshold optimization algorithms.

    Used to learn optimal values for configuration thresholds
    like cooldown periods, confidence requirements, etc.
    """

    @abstractmethod
    def suggest(self) -> dict[str, float]:
        """Suggest threshold values to try."""
        pass

    @abstractmethod
    def observe(self, thresholds: dict[str, float], reward: float) -> None:
        """Record observation of threshold performance."""
        pass

    @abstractmethod
    def get_best(self) -> dict[str, float]:
        """Get best known threshold values."""
        pass


class ReinforcementLearner(ABC):
    """Abstract base class for reinforcement learning algorithms.

    Learns optimal action sequences through trial and error.
    """

    @abstractmethod
    def get_action(self, state: Any) -> Any:
        """Select action for current state."""
        pass

    @abstractmethod
    def update(
        self,
        state: Any,
        action: Any,
        reward: float,
        next_state: Any,
        done: bool = False
    ) -> None:
        """Update Q-values or policy based on transition."""
        pass

    @abstractmethod
    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        pass

    @abstractmethod
    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        pass


def compute_reward(
    outcome: OutcomeType,
    severity: str | None = None,
    findings_count: int = 0,
    gained_access: bool = False,
    gained_root: bool = False,
    turns_used: int = 0,
    tokens_used: int = 0,
) -> float:
    """Compute reward signal for reinforcement learning.

    Reward function designed to encourage:
    - Finding high-severity vulnerabilities
    - Gaining access/escalating privileges
    - Efficiency (fewer turns/tokens)

    Args:
        outcome: The outcome type
        severity: Vulnerability severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        findings_count: Number of findings discovered
        gained_access: Whether shell/access was obtained
        gained_root: Whether root/admin was achieved
        turns_used: Number of turns consumed
        tokens_used: Number of tokens consumed

    Returns:
        Reward value (can be negative for penalties)
    """
    reward = 0.0

    # Outcome-based rewards
    if outcome == OutcomeType.SUCCESS:
        reward += 1.0
    elif outcome == OutcomeType.PARTIAL:
        reward += 0.3
    elif outcome == OutcomeType.FAILURE:
        reward -= 0.1
    elif outcome == OutcomeType.BLOCKED:
        reward -= 0.2
    elif outcome == OutcomeType.ERROR:
        reward -= 0.3

    # Severity-based rewards
    severity_rewards = {
        "CRITICAL": 10.0,
        "HIGH": 5.0,
        "MEDIUM": 2.0,
        "LOW": 0.5,
        "INFO": 0.1,
    }
    if severity:
        reward += severity_rewards.get(severity.upper(), 0.0)

    # Finding count bonus (diminishing returns)
    if findings_count > 0:
        import math
        reward += math.log1p(findings_count) * 2.0

    # Access progression (major rewards)
    if gained_root:
        reward += 100.0
    elif gained_access:
        reward += 50.0

    # Efficiency penalty (small but accumulates)
    reward -= turns_used * 0.05
    reward -= tokens_used * 0.00001  # Very small per-token penalty

    return reward


def normalize_reward(reward: float, min_val: float = -10.0, max_val: float = 100.0) -> float:
    """Normalize reward to [0, 1] range for algorithms that expect it.

    Args:
        reward: Raw reward value
        min_val: Minimum expected reward
        max_val: Maximum expected reward

    Returns:
        Normalized reward in [0, 1]
    """
    clamped = max(min_val, min(max_val, reward))
    return (clamped - min_val) / (max_val - min_val)
