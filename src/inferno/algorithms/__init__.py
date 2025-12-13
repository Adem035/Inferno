"""
Inferno Algorithms Module - Intelligent Decision Making

This module provides learning algorithms that replace static heuristics
with adaptive, data-driven decision making:

- Multi-Armed Bandits (UCB1, Thompson Sampling) for attack selection
- Monte Carlo Tree Search for attack path discovery
- Bayesian inference for vulnerability confidence
- Q-Learning for action sequencing
- Dynamic budget allocation

All algorithms persist learned parameters across sessions.
"""

from __future__ import annotations

from inferno.algorithms.bandits import (
    ArmStats,
    ContextualBandit,
    ThompsonSampling,
    UCB1Selector,
)
from inferno.algorithms.base import (
    AlgorithmState,
    OutcomeType,
    SelectionAlgorithm,
)
from inferno.algorithms.bayesian import (
    BayesianConfidence,
    ConfidenceLevel,
    EvidenceType,
    VulnerabilityPrior,
)
from inferno.algorithms.budget import (
    BudgetDecision,
    DynamicBudgetAllocator,
    SubagentROI,
)
from inferno.algorithms.manager import (
    AlgorithmManager,
    get_algorithm_manager,
)
from inferno.algorithms.mcts import (
    AttackAction,
    AttackTreeState,
    MCTSConfig,
    MCTSEngine,
    MCTSNode,
)
from inferno.algorithms.metrics import (
    AttackOutcome,
    BranchOutcome,
    MetricsCollector,
    SubagentOutcome,
    TriggerOutcome,
)
from inferno.algorithms.qlearning import (
    PentestAction,
    PentestState,
    QLearningAgent,
    RewardFunction,
)
from inferno.algorithms.state import (
    AlgorithmStateManager,
    GlobalAlgorithmState,
)

__all__ = [
    # Base
    "SelectionAlgorithm",
    "AlgorithmState",
    "OutcomeType",
    # Bandits
    "UCB1Selector",
    "ThompsonSampling",
    "ContextualBandit",
    "ArmStats",
    # Bayesian
    "BayesianConfidence",
    "VulnerabilityPrior",
    "EvidenceType",
    "ConfidenceLevel",
    # Q-Learning
    "QLearningAgent",
    "PentestState",
    "PentestAction",
    "RewardFunction",
    # MCTS
    "MCTSEngine",
    "AttackTreeState",
    "MCTSNode",
    "AttackAction",
    "MCTSConfig",
    # Budget
    "DynamicBudgetAllocator",
    "SubagentROI",
    "BudgetDecision",
    # State
    "AlgorithmStateManager",
    "GlobalAlgorithmState",
    # Metrics
    "MetricsCollector",
    "SubagentOutcome",
    "TriggerOutcome",
    "BranchOutcome",
    "AttackOutcome",
    # Manager
    "AlgorithmManager",
    "get_algorithm_manager",
]
