"""
Metrics Collection System for Inferno Algorithms.

Collects and persists metrics about agent performance, enabling
learning algorithms to improve over time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from inferno.algorithms.base import OutcomeType

logger = structlog.get_logger(__name__)


@dataclass
class SubagentOutcome:
    """Tracked outcome of a subagent execution."""

    agent_type: str
    task_hash: str  # Hash of task description
    target_type: str  # web, api, cms, etc.
    tech_stack: list[str]
    context_features: dict[str, Any]

    # Execution metrics
    turns_used: int
    tokens_used: int
    findings_count: int
    outcome: OutcomeType

    # Timing
    started_at: datetime
    duration_seconds: float

    # Learning signals
    reward: float

    # Finding details
    severity_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_type": self.agent_type,
            "task_hash": self.task_hash,
            "target_type": self.target_type,
            "tech_stack": self.tech_stack,
            "context_features": self.context_features,
            "turns_used": self.turns_used,
            "tokens_used": self.tokens_used,
            "findings_count": self.findings_count,
            "outcome": self.outcome.value,
            "started_at": self.started_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "reward": self.reward,
            "severity_counts": self.severity_counts,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubagentOutcome:
        """Create from dictionary."""
        return cls(
            agent_type=data["agent_type"],
            task_hash=data.get("task_hash", ""),
            target_type=data.get("target_type", "unknown"),
            tech_stack=data.get("tech_stack", []),
            context_features=data.get("context_features", {}),
            turns_used=data.get("turns_used", 0),
            tokens_used=data.get("tokens_used", 0),
            findings_count=data.get("findings_count", 0),
            outcome=OutcomeType(data.get("outcome", "failure")),
            started_at=datetime.fromisoformat(data["started_at"]) if "started_at" in data else datetime.now(UTC),
            duration_seconds=data.get("duration_seconds", 0.0),
            reward=data.get("reward", 0.0),
            severity_counts=data.get("severity_counts", {}),
        )


@dataclass
class TriggerOutcome:
    """Tracked outcome of a spawn trigger activation."""

    trigger_name: str  # e.g., "finding_triggered", "error_triggered"
    agent_type: str
    context_features: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # What happened
    spawned: bool = True
    outcome: OutcomeType | None = None  # None if not spawned

    # Learning signal
    reward: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trigger_name": self.trigger_name,
            "agent_type": self.agent_type,
            "context_features": self.context_features,
            "timestamp": self.timestamp.isoformat(),
            "spawned": self.spawned,
            "outcome": self.outcome.value if self.outcome else None,
            "reward": self.reward,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TriggerOutcome:
        """Create from dictionary."""
        outcome = None
        if data.get("outcome"):
            outcome = OutcomeType(data["outcome"])

        return cls(
            trigger_name=data["trigger_name"],
            agent_type=data.get("agent_type", ""),
            context_features=data.get("context_features", {}),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(UTC),
            spawned=data.get("spawned", True),
            outcome=outcome,
            reward=data.get("reward", 0.0),
        )


@dataclass
class BranchOutcome:
    """Tracked outcome of a branch exploration."""

    branch_id: str
    option_id: str
    decision_type: str  # attack_vector, endpoint, payload
    target_type: str
    tech_stack: list[str]

    # Context at decision time
    depth: int
    turn_number: int
    budget_remaining_percent: float

    # Result
    outcome: OutcomeType
    findings_count: int

    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Learning signal
    reward: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "branch_id": self.branch_id,
            "option_id": self.option_id,
            "decision_type": self.decision_type,
            "target_type": self.target_type,
            "tech_stack": self.tech_stack,
            "depth": self.depth,
            "turn_number": self.turn_number,
            "budget_remaining_percent": self.budget_remaining_percent,
            "outcome": self.outcome.value,
            "findings_count": self.findings_count,
            "timestamp": self.timestamp.isoformat(),
            "reward": self.reward,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BranchOutcome:
        """Create from dictionary."""
        return cls(
            branch_id=data["branch_id"],
            option_id=data["option_id"],
            decision_type=data.get("decision_type", ""),
            target_type=data.get("target_type", ""),
            tech_stack=data.get("tech_stack", []),
            depth=data.get("depth", 0),
            turn_number=data.get("turn_number", 0),
            budget_remaining_percent=data.get("budget_remaining_percent", 1.0),
            outcome=OutcomeType(data.get("outcome", "failure")),
            findings_count=data.get("findings_count", 0),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(UTC),
            reward=data.get("reward", 0.0),
        )


@dataclass
class AttackOutcome:
    """Tracked outcome of an attack attempt."""

    attack_type: str  # sqli, xss, rce, etc.
    target: str  # endpoint
    parameter: str
    payload_class: str  # union, blind, etc.

    # Context
    target_type: str
    tech_stack: list[str]

    # Result
    outcome: OutcomeType
    severity: str | None = None
    confidence: float = 0.0

    # Timing
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    response_time: float = 0.0

    # Learning signal
    reward: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attack_type": self.attack_type,
            "target": self.target,
            "parameter": self.parameter,
            "payload_class": self.payload_class,
            "target_type": self.target_type,
            "tech_stack": self.tech_stack,
            "outcome": self.outcome.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
            "response_time": self.response_time,
            "reward": self.reward,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackOutcome:
        """Create from dictionary."""
        return cls(
            attack_type=data["attack_type"],
            target=data.get("target", ""),
            parameter=data.get("parameter", ""),
            payload_class=data.get("payload_class", ""),
            target_type=data.get("target_type", ""),
            tech_stack=data.get("tech_stack", []),
            outcome=OutcomeType(data.get("outcome", "failure")),
            severity=data.get("severity"),
            confidence=data.get("confidence", 0.0),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(UTC),
            response_time=data.get("response_time", 0.0),
            reward=data.get("reward", 0.0),
        )


class MetricsCollector:
    """Collects and persists metrics for algorithmic learning.

    Provides statistics APIs for algorithms to query historical performance.
    """

    def __init__(
        self,
        storage_path: Path | None = None,
        max_history: int = 10000,
    ):
        """Initialize metrics collector.

        Args:
            storage_path: Path for persistence
            max_history: Maximum history entries to keep per type
        """
        self._storage_path = storage_path or Path.home() / ".inferno" / "metrics"
        self._storage_path.mkdir(parents=True, exist_ok=True)
        self._max_history = max_history

        self._subagent_outcomes: list[SubagentOutcome] = []
        self._trigger_outcomes: list[TriggerOutcome] = []
        self._branch_outcomes: list[BranchOutcome] = []
        self._attack_outcomes: list[AttackOutcome] = []

        self._load_history()

    def record_subagent_outcome(self, outcome: SubagentOutcome) -> None:
        """Record a subagent execution outcome."""
        self._subagent_outcomes.append(outcome)
        self._trim_history()
        self._save_history()

        logger.info(
            "subagent_outcome_recorded",
            agent_type=outcome.agent_type,
            outcome=outcome.outcome.value,
            reward=outcome.reward,
            findings=outcome.findings_count,
        )

    def record_trigger_outcome(self, outcome: TriggerOutcome) -> None:
        """Record a trigger activation outcome."""
        self._trigger_outcomes.append(outcome)
        self._trim_history()
        self._save_history()

        logger.debug(
            "trigger_outcome_recorded",
            trigger=outcome.trigger_name,
            agent_type=outcome.agent_type,
            reward=outcome.reward,
        )

    def record_branch_outcome(self, outcome: BranchOutcome) -> None:
        """Record a branch exploration outcome."""
        self._branch_outcomes.append(outcome)
        self._trim_history()
        self._save_history()

        logger.debug(
            "branch_outcome_recorded",
            branch_id=outcome.branch_id,
            option_id=outcome.option_id,
            outcome=outcome.outcome.value,
        )

    def record_attack_outcome(self, outcome: AttackOutcome) -> None:
        """Record an attack attempt outcome."""
        self._attack_outcomes.append(outcome)
        self._trim_history()
        self._save_history()

        logger.debug(
            "attack_outcome_recorded",
            attack_type=outcome.attack_type,
            target=outcome.target,
            outcome=outcome.outcome.value,
        )

    def get_subagent_stats(
        self,
        agent_type: str,
        target_type: str | None = None
    ) -> dict[str, float]:
        """Get statistics for an agent type.

        Args:
            agent_type: Type of agent
            target_type: Optional filter by target type

        Returns:
            Dictionary of statistics
        """
        outcomes = [
            o for o in self._subagent_outcomes
            if o.agent_type == agent_type
            and (target_type is None or o.target_type == target_type)
        ]

        if not outcomes:
            return {
                "count": 0,
                "success_rate": 0.5,
                "avg_reward": 0.0,
                "avg_findings": 0.0,
                "avg_turns": 0.0,
            }

        successes = sum(1 for o in outcomes if o.outcome == OutcomeType.SUCCESS)

        return {
            "count": len(outcomes),
            "success_rate": successes / len(outcomes),
            "avg_reward": sum(o.reward for o in outcomes) / len(outcomes),
            "avg_findings": sum(o.findings_count for o in outcomes) / len(outcomes),
            "avg_turns": sum(o.turns_used for o in outcomes) / len(outcomes),
            "avg_tokens": sum(o.tokens_used for o in outcomes) / len(outcomes),
        }

    def get_trigger_stats(self, trigger_name: str) -> dict[str, float]:
        """Get statistics for a trigger type."""
        outcomes = [
            o for o in self._trigger_outcomes
            if o.trigger_name == trigger_name
        ]

        if not outcomes:
            return {
                "count": 0,
                "success_rate": 0.5,
                "avg_reward": 0.0,
            }

        spawned = [o for o in outcomes if o.spawned]
        successful = [o for o in spawned if o.outcome == OutcomeType.SUCCESS]

        return {
            "count": len(outcomes),
            "spawn_rate": len(spawned) / len(outcomes) if outcomes else 0,
            "success_rate": len(successful) / len(spawned) if spawned else 0.5,
            "avg_reward": sum(o.reward for o in spawned) / len(spawned) if spawned else 0,
        }

    def get_attack_stats(
        self,
        attack_type: str,
        target_type: str | None = None,
        tech_stack: list[str] | None = None
    ) -> dict[str, float]:
        """Get statistics for an attack type.

        Args:
            attack_type: Type of attack (sqli, xss, etc.)
            target_type: Optional filter by target type
            tech_stack: Optional filter by tech stack

        Returns:
            Dictionary of statistics
        """
        outcomes = [o for o in self._attack_outcomes if o.attack_type == attack_type]

        if target_type:
            outcomes = [o for o in outcomes if o.target_type == target_type]

        if tech_stack:
            tech_set = set(t.lower() for t in tech_stack)
            outcomes = [
                o for o in outcomes
                if tech_set.intersection(set(t.lower() for t in o.tech_stack))
            ]

        if not outcomes:
            return {
                "count": 0,
                "success_rate": 0.5,
                "avg_reward": 0.0,
                "avg_confidence": 0.5,
            }

        successes = sum(1 for o in outcomes if o.outcome == OutcomeType.SUCCESS)

        return {
            "count": len(outcomes),
            "success_rate": successes / len(outcomes),
            "avg_reward": sum(o.reward for o in outcomes) / len(outcomes),
            "avg_confidence": sum(o.confidence for o in outcomes) / len(outcomes),
            "avg_response_time": sum(o.response_time for o in outcomes) / len(outcomes),
        }

    def get_branch_stats(
        self,
        decision_type: str,
        target_type: str | None = None
    ) -> dict[str, float]:
        """Get statistics for branch decisions."""
        outcomes = [
            o for o in self._branch_outcomes
            if o.decision_type == decision_type
            and (target_type is None or o.target_type == target_type)
        ]

        if not outcomes:
            return {
                "count": 0,
                "success_rate": 0.5,
                "avg_reward": 0.0,
            }

        successes = sum(1 for o in outcomes if o.outcome == OutcomeType.SUCCESS)

        return {
            "count": len(outcomes),
            "success_rate": successes / len(outcomes),
            "avg_reward": sum(o.reward for o in outcomes) / len(outcomes),
            "avg_depth": sum(o.depth for o in outcomes) / len(outcomes),
        }

    def get_summary(self) -> dict[str, Any]:
        """Get overall metrics summary."""
        total_subagent = len(self._subagent_outcomes)
        total_triggers = len(self._trigger_outcomes)
        total_branches = len(self._branch_outcomes)
        total_attacks = len(self._attack_outcomes)

        return {
            "total_records": {
                "subagent_outcomes": total_subagent,
                "trigger_outcomes": total_triggers,
                "branch_outcomes": total_branches,
                "attack_outcomes": total_attacks,
            },
            "overall_success_rates": {
                "subagents": self._calculate_overall_success_rate(self._subagent_outcomes),
                "attacks": self._calculate_overall_success_rate(self._attack_outcomes),
            },
            "top_performing_agents": self._get_top_agents(3),
            "top_performing_attacks": self._get_top_attacks(3),
        }

    def _calculate_overall_success_rate(self, outcomes: list) -> float:
        """Calculate overall success rate from outcomes."""
        if not outcomes:
            return 0.0
        successes = sum(1 for o in outcomes if o.outcome == OutcomeType.SUCCESS)
        return successes / len(outcomes)

    def _get_top_agents(self, n: int) -> list[dict[str, Any]]:
        """Get top performing agent types."""
        agent_stats = {}
        for outcome in self._subagent_outcomes:
            if outcome.agent_type not in agent_stats:
                agent_stats[outcome.agent_type] = {
                    "count": 0,
                    "successes": 0,
                    "total_reward": 0.0,
                }
            stats = agent_stats[outcome.agent_type]
            stats["count"] += 1
            stats["total_reward"] += outcome.reward
            if outcome.outcome == OutcomeType.SUCCESS:
                stats["successes"] += 1

        # Calculate success rates and sort
        results = []
        for agent_type, stats in agent_stats.items():
            if stats["count"] >= 3:  # Minimum samples
                results.append({
                    "agent_type": agent_type,
                    "success_rate": stats["successes"] / stats["count"],
                    "avg_reward": stats["total_reward"] / stats["count"],
                    "count": stats["count"],
                })

        return sorted(results, key=lambda x: x["avg_reward"], reverse=True)[:n]

    def _get_top_attacks(self, n: int) -> list[dict[str, Any]]:
        """Get top performing attack types."""
        attack_stats = {}
        for outcome in self._attack_outcomes:
            if outcome.attack_type not in attack_stats:
                attack_stats[outcome.attack_type] = {
                    "count": 0,
                    "successes": 0,
                    "total_reward": 0.0,
                }
            stats = attack_stats[outcome.attack_type]
            stats["count"] += 1
            stats["total_reward"] += outcome.reward
            if outcome.outcome == OutcomeType.SUCCESS:
                stats["successes"] += 1

        results = []
        for attack_type, stats in attack_stats.items():
            if stats["count"] >= 3:
                results.append({
                    "attack_type": attack_type,
                    "success_rate": stats["successes"] / stats["count"],
                    "avg_reward": stats["total_reward"] / stats["count"],
                    "count": stats["count"],
                })

        return sorted(results, key=lambda x: x["avg_reward"], reverse=True)[:n]

    def _trim_history(self) -> None:
        """Trim history to max size."""
        if len(self._subagent_outcomes) > self._max_history:
            self._subagent_outcomes = self._subagent_outcomes[-self._max_history:]
        if len(self._trigger_outcomes) > self._max_history:
            self._trigger_outcomes = self._trigger_outcomes[-self._max_history:]
        if len(self._branch_outcomes) > self._max_history:
            self._branch_outcomes = self._branch_outcomes[-self._max_history:]
        if len(self._attack_outcomes) > self._max_history:
            self._attack_outcomes = self._attack_outcomes[-self._max_history:]

    def _load_history(self) -> None:
        """Load metrics history from disk."""
        history_file = self._storage_path / "metrics_history.json"

        if not history_file.exists():
            return

        try:
            data = json.loads(history_file.read_text())

            self._subagent_outcomes = [
                SubagentOutcome.from_dict(d)
                for d in data.get("subagent_outcomes", [])
            ]
            self._trigger_outcomes = [
                TriggerOutcome.from_dict(d)
                for d in data.get("trigger_outcomes", [])
            ]
            self._branch_outcomes = [
                BranchOutcome.from_dict(d)
                for d in data.get("branch_outcomes", [])
            ]
            self._attack_outcomes = [
                AttackOutcome.from_dict(d)
                for d in data.get("attack_outcomes", [])
            ]

            logger.info(
                "metrics_loaded",
                subagent_outcomes=len(self._subagent_outcomes),
                trigger_outcomes=len(self._trigger_outcomes),
                branch_outcomes=len(self._branch_outcomes),
                attack_outcomes=len(self._attack_outcomes),
            )
        except Exception as e:
            logger.warning("metrics_load_failed", error=str(e))

    def _save_history(self) -> None:
        """Save metrics history to disk."""
        history_file = self._storage_path / "metrics_history.json"

        try:
            data = {
                "subagent_outcomes": [o.to_dict() for o in self._subagent_outcomes],
                "trigger_outcomes": [o.to_dict() for o in self._trigger_outcomes],
                "branch_outcomes": [o.to_dict() for o in self._branch_outcomes],
                "attack_outcomes": [o.to_dict() for o in self._attack_outcomes],
                "saved_at": datetime.now(UTC).isoformat(),
            }
            history_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning("metrics_save_failed", error=str(e))

    def clear(self) -> None:
        """Clear all metrics (use with caution)."""
        self._subagent_outcomes = []
        self._trigger_outcomes = []
        self._branch_outcomes = []
        self._attack_outcomes = []
        self._save_history()
        logger.warning("metrics_cleared")
