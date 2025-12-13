"""
Algorithm State Persistence for Inferno.

Manages persistence of all algorithm states across sessions,
enabling continuous learning over time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from inferno.algorithms.base import AlgorithmState

logger = structlog.get_logger(__name__)


@dataclass
class GlobalAlgorithmState:
    """Complete persisted state for all algorithms."""

    # Bandit states
    trigger_selector_state: dict[str, Any] = field(default_factory=dict)
    agent_selector_state: dict[str, Any] = field(default_factory=dict)
    attack_selector_state: dict[str, Any] = field(default_factory=dict)
    branch_selector_state: dict[str, Any] = field(default_factory=dict)

    # Bayesian state
    bayesian_state: dict[str, Any] = field(default_factory=dict)

    # Q-Learning state
    qlearning_state: dict[str, Any] = field(default_factory=dict)

    # MCTS state
    mcts_state: dict[str, Any] = field(default_factory=dict)

    # Budget allocator state
    budget_state: dict[str, Any] = field(default_factory=dict)

    # Metadata
    version: int = 2
    last_updated: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    total_operations: int = 0
    total_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trigger_selector_state": self.trigger_selector_state,
            "agent_selector_state": self.agent_selector_state,
            "attack_selector_state": self.attack_selector_state,
            "branch_selector_state": self.branch_selector_state,
            "bayesian_state": self.bayesian_state,
            "qlearning_state": self.qlearning_state,
            "mcts_state": self.mcts_state,
            "budget_state": self.budget_state,
            "version": self.version,
            "last_updated": self.last_updated,
            "total_operations": self.total_operations,
            "total_findings": self.total_findings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GlobalAlgorithmState:
        """Create from dictionary."""
        return cls(
            trigger_selector_state=data.get("trigger_selector_state", {}),
            agent_selector_state=data.get("agent_selector_state", {}),
            attack_selector_state=data.get("attack_selector_state", {}),
            branch_selector_state=data.get("branch_selector_state", {}),
            bayesian_state=data.get("bayesian_state", {}),
            qlearning_state=data.get("qlearning_state", {}),
            mcts_state=data.get("mcts_state", {}),
            budget_state=data.get("budget_state", {}),
            version=data.get("version", 2),
            last_updated=data.get("last_updated", ""),
            total_operations=data.get("total_operations", 0),
            total_findings=data.get("total_findings", 0),
        )


class AlgorithmStateManager:
    """Manages persistence of algorithm state.

    Singleton that coordinates saving/loading of all algorithm states.
    """

    _instance: AlgorithmStateManager | None = None

    def __new__(cls, storage_path: Path | None = None) -> AlgorithmStateManager:
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, storage_path: Path | None = None):
        """Initialize state manager.

        Args:
            storage_path: Path for state storage
        """
        if getattr(self, '_initialized', False):
            return

        self._storage_path = storage_path or Path.home() / ".inferno"
        self._state_file = self._storage_path / "algorithm_state.json"
        self._backup_file = self._storage_path / "algorithm_state.backup.json"
        self._state: GlobalAlgorithmState | None = None
        self._dirty = False
        self._initialized = True

    def load(self) -> GlobalAlgorithmState:
        """Load state from disk.

        Returns:
            Loaded or new state
        """
        if self._state is not None:
            return self._state

        self._storage_path.mkdir(parents=True, exist_ok=True)

        if self._state_file.exists():
            try:
                data = json.loads(self._state_file.read_text())
                self._state = GlobalAlgorithmState.from_dict(data)

                logger.info(
                    "algorithm_state_loaded",
                    operations=self._state.total_operations,
                    findings=self._state.total_findings,
                    version=self._state.version,
                )
            except Exception as e:
                logger.warning("algorithm_state_load_failed", error=str(e))
                self._try_backup_recovery()
        else:
            self._state = GlobalAlgorithmState()
            logger.info("algorithm_state_initialized_fresh")

        return self._state

    def _try_backup_recovery(self) -> None:
        """Try to recover from backup file."""
        if self._backup_file.exists():
            try:
                data = json.loads(self._backup_file.read_text())
                self._state = GlobalAlgorithmState.from_dict(data)
                logger.info("algorithm_state_recovered_from_backup")
            except Exception as e:
                logger.error("backup_recovery_failed", error=str(e))
                self._state = GlobalAlgorithmState()
        else:
            self._state = GlobalAlgorithmState()

    def save(self) -> None:
        """Save state to disk."""
        if self._state is None:
            return

        self._state.last_updated = datetime.now(UTC).isoformat()
        self._storage_path.mkdir(parents=True, exist_ok=True)

        try:
            # Backup existing file
            if self._state_file.exists():
                self._state_file.rename(self._backup_file)

            # Write new state
            self._state_file.write_text(
                json.dumps(self._state.to_dict(), indent=2)
            )
            self._dirty = False

            logger.debug(
                "algorithm_state_saved",
                operations=self._state.total_operations,
            )
        except Exception as e:
            logger.error("algorithm_state_save_failed", error=str(e))
            # Try to restore backup
            if self._backup_file.exists() and not self._state_file.exists():
                self._backup_file.rename(self._state_file)

    def mark_dirty(self) -> None:
        """Mark state as needing save."""
        self._dirty = True

    def save_if_dirty(self) -> None:
        """Save state if it has been modified."""
        if self._dirty:
            self.save()

    def update_trigger_state(self, state: AlgorithmState) -> None:
        """Update trigger selector state."""
        self.load()
        self._state.trigger_selector_state = state.to_dict()
        self.mark_dirty()

    def update_agent_state(self, state: AlgorithmState) -> None:
        """Update agent selector state."""
        self.load()
        self._state.agent_selector_state = state.to_dict()
        self.mark_dirty()

    def update_attack_state(self, state: AlgorithmState) -> None:
        """Update attack selector state."""
        self.load()
        self._state.attack_selector_state = state.to_dict()
        self.mark_dirty()

    def update_branch_state(self, state: AlgorithmState) -> None:
        """Update branch selector state."""
        self.load()
        self._state.branch_selector_state = state.to_dict()
        self.mark_dirty()

    def update_bayesian_state(self, state: AlgorithmState) -> None:
        """Update Bayesian confidence state."""
        self.load()
        self._state.bayesian_state = state.to_dict()
        self.mark_dirty()

    def update_qlearning_state(self, state: AlgorithmState) -> None:
        """Update Q-Learning state."""
        self.load()
        self._state.qlearning_state = state.to_dict()
        self.mark_dirty()

    def update_mcts_state(self, state: AlgorithmState) -> None:
        """Update MCTS state."""
        self.load()
        self._state.mcts_state = state.to_dict()
        self.mark_dirty()

    def update_budget_state(self, state: AlgorithmState) -> None:
        """Update budget allocator state."""
        self.load()
        self._state.budget_state = state.to_dict()
        self.mark_dirty()

    def increment_operations(self) -> None:
        """Increment operation counter."""
        self.load()
        self._state.total_operations += 1
        self.mark_dirty()

    def increment_findings(self, count: int = 1) -> None:
        """Increment findings counter."""
        self.load()
        self._state.total_findings += count
        self.mark_dirty()

    def get_trigger_state(self) -> AlgorithmState | None:
        """Get trigger selector state."""
        self.load()
        data = self._state.trigger_selector_state
        return AlgorithmState.from_dict(data) if data else None

    def get_agent_state(self) -> AlgorithmState | None:
        """Get agent selector state."""
        self.load()
        data = self._state.agent_selector_state
        return AlgorithmState.from_dict(data) if data else None

    def get_attack_state(self) -> AlgorithmState | None:
        """Get attack selector state."""
        self.load()
        data = self._state.attack_selector_state
        return AlgorithmState.from_dict(data) if data else None

    def get_branch_state(self) -> AlgorithmState | None:
        """Get branch selector state."""
        self.load()
        data = self._state.branch_selector_state
        return AlgorithmState.from_dict(data) if data else None

    def get_bayesian_state(self) -> AlgorithmState | None:
        """Get Bayesian confidence state."""
        self.load()
        data = self._state.bayesian_state
        return AlgorithmState.from_dict(data) if data else None

    def get_qlearning_state(self) -> AlgorithmState | None:
        """Get Q-Learning state."""
        self.load()
        data = self._state.qlearning_state
        return AlgorithmState.from_dict(data) if data else None

    def get_mcts_state(self) -> AlgorithmState | None:
        """Get MCTS state."""
        self.load()
        data = self._state.mcts_state
        return AlgorithmState.from_dict(data) if data else None

    def get_budget_state(self) -> AlgorithmState | None:
        """Get budget allocator state."""
        self.load()
        data = self._state.budget_state
        return AlgorithmState.from_dict(data) if data else None

    def get_summary(self) -> dict[str, Any]:
        """Get state summary."""
        self.load()
        return {
            "total_operations": self._state.total_operations,
            "total_findings": self._state.total_findings,
            "last_updated": self._state.last_updated,
            "version": self._state.version,
            "has_trigger_state": bool(self._state.trigger_selector_state),
            "has_agent_state": bool(self._state.agent_selector_state),
            "has_attack_state": bool(self._state.attack_selector_state),
            "has_branch_state": bool(self._state.branch_selector_state),
            "has_bayesian_state": bool(self._state.bayesian_state),
            "has_qlearning_state": bool(self._state.qlearning_state),
            "has_mcts_state": bool(self._state.mcts_state),
            "has_budget_state": bool(self._state.budget_state),
        }

    def reset(self) -> None:
        """Reset all algorithm state (use with caution)."""
        self._state = GlobalAlgorithmState()
        self.save()
        logger.warning("algorithm_state_reset")


def get_state_manager() -> AlgorithmStateManager:
    """Get the singleton state manager instance."""
    return AlgorithmStateManager()
