"""
Dynamic Budget Allocation for Inferno.

Implements intelligent budget allocation for subagents based on
expected value calculations and ROI tracking. Uses Kelly criterion
for risk-optimal allocation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from inferno.algorithms.base import AlgorithmState

logger = structlog.get_logger(__name__)


@dataclass
class SubagentROI:
    """ROI tracking for a subagent type."""

    agent_type: str

    # Resource usage
    total_tokens: int = 0
    total_turns: int = 0
    total_runs: int = 0

    # Outcomes
    successful_runs: int = 0
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0

    # Value metrics
    total_value: float = 0.0  # Sum of finding values

    @property
    def success_rate(self) -> float:
        """Probability of success."""
        return self.successful_runs / self.total_runs if self.total_runs > 0 else 0.5

    @property
    def avg_findings_per_run(self) -> float:
        """Average findings per run."""
        return self.findings_count / self.total_runs if self.total_runs > 0 else 0.0

    @property
    def avg_tokens_per_run(self) -> float:
        """Average tokens consumed per run."""
        return self.total_tokens / self.total_runs if self.total_runs > 0 else 1000

    @property
    def avg_value_per_token(self) -> float:
        """Value generated per token (efficiency metric)."""
        return self.total_value / self.total_tokens if self.total_tokens > 0 else 0.0

    @property
    def roi(self) -> float:
        """Return on investment (value / cost)."""
        cost = self.total_tokens * 0.00001  # Simplified cost model
        return self.total_value / cost if cost > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_type": self.agent_type,
            "total_tokens": self.total_tokens,
            "total_turns": self.total_turns,
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "findings_count": self.findings_count,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "total_value": self.total_value,
            "success_rate": self.success_rate,
            "roi": self.roi,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubagentROI:
        """Create from dictionary."""
        return cls(
            agent_type=data["agent_type"],
            total_tokens=data.get("total_tokens", 0),
            total_turns=data.get("total_turns", 0),
            total_runs=data.get("total_runs", 0),
            successful_runs=data.get("successful_runs", 0),
            findings_count=data.get("findings_count", 0),
            critical_findings=data.get("critical_findings", 0),
            high_findings=data.get("high_findings", 0),
            total_value=data.get("total_value", 0.0),
        )


@dataclass
class BudgetDecision:
    """A budget allocation decision."""

    agent_type: str
    allocated_turns: int
    allocated_tokens: int
    expected_value: float
    confidence: float
    rationale: str


class DynamicBudgetAllocator:
    """Dynamic budget allocation using expected value and Kelly criterion.

    Allocates budget to subagents based on:
    1. Historical ROI
    2. Current phase priorities
    3. Expected value calculations
    4. Kelly criterion for optimal sizing
    """

    def __init__(
        self,
        total_turns: int = 100,
        total_tokens: int = 100000,
        min_allocation_percent: float = 0.02,
        max_allocation_percent: float = 0.40,
    ):
        """Initialize budget allocator.

        Args:
            total_turns: Total turns available
            total_tokens: Total tokens available
            min_allocation_percent: Minimum allocation per agent (2%)
            max_allocation_percent: Maximum allocation per agent (40%)
        """
        self.total_turns = total_turns
        self.total_tokens = total_tokens
        self.min_allocation_percent = min_allocation_percent
        self.max_allocation_percent = max_allocation_percent

        # ROI tracking per agent type
        self._roi_data: dict[str, SubagentROI] = {}

        # Usage tracking
        self._turns_used = 0
        self._tokens_used = 0
        self._allocations_made: list[BudgetDecision] = []

        # Phase priorities (multipliers)
        self._phase_priorities = {
            "reconnaissance": {
                "reconnaissance": 3.0,
                "scanner": 1.5,
                "exploiter": 0.5,
                "post_exploitation": 0.2,
            },
            "scanning": {
                "reconnaissance": 1.0,
                "scanner": 3.0,
                "exploiter": 1.5,
                "post_exploitation": 0.3,
            },
            "exploitation": {
                "reconnaissance": 0.5,
                "scanner": 1.0,
                "exploiter": 3.0,
                "post_exploitation": 1.5,
            },
            "post_exploitation": {
                "reconnaissance": 0.3,
                "scanner": 0.5,
                "exploiter": 1.5,
                "post_exploitation": 3.0,
            },
        }

        # Base expected values per agent type
        self._base_expected_values = {
            "reconnaissance": 2.0,
            "scanner": 3.0,
            "exploiter": 8.0,
            "validator": 1.5,
            "post_exploitation": 10.0,
            "reporter": 0.5,
        }

    @property
    def remaining_turns(self) -> int:
        """Remaining turns available."""
        return max(0, self.total_turns - self._turns_used)

    @property
    def remaining_tokens(self) -> int:
        """Remaining tokens available."""
        return max(0, self.total_tokens - self._tokens_used)

    @property
    def budget_utilization(self) -> float:
        """Budget utilization percentage."""
        turn_util = self._turns_used / self.total_turns if self.total_turns > 0 else 0
        token_util = self._tokens_used / self.total_tokens if self.total_tokens > 0 else 0
        return (turn_util + token_util) / 2

    def record_usage(
        self,
        agent_type: str,
        turns_used: int,
        tokens_used: int,
        success: bool,
        findings_count: int = 0,
        finding_value: float = 0.0,
        critical_count: int = 0,
        high_count: int = 0,
    ) -> None:
        """Record resource usage and outcome.

        Args:
            agent_type: Type of subagent
            turns_used: Turns consumed
            tokens_used: Tokens consumed
            success: Whether run was successful
            findings_count: Number of findings
            finding_value: Total value of findings
            critical_count: Number of critical findings
            high_count: Number of high findings
        """
        if agent_type not in self._roi_data:
            self._roi_data[agent_type] = SubagentROI(agent_type=agent_type)

        roi = self._roi_data[agent_type]
        roi.total_runs += 1
        roi.total_turns += turns_used
        roi.total_tokens += tokens_used
        roi.findings_count += findings_count
        roi.total_value += finding_value
        roi.critical_findings += critical_count
        roi.high_findings += high_count

        if success:
            roi.successful_runs += 1

        self._turns_used += turns_used
        self._tokens_used += tokens_used

        logger.debug(
            "budget_usage_recorded",
            agent_type=agent_type,
            turns_used=turns_used,
            tokens_used=tokens_used,
            success=success,
            roi=roi.roi,
        )

    def calculate_expected_value(
        self,
        agent_type: str,
        phase: str,
        discovered_vulns: list[str] | None = None,
    ) -> float:
        """Calculate expected value for allocating to an agent type.

        EV = P(success) × E[Value | success] - E[Cost]

        Args:
            agent_type: Type of subagent
            phase: Current phase
            discovered_vulns: List of discovered vulnerabilities

        Returns:
            Expected value
        """
        # Get base expected value
        base_ev = self._base_expected_values.get(agent_type, 1.0)

        # Apply phase priority
        phase_priorities = self._phase_priorities.get(phase, {})
        phase_multiplier = phase_priorities.get(agent_type, 1.0)

        # Get historical success rate
        if agent_type in self._roi_data:
            roi = self._roi_data[agent_type]
            success_rate = roi.success_rate
            avg_value = roi.total_value / roi.successful_runs if roi.successful_runs > 0 else base_ev
        else:
            success_rate = 0.5  # Optimistic prior
            avg_value = base_ev

        # Context bonus: if we have discovered vulns, exploiter is more valuable
        context_bonus = 1.0
        if discovered_vulns and agent_type == "exploiter":
            context_bonus = 1.0 + min(2.0, len(discovered_vulns) * 0.2)

        # Calculate expected value
        expected_value = success_rate * avg_value * phase_multiplier * context_bonus

        return expected_value

    def kelly_fraction(
        self,
        agent_type: str,
        phase: str,
    ) -> float:
        """Calculate Kelly criterion optimal fraction.

        f* = (p × b - q) / b

        where:
            p = probability of success
            q = 1 - p
            b = payout ratio (value gained / cost)

        Args:
            agent_type: Type of subagent
            phase: Current phase

        Returns:
            Optimal allocation fraction (0 to 1)
        """
        # Get success probability
        if agent_type in self._roi_data:
            roi = self._roi_data[agent_type]
            p = roi.success_rate
            if p == 0:
                p = 0.1  # Small positive for unexplored
        else:
            p = 0.5  # Prior

        q = 1 - p

        # Calculate payout ratio
        ev = self.calculate_expected_value(agent_type, phase)
        avg_cost = 0.01  # Simplified cost per allocation
        b = ev / avg_cost if avg_cost > 0 else 1.0

        # Kelly fraction
        if b <= 0:
            return 0.0

        kelly = (p * b - q) / b

        # Clamp to reasonable bounds
        kelly = max(0, min(1, kelly))

        # Half-Kelly for more conservative sizing
        return kelly / 2

    def allocate(
        self,
        agent_type: str,
        phase: str,
        discovered_vulns: list[str] | None = None,
        force_minimum: bool = False,
    ) -> BudgetDecision:
        """Allocate budget for a subagent.

        Args:
            agent_type: Type of subagent
            phase: Current phase
            discovered_vulns: Discovered vulnerabilities
            force_minimum: Force minimum allocation even if EV is low

        Returns:
            Budget allocation decision
        """
        # Calculate expected value
        ev = self.calculate_expected_value(agent_type, phase, discovered_vulns)

        # Calculate Kelly fraction
        kelly = self.kelly_fraction(agent_type, phase)

        # Base allocation from Kelly
        base_turn_fraction = kelly
        base_token_fraction = kelly

        # Apply min/max bounds
        turn_fraction = max(
            self.min_allocation_percent,
            min(self.max_allocation_percent, base_turn_fraction)
        )
        token_fraction = max(
            self.min_allocation_percent,
            min(self.max_allocation_percent, base_token_fraction)
        )

        # Handle low EV case
        if ev < 0.5 and not force_minimum:
            turn_fraction = self.min_allocation_percent
            token_fraction = self.min_allocation_percent

        # Calculate actual allocation
        allocated_turns = int(self.remaining_turns * turn_fraction)
        allocated_tokens = int(self.remaining_tokens * token_fraction)

        # Minimum bounds
        allocated_turns = max(5, allocated_turns)  # At least 5 turns
        allocated_tokens = max(5000, allocated_tokens)  # At least 5k tokens

        # Cap at remaining budget
        allocated_turns = min(allocated_turns, self.remaining_turns)
        allocated_tokens = min(allocated_tokens, self.remaining_tokens)

        # Calculate confidence
        if agent_type in self._roi_data:
            samples = self._roi_data[agent_type].total_runs
            confidence = min(0.95, 0.5 + samples * 0.05)  # Confidence grows with samples
        else:
            confidence = 0.5  # Uncertain

        decision = BudgetDecision(
            agent_type=agent_type,
            allocated_turns=allocated_turns,
            allocated_tokens=allocated_tokens,
            expected_value=ev,
            confidence=confidence,
            rationale=self._generate_rationale(agent_type, phase, ev, kelly),
        )

        self._allocations_made.append(decision)

        logger.info(
            "budget_allocated",
            agent_type=agent_type,
            turns=allocated_turns,
            tokens=allocated_tokens,
            expected_value=ev,
            kelly_fraction=kelly,
        )

        return decision

    def _generate_rationale(
        self,
        agent_type: str,
        phase: str,
        ev: float,
        kelly: float,
    ) -> str:
        """Generate human-readable rationale for allocation."""
        parts = []

        # ROI info
        if agent_type in self._roi_data:
            roi = self._roi_data[agent_type]
            parts.append(
                f"Historical ROI: {roi.roi:.2f} from {roi.total_runs} runs "
                f"({roi.success_rate:.0%} success rate)"
            )
        else:
            parts.append("No historical data - using optimistic prior")

        # Phase relevance
        phase_priorities = self._phase_priorities.get(phase, {})
        priority = phase_priorities.get(agent_type, 1.0)
        if priority > 2.0:
            parts.append(f"High priority for {phase} phase (×{priority:.1f})")
        elif priority < 0.5:
            parts.append(f"Low priority for {phase} phase (×{priority:.1f})")

        # EV and Kelly
        parts.append(f"Expected value: {ev:.2f}, Kelly fraction: {kelly:.2%}")

        return "; ".join(parts)

    def get_allocation_summary(self) -> dict[str, Any]:
        """Get summary of all allocations and ROI data."""
        return {
            "total_budget": {
                "turns": self.total_turns,
                "tokens": self.total_tokens,
            },
            "used": {
                "turns": self._turns_used,
                "tokens": self._tokens_used,
            },
            "remaining": {
                "turns": self.remaining_turns,
                "tokens": self.remaining_tokens,
            },
            "utilization": self.budget_utilization,
            "roi_by_agent": {
                agent_type: roi.to_dict()
                for agent_type, roi in self._roi_data.items()
            },
            "allocations_count": len(self._allocations_made),
        }

    def should_reallocate(self) -> bool:
        """Check if we should trigger reallocation.

        Reallocation triggers:
        1. Significant ROI changes detected
        2. Budget utilization milestones (25%, 50%, 75%)
        """
        # Check utilization milestones
        utilization = self.budget_utilization
        milestone_triggers = [0.25, 0.50, 0.75]

        for milestone in milestone_triggers:
            # Check if we just crossed this milestone
            previous_util = (self._turns_used - 1) / self.total_turns if self.total_turns > 0 else 0
            if previous_util < milestone <= utilization:
                logger.info("budget_reallocation_trigger", milestone=milestone)
                return True

        return False

    def get_state(self) -> AlgorithmState:
        """Get persistable state."""
        return AlgorithmState(
            algorithm_name="DynamicBudgetAllocator",
            parameters={
                "total_turns": self.total_turns,
                "total_tokens": self.total_tokens,
                "turns_used": self._turns_used,
                "tokens_used": self._tokens_used,
            },
            history=[roi.to_dict() for roi in self._roi_data.values()],
        )

    def load_state(self, state: AlgorithmState) -> None:
        """Load state from persistence."""
        self.total_turns = state.parameters.get("total_turns", 100)
        self.total_tokens = state.parameters.get("total_tokens", 100000)
        self._turns_used = state.parameters.get("turns_used", 0)
        self._tokens_used = state.parameters.get("tokens_used", 0)

        self._roi_data = {}
        for item in state.history:
            agent_type = item.get("agent_type")
            if agent_type:
                self._roi_data[agent_type] = SubagentROI.from_dict(item)
