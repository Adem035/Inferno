"""
Branch-Point Tracking System for Inferno.

This module provides explicit decision tracking and systematic backtracking
to explore all possible attack paths, not just the first one tried.

Key features:
- Records every decision point during assessment
- Tracks which branches have been explored
- Enables programmatic backtracking to unexplored paths
- Prevents getting stuck in loops by tracking visited states
- Smart detection of futile exploration paths
- Semantic payload comparison to avoid redundant attempts
- Effectiveness tracking and learning from past successes
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class BranchStatus(str, Enum):
    """Status of a branch/decision point."""
    UNEXPLORED = "unexplored"  # Not yet tried
    EXPLORING = "exploring"  # Currently being explored
    EXHAUSTED = "exhausted"  # Fully explored, no more options
    SUCCESSFUL = "successful"  # Led to a finding
    DEAD_END = "dead_end"  # Explored but no results
    BLOCKED = "blocked"  # Cannot be explored (error, WAF, etc.)


class ExplorationResult(str, Enum):
    """Structured result types for better analysis."""
    WAF_BLOCKED = "waf_blocked"
    TIMEOUT = "timeout"
    AUTH_REQUIRED = "auth_required"
    VULNERABLE = "vulnerable"
    PATCHED = "patched"
    RATE_LIMITED = "rate_limited"
    NOT_APPLICABLE = "not_applicable"
    NETWORK_ERROR = "network_error"
    SUCCESS = "success"
    DEAD_END = "dead_end"


class DecisionType(str, Enum):
    """Types of decisions/branch points."""
    ATTACK_VECTOR = "attack_vector"  # Which vulnerability type to pursue
    ENDPOINT = "endpoint"  # Which endpoint to target
    PAYLOAD = "payload"  # Which payload to use
    PARAMETER = "parameter"  # Which parameter to test
    TECHNIQUE = "technique"  # Which technique to apply
    TOOL = "tool"  # Which tool to use
    CHAIN_STEP = "chain_step"  # Which chain to pursue
    ESCALATION = "escalation"  # Which escalation path to take


@dataclass
class BranchOption:
    """A single option at a branch point."""
    option_id: str
    description: str
    priority: int = 50  # 0-100, higher = try first
    status: BranchStatus = BranchStatus.UNEXPLORED
    result: str | None = None
    explored_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Effectiveness tracking
    success_count: int = 0
    failure_count: int = 0
    waf_blocked_count: int = 0
    timeout_count: int = 0
    result_type: ExplorationResult | None = None

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0

    @property
    def effectiveness_score(self) -> float:
        """Calculate effectiveness considering WAF blocks and timeouts."""
        # Penalize WAF blocks and timeouts
        penalty = (self.waf_blocked_count * 0.2) + (self.timeout_count * 0.1)
        return max(0, self.success_rate - penalty)

    def to_dict(self) -> dict[str, Any]:
        return {
            "option_id": self.option_id,
            "description": self.description,
            "priority": self.priority,
            "status": self.status.value,
            "result": self.result,
            "explored_at": self.explored_at,
            "metadata": self.metadata,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "waf_blocked_count": self.waf_blocked_count,
            "timeout_count": self.timeout_count,
            "result_type": self.result_type.value if self.result_type else None,
        }


@dataclass
class BranchPoint:
    """A decision point in the assessment with multiple options."""
    branch_id: str
    decision_type: DecisionType
    context: str  # What led to this decision point
    options: list[BranchOption] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    parent_branch_id: str | None = None  # For nested decisions
    depth: int = 0  # Depth in decision tree

    def to_dict(self) -> dict[str, Any]:
        return {
            "branch_id": self.branch_id,
            "decision_type": self.decision_type.value,
            "context": self.context,
            "options": [o.to_dict() for o in self.options],
            "created_at": self.created_at,
            "parent_branch_id": self.parent_branch_id,
            "depth": self.depth,
        }

    def get_unexplored_options(self) -> list[BranchOption]:
        """Get options that haven't been tried yet."""
        return [
            o for o in self.options
            if o.status == BranchStatus.UNEXPLORED
        ]

    def get_next_option(self) -> BranchOption | None:
        """Get the next option to try based on priority."""
        unexplored = self.get_unexplored_options()
        if not unexplored:
            return None
        return max(unexplored, key=lambda o: o.priority)

    def is_exhausted(self) -> bool:
        """Check if all options have been explored."""
        return all(
            o.status != BranchStatus.UNEXPLORED
            for o in self.options
        )

    def has_successful_path(self) -> bool:
        """Check if any path was successful."""
        return any(
            o.status == BranchStatus.SUCCESSFUL
            for o in self.options
        )


class ResponsePatternTracker:
    """Tracks response patterns to detect futile exploration paths."""

    def __init__(self, similarity_threshold: float = 0.85):
        self._response_history: dict[str, list[dict]] = defaultdict(list)
        self._payload_history: dict[str, list[str]] = defaultdict(list)
        self._similarity_threshold = similarity_threshold
        self._futile_patterns: dict[str, int] = defaultdict(int)

    def record_response(
        self,
        branch_id: str,
        status_code: int,
        response_length: int,
        payload: str = "",
        waf_detected: bool = False,
    ) -> None:
        """Record a response for pattern analysis."""
        response_data = {
            "status_code": status_code,
            "response_length": response_length,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "waf_detected": waf_detected,
        }
        self._response_history[branch_id].append(response_data)

        if payload:
            self._payload_history[branch_id].append(payload)

            # Check for similar payloads
            if len(self._payload_history[branch_id]) >= 2:
                recent_payload = self._payload_history[branch_id][-1]
                previous_payload = self._payload_history[branch_id][-2]
                similarity = self.compute_payload_similarity(recent_payload, previous_payload)

                if similarity > self._similarity_threshold:
                    self._futile_patterns[branch_id] += 1
                else:
                    # Reset counter if we're trying something different
                    self._futile_patterns[branch_id] = 0

    def is_futile_pattern(self, branch_id: str, threshold: int = 5) -> bool:
        """Check if branch shows futile repetitive pattern."""
        if branch_id not in self._response_history:
            return False

        responses = self._response_history[branch_id]
        if len(responses) < threshold:
            return False

        # Check last N responses
        recent = responses[-threshold:]

        # Pattern 1: All WAF blocks
        if all(r.get("waf_detected", False) for r in recent):
            logger.warning(
                "futile_pattern_detected",
                branch_id=branch_id,
                pattern="consecutive_waf_blocks",
                count=threshold,
            )
            return True

        # Pattern 2: All same status code (especially 403, 401, 404)
        status_codes = [r["status_code"] for r in recent]
        if len(set(status_codes)) == 1 and status_codes[0] in [401, 403, 404]:
            logger.warning(
                "futile_pattern_detected",
                branch_id=branch_id,
                pattern="repeated_blocking_status",
                status_code=status_codes[0],
                count=threshold,
            )
            return True

        # Pattern 3: All identical response lengths (likely same error page)
        lengths = [r["response_length"] for r in recent]
        if len(set(lengths)) == 1 and len(recent) >= threshold:
            # Only if combined with blocking status codes
            if all(sc in [400, 401, 403, 404, 500] for sc in status_codes):
                logger.warning(
                    "futile_pattern_detected",
                    branch_id=branch_id,
                    pattern="identical_error_responses",
                    length=lengths[0],
                    count=threshold,
                )
                return True

        # Pattern 4: High payload similarity
        if self._futile_patterns[branch_id] >= threshold:
            logger.warning(
                "futile_pattern_detected",
                branch_id=branch_id,
                pattern="highly_similar_payloads",
                count=self._futile_patterns[branch_id],
            )
            return True

        return False

    def compute_payload_similarity(self, payload1: str, payload2: str) -> float:
        """Compute Jaccard similarity between payloads."""
        if not payload1 or not payload2:
            return 0.0

        # Use character-level bigrams for similarity
        def get_bigrams(s: str) -> set[str]:
            return set(s[i:i+2] for i in range(len(s) - 1))

        bigrams1 = get_bigrams(payload1)
        bigrams2 = get_bigrams(payload2)

        if not bigrams1 and not bigrams2:
            return 1.0 if payload1 == payload2 else 0.0

        if not bigrams1 or not bigrams2:
            return 0.0

        intersection = len(bigrams1 & bigrams2)
        union = len(bigrams1 | bigrams2)

        return intersection / union if union > 0 else 0.0

    def get_pattern_summary(self, branch_id: str) -> dict:
        """Get summary of response patterns for a branch."""
        if branch_id not in self._response_history:
            return {"total_responses": 0}

        responses = self._response_history[branch_id]
        status_codes = [r["status_code"] for r in responses]
        waf_blocks = sum(1 for r in responses if r.get("waf_detected", False))

        return {
            "total_responses": len(responses),
            "unique_status_codes": len(set(status_codes)),
            "most_common_status": max(set(status_codes), key=status_codes.count) if status_codes else None,
            "waf_blocks": waf_blocks,
            "futile_score": self._futile_patterns[branch_id],
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for persistence."""
        return {
            "response_history": dict(self._response_history),
            "payload_history": dict(self._payload_history),
            "futile_patterns": dict(self._futile_patterns),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], similarity_threshold: float = 0.85) -> ResponsePatternTracker:
        """Deserialize from dict."""
        tracker = cls(similarity_threshold)
        tracker._response_history = defaultdict(list, data.get("response_history", {}))
        tracker._payload_history = defaultdict(list, data.get("payload_history", {}))
        tracker._futile_patterns = defaultdict(int, data.get("futile_patterns", {}))
        return tracker


class BranchTracker:
    """
    Tracks decision points and enables systematic exploration of all paths.

    This ensures the agent doesn't get stuck trying the same approach
    repeatedly, and can backtrack to explore alternative paths.

    Enhanced with:
    - Semantic payload comparison
    - Response pattern detection
    - Effectiveness tracking
    - Attack vector learning
    - Diminishing returns detection
    """

    def __init__(
        self,
        operation_dir: Path | None = None,
        max_depth: int = 10,
        max_branches: int = 100,
    ) -> None:
        self._operation_dir = operation_dir
        self._max_depth = max_depth
        self._max_branches = max_branches

        # Branch storage
        self._branches: dict[str, BranchPoint] = {}
        self._current_branch_id: str | None = None
        self._branch_stack: list[str] = []  # Stack of active branch IDs

        # State tracking to detect loops
        self._visited_states: set[str] = set()

        # Response pattern tracking
        self._pattern_tracker = ResponsePatternTracker()

        # Attack vector effectiveness memory
        self._vector_effectiveness: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"successes": 0, "failures": 0, "contexts": [], "avg_time": 0.0}
        )

        # Load existing branches if available
        if operation_dir:
            self._load_branches()

    def create_branch_point(
        self,
        decision_type: DecisionType,
        context: str,
        options: list[dict[str, Any]],
        parent_branch_id: str | None = None,
    ) -> BranchPoint:
        """
        Create a new branch point with multiple options.

        Args:
            decision_type: Type of decision being made
            context: What led to this decision point
            options: List of options, each with 'id', 'description', and optional 'priority'
            parent_branch_id: ID of parent branch if nested

        Returns:
            The created BranchPoint
        """
        if len(self._branches) >= self._max_branches:
            # Prune exhausted branches
            self._prune_exhausted_branches()

        # Generate branch ID
        branch_id = self._generate_branch_id(decision_type, context)

        # Calculate depth
        depth = 0
        if parent_branch_id and parent_branch_id in self._branches:
            depth = self._branches[parent_branch_id].depth + 1

        if depth > self._max_depth:
            logger.warning(
                "max_branch_depth_reached",
                depth=depth,
                max_depth=self._max_depth,
            )
            depth = self._max_depth

        # Create options
        branch_options = []
        for i, opt in enumerate(options):
            branch_options.append(BranchOption(
                option_id=opt.get("id", f"opt_{i}"),
                description=opt.get("description", f"Option {i}"),
                priority=opt.get("priority", 50),
                metadata=opt.get("metadata", {}),
            ))

        # Sort by priority (highest first)
        branch_options.sort(key=lambda o: o.priority, reverse=True)

        # Create branch point
        branch = BranchPoint(
            branch_id=branch_id,
            decision_type=decision_type,
            context=context,
            options=branch_options,
            parent_branch_id=parent_branch_id,
            depth=depth,
        )

        self._branches[branch_id] = branch
        self._save_branches()

        logger.info(
            "branch_point_created",
            branch_id=branch_id,
            decision_type=decision_type.value,
            options_count=len(branch_options),
            depth=depth,
        )

        return branch

    def start_exploring(self, branch_id: str, option_id: str) -> bool:
        """
        Mark an option as being explored.

        Args:
            branch_id: The branch point ID
            option_id: The option being explored

        Returns:
            True if successfully started, False if already explored
        """
        if branch_id not in self._branches:
            logger.warning("branch_not_found", branch_id=branch_id)
            return False

        branch = self._branches[branch_id]
        option = next((o for o in branch.options if o.option_id == option_id), None)

        if not option:
            logger.warning("option_not_found", branch_id=branch_id, option_id=option_id)
            return False

        if option.status != BranchStatus.UNEXPLORED:
            logger.info(
                "option_already_explored",
                branch_id=branch_id,
                option_id=option_id,
                status=option.status.value,
            )
            return False

        # Check for loops
        state_hash = self._compute_state_hash(branch_id, option_id)
        if state_hash in self._visited_states:
            logger.warning(
                "loop_detected",
                branch_id=branch_id,
                option_id=option_id,
            )
            option.status = BranchStatus.DEAD_END
            option.result = "Loop detected - already visited this state"
            self._save_branches()
            return False

        # Check for futile patterns
        if self._pattern_tracker.is_futile_pattern(branch_id):
            logger.warning(
                "futile_pattern_detected_on_start",
                branch_id=branch_id,
                option_id=option_id,
                recommendation="consider_pivoting",
            )
            # Don't block, but log for agent awareness

        # Mark as exploring
        option.status = BranchStatus.EXPLORING
        option.explored_at = datetime.now(timezone.utc).isoformat()
        self._current_branch_id = branch_id
        self._branch_stack.append(branch_id)
        self._visited_states.add(state_hash)
        self._save_branches()

        logger.info(
            "exploration_started",
            branch_id=branch_id,
            option_id=option_id,
            depth=branch.depth,
        )

        return True

    def mark_result(
        self,
        branch_id: str,
        option_id: str,
        status: BranchStatus,
        result: str = "",
        result_type: ExplorationResult | None = None,
        response_data: dict[str, Any] | None = None,
    ) -> None:
        """
        Mark the result of exploring an option.

        Args:
            branch_id: The branch point ID
            option_id: The option that was explored
            status: Result status (SUCCESSFUL, DEAD_END, BLOCKED)
            result: Description of what happened
            result_type: Structured result type for analysis
            response_data: Optional response data (status_code, length, payload)
        """
        if branch_id not in self._branches:
            return

        branch = self._branches[branch_id]
        option = next((o for o in branch.options if o.option_id == option_id), None)

        if option:
            option.status = status
            option.result = result
            option.result_type = result_type

            # Update effectiveness counters
            if status == BranchStatus.SUCCESSFUL:
                option.success_count += 1
            elif status in [BranchStatus.DEAD_END, BranchStatus.BLOCKED]:
                option.failure_count += 1

            if result_type == ExplorationResult.WAF_BLOCKED:
                option.waf_blocked_count += 1
            elif result_type == ExplorationResult.TIMEOUT:
                option.timeout_count += 1

            # Record response pattern if provided
            if response_data:
                self._pattern_tracker.record_response(
                    branch_id=branch_id,
                    status_code=response_data.get("status_code", 0),
                    response_length=response_data.get("response_length", 0),
                    payload=response_data.get("payload", ""),
                    waf_detected=(result_type == ExplorationResult.WAF_BLOCKED),
                )

            logger.info(
                "exploration_result",
                branch_id=branch_id,
                option_id=option_id,
                status=status.value,
                result_type=result_type.value if result_type else None,
                result=result[:100] if result else None,
            )

        # Pop from stack if we were exploring this branch
        if self._branch_stack and self._branch_stack[-1] == branch_id:
            self._branch_stack.pop()
            self._current_branch_id = self._branch_stack[-1] if self._branch_stack else None

        self._save_branches()

    def get_backtrack_target(self) -> tuple[str, str] | None:
        """
        Find the best branch point to backtrack to with effectiveness weighting.

        Returns the branch_id and option_id to try next, or None if
        all paths have been explored.

        Returns:
            Tuple of (branch_id, option_id) or None
        """
        candidates = []

        for branch in self._branches.values():
            for option in branch.options:
                if option.status == BranchStatus.UNEXPLORED:
                    # Calculate weighted score
                    base_priority = option.priority
                    effectiveness_bonus = option.effectiveness_score * 20
                    depth_penalty = branch.depth * 2  # Prefer shallower branches

                    # Check if similar options in this branch were blocked
                    similar_blocked = self._count_similar_blocked(branch.branch_id, option)
                    blocking_penalty = similar_blocked * 15

                    # Check for futile patterns
                    futile_penalty = 0
                    if self._pattern_tracker.is_futile_pattern(branch.branch_id, threshold=3):
                        futile_penalty = 30

                    final_score = (
                        base_priority
                        + effectiveness_bonus
                        - depth_penalty
                        - blocking_penalty
                        - futile_penalty
                    )

                    candidates.append((final_score, branch.branch_id, option.option_id))

        if not candidates:
            return None

        # Sort by score descending
        candidates.sort(key=lambda x: x[0], reverse=True)

        best_score, best_branch_id, best_option_id = candidates[0]

        logger.info(
            "backtrack_target_found",
            branch_id=best_branch_id,
            option_id=best_option_id,
            score=best_score,
        )

        return (best_branch_id, best_option_id)

    def _count_similar_blocked(self, branch_id: str, option: BranchOption) -> int:
        """Count how many similar options in this branch were blocked."""
        if branch_id not in self._branches:
            return 0

        branch = self._branches[branch_id]
        blocked_count = 0

        for other_option in branch.options:
            if other_option.option_id == option.option_id:
                continue

            if other_option.status == BranchStatus.BLOCKED:
                # Simple similarity check based on description
                if self._pattern_tracker.compute_payload_similarity(
                    option.description,
                    other_option.description
                ) > 0.7:
                    blocked_count += 1

        return blocked_count

    def check_diminishing_returns(self, branch_id: str) -> dict:
        """Check if branch is showing diminishing returns."""
        if branch_id not in self._branches:
            return {"diminishing": False}

        branch = self._branches[branch_id]
        explored = [o for o in branch.options if o.status != BranchStatus.UNEXPLORED]

        if len(explored) < 3:
            return {"diminishing": False, "reason": "insufficient_data"}

        # Calculate recent success rate (last 5 attempts)
        recent = explored[-5:]
        recent_successes = sum(1 for o in recent if o.status == BranchStatus.SUCCESSFUL)
        recent_rate = recent_successes / len(recent)

        # Calculate overall success rate
        all_successes = sum(1 for o in explored if o.status == BranchStatus.SUCCESSFUL)
        overall_rate = all_successes / len(explored) if explored else 0

        # Diminishing if recent rate < 50% of overall rate
        diminishing = (
            recent_rate < (overall_rate * 0.5) if overall_rate > 0
            else len(recent) >= 5 and recent_successes == 0
        )

        # Check for futile patterns
        pattern_summary = self._pattern_tracker.get_pattern_summary(branch_id)
        is_futile = self._pattern_tracker.is_futile_pattern(branch_id)

        recommendation = "pivot" if (diminishing or is_futile) else "continue"

        return {
            "diminishing": diminishing,
            "recent_success_rate": recent_rate,
            "overall_success_rate": overall_rate,
            "total_explored": len(explored),
            "futile_pattern": is_futile,
            "pattern_summary": pattern_summary,
            "recommendation": recommendation,
        }

    def update_vector_effectiveness(
        self,
        vector_type: str,
        target_type: str,
        success: bool,
        context: str = "",
        execution_time: float = 0.0,
    ) -> None:
        """Update effectiveness tracking for attack vectors."""
        key = f"{vector_type}:{target_type}"

        if success:
            self._vector_effectiveness[key]["successes"] += 1
        else:
            self._vector_effectiveness[key]["failures"] += 1

        if context:
            self._vector_effectiveness[key]["contexts"].append(context)
            # Keep only last 10 contexts
            self._vector_effectiveness[key]["contexts"] = (
                self._vector_effectiveness[key]["contexts"][-10:]
            )

        # Update average execution time
        if execution_time > 0:
            current_avg = self._vector_effectiveness[key]["avg_time"]
            total_attempts = (
                self._vector_effectiveness[key]["successes"]
                + self._vector_effectiveness[key]["failures"]
            )
            new_avg = ((current_avg * (total_attempts - 1)) + execution_time) / total_attempts
            self._vector_effectiveness[key]["avg_time"] = new_avg

        self._save_branches()

        logger.info(
            "vector_effectiveness_updated",
            vector=vector_type,
            target=target_type,
            success=success,
            total_successes=self._vector_effectiveness[key]["successes"],
            total_failures=self._vector_effectiveness[key]["failures"],
        )

    def get_recommended_vectors(self, target_type: str, top_n: int = 5) -> list[str]:
        """Get recommended attack vectors based on historical effectiveness."""
        scores = []

        for key, data in self._vector_effectiveness.items():
            if key.endswith(f":{target_type}"):
                vector = key.split(":")[0]
                total = data["successes"] + data["failures"]
                if total > 0:
                    success_rate = data["successes"] / total
                    # Boost vectors with more attempts (more reliable data)
                    confidence_factor = min(1.0, total / 10)
                    final_score = success_rate * (0.7 + (0.3 * confidence_factor))
                    scores.append((vector, final_score, total, success_rate))

        # Sort by final score, then by sample size
        scores.sort(key=lambda x: (x[1], x[2]), reverse=True)

        logger.info(
            "recommended_vectors_retrieved",
            target_type=target_type,
            top_vectors=[s[0] for s in scores[:top_n]],
        )

        return [s[0] for s in scores[:top_n]]

    def get_vector_effectiveness_summary(self) -> dict[str, Any]:
        """Get a summary of attack vector effectiveness."""
        summary = {}

        for key, data in self._vector_effectiveness.items():
            total = data["successes"] + data["failures"]
            if total > 0:
                summary[key] = {
                    "success_rate": data["successes"] / total,
                    "total_attempts": total,
                    "successes": data["successes"],
                    "failures": data["failures"],
                    "avg_time": round(data["avg_time"], 2),
                }

        return summary

    def get_unexplored_count(self) -> int:
        """Get total count of unexplored options across all branches."""
        count = 0
        for branch in self._branches.values():
            count += len(branch.get_unexplored_options())
        return count

    def get_exploration_summary(self) -> dict[str, Any]:
        """Get a summary of exploration progress."""
        total_options = 0
        explored = 0
        successful = 0
        dead_ends = 0
        blocked = 0

        for branch in self._branches.values():
            for option in branch.options:
                total_options += 1
                if option.status != BranchStatus.UNEXPLORED:
                    explored += 1
                if option.status == BranchStatus.SUCCESSFUL:
                    successful += 1
                elif option.status == BranchStatus.DEAD_END:
                    dead_ends += 1
                elif option.status == BranchStatus.BLOCKED:
                    blocked += 1

        return {
            "total_branches": len(self._branches),
            "total_options": total_options,
            "explored": explored,
            "unexplored": total_options - explored,
            "successful": successful,
            "dead_ends": dead_ends,
            "blocked": blocked,
            "exploration_percent": round(explored / total_options * 100, 1) if total_options > 0 else 0,
            "current_depth": len(self._branch_stack),
        }

    def get_unexplored_branches_summary(self) -> str:
        """Get a human-readable summary of unexplored options."""
        lines = ["# Unexplored Attack Paths", ""]

        for branch in self._branches.values():
            unexplored = branch.get_unexplored_options()
            if unexplored:
                # Add diminishing returns check
                dim_check = self.check_diminishing_returns(branch.branch_id)
                warning = ""
                if dim_check.get("diminishing") or dim_check.get("futile_pattern"):
                    warning = " [WARNING: Diminishing returns detected]"

                lines.append(f"## {branch.decision_type.value}: {branch.context[:50]}...{warning}")
                for opt in unexplored[:5]:  # Limit to 5 options
                    eff_score = opt.effectiveness_score
                    eff_indicator = f" (eff: {eff_score:.2f})" if eff_score > 0 else ""
                    lines.append(f"  - [{opt.priority}] {opt.description}{eff_indicator}")
                if len(unexplored) > 5:
                    lines.append(f"  ... and {len(unexplored) - 5} more")
                lines.append("")

        if len(lines) == 2:  # Just header
            lines.append("All paths have been explored!")

        return "\n".join(lines)

    def suggest_next_action(self) -> dict[str, Any] | None:
        """
        Suggest the next action based on unexplored branches.

        Returns a dict with branch info and recommended action.
        """
        target = self.get_backtrack_target()
        if not target:
            return None

        branch_id, option_id = target
        branch = self._branches[branch_id]
        option = next((o for o in branch.options if o.option_id == option_id), None)

        if not option:
            return None

        # Check diminishing returns
        dim_check = self.check_diminishing_returns(branch_id)

        return {
            "action": "backtrack",
            "branch_id": branch_id,
            "option_id": option_id,
            "decision_type": branch.decision_type.value,
            "context": branch.context,
            "option_description": option.description,
            "priority": option.priority,
            "depth": branch.depth,
            "effectiveness_score": option.effectiveness_score,
            "diminishing_returns": dim_check,
            "message": f"Backtrack to try: {option.description} (priority: {option.priority})",
        }

    def record_attack_vector_decision(
        self,
        context: str,
        vectors: list[str],
        priorities: dict[str, int] | None = None,
        target_type: str = "web",
    ) -> BranchPoint:
        """
        Convenience method to record an attack vector decision.

        Args:
            context: What we're attacking
            vectors: List of attack vectors (sqli, xss, ssrf, etc.)
            priorities: Optional priority overrides
            target_type: Type of target for effectiveness lookup

        Returns:
            The created BranchPoint
        """
        priorities = priorities or {}

        # Default priorities based on typical CTF impact
        default_priorities = {
            "rce": 95,
            "sqli": 90,
            "ssti": 88,
            "ssrf": 85,
            "lfi": 82,
            "file_upload": 80,
            "idor": 75,
            "xxe": 72,
            "xss": 70,
            "csrf": 60,
            "open_redirect": 50,
            "info_disclosure": 40,
        }

        # Get recommended vectors based on past success
        recommended = self.get_recommended_vectors(target_type)

        options = []
        for vector in vectors:
            base_priority = priorities.get(vector, default_priorities.get(vector, 50))

            # Boost priority if this vector has been successful before
            if vector in recommended:
                boost = (5 - recommended.index(vector)) * 5  # Top vector gets +25
                base_priority = min(100, base_priority + boost)

            options.append({
                "id": vector,
                "description": f"Test for {vector.upper()} vulnerabilities",
                "priority": base_priority,
            })

        return self.create_branch_point(
            decision_type=DecisionType.ATTACK_VECTOR,
            context=context,
            options=options,
        )

    def record_endpoint_decision(
        self,
        endpoints: list[dict[str, Any]],
        parent_branch_id: str | None = None,
    ) -> BranchPoint:
        """
        Record a decision about which endpoint to test.

        Args:
            endpoints: List of endpoints with 'url', 'method', 'priority'
            parent_branch_id: Parent branch if this is nested

        Returns:
            The created BranchPoint
        """
        options = []
        for ep in endpoints:
            url = ep.get("url", ep.get("endpoint", "unknown"))
            method = ep.get("method", "GET")
            priority = ep.get("priority", 50)

            # Boost priority for interesting patterns
            if any(x in url.lower() for x in ["admin", "api", "upload", "exec", "debug"]):
                priority = min(100, priority + 20)

            options.append({
                "id": f"{method}_{url}",
                "description": f"{method} {url}",
                "priority": priority,
                "metadata": ep,
            })

        return self.create_branch_point(
            decision_type=DecisionType.ENDPOINT,
            context=f"Testing {len(endpoints)} endpoints",
            options=options,
            parent_branch_id=parent_branch_id,
        )

    def record_payload_decision(
        self,
        vuln_type: str,
        payloads: list[str],
        parent_branch_id: str | None = None,
    ) -> BranchPoint:
        """
        Record a decision about which payload to try.

        Args:
            vuln_type: Type of vulnerability being tested
            payloads: List of payloads to try
            parent_branch_id: Parent branch if nested

        Returns:
            The created BranchPoint
        """
        options = []
        for i, payload in enumerate(payloads):
            # Simple payloads first (more likely to work without WAF issues)
            complexity = len(payload)
            priority = max(10, 100 - (complexity // 10))

            options.append({
                "id": f"payload_{i}",
                "description": payload[:50] + "..." if len(payload) > 50 else payload,
                "priority": priority,
                "metadata": {"full_payload": payload},
            })

        return self.create_branch_point(
            decision_type=DecisionType.PAYLOAD,
            context=f"Payload selection for {vuln_type}",
            options=options,
            parent_branch_id=parent_branch_id,
        )

    def _generate_branch_id(self, decision_type: DecisionType, context: str) -> str:
        """Generate a unique branch ID."""
        content = f"{decision_type.value}:{context}:{datetime.now(timezone.utc).isoformat()}"
        return f"branch_{hashlib.md5(content.encode()).hexdigest()[:12]}"

    def _compute_state_hash(self, branch_id: str, option_id: str) -> str:
        """Compute a hash representing the current state to detect loops."""
        # Include the path to this state
        path = ":".join(self._branch_stack + [branch_id, option_id])
        return hashlib.md5(path.encode()).hexdigest()

    def _prune_exhausted_branches(self) -> None:
        """Remove fully exhausted branches to save memory."""
        to_remove = []
        for branch_id, branch in self._branches.items():
            if branch.is_exhausted() and branch_id not in self._branch_stack:
                to_remove.append(branch_id)

        for branch_id in to_remove[:10]:  # Remove up to 10 at a time
            del self._branches[branch_id]

        if to_remove:
            logger.info("pruned_exhausted_branches", count=len(to_remove[:10]))

    def _load_branches(self) -> None:
        """Load branches from disk."""
        if not self._operation_dir:
            return

        path = self._operation_dir / "branch_tracker.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())

                # Load branches
                for branch_id, branch_data in data.get("branches", {}).items():
                    options = [
                        BranchOption(
                            option_id=o["option_id"],
                            description=o["description"],
                            priority=o.get("priority", 50),
                            status=BranchStatus(o.get("status", "unexplored")),
                            result=o.get("result"),
                            explored_at=o.get("explored_at"),
                            metadata=o.get("metadata", {}),
                            success_count=o.get("success_count", 0),
                            failure_count=o.get("failure_count", 0),
                            waf_blocked_count=o.get("waf_blocked_count", 0),
                            timeout_count=o.get("timeout_count", 0),
                            result_type=ExplorationResult(o["result_type"]) if o.get("result_type") else None,
                        )
                        for o in branch_data.get("options", [])
                    ]
                    self._branches[branch_id] = BranchPoint(
                        branch_id=branch_data["branch_id"],
                        decision_type=DecisionType(branch_data["decision_type"]),
                        context=branch_data["context"],
                        options=options,
                        created_at=branch_data.get("created_at", ""),
                        parent_branch_id=branch_data.get("parent_branch_id"),
                        depth=branch_data.get("depth", 0),
                    )

                # Load visited states
                self._visited_states = set(data.get("visited_states", []))

                # Load pattern tracker
                if "pattern_tracker" in data:
                    self._pattern_tracker = ResponsePatternTracker.from_dict(data["pattern_tracker"])

                # Load vector effectiveness
                if "vector_effectiveness" in data:
                    self._vector_effectiveness = defaultdict(
                        lambda: {"successes": 0, "failures": 0, "contexts": [], "avg_time": 0.0},
                        data["vector_effectiveness"]
                    )

                logger.info("branches_loaded", count=len(self._branches))
            except Exception as e:
                logger.warning("failed_to_load_branches", error=str(e))

    def _save_branches(self) -> None:
        """Save branches to disk."""
        if not self._operation_dir:
            return

        path = self._operation_dir / "branch_tracker.json"
        try:
            data = {
                "branches": {bid: b.to_dict() for bid, b in self._branches.items()},
                "visited_states": list(self._visited_states),
                "current_branch_id": self._current_branch_id,
                "branch_stack": self._branch_stack,
                "pattern_tracker": self._pattern_tracker.to_dict(),
                "vector_effectiveness": dict(self._vector_effectiveness),
            }
            path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning("failed_to_save_branches", error=str(e))

    def reset(self) -> None:
        """Reset all tracking state."""
        self._branches.clear()
        self._visited_states.clear()
        self._branch_stack.clear()
        self._current_branch_id = None
        self._pattern_tracker = ResponsePatternTracker()
        self._vector_effectiveness = defaultdict(
            lambda: {"successes": 0, "failures": 0, "contexts": [], "avg_time": 0.0}
        )
        self._save_branches()
        logger.info("branch_tracker_reset")
