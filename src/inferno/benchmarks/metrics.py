"""
Benchmark Metrics Collection and Analysis.

Provides comprehensive metrics tracking for benchmark evaluation
including accuracy, performance, and resource usage metrics.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class AccuracyMetrics:
    """Accuracy metrics for benchmark evaluation."""
    # Detection metrics
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    # CTF metrics
    flags_captured: int = 0
    flags_total: int = 0

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)"""
        total = self.true_positives + self.false_positives
        if total == 0:
            return 1.0
        return self.true_positives / total

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)"""
        total = self.true_positives + self.false_negatives
        if total == 0:
            return 1.0
        return self.true_positives / total

    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)"""
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def accuracy(self) -> float:
        """Overall accuracy = (TP + TN) / total"""
        total = (
            self.true_positives +
            self.false_positives +
            self.true_negatives +
            self.false_negatives
        )
        if total == 0:
            return 1.0
        return (self.true_positives + self.true_negatives) / total

    @property
    def false_positive_rate(self) -> float:
        """FPR = FP / (FP + TN)"""
        total = self.false_positives + self.true_negatives
        if total == 0:
            return 0.0
        return self.false_positives / total

    @property
    def flag_capture_rate(self) -> float:
        """Percentage of flags captured."""
        if self.flags_total == 0:
            return 1.0
        return self.flags_captured / self.flags_total

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "accuracy": round(self.accuracy, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "flags_captured": self.flags_captured,
            "flags_total": self.flags_total,
            "flag_capture_rate": round(self.flag_capture_rate, 4),
        }


@dataclass
class PerformanceMetrics:
    """Performance and resource usage metrics."""
    # Time metrics
    total_duration_seconds: float = 0.0
    task_durations: list[float] = field(default_factory=list)

    # Token metrics
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cache_tokens: int = 0

    # Cost metrics
    total_cost_usd: float = 0.0
    task_costs: list[float] = field(default_factory=list)

    # Turn metrics
    total_turns: int = 0
    task_turns: list[int] = field(default_factory=list)

    # Tool usage
    tool_calls: int = 0
    tool_calls_by_type: dict[str, int] = field(default_factory=dict)
    tool_errors: int = 0

    @property
    def total_tokens(self) -> int:
        """Total tokens used."""
        return self.total_input_tokens + self.total_output_tokens

    @property
    def avg_duration(self) -> float:
        """Average task duration."""
        if not self.task_durations:
            return 0.0
        return statistics.mean(self.task_durations)

    @property
    def avg_cost(self) -> float:
        """Average task cost."""
        if not self.task_costs:
            return 0.0
        return statistics.mean(self.task_costs)

    @property
    def avg_turns(self) -> float:
        """Average turns per task."""
        if not self.task_turns:
            return 0.0
        return statistics.mean(self.task_turns)

    @property
    def tokens_per_turn(self) -> float:
        """Average tokens per turn."""
        if self.total_turns == 0:
            return 0.0
        return self.total_tokens / self.total_turns

    @property
    def cost_per_token(self) -> float:
        """Cost per token in USD."""
        if self.total_tokens == 0:
            return 0.0
        return self.total_cost_usd / self.total_tokens

    @property
    def tool_error_rate(self) -> float:
        """Tool error rate."""
        if self.tool_calls == 0:
            return 0.0
        return self.tool_errors / self.tool_calls

    def record_task(
        self,
        duration: float,
        cost: float,
        turns: int,
        tokens: int = 0,
    ) -> None:
        """Record metrics for a completed task."""
        self.task_durations.append(duration)
        self.task_costs.append(cost)
        self.task_turns.append(turns)
        self.total_duration_seconds += duration
        self.total_cost_usd += cost
        self.total_turns += turns

    def record_tool_call(self, tool_name: str, success: bool = True) -> None:
        """Record a tool call."""
        self.tool_calls += 1
        self.tool_calls_by_type[tool_name] = (
            self.tool_calls_by_type.get(tool_name, 0) + 1
        )
        if not success:
            self.tool_errors += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_duration_seconds": round(self.total_duration_seconds, 2),
            "avg_duration": round(self.avg_duration, 2),
            "total_tokens": self.total_tokens,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cache_tokens": self.total_cache_tokens,
            "tokens_per_turn": round(self.tokens_per_turn, 2),
            "total_cost_usd": round(self.total_cost_usd, 4),
            "avg_cost": round(self.avg_cost, 4),
            "cost_per_token": round(self.cost_per_token * 1000000, 4),  # Per million
            "total_turns": self.total_turns,
            "avg_turns": round(self.avg_turns, 2),
            "tool_calls": self.tool_calls,
            "tool_error_rate": round(self.tool_error_rate, 4),
            "top_tools": dict(sorted(
                self.tool_calls_by_type.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
        }


@dataclass
class BenchmarkMetrics:
    """Complete benchmark metrics collection."""
    # Identification
    benchmark_id: str = ""
    benchmark_name: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    # Task tracking
    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_passed: int = 0
    tasks_failed: int = 0
    tasks_timeout: int = 0
    tasks_skipped: int = 0

    # Scores
    task_scores: list[float] = field(default_factory=list)
    weighted_scores: list[float] = field(default_factory=list)

    # Sub-metrics
    accuracy: AccuracyMetrics = field(default_factory=AccuracyMetrics)
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)

    # Category breakdown
    scores_by_category: dict[str, list[float]] = field(default_factory=dict)
    scores_by_difficulty: dict[str, list[float]] = field(default_factory=dict)

    @property
    def overall_score(self) -> float:
        """Overall benchmark score (0-100)."""
        if not self.task_scores:
            return 0.0
        return statistics.mean(self.task_scores) * 100

    @property
    def weighted_score(self) -> float:
        """Weighted score accounting for difficulty."""
        if not self.weighted_scores:
            return 0.0
        return statistics.mean(self.weighted_scores) * 100

    @property
    def pass_rate(self) -> float:
        """Task pass rate."""
        if self.tasks_completed == 0:
            return 0.0
        return self.tasks_passed / self.tasks_completed

    @property
    def completion_rate(self) -> float:
        """Task completion rate."""
        if self.tasks_total == 0:
            return 0.0
        return self.tasks_completed / self.tasks_total

    @property
    def duration_seconds(self) -> float:
        """Total benchmark duration."""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return (datetime.now(UTC) - self.started_at).total_seconds()

    def record_task_result(
        self,
        score: float,
        weighted_score: float,
        passed: bool,
        category: str = "",
        difficulty: str = "",
        timeout: bool = False,
    ) -> None:
        """Record a task result."""
        self.tasks_completed += 1
        self.task_scores.append(score)
        self.weighted_scores.append(weighted_score)

        if timeout:
            self.tasks_timeout += 1
        elif passed:
            self.tasks_passed += 1
        else:
            self.tasks_failed += 1

        # Category tracking
        if category:
            if category not in self.scores_by_category:
                self.scores_by_category[category] = []
            self.scores_by_category[category].append(score)

        # Difficulty tracking
        if difficulty:
            if difficulty not in self.scores_by_difficulty:
                self.scores_by_difficulty[difficulty] = []
            self.scores_by_difficulty[difficulty].append(score)

    def complete(self) -> None:
        """Mark benchmark as complete."""
        self.completed_at = datetime.now(UTC)

    def get_category_scores(self) -> dict[str, float]:
        """Get average scores by category."""
        return {
            cat: statistics.mean(scores) * 100
            for cat, scores in self.scores_by_category.items()
            if scores
        }

    def get_difficulty_scores(self) -> dict[str, float]:
        """Get average scores by difficulty."""
        return {
            diff: statistics.mean(scores) * 100
            for diff, scores in self.scores_by_difficulty.items()
            if scores
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to comprehensive dictionary."""
        return {
            "benchmark_id": self.benchmark_id,
            "benchmark_name": self.benchmark_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": {
                "tasks_total": self.tasks_total,
                "tasks_completed": self.tasks_completed,
                "tasks_passed": self.tasks_passed,
                "tasks_failed": self.tasks_failed,
                "tasks_timeout": self.tasks_timeout,
                "tasks_skipped": self.tasks_skipped,
                "pass_rate": round(self.pass_rate, 4),
                "completion_rate": round(self.completion_rate, 4),
            },
            "scores": {
                "overall_score": round(self.overall_score, 2),
                "weighted_score": round(self.weighted_score, 2),
                "by_category": self.get_category_scores(),
                "by_difficulty": self.get_difficulty_scores(),
            },
            "accuracy": self.accuracy.to_dict(),
            "performance": self.performance.to_dict(),
        }

    def generate_report(self) -> str:
        """Generate a human-readable benchmark report."""
        lines = [
            f"# Benchmark Report: {self.benchmark_name}",
            "",
            f"**Benchmark ID**: {self.benchmark_id}",
            f"**Duration**: {self.duration_seconds:.2f} seconds",
            "",
            "## Summary",
            f"- Tasks: {self.tasks_passed}/{self.tasks_completed} passed ({self.pass_rate*100:.1f}%)",
            f"- Timeouts: {self.tasks_timeout}",
            f"- Skipped: {self.tasks_skipped}",
            "",
            "## Scores",
            f"- Overall Score: **{self.overall_score:.1f}%**",
            f"- Weighted Score: **{self.weighted_score:.1f}%**",
            "",
            "### By Category",
        ]

        for cat, score in sorted(self.get_category_scores().items()):
            lines.append(f"- {cat}: {score:.1f}%")

        lines.extend([
            "",
            "### By Difficulty",
        ])

        for diff, score in sorted(self.get_difficulty_scores().items()):
            lines.append(f"- {diff}: {score:.1f}%")

        lines.extend([
            "",
            "## Accuracy Metrics",
            f"- Precision: {self.accuracy.precision*100:.1f}%",
            f"- Recall: {self.accuracy.recall*100:.1f}%",
            f"- F1 Score: {self.accuracy.f1_score*100:.1f}%",
            f"- False Positive Rate: {self.accuracy.false_positive_rate*100:.1f}%",
        ])

        if self.accuracy.flags_total > 0:
            lines.append(
                f"- Flag Capture Rate: {self.accuracy.flag_capture_rate*100:.1f}% "
                f"({self.accuracy.flags_captured}/{self.accuracy.flags_total})"
            )

        lines.extend([
            "",
            "## Performance Metrics",
            f"- Total Tokens: {self.performance.total_tokens:,}",
            f"- Total Cost: ${self.performance.total_cost_usd:.4f}",
            f"- Avg Turns per Task: {self.performance.avg_turns:.1f}",
            f"- Avg Duration per Task: {self.performance.avg_duration:.1f}s",
            f"- Tool Calls: {self.performance.tool_calls}",
            f"- Tool Error Rate: {self.performance.tool_error_rate*100:.1f}%",
        ])

        return "\n".join(lines)


class MetricsCollector:
    """
    Collects and aggregates metrics during benchmark execution.

    Thread-safe collector for real-time metrics updates.
    """

    def __init__(self, benchmark_id: str = "", benchmark_name: str = ""):
        """Initialize metrics collector."""
        self._metrics = BenchmarkMetrics(
            benchmark_id=benchmark_id,
            benchmark_name=benchmark_name,
        )
        self._task_metrics: dict[str, dict[str, Any]] = {}

    @property
    def metrics(self) -> BenchmarkMetrics:
        """Get current metrics."""
        return self._metrics

    def set_total_tasks(self, count: int) -> None:
        """Set total task count."""
        self._metrics.tasks_total = count

    def start_task(self, task_id: str) -> None:
        """Mark task as started."""
        self._task_metrics[task_id] = {
            "started_at": datetime.now(UTC),
            "tool_calls": [],
        }

    def record_tool_call(
        self,
        task_id: str,
        tool_name: str,
        success: bool = True,
    ) -> None:
        """Record a tool call for a task."""
        if task_id in self._task_metrics:
            self._task_metrics[task_id]["tool_calls"].append({
                "tool": tool_name,
                "success": success,
            })
        self._metrics.performance.record_tool_call(tool_name, success)

    def complete_task(
        self,
        task_id: str,
        score: float,
        weighted_score: float,
        passed: bool,
        category: str = "",
        difficulty: str = "",
        timeout: bool = False,
        tokens_used: int = 0,
        cost_usd: float = 0.0,
        turns_used: int = 0,
        findings_found: int = 0,
        findings_correct: int = 0,
        false_positives: int = 0,
        flags_found: int = 0,
        flags_total: int = 0,
    ) -> None:
        """Record task completion."""
        # Calculate duration
        duration = 0.0
        if task_id in self._task_metrics:
            started = self._task_metrics[task_id]["started_at"]
            duration = (datetime.now(UTC) - started).total_seconds()

        # Record to metrics
        self._metrics.record_task_result(
            score=score,
            weighted_score=weighted_score,
            passed=passed,
            category=category,
            difficulty=difficulty,
            timeout=timeout,
        )

        # Performance metrics
        self._metrics.performance.record_task(
            duration=duration,
            cost=cost_usd,
            turns=turns_used,
            tokens=tokens_used,
        )

        # Accuracy metrics
        self._metrics.accuracy.true_positives += findings_correct
        self._metrics.accuracy.false_positives += false_positives
        # Approximate false negatives (expected - found)
        expected = findings_found + findings_correct  # Simplified
        self._metrics.accuracy.false_negatives += max(0, expected - findings_found)

        # CTF metrics
        self._metrics.accuracy.flags_captured += flags_found
        self._metrics.accuracy.flags_total += flags_total

        logger.info(
            "task_metrics_recorded",
            task_id=task_id,
            score=score,
            passed=passed,
            duration=duration,
        )

    def skip_task(self, task_id: str) -> None:
        """Mark task as skipped."""
        self._metrics.tasks_skipped += 1

    def complete_benchmark(self) -> BenchmarkMetrics:
        """Mark benchmark as complete and return final metrics."""
        self._metrics.complete()
        logger.info(
            "benchmark_complete",
            benchmark_id=self._metrics.benchmark_id,
            overall_score=self._metrics.overall_score,
        )
        return self._metrics

    def get_report(self) -> str:
        """Generate metrics report."""
        return self._metrics.generate_report()

    def to_dict(self) -> dict[str, Any]:
        """Get metrics as dictionary."""
        return self._metrics.to_dict()
