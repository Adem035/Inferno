"""
Benchmark Runner - Execute and evaluate benchmark suites.

Provides the infrastructure to run benchmark tasks against
the Inferno agent and collect performance metrics.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from inferno.benchmarks.metrics import (
    BenchmarkMetrics,
    MetricsCollector,
)
from inferno.benchmarks.tasks import (
    BenchmarkTask,
    ExpectedFinding,
    TaskCategory,
    TaskDifficulty,
    TaskResult,
    TaskStatus,
    TaskValidation,
)

logger = structlog.get_logger(__name__)


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution."""
    # Execution settings
    max_parallel: int = 1  # Number of tasks to run in parallel
    timeout_seconds: float = 300.0  # Default timeout per task
    fail_fast: bool = False  # Stop on first failure

    # Resource limits
    max_total_cost_usd: float = 10.0  # Budget limit
    max_total_tokens: int = 1000000  # Token limit

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path("outputs/benchmarks"))
    save_results: bool = True
    verbose: bool = True

    # Filtering
    categories: list[TaskCategory] | None = None  # Filter by category
    difficulties: list[TaskDifficulty] | None = None  # Filter by difficulty
    tags: list[str] | None = None  # Filter by tags

    # Callbacks
    on_task_start: Callable[[str], None] | None = None
    on_task_complete: Callable[[str, TaskResult], None] | None = None
    on_progress: Callable[[int, int], None] | None = None


@dataclass
class BenchmarkSuite:
    """A collection of benchmark tasks."""
    suite_id: str
    name: str
    description: str
    tasks: list[BenchmarkTask] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_task(self, task: BenchmarkTask) -> None:
        """Add a task to the suite."""
        self.tasks.append(task)

    def get_tasks_by_category(
        self,
        category: TaskCategory,
    ) -> list[BenchmarkTask]:
        """Get tasks filtered by category."""
        return [t for t in self.tasks if t.category == category]

    def get_tasks_by_difficulty(
        self,
        difficulty: TaskDifficulty,
    ) -> list[BenchmarkTask]:
        """Get tasks filtered by difficulty."""
        return [t for t in self.tasks if t.difficulty == difficulty]

    def get_tasks_by_tags(
        self,
        tags: list[str],
    ) -> list[BenchmarkTask]:
        """Get tasks that have any of the specified tags."""
        tag_set = set(tags)
        return [t for t in self.tasks if tag_set.intersection(t.tags)]


@dataclass
class BenchmarkResult:
    """Complete result of a benchmark run."""
    benchmark_id: str
    suite_id: str
    config: BenchmarkConfig
    metrics: BenchmarkMetrics
    task_results: dict[str, TaskResult]
    started_at: datetime
    completed_at: datetime | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "benchmark_id": self.benchmark_id,
            "suite_id": self.suite_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "metrics": self.metrics.to_dict(),
            "task_results": {
                tid: {
                    "task_id": r.task_id,
                    "status": r.status.value,
                    "score": r.score,
                    "weighted_score": r.weighted_score,
                    "findings_expected": r.findings_expected,
                    "findings_found": r.findings_found,
                    "findings_correct": r.findings_correct,
                    "false_positives": r.false_positives,
                    "turns_used": r.turns_used,
                    "tokens_used": r.tokens_used,
                    "cost_usd": r.cost_usd,
                    "duration_seconds": r.duration_seconds,
                    "error": r.error,
                }
                for tid, r in self.task_results.items()
            },
        }

    def save(self, path: Path | None = None) -> Path:
        """Save results to JSON file."""
        if path is None:
            path = self.config.output_dir / f"benchmark_{self.benchmark_id}.json"

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

        return path


class TaskValidator:
    """Validates task execution results against expected findings."""

    def validate(
        self,
        task: BenchmarkTask,
        findings: list[dict[str, Any]],
        flags_captured: list[str] = None,
    ) -> tuple[float, int, int, int]:
        """
        Validate task results.

        Args:
            task: The benchmark task
            findings: Findings from agent execution
            flags_captured: Captured flags (for CTF tasks)

        Returns:
            Tuple of (score, findings_correct, false_positives, findings_expected)
        """
        validation = task.validation
        flags_captured = flags_captured or []

        # CTF task validation
        if validation.expected_flags:
            flags_found = sum(
                1 for flag in validation.expected_flags
                if flag in flags_captured
            )
            total_flags = len(validation.expected_flags)
            score = flags_found / total_flags if total_flags > 0 else 0.0
            return score, flags_found, 0, total_flags

        # Finding-based validation
        if validation.expected_findings:
            return self._validate_findings(validation, findings)

        # Custom validator
        if validation.custom_validator:
            try:
                score = validation.custom_validator({
                    "findings": findings,
                    "flags": flags_captured,
                })
                return score, 0, 0, 0
            except Exception as e:
                logger.error("custom_validator_error", error=str(e))
                return 0.0, 0, 0, 0

        # No validation criteria - assume success if any findings
        if findings:
            return 1.0, len(findings), 0, len(findings)

        return 0.0, 0, 0, 0

    def _validate_findings(
        self,
        validation: TaskValidation,
        findings: list[dict[str, Any]],
    ) -> tuple[float, int, int, int]:
        """Validate findings against expected findings."""
        expected = validation.expected_findings
        matched_findings = set()
        false_positives = 0
        score_parts = []

        for finding in findings:
            matched = False
            for i, expected_finding in enumerate(expected):
                if i in matched_findings:
                    continue

                if self._finding_matches(finding, expected_finding):
                    matched_findings.add(i)
                    matched = True
                    if expected_finding.required:
                        score_parts.append(1.0 / sum(1 for e in expected if e.required))
                    else:
                        score_parts.append(expected_finding.partial_credit)
                    break

            if not matched:
                false_positives += 1

        # Check for missing required findings
        required_count = sum(1 for e in expected if e.required)
        required_found = sum(1 for i, e in enumerate(expected) if e.required and i in matched_findings)

        # Calculate score
        score = sum(score_parts)
        score = min(1.0, max(0.0, score))  # Clamp to [0, 1]

        return score, len(matched_findings), false_positives, len(expected)

    def _finding_matches(
        self,
        finding: dict[str, Any],
        expected: ExpectedFinding,
    ) -> bool:
        """Check if a finding matches an expected finding."""
        # Check vuln_type
        if expected.vuln_type:
            finding_type = finding.get("vuln_type", "").lower()
            expected_type = expected.vuln_type.lower()
            if expected_type not in finding_type and finding_type not in expected_type:
                return False

        # Check severity
        if expected.severity:
            finding_severity = finding.get("severity", "").lower()
            if finding_severity != expected.severity.lower():
                return False

        # Check target pattern
        if expected.target_pattern:
            target = finding.get("target", "")
            if not re.search(expected.target_pattern, target, re.IGNORECASE):
                return False

        # Check evidence pattern
        if expected.evidence_pattern:
            evidence = finding.get("evidence", "")
            if not re.search(expected.evidence_pattern, evidence, re.IGNORECASE):
                return False

        return True


class BenchmarkRunner:
    """
    Runs benchmark suites against the Inferno agent.

    Orchestrates task execution, metrics collection, and
    result validation for comprehensive agent evaluation.
    """

    _instance: BenchmarkRunner | None = None

    def __new__(cls) -> BenchmarkRunner:
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._validator = TaskValidator()
        self._current_run: BenchmarkResult | None = None
        self._initialized = True

    async def run_suite(
        self,
        suite: BenchmarkSuite,
        config: BenchmarkConfig | None = None,
    ) -> BenchmarkResult:
        """
        Run a benchmark suite.

        Args:
            suite: Benchmark suite to run
            config: Execution configuration

        Returns:
            Complete benchmark results.
        """
        config = config or BenchmarkConfig()
        benchmark_id = f"bench_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        # Filter tasks
        tasks = self._filter_tasks(suite.tasks, config)

        logger.info(
            "benchmark_starting",
            benchmark_id=benchmark_id,
            suite=suite.name,
            task_count=len(tasks),
        )

        # Initialize metrics
        collector = MetricsCollector(
            benchmark_id=benchmark_id,
            benchmark_name=suite.name,
        )
        collector.set_total_tasks(len(tasks))

        # Initialize result
        result = BenchmarkResult(
            benchmark_id=benchmark_id,
            suite_id=suite.suite_id,
            config=config,
            metrics=collector.metrics,
            task_results={},
            started_at=datetime.now(UTC),
        )
        self._current_run = result

        # Execute tasks
        try:
            if config.max_parallel > 1:
                await self._run_tasks_parallel(
                    tasks, config, collector, result
                )
            else:
                await self._run_tasks_sequential(
                    tasks, config, collector, result
                )

        except Exception as e:
            logger.error("benchmark_error", error=str(e))
            result.error = str(e)

        # Finalize
        result.completed_at = datetime.now(UTC)
        result.metrics = collector.complete_benchmark()

        # Save results
        if config.save_results:
            path = result.save()
            logger.info("benchmark_results_saved", path=str(path))

        logger.info(
            "benchmark_complete",
            benchmark_id=benchmark_id,
            overall_score=result.metrics.overall_score,
            pass_rate=result.metrics.pass_rate,
        )

        return result

    def _filter_tasks(
        self,
        tasks: list[BenchmarkTask],
        config: BenchmarkConfig,
    ) -> list[BenchmarkTask]:
        """Filter tasks based on config criteria."""
        filtered = tasks

        if config.categories:
            filtered = [t for t in filtered if t.category in config.categories]

        if config.difficulties:
            filtered = [t for t in filtered if t.difficulty in config.difficulties]

        if config.tags:
            tag_set = set(config.tags)
            filtered = [t for t in filtered if tag_set.intersection(t.tags)]

        return filtered

    async def _run_tasks_sequential(
        self,
        tasks: list[BenchmarkTask],
        config: BenchmarkConfig,
        collector: MetricsCollector,
        result: BenchmarkResult,
    ) -> None:
        """Run tasks sequentially."""
        for i, task in enumerate(tasks):
            # Check budget limits
            if collector.metrics.performance.total_cost_usd >= config.max_total_cost_usd:
                logger.warning("benchmark_budget_exceeded")
                break

            if config.on_progress:
                config.on_progress(i, len(tasks))

            task_result = await self._run_single_task(task, config, collector)
            result.task_results[task.task_id] = task_result

            if config.fail_fast and task_result.status == TaskStatus.FAILED:
                logger.warning("benchmark_fail_fast_triggered", task_id=task.task_id)
                break

    async def _run_tasks_parallel(
        self,
        tasks: list[BenchmarkTask],
        config: BenchmarkConfig,
        collector: MetricsCollector,
        result: BenchmarkResult,
    ) -> None:
        """Run tasks in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(config.max_parallel)

        async def run_with_limit(task: BenchmarkTask) -> tuple[str, TaskResult]:
            async with semaphore:
                return task.task_id, await self._run_single_task(task, config, collector)

        # Create tasks
        coros = [run_with_limit(task) for task in tasks]

        # Run with progress tracking
        completed = 0
        for coro in asyncio.as_completed(coros):
            task_id, task_result = await coro
            result.task_results[task_id] = task_result
            completed += 1

            if config.on_progress:
                config.on_progress(completed, len(tasks))

    async def _run_single_task(
        self,
        task: BenchmarkTask,
        config: BenchmarkConfig,
        collector: MetricsCollector,
    ) -> TaskResult:
        """Execute a single benchmark task."""
        logger.info(
            "task_starting",
            task_id=task.task_id,
            task_name=task.name,
            difficulty=task.difficulty.value,
        )

        if config.on_task_start:
            config.on_task_start(task.task_id)

        collector.start_task(task.task_id)
        task.status = TaskStatus.RUNNING

        start_time = datetime.now(UTC)
        timeout = task.timeout_seconds or config.timeout_seconds

        try:
            # Execute task with agent
            # This would integrate with the actual Inferno agent
            findings, flags, tokens_used, cost_usd, turns_used = await self._execute_with_agent(
                task, timeout, collector
            )

            duration = (datetime.now(UTC) - start_time).total_seconds()

            # Validate results
            score, correct, fp, expected = self._validator.validate(
                task, findings, flags
            )

            # Apply hint penalty
            score = max(0.0, score - task.calculate_hint_penalty())

            # Calculate weighted score
            weighted_score = score * task.get_score_multiplier()

            # Determine pass/fail
            passed = score >= task.validation.partial_success_threshold

            # Create result
            task_result = TaskResult(
                task_id=task.task_id,
                status=TaskStatus.COMPLETED if passed else TaskStatus.FAILED,
                score=score,
                weighted_score=weighted_score,
                findings_expected=expected,
                findings_found=len(findings),
                findings_correct=correct,
                false_positives=fp,
                flags_expected=len(task.validation.expected_flags),
                flags_found=len(flags),
                turns_used=turns_used,
                tokens_used=tokens_used,
                cost_usd=cost_usd,
                duration_seconds=duration,
                hints_used=task.hints_used,
                findings_detail=findings,
            )

            task.status = task_result.status

        except TimeoutError:
            duration = (datetime.now(UTC) - start_time).total_seconds()
            task_result = TaskResult(
                task_id=task.task_id,
                status=TaskStatus.TIMEOUT,
                score=0.0,
                weighted_score=0.0,
                findings_expected=len(task.validation.expected_findings),
                findings_found=0,
                findings_correct=0,
                false_positives=0,
                duration_seconds=duration,
                error="Task timed out",
            )
            task.status = TaskStatus.TIMEOUT

        except Exception as e:
            duration = (datetime.now(UTC) - start_time).total_seconds()
            task_result = TaskResult(
                task_id=task.task_id,
                status=TaskStatus.FAILED,
                score=0.0,
                weighted_score=0.0,
                findings_expected=len(task.validation.expected_findings),
                findings_found=0,
                findings_correct=0,
                false_positives=0,
                duration_seconds=duration,
                error=str(e),
            )
            task.status = TaskStatus.FAILED
            logger.error("task_error", task_id=task.task_id, error=str(e))

        # Record metrics
        collector.complete_task(
            task_id=task.task_id,
            score=task_result.score,
            weighted_score=task_result.weighted_score,
            passed=task_result.status == TaskStatus.COMPLETED,
            category=task.category.value,
            difficulty=task.difficulty.value,
            timeout=task_result.status == TaskStatus.TIMEOUT,
            tokens_used=task_result.tokens_used,
            cost_usd=task_result.cost_usd,
            turns_used=task_result.turns_used,
            findings_found=task_result.findings_found,
            findings_correct=task_result.findings_correct,
            false_positives=task_result.false_positives,
            flags_found=task_result.flags_found,
            flags_total=task_result.flags_expected,
        )

        if config.on_task_complete:
            config.on_task_complete(task.task_id, task_result)

        logger.info(
            "task_complete",
            task_id=task.task_id,
            status=task_result.status.value,
            score=task_result.score,
        )

        return task_result

    async def _execute_with_agent(
        self,
        task: BenchmarkTask,
        timeout: float,
        collector: MetricsCollector,
    ) -> tuple[list[dict[str, Any]], list[str], int, float, int]:
        """
        Execute task with Inferno agent.

        This is the integration point with the actual agent.
        Returns: (findings, flags, tokens_used, cost_usd, turns_used)
        """
        # Import agent components
        try:
            from inferno.agent.sdk_executor import SDKExecutor
            from inferno.config.settings import InfernoSettings

            settings = InfernoSettings()
            executor = SDKExecutor(settings)

            # Run the assessment
            result = await asyncio.wait_for(
                executor.run(
                    target=task.get_target(),
                    objective=task.get_objective(),
                    max_turns=task.max_turns,
                ),
                timeout=timeout,
            )

            # Extract findings and flags from result
            findings = []
            flags = []

            if hasattr(result, 'findings'):
                findings = result.findings
            if hasattr(result, 'flags'):
                flags = result.flags

            # Get usage metrics
            tokens_used = getattr(result, 'tokens_used', 0)
            cost_usd = getattr(result, 'cost_usd', 0.0)
            turns_used = getattr(result, 'turns_used', 0)

            return findings, flags, tokens_used, cost_usd, turns_used

        except ImportError:
            # Agent not available - return placeholder results
            logger.warning("agent_not_available", message="Using placeholder results")
            return [], [], 0, 0.0, 0

    async def run_task(
        self,
        task: BenchmarkTask,
        config: BenchmarkConfig | None = None,
    ) -> TaskResult:
        """
        Run a single benchmark task.

        Args:
            task: Task to run
            config: Execution configuration

        Returns:
            Task result.
        """
        config = config or BenchmarkConfig()
        collector = MetricsCollector()
        return await self._run_single_task(task, config, collector)

    def get_current_progress(self) -> dict[str, Any] | None:
        """Get current benchmark progress."""
        if not self._current_run:
            return None

        return {
            "benchmark_id": self._current_run.benchmark_id,
            "tasks_completed": len(self._current_run.task_results),
            "current_score": self._current_run.metrics.overall_score,
        }


def get_benchmark_runner() -> BenchmarkRunner:
    """Get the global benchmark runner instance."""
    return BenchmarkRunner()


# Pre-built benchmark suites

def create_web_security_suite() -> BenchmarkSuite:
    """Create a standard web security benchmark suite."""

    suite = BenchmarkSuite(
        suite_id="web_security_standard",
        name="Web Security Standard Suite",
        description="Standard web application security benchmarks",
    )

    # Add common web security tasks
    # These would be populated with actual test targets
    suite.metadata["categories"] = ["injection", "xss", "auth"]

    return suite


def create_ctf_suite(challenges: list[dict[str, Any]]) -> BenchmarkSuite:
    """Create a CTF challenge benchmark suite."""
    from inferno.benchmarks.tasks import create_ctf_task

    suite = BenchmarkSuite(
        suite_id=f"ctf_{uuid.uuid4().hex[:8]}",
        name="CTF Challenge Suite",
        description="Capture The Flag challenges",
    )

    for i, challenge in enumerate(challenges):
        task = create_ctf_task(
            task_id=f"ctf_{i:03d}",
            name=challenge.get("name", f"Challenge {i}"),
            description=challenge.get("description", ""),
            target=challenge.get("target", ""),
            expected_flag=challenge.get("flag", ""),
            difficulty=TaskDifficulty(challenge.get("difficulty", "medium")),
            hints=challenge.get("hints", []),
        )
        suite.add_task(task)

    return suite
