"""
Inferno Benchmarks Module.

Provides benchmarking infrastructure for evaluating agent
performance on security assessment tasks.

Inspired by CAIBench integration patterns.
"""

from inferno.benchmarks.metrics import (
    AccuracyMetrics,
    BenchmarkMetrics,
    MetricsCollector,
    PerformanceMetrics,
)
from inferno.benchmarks.runner import (
    BenchmarkConfig,
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkSuite,
    get_benchmark_runner,
)
from inferno.benchmarks.tasks import (
    BenchmarkTask,
    TaskCategory,
    TaskDifficulty,
    create_task,
)

__all__ = [
    "BenchmarkRunner",
    "BenchmarkConfig",
    "BenchmarkResult",
    "BenchmarkSuite",
    "get_benchmark_runner",
    "BenchmarkMetrics",
    "MetricsCollector",
    "AccuracyMetrics",
    "PerformanceMetrics",
    "BenchmarkTask",
    "TaskCategory",
    "TaskDifficulty",
    "create_task",
]
