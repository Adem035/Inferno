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
    "AccuracyMetrics",
    "BenchmarkConfig",
    "BenchmarkMetrics",
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSuite",
    "BenchmarkTask",
    "MetricsCollector",
    "PerformanceMetrics",
    "TaskCategory",
    "TaskDifficulty",
    "create_task",
    "get_benchmark_runner",
]
