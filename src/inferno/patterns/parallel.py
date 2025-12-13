"""
Parallel execution pattern for Inferno.

This module provides the PARALLEL pattern implementation for running
multiple agents simultaneously. Useful for independent security tasks
that can be executed concurrently.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

import structlog

from inferno.patterns.pattern import (
    ParallelAgentConfig,
    Pattern,
    PatternType,
    parallel_pattern,
)

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)


@dataclass
class ParallelExecutionResult:
    """Result from a parallel execution."""

    agent_name: str
    success: bool
    output: str
    error: Optional[str] = None
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParallelBatchResult:
    """Aggregated results from parallel batch execution."""

    pattern_name: str
    total_agents: int
    successful: int
    failed: int
    results: List[ParallelExecutionResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate as a percentage."""
        if self.total_agents == 0:
            return 0.0
        return (self.successful / self.total_agents) * 100

    def get_failures(self) -> List[ParallelExecutionResult]:
        """Get all failed execution results."""
        return [r for r in self.results if not r.success]

    def get_successes(self) -> List[ParallelExecutionResult]:
        """Get all successful execution results."""
        return [r for r in self.results if r.success]


class ParallelExecutor:
    """
    Executor for running agents in parallel.

    Handles concurrent execution of multiple agents with configurable
    concurrency limits, timeouts, and error handling.
    """

    def __init__(
        self,
        max_concurrent: Optional[int] = None,
        default_timeout: float = 300.0,
        retry_on_failure: bool = False,
        max_retries: int = 1,
    ) -> None:
        """
        Initialize the parallel executor.

        Args:
            max_concurrent: Maximum concurrent executions (None = unlimited).
            default_timeout: Default timeout per agent in seconds.
            retry_on_failure: Whether to retry failed agents.
            max_retries: Maximum retry attempts.
        """
        self._max_concurrent = max_concurrent
        self._default_timeout = default_timeout
        self._retry_on_failure = retry_on_failure
        self._max_retries = max_retries
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def execute_pattern(
        self,
        pattern: Pattern,
        agent_executor: Callable[[ParallelAgentConfig, Dict[str, Any]], Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> ParallelBatchResult:
        """
        Execute a parallel pattern.

        Args:
            pattern: The parallel pattern to execute.
            agent_executor: Async callable that executes a single agent.
            context: Shared context passed to all agents.

        Returns:
            ParallelBatchResult with all agent results.

        Raises:
            ValueError: If pattern is not PARALLEL type.
        """
        if pattern.type != PatternType.PARALLEL:
            raise ValueError(
                f"ParallelExecutor only handles PARALLEL patterns, "
                f"got {pattern.type.value}"
            )

        context = context or {}
        configs = pattern.configs

        logger.info(
            "starting_parallel_execution",
            pattern=pattern.name,
            agent_count=len(configs),
            max_concurrent=self._max_concurrent,
        )

        # Create semaphore for concurrency control
        max_concurrent = pattern.max_concurrent or self._max_concurrent
        if max_concurrent:
            self._semaphore = asyncio.Semaphore(max_concurrent)
        else:
            self._semaphore = None

        # Sort by priority (higher priority first)
        sorted_configs = sorted(
            configs,
            key=lambda c: c.priority,
            reverse=True,
        )

        # Create tasks for all agents
        import time
        start_time = time.time()

        tasks = [
            self._execute_with_semaphore(
                config,
                agent_executor,
                context,
                pattern.unified_context,
            )
            for config in sorted_configs
        ]

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        execution_results: List[ParallelExecutionResult] = []
        successful = 0
        failed = 0

        for config, result in zip(sorted_configs, results):
            if isinstance(result, Exception):
                execution_results.append(
                    ParallelExecutionResult(
                        agent_name=config.agent_name,
                        success=False,
                        output="",
                        error=str(result),
                    )
                )
                failed += 1
            elif isinstance(result, ParallelExecutionResult):
                execution_results.append(result)
                if result.success:
                    successful += 1
                else:
                    failed += 1
            else:
                # Assume raw output
                execution_results.append(
                    ParallelExecutionResult(
                        agent_name=config.agent_name,
                        success=True,
                        output=str(result),
                    )
                )
                successful += 1

        total_duration = time.time() - start_time

        logger.info(
            "parallel_execution_complete",
            pattern=pattern.name,
            successful=successful,
            failed=failed,
            duration=total_duration,
        )

        return ParallelBatchResult(
            pattern_name=pattern.name,
            total_agents=len(configs),
            successful=successful,
            failed=failed,
            results=execution_results,
            total_duration_seconds=total_duration,
        )

    async def _execute_with_semaphore(
        self,
        config: ParallelAgentConfig,
        executor: Callable[[ParallelAgentConfig, Dict[str, Any]], Any],
        context: Dict[str, Any],
        unified_context: bool,
    ) -> ParallelExecutionResult:
        """Execute a single agent with semaphore control."""
        import time
        start_time = time.time()

        # Apply semaphore if configured
        if self._semaphore:
            async with self._semaphore:
                return await self._execute_single(
                    config, executor, context, unified_context, start_time
                )
        else:
            return await self._execute_single(
                config, executor, context, unified_context, start_time
            )

    async def _execute_single(
        self,
        config: ParallelAgentConfig,
        executor: Callable[[ParallelAgentConfig, Dict[str, Any]], Any],
        context: Dict[str, Any],
        unified_context: bool,
        start_time: float,
    ) -> ParallelExecutionResult:
        """Execute a single agent with retry logic."""
        import time

        timeout = config.timeout or self._default_timeout
        attempts = 0
        last_error: Optional[str] = None

        while attempts <= self._max_retries:
            try:
                # Prepare context for this agent
                agent_context = context.copy() if unified_context else {}
                agent_context["agent_name"] = config.agent_name

                # Execute with timeout
                result = await asyncio.wait_for(
                    executor(config, agent_context),
                    timeout=timeout,
                )

                duration = time.time() - start_time

                # Handle different result types
                if hasattr(result, "success"):
                    return ParallelExecutionResult(
                        agent_name=config.agent_name,
                        success=result.success,
                        output=getattr(result, "output", str(result)),
                        error=getattr(result, "error", None),
                        duration_seconds=duration,
                        metadata=getattr(result, "metadata", {}),
                    )
                else:
                    return ParallelExecutionResult(
                        agent_name=config.agent_name,
                        success=True,
                        output=str(result),
                        duration_seconds=duration,
                    )

            except asyncio.TimeoutError:
                last_error = f"Timeout after {timeout}s"
                logger.warning(
                    "agent_timeout",
                    agent=config.agent_name,
                    timeout=timeout,
                    attempt=attempts,
                )

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "agent_execution_error",
                    agent=config.agent_name,
                    error=str(e),
                    attempt=attempts,
                )

            attempts += 1
            if attempts <= self._max_retries and self._retry_on_failure:
                await asyncio.sleep(1.0)  # Brief delay before retry

        duration = time.time() - start_time
        return ParallelExecutionResult(
            agent_name=config.agent_name,
            success=False,
            output="",
            error=last_error,
            duration_seconds=duration,
        )


# Pre-defined parallel patterns for common pentest workflows


recon_parallel_pattern = parallel_pattern(
    name="recon_parallel",
    description=(
        "Run all reconnaissance tasks in parallel: port scanning, "
        "subdomain enumeration, and technology fingerprinting"
    ),
    agents=["reconnaissance", "scanner"],
    max_concurrent=3,
)


scan_parallel_pattern = parallel_pattern(
    name="scan_parallel",
    description=(
        "Run vulnerability scanners in parallel: nuclei, nikto, "
        "and custom scanners"
    ),
    agents=["scanner", "api_flow"],
    max_concurrent=2,
)


full_assessment_parallel = parallel_pattern(
    name="full_assessment_parallel",
    description=(
        "Full parallel assessment with recon, scanning, and exploitation "
        "running concurrently where possible"
    ),
    agents=[
        "reconnaissance",
        "scanner",
        "api_flow",
        "business_logic",
    ],
    max_concurrent=4,
)
