"""
Sequential pattern for Inferno.

This module provides the SEQUENTIAL pattern implementation for
executing agents in a defined order, passing results from each
step to the next.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from inferno.patterns.pattern import Pattern, PatternType, sequential_pattern

if TYPE_CHECKING:
    from inferno.swarm.message_bus import MessageBus

logger = structlog.get_logger(__name__)


@dataclass
class SequenceStep:
    """A step in a sequential execution."""

    step_number: int
    agent: Any
    agent_name: str
    wait_for_previous: bool = True
    timeout: float | None = None
    retry_on_failure: bool = False
    max_retries: int = 1
    condition: Callable[..., bool] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class StepResult:
    """Result from executing a single step."""

    step_number: int
    agent_name: str
    success: bool
    output: Any
    error: str | None = None
    duration_seconds: float = 0.0
    skipped: bool = False
    skip_reason: str | None = None


@dataclass
class SequentialExecutionContext:
    """Context passed between sequential steps."""

    target: str | None = None
    operation_id: str | None = None
    current_step: int = 0
    total_steps: int = 0
    previous_results: list[StepResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    accumulated_context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def get_previous_result(self) -> StepResult | None:
        """Get the most recent step result."""
        if self.previous_results:
            return self.previous_results[-1]
        return None

    def get_previous_output(self) -> Any:
        """Get the output from the previous step."""
        result = self.get_previous_result()
        if result and result.success:
            return result.output
        return None

    def add_to_context(self, key: str, value: Any) -> None:
        """Add data to accumulated context."""
        self.accumulated_context[key] = value

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a security finding."""
        finding["step"] = self.current_step
        self.findings.append(finding)


@dataclass
class SequentialExecutionResult:
    """Result from sequential pattern execution."""

    pattern_name: str
    total_steps: int
    completed_steps: int
    failed_steps: int
    skipped_steps: int
    step_results: list[StepResult] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    final_output: Any = None
    success: bool = True
    error: str | None = None
    duration_seconds: float = 0.0

    @property
    def completion_rate(self) -> float:
        """Calculate completion rate as percentage."""
        if self.total_steps == 0:
            return 0.0
        return (self.completed_steps / self.total_steps) * 100

    def get_step_result(self, step_number: int) -> StepResult | None:
        """Get result for a specific step."""
        for result in self.step_results:
            if result.step_number == step_number:
                return result
        return None


class SequentialExecutor:
    """
    Executor for sequential patterns.

    Manages ordered execution of agents, passing context and
    results between steps.
    """

    def __init__(
        self,
        default_timeout: float = 300.0,
        stop_on_failure: bool = True,
        retry_failed_steps: bool = False,
        message_bus: MessageBus | None = None,
    ) -> None:
        """
        Initialize the sequential executor.

        Args:
            default_timeout: Default timeout per step in seconds.
            stop_on_failure: Whether to stop sequence on failure.
            retry_failed_steps: Whether to retry failed steps.
            message_bus: Optional message bus for communication.
        """
        self._default_timeout = default_timeout
        self._stop_on_failure = stop_on_failure
        self._retry_failed_steps = retry_failed_steps
        self._message_bus = message_bus

    async def execute_pattern(
        self,
        pattern: Pattern,
        agent_executor: Callable[[Any, SequentialExecutionContext], Any],
        initial_context: dict[str, Any] | None = None,
        target: str | None = None,
        operation_id: str | None = None,
    ) -> SequentialExecutionResult:
        """
        Execute a sequential pattern.

        Args:
            pattern: The sequential pattern to execute.
            agent_executor: Async callable that executes a single agent.
            initial_context: Initial context data.
            target: Target URL/host.
            operation_id: Operation ID for memory sharing.

        Returns:
            SequentialExecutionResult with execution details.

        Raises:
            ValueError: If pattern is not SEQUENTIAL type.
        """
        if pattern.type != PatternType.SEQUENTIAL:
            raise ValueError(
                f"SequentialExecutor only handles SEQUENTIAL patterns, "
                f"got {pattern.type.value}"
            )

        import time
        start_time = time.time()

        # Build sequence steps
        steps = self._build_steps(pattern)

        # Initialize context
        context = SequentialExecutionContext(
            target=target,
            operation_id=operation_id,
            total_steps=len(steps),
            accumulated_context=initial_context or {},
        )

        logger.info(
            "starting_sequential_execution",
            pattern=pattern.name,
            total_steps=len(steps),
        )

        step_results: list[StepResult] = []
        completed = 0
        failed = 0
        skipped = 0
        final_output = None

        for step in steps:
            context.current_step = step.step_number

            # Check condition if present
            if step.condition and not step.condition(context):
                logger.debug(
                    "step_skipped_condition",
                    step=step.step_number,
                    agent=step.agent_name,
                )
                result = StepResult(
                    step_number=step.step_number,
                    agent_name=step.agent_name,
                    success=True,
                    output=None,
                    skipped=True,
                    skip_reason="Condition not met",
                )
                step_results.append(result)
                context.previous_results.append(result)
                skipped += 1
                continue

            # Wait for previous if required
            if step.wait_for_previous and context.previous_results:
                prev = context.get_previous_result()
                if prev and not prev.success and self._stop_on_failure:
                    logger.warning(
                        "stopping_sequence_previous_failed",
                        step=step.step_number,
                        previous_step=prev.step_number,
                    )
                    break

            # Execute step
            result = await self._execute_step(
                step,
                agent_executor,
                context,
            )

            step_results.append(result)
            context.previous_results.append(result)

            if result.success:
                completed += 1
                final_output = result.output
            else:
                failed += 1
                if self._stop_on_failure:
                    logger.warning(
                        "stopping_sequence_step_failed",
                        step=step.step_number,
                        agent=step.agent_name,
                        error=result.error,
                    )
                    break

        duration = time.time() - start_time

        logger.info(
            "sequential_execution_complete",
            pattern=pattern.name,
            completed=completed,
            failed=failed,
            skipped=skipped,
            duration=duration,
        )

        return SequentialExecutionResult(
            pattern_name=pattern.name,
            total_steps=len(steps),
            completed_steps=completed,
            failed_steps=failed,
            skipped_steps=skipped,
            step_results=step_results,
            findings=context.findings,
            final_output=final_output,
            success=failed == 0,
            duration_seconds=duration,
        )

    def _build_steps(self, pattern: Pattern) -> list[SequenceStep]:
        """Build sequence steps from pattern."""
        steps: list[SequenceStep] = []

        for i, seq_item in enumerate(pattern.sequence):
            agent = seq_item.get("agent") if isinstance(seq_item, dict) else seq_item
            wait = seq_item.get("wait_for_previous", True) if isinstance(seq_item, dict) else True

            agent_name = getattr(agent, "name", str(agent))

            step = SequenceStep(
                step_number=i + 1,
                agent=agent,
                agent_name=agent_name,
                wait_for_previous=wait,
            )
            steps.append(step)

        return steps

    async def _execute_step(
        self,
        step: SequenceStep,
        executor: Callable[[Any, SequentialExecutionContext], Any],
        context: SequentialExecutionContext,
    ) -> StepResult:
        """Execute a single sequence step."""
        import time
        start_time = time.time()

        timeout = step.timeout or self._default_timeout
        attempts = 0
        max_attempts = step.max_retries + 1 if step.retry_on_failure else 1
        last_error: str | None = None

        logger.debug(
            "executing_step",
            step=step.step_number,
            agent=step.agent_name,
        )

        while attempts < max_attempts:
            try:
                result = await asyncio.wait_for(
                    executor(step.agent, context),
                    timeout=timeout,
                )

                duration = time.time() - start_time

                # Handle different result types
                if hasattr(result, "success"):
                    return StepResult(
                        step_number=step.step_number,
                        agent_name=step.agent_name,
                        success=result.success,
                        output=getattr(result, "output", result),
                        error=getattr(result, "error", None),
                        duration_seconds=duration,
                    )
                else:
                    return StepResult(
                        step_number=step.step_number,
                        agent_name=step.agent_name,
                        success=True,
                        output=result,
                        duration_seconds=duration,
                    )

            except TimeoutError:
                last_error = f"Timeout after {timeout}s"
                logger.warning(
                    "step_timeout",
                    step=step.step_number,
                    agent=step.agent_name,
                    timeout=timeout,
                )

            except Exception as e:
                last_error = str(e)
                logger.warning(
                    "step_execution_error",
                    step=step.step_number,
                    agent=step.agent_name,
                    error=str(e),
                )

            attempts += 1
            if attempts < max_attempts:
                await asyncio.sleep(1.0)

        duration = time.time() - start_time
        return StepResult(
            step_number=step.step_number,
            agent_name=step.agent_name,
            success=False,
            output=None,
            error=last_error,
            duration_seconds=duration,
        )


# Pre-defined sequential patterns for pentest workflows


standard_pentest_sequence = sequential_pattern(
    name="standard_pentest_sequence",
    steps=[
        {"agent": "reconnaissance", "wait_for_previous": False},
        {"agent": "scanner", "wait_for_previous": True},
        {"agent": "exploiter", "wait_for_previous": True},
        {"agent": "validator", "wait_for_previous": True},
        {"agent": "reporter", "wait_for_previous": True},
    ],
    description=(
        "Standard penetration test workflow: "
        "recon -> scan -> exploit -> validate -> report"
    ),
)


web_assessment_sequence = sequential_pattern(
    name="web_assessment_sequence",
    steps=[
        {"agent": "reconnaissance", "wait_for_previous": False},
        {"agent": "api_flow", "wait_for_previous": True},
        {"agent": "scanner", "wait_for_previous": True},
        {"agent": "business_logic", "wait_for_previous": True},
        {"agent": "exploiter", "wait_for_previous": True},
        {"agent": "reporter", "wait_for_previous": True},
    ],
    description=(
        "Web application security assessment sequence with "
        "API and business logic testing"
    ),
)


iot_assessment_sequence = sequential_pattern(
    name="iot_assessment_sequence",
    steps=[
        {"agent": "iot_scanner", "wait_for_previous": False},
        {"agent": "firmware_analyst", "wait_for_previous": True},
        {"agent": "reverse_engineer", "wait_for_previous": True},
        {"agent": "memory_forensics", "wait_for_previous": True},
        {"agent": "reporter", "wait_for_previous": True},
    ],
    description=(
        "IoT device security assessment: "
        "scan -> firmware -> RE -> forensics -> report"
    ),
)
