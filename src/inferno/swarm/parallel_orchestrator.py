"""
Parallel Swarm Orchestrator - Supercharged worker parallelization.

This module implements Claude Code-style parallel agent execution for Inferno.
Instead of running workers sequentially, it spawns them truly in parallel
with intelligent task decomposition and result aggregation.

Key Features:
- True parallel execution with asyncio.gather
- Intelligent task decomposition into parallelizable subtasks
- Smart worker pooling and reuse
- Real-time result streaming as workers complete
- Dependency-aware task scheduling
- Automatic load balancing across worker types

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │              ParallelSwarmOrchestrator                  │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │           Task Decomposition Engine              │   │
    │  │  (breaks large tasks into parallel subtasks)     │   │
    │  └─────────────────────────────────────────────────┘   │
    │                         ▼                               │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │           Dependency Analyzer                    │   │
    │  │  (determines what can run in parallel)           │   │
    │  └─────────────────────────────────────────────────┘   │
    │                         ▼                               │
    │  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐     │
    │  │Worker│  │Worker│  │Worker│  │Worker│  │Worker│     │
    │  │  1   │  │  2   │  │  3   │  │  4   │  │  N   │     │
    │  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘     │
    │     └─────────┴─────────┴─────────┴─────────┘          │
    │                         ▼                               │
    │  ┌─────────────────────────────────────────────────┐   │
    │  │           Result Aggregator                      │   │
    │  │  (combines results as workers complete)          │   │
    │  └─────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import structlog

from inferno.swarm.agents import SubAgentType
from inferno.swarm.message_bus import get_message_bus

logger = structlog.get_logger(__name__)


class TaskPriority(int, Enum):
    """Task priority levels for scheduling."""
    CRITICAL = 100  # Run immediately, block others if needed
    HIGH = 75       # Run ASAP
    NORMAL = 50     # Standard priority
    LOW = 25        # Background task
    IDLE = 0        # Run when nothing else is happening


class TaskDependency(str, Enum):
    """Dependency types between tasks."""
    NONE = "none"           # Can run anytime
    REQUIRES_RECON = "requires_recon"  # Needs recon results first
    REQUIRES_SCAN = "requires_scan"    # Needs scan results first
    REQUIRES_EXPLOIT = "requires_exploit"  # Needs exploit results first


@dataclass
class ParallelTask:
    """A task that can be executed by a worker in the parallel swarm."""

    task_id: str
    worker_type: SubAgentType
    description: str
    context: dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    dependency: TaskDependency = TaskDependency.NONE
    max_turns: int = 25

    # Execution tracking
    status: str = "pending"  # pending, running, completed, failed
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: str = ""
    error: str | None = None
    findings: list[dict] = field(default_factory=list)

    # Parallel execution metadata
    can_parallelize: bool = True
    estimated_duration_seconds: int = 60
    actual_duration_seconds: float = 0.0


@dataclass
class SwarmExecutionResult:
    """Result of a parallel swarm execution."""

    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    total_findings: int
    execution_time_seconds: float
    parallelism_achieved: float  # Actual parallel execution ratio
    task_results: list[ParallelTask] = field(default_factory=list)
    aggregated_output: str = ""

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_tasks == 0:
            return 0.0
        return self.completed_tasks / self.total_tasks


class ParallelSwarmOrchestrator:
    """
    Supercharged swarm orchestrator with true parallel execution.

    This is the core engine that makes Inferno's swarm work like Claude Code's
    sub-agent spawning - multiple workers running truly in parallel with
    intelligent coordination.

    Usage:
        orchestrator = ParallelSwarmOrchestrator(
            target="https://example.com",
            operation_id="op_001",
            max_parallel_workers=8,
        )

        # Add tasks
        orchestrator.add_task(ParallelTask(
            task_id="recon_1",
            worker_type=SubAgentType.RECONNAISSANCE,
            description="Enumerate subdomains",
        ))
        orchestrator.add_task(ParallelTask(
            task_id="scan_ports",
            worker_type=SubAgentType.SCANNER,
            description="Port scan main domain",
        ))

        # Execute all tasks in parallel
        result = await orchestrator.execute_parallel()
    """

    def __init__(
        self,
        target: str,
        operation_id: str,
        objective: str = "",
        max_parallel_workers: int = 8,
        model: str = "claude-sonnet-4-20250514",
        on_task_complete: Callable[[ParallelTask], None] | None = None,
        on_finding: Callable[[dict], None] | None = None,
    ) -> None:
        """
        Initialize the parallel swarm orchestrator.

        Args:
            target: Target URL/IP
            operation_id: Operation ID for memory sharing
            objective: Overall assessment objective
            max_parallel_workers: Maximum concurrent workers
            model: Model to use for workers
            on_task_complete: Callback when task completes
            on_finding: Callback when finding is discovered
        """
        self._target = target
        self._operation_id = operation_id
        self._objective = objective
        self._max_parallel = max_parallel_workers
        self._model = model
        self._on_task_complete = on_task_complete
        self._on_finding = on_finding

        # Task management
        self._pending_tasks: list[ParallelTask] = []
        self._running_tasks: dict[str, ParallelTask] = {}
        self._completed_tasks: list[ParallelTask] = []

        # Shared context across all workers
        self._shared_context: dict[str, Any] = {
            "target": target,
            "operation_id": operation_id,
            "objective": objective,
            "discovered_endpoints": [],
            "discovered_technologies": [],
            "findings": [],
            "waf_detected": None,
        }

        # Message bus for inter-worker communication
        self._message_bus = get_message_bus()

        # Execution metrics
        self._start_time: datetime | None = None
        self._end_time: datetime | None = None

        logger.info(
            "parallel_orchestrator_initialized",
            target=target,
            operation_id=operation_id,
            max_parallel=max_parallel_workers,
        )

    def add_task(self, task: ParallelTask) -> None:
        """Add a task to the execution queue."""
        self._pending_tasks.append(task)
        logger.debug(
            "task_added",
            task_id=task.task_id,
            worker_type=task.worker_type.value,
            priority=task.priority.value,
        )

    def add_tasks(self, tasks: list[ParallelTask]) -> None:
        """Add multiple tasks at once."""
        for task in tasks:
            self.add_task(task)

    def decompose_task(
        self,
        description: str,
        target: str,
    ) -> list[ParallelTask]:
        """
        Intelligently decompose a high-level task into parallelizable subtasks.

        This is the "Claude Code magic" - taking a complex task and breaking it
        into components that can run simultaneously.

        Args:
            description: High-level task description
            target: Target for the task

        Returns:
            List of parallel tasks that can be executed concurrently
        """
        tasks = []
        task_counter = 0

        description_lower = description.lower()

        # Decomposition patterns
        if "full assessment" in description_lower or "pentest" in description_lower:
            # Full assessment - decompose into all phases
            tasks.extend(self._decompose_full_assessment(target))

        elif "reconnaissance" in description_lower or "recon" in description_lower:
            # Recon - split into parallel discovery tasks
            tasks.extend(self._decompose_recon(target))

        elif "scan" in description_lower or "vulnerability" in description_lower:
            # Scanning - split by vulnerability category
            tasks.extend(self._decompose_scanning(target))

        elif "exploit" in description_lower:
            # Exploitation - split by attack vector
            tasks.extend(self._decompose_exploitation(target))

        else:
            # Single task - create one worker
            task_counter += 1
            tasks.append(ParallelTask(
                task_id=f"task_{task_counter}",
                worker_type=self._infer_worker_type(description),
                description=description,
                context={"target": target},
            ))

        logger.info(
            "task_decomposed",
            original_description=description[:100],
            subtasks_created=len(tasks),
        )

        return tasks

    def _decompose_full_assessment(self, target: str) -> list[ParallelTask]:
        """Decompose a full assessment into parallel phases."""
        return [
            # Phase 1: Parallel Reconnaissance (all can run simultaneously)
            ParallelTask(
                task_id="recon_subdomains",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"Enumerate all subdomains of {target}",
                priority=TaskPriority.HIGH,
                dependency=TaskDependency.NONE,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="recon_ports",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"Scan open ports and services on {target}",
                priority=TaskPriority.HIGH,
                dependency=TaskDependency.NONE,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="recon_tech",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"Fingerprint technologies on {target}",
                priority=TaskPriority.HIGH,
                dependency=TaskDependency.NONE,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="recon_dirs",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"Discover hidden directories and endpoints on {target}",
                priority=TaskPriority.HIGH,
                dependency=TaskDependency.NONE,
                can_parallelize=True,
            ),

            # Phase 2: Parallel Scanning (can start after some recon)
            ParallelTask(
                task_id="scan_sqli",
                worker_type=SubAgentType.SCANNER,
                description=f"Test all endpoints for SQL injection on {target}",
                priority=TaskPriority.NORMAL,
                dependency=TaskDependency.REQUIRES_RECON,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="scan_xss",
                worker_type=SubAgentType.SCANNER,
                description=f"Test all endpoints for XSS vulnerabilities on {target}",
                priority=TaskPriority.NORMAL,
                dependency=TaskDependency.REQUIRES_RECON,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="scan_auth",
                worker_type=SubAgentType.SCANNER,
                description=f"Test authentication and authorization on {target}",
                priority=TaskPriority.NORMAL,
                dependency=TaskDependency.REQUIRES_RECON,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="scan_ssrf",
                worker_type=SubAgentType.SCANNER,
                description=f"Test for SSRF and internal access on {target}",
                priority=TaskPriority.NORMAL,
                dependency=TaskDependency.REQUIRES_RECON,
                can_parallelize=True,
            ),
        ]

    def _decompose_recon(self, target: str) -> list[ParallelTask]:
        """Decompose reconnaissance into parallel discovery tasks."""
        return [
            ParallelTask(
                task_id="recon_dns",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"DNS enumeration and subdomain discovery for {target}",
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="recon_ports",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"Port scanning and service detection on {target}",
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="recon_web",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"Web application discovery and fingerprinting on {target}",
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="recon_osint",
                worker_type=SubAgentType.RECONNAISSANCE,
                description=f"OSINT gathering for {target}",
                can_parallelize=True,
            ),
        ]

    def _decompose_scanning(self, target: str) -> list[ParallelTask]:
        """Decompose scanning into parallel vulnerability tests."""
        return [
            ParallelTask(
                task_id="scan_injection",
                worker_type=SubAgentType.SCANNER,
                description=f"Test for injection vulnerabilities (SQLi, NoSQLi, LDAP) on {target}",
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="scan_xss",
                worker_type=SubAgentType.SCANNER,
                description=f"Test for XSS (reflected, stored, DOM) on {target}",
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="scan_access",
                worker_type=SubAgentType.SCANNER,
                description=f"Test for broken access control (IDOR, privilege escalation) on {target}",
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="scan_config",
                worker_type=SubAgentType.SCANNER,
                description=f"Test for security misconfigurations on {target}",
                can_parallelize=True,
            ),
        ]

    def _decompose_exploitation(self, target: str) -> list[ParallelTask]:
        """Decompose exploitation into parallel attack vectors."""
        return [
            ParallelTask(
                task_id="exploit_confirmed",
                worker_type=SubAgentType.EXPLOITER,
                description=f"Exploit confirmed vulnerabilities on {target}",
                priority=TaskPriority.HIGH,
                can_parallelize=True,
            ),
            ParallelTask(
                task_id="exploit_bypass",
                worker_type=SubAgentType.WAF_BYPASS,
                description=f"Attempt WAF/filter bypasses on {target}",
                can_parallelize=True,
            ),
        ]

    def _infer_worker_type(self, description: str) -> SubAgentType:
        """Infer the best worker type from task description."""
        desc_lower = description.lower()

        if any(w in desc_lower for w in ["recon", "enumerate", "discover", "scan port", "fingerprint"]):
            return SubAgentType.RECONNAISSANCE
        elif any(w in desc_lower for w in ["scan", "test for", "check for", "vulnerability"]):
            return SubAgentType.SCANNER
        elif any(w in desc_lower for w in ["exploit", "extract", "dump", "shell", "access"]):
            return SubAgentType.EXPLOITER
        elif any(w in desc_lower for w in ["bypass", "waf", "filter", "evade"]):
            return SubAgentType.WAF_BYPASS
        elif any(w in desc_lower for w in ["validate", "verify", "confirm"]):
            return SubAgentType.VALIDATOR
        elif any(w in desc_lower for w in ["report", "document", "summary"]):
            return SubAgentType.REPORTER
        else:
            return SubAgentType.SCANNER  # Default to scanner

    async def execute_parallel(self) -> SwarmExecutionResult:
        """
        Execute all pending tasks in parallel.

        This is the main entry point that runs workers simultaneously
        like Claude Code's sub-agent spawning.

        Returns:
            SwarmExecutionResult with all findings and metrics
        """
        self._start_time = datetime.now(UTC)

        # Sort tasks by priority and dependencies
        self._pending_tasks.sort(
            key=lambda t: (t.dependency.value, -t.priority.value)
        )

        logger.info(
            "parallel_execution_starting",
            total_tasks=len(self._pending_tasks),
            max_parallel=self._max_parallel,
        )

        # Group tasks by dependency level
        no_deps = [t for t in self._pending_tasks if t.dependency == TaskDependency.NONE]
        recon_deps = [t for t in self._pending_tasks if t.dependency == TaskDependency.REQUIRES_RECON]
        scan_deps = [t for t in self._pending_tasks if t.dependency == TaskDependency.REQUIRES_SCAN]
        exploit_deps = [t for t in self._pending_tasks if t.dependency == TaskDependency.REQUIRES_EXPLOIT]

        # Execute in waves (parallel within each wave)
        if no_deps:
            await self._execute_wave(no_deps, "Wave 1: No Dependencies")

        if recon_deps:
            await self._execute_wave(recon_deps, "Wave 2: Post-Recon")

        if scan_deps:
            await self._execute_wave(scan_deps, "Wave 3: Post-Scan")

        if exploit_deps:
            await self._execute_wave(exploit_deps, "Wave 4: Post-Exploit")

        self._end_time = datetime.now(UTC)

        # Calculate metrics
        execution_time = (self._end_time - self._start_time).total_seconds()
        total_findings = sum(len(t.findings) for t in self._completed_tasks)

        # Calculate parallelism achieved
        total_task_time = sum(t.actual_duration_seconds for t in self._completed_tasks)
        parallelism = total_task_time / execution_time if execution_time > 0 else 1.0

        result = SwarmExecutionResult(
            total_tasks=len(self._completed_tasks),
            completed_tasks=len([t for t in self._completed_tasks if t.status == "completed"]),
            failed_tasks=len([t for t in self._completed_tasks if t.status == "failed"]),
            total_findings=total_findings,
            execution_time_seconds=execution_time,
            parallelism_achieved=parallelism,
            task_results=self._completed_tasks,
            aggregated_output=self._aggregate_results(),
        )

        logger.info(
            "parallel_execution_complete",
            total_tasks=result.total_tasks,
            completed=result.completed_tasks,
            failed=result.failed_tasks,
            findings=result.total_findings,
            execution_time=f"{execution_time:.1f}s",
            parallelism=f"{parallelism:.2f}x",
        )

        return result

    async def _execute_wave(self, tasks: list[ParallelTask], wave_name: str) -> None:
        """Execute a wave of tasks in parallel."""
        logger.info(
            "wave_starting",
            wave=wave_name,
            tasks=len(tasks),
        )

        # Create semaphore for max parallelism
        semaphore = asyncio.Semaphore(self._max_parallel)

        async def run_task(task: ParallelTask) -> None:
            async with semaphore:
                await self._execute_single_task(task)

        # Execute all tasks in this wave in parallel
        await asyncio.gather(*[run_task(t) for t in tasks], return_exceptions=True)

        logger.info(
            "wave_complete",
            wave=wave_name,
            completed=len([t for t in tasks if t.status == "completed"]),
        )

    async def _execute_single_task(self, task: ParallelTask) -> None:
        """Execute a single task using SwarmTool."""
        from inferno.swarm.tool import SwarmTool

        task.status = "running"
        task.started_at = datetime.now(UTC)
        self._running_tasks[task.task_id] = task

        logger.info(
            "task_starting",
            task_id=task.task_id,
            worker_type=task.worker_type.value,
        )

        # Build context with shared intelligence
        context_str = self._build_task_context(task)

        try:
            # Create SwarmTool instance
            swarm_tool = SwarmTool(
                model=self._model,
                operation_id=self._operation_id,
                target=self._target,
            )

            # Execute the worker
            result = await swarm_tool.execute(
                agent_type=task.worker_type.value,
                task=task.description,
                context=context_str,
                max_turns=task.max_turns,
            )

            task.completed_at = datetime.now(UTC)
            task.actual_duration_seconds = (task.completed_at - task.started_at).total_seconds()
            task.result = result.output
            task.status = "completed" if result.success else "failed"

            if not result.success:
                task.error = result.error

            # Extract findings from result
            task.findings = self._extract_findings(result.output)

            # Update shared context
            self._update_shared_context(task)

            # Fire callback
            if self._on_task_complete:
                self._on_task_complete(task)

            for finding in task.findings:
                if self._on_finding:
                    self._on_finding(finding)

            logger.info(
                "task_complete",
                task_id=task.task_id,
                status=task.status,
                duration=f"{task.actual_duration_seconds:.1f}s",
                findings=len(task.findings),
            )

        except Exception as e:
            task.completed_at = datetime.now(UTC)
            task.actual_duration_seconds = (task.completed_at - task.started_at).total_seconds()
            task.status = "failed"
            task.error = str(e)
            logger.error(
                "task_failed",
                task_id=task.task_id,
                error=str(e),
            )

        finally:
            # Move to completed
            if task.task_id in self._running_tasks:
                del self._running_tasks[task.task_id]
            self._completed_tasks.append(task)

    def _build_task_context(self, task: ParallelTask) -> str:
        """Build comprehensive context for a task."""
        parts = [
            f"Target: {self._target}",
            f"Objective: {self._objective}",
            "",
            "=== SHARED INTELLIGENCE ===",
            f"Discovered endpoints: {len(self._shared_context.get('discovered_endpoints', []))}",
        ]

        endpoints = self._shared_context.get('discovered_endpoints', [])[:20]
        if endpoints:
            parts.append("\n".join(endpoints))

        parts.extend([
            "",
            f"Technologies: {', '.join(self._shared_context.get('discovered_technologies', [])[:10])}",
            f"WAF: {self._shared_context.get('waf_detected', 'Unknown')}",
            "",
            "Previous findings:",
        ])

        for f in self._shared_context.get('findings', [])[:10]:
            parts.append(f"- {f.get('title', 'Unknown')}: {f.get('vuln_type', 'unknown')}")

        parts.extend([
            "",
            "=== TASK-SPECIFIC CONTEXT ===",
            str(task.context),
            "",
            "IMPORTANT: Share your discoveries via memory tool for other workers.",
        ])

        return "\n".join(parts)

    def _extract_findings(self, output: str) -> list[dict]:
        """Extract findings from worker output."""
        findings = []
        output_lower = output.lower()

        # Simple keyword-based extraction
        vuln_keywords = [
            ("sql injection", "sqli"),
            ("xss", "xss"),
            ("cross-site scripting", "xss"),
            ("ssrf", "ssrf"),
            ("idor", "idor"),
            ("authentication bypass", "auth_bypass"),
            ("rce", "rce"),
            ("remote code execution", "rce"),
            ("file inclusion", "lfi"),
            ("path traversal", "path_traversal"),
            ("cors", "cors"),
            ("csrf", "csrf"),
        ]

        for keyword, vuln_type in vuln_keywords:
            if keyword in output_lower and ("found" in output_lower or "discovered" in output_lower or "vulnerable" in output_lower):
                findings.append({
                    "vuln_type": vuln_type,
                    "title": f"{vuln_type.upper()} vulnerability detected",
                    "evidence": output[:500],
                })

        return findings

    def _update_shared_context(self, task: ParallelTask) -> None:
        """Update shared context with task results."""
        # Extract endpoints from result
        if "endpoint" in task.result.lower() or "url" in task.result.lower():
            # Simple URL extraction
            import re
            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', task.result)
            for url in urls[:50]:
                if url not in self._shared_context['discovered_endpoints']:
                    self._shared_context['discovered_endpoints'].append(url)

        # Add findings
        self._shared_context['findings'].extend(task.findings)

        # Detect WAF
        if "waf" in task.result.lower() or "firewall" in task.result.lower():
            if "cloudflare" in task.result.lower():
                self._shared_context['waf_detected'] = "Cloudflare"
            elif "akamai" in task.result.lower():
                self._shared_context['waf_detected'] = "Akamai"
            elif "modsecurity" in task.result.lower():
                self._shared_context['waf_detected'] = "ModSecurity"
            else:
                self._shared_context['waf_detected'] = "Yes (unknown type)"

    def _aggregate_results(self) -> str:
        """Aggregate all results into a summary."""
        parts = [
            "=" * 60,
            "PARALLEL SWARM EXECUTION SUMMARY",
            "=" * 60,
            "",
            f"Target: {self._target}",
            f"Total Tasks: {len(self._completed_tasks)}",
            f"Successful: {len([t for t in self._completed_tasks if t.status == 'completed'])}",
            f"Failed: {len([t for t in self._completed_tasks if t.status == 'failed'])}",
            "",
            "-" * 60,
            "FINDINGS",
            "-" * 60,
        ]

        all_findings = []
        for task in self._completed_tasks:
            all_findings.extend(task.findings)

        if all_findings:
            for i, finding in enumerate(all_findings, 1):
                parts.append(f"{i}. [{finding.get('vuln_type', 'unknown').upper()}] {finding.get('title', 'Unknown')}")
        else:
            parts.append("No findings discovered.")

        parts.extend([
            "",
            "-" * 60,
            "TASK DETAILS",
            "-" * 60,
        ])

        for task in self._completed_tasks:
            status_icon = "✓" if task.status == "completed" else "✗"
            parts.append(f"{status_icon} [{task.worker_type.value}] {task.description[:50]}...")
            parts.append(f"  Duration: {task.actual_duration_seconds:.1f}s, Findings: {len(task.findings)}")

        parts.append("=" * 60)

        return "\n".join(parts)

    @property
    def shared_context(self) -> dict[str, Any]:
        """Get the shared context dictionary."""
        return self._shared_context

    @property
    def pending_count(self) -> int:
        """Number of pending tasks."""
        return len(self._pending_tasks)

    @property
    def running_count(self) -> int:
        """Number of running tasks."""
        return len(self._running_tasks)

    @property
    def completed_count(self) -> int:
        """Number of completed tasks."""
        return len(self._completed_tasks)


# =============================================================================
# Convenience Functions
# =============================================================================

async def run_parallel_swarm(
    target: str,
    operation_id: str,
    task_description: str,
    max_parallel: int = 8,
    model: str = "claude-sonnet-4-20250514",
) -> SwarmExecutionResult:
    """
    Quick function to run a parallel swarm on a target.

    This automatically decomposes the task and runs workers in parallel.

    Args:
        target: Target URL/IP
        operation_id: Operation ID
        task_description: What to do (will be decomposed)
        max_parallel: Max parallel workers
        model: Model to use

    Returns:
        SwarmExecutionResult with all findings

    Example:
        result = await run_parallel_swarm(
            target="https://example.com",
            operation_id="op_001",
            task_description="Perform full security assessment",
        )
        print(f"Found {result.total_findings} vulnerabilities")
    """
    orchestrator = ParallelSwarmOrchestrator(
        target=target,
        operation_id=operation_id,
        max_parallel_workers=max_parallel,
        model=model,
    )

    # Decompose the task
    tasks = orchestrator.decompose_task(task_description, target)
    orchestrator.add_tasks(tasks)

    # Execute in parallel
    return await orchestrator.execute_parallel()
