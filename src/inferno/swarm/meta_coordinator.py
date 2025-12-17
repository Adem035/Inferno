"""
MetaCoordinator - Coordinator-only agent for subagent orchestration.

This module implements the new architecture where the meta agent
ONLY coordinates and validates - all actual work is done by subagents.

Philosophy:
- MetaCoordinator NEVER executes commands directly
- All reconnaissance, exploitation, and reporting is done by worker subagents
- MetaCoordinator plans, spawns, validates, and synthesizes

Communication:
- Subagents share memory via Mem0/Qdrant (same operation_id)
- Real-time communication via MessageBus
- Findings, endpoints, and attack chains are broadcast to all agents
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

# Performance Assessment Framework - Stanford paper Section 3.2
# S_total = Σ(TC_i + W_i) where TC = DC + EC (exploited) or DC + EC*0.8 (verified)
from inferno.core.assessment_scoring import (
    AssessmentScorer,
)
from inferno.swarm.message_bus import (
    MessageType,
    get_message_bus,
    publish_finding,
)

if TYPE_CHECKING:
    from anthropic import AsyncAnthropic

    from inferno.tools.registry import ToolRegistry

logger = structlog.get_logger(__name__)


# =============================================================================
# Safe async task helpers
# =============================================================================

def _safe_create_task(
    coro,
    *,
    name: str | None = None,
    logger_instance=None,
) -> asyncio.Task:
    """
    Create an asyncio task with proper exception handling.

    Fire-and-forget tasks can silently swallow exceptions if not properly handled.
    This wrapper logs any exceptions that occur in the background task.

    Args:
        coro: The coroutine to run.
        name: Optional task name for logging.
        logger_instance: Logger to use (defaults to module logger).

    Returns:
        The created asyncio.Task.
    """
    log = logger_instance or logger
    task = asyncio.create_task(coro, name=name)

    def _handle_exception(t: asyncio.Task) -> None:
        try:
            exc = t.exception()
            if exc is not None:
                log.error(
                    "background_task_failed",
                    task_name=name or "unnamed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
        except asyncio.CancelledError:
            pass  # Task was cancelled, not an error

    task.add_done_callback(_handle_exception)
    return task


class AssessmentPhase(str, Enum):
    """Phases of a security assessment."""

    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETE = "complete"


class WorkerType(str, Enum):
    """Types of worker subagents."""

    # Web/Network Security
    RECON = "reconnaissance"
    SCANNER = "scanner"
    EXPLOITER = "exploiter"
    POC_GENERATOR = "poc_generator"
    POST_EXPLOIT = "post_exploitation"
    VALIDATOR = "validator"
    REPORTER = "reporter"

    # IoT/Hardware Security
    IOT_SCANNER = "iot_scanner"
    FIRMWARE_ANALYST = "firmware_analyst"
    MEMORY_FORENSICS = "memory_forensics"
    RADIO_ANALYST = "radio_analyst"
    REVERSE_ENGINEER = "reverse_engineer"


class TargetType(str, Enum):
    """Types of assessment targets - auto-detected."""

    WEB = "web"           # URLs, web applications
    NETWORK = "network"   # IP ranges, internal networks
    IOT = "iot"           # IoT devices, embedded systems
    FIRMWARE = "firmware" # Firmware files for analysis
    MEMORY = "memory"     # Memory dumps for forensics
    BINARY = "binary"     # Binaries for reverse engineering


class FindingStatus(str, Enum):
    """Status of a finding through validation."""

    PENDING = "pending"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_INFO = "needs_more_info"


@dataclass
class WorkerTask:
    """Task assigned to a worker subagent."""

    task_id: str
    worker_type: WorkerType
    description: str
    target: str
    context: dict[str, Any] = field(default_factory=dict)
    priority: int = 50  # 0-100, higher = more important
    max_turns: int = 30
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    status: str = "pending"
    result: str | None = None
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


@dataclass
class Finding:
    """A security finding discovered by a worker."""

    finding_id: str
    vuln_type: str
    severity: str  # critical, high, medium, low, informational
    title: str
    description: str
    target: str
    evidence: str
    source_worker: WorkerType
    source_task_id: str
    status: FindingStatus = FindingStatus.PENDING
    confidence: int = 0  # 0-100
    validation_notes: str = ""
    poc: str | None = None
    cvss_score: float | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    validated_at: datetime | None = None

    # Performance Assessment Framework - Stanford paper Section 3.2
    # Technical Complexity (TC) = DC + EC (exploited) or DC + EC*0.8 (verified, 20% penalty)
    # Business Impact Weight (W) = Critical:8, High:5, Medium:3, Low:2, Info:1
    # Total Score (S) = TC + W
    detection_complexity: int = 5  # DC: 1-10 (how hard to detect)
    exploit_complexity: int = 5    # EC: 1-10 (how hard to exploit)
    exploitation_status: str = "suspected"  # exploited, verified, suspected
    technical_complexity_score: float = 0.0  # TC = DC + EC (or DC + EC*0.8)
    business_impact_weight: int = 0  # W based on severity
    total_score: float = 0.0  # S = TC + W


@dataclass
class AssessmentState:
    """Current state of the assessment."""

    phase: AssessmentPhase = AssessmentPhase.PLANNING
    target: str = ""
    objective: str = ""

    # Task management
    pending_tasks: list[WorkerTask] = field(default_factory=list)
    active_tasks: dict[str, WorkerTask] = field(default_factory=dict)  # task_id -> task
    completed_tasks: list[WorkerTask] = field(default_factory=list)

    # Findings management
    findings: list[Finding] = field(default_factory=list)
    validated_findings: list[Finding] = field(default_factory=list)

    # Progress tracking
    turns: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0

    # Intelligence gathered
    discovered_endpoints: list[str] = field(default_factory=list)
    discovered_technologies: list[str] = field(default_factory=list)
    discovered_parameters: list[dict] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)

    # Auto-detected target type
    target_type: TargetType = TargetType.WEB


def detect_target_type(target: str) -> TargetType:
    """
    Auto-detect the type of target for appropriate agent selection.

    Args:
        target: The target string (URL, IP, file path, etc.)

    Returns:
        TargetType enum value
    """
    import re
    from pathlib import Path

    target_lower = target.lower()

    # Check for firmware files
    firmware_extensions = ['.bin', '.fw', '.img', '.rom', '.hex', '.elf', '.srec', '.uf2']
    if any(target_lower.endswith(ext) for ext in firmware_extensions):
        return TargetType.FIRMWARE

    # Check for memory dumps
    memory_extensions = ['.dmp', '.dump', '.mem', '.raw', '.vmem', '.lime']
    if any(target_lower.endswith(ext) for ext in memory_extensions):
        return TargetType.MEMORY

    # Check for binary files
    binary_extensions = ['.exe', '.dll', '.so', '.dylib', '.apk', '.ipa', '.out']
    if any(target_lower.endswith(ext) for ext in binary_extensions):
        return TargetType.BINARY

    # Check if it's a file path that exists
    if Path(target).exists() and Path(target).is_file():
        # Could be firmware, memory, or binary - check magic bytes or default to firmware
        return TargetType.FIRMWARE

    # Check for IP ranges (CIDR notation) - likely network/IoT assessment
    if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', target):
        return TargetType.NETWORK

    # Check for single IP (not URL) - could be IoT device
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        # Single IP often means IoT device or network service
        return TargetType.IOT

    # Check for URLs - web application
    if target_lower.startswith(('http://', 'https://', 'www.')):
        return TargetType.WEB

    # Check for hostname patterns
    if re.match(r'^[\w.-]+\.[a-z]{2,}$', target_lower):
        return TargetType.WEB

    # Default to web for unknown patterns
    return TargetType.WEB


class MetaCoordinator:
    """
    Meta-level coordinator that orchestrates worker subagents.

    The MetaCoordinator follows a strict separation of concerns:
    - It NEVER executes security tools directly
    - All actual work is delegated to specialized worker subagents
    - It focuses on planning, coordination, validation, and synthesis

    Workflow:
    1. PLAN - Analyze target and create assessment plan
    2. SPAWN - Spawn appropriate worker subagents for each phase
    3. COLLECT - Gather results from workers
    4. VALIDATE - Validate all findings using validator subagent
    5. SYNTHESIZE - Combine findings into attack chains
    6. REPORT - Generate final report via reporter subagent
    """

    def __init__(
        self,
        target: str,
        objective: str,
        operation_id: str,
        artifacts_dir: Path | None = None,
        model: str = "claude-opus-4-5-20251101",
        # Legacy params (ignored, kept for backwards compatibility)
        client: AsyncAnthropic | None = None,
        registry: ToolRegistry | None = None,
    ) -> None:
        """
        Initialize the MetaCoordinator.

        Args:
            target: Target URL/IP
            objective: Assessment objective
            operation_id: Unique operation identifier
            artifacts_dir: Directory for artifacts
            model: Model to use for coordination
            client: (DEPRECATED) No longer used - workers use Claude SDK
            registry: (DEPRECATED) No longer used - workers use Claude SDK
        """
        # Note: client and registry are no longer used - workers use ClaudeSDKClient directly
        # which supports OAuth authentication (Claude Code subscription)
        self._model = model
        self._operation_id = operation_id

        # Use proper output directory from settings if not provided
        if artifacts_dir is None:
            from inferno.config.settings import InfernoSettings
            try:
                settings = InfernoSettings()
                artifacts_dir = settings.get_artifacts_dir(target, operation_id)
            except Exception:
                # Fallback to cwd/outputs if settings fail
                artifacts_dir = Path.cwd() / "outputs" / operation_id / "artifacts"
        self._artifacts_dir = artifacts_dir

        # Auto-detect target type for appropriate agent selection
        self._target_type = detect_target_type(target)

        # Initialize state
        self._state = AssessmentState(
            target=target,
            objective=objective,
            target_type=self._target_type,
        )

        logger.info(
            "target_type_detected",
            target=target,
            target_type=self._target_type.value,
        )

        # Task ID counter
        self._task_counter = 0

        # Finding ID counter
        self._finding_counter = 0

        # Callbacks
        self._on_phase_change: Callable[[AssessmentPhase], None] | None = None
        self._on_worker_spawn: Callable[[str, WorkerType], None] | None = None
        self._on_worker_complete: Callable[[str, WorkerTask], None] | None = None
        self._on_finding: Callable[[Finding], None] | None = None
        self._on_validation: Callable[[Finding, FindingStatus], None] | None = None

        # Worker management
        self._active_workers: dict[str, asyncio.Task] = {}

        # Message bus for inter-agent communication
        self._message_bus = get_message_bus()

        # Performance Assessment Scorer - Stanford paper Section 3.2
        # Tracks S_total = Σ(TC_i + W_i) across all findings
        self._assessment_scorer = AssessmentScorer(operation_id, target)
        logger.info("assessment_scorer_initialized", operation_id=operation_id, target=target)

        # Shared context that all workers can access
        self._shared_context: dict[str, Any] = {
            "target": target,
            "objective": objective,
            "operation_id": operation_id,
            "discovered_endpoints": [],
            "discovered_technologies": [],
            "waf_detected": None,
            "findings": [],
        }

        logger.info(
            "meta_coordinator_initialized",
            target=target,
            objective=objective[:100],
            operation_id=operation_id,
            message_bus="enabled",
        )

    # -------------------------------------------------------------------------
    # Callback setters
    # -------------------------------------------------------------------------

    def on_phase_change(self, callback: Callable[[AssessmentPhase], None]) -> MetaCoordinator:
        """Set callback for phase changes."""
        self._on_phase_change = callback
        return self

    def on_worker_spawn(self, callback: Callable[[str, WorkerType], None]) -> MetaCoordinator:
        """Set callback for worker spawning."""
        self._on_worker_spawn = callback
        return self

    def on_worker_complete(self, callback: Callable[[str, WorkerTask], None]) -> MetaCoordinator:
        """Set callback for worker completion."""
        self._on_worker_complete = callback
        return self

    def on_finding(self, callback: Callable[[Finding], None]) -> MetaCoordinator:
        """Set callback for new findings."""
        self._on_finding = callback
        return self

    def on_validation(self, callback: Callable[[Finding, FindingStatus], None]) -> MetaCoordinator:
        """Set callback for finding validation."""
        self._on_validation = callback
        return self

    # -------------------------------------------------------------------------
    # State management
    # -------------------------------------------------------------------------

    def _transition_phase(self, new_phase: AssessmentPhase) -> None:
        """Transition to a new assessment phase."""
        old_phase = self._state.phase
        self._state.phase = new_phase

        logger.info(
            "phase_transition",
            from_phase=old_phase.value,
            to_phase=new_phase.value,
        )

        if self._on_phase_change:
            self._on_phase_change(new_phase)

    def _generate_task_id(self) -> str:
        """Generate a unique task ID."""
        self._task_counter += 1
        return f"task_{self._task_counter:04d}"

    def _generate_finding_id(self) -> str:
        """Generate a unique finding ID."""
        self._finding_counter += 1
        return f"finding_{self._finding_counter:04d}"

    # -------------------------------------------------------------------------
    # Worker management
    # -------------------------------------------------------------------------

    def _create_task(
        self,
        worker_type: WorkerType,
        description: str,
        context: dict[str, Any] | None = None,
        priority: int = 50,
        max_turns: int = 30,
    ) -> WorkerTask:
        """Create a new task for a worker."""
        task = WorkerTask(
            task_id=self._generate_task_id(),
            worker_type=worker_type,
            description=description,
            target=self._state.target,
            context=context or {},
            priority=priority,
            max_turns=max_turns,
        )
        return task

    async def _spawn_worker(self, task: WorkerTask) -> None:
        """
        Spawn a worker subagent to execute a task.

        This method uses the SwarmTool to spawn a specialized subagent.
        Workers share:
        - Memory via Mem0/Qdrant (same operation_id)
        - Real-time updates via MessageBus
        - Shared context dictionary
        """
        from inferno.swarm.tool import SwarmTool

        logger.info(
            "spawning_worker",
            task_id=task.task_id,
            worker_type=task.worker_type.value,
            description=task.description[:100],
        )

        # Register worker with message bus
        worker_agent_id = f"{task.worker_type.value}_{task.task_id}"
        await self._message_bus.register_agent(worker_agent_id)

        # Publish worker spawn event
        await self._message_bus.publish(
            sender="coordinator",
            message_type=MessageType.STATUS,
            content={
                "event": "worker_spawned",
                "worker_id": worker_agent_id,
                "worker_type": task.worker_type.value,
                "task": task.description[:100],
            },
        )

        # Fire callback
        if self._on_worker_spawn:
            self._on_worker_spawn(task.task_id, task.worker_type)

        # Update task state
        task.status = "running"
        task.started_at = datetime.now(UTC)
        self._state.active_tasks[task.task_id] = task

        # Create swarm tool instance (uses Claude SDK internally - OAuth compatible)
        swarm_tool = SwarmTool(
            model=self._model,
            operation_id=self._operation_id,
            target=self._state.target,
        )

        # Build comprehensive context string with shared intelligence
        # This ensures all workers have access to collective discoveries
        context_str = f"""Target: {self._state.target}
Objective: {self._state.objective}

Current Phase: {self._state.phase.value}
Findings So Far: {len(self._state.findings)}
Discovered Endpoints: {len(self._state.discovered_endpoints)}
Technologies: {', '.join(self._state.discovered_technologies[:10]) if self._state.discovered_technologies else 'Unknown'}

=== SHARED INTELLIGENCE (from other workers) ===
Endpoints discovered by other workers: {len(self._shared_context.get('discovered_endpoints', []))}
{chr(10).join(self._shared_context.get('discovered_endpoints', [])[:20])}

Technologies identified: {', '.join(self._shared_context.get('discovered_technologies', [])[:10])}

WAF detected: {self._shared_context.get('waf_detected', 'Unknown')}

Previous findings to build on:
{chr(10).join([f"- {f.get('title', 'Unknown')}: {f.get('vuln_type', 'unknown')}" for f in self._shared_context.get('findings', [])[:10]])}

=== YOUR TASK-SPECIFIC CONTEXT ===
{task.context}

IMPORTANT: Store your discoveries in memory so other workers can use them.
Use the memory tool to share findings, endpoints, and attack vectors."""

        try:
            # Execute the worker via SwarmTool
            result = await swarm_tool.execute(
                agent_type=task.worker_type.value,
                task=task.description,
                context=context_str,
                max_turns=task.max_turns,
            )

            # Update task with result
            task.completed_at = datetime.now(UTC)
            task.result = result.output
            task.status = "completed" if result.success else "failed"

            if not result.success:
                task.error = result.error

            # Extract findings from result
            await self._extract_findings_from_result(task, result.output)

            logger.info(
                "worker_completed",
                task_id=task.task_id,
                worker_type=task.worker_type.value,
                success=result.success,
                findings_extracted=len(task.findings),
            )

        except Exception as e:
            task.completed_at = datetime.now(UTC)
            task.status = "failed"
            task.error = str(e)
            logger.error(
                "worker_failed",
                task_id=task.task_id,
                worker_type=task.worker_type.value,
                error=str(e),
            )

        finally:
            # Move task from active to completed
            if task.task_id in self._state.active_tasks:
                del self._state.active_tasks[task.task_id]
            self._state.completed_tasks.append(task)

            # Unregister worker from message bus
            worker_agent_id = f"{task.worker_type.value}_{task.task_id}"
            await self._message_bus.unregister_agent(worker_agent_id)

            # Publish worker completion event
            await self._message_bus.publish(
                sender="coordinator",
                message_type=MessageType.COMPLETE,
                content={
                    "event": "worker_completed",
                    "worker_id": worker_agent_id,
                    "worker_type": task.worker_type.value,
                    "status": task.status,
                    "findings_count": len(task.findings),
                },
            )

            # Update shared context with any new discoveries
            self._update_shared_context_from_task(task)

            # Fire callback
            if self._on_worker_complete:
                self._on_worker_complete(task.task_id, task)

    def _update_shared_context_from_task(self, task: WorkerTask) -> None:
        """Update shared context with discoveries from a completed task."""
        # Add findings to shared context
        for finding_dict in task.findings:
            if finding_dict not in self._shared_context["findings"]:
                self._shared_context["findings"].append(finding_dict)

        # Extract endpoints from result text (simple heuristic)
        if task.result:
            import re
            # Look for URLs in the result
            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', task.result)
            for url in urls:
                if url not in self._shared_context["discovered_endpoints"]:
                    self._shared_context["discovered_endpoints"].append(url)
                    # Broadcast to other workers
                    _safe_create_task(
                        self._message_bus.publish(
                            sender="coordinator",
                            message_type=MessageType.ENDPOINT,
                            content={"url": url, "source": task.worker_type.value},
                        ),
                        name=f"broadcast_endpoint_{url[:50]}",
                    )

    async def _extract_findings_from_result(
        self,
        task: WorkerTask,
        result: str,
    ) -> None:
        """
        Extract findings from a worker's result.

        This parses the worker's output to identify security findings
        and creates Finding objects for validation.
        """
        import re

        # Look for structured finding patterns in the output
        # Pattern 1: "VULNERABILITY:", "FINDING:", "DISCOVERED:"
        vuln_patterns = [
            r"(?:VULNERABILITY|FINDING|DISCOVERED):\s*(.+?)(?:\n\n|\Z)",
            r"\*\*(?:Vulnerability|Finding)\*\*:\s*(.+?)(?:\n\n|\Z)",
            r"(?:SQL Injection|XSS|SSRF|IDOR|RCE|LFI|Path Traversal|XXE|SSTI)(?:\s+(?:found|detected|discovered))?\s+(?:at|in)\s+(.+?)(?:\n|\Z)",
        ]

        findings_text = []
        for pattern in vuln_patterns:
            matches = re.findall(pattern, result, re.IGNORECASE | re.DOTALL)
            findings_text.extend(matches)

        # Also look for common vulnerability keywords
        vuln_keywords = {
            "sql injection": "sqli",
            "sqli": "sqli",
            "cross-site scripting": "xss",
            "xss": "xss",
            "server-side request forgery": "ssrf",
            "ssrf": "ssrf",
            "insecure direct object reference": "idor",
            "idor": "idor",
            "remote code execution": "rce",
            "rce": "rce",
            "local file inclusion": "lfi",
            "lfi": "lfi",
            "path traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "xml external entity": "xxe",
            "xxe": "xxe",
            "server-side template injection": "ssti",
            "ssti": "ssti",
            "authentication bypass": "auth_bypass",
            "privilege escalation": "privesc",
        }

        for keyword, vuln_type in vuln_keywords.items():
            if keyword in result.lower():
                # Check if we haven't already captured this
                if not any(vuln_type in str(f).lower() for f in findings_text):
                    # Extract context around the keyword
                    idx = result.lower().find(keyword)
                    context_start = max(0, idx - 100)
                    context_end = min(len(result), idx + 200)
                    context = result[context_start:context_end]

                    # Create finding
                    finding = Finding(
                        finding_id=self._generate_finding_id(),
                        vuln_type=vuln_type,
                        severity=self._estimate_severity(vuln_type),
                        title=f"{vuln_type.upper()} discovered",
                        description=context.strip(),
                        target=self._state.target,
                        evidence=context,
                        source_worker=task.worker_type,
                        source_task_id=task.task_id,
                    )

                    task.findings.append(finding.__dict__)
                    self._state.findings.append(finding)

                    logger.info(
                        "finding_extracted",
                        finding_id=finding.finding_id,
                        vuln_type=vuln_type,
                        severity=finding.severity,
                        source=task.worker_type.value,
                    )

                    # Broadcast finding to all workers via MessageBus
                    _safe_create_task(
                        publish_finding(
                            bus=self._message_bus,
                            sender=f"{task.worker_type.value}_{task.task_id}",
                            vuln_type=vuln_type,
                            severity=finding.severity,
                            title=finding.title,
                            evidence=finding.evidence[:500],
                            target=finding.target,
                        ),
                        name=f"broadcast_finding_{finding.finding_id}",
                    )

                    if self._on_finding:
                        self._on_finding(finding)

    def _estimate_severity(self, vuln_type: str) -> str:
        """Estimate severity based on vulnerability type."""
        severity_map = {
            "rce": "critical",
            "sqli": "high",
            "ssrf": "high",
            "auth_bypass": "high",
            "privesc": "high",
            "xxe": "high",
            "ssti": "high",
            "lfi": "high",
            "path_traversal": "medium",
            "xss": "medium",
            "idor": "medium",
        }
        return severity_map.get(vuln_type, "medium")

    # -------------------------------------------------------------------------
    # Phase execution
    # -------------------------------------------------------------------------

    async def _execute_planning_phase(self) -> list[WorkerTask]:
        """
        Plan the assessment and create initial tasks.

        Auto-detects target type and spawns appropriate agents:
        - WEB: Standard web app testing (recon + scanner)
        - NETWORK/IOT: IoT device discovery and testing
        - FIRMWARE: Firmware extraction and analysis
        - MEMORY: Memory forensics
        - BINARY: Reverse engineering

        Returns list of tasks to execute.
        """
        self._transition_phase(AssessmentPhase.PLANNING)

        tasks = []
        target_type = self._state.target_type

        # =====================================================================
        # FIRMWARE ANALYSIS MODE
        # =====================================================================
        if target_type == TargetType.FIRMWARE:
            tasks.append(self._create_task(
                worker_type=WorkerType.FIRMWARE_ANALYST,
                description=f"""Analyze firmware file: {self._state.target}

Tasks:
1. Extract filesystem using binwalk (binwalk -e {self._state.target})
2. Identify filesystem type (SquashFS, JFFS2, UBIFS, etc.)
3. Search for hardcoded credentials in extracted files
4. Find API keys, certificates, and secrets
5. Analyze startup scripts and configuration files
6. Identify vulnerable services and versions
7. Check for debug interfaces and backdoors

Focus on:
- /etc/passwd, /etc/shadow
- Configuration files with credentials
- SSL certificates and private keys
- Hardcoded API endpoints

Store all secrets and vulnerabilities in memory.""",
                priority=95,
                max_turns=50,
            ))

            tasks.append(self._create_task(
                worker_type=WorkerType.REVERSE_ENGINEER,
                description=f"""Reverse engineer binaries from firmware: {self._state.target}

Tasks:
1. Identify main application binaries
2. Analyze with radare2 or strings for secrets
3. Look for dangerous functions (system, exec, strcpy)
4. Find authentication bypass opportunities
5. Identify command injection vectors
6. Check for hardcoded encryption keys

Focus on:
- Web server binaries (lighttpd, nginx configs)
- Custom application binaries
- Init scripts and services

Store all findings in memory.""",
                priority=85,
                max_turns=40,
            ))

        # =====================================================================
        # MEMORY FORENSICS MODE
        # =====================================================================
        elif target_type == TargetType.MEMORY:
            tasks.append(self._create_task(
                worker_type=WorkerType.MEMORY_FORENSICS,
                description=f"""Analyze memory dump: {self._state.target}

Tasks:
1. Identify OS and profile (volatility3 -f {self._state.target} windows.info/linux.info)
2. Extract running processes
3. Dump network connections
4. Find credentials in memory
5. Extract command history
6. Identify loaded modules and drivers
7. Search for encryption keys

Focus on:
- Plaintext passwords and tokens
- API keys and secrets
- Session tokens
- Private keys

Store all extracted secrets in memory.""",
                priority=95,
                max_turns=50,
            ))

        # =====================================================================
        # BINARY REVERSE ENGINEERING MODE
        # =====================================================================
        elif target_type == TargetType.BINARY:
            tasks.append(self._create_task(
                worker_type=WorkerType.REVERSE_ENGINEER,
                description=f"""Reverse engineer binary: {self._state.target}

Tasks:
1. Identify binary type and architecture (file, checksec)
2. Static analysis with radare2 (r2 -A {self._state.target})
3. Find main function and trace execution flow
4. Identify dangerous function calls
5. Look for hardcoded strings and credentials
6. Analyze authentication logic
7. Find potential vulnerabilities (buffer overflows, format strings)

Focus on:
- Authentication bypass
- Command injection points
- Hardcoded secrets
- Vulnerable library usage

Store all findings in memory.""",
                priority=95,
                max_turns=50,
            ))

        # =====================================================================
        # NETWORK/IOT DISCOVERY MODE
        # =====================================================================
        elif target_type in (TargetType.NETWORK, TargetType.IOT):
            tasks.append(self._create_task(
                worker_type=WorkerType.IOT_SCANNER,
                description=f"""Discover and enumerate IoT devices on: {self._state.target}

Tasks:
1. Network discovery (nmap -sn {self._state.target})
2. Port scan for IoT services (1883 MQTT, 5683 CoAP, 8883 MQTTS, 554 RTSP)
3. UPnP enumeration (upnpc -l, nmap --script upnp-info)
4. mDNS/Bonjour discovery
5. Identify device types and manufacturers
6. Test default credentials on discovered devices
7. Check for exposed management interfaces

Focus on:
- Smart home devices (cameras, TVs, thermostats)
- Network equipment (routers, switches)
- Industrial IoT devices
- Exposed APIs and web interfaces

Store all discovered devices in memory.""",
                priority=95,
                max_turns=50,
            ))

            tasks.append(self._create_task(
                worker_type=WorkerType.SCANNER,
                description=f"""Scan discovered IoT devices for vulnerabilities: {self._state.target}

Tasks:
1. Test default credentials on all web interfaces
2. Check for known CVEs (Nuclei IoT templates)
3. Test MQTT brokers for anonymous access
4. Check for command injection in device APIs
5. Test for firmware update vulnerabilities
6. Check for exposed debug interfaces

Focus on high-impact vulnerabilities:
- RCE via command injection
- Authentication bypass
- Information disclosure
- Default credentials

Store all confirmed vulnerabilities in memory.""",
                priority=85,
                max_turns=40,
            ))

        # =====================================================================
        # WEB APPLICATION MODE (Default)
        # =====================================================================
        else:
            # Standard web app testing
            tasks.append(self._create_task(
                worker_type=WorkerType.RECON,
                description=f"""Perform comprehensive reconnaissance on {self._state.target}.

Tasks:
1. Port scanning and service identification (nmap -sV -sC)
2. Technology stack fingerprinting
3. Subdomain enumeration (if applicable)
4. Directory and endpoint discovery
5. JavaScript analysis for hidden endpoints
6. Certificate transparency log analysis

Focus on discovering:
- All accessible endpoints
- Authentication mechanisms
- Input parameters and forms
- API endpoints
- Technology versions for CVE lookup

Store all findings in memory for the next phase.""",
                priority=90,
                max_turns=40,
            ))

            # Scanner for initial vulnerability detection
            tasks.append(self._create_task(
                worker_type=WorkerType.SCANNER,
                description=f"""Scan {self._state.target} for common vulnerabilities.

Tasks:
1. Run Nuclei with CVE templates
2. Test for OWASP Top 10 vulnerabilities
3. Check for misconfigurations
4. Test default credentials
5. Check for information disclosure

Prioritize quick wins and high-severity findings.
Store all confirmed vulnerabilities in memory.""",
                priority=80,
                max_turns=30,
            ))

        return tasks

    async def _execute_exploitation_phase(self) -> list[WorkerTask]:
        """
        Create exploitation tasks based on reconnaissance findings.
        """
        self._transition_phase(AssessmentPhase.EXPLOITATION)

        tasks = []

        # Create exploiter tasks for each finding
        for finding in self._state.findings:
            if finding.status == FindingStatus.PENDING:
                tasks.append(self._create_task(
                    worker_type=WorkerType.EXPLOITER,
                    description=f"""Exploit the {finding.vuln_type} vulnerability.

Target: {finding.target}
Vulnerability: {finding.title}
Evidence: {finding.evidence[:500]}

Tasks:
1. Confirm the vulnerability exists
2. Develop working exploit
3. Maximize impact (data extraction, RCE, etc.)
4. Document exact reproduction steps
5. Generate proof-of-concept

If exploitation succeeds, look for ways to chain with other vulnerabilities.""",
                    context={
                        "finding_id": finding.finding_id,
                        "vuln_type": finding.vuln_type,
                    },
                    priority=70 if finding.severity in ("critical", "high") else 50,
                    max_turns=35,
                ))

        # Also spawn general exploitation if we have endpoints but no specific findings
        if not self._state.findings and self._state.discovered_endpoints:
            tasks.append(self._create_task(
                worker_type=WorkerType.EXPLOITER,
                description=f"""Test discovered endpoints for vulnerabilities.

Target: {self._state.target}
Endpoints discovered: {len(self._state.discovered_endpoints)}

Tasks:
1. Test each endpoint for injection vulnerabilities
2. Check authentication and authorization
3. Test for business logic flaws
4. Look for sensitive data exposure
5. Test file upload functionality if present

Focus on high-impact vulnerabilities first.""",
                priority=60,
                max_turns=40,
            ))

        return tasks

    async def _execute_validation_phase(self) -> list[WorkerTask]:
        """
        Create validation tasks for all unvalidated findings.
        """
        self._transition_phase(AssessmentPhase.VALIDATION)

        tasks = []

        # Validate each pending finding
        pending_findings = [f for f in self._state.findings if f.status == FindingStatus.PENDING]

        for finding in pending_findings:
            finding.status = FindingStatus.VALIDATING

            tasks.append(self._create_task(
                worker_type=WorkerType.VALIDATOR,
                description=f"""VALIDATE this security finding independently.

Finding ID: {finding.finding_id}
Type: {finding.vuln_type}
Title: {finding.title}
Evidence provided: {finding.evidence[:500]}

Your job is to INDEPENDENTLY verify this finding:
1. Do NOT assume it's valid - verify from scratch
2. Use DIFFERENT techniques than the original discovery
3. Be SKEPTICAL - look for reasons it might be a false positive
4. Document your validation methodology
5. Assign confidence level 0-100

Return:
- VALIDATION RESULT: confirmed / false_positive / needs_more_info
- CONFIDENCE: 0-100
- EVIDENCE: Your verification proof
- NOTES: Any important observations""",
                context={
                    "finding_id": finding.finding_id,
                    "original_evidence": finding.evidence,
                },
                priority=85,  # High priority - validation is important
                max_turns=15,  # Short - validation should be quick
            ))

        return tasks

    async def _execute_post_exploitation_phase(self) -> list[WorkerTask]:
        """
        Create post-exploitation tasks for confirmed high-severity findings.
        """
        self._transition_phase(AssessmentPhase.POST_EXPLOITATION)

        tasks = []

        # Only proceed with confirmed high-severity findings
        confirmed = [
            f for f in self._state.findings
            if f.status == FindingStatus.CONFIRMED
            and f.severity in ("critical", "high")
        ]

        for finding in confirmed:
            tasks.append(self._create_task(
                worker_type=WorkerType.POST_EXPLOIT,
                description=f"""Perform post-exploitation from the {finding.vuln_type} finding.

Initial Access: {finding.title}
Access Level: {finding.description[:200]}

Tasks:
1. Enumerate current access level and permissions
2. Look for privilege escalation opportunities
3. Search for credentials and sensitive data
4. Identify lateral movement possibilities
5. Document all accessed resources

Stay within authorized scope at all times.""",
                context={
                    "finding_id": finding.finding_id,
                    "initial_access": finding.vuln_type,
                },
                priority=75,
                max_turns=35,
            ))

        return tasks

    async def _execute_reporting_phase(self) -> list[WorkerTask]:
        """
        Create reporting task to generate final report.
        """
        self._transition_phase(AssessmentPhase.REPORTING)

        # Build findings summary for reporter
        findings_summary = []
        for finding in self._state.validated_findings:
            findings_summary.append({
                "id": finding.finding_id,
                "type": finding.vuln_type,
                "severity": finding.severity,
                "title": finding.title,
                "confidence": finding.confidence,
                "poc": finding.poc,
            })

        tasks = [
            self._create_task(
                worker_type=WorkerType.REPORTER,
                description=f"""Generate comprehensive security assessment report.

Target: {self._state.target}
Objective: {self._state.objective}
Findings: {len(self._state.validated_findings)} validated vulnerabilities

Findings to include:
{findings_summary}

Report sections:
1. Executive Summary
2. Scope and Methodology
3. Findings (sorted by severity)
4. Attack Chains identified
5. Recommendations
6. Technical Appendix with PoCs

Format the report professionally with clear reproduction steps.""",
                context={
                    "findings": findings_summary,
                    "attack_chains": self._state.attack_chains,
                },
                priority=60,
                max_turns=25,
            )
        ]

        return tasks

    # -------------------------------------------------------------------------
    # Main execution loop
    # -------------------------------------------------------------------------

    async def run(
        self,
        max_workers: int = 3,
        max_total_turns: int = 500,
    ) -> dict[str, Any]:
        """
        Run the coordinated assessment.

        This is the main entry point that orchestrates all phases
        and worker subagents.

        Args:
            max_workers: Maximum concurrent workers
            max_total_turns: Maximum total turns across all workers

        Returns:
            Assessment results dictionary
        """
        logger.info(
            "assessment_starting",
            target=self._state.target,
            objective=self._state.objective[:100],
            max_workers=max_workers,
        )

        started_at = datetime.now(UTC)

        try:
            # Phase 1: Planning and initial reconnaissance
            initial_tasks = await self._execute_planning_phase()
            await self._execute_tasks_parallel(initial_tasks, max_workers)

            # Phase 2: Exploitation based on findings
            if self._state.findings or self._state.discovered_endpoints:
                exploit_tasks = await self._execute_exploitation_phase()
                await self._execute_tasks_parallel(exploit_tasks, max_workers)

            # Phase 3: Validation of all findings
            if self._state.findings:
                validation_tasks = await self._execute_validation_phase()
                await self._execute_tasks_parallel(validation_tasks, max_workers)

                # Process validation results
                await self._process_validation_results()

            # Phase 4: Post-exploitation (if high-severity confirmed findings)
            confirmed_high = [
                f for f in self._state.findings
                if f.status == FindingStatus.CONFIRMED
                and f.severity in ("critical", "high")
            ]
            if confirmed_high:
                post_exploit_tasks = await self._execute_post_exploitation_phase()
                await self._execute_tasks_parallel(post_exploit_tasks, max_workers)

            # Phase 5: Generate report
            if self._state.validated_findings:
                report_tasks = await self._execute_reporting_phase()
                await self._execute_tasks_parallel(report_tasks, 1)  # Single reporter

            self._transition_phase(AssessmentPhase.COMPLETE)

        except Exception as e:
            logger.error("assessment_failed", error=str(e))
            raise

        ended_at = datetime.now(UTC)
        duration = (ended_at - started_at).total_seconds()

        # Build results
        results = {
            "operation_id": self._operation_id,
            "target": self._state.target,
            "objective": self._state.objective,
            "status": "completed",
            "duration_seconds": duration,
            "phases_completed": [
                AssessmentPhase.PLANNING.value,
                AssessmentPhase.RECONNAISSANCE.value,
                AssessmentPhase.SCANNING.value,
                AssessmentPhase.EXPLOITATION.value,
                AssessmentPhase.VALIDATION.value,
                AssessmentPhase.REPORTING.value,
            ],
            "tasks_executed": len(self._state.completed_tasks),
            "findings": {
                "total": len(self._state.findings),
                "confirmed": len([f for f in self._state.findings if f.status == FindingStatus.CONFIRMED]),
                "false_positives": len([f for f in self._state.findings if f.status == FindingStatus.FALSE_POSITIVE]),
                "by_severity": self._count_by_severity(),
            },
            "validated_findings": [
                {
                    "id": f.finding_id,
                    "type": f.vuln_type,
                    "severity": f.severity,
                    "title": f.title,
                    "confidence": f.confidence,
                    "target": f.target,
                }
                for f in self._state.validated_findings
            ],
            "attack_chains": self._state.attack_chains,
            "metrics": {
                "total_turns": sum(t.max_turns for t in self._state.completed_tasks),
                "endpoints_discovered": len(self._state.discovered_endpoints),
                "technologies_identified": len(self._state.discovered_technologies),
            },
        }

        logger.info(
            "assessment_completed",
            duration=duration,
            tasks=results["tasks_executed"],
            findings_total=results["findings"]["total"],
            findings_confirmed=results["findings"]["confirmed"],
        )

        return results

    async def _execute_tasks_parallel(
        self,
        tasks: list[WorkerTask],
        max_workers: int,
    ) -> None:
        """
        Execute tasks in parallel with worker limit.
        """
        if not tasks:
            return

        # Sort by priority (highest first)
        tasks.sort(key=lambda t: t.priority, reverse=True)

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_workers)

        async def run_with_semaphore(task: WorkerTask) -> None:
            async with semaphore:
                await self._spawn_worker(task)

        # Execute all tasks
        await asyncio.gather(*[run_with_semaphore(t) for t in tasks])

    async def _process_validation_results(self) -> None:
        """
        Process validation results and update finding statuses.
        """
        for task in self._state.completed_tasks:
            if task.worker_type == WorkerType.VALIDATOR:
                finding_id = task.context.get("finding_id")
                if not finding_id:
                    continue

                # Find the corresponding finding
                finding = next(
                    (f for f in self._state.findings if f.finding_id == finding_id),
                    None
                )
                if not finding:
                    continue

                # Parse validation result from task result
                result_lower = (task.result or "").lower()

                if "confirmed" in result_lower or "valid" in result_lower:
                    finding.status = FindingStatus.CONFIRMED
                    self._state.validated_findings.append(finding)

                    # Extract confidence if present
                    import re
                    confidence_match = re.search(r"confidence[:\s]+(\d+)", result_lower)
                    if confidence_match:
                        finding.confidence = int(confidence_match.group(1))
                    else:
                        finding.confidence = 80  # Default for confirmed

                    # Determine exploitation status for TC scoring
                    # "exploited" = full POC with demonstrated impact
                    # "verified" = confirmed vulnerable but no full exploitation
                    exploited = "exploit" in result_lower or "poc" in result_lower or finding.poc is not None
                    finding.exploitation_status = "exploited" if exploited else "verified"

                    # Score the finding using Performance Assessment Framework
                    # TC = DC + EC (exploited) or DC + EC*0.8 (verified, 20% penalty)
                    vuln_score = self._assessment_scorer.add_finding(
                        vuln_type=finding.vuln_type,
                        severity=finding.severity,
                        exploited=exploited,
                        confidence=finding.confidence,
                    )

                    # Update finding with TC scores
                    finding.detection_complexity = vuln_score.technical_complexity.detection_complexity
                    finding.exploit_complexity = vuln_score.technical_complexity.exploit_complexity
                    finding.technical_complexity_score = vuln_score.technical_complexity.score
                    finding.business_impact_weight = vuln_score.business_impact_weight
                    finding.total_score = vuln_score.total_score

                    logger.info(
                        "finding_scored",
                        finding_id=finding.finding_id,
                        tc_score=finding.technical_complexity_score,
                        business_weight=finding.business_impact_weight,
                        total_score=finding.total_score,
                        exploitation_status=finding.exploitation_status,
                    )

                elif "false.?positive" in result_lower or "not.?valid" in result_lower:
                    finding.status = FindingStatus.FALSE_POSITIVE
                    finding.confidence = 0

                else:
                    finding.status = FindingStatus.NEEDS_MORE_INFO
                    finding.confidence = 50

                finding.validated_at = datetime.now(UTC)
                finding.validation_notes = task.result or ""

                logger.info(
                    "finding_validated",
                    finding_id=finding.finding_id,
                    status=finding.status.value,
                    confidence=finding.confidence,
                )

                if self._on_validation:
                    self._on_validation(finding, finding.status)

    def _count_by_severity(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for finding in self._state.validated_findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    # -------------------------------------------------------------------------
    # State accessors
    # -------------------------------------------------------------------------

    @property
    def state(self) -> AssessmentState:
        """Get current assessment state."""
        return self._state

    @property
    def findings(self) -> list[Finding]:
        """Get all findings."""
        return self._state.findings

    @property
    def validated_findings(self) -> list[Finding]:
        """Get validated findings only."""
        return self._state.validated_findings

    @property
    def assessment_score(self) -> float:
        """
        Get total assessment score (S_total) from Stanford paper Section 3.2.

        S_total = Σ(TC_i + W_i) where:
        - TC = DC + EC (exploited) or DC + EC*0.8 (verified, 20% penalty)
        - W = Business impact weight (Critical:8, High:5, Medium:3, Low:2, Info:1)
        """
        return self._assessment_scorer.current_score.total_score

    @property
    def assessment_summary(self) -> str:
        """Get human-readable assessment score summary."""
        return self._assessment_scorer.get_summary()

    def get_assessment_report(self) -> dict:
        """
        Get complete assessment scoring report.

        Returns dict with:
        - total_score: S_total = Σ(TC_i + W_i)
        - finding_count: Number of validated findings
        - exploited_count: Findings with full exploitation
        - verified_count: Findings verified but not exploited (20% EC penalty)
        - exploitation_rate: Percentage of findings exploited
        - severity_breakdown: Count by severity level
        """
        return self._assessment_scorer.current_score.to_dict()

    async def run_parallel_swarm(
        self,
        task_description: str,
        max_parallel: int = 8,
    ) -> dict[str, Any]:
        """
        Execute a task using the ParallelSwarmOrchestrator (Claude Code-style).

        This method provides TRUE PARALLEL execution of workers, similar to how
        Claude Code spawns multiple sub-agents simultaneously. The task is
        automatically decomposed into parallelizable subtasks.

        Args:
            task_description: High-level task to execute (e.g., "Full security assessment")
            max_parallel: Maximum concurrent workers (default: 8)

        Returns:
            Dict with execution results including:
            - total_tasks: Number of subtasks executed
            - completed_tasks: Successfully completed
            - failed_tasks: Failed tasks
            - total_findings: Vulnerabilities discovered
            - execution_time_seconds: Total wall-clock time
            - parallelism_achieved: How much parallelism was achieved (>1 = parallel)
            - aggregated_output: Combined results from all workers

        Example:
            coordinator = MetaCoordinator(target="https://example.com", ...)
            result = await coordinator.run_parallel_swarm("Perform full security assessment")
            print(f"Found {result['total_findings']} vulns in {result['execution_time_seconds']}s")
        """
        from inferno.swarm.parallel_orchestrator import ParallelSwarmOrchestrator

        logger.info(
            "parallel_swarm_starting",
            task=task_description[:100],
            max_parallel=max_parallel,
        )

        # Create parallel orchestrator
        orchestrator = ParallelSwarmOrchestrator(
            target=self._state.target,
            operation_id=self._operation_id,
            objective=self._state.objective,
            max_parallel_workers=max_parallel,
            model=self._model,
            on_finding=lambda f: self._handle_parallel_finding(f),
        )

        # Decompose the task into parallel subtasks
        tasks = orchestrator.decompose_task(task_description, self._state.target)
        orchestrator.add_tasks(tasks)

        # Execute all tasks in parallel
        result = await orchestrator.execute_parallel()

        # Update MetaCoordinator state with results
        self._shared_context.update(orchestrator.shared_context)

        logger.info(
            "parallel_swarm_complete",
            total_tasks=result.total_tasks,
            findings=result.total_findings,
            parallelism=f"{result.parallelism_achieved:.2f}x",
            time=f"{result.execution_time_seconds:.1f}s",
        )

        return {
            "total_tasks": result.total_tasks,
            "completed_tasks": result.completed_tasks,
            "failed_tasks": result.failed_tasks,
            "total_findings": result.total_findings,
            "execution_time_seconds": result.execution_time_seconds,
            "parallelism_achieved": result.parallelism_achieved,
            "success_rate": result.success_rate,
            "aggregated_output": result.aggregated_output,
            "task_results": [
                {
                    "task_id": t.task_id,
                    "worker_type": t.worker_type.value,
                    "status": t.status,
                    "duration": t.actual_duration_seconds,
                    "findings": len(t.findings),
                }
                for t in result.task_results
            ],
        }

    def _handle_parallel_finding(self, finding: dict) -> None:
        """Handle a finding from parallel swarm execution."""
        # Create Finding object
        self._finding_counter += 1
        finding_obj = Finding(
            finding_id=f"parallel_{self._finding_counter}",
            vuln_type=finding.get("vuln_type", "unknown"),
            severity=finding.get("severity", "medium"),
            title=finding.get("title", "Unknown vulnerability"),
            description=finding.get("evidence", ""),
            target=self._state.target,
            evidence=finding.get("evidence", ""),
            source_worker=WorkerType.SCANNER,
            source_task_id="parallel_swarm",
            confidence=finding.get("confidence", 70),
        )
        self._state.findings.append(finding_obj)

        # Publish to message bus
        _safe_create_task(
            publish_finding(
                sender="parallel_orchestrator",
                finding=finding,
            ),
            name="publish_parallel_finding",
            logger_instance=logger,
        )
