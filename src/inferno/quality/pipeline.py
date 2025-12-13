"""
Quality gate pipeline orchestrator for Bug Bounty finding validation.

This module provides the QualityGatePipeline class that orchestrates the flow
of security findings through multiple quality gates, ensuring findings meet
Bug Bounty program standards before being included in reports.
"""

from __future__ import annotations

import structlog
from anthropic import AsyncAnthropic

from inferno.quality.candidate import FindingCandidate
from inferno.quality.config import DEFAULT_GATE_WEIGHTS, QualityConfig
from inferno.quality.gate import QualityGate
from inferno.reporting.models import Finding
from inferno.tools.registry import ToolRegistry

logger = structlog.get_logger(__name__)


class QualityGatePipeline:
    """
    Orchestrates the flow of findings through quality gates.

    A finding must pass ALL blocking gates to be approved for reporting:
    1. SoWhatGate - Requires concrete impact and exploitability
    2. TechnologyContextGate - Filters out false positives by tech
    3. EscalationGate - Requires minimum escalation attempts
    4. SeverityGate - Adjusts severity based on proven impact
    5. PreReportChecklistGate - Final validation before report

    The pipeline processes candidates sequentially through each gate, tracking
    which gates passed/failed and calculating an overall quality score. Only
    candidates that pass all blocking gates are approved for reporting.
    """

    def __init__(
        self,
        client: AsyncAnthropic | None = None,
        registry: ToolRegistry | None = None,
        config: QualityConfig | None = None,
    ) -> None:
        """
        Initialize quality gate pipeline.

        Args:
            client: Anthropic client for AI-powered gate evaluations (optional)
            registry: Tool registry for tool-based escalation (optional)
            config: Quality configuration settings (uses defaults if not provided)
        """
        self.client = client
        self.registry = registry
        self.config = config or QualityConfig()

        # Initialize gates in order (will be populated by gate implementations)
        self._gates: list[QualityGate] = []

        # Gate weights for quality scoring
        self._gate_weights = {gw.gate_name: gw for gw in DEFAULT_GATE_WEIGHTS}

        self._log = logger.bind(component="quality_pipeline")
        self._log.info(
            "quality_pipeline_initialized",
            gate_count=len(self._gates),
            config=self.config.model_dump(),
        )

    def register_gate(self, gate: QualityGate) -> None:
        """
        Register a quality gate with the pipeline.

        Gates are evaluated in the order they are registered.

        Args:
            gate: QualityGate instance to add to the pipeline
        """
        self._gates.append(gate)
        self._log.info("gate_registered", gate_name=gate.name, gate_type=type(gate).__name__)

    def register_gates(self, gates: list[QualityGate]) -> None:
        """
        Register multiple quality gates with the pipeline.

        Args:
            gates: List of QualityGate instances to add to the pipeline
        """
        for gate in gates:
            self.register_gate(gate)

    async def process_candidate(
        self, candidate: FindingCandidate, target: str
    ) -> tuple[bool, Finding | None]:
        """
        Process a finding candidate through all quality gates.

        The candidate is evaluated through each gate in sequence. For blocking gates,
        failure immediately returns False. Non-blocking gates contribute to the quality
        score but don't prevent approval.

        Args:
            candidate: Finding candidate to validate
            target: Target URL/hostname for environment validation

        Returns:
            Tuple of (approved, finding):
            - approved: True if all blocking gates passed
            - finding: Finding object if approved, None otherwise
        """
        self._log.info(
            "processing_candidate",
            title=candidate.title,
            vuln_type=candidate.vuln_type,
            initial_severity=candidate.initial_severity.value,
            target=target,
        )

        # Track quality score components
        total_weight = 0.0
        weighted_score = 0.0

        # Process each gate in sequence
        for gate in self._gates:
            gate_log = self._log.bind(gate_name=gate.name, gate_type=type(gate).__name__)

            try:
                gate_log.debug("evaluating_gate", is_blocking=gate.is_blocking)

                # Evaluate gate
                passed, message = await gate.evaluate(candidate, target)

                # Update quality score
                gate_weight = self._gate_weights.get(gate.name)
                if gate_weight:
                    total_weight += gate_weight.weight
                    if passed:
                        weighted_score += gate_weight.weight

                # Log result
                gate_log.info(
                    "gate_evaluated",
                    passed=passed,
                    message=message,
                    is_blocking=gate.is_blocking,
                )

                if passed:
                    candidate.mark_gate_passed(gate.name)
                else:
                    candidate.mark_gate_failed(gate.name, message)

                    # For blocking gates, reject immediately
                    if gate.is_blocking:
                        gate_log.warning(
                            "blocking_gate_failed",
                            reason=message,
                            gates_passed=candidate.gates_passed,
                            gates_failed=candidate.gates_failed,
                        )

                        candidate.reject(f"Failed blocking gate: {gate.name}")
                        self._log.info(
                            "candidate_rejected",
                            title=candidate.title,
                            gate=gate.name,
                            reason=message,
                        )
                        return False, None

            except Exception as e:
                gate_log.error(
                    "gate_evaluation_error",
                    error=str(e),
                    error_type=type(e).__name__,
                    exc_info=True,
                )

                # Treat exceptions as gate failures
                candidate.mark_gate_failed(gate.name, f"Evaluation error: {e!s}")

                # Fail fast for blocking gates
                if gate.is_blocking:
                    candidate.reject(f"Gate evaluation error: {gate.name}")
                    return False, None

        # Calculate final quality score
        quality_score = (weighted_score / total_weight) if total_weight > 0 else 0.0
        candidate.quality_score = quality_score

        self._log.info(
            "quality_score_calculated",
            title=candidate.title,
            quality_score=quality_score,
            min_required=self.config.min_quality_score,
            gates_passed=candidate.gates_passed,
            gates_failed=candidate.gates_failed,
        )

        # Check if quality score meets minimum threshold
        if quality_score < self.config.min_quality_score:
            self._log.warning(
                "quality_score_too_low",
                title=candidate.title,
                quality_score=quality_score,
                min_required=self.config.min_quality_score,
            )
            candidate.reject(
                f"Quality score {quality_score:.2f} below minimum {self.config.min_quality_score}"
            )
            return False, None

        # All blocking gates passed, approve candidate
        candidate.approve(quality_score)

        # Convert to Finding
        finding = self._to_finding(candidate)

        self._log.info(
            "candidate_approved",
            title=candidate.title,
            quality_score=quality_score,
            final_severity=candidate.final_severity.value,
            gates_passed=len(candidate.gates_passed),
            gates_failed=len(candidate.gates_failed),
        )

        return True, finding

    async def process_batch(
        self, candidates: list[FindingCandidate], target: str
    ) -> list[Finding]:
        """
        Process multiple finding candidates through quality gates.

        This method processes each candidate sequentially and collects only
        the approved findings.

        Args:
            candidates: List of finding candidates to validate
            target: Target URL/hostname for environment validation

        Returns:
            List of approved Finding objects (may be empty)
        """
        self._log.info(
            "processing_batch",
            candidate_count=len(candidates),
            target=target,
        )

        approved_findings: list[Finding] = []
        rejected_count = 0

        for candidate in candidates:
            approved, finding = await self.process_candidate(candidate, target)

            if approved and finding:
                approved_findings.append(finding)
            else:
                rejected_count += 1

        self._log.info(
            "batch_processing_complete",
            total_candidates=len(candidates),
            approved=len(approved_findings),
            rejected=rejected_count,
            approval_rate=len(approved_findings) / len(candidates) if candidates else 0.0,
        )

        return approved_findings

    def _to_finding(self, candidate: FindingCandidate) -> Finding:
        """
        Convert approved FindingCandidate to Finding object.

        This method enriches the Finding with quality metadata including
        quality score, gates passed, and escalation summary.

        Args:
            candidate: Approved finding candidate

        Returns:
            Finding object ready for report inclusion
        """
        # Build escalation summary
        escalation_summary = []
        if candidate.escalation_attempts:
            escalation_summary.append(
                f"Escalation attempts: {len(candidate.escalation_attempts)}"
            )
        if candidate.escalation_successes:
            escalation_summary.append(
                f"Successful escalations: {len(candidate.escalation_successes)}"
            )
            for success in candidate.escalation_successes:
                escalation_summary.append(
                    f"  - {success.from_finding} -> {success.to_finding} via {success.method}"
                )

        # Build quality metadata
        quality_metadata = {
            "quality_score": candidate.quality_score,
            "gates_passed": candidate.gates_passed,
            "gates_failed": candidate.gates_failed,
            "escalation_count": candidate.escalation_count,
            "has_successful_escalation": candidate.has_successful_escalation,
            "validation_timestamp": candidate.validated_at.isoformat()
            if candidate.validated_at
            else None,
        }

        # Add context adjustments if any
        if candidate.context_adjustments:
            quality_metadata["context_adjustments"] = [
                adj.to_dict() for adj in candidate.context_adjustments
            ]

        # Add severity adjustment rationale
        if candidate.severity_rationale:
            quality_metadata["severity_rationale"] = candidate.severity_rationale

        # Build description with escalation details
        description = candidate.description
        if escalation_summary:
            description += "\n\n**Escalation Details:**\n" + "\n".join(escalation_summary)

        # Create Finding object
        poc = (
            candidate.exploitability_proof if candidate.exploitability_proof else None
        )
        finding = Finding(
            title=candidate.title,
            description=description,
            severity=candidate.final_severity,
            affected_asset=candidate.affected_asset,
            evidence=candidate.evidence,
            remediation="",  # To be filled by report generator
            proof_of_concept=poc,
            metadata=quality_metadata,
            # Quality gate metadata
            quality_score=candidate.quality_score,
            gates_passed=candidate.gates_passed.copy(),
            escalation_summary="\n".join(escalation_summary) if escalation_summary else "",
            technology_context=candidate.technology_context,
        )

        self._log.debug(
            "finding_converted",
            title=finding.title,
            severity=finding.severity.value,
            quality_score=candidate.quality_score,
        )

        return finding

    @property
    def gate_count(self) -> int:
        """Get number of registered gates."""
        return len(self._gates)

    @property
    def blocking_gate_count(self) -> int:
        """Get number of blocking gates."""
        return sum(1 for gate in self._gates if gate.is_blocking)

    @property
    def gate_names(self) -> list[str]:
        """Get names of all registered gates."""
        return [gate.name for gate in self._gates]

    def __repr__(self) -> str:
        """String representation."""
        return (
            f"QualityGatePipeline(gates={self.gate_count}, "
            f"blocking={self.blocking_gate_count})"
        )
