"""
Finding candidate model for quality gate validation.

This module defines the FindingCandidate dataclass that tracks a security
finding through the quality gate system, accumulating evidence and validation
data at each stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from inferno.reporting.models import Severity


@dataclass
class EscalationAttempt:
    """Record of a single escalation attempt."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    method: str = ""  # e.g., "privilege_escalation", "horizontal_movement", "data_exfiltration"
    description: str = ""
    payload: str = ""
    result: str = ""  # Success, failure, partial
    evidence: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "description": self.description,
            "payload": self.payload,
            "result": self.result,
            "evidence": self.evidence,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EscalationAttempt:
        """Create from dictionary."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.now(UTC),
            method=data.get("method", ""),
            description=data.get("description", ""),
            payload=data.get("payload", ""),
            result=data.get("result", ""),
            evidence=data.get("evidence", ""),
            notes=data.get("notes", ""),
        )


@dataclass
class EscalationSuccess:
    """Record of a successful escalation."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    from_finding: str = ""  # Original finding that was escalated
    to_finding: str = ""  # New finding discovered through escalation
    method: str = ""
    severity_increase: str = ""  # e.g., "LOW -> HIGH"
    impact_description: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "from_finding": self.from_finding,
            "to_finding": self.to_finding,
            "method": self.method,
            "severity_increase": self.severity_increase,
            "impact_description": self.impact_description,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EscalationSuccess:
        """Create from dictionary."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.now(UTC),
            from_finding=data.get("from_finding", ""),
            to_finding=data.get("to_finding", ""),
            method=data.get("method", ""),
            severity_increase=data.get("severity_increase", ""),
            impact_description=data.get("impact_description", ""),
            evidence=data.get("evidence", ""),
        )


@dataclass
class ContextAdjustment:
    """Technology context-based severity adjustment."""

    context_type: str = ""  # e.g., "public_api_endpoint", "debug_route"
    original_severity: Severity = Severity.INFO
    adjusted_severity: Severity = Severity.INFO
    rationale: str = ""
    is_by_design: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "context_type": self.context_type,
            "original_severity": self.original_severity.value,
            "adjusted_severity": self.adjusted_severity.value,
            "rationale": self.rationale,
            "is_by_design": self.is_by_design,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextAdjustment:
        """Create from dictionary."""
        return cls(
            context_type=data.get("context_type", ""),
            original_severity=Severity(data.get("original_severity", "info")),
            adjusted_severity=Severity(data.get("adjusted_severity", "info")),
            rationale=data.get("rationale", ""),
            is_by_design=data.get("is_by_design", False),
        )


@dataclass
class FindingCandidate:
    """
    Security finding candidate tracked through quality gates.

    This class accumulates validation data as a finding passes through
    multiple quality gates, ensuring Bug Bounty program standards are met.
    """

    # Core finding data
    title: str
    description: str
    initial_severity: Severity
    affected_asset: str
    evidence: str
    vuln_type: str  # e.g., "SQLi", "XSS", "IDOR"

    # "So What?" gate data
    attacker_action: str = ""  # What can an attacker actually DO with this?
    concrete_impact: str = ""  # Specific, measurable business impact
    exploitability_proof: str = ""  # Evidence of exploitability (not just theory)

    # Technology context
    technology_context: str = ""  # e.g., "public_api", "admin_panel", "debug_endpoint"
    is_public_by_design: bool = False  # Is this intentionally public?
    context_adjustments: list[ContextAdjustment] = field(default_factory=list)

    # Escalation tracking
    escalation_attempts: list[EscalationAttempt] = field(default_factory=list)
    escalation_required: int = field(
        default=3
    )  # Number of escalation attempts required (from config)
    escalation_successes: list[EscalationSuccess] = field(default_factory=list)

    # Severity adjustment
    adjusted_severity: Severity | None = None
    severity_rationale: str = ""
    has_theoretical_language: bool = False  # "could", "might", "may", "potentially"

    # Pre-report checklist
    is_production: bool = False  # Confirmed production environment
    impact_demonstrated: bool = False  # Impact actually shown (not theoretical)
    escalation_documented: bool = False  # Escalation attempts recorded
    data_intentionally_public: bool = False  # Is leaked data meant to be public?

    # Final state
    approved_for_report: bool = False
    rejection_reasons: list[str] = field(default_factory=list)
    quality_score: float = 0.0  # 0-1 score based on gate weights
    gates_passed: list[str] = field(default_factory=list)
    gates_failed: list[str] = field(default_factory=list)

    # Metadata
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    validated_at: datetime | None = None

    @property
    def final_severity(self) -> Severity:
        """Get the final severity after all adjustments."""
        return self.adjusted_severity if self.adjusted_severity else self.initial_severity

    @property
    def escalation_count(self) -> int:
        """Get number of escalation attempts."""
        return len(self.escalation_attempts)

    @property
    def has_successful_escalation(self) -> bool:
        """Check if any escalation attempts were successful."""
        return len(self.escalation_successes) > 0

    @property
    def met_escalation_requirement(self) -> bool:
        """Check if escalation requirement is met."""
        return self.escalation_count >= self.escalation_required

    def add_escalation_attempt(self, attempt: EscalationAttempt) -> None:
        """Add an escalation attempt."""
        self.escalation_attempts.append(attempt)
        self.escalation_documented = True

    def add_escalation_success(self, success: EscalationSuccess) -> None:
        """Add a successful escalation."""
        self.escalation_successes.append(success)

    def add_context_adjustment(self, adjustment: ContextAdjustment) -> None:
        """Add a technology context adjustment."""
        self.context_adjustments.append(adjustment)

    def add_rejection_reason(self, reason: str) -> None:
        """Add a reason for rejection."""
        if reason not in self.rejection_reasons:
            self.rejection_reasons.append(reason)

    def mark_gate_passed(self, gate_name: str) -> None:
        """Mark a quality gate as passed."""
        if gate_name not in self.gates_passed:
            self.gates_passed.append(gate_name)

    def mark_gate_failed(self, gate_name: str, reason: str) -> None:
        """Mark a quality gate as failed."""
        if gate_name not in self.gates_failed:
            self.gates_failed.append(gate_name)
        self.add_rejection_reason(f"{gate_name}: {reason}")

    def approve(self, quality_score: float) -> None:
        """Approve finding for report inclusion."""
        self.approved_for_report = True
        self.quality_score = quality_score
        self.validated_at = datetime.now(UTC)

    def reject(self, reason: str) -> None:
        """Reject finding from report."""
        self.approved_for_report = False
        self.add_rejection_reason(reason)
        self.validated_at = datetime.now(UTC)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "initial_severity": self.initial_severity.value,
            "affected_asset": self.affected_asset,
            "evidence": self.evidence,
            "vuln_type": self.vuln_type,
            "attacker_action": self.attacker_action,
            "concrete_impact": self.concrete_impact,
            "exploitability_proof": self.exploitability_proof,
            "technology_context": self.technology_context,
            "is_public_by_design": self.is_public_by_design,
            "context_adjustments": [adj.to_dict() for adj in self.context_adjustments],
            "escalation_attempts": [att.to_dict() for att in self.escalation_attempts],
            "escalation_required": self.escalation_required,
            "escalation_successes": [suc.to_dict() for suc in self.escalation_successes],
            "adjusted_severity": self.adjusted_severity.value if self.adjusted_severity else None,
            "severity_rationale": self.severity_rationale,
            "has_theoretical_language": self.has_theoretical_language,
            "is_production": self.is_production,
            "impact_demonstrated": self.impact_demonstrated,
            "escalation_documented": self.escalation_documented,
            "data_intentionally_public": self.data_intentionally_public,
            "approved_for_report": self.approved_for_report,
            "rejection_reasons": self.rejection_reasons,
            "quality_score": self.quality_score,
            "gates_passed": self.gates_passed,
            "gates_failed": self.gates_failed,
            "discovered_at": self.discovered_at.isoformat(),
            "validated_at": self.validated_at.isoformat() if self.validated_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FindingCandidate:
        """Create from dictionary."""
        return cls(
            title=data["title"],
            description=data["description"],
            initial_severity=Severity(data["initial_severity"]),
            affected_asset=data["affected_asset"],
            evidence=data["evidence"],
            vuln_type=data["vuln_type"],
            attacker_action=data.get("attacker_action", ""),
            concrete_impact=data.get("concrete_impact", ""),
            exploitability_proof=data.get("exploitability_proof", ""),
            technology_context=data.get("technology_context", ""),
            is_public_by_design=data.get("is_public_by_design", False),
            context_adjustments=[
                ContextAdjustment.from_dict(adj) for adj in data.get("context_adjustments", [])
            ],
            escalation_attempts=[
                EscalationAttempt.from_dict(att) for att in data.get("escalation_attempts", [])
            ],
            escalation_required=data.get("escalation_required", 3),
            escalation_successes=[
                EscalationSuccess.from_dict(suc) for suc in data.get("escalation_successes", [])
            ],
            adjusted_severity=Severity(data["adjusted_severity"])
            if data.get("adjusted_severity")
            else None,
            severity_rationale=data.get("severity_rationale", ""),
            has_theoretical_language=data.get("has_theoretical_language", False),
            is_production=data.get("is_production", False),
            impact_demonstrated=data.get("impact_demonstrated", False),
            escalation_documented=data.get("escalation_documented", False),
            data_intentionally_public=data.get("data_intentionally_public", False),
            approved_for_report=data.get("approved_for_report", False),
            rejection_reasons=data.get("rejection_reasons", []),
            quality_score=data.get("quality_score", 0.0),
            gates_passed=data.get("gates_passed", []),
            gates_failed=data.get("gates_failed", []),
            discovered_at=datetime.fromisoformat(data["discovered_at"])
            if "discovered_at" in data
            else datetime.now(UTC),
            validated_at=datetime.fromisoformat(data["validated_at"])
            if data.get("validated_at")
            else None,
        )
