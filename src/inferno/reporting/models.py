"""
Report models for Inferno.

This module defines the data models for security assessment findings
and reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def color(self) -> str:
        """Get color for severity."""
        colors = {
            Severity.CRITICAL: "#FF0000",
            Severity.HIGH: "#FF6600",
            Severity.MEDIUM: "#FFCC00",
            Severity.LOW: "#00CC00",
            Severity.INFO: "#0066FF",
        }
        return colors.get(self, "#000000")

    @property
    def score_range(self) -> tuple[float, float]:
        """Get CVSS score range for severity."""
        ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0),
        }
        return ranges.get(self, (0.0, 0.0))


@dataclass
class Finding:
    """A security finding from the assessment."""

    title: str
    description: str
    severity: Severity
    affected_asset: str
    evidence: str
    remediation: str
    cvss_score: float | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    proof_of_concept: str | None = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    # Quality gate metadata (optional, populated if quality gates enabled)
    quality_score: float = 0.0
    gates_passed: list[str] = field(default_factory=list)
    escalation_summary: str = ""
    technology_context: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "affected_asset": self.affected_asset,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "proof_of_concept": self.proof_of_concept,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
            "quality_score": self.quality_score,
            "gates_passed": self.gates_passed,
            "escalation_summary": self.escalation_summary,
            "technology_context": self.technology_context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Create from dictionary."""
        return cls(
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            affected_asset=data["affected_asset"],
            evidence=data["evidence"],
            remediation=data["remediation"],
            cvss_score=data.get("cvss_score"),
            cve_ids=data.get("cve_ids", []),
            cwe_ids=data.get("cwe_ids", []),
            references=data.get("references", []),
            proof_of_concept=data.get("proof_of_concept"),
            discovered_at=datetime.fromisoformat(data["discovered_at"]) if "discovered_at" in data else datetime.now(UTC),
            metadata=data.get("metadata", {}),
            quality_score=data.get("quality_score", 0.0),
            gates_passed=data.get("gates_passed", []),
            escalation_summary=data.get("escalation_summary", ""),
            technology_context=data.get("technology_context", ""),
        )


@dataclass
class ReportMetadata:
    """Metadata for the assessment report."""

    operation_id: str
    target: str
    objective: str
    scope: str
    assessor: str = "Inferno AI"
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    turns_used: int = 0
    tokens_used: int = 0
    methodology: str = "Automated AI-driven penetration testing"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "operation_id": self.operation_id,
            "target": self.target,
            "objective": self.objective,
            "scope": self.scope,
            "assessor": self.assessor,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "turns_used": self.turns_used,
            "tokens_used": self.tokens_used,
            "methodology": self.methodology,
        }


@dataclass
class Report:
    """Complete security assessment report."""

    metadata: ReportMetadata
    findings: list[Finding] = field(default_factory=list)
    executive_summary: str = ""
    technical_summary: str = ""
    recommendations: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of medium findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of low findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Count of informational findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        if not self.findings:
            return 0.0

        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 15,
            Severity.LOW: 5,
            Severity.INFO: 1,
        }

        total_weight = sum(weights[f.severity] for f in self.findings)
        max_possible = len(self.findings) * weights[Severity.CRITICAL]

        return min(100.0, (total_weight / max_possible) * 100) if max_possible > 0 else 0.0

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the report."""
        self.findings.append(finding)

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "executive_summary": self.executive_summary,
            "technical_summary": self.technical_summary,
            "recommendations": self.recommendations,
            "artifacts": self.artifacts,
            "statistics": {
                "total_findings": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "risk_score": self.risk_score,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Report:
        """Create from dictionary."""
        metadata_data = data["metadata"]
        metadata = ReportMetadata(
            operation_id=metadata_data["operation_id"],
            target=metadata_data["target"],
            objective=metadata_data["objective"],
            scope=metadata_data["scope"],
            assessor=metadata_data.get("assessor", "Inferno AI"),
            started_at=datetime.fromisoformat(metadata_data["started_at"]),
            completed_at=datetime.fromisoformat(metadata_data["completed_at"]) if metadata_data.get("completed_at") else None,
            duration_seconds=metadata_data.get("duration_seconds", 0),
            turns_used=metadata_data.get("turns_used", 0),
            tokens_used=metadata_data.get("tokens_used", 0),
        )

        return cls(
            metadata=metadata,
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            executive_summary=data.get("executive_summary", ""),
            technical_summary=data.get("technical_summary", ""),
            recommendations=data.get("recommendations", []),
            artifacts=data.get("artifacts", []),
        )
