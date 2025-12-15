"""
Performance Assessment Framework for Inferno.

Implements the unified scoring metric from the paper:
"Comparing AI Agents to Cybersecurity Professionals in Real-World Penetration Testing"

Scoring Formula:
    S_total = Σ(TC_i + W_i)

Where:
    TC_i = Technical Complexity = DC_i + EC_i (if exploited)
                                = DC_i + (EC_i × 0.8) (if only verified)
    W_i = Weighted Criticality (Business Impact)

Detection Complexity (DC): How hard is it to detect the vulnerability?
Exploit Complexity (EC): How technically complex is the exploit?
Business Impact (W): What's the potential business damage?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from inferno.core.mitre_attack import ATTACKMapping

logger = structlog.get_logger(__name__)


class VulnerabilitySeverity(str, Enum):
    """Severity levels aligned with CVSS."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def business_impact_weight(self) -> int:
        """
        Get business impact weight (W) for this severity.

        Mirrors exponential reward structures in bug bounty programs.
        """
        weights = {
            VulnerabilitySeverity.CRITICAL: 8,
            VulnerabilitySeverity.HIGH: 5,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFORMATIONAL: 1,
        }
        return weights[self]


class ExploitationStatus(str, Enum):
    """Status of vulnerability exploitation."""

    EXPLOITED = "exploited"  # Full exploitation with demonstrated impact
    VERIFIED = "verified"  # Confirmed existence but not exploited
    SUSPECTED = "suspected"  # Potential vulnerability, needs confirmation
    FALSE_POSITIVE = "false_positive"  # Confirmed not vulnerable


class DetectionDifficulty(str, Enum):
    """How difficult the vulnerability was to detect."""

    TRIVIAL = "trivial"  # Obvious, found by automated scanner
    EASY = "easy"  # Basic manual testing
    MODERATE = "moderate"  # Requires understanding of app logic
    HARD = "hard"  # Requires deep analysis/chain of findings
    EXPERT = "expert"  # Novel technique or complex chain


class ExploitDifficulty(str, Enum):
    """How difficult the vulnerability was to exploit."""

    TRIVIAL = "trivial"  # One-click exploit, public PoC
    EASY = "easy"  # Standard technique, minimal customization
    MODERATE = "moderate"  # Requires bypass/customization
    HARD = "hard"  # Custom exploit development
    EXPERT = "expert"  # Novel technique, significant research


# Complexity score mappings (1-10 scale)
DETECTION_COMPLEXITY_SCORES = {
    DetectionDifficulty.TRIVIAL: 1,
    DetectionDifficulty.EASY: 3,
    DetectionDifficulty.MODERATE: 5,
    DetectionDifficulty.HARD: 7,
    DetectionDifficulty.EXPERT: 10,
}

EXPLOIT_COMPLEXITY_SCORES = {
    ExploitDifficulty.TRIVIAL: 1,
    ExploitDifficulty.EASY: 3,
    ExploitDifficulty.MODERATE: 5,
    ExploitDifficulty.HARD: 7,
    ExploitDifficulty.EXPERT: 10,
}


@dataclass
class TechnicalComplexityScore:
    """
    Technical Complexity (TC) score for a finding.

    TC = DC + EC (if exploited)
    TC = DC + (EC × 0.8) (if only verified, 20% penalty)
    """

    detection_complexity: int  # DC: 1-10
    exploit_complexity: int  # EC: 1-10
    exploitation_status: ExploitationStatus

    @property
    def score(self) -> float:
        """
        Calculate Technical Complexity score.

        Returns:
            TC score (2-20 range for exploited, slightly less for verified)
        """
        dc = self.detection_complexity
        ec = self.exploit_complexity

        if self.exploitation_status == ExploitationStatus.EXPLOITED:
            # Full credit for exploitation
            return dc + ec
        elif self.exploitation_status == ExploitationStatus.VERIFIED:
            # 20% penalty on EC for verification-only
            return dc + (ec * 0.8)
        else:
            # Suspected or false positive get minimal credit
            return dc * 0.5

    @property
    def normalized_score(self) -> float:
        """Get score normalized to 0-1 range."""
        # Max possible score is 20 (DC=10 + EC=10)
        return self.score / 20.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "detection_complexity": self.detection_complexity,
            "exploit_complexity": self.exploit_complexity,
            "exploitation_status": self.exploitation_status.value,
            "score": self.score,
            "normalized_score": self.normalized_score,
        }


@dataclass
class VulnerabilityScore:
    """
    Complete scoring for a single vulnerability finding.

    S_i = TC_i + W_i
    """

    # Core components
    technical_complexity: TechnicalComplexityScore
    severity: VulnerabilitySeverity

    # Optional metadata
    vuln_type: str = ""
    attack_technique_ids: list[str] = field(default_factory=list)
    attack_tactic_ids: list[str] = field(default_factory=list)

    # Timing
    discovered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    exploited_at: datetime | None = None

    @property
    def business_impact_weight(self) -> int:
        """Get business impact weight (W)."""
        return self.severity.business_impact_weight

    @property
    def total_score(self) -> float:
        """
        Calculate total score for this finding.

        S_i = TC_i + W_i
        """
        return self.technical_complexity.score + self.business_impact_weight

    @property
    def weighted_score(self) -> float:
        """
        Calculate weighted score emphasizing business impact.

        This variant weights business impact more heavily for
        prioritization purposes.
        """
        tc = self.technical_complexity.score
        w = self.business_impact_weight
        # Weight business impact 1.5x
        return tc + (w * 1.5)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technical_complexity": self.technical_complexity.to_dict(),
            "severity": self.severity.value,
            "business_impact_weight": self.business_impact_weight,
            "total_score": self.total_score,
            "weighted_score": self.weighted_score,
            "vuln_type": self.vuln_type,
            "attack_technique_ids": self.attack_technique_ids,
            "attack_tactic_ids": self.attack_tactic_ids,
            "discovered_at": self.discovered_at.isoformat(),
            "exploited_at": self.exploited_at.isoformat() if self.exploited_at else None,
        }


@dataclass
class AssessmentScore:
    """
    Total assessment score aggregating all findings.

    S_total = Σ(TC_i + W_i) for all findings i
    """

    finding_scores: list[VulnerabilityScore] = field(default_factory=list)
    assessment_id: str = ""
    target: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    def add_finding(self, score: VulnerabilityScore) -> None:
        """Add a finding score to the assessment."""
        self.finding_scores.append(score)

    @property
    def total_score(self) -> float:
        """
        Calculate S_total = Σ(TC_i + W_i).
        """
        return sum(f.total_score for f in self.finding_scores)

    @property
    def weighted_total(self) -> float:
        """Calculate weighted total emphasizing business impact."""
        return sum(f.weighted_score for f in self.finding_scores)

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.finding_scores)

    @property
    def exploited_count(self) -> int:
        """Number of exploited findings."""
        return sum(
            1 for f in self.finding_scores
            if f.technical_complexity.exploitation_status == ExploitationStatus.EXPLOITED
        )

    @property
    def verified_count(self) -> int:
        """Number of verified (but not exploited) findings."""
        return sum(
            1 for f in self.finding_scores
            if f.technical_complexity.exploitation_status == ExploitationStatus.VERIFIED
        )

    @property
    def exploitation_rate(self) -> float:
        """Percentage of findings that were exploited."""
        if not self.finding_scores:
            return 0.0
        return self.exploited_count / self.finding_count

    @property
    def severity_breakdown(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {s.value: 0 for s in VulnerabilitySeverity}
        for f in self.finding_scores:
            counts[f.severity.value] += 1
        return counts

    @property
    def tactic_coverage(self) -> dict[str, int]:
        """Count findings by ATT&CK tactic."""
        coverage: dict[str, int] = {}
        for f in self.finding_scores:
            for tactic_id in f.attack_tactic_ids:
                coverage[tactic_id] = coverage.get(tactic_id, 0) + 1
        return coverage

    @property
    def average_technical_complexity(self) -> float:
        """Average TC score across findings."""
        if not self.finding_scores:
            return 0.0
        return sum(f.technical_complexity.score for f in self.finding_scores) / self.finding_count

    @property
    def max_single_finding_score(self) -> float:
        """Highest individual finding score."""
        if not self.finding_scores:
            return 0.0
        return max(f.total_score for f in self.finding_scores)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_id": self.assessment_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_score": self.total_score,
            "weighted_total": self.weighted_total,
            "finding_count": self.finding_count,
            "exploited_count": self.exploited_count,
            "verified_count": self.verified_count,
            "exploitation_rate": self.exploitation_rate,
            "severity_breakdown": self.severity_breakdown,
            "tactic_coverage": self.tactic_coverage,
            "average_technical_complexity": self.average_technical_complexity,
            "max_single_finding_score": self.max_single_finding_score,
            "findings": [f.to_dict() for f in self.finding_scores],
        }

    def to_summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "=" * 60,
            "PERFORMANCE ASSESSMENT SCORE",
            "=" * 60,
            f"Target: {self.target}",
            f"Assessment ID: {self.assessment_id}",
            "",
            f"TOTAL SCORE (S_total): {self.total_score:.1f}",
            f"Weighted Score: {self.weighted_total:.1f}",
            "",
            "FINDINGS BREAKDOWN:",
            f"  Total Findings: {self.finding_count}",
            f"  Exploited: {self.exploited_count}",
            f"  Verified Only: {self.verified_count}",
            f"  Exploitation Rate: {self.exploitation_rate:.1%}",
            "",
            "SEVERITY DISTRIBUTION:",
        ]

        for severity, count in self.severity_breakdown.items():
            if count > 0:
                lines.append(f"  {severity.upper()}: {count}")

        lines.extend([
            "",
            "METRICS:",
            f"  Average Technical Complexity: {self.average_technical_complexity:.1f}",
            f"  Max Single Finding Score: {self.max_single_finding_score:.1f}",
        ])

        if self.tactic_coverage:
            lines.extend([
                "",
                "ATT&CK TACTIC COVERAGE:",
            ])
            for tactic_id, count in sorted(self.tactic_coverage.items()):
                lines.append(f"  {tactic_id}: {count} findings")

        lines.append("=" * 60)

        return "\n".join(lines)


# =============================================================================
# Scoring Factory Functions
# =============================================================================

def create_vulnerability_score(
    vuln_type: str,
    severity: str | VulnerabilitySeverity,
    exploitation_status: str | ExploitationStatus,
    detection_difficulty: str | DetectionDifficulty | int,
    exploit_difficulty: str | ExploitDifficulty | int,
    attack_mapping: ATTACKMapping | None = None,
) -> VulnerabilityScore:
    """
    Factory function to create a VulnerabilityScore.

    Args:
        vuln_type: Type of vulnerability (e.g., "sqli", "xss")
        severity: Severity level
        exploitation_status: Whether exploited or just verified
        detection_difficulty: How hard to detect (enum, string, or 1-10)
        exploit_difficulty: How hard to exploit (enum, string, or 1-10)
        attack_mapping: Optional ATT&CK mapping for technique IDs

    Returns:
        VulnerabilityScore instance
    """
    # Convert severity
    if isinstance(severity, str):
        severity = VulnerabilitySeverity(severity.lower())

    # Convert exploitation status
    if isinstance(exploitation_status, str):
        exploitation_status = ExploitationStatus(exploitation_status.lower())

    # Convert detection difficulty to int score
    if isinstance(detection_difficulty, DetectionDifficulty):
        dc_score = DETECTION_COMPLEXITY_SCORES[detection_difficulty]
    elif isinstance(detection_difficulty, str):
        dc_score = DETECTION_COMPLEXITY_SCORES[DetectionDifficulty(detection_difficulty.lower())]
    else:
        dc_score = max(1, min(10, detection_difficulty))

    # Convert exploit difficulty to int score
    if isinstance(exploit_difficulty, ExploitDifficulty):
        ec_score = EXPLOIT_COMPLEXITY_SCORES[exploit_difficulty]
    elif isinstance(exploit_difficulty, str):
        ec_score = EXPLOIT_COMPLEXITY_SCORES[ExploitDifficulty(exploit_difficulty.lower())]
    else:
        ec_score = max(1, min(10, exploit_difficulty))

    # Create technical complexity score
    tc = TechnicalComplexityScore(
        detection_complexity=dc_score,
        exploit_complexity=ec_score,
        exploitation_status=exploitation_status,
    )

    # Get ATT&CK info if provided
    technique_ids = []
    tactic_ids = []
    if attack_mapping:
        technique_ids = attack_mapping.technique_ids
        tactic_ids = attack_mapping.tactic_ids

    return VulnerabilityScore(
        technical_complexity=tc,
        severity=severity,
        vuln_type=vuln_type,
        attack_technique_ids=technique_ids,
        attack_tactic_ids=tactic_ids,
    )


def score_from_finding(
    vuln_type: str,
    severity: str,
    exploited: bool,
    confidence: int = 80,
) -> VulnerabilityScore:
    """
    Quick scoring from basic finding info.

    Uses heuristics to estimate complexity scores based on
    vulnerability type and confidence.

    Args:
        vuln_type: Vulnerability type
        severity: Severity level
        exploited: Whether successfully exploited
        confidence: Confidence level 0-100

    Returns:
        VulnerabilityScore instance
    """
    from inferno.core.mitre_attack import map_finding_to_attack

    # Map to ATT&CK
    attack_mapping = map_finding_to_attack(vuln_type)

    # Use ATT&CK complexity scores if available
    dc = attack_mapping.detection_complexity
    ec = attack_mapping.exploit_complexity

    # Adjust based on confidence
    if confidence < 50:
        dc = max(1, dc - 2)  # Less confident = probably easier to detect
    elif confidence > 90:
        dc = min(10, dc + 1)  # High confidence may mean subtle finding

    # Determine exploitation status
    if exploited:
        status = ExploitationStatus.EXPLOITED
    elif confidence >= 70:
        status = ExploitationStatus.VERIFIED
    else:
        status = ExploitationStatus.SUSPECTED

    tc = TechnicalComplexityScore(
        detection_complexity=dc,
        exploit_complexity=ec,
        exploitation_status=status,
    )

    return VulnerabilityScore(
        technical_complexity=tc,
        severity=VulnerabilitySeverity(severity.lower()),
        vuln_type=vuln_type,
        attack_technique_ids=attack_mapping.technique_ids,
        attack_tactic_ids=attack_mapping.tactic_ids,
    )


def estimate_complexity_from_vuln_type(vuln_type: str) -> tuple[int, int]:
    """
    Estimate DC and EC scores from vulnerability type.

    Uses the ATT&CK mapping database for complexity scores.

    Args:
        vuln_type: Vulnerability type

    Returns:
        Tuple of (detection_complexity, exploit_complexity)
    """
    from inferno.core.mitre_attack import map_finding_to_attack

    mapping = map_finding_to_attack(vuln_type)
    return (mapping.detection_complexity, mapping.exploit_complexity)


# =============================================================================
# Assessment Scorer Class
# =============================================================================

class AssessmentScorer:
    """
    Manages scoring throughout an assessment.

    Integrates with the main agent loop to track and score findings
    in real-time.
    """

    def __init__(self, assessment_id: str, target: str) -> None:
        """
        Initialize scorer.

        Args:
            assessment_id: Unique assessment identifier
            target: Target being assessed
        """
        self._score = AssessmentScore(
            assessment_id=assessment_id,
            target=target,
        )
        self._logger = structlog.get_logger(__name__)

    def add_finding(
        self,
        vuln_type: str,
        severity: str,
        exploited: bool = False,
        confidence: int = 80,
        detection_difficulty: int | None = None,
        exploit_difficulty: int | None = None,
    ) -> VulnerabilityScore:
        """
        Add and score a finding.

        Args:
            vuln_type: Type of vulnerability
            severity: Severity level
            exploited: Whether successfully exploited
            confidence: Confidence level
            detection_difficulty: Override DC score
            exploit_difficulty: Override EC score

        Returns:
            The created VulnerabilityScore
        """
        # Get base scores from heuristics
        if detection_difficulty is None or exploit_difficulty is None:
            est_dc, est_ec = estimate_complexity_from_vuln_type(vuln_type)
            detection_difficulty = detection_difficulty or est_dc
            exploit_difficulty = exploit_difficulty or est_ec

        # Create score
        score = create_vulnerability_score(
            vuln_type=vuln_type,
            severity=severity,
            exploitation_status="exploited" if exploited else ("verified" if confidence >= 70 else "suspected"),
            detection_difficulty=detection_difficulty,
            exploit_difficulty=exploit_difficulty,
        )

        self._score.add_finding(score)

        self._logger.info(
            "finding_scored",
            vuln_type=vuln_type,
            severity=severity,
            total_score=score.total_score,
            tc_score=score.technical_complexity.score,
            business_impact=score.business_impact_weight,
            assessment_total=self._score.total_score,
        )

        return score

    def mark_finding_exploited(self, finding_index: int) -> None:
        """Mark a finding as exploited (upgrades from verified)."""
        if 0 <= finding_index < len(self._score.finding_scores):
            finding = self._score.finding_scores[finding_index]
            finding.technical_complexity.exploitation_status = ExploitationStatus.EXPLOITED
            finding.exploited_at = datetime.now(UTC)

            self._logger.info(
                "finding_upgraded_to_exploited",
                index=finding_index,
                new_score=finding.total_score,
            )

    def complete_assessment(self) -> AssessmentScore:
        """Mark assessment as complete and return final score."""
        self._score.completed_at = datetime.now(UTC)

        self._logger.info(
            "assessment_completed",
            total_score=self._score.total_score,
            finding_count=self._score.finding_count,
            exploited_count=self._score.exploited_count,
            exploitation_rate=self._score.exploitation_rate,
        )

        return self._score

    @property
    def current_score(self) -> AssessmentScore:
        """Get current score (may be incomplete)."""
        return self._score

    def get_summary(self) -> str:
        """Get human-readable summary."""
        return self._score.to_summary()


# =============================================================================
# Rich Report Generation
# =============================================================================

def generate_scoring_report(
    findings: list[dict[str, Any]],
    target: str,
    operation_id: str,
) -> dict[str, Any]:
    """
    Generate a comprehensive scoring report from a list of findings.

    This function takes raw finding dictionaries and produces a complete
    scoring report with MITRE ATT&CK mapping and Performance Assessment metrics.

    Args:
        findings: List of finding dictionaries with vuln_type, severity, etc.
        target: Target that was assessed
        operation_id: Assessment operation ID

    Returns:
        Comprehensive scoring report dictionary
    """
    scorer = AssessmentScorer(operation_id, target)

    for finding in findings:
        vuln_type = finding.get("vuln_type") or finding.get("type") or "unknown"
        severity = finding.get("severity", "medium")
        exploited = finding.get("exploitation_status") == "exploited" or finding.get("exploited", False)
        confidence = finding.get("confidence", 80)
        dc = finding.get("detection_complexity")
        ec = finding.get("exploit_complexity")

        scorer.add_finding(
            vuln_type=vuln_type,
            severity=severity,
            exploited=exploited,
            confidence=confidence,
            detection_difficulty=dc,
            exploit_difficulty=ec,
        )

    final_score = scorer.complete_assessment()
    return final_score.to_dict()


def format_scoring_report_text(score_data: dict[str, Any]) -> str:
    """
    Format scoring data as human-readable text report.

    Args:
        score_data: Dictionary from AssessmentScore.to_dict()

    Returns:
        Formatted text report
    """
    lines = [
        "",
        "=" * 70,
        "PERFORMANCE ASSESSMENT FRAMEWORK REPORT",
        "=" * 70,
        "",
        f"Assessment ID: {score_data.get('assessment_id', 'N/A')}",
        f"Target: {score_data.get('target', 'N/A')}",
        "",
        "-" * 70,
        "UNIFIED SCORING (S_total = Σ(TC_i + W_i))",
        "-" * 70,
        "",
        f"  TOTAL SCORE: {score_data.get('total_score', 0):.1f}",
        f"  Weighted Total: {score_data.get('weighted_total', 0):.1f}",
        "",
        "-" * 70,
        "FINDINGS ANALYSIS",
        "-" * 70,
        "",
        f"  Total Findings: {score_data.get('finding_count', 0)}",
        f"  Fully Exploited: {score_data.get('exploited_count', 0)}",
        f"  Verification Only: {score_data.get('verified_count', 0)}",
        f"  Exploitation Rate: {score_data.get('exploitation_rate', 0):.1%}",
        "",
    ]

    # Severity breakdown
    severity_breakdown = score_data.get("severity_breakdown", {})
    if severity_breakdown:
        lines.extend([
            "-" * 70,
            "SEVERITY DISTRIBUTION",
            "-" * 70,
            "",
        ])
        for sev, count in severity_breakdown.items():
            if count > 0:
                weight = {"critical": 8, "high": 5, "medium": 3, "low": 2, "informational": 1}.get(sev, 1)
                lines.append(f"  {sev.upper():15s}: {count:3d} (Business Impact Weight: {weight})")
        lines.append("")

    # Technical metrics
    lines.extend([
        "-" * 70,
        "TECHNICAL METRICS",
        "-" * 70,
        "",
        f"  Average Technical Complexity: {score_data.get('average_technical_complexity', 0):.1f}",
        f"  Max Single Finding Score: {score_data.get('max_single_finding_score', 0):.1f}",
        "",
    ])

    # ATT&CK tactic coverage
    tactic_coverage = score_data.get("tactic_coverage", {})
    if tactic_coverage:
        lines.extend([
            "-" * 70,
            "MITRE ATT&CK TACTIC COVERAGE",
            "-" * 70,
            "",
        ])

        # Map tactic IDs to names
        tactic_names = {
            "TA0043": "Reconnaissance",
            "TA0042": "Resource Development",
            "TA0001": "Initial Access",
            "TA0002": "Execution",
            "TA0003": "Persistence",
            "TA0004": "Privilege Escalation",
            "TA0005": "Defense Evasion",
            "TA0006": "Credential Access",
            "TA0007": "Discovery",
            "TA0008": "Lateral Movement",
            "TA0009": "Collection",
            "TA0010": "Exfiltration",
            "TA0011": "Command and Control",
            "TA0040": "Impact",
        }

        for tactic_id, count in sorted(tactic_coverage.items()):
            tactic_name = tactic_names.get(tactic_id, tactic_id)
            lines.append(f"  {tactic_id} ({tactic_name}): {count} findings")
        lines.append("")

    lines.extend([
        "=" * 70,
        "END OF PERFORMANCE ASSESSMENT REPORT",
        "=" * 70,
        "",
    ])

    return "\n".join(lines)


def calculate_benchmark_percentile(total_score: float, finding_count: int) -> dict[str, Any]:
    """
    Calculate benchmark percentile for the assessment.

    Based on typical penetration testing results:
    - Average automated scan: 5-15 score
    - Junior pentester: 15-40 score
    - Senior pentester: 40-80 score
    - Expert pentester: 80+ score

    Args:
        total_score: Total assessment score
        finding_count: Number of findings

    Returns:
        Benchmark analysis dictionary
    """
    # Score per finding (quality metric)
    avg_score_per_finding = total_score / finding_count if finding_count > 0 else 0

    # Determine tier
    if total_score >= 80:
        tier = "expert"
        percentile = min(99, 90 + (total_score - 80) * 0.5)
    elif total_score >= 40:
        tier = "senior"
        percentile = 70 + (total_score - 40) * 0.5
    elif total_score >= 15:
        tier = "junior"
        percentile = 40 + (total_score - 15) * 1.2
    else:
        tier = "automated"
        percentile = total_score * 2.67

    return {
        "tier": tier,
        "percentile": min(99, max(1, percentile)),
        "avg_score_per_finding": avg_score_per_finding,
        "interpretation": {
            "expert": "Results comparable to expert penetration testers",
            "senior": "Results comparable to senior penetration testers",
            "junior": "Results comparable to junior penetration testers",
            "automated": "Results comparable to automated scanning tools",
        }[tier],
    }
