"""
Comprehensive tests for the Performance Assessment Framework.

Tests the Stanford paper's unified scoring metric implementation:
S_total = Σ(TC_i + W_i)

Where:
- TC_i = Technical Complexity = DC + EC (exploited) or DC + EC*0.8 (verified)
- W_i = Business Impact Weight (Critical=8, High=5, Medium=3, Low=2, Info=1)
"""

import pytest
from datetime import datetime, timezone

from inferno.core.assessment_scoring import (
    VulnerabilitySeverity,
    ExploitationStatus,
    DetectionDifficulty,
    ExploitDifficulty,
    TechnicalComplexityScore,
    VulnerabilityScore,
    AssessmentScore,
    AssessmentScorer,
    DETECTION_COMPLEXITY_SCORES,
    EXPLOIT_COMPLEXITY_SCORES,
    create_vulnerability_score,
    score_from_finding,
    estimate_complexity_from_vuln_type,
    generate_scoring_report,
    format_scoring_report_text,
    calculate_benchmark_percentile,
)


# =============================================================================
# Business Impact Weight Tests (W_i)
# =============================================================================

class TestBusinessImpactWeights:
    """Test W_i weights match Stanford paper Section 3.2."""

    def test_critical_weight(self):
        """Critical vulnerabilities have W=8."""
        assert VulnerabilitySeverity.CRITICAL.business_impact_weight == 8

    def test_high_weight(self):
        """High vulnerabilities have W=5."""
        assert VulnerabilitySeverity.HIGH.business_impact_weight == 5

    def test_medium_weight(self):
        """Medium vulnerabilities have W=3."""
        assert VulnerabilitySeverity.MEDIUM.business_impact_weight == 3

    def test_low_weight(self):
        """Low vulnerabilities have W=2."""
        assert VulnerabilitySeverity.LOW.business_impact_weight == 2

    def test_informational_weight(self):
        """Informational vulnerabilities have W=1."""
        assert VulnerabilitySeverity.INFORMATIONAL.business_impact_weight == 1


# =============================================================================
# Detection Complexity Score Tests (DC)
# =============================================================================

class TestDetectionComplexityScores:
    """Test DC scores on 1-10 scale."""

    def test_trivial_detection(self):
        """Trivial detection = 1 (automated scanner finds it)."""
        assert DETECTION_COMPLEXITY_SCORES[DetectionDifficulty.TRIVIAL] == 1

    def test_easy_detection(self):
        """Easy detection = 3 (basic manual testing)."""
        assert DETECTION_COMPLEXITY_SCORES[DetectionDifficulty.EASY] == 3

    def test_moderate_detection(self):
        """Moderate detection = 5 (app logic understanding)."""
        assert DETECTION_COMPLEXITY_SCORES[DetectionDifficulty.MODERATE] == 5

    def test_hard_detection(self):
        """Hard detection = 7 (deep analysis/chaining)."""
        assert DETECTION_COMPLEXITY_SCORES[DetectionDifficulty.HARD] == 7

    def test_expert_detection(self):
        """Expert detection = 10 (novel technique)."""
        assert DETECTION_COMPLEXITY_SCORES[DetectionDifficulty.EXPERT] == 10


# =============================================================================
# Exploit Complexity Score Tests (EC)
# =============================================================================

class TestExploitComplexityScores:
    """Test EC scores on 1-10 scale."""

    def test_trivial_exploit(self):
        """Trivial exploit = 1 (one-click, public PoC)."""
        assert EXPLOIT_COMPLEXITY_SCORES[ExploitDifficulty.TRIVIAL] == 1

    def test_easy_exploit(self):
        """Easy exploit = 3 (standard technique)."""
        assert EXPLOIT_COMPLEXITY_SCORES[ExploitDifficulty.EASY] == 3

    def test_moderate_exploit(self):
        """Moderate exploit = 5 (requires bypass)."""
        assert EXPLOIT_COMPLEXITY_SCORES[ExploitDifficulty.MODERATE] == 5

    def test_hard_exploit(self):
        """Hard exploit = 7 (custom development)."""
        assert EXPLOIT_COMPLEXITY_SCORES[ExploitDifficulty.HARD] == 7

    def test_expert_exploit(self):
        """Expert exploit = 10 (novel technique)."""
        assert EXPLOIT_COMPLEXITY_SCORES[ExploitDifficulty.EXPERT] == 10


# =============================================================================
# Technical Complexity Score Tests (TC)
# =============================================================================

class TestTechnicalComplexityScore:
    """Test TC = DC + EC (exploited) or DC + EC*0.8 (verified)."""

    def test_exploited_full_credit(self):
        """Exploited findings get TC = DC + EC (full credit)."""
        tc = TechnicalComplexityScore(
            detection_complexity=5,
            exploit_complexity=5,
            exploitation_status=ExploitationStatus.EXPLOITED
        )
        assert tc.score == 10.0  # 5 + 5

    def test_verified_20_percent_penalty(self):
        """Verified findings get TC = DC + EC*0.8 (20% penalty on EC)."""
        tc = TechnicalComplexityScore(
            detection_complexity=5,
            exploit_complexity=5,
            exploitation_status=ExploitationStatus.VERIFIED
        )
        assert tc.score == 9.0  # 5 + (5 * 0.8) = 5 + 4

    def test_suspected_minimal_credit(self):
        """Suspected findings get DC*0.5 (minimal credit)."""
        tc = TechnicalComplexityScore(
            detection_complexity=6,
            exploit_complexity=8,
            exploitation_status=ExploitationStatus.SUSPECTED
        )
        assert tc.score == 3.0  # 6 * 0.5

    def test_false_positive_minimal_credit(self):
        """False positives get DC*0.5 (minimal credit)."""
        tc = TechnicalComplexityScore(
            detection_complexity=6,
            exploit_complexity=8,
            exploitation_status=ExploitationStatus.FALSE_POSITIVE
        )
        assert tc.score == 3.0  # 6 * 0.5

    def test_max_tc_exploited(self):
        """Max TC = 20 (DC=10 + EC=10) for exploited."""
        tc = TechnicalComplexityScore(
            detection_complexity=10,
            exploit_complexity=10,
            exploitation_status=ExploitationStatus.EXPLOITED
        )
        assert tc.score == 20.0

    def test_max_tc_verified(self):
        """Max TC = 18 (DC=10 + EC*0.8) for verified."""
        tc = TechnicalComplexityScore(
            detection_complexity=10,
            exploit_complexity=10,
            exploitation_status=ExploitationStatus.VERIFIED
        )
        assert tc.score == 18.0  # 10 + (10 * 0.8)

    def test_min_tc_exploited(self):
        """Min TC = 2 (DC=1 + EC=1) for exploited."""
        tc = TechnicalComplexityScore(
            detection_complexity=1,
            exploit_complexity=1,
            exploitation_status=ExploitationStatus.EXPLOITED
        )
        assert tc.score == 2.0

    def test_normalized_score(self):
        """Normalized score is in range 0-1."""
        tc = TechnicalComplexityScore(
            detection_complexity=5,
            exploit_complexity=5,
            exploitation_status=ExploitationStatus.EXPLOITED
        )
        assert tc.normalized_score == 0.5  # 10/20

    def test_to_dict_includes_all_fields(self):
        """to_dict includes all required fields."""
        tc = TechnicalComplexityScore(
            detection_complexity=5,
            exploit_complexity=7,
            exploitation_status=ExploitationStatus.EXPLOITED
        )
        result = tc.to_dict()

        assert result["detection_complexity"] == 5
        assert result["exploit_complexity"] == 7
        assert result["exploitation_status"] == "exploited"
        assert result["score"] == 12.0
        assert result["normalized_score"] == 0.6


# =============================================================================
# Vulnerability Score Tests (S_i = TC_i + W_i)
# =============================================================================

class TestVulnerabilityScore:
    """Test S_i = TC_i + W_i for individual findings."""

    def test_critical_exploited_max_score(self):
        """Critical exploited vuln: TC=20, W=8, S=28."""
        tc = TechnicalComplexityScore(10, 10, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.CRITICAL
        )
        assert vs.total_score == 28.0  # 20 + 8

    def test_high_verified_score(self):
        """High verified vuln: TC=9, W=5, S=14."""
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.VERIFIED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.HIGH
        )
        assert vs.total_score == 14.0  # 9 + 5

    def test_medium_exploited_score(self):
        """Medium exploited vuln: TC=10, W=3, S=13."""
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.MEDIUM
        )
        assert vs.total_score == 13.0  # 10 + 3

    def test_low_verified_score(self):
        """Low verified vuln: TC=2.8, W=2, S=4.8."""
        tc = TechnicalComplexityScore(1, 2, ExploitationStatus.VERIFIED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.LOW
        )
        expected_tc = 1 + (2 * 0.8)  # 2.6
        assert vs.total_score == expected_tc + 2  # 4.6

    def test_informational_score(self):
        """Informational vuln: TC=2, W=1, S=3."""
        tc = TechnicalComplexityScore(1, 1, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.INFORMATIONAL
        )
        assert vs.total_score == 3.0  # 2 + 1

    def test_weighted_score_higher_than_total(self):
        """Weighted score emphasizes business impact (W*1.5)."""
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.CRITICAL
        )
        # weighted = TC + W*1.5 = 10 + 8*1.5 = 22
        assert vs.weighted_score == 22.0
        assert vs.weighted_score > vs.total_score

    def test_business_impact_weight_property(self):
        """business_impact_weight returns severity weight."""
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.HIGH
        )
        assert vs.business_impact_weight == 5

    def test_to_dict_includes_metadata(self):
        """to_dict includes vuln_type and ATT&CK IDs."""
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(
            technical_complexity=tc,
            severity=VulnerabilitySeverity.HIGH,
            vuln_type="sqli",
            attack_technique_ids=["T1190"],
            attack_tactic_ids=["TA0001"]
        )
        result = vs.to_dict()

        assert result["vuln_type"] == "sqli"
        assert "T1190" in result["attack_technique_ids"]
        assert "TA0001" in result["attack_tactic_ids"]
        assert result["total_score"] == 15.0
        assert result["business_impact_weight"] == 5


# =============================================================================
# Assessment Score Tests (S_total = Σ(TC_i + W_i))
# =============================================================================

class TestAssessmentScore:
    """Test S_total aggregation across all findings."""

    def test_empty_assessment_zero_score(self):
        """Empty assessment has zero score."""
        score = AssessmentScore()
        assert score.total_score == 0.0
        assert score.finding_count == 0

    def test_single_finding_total(self):
        """Single finding score equals total."""
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        vs = VulnerabilityScore(tc, VulnerabilitySeverity.HIGH)

        score = AssessmentScore()
        score.add_finding(vs)

        assert score.total_score == 15.0  # 10 + 5
        assert score.finding_count == 1

    def test_multiple_findings_sum(self):
        """S_total = Σ(TC_i + W_i) for multiple findings."""
        score = AssessmentScore()

        # Finding 1: Critical exploited (TC=20, W=8, S=28)
        tc1 = TechnicalComplexityScore(10, 10, ExploitationStatus.EXPLOITED)
        vs1 = VulnerabilityScore(tc1, VulnerabilitySeverity.CRITICAL)
        score.add_finding(vs1)

        # Finding 2: High verified (TC=9, W=5, S=14)
        tc2 = TechnicalComplexityScore(5, 5, ExploitationStatus.VERIFIED)
        vs2 = VulnerabilityScore(tc2, VulnerabilitySeverity.HIGH)
        score.add_finding(vs2)

        # Finding 3: Medium exploited (TC=10, W=3, S=13)
        tc3 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        vs3 = VulnerabilityScore(tc3, VulnerabilitySeverity.MEDIUM)
        score.add_finding(vs3)

        assert score.total_score == 55.0  # 28 + 14 + 13
        assert score.finding_count == 3

    def test_exploited_count(self):
        """exploited_count tracks fully exploited findings."""
        score = AssessmentScore()

        tc1 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        tc2 = TechnicalComplexityScore(5, 5, ExploitationStatus.VERIFIED)
        tc3 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)

        score.add_finding(VulnerabilityScore(tc1, VulnerabilitySeverity.HIGH))
        score.add_finding(VulnerabilityScore(tc2, VulnerabilitySeverity.HIGH))
        score.add_finding(VulnerabilityScore(tc3, VulnerabilitySeverity.HIGH))

        assert score.exploited_count == 2
        assert score.verified_count == 1

    def test_exploitation_rate(self):
        """Exploitation rate = exploited / total."""
        score = AssessmentScore()

        tc1 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        tc2 = TechnicalComplexityScore(5, 5, ExploitationStatus.VERIFIED)
        tc3 = TechnicalComplexityScore(5, 5, ExploitationStatus.VERIFIED)
        tc4 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)

        for tc in [tc1, tc2, tc3, tc4]:
            score.add_finding(VulnerabilityScore(tc, VulnerabilitySeverity.MEDIUM))

        assert score.exploitation_rate == 0.5  # 2/4

    def test_severity_breakdown(self):
        """severity_breakdown counts by severity level."""
        score = AssessmentScore()
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)

        score.add_finding(VulnerabilityScore(tc, VulnerabilitySeverity.CRITICAL))
        score.add_finding(VulnerabilityScore(tc, VulnerabilitySeverity.CRITICAL))
        score.add_finding(VulnerabilityScore(tc, VulnerabilitySeverity.HIGH))
        score.add_finding(VulnerabilityScore(tc, VulnerabilitySeverity.MEDIUM))

        breakdown = score.severity_breakdown
        assert breakdown["critical"] == 2
        assert breakdown["high"] == 1
        assert breakdown["medium"] == 1
        assert breakdown["low"] == 0

    def test_average_technical_complexity(self):
        """Average TC across findings."""
        score = AssessmentScore()

        # TC=10, TC=9, TC=8 -> avg=9
        tc1 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)  # 10
        tc2 = TechnicalComplexityScore(5, 5, ExploitationStatus.VERIFIED)   # 9
        tc3 = TechnicalComplexityScore(4, 4, ExploitationStatus.EXPLOITED)  # 8

        score.add_finding(VulnerabilityScore(tc1, VulnerabilitySeverity.HIGH))
        score.add_finding(VulnerabilityScore(tc2, VulnerabilitySeverity.HIGH))
        score.add_finding(VulnerabilityScore(tc3, VulnerabilitySeverity.HIGH))

        assert score.average_technical_complexity == 9.0

    def test_max_single_finding_score(self):
        """Max single finding score identifies highest impact."""
        score = AssessmentScore()

        tc1 = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        tc2 = TechnicalComplexityScore(10, 10, ExploitationStatus.EXPLOITED)

        score.add_finding(VulnerabilityScore(tc1, VulnerabilitySeverity.MEDIUM))  # 13
        score.add_finding(VulnerabilityScore(tc2, VulnerabilitySeverity.CRITICAL))  # 28

        assert score.max_single_finding_score == 28.0

    def test_tactic_coverage(self):
        """Tactic coverage tracks ATT&CK tactics."""
        score = AssessmentScore()
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)

        vs1 = VulnerabilityScore(tc, VulnerabilitySeverity.HIGH,
                                  attack_tactic_ids=["TA0001", "TA0002"])
        vs2 = VulnerabilityScore(tc, VulnerabilitySeverity.HIGH,
                                  attack_tactic_ids=["TA0001"])

        score.add_finding(vs1)
        score.add_finding(vs2)

        assert score.tactic_coverage["TA0001"] == 2
        assert score.tactic_coverage["TA0002"] == 1

    def test_to_summary_format(self):
        """to_summary generates readable text."""
        score = AssessmentScore(
            assessment_id="test_001",
            target="https://example.com"
        )
        tc = TechnicalComplexityScore(5, 5, ExploitationStatus.EXPLOITED)
        score.add_finding(VulnerabilityScore(tc, VulnerabilitySeverity.HIGH))

        summary = score.to_summary()

        assert "TOTAL SCORE (S_total)" in summary
        assert "15.0" in summary
        assert "https://example.com" in summary


# =============================================================================
# Factory Function Tests
# =============================================================================

class TestFactoryFunctions:
    """Test create_vulnerability_score and score_from_finding."""

    def test_create_vulnerability_score_with_strings(self):
        """Create score from string inputs."""
        vs = create_vulnerability_score(
            vuln_type="sqli",
            severity="high",
            exploitation_status="exploited",
            detection_difficulty="moderate",
            exploit_difficulty="moderate"
        )

        assert vs.severity == VulnerabilitySeverity.HIGH
        assert vs.technical_complexity.exploitation_status == ExploitationStatus.EXPLOITED
        assert vs.technical_complexity.detection_complexity == 5
        assert vs.technical_complexity.exploit_complexity == 5

    def test_create_vulnerability_score_with_enums(self):
        """Create score from enum inputs."""
        vs = create_vulnerability_score(
            vuln_type="xss",
            severity=VulnerabilitySeverity.MEDIUM,
            exploitation_status=ExploitationStatus.VERIFIED,
            detection_difficulty=DetectionDifficulty.EASY,
            exploit_difficulty=ExploitDifficulty.EASY
        )

        assert vs.severity == VulnerabilitySeverity.MEDIUM
        assert vs.technical_complexity.detection_complexity == 3
        assert vs.technical_complexity.exploit_complexity == 3

    def test_create_vulnerability_score_with_ints(self):
        """Create score from integer complexity values."""
        vs = create_vulnerability_score(
            vuln_type="rce",
            severity="critical",
            exploitation_status="exploited",
            detection_difficulty=8,
            exploit_difficulty=9
        )

        assert vs.technical_complexity.detection_complexity == 8
        assert vs.technical_complexity.exploit_complexity == 9

    def test_create_vulnerability_score_clamps_values(self):
        """Integer complexity values are clamped to 1-10."""
        vs = create_vulnerability_score(
            vuln_type="test",
            severity="low",
            exploitation_status="verified",
            detection_difficulty=0,  # Should clamp to 1
            exploit_difficulty=15    # Should clamp to 10
        )

        assert vs.technical_complexity.detection_complexity == 1
        assert vs.technical_complexity.exploit_complexity == 10


# =============================================================================
# AssessmentScorer Class Tests
# =============================================================================

class TestAssessmentScorer:
    """Test the AssessmentScorer manager class."""

    def test_add_finding_returns_score(self):
        """add_finding returns VulnerabilityScore."""
        scorer = AssessmentScorer("test_001", "https://example.com")
        result = scorer.add_finding(
            vuln_type="sqli",
            severity="high",
            exploited=True
        )

        assert isinstance(result, VulnerabilityScore)
        assert result.severity == VulnerabilitySeverity.HIGH

    def test_add_finding_increments_total(self):
        """Adding findings increments total score."""
        scorer = AssessmentScorer("test_001", "https://example.com")

        scorer.add_finding(vuln_type="sqli", severity="high", exploited=True)
        scorer.add_finding(vuln_type="xss", severity="medium", exploited=False)

        assert scorer.current_score.finding_count == 2
        assert scorer.current_score.total_score > 0

    def test_mark_finding_exploited(self):
        """mark_finding_exploited upgrades verified to exploited."""
        scorer = AssessmentScorer("test_001", "https://example.com")

        # Add verified finding
        scorer.add_finding(vuln_type="sqli", severity="high", exploited=False, confidence=80)
        initial_score = scorer.current_score.total_score

        # Upgrade to exploited
        scorer.mark_finding_exploited(0)

        # Score should increase (EC*0.8 -> EC*1.0)
        assert scorer.current_score.total_score > initial_score

    def test_complete_assessment_sets_timestamp(self):
        """complete_assessment sets completed_at."""
        scorer = AssessmentScorer("test_001", "https://example.com")
        scorer.add_finding(vuln_type="sqli", severity="high", exploited=True)

        result = scorer.complete_assessment()

        assert result.completed_at is not None
        assert isinstance(result.completed_at, datetime)

    def test_get_summary(self):
        """get_summary returns formatted string."""
        scorer = AssessmentScorer("test_001", "https://example.com")
        scorer.add_finding(vuln_type="sqli", severity="critical", exploited=True)

        summary = scorer.get_summary()

        assert "PERFORMANCE ASSESSMENT SCORE" in summary
        assert "critical" in summary.lower()


# =============================================================================
# Report Generation Tests
# =============================================================================

class TestReportGeneration:
    """Test report generation functions."""

    def test_generate_scoring_report(self):
        """Generate complete scoring report from findings list."""
        findings = [
            {"vuln_type": "sqli", "severity": "critical", "exploited": True},
            {"vuln_type": "xss", "severity": "high", "exploited": False, "confidence": 80},
            {"vuln_type": "idor", "severity": "medium", "exploitation_status": "exploited"},
        ]

        report = generate_scoring_report(
            findings=findings,
            target="https://example.com",
            operation_id="op_001"
        )

        assert report["finding_count"] == 3
        assert report["target"] == "https://example.com"
        assert report["total_score"] > 0
        assert len(report["findings"]) == 3

    def test_format_scoring_report_text(self):
        """Format report as human-readable text."""
        score_data = {
            "assessment_id": "test_001",
            "target": "https://example.com",
            "total_score": 55.0,
            "weighted_total": 65.0,
            "finding_count": 3,
            "exploited_count": 2,
            "verified_count": 1,
            "exploitation_rate": 0.67,
            "severity_breakdown": {"critical": 1, "high": 1, "medium": 1, "low": 0, "informational": 0},
            "average_technical_complexity": 10.0,
            "max_single_finding_score": 28.0,
            "tactic_coverage": {"TA0001": 2},
        }

        text = format_scoring_report_text(score_data)

        assert "PERFORMANCE ASSESSMENT FRAMEWORK REPORT" in text
        assert "55.0" in text
        assert "CRITICAL" in text
        assert "TA0001" in text


# =============================================================================
# Benchmark Percentile Tests
# =============================================================================

class TestBenchmarkPercentile:
    """Test benchmark percentile calculation."""

    def test_automated_tier(self):
        """Low scores are automated tier."""
        result = calculate_benchmark_percentile(10.0, 5)
        assert result["tier"] == "automated"
        assert result["percentile"] < 40

    def test_junior_tier(self):
        """Medium scores are junior tier."""
        result = calculate_benchmark_percentile(25.0, 5)
        assert result["tier"] == "junior"
        assert 40 <= result["percentile"] < 70

    def test_senior_tier(self):
        """Higher scores are senior tier."""
        result = calculate_benchmark_percentile(60.0, 10)
        assert result["tier"] == "senior"
        assert 70 <= result["percentile"] < 90

    def test_expert_tier(self):
        """Top scores are expert tier."""
        result = calculate_benchmark_percentile(100.0, 15)
        assert result["tier"] == "expert"
        assert result["percentile"] >= 90

    def test_avg_score_per_finding(self):
        """Calculates average score per finding."""
        result = calculate_benchmark_percentile(50.0, 10)
        assert result["avg_score_per_finding"] == 5.0

    def test_interpretation_included(self):
        """Includes interpretation string."""
        result = calculate_benchmark_percentile(50.0, 10)
        assert "interpretation" in result
        assert "penetration tester" in result["interpretation"].lower()


# =============================================================================
# Edge Cases and Integration Tests
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_findings_list(self):
        """Handle empty findings list gracefully."""
        report = generate_scoring_report([], "https://example.com", "op_001")
        assert report["finding_count"] == 0
        assert report["total_score"] == 0.0

    def test_zero_confidence_finding(self):
        """Zero confidence findings become suspected."""
        scorer = AssessmentScorer("test", "http://test")
        scorer.add_finding("test", "medium", exploited=False, confidence=0)

        finding = scorer.current_score.finding_scores[0]
        assert finding.technical_complexity.exploitation_status == ExploitationStatus.SUSPECTED

    def test_100_confidence_verified(self):
        """100% confidence non-exploited becomes verified."""
        scorer = AssessmentScorer("test", "http://test")
        scorer.add_finding("test", "high", exploited=False, confidence=100)

        finding = scorer.current_score.finding_scores[0]
        assert finding.technical_complexity.exploitation_status == ExploitationStatus.VERIFIED

    def test_unknown_vuln_type(self):
        """Unknown vuln types get default complexity scores."""
        vs = create_vulnerability_score(
            vuln_type="unknown_vuln_xyz",
            severity="medium",
            exploitation_status="exploited",
            detection_difficulty=5,
            exploit_difficulty=5
        )

        assert vs.total_score > 0  # Should still calculate

    def test_case_insensitive_severity(self):
        """Severity matching is case insensitive."""
        vs1 = create_vulnerability_score("test", "HIGH", "exploited", 5, 5)
        vs2 = create_vulnerability_score("test", "high", "exploited", 5, 5)
        vs3 = create_vulnerability_score("test", "High", "exploited", 5, 5)

        assert vs1.severity == vs2.severity == vs3.severity


# =============================================================================
# Formula Verification Tests (Stanford Paper 3.2)
# =============================================================================

class TestStanfordPaperFormulas:
    """Verify exact formulas from Stanford paper Section 3.2."""

    def test_formula_s_total(self):
        """Verify S_total = Σ(TC_i + W_i)."""
        score = AssessmentScore()

        # Three findings with known scores
        findings = [
            (10, 10, ExploitationStatus.EXPLOITED, VulnerabilitySeverity.CRITICAL),  # TC=20, W=8
            (5, 5, ExploitationStatus.VERIFIED, VulnerabilitySeverity.HIGH),         # TC=9, W=5
            (3, 3, ExploitationStatus.EXPLOITED, VulnerabilitySeverity.LOW),         # TC=6, W=2
        ]

        for dc, ec, status, sev in findings:
            tc = TechnicalComplexityScore(dc, ec, status)
            score.add_finding(VulnerabilityScore(tc, sev))

        # Manual calculation: (20+8) + (9+5) + (6+2) = 28 + 14 + 8 = 50
        assert score.total_score == 50.0

    def test_formula_tc_exploited(self):
        """Verify TC = DC + EC for exploited vulnerabilities."""
        tc = TechnicalComplexityScore(7, 8, ExploitationStatus.EXPLOITED)
        assert tc.score == 15.0  # 7 + 8

    def test_formula_tc_verified_penalty(self):
        """Verify TC = DC + (EC × 0.8) for verified vulnerabilities."""
        tc = TechnicalComplexityScore(7, 8, ExploitationStatus.VERIFIED)
        expected = 7 + (8 * 0.8)  # 7 + 6.4 = 13.4
        assert tc.score == expected

    def test_formula_business_impact_weights(self):
        """Verify exact W values from paper."""
        weights = {
            VulnerabilitySeverity.CRITICAL: 8,
            VulnerabilitySeverity.HIGH: 5,
            VulnerabilitySeverity.MEDIUM: 3,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFORMATIONAL: 1,
        }

        for severity, expected_weight in weights.items():
            assert severity.business_impact_weight == expected_weight

    def test_exploitation_vs_verification_difference(self):
        """Exploited findings score higher than verified."""
        exploited = TechnicalComplexityScore(5, 10, ExploitationStatus.EXPLOITED)
        verified = TechnicalComplexityScore(5, 10, ExploitationStatus.VERIFIED)

        # Difference should be EC * 0.2 = 10 * 0.2 = 2
        assert exploited.score - verified.score == 2.0
