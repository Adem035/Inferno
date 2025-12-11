"""
Differential Analyzer for Inferno.

Compares responses to detect subtle differences indicating vulnerabilities.
Essential for blind injection detection, timing attacks, and error-based discovery.

Key features:
- Response length comparison
- Timing difference detection
- Content diff analysis
- Error message variations
- Header change detection
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class DifferenceType(str, Enum):
    """Types of differences detected."""

    LENGTH = "length"  # Response length differs
    TIMING = "timing"  # Response time differs
    STATUS = "status"  # Status code differs
    CONTENT = "content"  # Content differs
    HEADERS = "headers"  # Headers differ
    ERROR = "error"  # Error message differs
    STRUCTURE = "structure"  # HTML/JSON structure differs


class VulnerabilityIndicator(str, Enum):
    """What the difference might indicate."""

    BLIND_SQLI = "blind_sqli"
    BLIND_XXEI = "blind_xxe"
    BLIND_SSRF = "blind_ssrf"
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    OUT_OF_BAND = "out_of_band"
    NONE = "none"


@dataclass
class ResponseFingerprint:
    """Fingerprint of a response for comparison."""

    url: str
    status_code: int
    content_length: int
    response_time: float  # in seconds
    content_hash: str  # SHA256 of body
    headers_hash: str  # SHA256 of sorted headers
    word_count: int
    line_count: int
    error_patterns: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_response(
        cls,
        url: str,
        status_code: int,
        body: str,
        headers: dict[str, str],
        response_time: float,
    ) -> ResponseFingerprint:
        """Create fingerprint from response data."""
        # Hash content
        content_hash = hashlib.sha256(body.encode()).hexdigest()

        # Hash headers (sorted for consistency)
        headers_str = str(sorted(headers.items()))
        headers_hash = hashlib.sha256(headers_str.encode()).hexdigest()

        # Extract error patterns
        error_patterns = []
        error_regexes = [
            r"error",
            r"exception",
            r"warning",
            r"failed",
            r"invalid",
            r"denied",
        ]
        for pattern in error_regexes:
            if re.search(pattern, body, re.I):
                error_patterns.append(pattern)

        return cls(
            url=url,
            status_code=status_code,
            content_length=len(body),
            response_time=response_time,
            content_hash=content_hash,
            headers_hash=headers_hash,
            word_count=len(body.split()),
            line_count=body.count("\n") + 1,
            error_patterns=error_patterns,
        )


@dataclass
class Difference:
    """A detected difference between responses."""

    diff_type: DifferenceType
    baseline_value: Any
    test_value: Any
    significance: float  # 0.0-1.0, how significant is this difference
    description: str
    possible_indicator: VulnerabilityIndicator = VulnerabilityIndicator.NONE


@dataclass
class DifferentialResult:
    """Result of differential analysis."""

    is_different: bool
    differences: list[Difference] = field(default_factory=list)
    overall_significance: float = 0.0
    likely_vulnerability: VulnerabilityIndicator = VulnerabilityIndicator.NONE
    confidence: float = 0.0
    recommendation: str = ""


class DifferentialAnalyzer:
    """
    Analyze differences between baseline and test responses.

    Used for:
    - Blind SQL injection (boolean-based, time-based)
    - Blind XXE
    - SSRF detection
    - Any vulnerability requiring response comparison
    """

    # Thresholds for significance
    LENGTH_THRESHOLD_PERCENT = 5.0  # % difference in length to flag
    TIMING_THRESHOLD_SECONDS = 3.0  # Seconds difference for timing attacks
    TIMING_THRESHOLD_RATIO = 2.0  # Ratio difference for timing attacks

    def __init__(self) -> None:
        """Initialize the differential analyzer."""
        self._baselines: dict[str, ResponseFingerprint] = {}

    def store_baseline(
        self,
        key: str,
        fingerprint: ResponseFingerprint,
    ) -> None:
        """
        Store a baseline response for comparison.

        Args:
            key: Unique key for this baseline (e.g., URL + param combo)
            fingerprint: The response fingerprint
        """
        self._baselines[key] = fingerprint
        logger.debug("baseline_stored", key=key, length=fingerprint.content_length)

    def get_baseline(self, key: str) -> ResponseFingerprint | None:
        """Get a stored baseline."""
        return self._baselines.get(key)

    def compare(
        self,
        baseline: ResponseFingerprint,
        test: ResponseFingerprint,
        payload_context: str = "",
    ) -> DifferentialResult:
        """
        Compare two responses for significant differences.

        Args:
            baseline: The baseline (normal) response
            test: The test (potentially vulnerable) response
            payload_context: Description of what payload was used

        Returns:
            DifferentialResult with all detected differences
        """
        differences: list[Difference] = []

        # Status code comparison
        if baseline.status_code != test.status_code:
            diff = Difference(
                diff_type=DifferenceType.STATUS,
                baseline_value=baseline.status_code,
                test_value=test.status_code,
                significance=0.9,
                description=f"Status changed: {baseline.status_code} -> {test.status_code}",
                possible_indicator=VulnerabilityIndicator.ERROR_BASED,
            )
            differences.append(diff)

        # Length comparison
        length_diff = abs(baseline.content_length - test.content_length)
        if baseline.content_length > 0:
            length_percent = (length_diff / baseline.content_length) * 100
        else:
            length_percent = 100 if test.content_length > 0 else 0

        if length_percent >= self.LENGTH_THRESHOLD_PERCENT:
            diff = Difference(
                diff_type=DifferenceType.LENGTH,
                baseline_value=baseline.content_length,
                test_value=test.content_length,
                significance=min(length_percent / 100, 1.0),
                description=f"Length differs by {length_diff} bytes ({length_percent:.1f}%)",
                possible_indicator=VulnerabilityIndicator.BOOLEAN_BASED,
            )
            differences.append(diff)

        # Timing comparison
        timing_diff = test.response_time - baseline.response_time
        timing_ratio = test.response_time / max(baseline.response_time, 0.001)

        if (timing_diff >= self.TIMING_THRESHOLD_SECONDS or
            timing_ratio >= self.TIMING_THRESHOLD_RATIO):
            diff = Difference(
                diff_type=DifferenceType.TIMING,
                baseline_value=baseline.response_time,
                test_value=test.response_time,
                significance=min(timing_diff / 10, 1.0),  # Cap at 10 seconds
                description=f"Response time: {baseline.response_time:.2f}s -> {test.response_time:.2f}s ({timing_ratio:.1f}x)",
                possible_indicator=VulnerabilityIndicator.TIME_BASED,
            )
            differences.append(diff)

        # Content hash comparison
        if baseline.content_hash != test.content_hash:
            diff = Difference(
                diff_type=DifferenceType.CONTENT,
                baseline_value=baseline.content_hash[:16],
                test_value=test.content_hash[:16],
                significance=0.7,
                description="Response content differs",
                possible_indicator=VulnerabilityIndicator.BOOLEAN_BASED,
            )
            differences.append(diff)

        # Error pattern comparison
        new_errors = set(test.error_patterns) - set(baseline.error_patterns)
        removed_errors = set(baseline.error_patterns) - set(test.error_patterns)

        if new_errors:
            diff = Difference(
                diff_type=DifferenceType.ERROR,
                baseline_value=baseline.error_patterns,
                test_value=test.error_patterns,
                significance=0.85,
                description=f"New error patterns: {', '.join(new_errors)}",
                possible_indicator=VulnerabilityIndicator.ERROR_BASED,
            )
            differences.append(diff)

        # Word count comparison (useful for boolean-based detection)
        word_diff = abs(baseline.word_count - test.word_count)
        if word_diff > 10:  # Significant word count change
            diff = Difference(
                diff_type=DifferenceType.STRUCTURE,
                baseline_value=baseline.word_count,
                test_value=test.word_count,
                significance=min(word_diff / 100, 0.8),
                description=f"Word count differs by {word_diff}",
                possible_indicator=VulnerabilityIndicator.BOOLEAN_BASED,
            )
            differences.append(diff)

        # Calculate overall results
        is_different = len(differences) > 0
        overall_significance = max((d.significance for d in differences), default=0.0)

        # Determine most likely vulnerability type
        likely_vuln = VulnerabilityIndicator.NONE
        vuln_counts: dict[VulnerabilityIndicator, int] = {}

        for diff in differences:
            if diff.possible_indicator != VulnerabilityIndicator.NONE:
                vuln_counts[diff.possible_indicator] = vuln_counts.get(
                    diff.possible_indicator, 0
                ) + 1

        if vuln_counts:
            likely_vuln = max(vuln_counts, key=lambda k: vuln_counts[k])

        # Generate recommendation
        recommendation = self._generate_recommendation(
            differences, likely_vuln, payload_context
        )

        result = DifferentialResult(
            is_different=is_different,
            differences=differences,
            overall_significance=overall_significance,
            likely_vulnerability=likely_vuln,
            confidence=overall_significance,
            recommendation=recommendation,
        )

        if is_different:
            logger.info(
                "differential_analysis_complete",
                is_different=is_different,
                num_differences=len(differences),
                likely_vuln=likely_vuln.value,
                significance=overall_significance,
            )

        return result

    def _generate_recommendation(
        self,
        differences: list[Difference],
        likely_vuln: VulnerabilityIndicator,
        payload_context: str,
    ) -> str:
        """Generate actionable recommendation based on analysis."""
        if not differences:
            return "No significant differences detected. Try different payloads."

        recommendations = {
            VulnerabilityIndicator.TIME_BASED: (
                "Timing difference detected! This suggests time-based blind injection. "
                "Try: SLEEP() for MySQL, pg_sleep() for PostgreSQL, WAITFOR DELAY for MSSQL. "
                "Increase sleep time to confirm (e.g., 5s, 10s)."
            ),
            VulnerabilityIndicator.BOOLEAN_BASED: (
                "Boolean-based difference detected! Response changes based on condition. "
                "Try: Compare true condition (1=1) vs false (1=2). "
                "Extract data character by character using binary search."
            ),
            VulnerabilityIndicator.ERROR_BASED: (
                "Error-based difference detected! Errors reveal information. "
                "Try: extractvalue(), updatexml() for MySQL. "
                "CAST/CONVERT errors for data extraction."
            ),
            VulnerabilityIndicator.BLIND_SQLI: (
                "Blind SQL injection indicators present. "
                "Combine boolean and time-based techniques for confirmation. "
                "Use tools: sqlmap --technique=B, sqlmap --technique=T"
            ),
        }

        if likely_vuln in recommendations:
            return recommendations[likely_vuln]

        # Generic recommendation based on difference types
        diff_types = [d.diff_type for d in differences]

        if DifferenceType.TIMING in diff_types:
            return "Timing anomaly detected. Investigate with time-based payloads."
        elif DifferenceType.LENGTH in diff_types:
            return "Content length varies. Test with boolean conditions to confirm injection."
        elif DifferenceType.ERROR in diff_types:
            return "Error behavior changed. Analyze error messages for information leakage."

        return "Differences detected. Further investigation recommended."

    def analyze_timing_series(
        self,
        url: str,
        times: list[float],
        labels: list[str],
    ) -> dict[str, Any]:
        """
        Analyze a series of timing measurements.

        Useful for detecting time-based blind injection with multiple samples.

        Args:
            url: The URL being tested
            times: List of response times
            labels: Labels for each measurement (e.g., payload used)

        Returns:
            Analysis results with timing anomalies
        """
        if len(times) < 2:
            return {"anomalies": [], "baseline_avg": 0}

        # Calculate baseline (assuming most requests are normal)
        sorted_times = sorted(times)
        # Use median as baseline (robust to outliers)
        median_time = sorted_times[len(sorted_times) // 2]

        anomalies = []
        for i, (t, label) in enumerate(zip(times, labels)):
            if t > median_time * 2 or t > median_time + 3:  # 2x or +3s
                anomalies.append({
                    "index": i,
                    "time": t,
                    "label": label,
                    "deviation": t - median_time,
                    "ratio": t / median_time,
                })

        return {
            "baseline_avg": median_time,
            "min_time": min(times),
            "max_time": max(times),
            "anomalies": anomalies,
            "likely_injectable": len(anomalies) > 0,
        }

    def create_fingerprint(
        self,
        url: str,
        status_code: int,
        body: str,
        headers: dict[str, str],
        response_time: float,
    ) -> ResponseFingerprint:
        """Convenience method to create a fingerprint."""
        return ResponseFingerprint.from_response(
            url=url,
            status_code=status_code,
            body=body,
            headers=headers,
            response_time=response_time,
        )


# Global singleton
_differential_analyzer: DifferentialAnalyzer | None = None


def get_differential_analyzer() -> DifferentialAnalyzer:
    """Get the global differential analyzer instance."""
    global _differential_analyzer
    if _differential_analyzer is None:
        _differential_analyzer = DifferentialAnalyzer()
    return _differential_analyzer
