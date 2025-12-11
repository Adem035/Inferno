"""
Quality gates for Bug Bounty finding validation.

This module provides specialized quality gates that validate security findings
against Bug Bounty program standards, filtering false positives and ensuring
high-quality submissions.

Available Gates:
    - SoWhatGate: Validates concrete impact and exploitability (blocking, weight=0.30)
    - TechnologyContextGate: Applies technology-specific filters (blocking, weight=0.20)
    - EscalationGate: Ensures findings are escalated to max impact (non-blocking, weight=0.25)
    - SeverityGate: Validates severity ratings (non-blocking, weight=0.15)
    - PreReportChecklistGate: Pre-report validation checklist (blocking, weight=0.10)

Example:
    >>> from inferno.quality.gates import SoWhatGate
    >>> from inferno.quality.candidate import FindingCandidate
    >>> from inferno.reporting.models import Severity
    >>>
    >>> gate = SoWhatGate()
    >>> candidate = FindingCandidate(
    ...     title="SQL Injection in Login",
    ...     description="Found SQLi vulnerability",
    ...     initial_severity=Severity.HIGH,
    ...     evidence="' OR '1'='1",
    ...     affected_asset="https://example.com/login",
    ...     vuln_type="sqli",
    ...     attacker_action="Bypassed authentication",
    ...     concrete_impact="Accessed 500 user accounts",
    ...     exploitability_proof="Successfully logged in as admin"
    ... )
    >>> passed, message = await gate.evaluate(candidate, "https://example.com")
    >>> print(f"Passed: {passed}, Message: {message}")
"""

from inferno.quality.gates.checklist import PreReportChecklistGate
from inferno.quality.gates.escalation import EscalationGate
from inferno.quality.gates.severity import SeverityGate
from inferno.quality.gates.so_what import SoWhatGate
from inferno.quality.gates.technology import TechnologyContextGate
from inferno.quality.gates.validation import ValidationGate, create_validation_gate

__all__ = [
    "SoWhatGate",
    "TechnologyContextGate",
    "EscalationGate",
    "SeverityGate",
    "PreReportChecklistGate",
    "ValidationGate",
    "create_validation_gate",
]
