"""Escalation engine for finding impact demonstration.

This module provides automated escalation strategies to demonstrate the maximum
impact of discovered vulnerabilities for bug bounty submissions.
"""

from inferno.quality.escalation.base import (
    BaseEscalationStrategy,
    EscalationAttempt,
    EscalationResult,
    FindingCandidate,
)
from inferno.quality.escalation.chaining import ChainingStrategy
from inferno.quality.escalation.horizontal import HorizontalEscalation
from inferno.quality.escalation.permission import PermissionTestingStrategy
from inferno.quality.escalation.vertical import VerticalEscalation

__all__ = [
    "BaseEscalationStrategy",
    "ChainingStrategy",
    "EscalationAttempt",
    "EscalationResult",
    "FindingCandidate",
    "HorizontalEscalation",
    "PermissionTestingStrategy",
    "VerticalEscalation",
]
