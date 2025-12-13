"""Horizontal escalation strategy for IDOR and access control issues.

This strategy attempts to access resources belonging to other users by modifying
identifiers in URLs, parameters, or request bodies.
"""

import logging
import re
from typing import Any

from inferno.quality.escalation.base import (
    BaseEscalationStrategy,
    EscalationAttempt,
    EscalationResult,
    FindingCandidate,
)
from inferno.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class HorizontalEscalation(BaseEscalationStrategy):
    """Horizontal privilege escalation through IDOR testing.

    Tests access to other users' resources by modifying identifiers:
    - Numeric IDs (1, 2, 100, 999)
    - Common usernames (admin, test, user)
    - Random UUIDs
    - Sequential variations
    """

    # Test IDs to try for horizontal escalation
    TEST_IDS = [
        "1",
        "2",
        "100",
        "999",
        "admin",
        "administrator",
        "test",
        "user",
        "guest",
    ]

    # Vulnerability types this strategy applies to
    APPLICABLE_TYPES = {
        "idor",
        "auth_bypass",
        "info_disclosure",
        "broken_access_control",
        "missing_authorization",
    }

    async def is_applicable(self, candidate: FindingCandidate) -> bool:
        """Check if horizontal escalation applies to this finding.

        Args:
            candidate: The finding to evaluate

        Returns:
            True if finding involves access control or IDOR
        """
        vuln_lower = candidate.vuln_type.lower()
        return any(applicable in vuln_lower for applicable in self.APPLICABLE_TYPES)

    async def attempt(
        self, candidate: FindingCandidate, target: str | None = None
    ) -> EscalationAttempt:
        """Attempt horizontal escalation via IDOR testing.

        Args:
            candidate: The finding to escalate
            target: Optional specific target URL

        Returns:
            Record of the escalation attempt
        """
        target_url = target or candidate.target_url
        logger.info(f"Attempting horizontal escalation on {target_url}")

        # Try to use IDOR scanner tool if available
        registry = ToolRegistry()
        idor_tool = registry.get("idor_scanner")

        if idor_tool:
            try:
                result = await self._use_idor_scanner(
                    idor_tool, target_url, candidate.evidence
                )
                if result:
                    return result
            except Exception as e:
                logger.warning(f"IDOR scanner failed: {e}, falling back to manual testing")

        # Manual IDOR testing
        return await self._manual_idor_test(target_url, candidate)

    async def _use_idor_scanner(
        self, tool: Any, target_url: str, evidence: str
    ) -> EscalationAttempt | None:
        """Use the IDOR scanner tool if available.

        Args:
            tool: The IDOR scanner tool instance
            target_url: Target URL to scan
            evidence: Original finding evidence

        Returns:
            EscalationAttempt if scanner found issues, None otherwise
        """
        try:
            # Extract original ID from URL or evidence
            original_id = self._extract_id(target_url) or self._extract_id(evidence)

            result = await tool.execute(
                url=target_url,
                original_id=original_id,
                test_ids=self.TEST_IDS,
            )

            if result.success and result.data.get("vulnerable"):
                findings = result.data.get("findings", [])
                if findings:
                    evidence_parts = ["IDOR Scanner Results:"]
                    for finding in findings:
                        evidence_parts.append(
                            f"- ID {finding['test_id']}: {finding['status']}"
                        )

                    return self._create_attempt(
                        description=f"Horizontal escalation via IDOR to {len(findings)} other user(s)",
                        target=target_url,
                        result=EscalationResult.SUCCESS,
                        evidence="\n".join(evidence_parts),
                        payload=f"Test IDs: {', '.join(str(f['test_id']) for f in findings)}",
                    )

        except Exception as e:
            logger.warning(f"IDOR scanner execution failed: {e}")

        return None

    async def _manual_idor_test(
        self, target_url: str, candidate: FindingCandidate
    ) -> EscalationAttempt:
        """Manually test for IDOR by modifying IDs.

        Args:
            target_url: Target URL to test
            candidate: Original finding

        Returns:
            EscalationAttempt with results
        """
        # Extract potential ID from URL
        original_id = self._extract_id(target_url)
        if not original_id:
            return self._create_attempt(
                description="Could not identify ID parameter for horizontal escalation",
                target=target_url,
                result=EscalationResult.NOT_APPLICABLE,
                evidence="No numeric or UUID identifier found in URL or parameters",
            )

        # Try HTTP tool for testing
        registry = ToolRegistry()
        http_tool = registry.get("http_request")

        if not http_tool:
            return self._create_attempt(
                description="HTTP tool not available for testing",
                target=target_url,
                result=EscalationResult.FAILED,
                evidence="Cannot perform HTTP requests without http_request tool",
            )

        # Test different IDs
        accessible_ids = []
        for test_id in self.TEST_IDS:
            if str(test_id) == str(original_id):
                continue

            test_url = target_url.replace(str(original_id), str(test_id))

            try:
                result = await http_tool.execute(url=test_url, method="GET")

                if result.success:
                    status = result.data.get("status_code", 0)
                    if status == 200:
                        accessible_ids.append(test_id)
                        logger.info(f"Successfully accessed resource with ID {test_id}")

            except Exception as e:
                logger.debug(f"Error testing ID {test_id}: {e}")
                continue

        if accessible_ids:
            return self._create_attempt(
                description=f"Horizontal escalation: accessed {len(accessible_ids)} other user resource(s)",
                target=target_url,
                result=EscalationResult.SUCCESS,
                evidence=f"Original ID: {original_id}\nAccessible IDs: {', '.join(map(str, accessible_ids))}",
                payload=f"Test IDs: {', '.join(map(str, self.TEST_IDS))}",
            )

        return self._create_attempt(
            description="No horizontal escalation found with tested IDs",
            target=target_url,
            result=EscalationResult.BLOCKED,
            evidence=f"Tested {len(self.TEST_IDS)} different IDs, none accessible",
        )

    def _extract_id(self, text: str) -> str | None:
        """Extract potential ID from URL or text.

        Args:
            text: Text to search for IDs

        Returns:
            Extracted ID or None
        """
        # Try numeric ID
        numeric_match = re.search(r"/(\d+)(?:/|$|\?)", text)
        if numeric_match:
            return numeric_match.group(1)

        # Try UUID
        uuid_match = re.search(
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", text, re.I
        )
        if uuid_match:
            return uuid_match.group(1)

        # Try query parameter id
        param_match = re.search(r"[?&]id=([^&]+)", text, re.I)
        if param_match:
            return param_match.group(1)

        return None
