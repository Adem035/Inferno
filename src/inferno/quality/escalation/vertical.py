"""Vertical escalation strategy for privilege elevation.

This strategy attempts to access administrative functions or higher-privileged
resources using discovered credentials or tokens.
"""

import logging
from typing import Any

from inferno.quality.escalation.base import (
    BaseEscalationStrategy,
    EscalationAttempt,
    EscalationResult,
    FindingCandidate,
)
from inferno.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


class VerticalEscalation(BaseEscalationStrategy):
    """Vertical privilege escalation to admin access.

    Tests access to administrative endpoints using discovered credentials:
    - Common admin paths (/admin, /wp-admin, /dashboard, etc.)
    - API admin endpoints (/api/admin, /api/v1/admin)
    - Management interfaces
    """

    # Admin endpoints to test
    ADMIN_ENDPOINTS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/administrator/",
        "/wp-admin",
        "/wp-admin/",
        "/manage",
        "/manage/",
        "/dashboard",
        "/dashboard/",
        "/api/admin",
        "/api/admin/",
        "/api/v1/admin",
        "/api/v1/admin/",
        "/backend",
        "/backend/",
        "/control-panel",
        "/control-panel/",
        "/cpanel",
        "/cpanel/",
        "/admin/dashboard",
        "/admin/users",
        "/admin/settings",
    ]

    async def is_applicable(self, candidate: FindingCandidate) -> bool:
        """Check if vertical escalation applies to this finding.

        Args:
            candidate: The finding to evaluate

        Returns:
            True for all authenticated findings (we attempt vertical escalation
            on any finding that might provide credentials or tokens)
        """
        # Applicable to any finding that might provide credentials
        vuln_lower = candidate.vuln_type.lower()
        high_priority = {
            "auth",
            "idor",
            "sqli",
            "jwt",
            "session",
            "token",
            "credential",
            "password",
        }

        # High priority if vulnerability type contains auth-related terms
        if any(term in vuln_lower for term in high_priority):
            return True

        # Also applicable if evidence contains tokens or credentials
        evidence_lower = candidate.evidence.lower()
        return any(
            indicator in evidence_lower
            for indicator in ["token", "jwt", "session", "cookie", "password", "api_key"]
        )

    async def attempt(
        self, candidate: FindingCandidate, target: str | None = None
    ) -> EscalationAttempt:
        """Attempt vertical escalation to admin access.

        Args:
            candidate: The finding to escalate
            target: Optional specific target URL

        Returns:
            Record of the escalation attempt
        """
        target_url = target or candidate.target_url
        logger.info(f"Attempting vertical escalation on {target_url}")

        # Extract base URL
        base_url = self._extract_base_url(target_url)
        if not base_url:
            return self._create_attempt(
                description="Could not extract base URL for admin endpoint testing",
                target=target_url,
                result=EscalationResult.NOT_APPLICABLE,
                evidence="Invalid or unparseable target URL",
            )

        # Extract credentials or tokens from evidence
        credentials = self._extract_credentials(candidate.evidence)
        headers = self._build_auth_headers(credentials)

        # Get HTTP tool
        registry = ToolRegistry()
        http_tool = registry.get("http_request")

        if not http_tool:
            return self._create_attempt(
                description="HTTP tool not available for testing",
                target=target_url,
                result=EscalationResult.FAILED,
                evidence="Cannot perform HTTP requests without http_request tool",
            )

        # Test admin endpoints
        accessible_endpoints = []
        for endpoint in self.ADMIN_ENDPOINTS:
            admin_url = f"{base_url}{endpoint}"

            try:
                result = await http_tool.execute(
                    url=admin_url, method="GET", headers=headers
                )

                if result.success:
                    status = result.data.get("status_code", 0)
                    body = result.data.get("body", "")

                    # Success indicators
                    if status == 200 and self._is_admin_page(body):
                        accessible_endpoints.append(endpoint)
                        logger.info(f"Successfully accessed admin endpoint: {endpoint}")

            except Exception as e:
                logger.debug(f"Error testing admin endpoint {endpoint}: {e}")
                continue

        if accessible_endpoints:
            return self._create_attempt(
                description=f"Vertical escalation: accessed {len(accessible_endpoints)} admin endpoint(s)",
                target=base_url,
                result=EscalationResult.SUCCESS,
                evidence="Accessible admin endpoints:\n"
                + "\n".join(f"- {base_url}{ep}" for ep in accessible_endpoints),
                token_tested=credentials.get("token") if credentials else None,
            )

        return self._create_attempt(
            description="No vertical escalation found with tested endpoints",
            target=base_url,
            result=EscalationResult.BLOCKED,
            evidence=f"Tested {len(self.ADMIN_ENDPOINTS)} admin endpoints, none accessible",
            token_tested=credentials.get("token") if credentials else None,
        )

    def _extract_base_url(self, url: str) -> str | None:
        """Extract base URL from full URL.

        Args:
            url: Full URL

        Returns:
            Base URL (scheme + host) or None
        """
        import re

        match = re.match(r"(https?://[^/]+)", url)
        return match.group(1) if match else None

    def _extract_credentials(self, evidence: str) -> dict[str, Any] | None:
        """Extract credentials or tokens from evidence.

        Args:
            evidence: Finding evidence text

        Returns:
            Dictionary of extracted credentials or None
        """
        import re

        credentials = {}

        # JWT token
        jwt_match = re.search(r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", evidence)
        if jwt_match:
            credentials["token"] = jwt_match.group(1)
            credentials["type"] = "jwt"

        # API key
        api_key_match = re.search(r"api[_-]?key[:\s=]+([A-Za-z0-9_-]+)", evidence, re.I)
        if api_key_match:
            credentials["api_key"] = api_key_match.group(1)
            credentials["type"] = "api_key"

        # Session token
        session_match = re.search(r"session[:\s=]+([A-Za-z0-9_-]+)", evidence, re.I)
        if session_match:
            credentials["session"] = session_match.group(1)
            credentials["type"] = "session"

        # Bearer token
        bearer_match = re.search(r"Bearer\s+([A-Za-z0-9_-]+)", evidence, re.I)
        if bearer_match:
            credentials["token"] = bearer_match.group(1)
            credentials["type"] = "bearer"

        return credentials if credentials else None

    def _build_auth_headers(self, credentials: dict[str, Any] | None) -> dict[str, str]:
        """Build authentication headers from credentials.

        Args:
            credentials: Extracted credentials

        Returns:
            Dictionary of HTTP headers
        """
        headers = {}

        if not credentials:
            return headers

        cred_type = credentials.get("type")

        if cred_type == "jwt" or cred_type == "bearer":
            headers["Authorization"] = f"Bearer {credentials.get('token')}"
        elif cred_type == "api_key":
            headers["X-API-Key"] = credentials.get("api_key")
        elif cred_type == "session":
            headers["Cookie"] = f"session={credentials.get('session')}"

        return headers

    def _is_admin_page(self, body: str) -> bool:
        """Check if response body indicates admin page.

        Args:
            body: HTTP response body

        Returns:
            True if page appears to be admin interface
        """
        admin_indicators = [
            "admin dashboard",
            "administration",
            "control panel",
            "admin panel",
            "user management",
            "system settings",
            "admin menu",
            "administrator",
        ]

        body_lower = body.lower()
        return any(indicator in body_lower for indicator in admin_indicators)
