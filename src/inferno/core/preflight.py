"""
Pre-flight validation for Inferno.

This module provides validation checks before starting an assessment
to catch configuration issues, missing dependencies, and connectivity
problems early.
"""

from __future__ import annotations

import shutil
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of a single validation check."""

    name: str
    passed: bool
    message: str
    severity: str = "error"  # "error", "warning", "info"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PreflightReport:
    """Complete pre-flight validation report."""

    passed: bool
    checks: list[ValidationResult]
    errors: int = 0
    warnings: int = 0

    def summary(self) -> str:
        """Generate a human-readable summary."""
        lines = ["Pre-flight Validation Report", "=" * 30]

        for check in self.checks:
            status = "✓" if check.passed else ("⚠" if check.severity == "warning" else "✗")
            lines.append(f"  {status} {check.name}: {check.message}")

        lines.append("")
        if self.passed:
            lines.append(f"All critical checks passed ({self.warnings} warnings)")
        else:
            lines.append(f"FAILED: {self.errors} errors, {self.warnings} warnings")

        return "\n".join(lines)


class PreflightValidator:
    """
    Pre-flight validation for Inferno assessments.

    Validates:
    - Target reachability
    - Required tools availability
    - Configuration validity
    - API connectivity
    - Memory/storage availability
    """

    def __init__(self) -> None:
        self._results: list[ValidationResult] = []

    async def validate(
        self,
        target: str | None = None,
        check_api: bool = True,
        check_tools: bool = True,
        check_network: bool = True,
        check_memory: bool = True,
    ) -> PreflightReport:
        """
        Run all pre-flight validation checks.

        Args:
            target: Target URL/IP to validate (optional)
            check_api: Check Anthropic API connectivity
            check_tools: Check required tools are installed
            check_network: Check network configuration
            check_memory: Check memory/Qdrant availability

        Returns:
            PreflightReport with all check results
        """
        self._results = []

        # Run validation checks
        if check_api:
            await self._check_api_key()

        if check_tools:
            await self._check_required_tools()

        if check_network:
            await self._check_network_config()

        if check_memory:
            await self._check_memory_backend()

        if target:
            await self._check_target_reachability(target)

        # Compile report
        errors = sum(1 for r in self._results if not r.passed and r.severity == "error")
        warnings = sum(1 for r in self._results if not r.passed and r.severity == "warning")

        return PreflightReport(
            passed=errors == 0,
            checks=self._results,
            errors=errors,
            warnings=warnings,
        )

    async def _check_api_key(self) -> None:
        """Check Anthropic API key is configured."""
        try:
            from inferno.config.settings import InfernoSettings
            settings = InfernoSettings()

            if settings.anthropic_api_key:
                self._results.append(ValidationResult(
                    name="API Key",
                    passed=True,
                    message="Anthropic API key configured",
                    severity="info",
                ))
            else:
                # Check for OAuth
                import os
                oauth_file = os.path.expanduser("~/.inferno/oauth_token")
                if os.path.exists(oauth_file):
                    self._results.append(ValidationResult(
                        name="API Key",
                        passed=True,
                        message="OAuth authentication configured",
                        severity="info",
                    ))
                else:
                    self._results.append(ValidationResult(
                        name="API Key",
                        passed=False,
                        message="No API key or OAuth token found. Run 'inferno auth login' or set ANTHROPIC_API_KEY",
                        severity="error",
                    ))
        except Exception as e:
            self._results.append(ValidationResult(
                name="API Key",
                passed=False,
                message=f"Failed to check API key: {e}",
                severity="error",
            ))

    async def _check_required_tools(self) -> None:
        """Check that required system tools are available."""
        # Essential tools
        essential_tools = ["curl", "git"]
        # Optional but recommended tools
        optional_tools = ["nmap", "gobuster", "sqlmap", "hydra", "nikto", "nuclei"]

        for tool in essential_tools:
            if shutil.which(tool):
                self._results.append(ValidationResult(
                    name=f"Tool: {tool}",
                    passed=True,
                    message=f"{tool} is available",
                    severity="info",
                ))
            else:
                self._results.append(ValidationResult(
                    name=f"Tool: {tool}",
                    passed=False,
                    message=f"{tool} not found in PATH (required)",
                    severity="error",
                ))

        missing_optional = []
        for tool in optional_tools:
            if not shutil.which(tool):
                missing_optional.append(tool)

        if missing_optional:
            self._results.append(ValidationResult(
                name="Optional Tools",
                passed=True,  # Not critical
                message=f"Missing optional tools: {', '.join(missing_optional)}",
                severity="warning",
                details={"missing": missing_optional},
            ))
        else:
            self._results.append(ValidationResult(
                name="Optional Tools",
                passed=True,
                message="All recommended security tools are available",
                severity="info",
            ))

    async def _check_network_config(self) -> None:
        """Check network configuration."""
        try:
            from inferno.config.settings import InfernoSettings
            settings = InfernoSettings()

            # Check SSL verification setting
            if not settings.network.verify_ssl:
                self._results.append(ValidationResult(
                    name="SSL Verification",
                    passed=True,
                    message="SSL verification DISABLED (insecure but may be needed for testing)",
                    severity="warning",
                ))
            else:
                self._results.append(ValidationResult(
                    name="SSL Verification",
                    passed=True,
                    message="SSL verification enabled",
                    severity="info",
                ))

            # Check rate limiting
            if settings.network.rate_limit_mode == "aggressive":
                self._results.append(ValidationResult(
                    name="Rate Limiting",
                    passed=True,
                    message="Aggressive rate limiting (may trigger WAF)",
                    severity="warning",
                ))
            else:
                self._results.append(ValidationResult(
                    name="Rate Limiting",
                    passed=True,
                    message=f"Rate limiting mode: {settings.network.rate_limit_mode}",
                    severity="info",
                ))

        except Exception as e:
            self._results.append(ValidationResult(
                name="Network Config",
                passed=False,
                message=f"Failed to check network config: {e}",
                severity="warning",
            ))

    async def _check_memory_backend(self) -> None:
        """Check memory/Qdrant availability."""
        try:
            from inferno.config.settings import InfernoSettings
            settings = InfernoSettings()

            if not settings.memory.use_mem0:
                self._results.append(ValidationResult(
                    name="Memory Backend",
                    passed=True,
                    message="Using in-memory storage (no persistence)",
                    severity="warning",
                ))
                return

            # Try to connect to Qdrant
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((settings.memory.qdrant_host, settings.memory.qdrant_port))
                sock.close()

                if result == 0:
                    self._results.append(ValidationResult(
                        name="Memory Backend",
                        passed=True,
                        message=f"Qdrant reachable at {settings.memory.qdrant_host}:{settings.memory.qdrant_port}",
                        severity="info",
                    ))
                else:
                    self._results.append(ValidationResult(
                        name="Memory Backend",
                        passed=True,  # Not critical - fallback to in-memory
                        message=f"Qdrant not reachable - using in-memory fallback",
                        severity="warning",
                    ))
            except Exception:
                self._results.append(ValidationResult(
                    name="Memory Backend",
                    passed=True,
                    message="Qdrant connection failed - using in-memory fallback",
                    severity="warning",
                ))

        except Exception as e:
            self._results.append(ValidationResult(
                name="Memory Backend",
                passed=True,
                message=f"Memory check failed: {e} - using defaults",
                severity="warning",
            ))

    async def _check_target_reachability(self, target: str) -> None:
        """Check if target is reachable."""
        try:
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path

            # Remove port if present
            if ":" in host:
                host = host.split(":")[0]

            # Try DNS resolution
            try:
                ip = socket.gethostbyname(host)
                self._results.append(ValidationResult(
                    name="Target DNS",
                    passed=True,
                    message=f"Target {host} resolves to {ip}",
                    severity="info",
                ))
            except socket.gaierror:
                self._results.append(ValidationResult(
                    name="Target DNS",
                    passed=False,
                    message=f"Cannot resolve target hostname: {host}",
                    severity="error",
                ))
                return

            # Try TCP connection
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    self._results.append(ValidationResult(
                        name="Target Connectivity",
                        passed=True,
                        message=f"Target {host}:{port} is reachable",
                        severity="info",
                    ))
                else:
                    self._results.append(ValidationResult(
                        name="Target Connectivity",
                        passed=False,
                        message=f"Cannot connect to target {host}:{port}",
                        severity="error",
                    ))
            except Exception as e:
                self._results.append(ValidationResult(
                    name="Target Connectivity",
                    passed=False,
                    message=f"Connection to target failed: {e}",
                    severity="error",
                ))

        except Exception as e:
            self._results.append(ValidationResult(
                name="Target Check",
                passed=False,
                message=f"Failed to check target: {e}",
                severity="error",
            ))


async def run_preflight(
    target: str | None = None,
    verbose: bool = False,
) -> PreflightReport:
    """
    Run pre-flight validation checks.

    Args:
        target: Target to validate (optional)
        verbose: Print verbose output

    Returns:
        PreflightReport with results
    """
    validator = PreflightValidator()
    report = await validator.validate(target=target)

    if verbose:
        print(report.summary())

    return report
