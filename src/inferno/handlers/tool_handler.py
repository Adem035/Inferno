"""
Tool event handlers for Inferno.

This module provides handlers for processing tool execution events,
including result parsing, artifact management, and finding extraction.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from inferno.handlers.base import Event, EventHandler, EventType

logger = structlog.get_logger(__name__)


class ToolResultHandler(EventHandler):
    """
    Handler for processing tool execution results.

    Responsibilities:
    - Parse tool output for structured data
    - Extract findings and vulnerabilities
    - Save artifacts to disk
    - Track tool execution history
    """

    def __init__(
        self,
        artifacts_dir: Path | None = None,
        save_raw_output: bool = True,
    ) -> None:
        """
        Initialize the tool result handler.

        Args:
            artifacts_dir: Directory for saving artifacts.
            save_raw_output: Whether to save raw tool output.
        """
        self._artifacts_dir = artifacts_dir
        self._save_raw = save_raw_output
        self._execution_history: list[dict[str, Any]] = []

    @property
    def name(self) -> str:
        return "tool_result_handler"

    @property
    def handles(self) -> list[EventType]:
        return [EventType.TOOL_COMPLETE, EventType.TOOL_ERROR]

    async def handle(self, event: Event) -> None:
        """Process tool execution events."""
        tool_name = event.data.get("tool_name", "unknown")
        output = event.data.get("output", "")
        success = event.data.get("success", False)

        # Log execution
        execution_record = {
            "tool": tool_name,
            "success": success,
            "timestamp": datetime.now(UTC).isoformat(),
            "output_length": len(output),
        }
        self._execution_history.append(execution_record)

        logger.info(
            "tool_execution_recorded",
            tool=tool_name,
            success=success,
        )

        # Save artifact if configured
        if self._save_raw and self._artifacts_dir and output:
            await self._save_artifact(tool_name, output)

        # Extract findings from output
        if success and output:
            findings = self._extract_findings(tool_name, output)
            if findings:
                event.data["findings"] = findings
                logger.info(
                    "findings_extracted",
                    tool=tool_name,
                    count=len(findings),
                )

    async def _save_artifact(self, tool_name: str, output: str) -> Path | None:
        """Save tool output as an artifact."""
        if not self._artifacts_dir:
            return None

        self._artifacts_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"{tool_name}_{timestamp}.txt"
        artifact_path = self._artifacts_dir / filename

        artifact_path.write_text(output, encoding="utf-8")
        logger.debug("artifact_saved", path=str(artifact_path))

        return artifact_path

    def _extract_findings(
        self,
        tool_name: str,
        output: str,
    ) -> list[dict[str, Any]]:
        """Extract structured findings from tool output."""
        findings = []

        # Tool-specific parsing
        if tool_name == "nmap":
            findings.extend(self._parse_nmap(output))
        elif tool_name == "nikto":
            findings.extend(self._parse_nikto(output))
        elif tool_name == "sqlmap":
            findings.extend(self._parse_sqlmap(output))
        elif tool_name == "gobuster":
            findings.extend(self._parse_gobuster(output))

        # Generic vulnerability patterns
        findings.extend(self._extract_generic_findings(output))

        return findings

    def _parse_nmap(self, output: str) -> list[dict[str, Any]]:
        """Parse nmap output for findings."""
        findings = []

        # Extract open ports
        port_pattern = r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)"
        for match in re.finditer(port_pattern, output):
            port, protocol, service, version = match.groups()
            findings.append({
                "type": "open_port",
                "severity": "info",
                "port": int(port),
                "protocol": protocol,
                "service": service,
                "version": version.strip() if version else None,
            })

        # Check for vulnerability script results
        if "VULNERABLE" in output:
            findings.append({
                "type": "vulnerability",
                "severity": "high",
                "description": "Nmap vulnerability scripts found issues",
            })

        return findings

    def _parse_nikto(self, output: str) -> list[dict[str, Any]]:
        """Parse nikto output for findings."""
        findings = []

        # Nikto finding patterns
        if "OSVDB" in output:
            findings.append({
                "type": "vulnerability",
                "severity": "medium",
                "source": "nikto",
                "description": "Nikto identified potential vulnerabilities",
            })

        if "Server leaks" in output:
            findings.append({
                "type": "information_disclosure",
                "severity": "low",
                "description": "Server information leakage detected",
            })

        return findings

    def _parse_sqlmap(self, output: str) -> list[dict[str, Any]]:
        """Parse sqlmap output for findings."""
        findings = []

        if "is vulnerable" in output.lower():
            findings.append({
                "type": "sql_injection",
                "severity": "critical",
                "description": "SQL Injection vulnerability confirmed",
            })

        if "database:" in output.lower():
            findings.append({
                "type": "data_extraction",
                "severity": "critical",
                "description": "Database information extracted",
            })

        return findings

    def _parse_gobuster(self, output: str) -> list[dict[str, Any]]:
        """Parse gobuster output for findings."""
        findings = []

        # Look for interesting directories
        sensitive_paths = [
            "admin", "backup", "config", ".git", ".env",
            "api", "debug", "test", "internal", "private",
        ]

        for path in sensitive_paths:
            if f"/{path}" in output.lower():
                findings.append({
                    "type": "directory_found",
                    "severity": "medium" if path in [".git", ".env", "backup"] else "low",
                    "path": path,
                    "description": f"Sensitive directory discovered: {path}",
                })

        return findings

    def _extract_generic_findings(self, output: str) -> list[dict[str, Any]]:
        """Extract generic security findings from any output."""
        findings = []

        # Look for CVE references
        cve_pattern = r"CVE-\d{4}-\d{4,}"
        cves = set(re.findall(cve_pattern, output, re.IGNORECASE))
        for cve in cves:
            findings.append({
                "type": "cve_reference",
                "severity": "medium",
                "cve": cve.upper(),
            })

        # Look for credentials
        if re.search(r"password[:\s]*\S+", output, re.IGNORECASE):
            findings.append({
                "type": "credential_found",
                "severity": "high",
                "description": "Potential credentials in output",
            })

        return findings

    def get_history(self) -> list[dict[str, Any]]:
        """Get tool execution history."""
        return self._execution_history.copy()


class ToolMetricsHandler(EventHandler):
    """
    Handler for collecting tool execution metrics.

    Tracks timing, success rates, and usage patterns.
    """

    def __init__(self) -> None:
        """Initialize the metrics handler."""
        self._metrics: dict[str, dict[str, Any]] = {}

    @property
    def name(self) -> str:
        return "tool_metrics_handler"

    @property
    def handles(self) -> list[EventType]:
        return [EventType.TOOL_START, EventType.TOOL_COMPLETE, EventType.TOOL_ERROR]

    async def handle(self, event: Event) -> None:
        """Process tool events for metrics."""
        tool_name = event.data.get("tool_name", "unknown")

        if tool_name not in self._metrics:
            self._metrics[tool_name] = {
                "total_calls": 0,
                "successful": 0,
                "failed": 0,
                "total_duration_ms": 0,
            }

        metrics = self._metrics[tool_name]

        if event.type == EventType.TOOL_START:
            metrics["total_calls"] += 1
            metrics["last_start"] = event.timestamp

        elif event.type == EventType.TOOL_COMPLETE:
            metrics["successful"] += 1
            if "last_start" in metrics and event.timestamp:
                duration = (event.timestamp - metrics["last_start"]) * 1000
                metrics["total_duration_ms"] += duration

        elif event.type == EventType.TOOL_ERROR:
            metrics["failed"] += 1

    def get_metrics(self) -> dict[str, dict[str, Any]]:
        """Get collected metrics."""
        return self._metrics.copy()

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of all metrics."""
        total_calls = sum(m["total_calls"] for m in self._metrics.values())
        total_success = sum(m["successful"] for m in self._metrics.values())

        return {
            "total_tool_calls": total_calls,
            "success_rate": total_success / total_calls if total_calls > 0 else 0,
            "tools_used": list(self._metrics.keys()),
            "by_tool": self._metrics,
        }
