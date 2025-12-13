"""
Output parsing utilities for Inferno.

This module provides parsers for extracting structured data from
security tool outputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ParsedPort:
    """Parsed port information."""

    port: int
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class ParsedHost:
    """Parsed host information."""

    ip: str
    hostname: str | None = None
    state: str = "up"
    ports: list[ParsedPort] = field(default_factory=list)
    os_guess: str | None = None


@dataclass
class ParsedVulnerability:
    """Parsed vulnerability information."""

    name: str
    severity: str
    description: str
    location: str | None = None
    cve: str | None = None
    evidence: str | None = None


class NmapParser:
    """Parser for nmap output formats."""

    @staticmethod
    def parse_text(output: str) -> list[ParsedHost]:
        """
        Parse nmap text output.

        Args:
            output: Raw nmap text output.

        Returns:
            List of parsed hosts.
        """
        hosts: list[ParsedHost] = []
        current_host: ParsedHost | None = None

        for line in output.split("\n"):
            line = line.strip()

            # New host
            if line.startswith("Nmap scan report for"):
                if current_host:
                    hosts.append(current_host)

                # Extract IP/hostname
                match = re.search(r"for (\S+)", line)
                if match:
                    target = match.group(1)
                    # Check if IP is in parentheses
                    ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                    if ip_match:
                        current_host = ParsedHost(
                            ip=ip_match.group(1),
                            hostname=target,
                        )
                    else:
                        current_host = ParsedHost(ip=target)

            # Port information
            elif current_host and re.match(r"^\d+/(tcp|udp)", line):
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split("/")
                    port = ParsedPort(
                        port=int(port_proto[0]),
                        protocol=port_proto[1],
                        state=parts[1],
                        service=parts[2] if len(parts) > 2 else None,
                        version=" ".join(parts[3:]) if len(parts) > 3 else None,
                    )
                    current_host.ports.append(port)

            # OS detection
            elif current_host and "OS details:" in line:
                match = re.search(r"OS details: (.+)", line)
                if match:
                    current_host.os_guess = match.group(1)

        if current_host:
            hosts.append(current_host)

        return hosts

    @staticmethod
    def parse_xml(xml_content: str) -> list[ParsedHost]:
        """
        Parse nmap XML output.

        Args:
            xml_content: Nmap XML output string.

        Returns:
            List of parsed hosts.
        """
        hosts: list[ParsedHost] = []

        try:
            root = ElementTree.fromstring(xml_content)

            for host_elem in root.findall(".//host"):
                # Get address
                addr_elem = host_elem.find("address")
                if addr_elem is None:
                    continue

                ip = addr_elem.get("addr", "")

                # Get hostname
                hostname_elem = host_elem.find(".//hostname")
                hostname = hostname_elem.get("name") if hostname_elem is not None else None

                # Get state
                status_elem = host_elem.find("status")
                state = status_elem.get("state", "unknown") if status_elem is not None else "unknown"

                host = ParsedHost(ip=ip, hostname=hostname, state=state)

                # Get ports
                for port_elem in host_elem.findall(".//port"):
                    port_id = int(port_elem.get("portid", 0))
                    protocol = port_elem.get("protocol", "tcp")

                    state_elem = port_elem.find("state")
                    port_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                    service_elem = port_elem.find("service")
                    service = service_elem.get("name") if service_elem is not None else None
                    version = service_elem.get("version") if service_elem is not None else None

                    port = ParsedPort(
                        port=port_id,
                        protocol=protocol,
                        state=port_state,
                        service=service,
                        version=version,
                    )

                    # Parse script output
                    for script_elem in port_elem.findall("script"):
                        script_id = script_elem.get("id", "")
                        script_output = script_elem.get("output", "")
                        port.scripts[script_id] = script_output

                    host.ports.append(port)

                # Get OS
                os_elem = host_elem.find(".//osmatch")
                if os_elem is not None:
                    host.os_guess = os_elem.get("name")

                hosts.append(host)

        except ElementTree.ParseError as e:
            logger.error("nmap_xml_parse_error", error=str(e))

        return hosts


class SQLMapParser:
    """Parser for sqlmap output."""

    @staticmethod
    def parse_output(output: str) -> dict[str, Any]:
        """
        Parse sqlmap output.

        Args:
            output: Raw sqlmap output.

        Returns:
            Parsed results dictionary.
        """
        result: dict[str, Any] = {
            "vulnerable": False,
            "injection_type": None,
            "databases": [],
            "tables": [],
            "columns": [],
            "data": [],
        }

        # Check for vulnerability confirmation
        if "is vulnerable" in output.lower():
            result["vulnerable"] = True

        # Extract injection type
        injection_types = [
            "boolean-based blind",
            "time-based blind",
            "error-based",
            "UNION query",
            "stacked queries",
        ]
        for inj_type in injection_types:
            if inj_type.lower() in output.lower():
                result["injection_type"] = inj_type
                break

        # Extract databases
        db_pattern = r"\[\*\]\s+(.+)"
        for match in re.finditer(db_pattern, output):
            db_name = match.group(1).strip()
            if db_name and not db_name.startswith("["):
                result["databases"].append(db_name)

        # Extract tables
        table_pattern = r"\| (\w+)\s+\|"
        tables = re.findall(table_pattern, output)
        result["tables"] = list(set(tables))

        return result


class GobusterParser:
    """Parser for gobuster output."""

    @staticmethod
    def parse_output(output: str) -> list[dict[str, Any]]:
        """
        Parse gobuster output.

        Args:
            output: Raw gobuster output.

        Returns:
            List of discovered paths.
        """
        results: list[dict[str, Any]] = []

        # Pattern for gobuster dir mode
        # Example: /admin (Status: 200) [Size: 1234]
        pattern = r"(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?"

        for match in re.finditer(pattern, output):
            path, status, size = match.groups()
            results.append({
                "path": path,
                "status": int(status),
                "size": int(size) if size else None,
            })

        return results


class GenericParser:
    """Generic output parser for common patterns."""

    @staticmethod
    def extract_ips(text: str) -> list[str]:
        """Extract IP addresses from text."""
        pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_urls(text: str) -> list[str]:
        """Extract URLs from text."""
        pattern = r"https?://[^\s<>\"'{}|\\^`\[\]]+"
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_emails(text: str) -> list[str]:
        """Extract email addresses from text."""
        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        return list(set(re.findall(pattern, text)))

    @staticmethod
    def extract_cves(text: str) -> list[str]:
        """Extract CVE identifiers from text."""
        pattern = r"CVE-\d{4}-\d{4,}"
        return list(set(re.findall(pattern, text, re.IGNORECASE)))

    @staticmethod
    def extract_hashes(text: str) -> dict[str, list[str]]:
        """Extract potential hash values from text."""
        hashes: dict[str, list[str]] = {
            "md5": [],
            "sha1": [],
            "sha256": [],
        }

        # MD5 (32 hex chars)
        md5_pattern = r"\b[a-fA-F0-9]{32}\b"
        hashes["md5"] = list(set(re.findall(md5_pattern, text)))

        # SHA1 (40 hex chars)
        sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
        hashes["sha1"] = list(set(re.findall(sha1_pattern, text)))

        # SHA256 (64 hex chars)
        sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
        hashes["sha256"] = list(set(re.findall(sha256_pattern, text)))

        return hashes
