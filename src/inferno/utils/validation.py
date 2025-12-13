"""
Input validation utilities for Inferno.

This module provides validation functions for targets, inputs,
and security-related data.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class ValidationError(Exception):
    """Raised when validation fails."""

    pass


def validate_ip(ip: str) -> tuple[bool, str | None]:
    """
    Validate an IP address.

    Args:
        ip: IP address string.

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError:
        return False, f"Invalid IP address: {ip}"


def validate_ip_network(network: str) -> tuple[bool, str | None]:
    """
    Validate a CIDR network notation.

    Args:
        network: Network in CIDR notation (e.g., 192.168.1.0/24).

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True, None
    except ValueError:
        return False, f"Invalid network: {network}"


def validate_url(url: str, require_scheme: bool = True) -> tuple[bool, str | None]:
    """
    Validate a URL.

    Args:
        url: URL string.
        require_scheme: Whether to require http/https scheme.

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        parsed = urlparse(url)

        if require_scheme and parsed.scheme not in ("http", "https"):
            return False, f"URL must have http or https scheme: {url}"

        if not parsed.netloc:
            return False, f"URL must have a host: {url}"

        return True, None
    except Exception as e:
        return False, f"Invalid URL: {e}"


def validate_hostname(hostname: str) -> tuple[bool, str | None]:
    """
    Validate a hostname.

    Args:
        hostname: Hostname string.

    Returns:
        Tuple of (is_valid, error_message).
    """
    # RFC 1123 compliant hostname pattern
    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"

    if len(hostname) > 253:
        return False, "Hostname too long (max 253 characters)"

    if re.match(pattern, hostname):
        return True, None

    return False, f"Invalid hostname: {hostname}"


def validate_port(port: int | str) -> tuple[bool, str | None]:
    """
    Validate a port number.

    Args:
        port: Port number.

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return True, None
        return False, f"Port must be between 1 and 65535: {port}"
    except (ValueError, TypeError):
        return False, f"Invalid port number: {port}"


def validate_port_range(port_range: str) -> tuple[bool, str | None]:
    """
    Validate a port range (e.g., "80-443" or "22,80,443").

    Args:
        port_range: Port range string.

    Returns:
        Tuple of (is_valid, error_message).
    """
    # Handle comma-separated ports
    if "," in port_range:
        for port in port_range.split(","):
            valid, error = validate_port(port.strip())
            if not valid:
                return False, error
        return True, None

    # Handle range notation
    if "-" in port_range:
        parts = port_range.split("-")
        if len(parts) != 2:
            return False, f"Invalid port range format: {port_range}"

        valid1, error1 = validate_port(parts[0])
        valid2, error2 = validate_port(parts[1])

        if not valid1:
            return False, error1
        if not valid2:
            return False, error2

        if int(parts[0]) >= int(parts[1]):
            return False, "Invalid range: start must be less than end"

        return True, None

    # Single port
    return validate_port(port_range)


def validate_target(target: str) -> tuple[str, str | None]:
    """
    Validate and classify a target.

    Args:
        target: Target string (IP, URL, hostname, etc.).

    Returns:
        Tuple of (target_type, error_message).
        Target types: "ip", "network", "url", "hostname", "unknown"
    """
    # Check if IP address
    valid, _ = validate_ip(target)
    if valid:
        return "ip", None

    # Check if network
    valid, _ = validate_ip_network(target)
    if valid:
        return "network", None

    # Check if URL
    if target.startswith(("http://", "https://")):
        valid, error = validate_url(target)
        if valid:
            return "url", None
        return "unknown", error

    # Check if hostname
    valid, _ = validate_hostname(target)
    if valid:
        return "hostname", None

    return "unknown", f"Could not determine target type: {target}"


def sanitize_command(command: str) -> str:
    """
    Sanitize a shell command to remove potentially dangerous patterns.

    Args:
        command: Shell command string.

    Returns:
        Sanitized command string.

    Note:
        This is a basic sanitization. Always validate commands
        against an allowlist for production use.
    """
    # Remove shell metacharacters that could be dangerous
    dangerous_patterns = [
        r";\s*rm\s+-rf",
        r"\$\(",
        r"`",
        r">\s*/dev/",
        r"&&\s*rm\s+-rf",
        r"\|\s*sh\b",
        r"\|\s*bash\b",
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            logger.warning("dangerous_pattern_removed", pattern=pattern)
            command = re.sub(pattern, "", command)

    return command


def validate_file_path(
    path: str,
    allowed_extensions: list[str] | None = None,
) -> tuple[bool, str | None]:
    """
    Validate a file path.

    Args:
        path: File path string.
        allowed_extensions: List of allowed file extensions.

    Returns:
        Tuple of (is_valid, error_message).
    """
    # Check for path traversal
    if ".." in path:
        return False, "Path traversal not allowed"

    # Check extension if specified
    if allowed_extensions:
        ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if ext not in [e.lower().lstrip(".") for e in allowed_extensions]:
            return False, f"Extension not allowed. Allowed: {allowed_extensions}"

    return True, None


def validate_json(data: str) -> tuple[bool, Any | None]:
    """
    Validate JSON string.

    Args:
        data: JSON string.

    Returns:
        Tuple of (is_valid, parsed_data or error_message).
    """
    import json

    try:
        parsed = json.loads(data)
        return True, parsed
    except json.JSONDecodeError as e:
        return False, str(e)
