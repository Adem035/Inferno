"""
Output formatting utilities for Inferno.

This module provides formatting functions for displaying
tool outputs, findings, and reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def format_timestamp(
    dt: datetime | None = None,
    fmt: str = "%Y-%m-%d %H:%M:%S UTC",
) -> str:
    """
    Format a timestamp.

    Args:
        dt: Datetime object (defaults to now).
        fmt: Format string.

    Returns:
        Formatted timestamp string.
    """
    if dt is None:
        dt = datetime.now(UTC)
    return dt.strftime(fmt)


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string.

    Args:
        size: Size in bytes.

    Returns:
        Human-readable size string.
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        Human-readable duration string.
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def format_finding(
    finding: dict[str, Any],
    include_evidence: bool = True,
) -> str:
    """
    Format a security finding for display.

    Args:
        finding: Finding dictionary.
        include_evidence: Whether to include evidence.

    Returns:
        Formatted finding string.
    """
    severity = finding.get("severity", "unknown").upper()
    severity_colors = {
        "CRITICAL": "[!]",
        "HIGH": "[!]",
        "MEDIUM": "[*]",
        "LOW": "[.]",
        "INFO": "[i]",
    }

    marker = severity_colors.get(severity, "[?]")
    name = finding.get("name", finding.get("type", "Finding"))
    description = finding.get("description", "No description")

    output = f"{marker} {severity}: {name}\n"
    output += f"    {description}\n"

    if "location" in finding:
        output += f"    Location: {finding['location']}\n"

    if "cve" in finding:
        output += f"    CVE: {finding['cve']}\n"

    if include_evidence and "evidence" in finding:
        evidence = finding["evidence"]
        if len(evidence) > 200:
            evidence = evidence[:200] + "..."
        output += f"    Evidence: {evidence}\n"

    return output


def format_findings_table(findings: list[dict[str, Any]]) -> str:
    """
    Format findings as a simple table.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Table-formatted string.
    """
    if not findings:
        return "No findings."

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "").lower(), 5),
    )

    lines = [
        "=" * 60,
        "FINDINGS SUMMARY",
        "=" * 60,
    ]

    for finding in sorted_findings:
        severity = finding.get("severity", "?").upper()[:4]
        name = finding.get("name", finding.get("type", "Unknown"))[:40]
        location = finding.get("location", "-")[:20]
        lines.append(f"[{severity:4}] {name:40} @ {location}")

    lines.append("=" * 60)
    lines.append(f"Total: {len(findings)} findings")

    return "\n".join(lines)


def format_port_list(ports: list[dict[str, Any]]) -> str:
    """
    Format a list of ports for display.

    Args:
        ports: List of port dictionaries.

    Returns:
        Formatted port list string.
    """
    if not ports:
        return "No ports found."

    lines = [
        "PORT      STATE    SERVICE        VERSION",
        "-" * 60,
    ]

    for port in sorted(ports, key=lambda p: p.get("port", 0)):
        port_num = port.get("port", 0)
        protocol = port.get("protocol", "tcp")
        state = port.get("state", "unknown")
        service = port.get("service", "unknown")
        version = port.get("version", "")

        line = f"{port_num}/{protocol:3}  {state:8} {service:14} {version}"
        lines.append(line.strip())

    return "\n".join(lines)


def format_progress_bar(
    current: int,
    total: int,
    width: int = 40,
    show_percent: bool = True,
) -> str:
    """
    Create a text-based progress bar.

    Args:
        current: Current progress value.
        total: Total value.
        width: Bar width in characters.
        show_percent: Whether to show percentage.

    Returns:
        Progress bar string.
    """
    if total == 0:
        percent = 0
    else:
        percent = (current / total) * 100

    filled = int(width * current / total) if total > 0 else 0
    bar = "█" * filled + "░" * (width - filled)

    if show_percent:
        return f"[{bar}] {percent:.1f}%"
    return f"[{bar}]"


def truncate_string(
    text: str,
    max_length: int = 100,
    suffix: str = "...",
) -> str:
    """
    Truncate a string to a maximum length.

    Args:
        text: String to truncate.
        max_length: Maximum length.
        suffix: Suffix to add when truncated.

    Returns:
        Truncated string.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def format_json_pretty(data: Any, indent: int = 2) -> str:
    """
    Format data as pretty-printed JSON.

    Args:
        data: Data to format.
        indent: Indentation level.

    Returns:
        Pretty-printed JSON string.
    """
    import json

    try:
        return json.dumps(data, indent=indent, default=str)
    except (TypeError, ValueError):
        return str(data)


def format_markdown_table(
    headers: list[str],
    rows: list[list[str]],
) -> str:
    """
    Format data as a Markdown table.

    Args:
        headers: Table headers.
        rows: Table rows.

    Returns:
        Markdown table string.
    """
    if not headers:
        return ""

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))

    # Format header
    header_row = "| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)) + " |"
    separator = "| " + " | ".join("-" * w for w in widths) + " |"

    # Format rows
    data_rows = []
    for row in rows:
        cells = [str(cell).ljust(widths[i]) if i < len(widths) else str(cell) for i, cell in enumerate(row)]
        data_rows.append("| " + " | ".join(cells) + " |")

    return "\n".join([header_row, separator] + data_rows)
