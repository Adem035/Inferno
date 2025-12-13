"""
Environment setup and validation for Inferno.

This module handles environment validation, security tool discovery,
and runtime setup for the pentesting agent.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from inferno.config.settings import InfernoSettings

logger = structlog.get_logger(__name__)


@dataclass
class SecurityTool:
    """Represents an available security tool."""

    name: str
    path: Path | None
    version: str | None = None
    available: bool = False
    description: str = ""


@dataclass
class EnvironmentInfo:
    """Information about the runtime environment."""

    python_version: str
    platform: str
    hostname: str
    user: str
    working_dir: Path
    inferno_version: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class OperationContext:
    """Context for a specific pentesting operation."""

    operation_id: str
    target: str
    objective: str
    output_dir: Path
    artifacts_dir: Path
    tools_dir: Path
    memory_dir: Path
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))


# Core security tools that Inferno can use
SECURITY_TOOLS: dict[str, str] = {
    # Network reconnaissance
    "nmap": "Network port scanner and service detection",
    "masscan": "Fast port scanner",
    "rustscan": "Fast port scanner with nmap integration",
    # Web scanning
    "nikto": "Web server scanner",
    "gobuster": "Directory/file brute-forcer",
    "dirb": "Web content scanner",
    "feroxbuster": "Fast content discovery tool",
    "ffuf": "Fast web fuzzer",
    "wfuzz": "Web application fuzzer",
    "dirsearch": "Web path scanner",
    # Vulnerability scanning
    "nuclei": "Template-based vulnerability scanner",
    "sqlmap": "SQL injection detection and exploitation",
    "xsstrike": "XSS detection suite",
    "wpscan": "WordPress vulnerability scanner",
    # Subdomain enumeration
    "subfinder": "Subdomain discovery tool",
    "amass": "Attack surface mapping",
    "assetfinder": "Find related domains",
    # Web crawling
    "katana": "Web crawler",
    "gospider": "Web spider",
    "hakrawler": "Web crawler for gathering URLs",
    # HTTP tools
    "httpx": "HTTP toolkit",
    "httprobe": "HTTP server probing",
    "curl": "HTTP client",
    "wget": "Network downloader",
    # Credential attacks
    "hydra": "Network login cracker",
    "john": "John the Ripper password cracker",
    "hashcat": "Advanced password recovery",
    # Git and secrets
    "git-dumper": "Dump exposed .git repositories",
    "trufflehog": "Secret scanner for git repos",
    "gitleaks": "Git secrets scanner",
    # Exploitation frameworks
    "msfconsole": "Metasploit Framework",
    # Network tools
    "nc": "Network utility (netcat)",
    "socat": "Multipurpose relay",
    "tcpdump": "Packet analyzer",
    # Impacket tools
    "impacket-smbserver": "SMB server for file transfer",
    "impacket-psexec": "Remote command execution",
    # SSL/TLS
    "sslscan": "SSL/TLS scanner",
    "testssl.sh": "TLS/SSL testing",
    # DNS
    "dig": "DNS lookup utility",
    "dnsenum": "DNS enumeration tool",
    "dnsrecon": "DNS reconnaissance",
    # Utilities
    "jq": "JSON processor",
    "base64": "Base64 encoder/decoder",
    "xxd": "Hex dump utility",
    "whois": "WHOIS lookup",
    "sshpass": "Non-interactive SSH password auth",
}


def discover_security_tools() -> dict[str, SecurityTool]:
    """
    Discover available security tools on the system.

    Returns:
        Dictionary mapping tool names to SecurityTool objects.
    """
    discovered: dict[str, SecurityTool] = {}

    for tool_name, description in SECURITY_TOOLS.items():
        # Special handling for sqlmap (often has broken wrapper scripts)
        if tool_name == "sqlmap":
            sqlmap_cmd = _get_sqlmap_command()
            if sqlmap_cmd:
                exe, args = sqlmap_cmd
                discovered[tool_name] = SecurityTool(
                    name=tool_name,
                    path=Path(exe),
                    version="available",
                    available=True,
                    description=description,
                )
                logger.debug("discovered_security_tool", tool=tool_name, path=exe, version="available")
            else:
                discovered[tool_name] = SecurityTool(
                    name=tool_name,
                    path=None,
                    version=None,
                    available=False,
                    description=description,
                )
                logger.debug("security_tool_not_found", tool=tool_name)
            continue

        tool_path = shutil.which(tool_name)

        if tool_path:
            version = _get_tool_version(tool_name, tool_path)
            # If version is None and we expected output, tool may be broken
            # But still mark as available since shutil.which found it
            discovered[tool_name] = SecurityTool(
                name=tool_name,
                path=Path(tool_path),
                version=version,
                available=True,
                description=description,
            )
            logger.debug("discovered_security_tool", tool=tool_name, path=tool_path, version=version)
        else:
            discovered[tool_name] = SecurityTool(
                name=tool_name,
                path=None,
                version=None,
                available=False,
                description=description,
            )
            logger.debug("security_tool_not_found", tool=tool_name)

    available_count = sum(1 for t in discovered.values() if t.available)
    logger.info(
        "security_tools_discovery_complete",
        total=len(SECURITY_TOOLS),
        available=available_count,
        missing=len(SECURITY_TOOLS) - available_count,
    )

    return discovered


def _get_tool_version(tool_name: str, tool_path: str) -> str | None:
    """
    Attempt to get the version of a security tool.

    Args:
        tool_name: Name of the tool.
        tool_path: Path to the tool executable.

    Returns:
        Version string if available, None otherwise.
    """
    version_flags = ["--version", "-V", "-v", "version"]

    for flag in version_flags:
        try:
            result = subprocess.run(
                [tool_path, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout or result.stderr
            if output:
                # Check for error indicators that suggest tool is broken
                if "SyntaxError" in output or "Traceback" in output:
                    logger.warning("tool_broken", tool=tool_name, error=output[:100])
                    return None

                # Extract first line and clean it up
                first_line = output.strip().split("\n")[0]
                # Remove the tool name if it appears at the start
                version_str = first_line.replace(tool_name, "").strip()
                if version_str:
                    return version_str[:50]  # Limit length
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            continue

    return None


def _get_sqlmap_command() -> tuple[str, list[str]] | None:
    """
    Get the correct command to run sqlmap.

    Handles cases where sqlmap is installed as a Python module
    or has a broken wrapper script.

    Returns:
        Tuple of (executable, args_prefix) or None if not found.
    """
    # Try Homebrew paths first (most reliable on macOS)
    homebrew_sqlmap = Path("/opt/homebrew/Cellar/sqlmap")
    if homebrew_sqlmap.exists():
        for version_dir in sorted(homebrew_sqlmap.iterdir(), reverse=True):
            sqlmap_py = version_dir / "libexec" / "sqlmap.py"
            if sqlmap_py.exists():
                # Verify it works
                try:
                    result = subprocess.run(
                        ["python3", str(sqlmap_py), "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        return ("python3", [str(sqlmap_py)])
                except Exception:
                    pass

    # Try direct sqlmap command
    sqlmap_path = shutil.which("sqlmap")
    if sqlmap_path:
        try:
            result = subprocess.run(
                [sqlmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "sqlmap" in (result.stdout + result.stderr).lower():
                return (sqlmap_path, [])
        except Exception:
            pass

    # Try python3 -m sqlmap (pip installed) - but verify it actually works
    try:
        result = subprocess.run(
            ["python3", "-m", "sqlmap", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and "sqlmap" in (result.stdout + result.stderr).lower():
            return ("python3", ["-m", "sqlmap"])
    except Exception:
        pass

    # Try other common installation paths
    common_paths = [
        # Intel Mac Homebrew
        "/usr/local/Cellar/sqlmap/1.9.11/libexec/sqlmap.py",
        # Linux
        "/usr/share/sqlmap/sqlmap.py",
        "/opt/sqlmap/sqlmap.py",
    ]

    for path in common_paths:
        path = Path(path)
        if path.exists():
            # Verify it's actually Python, not a bash wrapper
            try:
                with open(path) as f:
                    first_line = f.readline()
                    if first_line.startswith("#!/bin/bash") or "exec " in first_line:
                        continue  # Skip bash wrappers
                # Verify it works
                result = subprocess.run(
                    ["python3", str(path), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return ("python3", [str(path)])
            except Exception:
                pass

    return None


def get_environment_info() -> EnvironmentInfo:
    """
    Get information about the runtime environment.

    Returns:
        EnvironmentInfo object with system details.
    """
    import platform
    import sys

    from inferno import __version__

    return EnvironmentInfo(
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        hostname=platform.node(),
        user=os.getenv("USER", os.getenv("USERNAME", "unknown")),
        working_dir=Path.cwd(),
        inferno_version=__version__,
    )


def generate_operation_id() -> str:
    """
    Generate a unique operation ID.

    Format: OP_YYYYMMDD_HHMMSS

    Returns:
        Unique operation identifier string.
    """
    now = datetime.now(UTC)
    return f"OP_{now.strftime('%Y%m%d_%H%M%S')}"


def setup_operation_context(
    settings: InfernoSettings,
    target: str,
    objective: str,
    operation_id: str | None = None,
) -> OperationContext:
    """
    Set up the context for a pentesting operation.

    Creates necessary directories and sets environment variables.

    Args:
        settings: Inferno configuration settings.
        target: Target host/URL for the assessment.
        objective: Assessment objective description.
        operation_id: Optional operation ID (generated if not provided).

    Returns:
        OperationContext with all paths and metadata.
    """
    if operation_id is None:
        operation_id = generate_operation_id()

    # Create directory paths
    output_dir = settings.get_output_dir(target, operation_id)
    artifacts_dir = settings.get_artifacts_dir(target, operation_id)
    tools_dir = output_dir / "tools"
    memory_dir = settings.get_memory_dir(target)

    # Create directories
    for directory in [output_dir, artifacts_dir, tools_dir, memory_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    # Set environment variables for tool scripts
    os.environ["INFERNO_OPERATION_ID"] = operation_id
    os.environ["INFERNO_TARGET"] = target
    os.environ["INFERNO_OUTPUT_DIR"] = str(output_dir)
    os.environ["INFERNO_ARTIFACTS_DIR"] = str(artifacts_dir)
    os.environ["INFERNO_TOOLS_DIR"] = str(tools_dir)
    os.environ["INFERNO_MEMORY_DIR"] = str(memory_dir)

    context = OperationContext(
        operation_id=operation_id,
        target=target,
        objective=objective,
        output_dir=output_dir,
        artifacts_dir=artifacts_dir,
        tools_dir=tools_dir,
        memory_dir=memory_dir,
    )

    logger.info(
        "operation_context_created",
        operation_id=operation_id,
        target=target,
        output_dir=str(output_dir),
    )

    return context


def validate_environment(settings: InfernoSettings) -> tuple[bool, list[str]]:
    """
    Validate the runtime environment for Inferno.

    Checks:
    - API key is set
    - Required tools are available
    - Output directory is writable
    - Qdrant is reachable (if configured)

    Args:
        settings: Inferno configuration settings.

    Returns:
        Tuple of (is_valid, list of error messages).
    """
    errors: list[str] = []

    # Check API key
    try:
        api_key = settings.get_api_key()
        if not api_key or len(api_key) < 10:
            errors.append("Invalid Anthropic API key")
    except Exception as e:
        errors.append(f"Failed to retrieve API key: {e}")

    # Check output directory is writable
    try:
        test_file = settings.output.base_dir / ".inferno_test"
        settings.output.base_dir.mkdir(parents=True, exist_ok=True)
        test_file.touch()
        test_file.unlink()
    except Exception as e:
        errors.append(f"Output directory not writable: {e}")

    # Check for minimum required tools
    required_tools = ["curl", "nmap"]
    discovered = discover_security_tools()
    for tool in required_tools:
        if tool not in discovered or not discovered[tool].available:
            errors.append(f"Required tool '{tool}' not found in PATH")

    # Validate Qdrant connection (if not localhost, do a basic check)
    if settings.memory.qdrant_host != "localhost":
        try:
            from qdrant_client import QdrantClient

            client = QdrantClient(
                host=settings.memory.qdrant_host,
                port=settings.memory.qdrant_port,
                api_key=settings.memory.qdrant_api_key.get_secret_value()
                if settings.memory.qdrant_api_key
                else None,
                timeout=5,
            )
            client.get_collections()
        except Exception as e:
            errors.append(f"Cannot connect to Qdrant: {e}")

    is_valid = len(errors) == 0

    if is_valid:
        logger.info("environment_validation_passed")
    else:
        logger.error("environment_validation_failed", errors=errors)

    return is_valid, errors


def setup_logging(settings: InfernoSettings) -> None:
    """
    Configure structured logging for Inferno.

    Args:
        settings: Inferno configuration settings.
    """
    log_level = getattr(logging, settings.output.log_level)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer() if log_level == logging.DEBUG else structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Also configure standard logging for third-party libraries
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
