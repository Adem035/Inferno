"""
Tool installer for Inferno.

This module provides automatic installation of security tools
with platform-aware commands for macOS (brew) and Linux (apt).
"""

from __future__ import annotations

import asyncio
import platform
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class Platform(str, Enum):
    """Supported platforms."""

    MACOS = "darwin"
    LINUX = "linux"
    UNKNOWN = "unknown"


class InstallMethod(str, Enum):
    """Installation method."""

    BREW = "brew"
    APT = "apt"
    PIP = "pip"
    PIPX = "pipx"
    GO = "go"
    CARGO = "cargo"
    MANUAL = "manual"


@dataclass
class ToolInfo:
    """Information about a tool and how to install it."""

    name: str
    description: str
    brew_package: str | None = None
    apt_package: str | None = None
    pip_package: str | None = None
    pipx_package: str | None = None
    go_package: str | None = None
    cargo_package: str | None = None
    manual_url: str | None = None
    binary_name: str | None = None  # If different from name
    optional: bool = False
    category: str = "general"

    @property
    def check_name(self) -> str:
        """Get the name to check for in PATH."""
        return self.binary_name or self.name


# Comprehensive list of security tools with install instructions
SECURITY_TOOLS: dict[str, ToolInfo] = {
    # Core reconnaissance
    "nmap": ToolInfo(
        name="nmap",
        description="Network scanner and port enumeration",
        brew_package="nmap",
        apt_package="nmap",
        category="reconnaissance",
    ),
    "masscan": ToolInfo(
        name="masscan",
        description="Fast port scanner",
        brew_package="masscan",
        apt_package="masscan",
        category="reconnaissance",
    ),
    "rustscan": ToolInfo(
        name="rustscan",
        description="Modern fast port scanner",
        brew_package="rustscan",
        cargo_package="rustscan",
        category="reconnaissance",
    ),
    # Web enumeration
    "gobuster": ToolInfo(
        name="gobuster",
        description="Directory and DNS bruteforcer",
        brew_package="gobuster",
        apt_package="gobuster",
        go_package="github.com/OJ/gobuster/v3@latest",
        category="web",
    ),
    "ffuf": ToolInfo(
        name="ffuf",
        description="Fast web fuzzer",
        brew_package="ffuf",
        apt_package="ffuf",
        go_package="github.com/ffuf/ffuf/v2@latest",
        category="web",
    ),
    "feroxbuster": ToolInfo(
        name="feroxbuster",
        description="Fast recursive content discovery",
        brew_package="feroxbuster",
        cargo_package="feroxbuster",
        category="web",
    ),
    "dirsearch": ToolInfo(
        name="dirsearch",
        description="Web path scanner",
        pip_package="dirsearch",
        pipx_package="dirsearch",
        category="web",
    ),
    "wfuzz": ToolInfo(
        name="wfuzz",
        description="Web fuzzer",
        brew_package="wfuzz",
        pip_package="wfuzz",
        apt_package="wfuzz",
        category="web",
    ),
    # Vulnerability scanning
    "nikto": ToolInfo(
        name="nikto",
        description="Web server vulnerability scanner",
        brew_package="nikto",
        apt_package="nikto",
        category="vulnerability",
    ),
    "nuclei": ToolInfo(
        name="nuclei",
        description="Template-based vulnerability scanner",
        brew_package="nuclei",
        go_package="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        category="vulnerability",
    ),
    "sqlmap": ToolInfo(
        name="sqlmap",
        description="SQL injection detection and exploitation",
        brew_package="sqlmap",
        apt_package="sqlmap",
        pip_package="sqlmap",
        category="vulnerability",
    ),
    # Subdomain discovery
    "subfinder": ToolInfo(
        name="subfinder",
        description="Subdomain discovery tool",
        brew_package="subfinder",
        go_package="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        category="reconnaissance",
    ),
    "amass": ToolInfo(
        name="amass",
        description="Attack surface mapping",
        brew_package="amass",
        apt_package="amass",
        go_package="github.com/owasp-amass/amass/v4/...@master",
        category="reconnaissance",
    ),
    "assetfinder": ToolInfo(
        name="assetfinder",
        description="Find related domains and subdomains",
        go_package="github.com/tomnomnom/assetfinder@latest",
        category="reconnaissance",
    ),
    # HTTP tools
    "httpx": ToolInfo(
        name="httpx",
        description="Fast HTTP toolkit",
        brew_package="httpx",
        go_package="github.com/projectdiscovery/httpx/cmd/httpx@latest",
        binary_name="httpx",
        category="web",
    ),
    "httprobe": ToolInfo(
        name="httprobe",
        description="Probe for working HTTP servers",
        go_package="github.com/tomnomnom/httprobe@latest",
        category="web",
    ),
    # Credential attacks
    "hydra": ToolInfo(
        name="hydra",
        description="Network login cracker",
        brew_package="hydra",
        apt_package="hydra",
        category="exploitation",
    ),
    "john": ToolInfo(
        name="john",
        description="John the Ripper password cracker",
        brew_package="john",
        apt_package="john",
        category="exploitation",
    ),
    "hashcat": ToolInfo(
        name="hashcat",
        description="Advanced password recovery",
        brew_package="hashcat",
        apt_package="hashcat",
        category="exploitation",
    ),
    # Git tools
    "git-dumper": ToolInfo(
        name="git-dumper",
        description="Dump exposed .git repositories",
        pip_package="git-dumper",
        pipx_package="git-dumper",
        category="exploitation",
    ),
    "trufflehog": ToolInfo(
        name="trufflehog",
        description="Find secrets in git repos",
        brew_package="trufflehog",
        go_package="github.com/trufflesecurity/trufflehog/v3@latest",
        category="reconnaissance",
    ),
    "gitleaks": ToolInfo(
        name="gitleaks",
        description="Scan git repos for secrets",
        brew_package="gitleaks",
        go_package="github.com/gitleaks/gitleaks/v8@latest",
        category="reconnaissance",
    ),
    # Network tools
    "netcat": ToolInfo(
        name="nc",
        description="Network utility (netcat)",
        brew_package="netcat",
        apt_package="netcat-openbsd",
        binary_name="nc",
        category="network",
    ),
    "socat": ToolInfo(
        name="socat",
        description="Multipurpose relay",
        brew_package="socat",
        apt_package="socat",
        category="network",
    ),
    "tcpdump": ToolInfo(
        name="tcpdump",
        description="Packet analyzer",
        brew_package="tcpdump",
        apt_package="tcpdump",
        category="network",
    ),
    # Impacket tools
    "impacket": ToolInfo(
        name="impacket",
        description="Network protocol tools",
        pip_package="impacket",
        pipx_package="impacket",
        apt_package="python3-impacket",
        binary_name="impacket-smbserver",
        category="exploitation",
    ),
    # CMS scanners
    "wpscan": ToolInfo(
        name="wpscan",
        description="WordPress vulnerability scanner",
        brew_package="wpscan",
        apt_package="wpscan",
        category="vulnerability",
    ),
    "droopescan": ToolInfo(
        name="droopescan",
        description="CMS vulnerability scanner",
        pip_package="droopescan",
        pipx_package="droopescan",
        category="vulnerability",
    ),
    # SSL/TLS tools
    "testssl": ToolInfo(
        name="testssl.sh",
        description="SSL/TLS testing",
        brew_package="testssl",
        binary_name="testssl.sh",
        category="vulnerability",
    ),
    "sslscan": ToolInfo(
        name="sslscan",
        description="SSL cipher scanner",
        brew_package="sslscan",
        apt_package="sslscan",
        category="vulnerability",
    ),
    # DNS tools
    "dig": ToolInfo(
        name="dig",
        description="DNS lookup utility",
        brew_package="bind",
        apt_package="dnsutils",
        category="reconnaissance",
    ),
    "dnsrecon": ToolInfo(
        name="dnsrecon",
        description="DNS enumeration",
        brew_package="dnsrecon",
        apt_package="dnsrecon",
        pip_package="dnsrecon",
        category="reconnaissance",
    ),
    # Wordlists
    "seclists": ToolInfo(
        name="seclists",
        description="Security wordlists collection",
        brew_package="seclists",
        apt_package="seclists",
        manual_url="https://github.com/danielmiessler/SecLists",
        binary_name=None,  # Not a binary
        category="wordlists",
    ),
    # Misc utilities
    "jq": ToolInfo(
        name="jq",
        description="JSON processor",
        brew_package="jq",
        apt_package="jq",
        category="utility",
    ),
    "curl": ToolInfo(
        name="curl",
        description="HTTP client",
        brew_package="curl",
        apt_package="curl",
        category="utility",
    ),
    "wget": ToolInfo(
        name="wget",
        description="Network downloader",
        brew_package="wget",
        apt_package="wget",
        category="utility",
    ),
    "whois": ToolInfo(
        name="whois",
        description="WHOIS lookup",
        brew_package="whois",
        apt_package="whois",
        category="reconnaissance",
    ),
}

# Core tools that should always be installed
CORE_TOOLS = [
    "nmap",
    "gobuster",
    "ffuf",
    "nikto",
    "nuclei",
    "sqlmap",
    "hydra",
    "curl",
    "jq",
]

# Extended tools for full functionality
EXTENDED_TOOLS = [
    "subfinder",
    "httpx",
    "feroxbuster",
    "john",
    "hashcat",
    "git-dumper",
    "wfuzz",
    "seclists",
]


@dataclass
class InstallResult:
    """Result of a tool installation attempt."""

    tool: str
    success: bool
    method: InstallMethod | None
    message: str
    already_installed: bool = False


class ToolInstaller:
    """
    Install security tools automatically.

    Detects the platform and uses the appropriate package manager
    (brew for macOS, apt for Linux, pip/go as fallbacks).
    """

    def __init__(
        self,
        auto_sudo: bool = True,
        prefer_pipx: bool = True,
    ) -> None:
        """
        Initialize the ToolInstaller.

        Args:
            auto_sudo: Whether to use sudo for apt commands.
            prefer_pipx: Whether to prefer pipx over pip for Python tools.
        """
        self._auto_sudo = auto_sudo
        self._prefer_pipx = prefer_pipx
        self._platform = self._detect_platform()
        self._available_methods = self._detect_available_methods()

    def _detect_platform(self) -> Platform:
        """Detect the current platform."""
        system = platform.system().lower()
        if system == "darwin":
            return Platform.MACOS
        elif system == "linux":
            return Platform.LINUX
        return Platform.UNKNOWN

    def _detect_available_methods(self) -> set[InstallMethod]:
        """Detect which installation methods are available."""
        methods = set()

        if shutil.which("brew"):
            methods.add(InstallMethod.BREW)
        if shutil.which("apt-get") or shutil.which("apt"):
            methods.add(InstallMethod.APT)
        if shutil.which("pip3") or shutil.which("pip"):
            methods.add(InstallMethod.PIP)
        if shutil.which("pipx"):
            methods.add(InstallMethod.PIPX)
        if shutil.which("go"):
            methods.add(InstallMethod.GO)
        if shutil.which("cargo"):
            methods.add(InstallMethod.CARGO)

        logger.debug("available_install_methods", methods=[m.value for m in methods])
        return methods

    def is_installed(self, tool: str) -> bool:
        """Check if a tool is installed."""
        info = SECURITY_TOOLS.get(tool)
        if not info:
            # Unknown tool, check by name
            return shutil.which(tool) is not None

        # Special case for seclists - check for directories
        if tool == "seclists":
            return self._check_seclists_installed()

        check_name = info.check_name
        if check_name is None:
            return True  # Non-binary package

        return shutil.which(check_name) is not None

    def _check_seclists_installed(self) -> bool:
        """Check if SecLists is installed."""
        common_paths = [
            Path("/usr/share/seclists"),
            Path("/usr/share/wordlists/seclists"),
            Path("/opt/homebrew/Cellar/seclists"),
            Path("/usr/local/Cellar/seclists"),
            Path.home() / "SecLists",
            Path.home() / ".wordlists",
        ]
        return any(p.exists() for p in common_paths)

    def _get_install_command(self, info: ToolInfo) -> tuple[InstallMethod, list[str]] | None:
        """Get the install command for a tool based on platform and available methods."""
        # Platform-specific primary method
        if self._platform == Platform.MACOS and InstallMethod.BREW in self._available_methods:
            if info.brew_package:
                return (InstallMethod.BREW, ["brew", "install", info.brew_package])

        if self._platform == Platform.LINUX and InstallMethod.APT in self._available_methods:
            if info.apt_package:
                cmd = ["apt-get", "install", "-y", info.apt_package]
                if self._auto_sudo:
                    cmd = ["sudo"] + cmd
                return (InstallMethod.APT, cmd)

        # Fallback methods (cross-platform)
        if self._prefer_pipx and InstallMethod.PIPX in self._available_methods:
            if info.pipx_package:
                return (InstallMethod.PIPX, ["pipx", "install", info.pipx_package])

        if InstallMethod.PIP in self._available_methods:
            if info.pip_package:
                pip_cmd = "pip3" if shutil.which("pip3") else "pip"
                return (InstallMethod.PIP, [pip_cmd, "install", info.pip_package])

        if InstallMethod.GO in self._available_methods:
            if info.go_package:
                return (InstallMethod.GO, ["go", "install", info.go_package])

        if InstallMethod.CARGO in self._available_methods:
            if info.cargo_package:
                return (InstallMethod.CARGO, ["cargo", "install", info.cargo_package])

        # Fallback to brew even on Linux if available
        if InstallMethod.BREW in self._available_methods and info.brew_package:
            return (InstallMethod.BREW, ["brew", "install", info.brew_package])

        return None

    async def install_tool(self, tool: str, force: bool = False) -> InstallResult:
        """
        Install a single tool.

        Args:
            tool: Tool name to install.
            force: Force reinstall even if already installed.

        Returns:
            InstallResult with the outcome.
        """
        # Check if already installed
        if not force and self.is_installed(tool):
            return InstallResult(
                tool=tool,
                success=True,
                method=None,
                message=f"{tool} is already installed",
                already_installed=True,
            )

        # Get tool info
        info = SECURITY_TOOLS.get(tool)
        if not info:
            return InstallResult(
                tool=tool,
                success=False,
                method=None,
                message=f"Unknown tool: {tool}. Cannot auto-install.",
            )

        # Get install command
        install_info = self._get_install_command(info)
        if not install_info:
            manual_hint = f" See: {info.manual_url}" if info.manual_url else ""
            return InstallResult(
                tool=tool,
                success=False,
                method=InstallMethod.MANUAL,
                message=f"No installation method available for {tool}.{manual_hint}",
            )

        method, command = install_info
        logger.info("installing_tool", tool=tool, method=method.value, command=" ".join(command))

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300,  # 5 minute timeout for installation
            )

            if process.returncode == 0:
                logger.info("tool_installed", tool=tool, method=method.value)
                return InstallResult(
                    tool=tool,
                    success=True,
                    method=method,
                    message=f"Successfully installed {tool} via {method.value}",
                )
            else:
                error_msg = stderr.decode("utf-8", errors="replace")[:500]
                logger.warning("tool_install_failed", tool=tool, error=error_msg)
                return InstallResult(
                    tool=tool,
                    success=False,
                    method=method,
                    message=f"Failed to install {tool}: {error_msg}",
                )

        except TimeoutError:
            logger.warning("tool_install_timeout", tool=tool)
            return InstallResult(
                tool=tool,
                success=False,
                method=method,
                message=f"Installation of {tool} timed out after 5 minutes",
            )
        except Exception as e:
            logger.error("tool_install_error", tool=tool, error=str(e))
            return InstallResult(
                tool=tool,
                success=False,
                method=method,
                message=f"Error installing {tool}: {e}",
            )

    async def ensure_tool(self, tool: str) -> InstallResult:
        """
        Ensure a tool is installed, installing if necessary.

        Args:
            tool: Tool name to ensure.

        Returns:
            InstallResult with the outcome.
        """
        return await self.install_tool(tool, force=False)

    async def ensure_core_tools(self) -> list[InstallResult]:
        """
        Ensure all core tools are installed.

        Returns:
            List of InstallResults for each tool.
        """
        results = []
        for tool in CORE_TOOLS:
            result = await self.ensure_tool(tool)
            results.append(result)
        return results

    async def ensure_all_tools(self) -> list[InstallResult]:
        """
        Ensure all security tools are installed.

        Returns:
            List of InstallResults for each tool.
        """
        results = []
        all_tools = list(set(CORE_TOOLS + EXTENDED_TOOLS))
        for tool in all_tools:
            result = await self.ensure_tool(tool)
            results.append(result)
        return results

    async def install_tools_parallel(
        self,
        tools: list[str],
        max_concurrent: int = 3,
    ) -> list[InstallResult]:
        """
        Install multiple tools in parallel.

        Args:
            tools: List of tool names to install.
            max_concurrent: Maximum concurrent installations.

        Returns:
            List of InstallResults.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def install_with_semaphore(tool: str) -> InstallResult:
            async with semaphore:
                return await self.install_tool(tool)

        tasks = [install_with_semaphore(tool) for tool in tools]
        return await asyncio.gather(*tasks)

    def get_missing_tools(self, tools: list[str] | None = None) -> list[str]:
        """
        Get list of missing tools.

        Args:
            tools: List of tools to check. Defaults to core tools.

        Returns:
            List of missing tool names.
        """
        if tools is None:
            tools = CORE_TOOLS

        return [tool for tool in tools if not self.is_installed(tool)]

    def get_install_summary(self) -> dict[str, Any]:
        """
        Get a summary of tool installation status.

        Returns:
            Dictionary with installation status summary.
        """
        installed = []
        missing = []

        for tool in SECURITY_TOOLS:
            if self.is_installed(tool):
                installed.append(tool)
            else:
                missing.append(tool)

        return {
            "platform": self._platform.value,
            "available_methods": [m.value for m in self._available_methods],
            "installed_count": len(installed),
            "missing_count": len(missing),
            "installed": installed,
            "missing": missing,
            "core_missing": [t for t in CORE_TOOLS if t in missing],
        }


# Global installer instance
_tool_installer: ToolInstaller | None = None


def get_tool_installer() -> ToolInstaller:
    """Get the global ToolInstaller instance."""
    global _tool_installer
    if _tool_installer is None:
        _tool_installer = ToolInstaller()
    return _tool_installer


async def ensure_tool_installed(tool: str) -> bool:
    """
    Convenience function to ensure a tool is installed.

    Args:
        tool: Tool name to ensure.

    Returns:
        True if tool is available (installed or already present).
    """
    installer = get_tool_installer()
    result = await installer.ensure_tool(tool)
    return result.success
