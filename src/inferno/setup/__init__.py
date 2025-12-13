"""
Inferno Setup Package.

This module handles automatic setup, dependency checking,
and environment management for a seamless first-run experience.
"""

from inferno.setup.checker import SetupChecker, SetupStatus
from inferno.setup.docker_manager import DockerManager
from inferno.setup.installer import (
    InstallResult,
    ToolInfo,
    ToolInstaller,
    ensure_tool_installed,
    get_tool_installer,
)

__all__ = [
    "DockerManager",
    "InstallResult",
    "SetupChecker",
    "SetupStatus",
    "ToolInfo",
    "ToolInstaller",
    "ensure_tool_installed",
    "get_tool_installer",
]
