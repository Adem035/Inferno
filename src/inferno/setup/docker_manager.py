"""
Docker manager for Inferno.

This module handles starting and managing Docker containers:
1. Qdrant - Vector memory storage
2. Kali - Isolated execution environment for pentesting tools
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class ContainerStatus(str, Enum):
    """Status of a Docker container."""

    RUNNING = "running"
    STOPPED = "stopped"
    NOT_FOUND = "not_found"
    ERROR = "error"


@dataclass
class ContainerInfo:
    """Information about a Docker container."""

    name: str
    status: ContainerStatus
    image: str | None = None
    ports: dict[str, str] | None = None
    message: str = ""


class DockerManager:
    """
    Manages Docker containers for Inferno.

    Handles automatic starting/stopping of required services:
    - Qdrant for vector memory storage
    - Kali Linux for isolated pentesting command execution
    """

    # Qdrant configuration
    QDRANT_CONTAINER_NAME = "inferno-qdrant"
    QDRANT_IMAGE = "qdrant/qdrant:latest"
    QDRANT_PORT = 6333
    QDRANT_GRPC_PORT = 6334

    # Kali execution container configuration
    KALI_CONTAINER_NAME = "inferno-kali"
    KALI_IMAGE = "kalilinux/kali-rolling:latest"
    KALI_WORKSPACE = "/workspace"

    def __init__(self) -> None:
        """Initialize the Docker manager."""
        self._docker_available: bool | None = None

    def is_docker_available(self) -> bool:
        """Check if Docker is available and running."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._docker_available = result.returncode == 0
        except Exception:
            self._docker_available = False

        return self._docker_available

    def get_container_status(self, container_name: str) -> ContainerInfo:
        """
        Get the status of a Docker container.

        Args:
            container_name: Name of the container.

        Returns:
            ContainerInfo with status details.
        """
        if not self.is_docker_available():
            return ContainerInfo(
                name=container_name,
                status=ContainerStatus.ERROR,
                message="Docker is not available",
            )

        try:
            # Check if container exists
            result = subprocess.run(
                ["docker", "inspect", container_name],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return ContainerInfo(
                    name=container_name,
                    status=ContainerStatus.NOT_FOUND,
                    message="Container does not exist",
                )

            # Parse container info
            import json
            info = json.loads(result.stdout)[0]
            state = info.get("State", {})
            is_running = state.get("Running", False)

            # Get port mappings
            ports = {}
            port_bindings = info.get("NetworkSettings", {}).get("Ports", {})
            for container_port, host_bindings in port_bindings.items():
                if host_bindings:
                    ports[container_port] = host_bindings[0].get("HostPort", "")

            return ContainerInfo(
                name=container_name,
                status=ContainerStatus.RUNNING if is_running else ContainerStatus.STOPPED,
                image=info.get("Config", {}).get("Image"),
                ports=ports,
                message="Running" if is_running else "Stopped",
            )

        except Exception as e:
            return ContainerInfo(
                name=container_name,
                status=ContainerStatus.ERROR,
                message=str(e),
            )

    def start_qdrant(self, wait: bool = True, timeout: int = 30) -> ContainerInfo:
        """
        Start the Qdrant container.

        Args:
            wait: Wait for Qdrant to be healthy.
            timeout: Timeout in seconds for health check.

        Returns:
            ContainerInfo with status.
        """
        if not self.is_docker_available():
            return ContainerInfo(
                name=self.QDRANT_CONTAINER_NAME,
                status=ContainerStatus.ERROR,
                message="Docker is not available. Please install and start Docker.",
            )

        # Check current status
        current = self.get_container_status(self.QDRANT_CONTAINER_NAME)

        if current.status == ContainerStatus.RUNNING:
            logger.info("qdrant_already_running")
            return current

        if current.status == ContainerStatus.STOPPED:
            # Start existing container
            logger.info("starting_existing_qdrant_container")
            result = subprocess.run(
                ["docker", "start", self.QDRANT_CONTAINER_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return ContainerInfo(
                    name=self.QDRANT_CONTAINER_NAME,
                    status=ContainerStatus.ERROR,
                    message=f"Failed to start container: {result.stderr}",
                )
        else:
            # Create and start new container
            logger.info("creating_qdrant_container", image=self.QDRANT_IMAGE)

            # Pull image first
            subprocess.run(
                ["docker", "pull", self.QDRANT_IMAGE],
                capture_output=True,
                timeout=120,
            )

            # Create container
            result = subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", self.QDRANT_CONTAINER_NAME,
                    "-p", f"{self.QDRANT_PORT}:{self.QDRANT_PORT}",
                    "-p", f"{self.QDRANT_GRPC_PORT}:{self.QDRANT_GRPC_PORT}",
                    "-v", "inferno-qdrant-data:/qdrant/storage",
                    "--restart", "unless-stopped",
                    self.QDRANT_IMAGE,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                return ContainerInfo(
                    name=self.QDRANT_CONTAINER_NAME,
                    status=ContainerStatus.ERROR,
                    message=f"Failed to create container: {result.stderr}",
                )

        # Wait for health check if requested
        if wait:
            if self._wait_for_qdrant_health(timeout):
                logger.info("qdrant_started_successfully")
                return ContainerInfo(
                    name=self.QDRANT_CONTAINER_NAME,
                    status=ContainerStatus.RUNNING,
                    image=self.QDRANT_IMAGE,
                    ports={f"{self.QDRANT_PORT}/tcp": str(self.QDRANT_PORT)},
                    message="Running and healthy",
                )
            else:
                return ContainerInfo(
                    name=self.QDRANT_CONTAINER_NAME,
                    status=ContainerStatus.ERROR,
                    message="Container started but health check failed",
                )

        return self.get_container_status(self.QDRANT_CONTAINER_NAME)

    def stop_qdrant(self) -> ContainerInfo:
        """
        Stop the Qdrant container.

        Returns:
            ContainerInfo with status.
        """
        if not self.is_docker_available():
            return ContainerInfo(
                name=self.QDRANT_CONTAINER_NAME,
                status=ContainerStatus.ERROR,
                message="Docker is not available",
            )

        result = subprocess.run(
            ["docker", "stop", self.QDRANT_CONTAINER_NAME],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.info("qdrant_stopped")
            return ContainerInfo(
                name=self.QDRANT_CONTAINER_NAME,
                status=ContainerStatus.STOPPED,
                message="Container stopped",
            )

        return self.get_container_status(self.QDRANT_CONTAINER_NAME)

    def remove_qdrant(self) -> bool:
        """
        Remove the Qdrant container and volume.

        Returns:
            True if successful.
        """
        if not self.is_docker_available():
            return False

        # Stop container
        subprocess.run(
            ["docker", "stop", self.QDRANT_CONTAINER_NAME],
            capture_output=True,
            timeout=30,
        )

        # Remove container
        subprocess.run(
            ["docker", "rm", self.QDRANT_CONTAINER_NAME],
            capture_output=True,
            timeout=30,
        )

        # Remove volume
        subprocess.run(
            ["docker", "volume", "rm", "inferno-qdrant-data"],
            capture_output=True,
            timeout=30,
        )

        logger.info("qdrant_removed")
        return True

    def _wait_for_qdrant_health(self, timeout: int = 30) -> bool:
        """
        Wait for Qdrant to be healthy.

        Args:
            timeout: Timeout in seconds.

        Returns:
            True if healthy within timeout.
        """
        url = f"http://localhost:{self.QDRANT_PORT}/healthz"
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                response = httpx.get(url, timeout=2.0)
                if response.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(1)

        return False

    def ensure_qdrant_running(self) -> bool:
        """
        Ensure Qdrant is running, starting it if necessary.

        Returns:
            True if Qdrant is running.
        """
        status = self.get_container_status(self.QDRANT_CONTAINER_NAME)

        if status.status == ContainerStatus.RUNNING:
            return True

        result = self.start_qdrant(wait=True)
        return result.status == ContainerStatus.RUNNING

    def get_qdrant_url(self) -> str:
        """Get the Qdrant connection URL."""
        return f"http://localhost:{self.QDRANT_PORT}"

    # ==================== Kali Container Methods ====================

    def start_kali(self, wait: bool = True, timeout: int = 60) -> ContainerInfo:
        """
        Start the Kali Linux execution container.

        Args:
            wait: Wait for container to be ready.
            timeout: Timeout in seconds.

        Returns:
            ContainerInfo with status.
        """
        if not self.is_docker_available():
            return ContainerInfo(
                name=self.KALI_CONTAINER_NAME,
                status=ContainerStatus.ERROR,
                message="Docker is not available. Please install and start Docker.",
            )

        current = self.get_container_status(self.KALI_CONTAINER_NAME)

        if current.status == ContainerStatus.RUNNING:
            logger.info("kali_already_running")
            return current

        if current.status == ContainerStatus.STOPPED:
            logger.info("starting_existing_kali_container")
            result = subprocess.run(
                ["docker", "start", self.KALI_CONTAINER_NAME],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return ContainerInfo(
                    name=self.KALI_CONTAINER_NAME,
                    status=ContainerStatus.ERROR,
                    message=f"Failed to start container: {result.stderr}",
                )
        else:
            logger.info("creating_kali_container", image=self.KALI_IMAGE)

            # Pull image first
            subprocess.run(
                ["docker", "pull", self.KALI_IMAGE],
                capture_output=True,
                timeout=300,
            )

            # Build docker run command
            # SecLists will be installed via apt inside the container
            cmd = [
                "docker", "run", "-d",
                "--name", self.KALI_CONTAINER_NAME,
                "-v", "inferno-kali-workspace:/workspace",
                "--network", "host",
                "--restart", "unless-stopped",
                self.KALI_IMAGE, "tail", "-f", "/dev/null",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                return ContainerInfo(
                    name=self.KALI_CONTAINER_NAME,
                    status=ContainerStatus.ERROR,
                    message=f"Failed to create container: {result.stderr}",
                )

            # Install essential pentesting tools
            if wait:
                self._install_kali_tools()

        if wait:
            if self._wait_for_kali_ready(timeout):
                logger.info("kali_started_successfully")
                return ContainerInfo(
                    name=self.KALI_CONTAINER_NAME,
                    status=ContainerStatus.RUNNING,
                    image=self.KALI_IMAGE,
                    message="Running and ready",
                )
            else:
                return ContainerInfo(
                    name=self.KALI_CONTAINER_NAME,
                    status=ContainerStatus.ERROR,
                    message="Container started but readiness check failed",
                )

        return self.get_container_status(self.KALI_CONTAINER_NAME)

    def stop_kali(self) -> ContainerInfo:
        """Stop the Kali container."""
        if not self.is_docker_available():
            return ContainerInfo(
                name=self.KALI_CONTAINER_NAME,
                status=ContainerStatus.ERROR,
                message="Docker is not available",
            )

        result = subprocess.run(
            ["docker", "stop", self.KALI_CONTAINER_NAME],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            logger.info("kali_stopped")
            return ContainerInfo(
                name=self.KALI_CONTAINER_NAME,
                status=ContainerStatus.STOPPED,
                message="Container stopped",
            )

        return self.get_container_status(self.KALI_CONTAINER_NAME)

    def remove_kali(self) -> bool:
        """Remove the Kali container and workspace volume."""
        if not self.is_docker_available():
            return False

        subprocess.run(
            ["docker", "stop", self.KALI_CONTAINER_NAME],
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "rm", self.KALI_CONTAINER_NAME],
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "volume", "rm", "inferno-kali-workspace"],
            capture_output=True,
            timeout=30,
        )

        logger.info("kali_removed")
        return True

    def ensure_kali_running(self) -> bool:
        """Ensure Kali is running, starting it if necessary."""
        status = self.get_container_status(self.KALI_CONTAINER_NAME)

        if status.status == ContainerStatus.RUNNING:
            return True

        result = self.start_kali(wait=True)
        return result.status == ContainerStatus.RUNNING

    def _wait_for_kali_ready(self, timeout: int = 60) -> bool:
        """Wait for Kali container to be ready."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                result = subprocess.run(
                    ["docker", "exec", self.KALI_CONTAINER_NAME, "echo", "ready"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and "ready" in result.stdout:
                    return True
            except Exception:
                pass
            time.sleep(1)

        return False

    def _install_kali_tools(self) -> None:
        """Install essential pentesting tools in Kali container."""
        logger.info("installing_kali_tools")

        # Install comprehensive pentesting toolkit
        install_cmd = (
            "apt-get update && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y "
            # Network scanning
            "nmap masscan "
            # Web fuzzing & directory bruteforce
            "gobuster ffuf dirb feroxbuster "
            # Vulnerability scanners
            "nikto sqlmap nuclei wpscan "
            # Password & brute force
            "hydra john hashcat medusa "
            # Exploitation tools
            "exploitdb "  # searchsploit
            # Recon & OSINT
            "subfinder amass dnsrecon whatweb wafw00f "
            # Utilities
            "curl wget python3 python3-pip python3-requests "
            "netcat-openbsd dnsutils whois git jq "
            # SecLists - comprehensive wordlists
            "seclists wordlists "
            "&& apt-get clean && rm -rf /var/lib/apt/lists/* "
            # Update nuclei templates to latest
            "&& nuclei -update-templates 2>/dev/null || true"
        )

        subprocess.run(
            ["docker", "exec", self.KALI_CONTAINER_NAME, "sh", "-c", install_cmd],
            capture_output=True,
            timeout=900,  # 15 min for larger install
        )

    def install_additional_tools(self, tools: list[str]) -> dict[str, bool]:
        """
        Install additional tools in the Kali container on-demand.

        Args:
            tools: List of apt package names to install.

        Returns:
            Dict mapping tool names to success status.
        """
        if not self.ensure_kali_running():
            return {tool: False for tool in tools}

        results = {}
        for tool in tools:
            result = subprocess.run(
                [
                    "docker", "exec", self.KALI_CONTAINER_NAME,
                    "sh", "-c",
                    f"DEBIAN_FRONTEND=noninteractive apt-get install -y {tool}"
                ],
                capture_output=True,
                timeout=300,
            )
            results[tool] = result.returncode == 0
            if result.returncode == 0:
                logger.info("tool_installed", tool=tool)
            else:
                logger.warning("tool_install_failed", tool=tool, error=result.stderr.decode())

        return results

    async def execute_in_kali(
        self,
        command: str,
        timeout: int = 300,
        workdir: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute a command in the Kali container.

        Args:
            command: Command to execute.
            timeout: Timeout in seconds.
            workdir: Working directory inside container.

        Returns:
            Dict with stdout, stderr, return_code.
        """
        if not self.ensure_kali_running():
            return {
                "stdout": "",
                "stderr": "Failed to start Kali container",
                "return_code": -1,
                "success": False,
            }

        # Build docker exec command
        cmd = ["docker", "exec"]

        if workdir:
            cmd.extend(["-w", workdir])

        cmd.extend([self.KALI_CONTAINER_NAME, "sh", "-c", command])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "return_code": proc.returncode,
                "success": proc.returncode == 0,
            }

        except asyncio.TimeoutError:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
                "return_code": -1,
                "success": False,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "success": False,
            }

    def execute_in_kali_sync(
        self,
        command: str,
        timeout: int = 300,
        workdir: str | None = None,
    ) -> dict[str, Any]:
        """
        Execute a command in the Kali container (synchronous version).

        Args:
            command: Command to execute.
            timeout: Timeout in seconds.
            workdir: Working directory inside container.

        Returns:
            Dict with stdout, stderr, return_code.
        """
        if not self.ensure_kali_running():
            return {
                "stdout": "",
                "stderr": "Failed to start Kali container",
                "return_code": -1,
                "success": False,
            }

        cmd = ["docker", "exec"]

        if workdir:
            cmd.extend(["-w", workdir])

        cmd.extend([self.KALI_CONTAINER_NAME, "sh", "-c", command])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "success": result.returncode == 0,
            }

        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
                "return_code": -1,
                "success": False,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "success": False,
            }
