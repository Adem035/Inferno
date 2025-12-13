"""
Shell Session Management for Inferno.

Provides PTY-based interactive shell sessions with:
- Friendly session IDs (S1, S2, S3)
- Streaming output with Rich panels
- Idle timeout detection
- Environment auto-detection (local, container, SSH)
- Non-blocking read using select

Ported from CAI with Inferno-specific adaptations.
"""

from __future__ import annotations

import os
import pty
import select
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


# ============================================================================
# Global Session Registry
# ============================================================================

# Active sessions keyed by full session ID
ACTIVE_SESSIONS: Dict[str, "ShellSession"] = {}

# Friendly ID mappings: S1 -> full_id, full_id -> S1
FRIENDLY_SESSION_MAP: Dict[str, str] = {}
REVERSE_SESSION_MAP: Dict[str, str] = {}
SESSION_COUNTER: int = 0


class SessionEnvironment(str, Enum):
    """Execution environment types."""
    LOCAL = "local"
    CONTAINER = "container"
    SSH = "ssh"


@dataclass
class SessionInfo:
    """Information about a shell session for display."""
    friendly_id: str
    session_id: str
    command: str
    environment: SessionEnvironment
    is_running: bool
    created_at: float
    last_activity: float
    output_lines: int = 0


# ============================================================================
# Workspace Directory Resolution
# ============================================================================

def get_workspace_dir() -> str:
    """
    Determine the target workspace directory based on environment variables.

    Checks:
    - INFERNO_WORKSPACE_DIR: Base directory for workspaces
    - INFERNO_WORKSPACE: Specific workspace name
    - Falls back to current working directory

    Returns:
        Absolute path to the workspace directory.
    """
    base_dir_env = os.getenv("INFERNO_WORKSPACE_DIR")
    workspace_name = os.getenv("INFERNO_WORKSPACE")

    # Determine base directory
    if base_dir_env:
        base_dir = os.path.abspath(base_dir_env)
    elif workspace_name:
        base_dir = os.path.join(os.getcwd(), "workspaces")
    else:
        return os.getcwd()

    # Append workspace name if provided
    if workspace_name:
        # Validate workspace name
        if not all(c.isalnum() or c in ('_', '-') for c in workspace_name):
            logger.warning(
                "invalid_workspace_name",
                workspace=workspace_name,
                fallback=base_dir
            )
            target_dir = base_dir
        else:
            target_dir = os.path.join(base_dir, workspace_name)
    else:
        target_dir = base_dir

    # Ensure directory exists
    abs_target_dir = os.path.abspath(target_dir)
    try:
        os.makedirs(abs_target_dir, exist_ok=True)
        return abs_target_dir
    except OSError as e:
        logger.error(
            "workspace_creation_failed",
            directory=abs_target_dir,
            error=str(e)
        )
        return os.getcwd()


def get_container_workspace_path() -> str:
    """
    Determine the workspace path inside a container.

    Returns:
        Container workspace path (default: /workspace).
    """
    workspace_name = os.getenv("INFERNO_WORKSPACE")
    if workspace_name:
        if not all(c.isalnum() or c in ('_', '-') for c in workspace_name):
            return "/workspace"
        return f"/workspace/workspaces/{workspace_name}"
    return "/workspace"


# ============================================================================
# Shell Session Class
# ============================================================================

class ShellSession:
    """
    Interactive shell session with PTY support.

    Features:
    - PTY-based terminal emulation
    - Non-blocking output reading with select()
    - Idle timeout detection
    - Process group management for clean termination
    - Environment auto-detection (local, container, SSH)
    - Friendly session IDs (S1, S2, S3)
    - Streaming output support with Rich panels

    Attributes:
        session_id: Unique session identifier (UUID)
        friendly_id: Human-friendly alias (S1, S2, etc.)
        command: The command being executed
        environment: Execution environment type
        is_running: Whether the session is active
        output_buffer: Accumulated output lines
    """

    def __init__(
        self,
        command: str,
        session_id: Optional[str] = None,
        container_id: Optional[str] = None,
        ssh_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        workspace_dir: Optional[str] = None,
        idle_timeout: float = 300.0,
        on_output: Optional[Callable[[str], None]] = None,
    ) -> None:
        """
        Initialize a shell session.

        Args:
            command: Command to execute
            session_id: Optional custom session ID (auto-generated if not provided)
            container_id: Docker container ID for container execution
            ssh_host: SSH host for remote execution
            ssh_user: SSH username for remote execution
            workspace_dir: Working directory for the command
            idle_timeout: Seconds of inactivity before marking as idle
            on_output: Optional callback for streaming output
        """
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.friendly_id: Optional[str] = None
        self.command = command
        self.container_id = container_id
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.idle_timeout = idle_timeout
        self.on_output = on_output

        # Determine environment and workspace
        if container_id:
            self.environment = SessionEnvironment.CONTAINER
            self.workspace_dir = get_container_workspace_path()
        elif ssh_host and ssh_user:
            self.environment = SessionEnvironment.SSH
            self.workspace_dir = workspace_dir or "/tmp"
        else:
            self.environment = SessionEnvironment.LOCAL
            self.workspace_dir = workspace_dir or get_workspace_dir()

        # Process and PTY handles
        self.process: Optional[subprocess.Popen] = None
        self.master_fd: Optional[int] = None
        self.slave_fd: Optional[int] = None

        # State tracking
        self.created_at = time.time()
        self.last_activity = time.time()
        self.is_running = False
        self.is_idle = False

        # Output management
        self.output_buffer: List[str] = []
        self._output_position: int = 0
        self._read_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        logger.debug(
            "session_created",
            session_id=self.session_id,
            command=command[:50],
            environment=self.environment.value
        )

    def start(self) -> Optional[str]:
        """
        Start the shell session.

        Returns:
            None on success, error message on failure.
        """
        if self.environment == SessionEnvironment.CONTAINER:
            return self._start_in_container()
        elif self.environment == SessionEnvironment.SSH:
            return self._start_via_ssh()
        else:
            return self._start_local()

    def _start_local(self) -> Optional[str]:
        """Start a local PTY session."""
        try:
            self.master_fd, self.slave_fd = pty.openpty()

            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                cwd=self.workspace_dir,
                preexec_fn=os.setsid,
                universal_newlines=True,
            )

            self.is_running = True
            self.output_buffer.append(
                f"[Session {self.session_id}] Started: {self.command}"
            )

            # Start output reader thread
            self._read_thread = threading.Thread(
                target=self._read_output,
                daemon=True,
                name=f"session-reader-{self.session_id}"
            )
            self._read_thread.start()

            logger.info(
                "session_started_local",
                session_id=self.session_id,
                pid=self.process.pid,
                workspace=self.workspace_dir
            )
            return None

        except Exception as e:
            error_msg = f"Error starting local session: {e}"
            self.output_buffer.append(error_msg)
            self.is_running = False
            logger.error("session_start_failed", error=str(e))
            return error_msg

    def _start_in_container(self) -> Optional[str]:
        """Start a session inside a Docker container."""
        try:
            self.master_fd, self.slave_fd = pty.openpty()

            docker_cmd = [
                "docker", "exec", "-i", "-t",
                "-w", self.workspace_dir,
                self.container_id,
                "sh", "-c", self.command,
            ]

            self.process = subprocess.Popen(
                docker_cmd,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid,
                universal_newlines=True,
            )

            self.is_running = True
            container_short = self.container_id[:12] if self.container_id else "unknown"
            self.output_buffer.append(
                f"[Session {self.session_id}] Started in container {container_short}: {self.command}"
            )

            # Start output reader thread
            self._read_thread = threading.Thread(
                target=self._read_output,
                daemon=True,
                name=f"session-reader-{self.session_id}"
            )
            self._read_thread.start()

            logger.info(
                "session_started_container",
                session_id=self.session_id,
                container=container_short,
                pid=self.process.pid
            )
            return None

        except Exception as e:
            error_msg = f"Error starting container session: {e}"
            self.output_buffer.append(error_msg)
            self.is_running = False
            logger.error("session_start_failed_container", error=str(e))
            return error_msg

    def _start_via_ssh(self) -> Optional[str]:
        """Start a session via SSH."""
        try:
            self.master_fd, self.slave_fd = pty.openpty()

            ssh_pass = os.environ.get('SSH_PASS')
            if ssh_pass:
                ssh_cmd = [
                    "sshpass", "-p", ssh_pass,
                    "ssh", "-t",
                    f"{self.ssh_user}@{self.ssh_host}",
                    self.command
                ]
            else:
                ssh_cmd = [
                    "ssh", "-t",
                    f"{self.ssh_user}@{self.ssh_host}",
                    self.command
                ]

            self.process = subprocess.Popen(
                ssh_cmd,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid,
                universal_newlines=True,
            )

            self.is_running = True
            self.output_buffer.append(
                f"[Session {self.session_id}] Started via SSH to {self.ssh_host}: {self.command}"
            )

            # Start output reader thread
            self._read_thread = threading.Thread(
                target=self._read_output,
                daemon=True,
                name=f"session-reader-{self.session_id}"
            )
            self._read_thread.start()

            logger.info(
                "session_started_ssh",
                session_id=self.session_id,
                host=self.ssh_host,
                pid=self.process.pid
            )
            return None

        except FileNotFoundError:
            error_msg = "SSH or sshpass command not found. Ensure they are installed."
            self.output_buffer.append(error_msg)
            self.is_running = False
            return error_msg
        except Exception as e:
            error_msg = f"Error starting SSH session: {e}"
            self.output_buffer.append(error_msg)
            self.is_running = False
            logger.error("session_start_failed_ssh", error=str(e))
            return error_msg

    def _read_output(self) -> None:
        """
        Read output from PTY with non-blocking select.

        This runs in a background thread and continuously reads
        output from the PTY master file descriptor.
        """
        try:
            while self.is_running and self.master_fd is not None:
                # Check if process has exited
                if self.process and self.process.poll() is not None:
                    self.is_running = False
                    break

                # Non-blocking check for data using select
                try:
                    ready, _, _ = select.select([self.master_fd], [], [], 0.5)
                except (ValueError, OSError):
                    # File descriptor closed or invalid
                    self.is_running = False
                    break

                if not ready:
                    # No data available - check idle timeout
                    idle_time = time.time() - self.last_activity
                    if idle_time > self.idle_timeout:
                        self.is_idle = True

                    # Re-check process status
                    if self.process and self.process.poll() is not None:
                        self.is_running = False
                        break
                    continue

                # Read available data
                try:
                    data = os.read(self.master_fd, 4096)
                    if data:
                        output = data.decode('utf-8', errors='replace')
                        with self._lock:
                            self.output_buffer.append(output)
                        self.last_activity = time.time()
                        self.is_idle = False

                        # Call streaming callback if provided
                        if self.on_output:
                            try:
                                self.on_output(output)
                            except Exception:
                                pass  # Don't let callback errors kill the reader
                    else:
                        # Empty read - check if process is still running
                        if self.process and self.process.poll() is None:
                            # Process alive but no output - might be waiting for input
                            pass
                        else:
                            self.is_running = False
                            break
                except UnicodeDecodeError:
                    with self._lock:
                        self.output_buffer.append(
                            f"[Session {self.session_id}] Unicode decode error in output\n"
                        )
                except OSError as e:
                    with self._lock:
                        self.output_buffer.append(f"Error reading output: {e}\n")
                    self.is_running = False
                    break

                # Small sleep to prevent busy-waiting
                if self.is_process_running():
                    time.sleep(0.05)

        except Exception as e:
            with self._lock:
                self.output_buffer.append(f"Error in read_output loop: {e}")
            self.is_running = False
            logger.error("read_output_error", session_id=self.session_id, error=str(e))

    def is_process_running(self) -> bool:
        """Check if the underlying process is still running."""
        if not self.process:
            return False
        return self.process.poll() is None

    def send_input(self, input_data: str) -> str:
        """
        Send input to the session.

        Args:
            input_data: Text to send to the process

        Returns:
            Status message.
        """
        if not self.is_running:
            # Check if process is actually still running
            if self.process and self.process.poll() is None:
                self.is_running = True
            else:
                return "Session is not running"

        try:
            if self.master_fd is not None:
                # Append newline if not present
                if not input_data.endswith('\n'):
                    input_data = input_data + '\n'

                input_bytes = input_data.encode('utf-8')
                bytes_written = os.write(self.master_fd, input_bytes)

                if bytes_written != len(input_bytes):
                    with self._lock:
                        self.output_buffer.append(
                            f"[Session {self.session_id}] Warning: Partial input write"
                        )

                self.last_activity = time.time()
                return "Input sent to session"
            else:
                return "Session PTY not available"

        except Exception as e:
            error_msg = f"Error sending input: {e}"
            with self._lock:
                self.output_buffer.append(error_msg)
            return error_msg

    def get_output(self, clear: bool = True) -> str:
        """
        Get accumulated output from the session.

        Args:
            clear: Whether to clear the buffer after reading

        Returns:
            Concatenated output string.
        """
        with self._lock:
            output = "".join(self.output_buffer)
            if clear:
                self.output_buffer.clear()
            return output

    def get_new_output(self, mark_position: bool = True) -> str:
        """
        Get only new output since last read.

        Args:
            mark_position: Whether to update the read position

        Returns:
            New output since last marked position.
        """
        with self._lock:
            new_lines = self.output_buffer[self._output_position:]
            new_output = "".join(new_lines)

            if mark_position:
                self._output_position = len(self.output_buffer)

            return new_output

    def terminate(self) -> str:
        """
        Terminate the session and clean up resources.

        Returns:
            Termination status message.
        """
        session_short = self.session_id[:8]
        message = f"Session {session_short} terminated"

        if not self.is_running:
            if self.process and self.process.poll() is None:
                pass  # Process is running, proceed with termination
            else:
                return f"Session {session_short} already terminated"

        try:
            self.is_running = False

            if self.process:
                try:
                    # Try to terminate the process group
                    pgid = os.getpgid(self.process.pid)
                    os.killpg(pgid, signal.SIGTERM)

                    # Wait briefly for graceful shutdown
                    try:
                        self.process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        # Force kill if still running
                        logger.warning(
                            "session_force_kill",
                            session_id=session_short
                        )
                        os.killpg(pgid, signal.SIGKILL)
                        self.process.wait(timeout=1.0)

                except ProcessLookupError:
                    pass  # Process already gone
                except Exception as e:
                    message = f"Session {session_short} terminated (with error: {e})"
                    try:
                        self.process.kill()
                    except Exception:
                        pass

                # Final check
                if self.process.poll() is None:
                    logger.warning(
                        "session_still_running",
                        session_id=session_short,
                        pid=self.process.pid
                    )
                    message += " (Warning: Process may still be running)"

            # Clean up PTY file descriptors
            if self.master_fd is not None:
                try:
                    os.close(self.master_fd)
                except OSError:
                    pass
                self.master_fd = None

            if self.slave_fd is not None:
                try:
                    os.close(self.slave_fd)
                except OSError:
                    pass
                self.slave_fd = None

            logger.info("session_terminated", session_id=session_short)
            return message

        except Exception as e:
            return f"Error terminating session {session_short}: {e}"

    def get_info(self) -> SessionInfo:
        """Get session information for display."""
        return SessionInfo(
            friendly_id=self.friendly_id or f"S{self.session_id[:4]}",
            session_id=self.session_id,
            command=self.command,
            environment=self.environment,
            is_running=self.is_running,
            created_at=self.created_at,
            last_activity=self.last_activity,
            output_lines=len(self.output_buffer)
        )


# ============================================================================
# Session Management Functions
# ============================================================================

def create_shell_session(
    command: str,
    container_id: Optional[str] = None,
    ssh_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    workspace_dir: Optional[str] = None,
    idle_timeout: float = 300.0,
    on_output: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Create and start a new shell session.

    Args:
        command: Command to execute
        container_id: Docker container ID for container execution
        ssh_host: SSH host for remote execution
        ssh_user: SSH username for remote execution
        workspace_dir: Working directory
        idle_timeout: Idle timeout in seconds
        on_output: Callback for streaming output

    Returns:
        Session ID (full UUID portion) on success,
        error message (prefixed with "Failed:") on failure.
    """
    global SESSION_COUNTER

    # Auto-detect environment if not explicitly specified
    if not container_id:
        container_id = os.getenv("INFERNO_CONTAINER")
    if not ssh_host:
        ssh_host = os.getenv("SSH_HOST")
    if not ssh_user:
        ssh_user = os.getenv("SSH_USER")

    session = ShellSession(
        command=command,
        container_id=container_id,
        ssh_host=ssh_host,
        ssh_user=ssh_user,
        workspace_dir=workspace_dir,
        idle_timeout=idle_timeout,
        on_output=on_output,
    )

    error = session.start()

    if session.is_running or error is None:
        # Register session and assign friendly ID
        SESSION_COUNTER += 1
        friendly_id = f"S{SESSION_COUNTER}"
        session.friendly_id = friendly_id

        ACTIVE_SESSIONS[session.session_id] = session
        FRIENDLY_SESSION_MAP[friendly_id] = session.session_id
        REVERSE_SESSION_MAP[session.session_id] = friendly_id

        logger.info(
            "session_registered",
            friendly_id=friendly_id,
            session_id=session.session_id,
            command=command[:50]
        )
        return session.session_id
    else:
        error_msg = session.get_output(clear=True)
        logger.error("session_creation_failed", error=error_msg)
        return f"Failed: {error_msg}"


def list_shell_sessions() -> List[SessionInfo]:
    """
    List all active shell sessions.

    Returns:
        List of SessionInfo for all active sessions.
    """
    result = []

    for session_id in list(ACTIVE_SESSIONS.keys()):
        session = ACTIVE_SESSIONS.get(session_id)
        if session is None:
            continue

        # Clean up terminated sessions
        if not session.is_running and not session.is_process_running():
            del ACTIVE_SESSIONS[session_id]
            friendly = REVERSE_SESSION_MAP.pop(session_id, None)
            if friendly:
                FRIENDLY_SESSION_MAP.pop(friendly, None)
            continue

        result.append(session.get_info())

    return result


def resolve_session_id(session_identifier: str) -> Optional[str]:
    """
    Resolve a session identifier to a full session ID.

    Accepts multiple formats:
    - Full session ID: "abc12345"
    - Friendly ID: "S1", "s1"
    - Numeric: "1", "#1"
    - Special: "last" for most recent session

    Args:
        session_identifier: Session identifier in any format

    Returns:
        Full session ID or None if not found.
    """
    if not session_identifier:
        return None

    sid = str(session_identifier).strip()

    # Handle "last" - return most recent active session
    if sid.lower() == 'last':
        if not ACTIVE_SESSIONS:
            return None
        latest = None
        latest_time = -1.0
        for sess_id, session in ACTIVE_SESSIONS.items():
            if session.created_at > latest_time and session.is_running:
                latest = sess_id
                latest_time = session.created_at
        return latest or next(iter(ACTIVE_SESSIONS.keys()), None)

    # Normalize to friendly format
    key = sid
    if sid.startswith('#'):
        key = f"S{sid[1:]}"
    elif sid.isdigit():
        key = f"S{sid}"
    elif sid.upper().startswith('S') and sid[1:].isdigit():
        key = sid.upper()

    # Check direct match (full ID)
    if sid in ACTIVE_SESSIONS:
        return sid

    # Check friendly map
    if key in FRIENDLY_SESSION_MAP:
        return FRIENDLY_SESSION_MAP[key]

    # Partial match on full ID
    for full_id in ACTIVE_SESSIONS.keys():
        if full_id.startswith(sid) or sid in full_id:
            return full_id

    return None


def send_to_session(session_identifier: str, input_data: str) -> str:
    """
    Send input to a specific session.

    Args:
        session_identifier: Session ID (full, friendly, or partial)
        input_data: Text to send

    Returns:
        Status message.
    """
    resolved = resolve_session_id(session_identifier)
    if not resolved or resolved not in ACTIVE_SESSIONS:
        return f"Session {session_identifier} not found"

    session = ACTIVE_SESSIONS[resolved]
    return session.send_input(input_data)


def get_session_output(session_identifier: str, clear: bool = True) -> str:
    """
    Get output from a specific session.

    Args:
        session_identifier: Session ID (full, friendly, or partial)
        clear: Whether to clear the buffer after reading

    Returns:
        Session output or error message.
    """
    resolved = resolve_session_id(session_identifier)
    if not resolved or resolved not in ACTIVE_SESSIONS:
        return f"Session {session_identifier} not found"

    session = ACTIVE_SESSIONS[resolved]
    return session.get_output(clear)


def terminate_session(session_identifier: str) -> str:
    """
    Terminate a specific session.

    Args:
        session_identifier: Session ID (full, friendly, or partial)

    Returns:
        Termination status message.
    """
    resolved = resolve_session_id(session_identifier)
    if not resolved or resolved not in ACTIVE_SESSIONS:
        return f"Session {session_identifier} not found or already terminated"

    session = ACTIVE_SESSIONS[resolved]
    result = session.terminate()

    # Clean up registries
    if resolved in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[resolved]
    friendly = REVERSE_SESSION_MAP.pop(resolved, None)
    if friendly:
        FRIENDLY_SESSION_MAP.pop(friendly, None)

    return result


def terminate_all_sessions() -> str:
    """
    Terminate all active sessions.

    Returns:
        Summary of terminated sessions.
    """
    count = 0
    for session_id in list(ACTIVE_SESSIONS.keys()):
        session = ACTIVE_SESSIONS.get(session_id)
        if session:
            session.terminate()
            count += 1

    ACTIVE_SESSIONS.clear()
    FRIENDLY_SESSION_MAP.clear()
    REVERSE_SESSION_MAP.clear()

    return f"Terminated {count} session(s)"


def get_session(session_identifier: str) -> Optional[ShellSession]:
    """
    Get a session object by identifier.

    Args:
        session_identifier: Session ID (full, friendly, or partial)

    Returns:
        ShellSession or None if not found.
    """
    resolved = resolve_session_id(session_identifier)
    if resolved:
        return ACTIVE_SESSIONS.get(resolved)
    return None


# ============================================================================
# Rich Display Helpers
# ============================================================================

def format_sessions_table() -> str:
    """
    Format active sessions as a table string.

    Returns:
        Formatted string with session information.
    """
    sessions = list_shell_sessions()

    if not sessions:
        return "No active sessions"

    lines = ["Active Sessions:", ""]
    lines.append(f"{'ID':<6} {'Command':<40} {'Status':<10} {'Last Activity':<15}")
    lines.append("-" * 75)

    for info in sessions:
        cmd = info.command[:38] + ".." if len(info.command) > 40 else info.command
        status = "running" if info.is_running else "stopped"
        if info.is_running:
            # Check if idle
            session = get_session(info.session_id)
            if session and session.is_idle:
                status = "idle"

        last_activity = time.strftime(
            "%H:%M:%S",
            time.localtime(info.last_activity)
        )

        lines.append(f"{info.friendly_id:<6} {cmd:<40} {status:<10} {last_activity:<15}")

    return "\n".join(lines)


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    # Classes
    "ShellSession",
    "SessionEnvironment",
    "SessionInfo",
    # Session management
    "create_shell_session",
    "list_shell_sessions",
    "resolve_session_id",
    "send_to_session",
    "get_session_output",
    "terminate_session",
    "terminate_all_sessions",
    "get_session",
    # Utilities
    "get_workspace_dir",
    "get_container_workspace_path",
    "format_sessions_table",
    # Globals (for advanced use)
    "ACTIVE_SESSIONS",
    "FRIENDLY_SESSION_MAP",
    "REVERSE_SESSION_MAP",
]
