"""
Unified Execute Command Tool - The ONE tool to run everything.

This is the primary tool for Inferno. Instead of 81 specialized tools,
the agent uses this single tool to run any command it needs:
- nmap, sqlmap, gobuster, hydra
- curl, wget, nc, ssh
- python, bash, any script
- Everything else

Design Philosophy:
- Let the LLM decide what command to run (it knows pentest tools)
- Don't force tool selection decisions before execution
- Reduce cognitive load: "run this command" not "which of 81 tools?"
"""

from __future__ import annotations

import asyncio
import os
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

from inferno.tools.base import ToolCategory, ToolResult
from inferno.tools.decorator import function_tool
from inferno.tools.shell_session import (
    ShellSession,
    create_shell_session,
    list_shell_sessions,
    resolve_session_id,
    send_to_session,
    get_session_output as shell_get_output,
    terminate_session,
    terminate_all_sessions,
    get_session,
    format_sessions_table,
    ACTIVE_SESSIONS,
)

logger = structlog.get_logger(__name__)


# ============================================================================
# Session Management (Using ShellSession)
# ============================================================================

def list_sessions() -> str:
    """List all active sessions with friendly IDs."""
    return format_sessions_table()


async def get_session_output_async(session_id: str) -> str:
    """Get output from a session (async wrapper)."""
    return shell_get_output(session_id, clear=True)


async def kill_session(session_id: str) -> str:
    """Kill a session."""
    return terminate_session(session_id)


# ============================================================================
# Security: Unicode Homograph Detection
# ============================================================================

def detect_unicode_homographs(text: str) -> tuple[bool, str]:
    """
    Detect and normalize Unicode homograph characters used to bypass security.
    Returns (has_homographs, normalized_text)
    """
    homograph_map = {
        # Cyrillic to Latin
        '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
        '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
        '\u0410': 'A', '\u0415': 'E', '\u041e': 'O', '\u0420': 'P',
        '\u0421': 'C', '\u0425': 'X',
        # Greek to Latin
        '\u03b1': 'a', '\u03bf': 'o', '\u03c1': 'p', '\u03c5': 'u',
        '\u03c7': 'x', '\u0391': 'A', '\u039f': 'O', '\u03a1': 'P',
    }

    has_homographs = any(char in text for char in homograph_map)
    normalized = text
    for homograph, replacement in homograph_map.items():
        normalized = normalized.replace(homograph, replacement)
    normalized = unicodedata.normalize('NFKD', normalized)

    return has_homographs, normalized


# ============================================================================
# Security: Command Safety Validation
# ============================================================================

BLOCKED_COMMANDS = frozenset({
    "rm -rf /", "rm -rf /*", "dd if=/dev/zero", "mkfs", "fdisk",
    ":(){ :|:& };:", "chmod -R 777 /", "> /dev/sda", "mv / /dev/null",
    "wget -O- | sh", "curl | sh", "shutdown", "reboot", "init 0",
})

DANGEROUS_PATTERNS = [
    r"rm\s+(-[rf]+\s+)*[/~]",
    r":\(\)\s*\{\s*:\|:&\s*\}",
    r">\s*/dev/sd[a-z]",
    r"dd\s+.*of=/dev/",
    r"mkfs\.",
    r"chmod\s+(-[rR]+\s+)*777\s+/",
    r"curl.*\|\s*(ba)?sh",
    r"wget.*\|\s*(ba)?sh",
    r"nc\s+.*-[el].*\|\s*(ba)?sh",
    r"bash\s+-i\s+>&\s*/dev/tcp/",
]


def is_command_safe(command: str) -> tuple[bool, str | None]:
    """Check if command is safe to execute."""
    command_lower = command.lower().strip()
    normalized = re.sub(r'\s+', ' ', command_lower)

    for blocked in BLOCKED_COMMANDS:
        if blocked in normalized:
            return False, f"Blocked: {blocked}"

    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, normalized):
            return False, f"Dangerous pattern: {pattern}"

    return True, None


# ============================================================================
# Timeout Calculation
# ============================================================================

def calculate_timeout(command: str, default: int = 120) -> int:
    """Calculate adaptive timeout based on command type."""
    cmd_lower = command.lower()

    # Very long (30 min) - full port scans, deep crawls
    if re.search(r'nmap.*-p-|masscan.*--rate\s+[0-9]{4,}|sqlmap.*--crawl', cmd_lower):
        return 1800

    # Long (10 min) - security tools
    if re.search(r'^(nmap|masscan|sqlmap|nikto|gobuster|ffuf|hydra|john|hashcat|nuclei|wfuzz)', cmd_lower):
        return 600

    # Medium (2 min) - network tools
    if re.search(r'^(curl|wget|dig|nc|ssh|ping|whois|git)', cmd_lower):
        return 120

    # Quick (30s) - basic commands
    if re.search(r'^(echo|cat|head|tail|grep|ls|pwd|whoami|id)', cmd_lower):
        return 30

    return default


# ============================================================================
# Environment Detection
# ============================================================================

def detect_environment() -> Dict[str, Any]:
    """Detect the execution environment."""
    env = {
        "type": "local",
        "container": os.getenv("INFERNO_CONTAINER"),
        "ssh_host": os.getenv("SSH_HOST"),
        "ssh_user": os.getenv("SSH_USER"),
        "workspace": os.getenv("INFERNO_WORKSPACE", os.getcwd()),
    }

    if env["container"]:
        env["type"] = "container"
    elif env["ssh_host"] and env["ssh_user"]:
        env["type"] = "ssh"

    return env


def get_environment_info() -> str:
    """Get human-readable environment info."""
    env = detect_environment()
    lines = ["Current Environment:"]

    if env["type"] == "container":
        lines.append(f"  Container: {env['container'][:12]}")
    elif env["type"] == "ssh":
        lines.append(f"  SSH: {env['ssh_user']}@{env['ssh_host']}")
    else:
        lines.append("  Local execution")

    lines.append(f"  Workspace: {env['workspace']}")
    return "\n".join(lines)


# ============================================================================
# Main Execute Command Tool
# ============================================================================

@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="execute_command",
    description="""Execute any command on the target system.

This is the PRIMARY tool for running commands. Use it for:
- Security tools: nmap, sqlmap, gobuster, nikto, hydra, nuclei, etc.
- System commands: ls, cat, grep, find, whoami, id, etc.
- Network tools: curl, wget, nc, ssh, ping, dig, etc.
- Scripts: python, bash, perl, ruby, etc.
- Everything else - just run the command you need.

The system auto-detects the environment (local, container, SSH) and
handles timeouts adaptively based on command type.

Special commands for session management:
- "sessions" - list active sessions with friendly IDs (S1, S2, S3...)
- "output S1" - get output from session S1 (or use full ID)
- "kill S1" - terminate session S1
- "kill all" - terminate all sessions
- "env info" - show current execution environment

Sessions support friendly IDs (S1, S2, etc.) for easier reference.
You can also use #1, 1, or the full session ID.
""",
)
async def execute_command(
    command: str,
    timeout: Optional[int] = None,
    interactive: bool = False,
    session_id: Optional[str] = None,
    working_dir: Optional[str] = None,
) -> ToolResult:
    """
    Execute any command on the target system.

    Args:
        command: The complete command to execute (e.g., "nmap -sV target.com",
                 "sqlmap -u 'http://target/page?id=1' --batch", "ls -la")
        timeout: Command timeout in seconds. Auto-calculated if not specified.
                 Max: 3600 (1 hour).
        interactive: Set True for commands needing persistent sessions
                    (ssh, nc, python REPL, etc.)
        session_id: Send command to existing session instead of starting new one.
        working_dir: Working directory for command execution.

    Returns:
        Command output or session info for interactive commands.

    Examples:
        execute_command("nmap -sV -sC 192.168.1.1")
        execute_command("sqlmap -u 'http://target/vuln?id=1' --batch --dbs")
        execute_command("gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt")
        execute_command("curl -X POST http://target/api -d 'user=admin'")
        execute_command("ssh user@host", interactive=True)  # Creates session S1
        execute_command("whoami", session_id="S1")  # Send to session S1
        execute_command("output S1")  # Get output from session S1
        execute_command("sessions")  # List all sessions
        execute_command("kill S1")  # Terminate session S1
    """
    # Handle special session management commands
    cmd_lower = command.strip().lower()

    if cmd_lower in ("sessions", "session list", "list sessions"):
        return ToolResult(success=True, output=list_sessions())

    if cmd_lower.startswith("output "):
        sid = command.split(None, 1)[1]
        output = await get_session_output_async(sid)
        return ToolResult(success=True, output=output)

    if cmd_lower.startswith("kill "):
        sid = command.split(None, 1)[1]
        result = await kill_session(sid)
        return ToolResult(success=True, output=result)

    if cmd_lower == "kill all" or cmd_lower == "terminate all":
        result = terminate_all_sessions()
        return ToolResult(success=True, output=result)

    if cmd_lower in ("env info", "environment info"):
        return ToolResult(success=True, output=get_environment_info())

    if not command.strip():
        return ToolResult(success=False, output="", error="No command provided")

    # Security: Check for Unicode homograph bypass
    guardrails_enabled = os.getenv("INFERNO_GUARDRAILS", "true").lower() != "false"
    if guardrails_enabled:
        has_homographs, normalized = detect_unicode_homographs(command)
        if has_homographs:
            dangerous = ['curl', 'wget', 'nc', 'bash', 'sh ', 'exec', 'eval']
            if any(d in normalized.lower() for d in dangerous):
                if '$(' in normalized or '`' in normalized:
                    return ToolResult(
                        success=False, output="",
                        error="Blocked: Unicode homograph bypass attempt detected"
                    )

    # Security: Check command safety
    is_safe, reason = is_command_safe(command)
    if not is_safe:
        logger.warning("blocked_command", command=command[:100], reason=reason)
        return ToolResult(success=False, output="", error=f"Command blocked: {reason}")

    # Calculate timeout
    if timeout is None:
        timeout = calculate_timeout(command)
    else:
        timeout = min(timeout, 3600)

    # Set working directory
    cwd: Path | str | None = None
    if working_dir:
        cwd = Path(working_dir)
        if not cwd.exists():
            return ToolResult(
                success=False, output="",
                error=f"Working directory does not exist: {working_dir}"
            )
    elif os.getenv("INFERNO_ARTIFACTS_DIR"):
        cwd = os.environ["INFERNO_ARTIFACTS_DIR"]

    # Handle sending to existing session
    if session_id:
        resolved_sid = resolve_session_id(session_id)
        if resolved_sid:
            session = get_session(resolved_sid)
            if session and session.is_running:
                result = send_to_session(resolved_sid, command)
                await asyncio.sleep(0.5)  # Wait for response
                output = shell_get_output(resolved_sid, clear=True)
                friendly = session.friendly_id or resolved_sid[:8]
                return ToolResult(
                    success=True,
                    output=output or result,
                    metadata={"session_id": resolved_sid, "friendly_id": friendly}
                )
        return ToolResult(success=False, output="", error=f"Session not found: {session_id}")

    # Handle interactive commands with ShellSession (PTY-based)
    if interactive:
        try:
            # Create a new PTY-based shell session
            new_sid = create_shell_session(
                command=command,
                workspace_dir=str(cwd) if cwd else None,
            )

            if new_sid.startswith("Failed:"):
                return ToolResult(success=False, output="", error=new_sid)

            # Get the session to retrieve friendly ID
            session = get_session(new_sid)
            friendly = session.friendly_id if session else new_sid[:8]

            return ToolResult(
                success=True,
                output=f"Interactive session started: {friendly} ({new_sid[:8]})\n"
                       f"Use 'output {friendly}' to get output\n"
                       f"Use session_id='{friendly}' to send commands\n"
                       f"Use 'kill {friendly}' to terminate",
                metadata={"session_id": new_sid, "friendly_id": friendly}
            )
        except Exception as e:
            logger.error("session_start_failed", error=str(e))
            return ToolResult(success=False, output="", error=f"Failed to start session: {e}")

    # Standard command execution
    logger.info("executing_command", command=command[:200], timeout=timeout)

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            # Graceful termination
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

            return ToolResult(
                success=False, output="",
                error=f"Command timed out after {timeout}s",
                metadata={"timeout": timeout}
            )

        # Decode output
        stdout_str = stdout.decode("utf-8", errors="replace") if stdout else ""
        stderr_str = stderr.decode("utf-8", errors="replace") if stderr else ""

        # Combine output
        if stdout_str and stderr_str:
            output = f"{stdout_str}\n\nSTDERR:\n{stderr_str}"
        else:
            output = stdout_str or stderr_str

        # Truncate large output
        max_size = 100000
        if len(output) > max_size:
            output = output[:max_size] + f"\n\n[Output truncated at {max_size} chars]"

        success = process.returncode == 0

        logger.info(
            "command_complete",
            return_code=process.returncode,
            output_length=len(output),
        )

        return ToolResult(
            success=success,
            output=output,
            error=None if success else f"Exit code: {process.returncode}",
            metadata={"return_code": process.returncode, "command": command}
        )

    except Exception as e:
        logger.error("command_error", error=str(e), exc_info=True)
        return ToolResult(success=False, output="", error=f"Execution failed: {e}")


# ============================================================================
# Minimal Tools for Container-Based Execution (3-Tool Architecture)
# ============================================================================
# These tools are designed for the minimal prompt system with Docker execution.
# They provide a cleaner API and integrate with the Kali container.

# Global Docker manager instance (lazy loaded)
_docker_manager = None


def _get_docker_manager():
    """Get or create the Docker manager instance."""
    global _docker_manager
    if _docker_manager is None:
        from inferno.setup.docker_manager import DockerManager
        _docker_manager = DockerManager()
    return _docker_manager


@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="generic_linux_command",
    description="""Execute any Linux command in the Kali container.

Use for ALL command-line tools:
- Network: nmap, masscan, ping, dig, whois, nc, curl, wget
- Web: gobuster, ffuf, nikto, wpscan, sqlmap, nuclei
- Recon: subfinder, amass, sublist3r, assetfinder
- Exploit: msfconsole, searchsploit, hydra, john, hashcat
- Utils: grep, find, cat, head, tail, awk, sed, jq

Wordlists are available at /wordlists/
Workspace for saving files: /workspace/
""",
)
async def generic_linux_command(
    command: str,
    timeout: int = 300,
    workdir: str = "/workspace",
) -> ToolResult:
    """
    Execute any Linux command in the Kali container.

    Args:
        command: The command to execute (e.g., "nmap -sV target.com")
        timeout: Timeout in seconds (default: 300, max: 3600)
        workdir: Working directory (default: /workspace)

    Returns:
        ToolResult with stdout, stderr, and return code.

    Examples:
        generic_linux_command("nmap -sV -sC 10.10.10.1")
        generic_linux_command("gobuster dir -u http://target -w /wordlists/common-dirs.txt")
        generic_linux_command("sqlmap -u 'http://target/page?id=1' --batch --dbs")
        generic_linux_command("curl -s http://target/api/users | jq .")
    """
    if not command.strip():
        return ToolResult(success=False, output="", error="No command provided")

    # Security checks (reuse existing)
    guardrails_enabled = os.getenv("INFERNO_GUARDRAILS", "true").lower() != "false"
    if guardrails_enabled:
        has_homographs, normalized = detect_unicode_homographs(command)
        if has_homographs:
            dangerous = ['curl', 'wget', 'nc', 'bash', 'sh ', 'exec', 'eval']
            if any(d in normalized.lower() for d in dangerous):
                if '$(' in normalized or '`' in normalized:
                    return ToolResult(
                        success=False, output="",
                        error="Blocked: Unicode homograph bypass attempt detected"
                    )

    is_safe, reason = is_command_safe(command)
    if not is_safe:
        return ToolResult(success=False, output="", error=f"Command blocked: {reason}")

    # Cap timeout
    timeout = min(timeout, 3600)

    # Execute in Docker container
    docker = _get_docker_manager()
    result = await docker.execute_in_kali(command, timeout=timeout, workdir=workdir)

    output = result["stdout"]
    if result["stderr"]:
        if output:
            output += f"\n\nSTDERR:\n{result['stderr']}"
        else:
            output = result["stderr"]

    # Truncate large output
    max_size = 100000
    if len(output) > max_size:
        output = output[:max_size] + f"\n\n[Output truncated at {max_size} chars]"

    return ToolResult(
        success=result["success"],
        output=output,
        error=None if result["success"] else f"Exit code: {result['return_code']}",
        metadata={"return_code": result["return_code"], "command": command}
    )


@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="execute_code",
    description="""Execute Python or Bash code/scripts in the Kali container.

Use for:
- Custom exploits and payloads
- Data processing and parsing
- Complex logic that can't be done with simple commands
- Multi-step automation

Supports: python, python3, bash, sh
""",
)
async def execute_code(
    code: str,
    language: str = "python",
    timeout: int = 300,
    save_as: Optional[str] = None,
) -> ToolResult:
    """
    Execute code in the Kali container.

    Args:
        code: The code to execute (multi-line supported)
        language: Programming language (python, python3, bash, sh)
        timeout: Timeout in seconds (default: 300, max: 3600)
        save_as: Optional filename to save the script in /workspace/

    Returns:
        ToolResult with execution output.

    Examples:
        execute_code('''
import requests
r = requests.get("http://target/api")
print(r.json())
''', language="python")

        execute_code('''
for i in $(seq 1 100); do
    curl -s "http://target/user/$i"
done
''', language="bash")
    """
    if not code.strip():
        return ToolResult(success=False, output="", error="No code provided")

    # Validate language
    supported = {"python", "python3", "bash", "sh"}
    if language not in supported:
        return ToolResult(
            success=False, output="",
            error=f"Unsupported language: {language}. Use: {supported}"
        )

    timeout = min(timeout, 3600)
    docker = _get_docker_manager()

    # If save_as is provided, save the script first
    if save_as:
        save_path = f"/workspace/{save_as}"
        # Escape single quotes in code for shell
        escaped_code = code.replace("'", "'\\''")
        save_cmd = f"cat > {save_path} << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"
        await docker.execute_in_kali(save_cmd, timeout=10)

        # Make executable if bash/sh
        if language in ("bash", "sh"):
            await docker.execute_in_kali(f"chmod +x {save_path}", timeout=5)

    # Build execution command
    if language in ("python", "python3"):
        # Use heredoc for Python
        cmd = f"python3 << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"
    else:
        # Bash/sh
        cmd = f"bash << 'INFERNO_CODE_EOF'\n{code}\nINFERNO_CODE_EOF"

    result = await docker.execute_in_kali(cmd, timeout=timeout, workdir="/workspace")

    output = result["stdout"]
    if result["stderr"]:
        if output:
            output += f"\n\nSTDERR:\n{result['stderr']}"
        else:
            output = result["stderr"]

    metadata = {"return_code": result["return_code"], "language": language}
    if save_as:
        metadata["saved_to"] = f"/workspace/{save_as}"

    return ToolResult(
        success=result["success"],
        output=output,
        error=None if result["success"] else f"Exit code: {result['return_code']}",
        metadata=metadata
    )


@function_tool(
    category=ToolCategory.CORE,
    defer_loading=False,
    name="web_request",
    description="""Make HTTP requests with full control over method, headers, body, and cookies.

Use for:
- API interactions and testing
- Form submissions (login, file upload)
- Custom header manipulation
- Cookie handling
- Following/not following redirects

For simple requests, consider using curl via generic_linux_command instead.
""",
)
async def web_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    cookies: Optional[Dict[str, str]] = None,
    follow_redirects: bool = True,
    timeout: int = 30,
    verify_ssl: bool = True,
) -> ToolResult:
    """
    Make an HTTP request with full control.

    Args:
        url: The URL to request
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
        headers: Optional headers dict
        body: Optional request body (string)
        cookies: Optional cookies dict
        follow_redirects: Follow HTTP redirects (default: True)
        timeout: Request timeout in seconds (default: 30)
        verify_ssl: Verify SSL certificates (default: True)

    Returns:
        ToolResult with status code, headers, and body.

    Examples:
        web_request("http://target/api/users")
        web_request("http://target/login", method="POST",
                   body="username=admin&password=test",
                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        web_request("http://target/api", headers={"Authorization": "Bearer token123"})
    """
    import httpx

    if not url.strip():
        return ToolResult(success=False, output="", error="No URL provided")

    method = method.upper()
    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
    if method not in valid_methods:
        return ToolResult(
            success=False, output="",
            error=f"Invalid method: {method}. Use: {valid_methods}"
        )

    try:
        async with httpx.AsyncClient(
            follow_redirects=follow_redirects,
            verify=verify_ssl,
            timeout=timeout,
        ) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
                cookies=cookies,
            )

        # Format response
        output_lines = [
            f"Status: {response.status_code} {response.reason_phrase}",
            "",
            "Headers:",
        ]
        for name, value in response.headers.items():
            output_lines.append(f"  {name}: {value}")

        output_lines.extend(["", "Body:"])

        # Handle response body
        body_text = response.text
        max_body = 50000
        if len(body_text) > max_body:
            body_text = body_text[:max_body] + f"\n\n[Body truncated at {max_body} chars]"
        output_lines.append(body_text)

        return ToolResult(
            success=True,
            output="\n".join(output_lines),
            metadata={
                "status_code": response.status_code,
                "url": str(response.url),
                "method": method,
                "content_length": len(response.content),
            }
        )

    except httpx.TimeoutException:
        return ToolResult(success=False, output="", error=f"Request timed out after {timeout}s")
    except httpx.RequestError as e:
        return ToolResult(success=False, output="", error=f"Request failed: {e}")
    except Exception as e:
        return ToolResult(success=False, output="", error=f"Error: {e}")


# Export all tools
__all__ = [
    "execute_command",
    "generic_linux_command",
    "execute_code",
    "web_request",
]
