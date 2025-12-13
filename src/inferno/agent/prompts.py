"""
System prompt builder for Inferno.

This module provides the system prompt construction for the
pentesting agent with dynamic context injection.

It integrates with the new engine-based prompt system that
dynamically assembles prompts from modular markdown templates.

Architecture:
- templates/: Core identity and report templates
- behaviors/: Composable behavior modules (exploitation, CVE-driven, etc.)
- phases/: Phase-specific guidance (recon, enumeration, exploitation)
- contexts/: Target-type specific guidance (web, API, network, CTF)
- tools/: Tool usage protocols
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from inferno.prompts import (
    AgentPersona,
    detect_context_type,
)
from inferno.prompts import (
    build_system_prompt as engine_build_system_prompt,
)
from inferno.prompts import (
    get_checkpoint_prompt as engine_get_checkpoint_prompt,
)

if TYPE_CHECKING:
    from inferno.config.environment import OperationContext


@dataclass
class TargetInfo:
    """Target information for the assessment."""

    target: str
    scope: str = "as provided"
    target_type: str = "unknown"
    additional_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectiveInfo:
    """Objective information for the assessment."""

    objective: str
    success_criteria: list[str] = field(default_factory=list)


class SystemPromptBuilder:
    """
    Builds dynamic system prompts for the Inferno agent.

    This builder uses the new engine-based prompt system that
    dynamically assembles prompts from modular markdown templates.

    The prompt is constructed from:
    - Core identity and ethical guidelines (templates/system.md)
    - Behavioral modules (behaviors/*.md)
    - Phase-specific guidance (phases/*.md)
    - Context-specific guidance (contexts/*.md)
    - Tool usage protocols (tools/tool_guide.md)
    - Dynamic operation context (IDs, directories, budget)
    """

    def __init__(self, persona: AgentPersona = AgentPersona.THOROUGH) -> None:
        """
        Initialize the prompt builder.

        Args:
            persona: The agent persona to use.
        """
        self._persona = persona
        self._operation_context: OperationContext | None = None
        self._target_info: TargetInfo | None = None
        self._objective: ObjectiveInfo | None = None
        self._available_tools: list[str] = []
        self._custom_rules: list[str] = []
        self._budget_info: dict[str, Any] = {}

    @property
    def persona(self) -> AgentPersona:
        """Get the current persona."""
        return self._persona

    def set_persona(self, persona: AgentPersona) -> SystemPromptBuilder:
        """
        Set the agent persona.

        Args:
            persona: The persona to use.

        Returns:
            Self for chaining.
        """
        self._persona = persona
        return self

    def set_operation_context(self, context: OperationContext) -> SystemPromptBuilder:
        """Set the operation context."""
        self._operation_context = context
        return self

    def set_target(
        self,
        target: str,
        scope: str = "as provided",
        target_type: str = "unknown",
        **additional: Any,
    ) -> SystemPromptBuilder:
        """Set target information."""
        self._target_info = TargetInfo(
            target=target,
            scope=scope,
            target_type=target_type,
            additional_info=additional,
        )
        return self

    def set_objective(
        self,
        objective: str,
        success_criteria: list[str] | None = None,
    ) -> SystemPromptBuilder:
        """Set the assessment objective."""
        self._objective = ObjectiveInfo(
            objective=objective,
            success_criteria=success_criteria or [],
        )
        return self

    def set_available_tools(self, tools: list[str]) -> SystemPromptBuilder:
        """Set the list of available security tools."""
        self._available_tools = tools
        return self

    def add_rule(self, rule: str) -> SystemPromptBuilder:
        """Add a custom rule or constraint."""
        self._custom_rules.append(rule)
        return self

    def set_rules(self, rules: list[str]) -> SystemPromptBuilder:
        """Set all custom rules."""
        self._custom_rules = rules
        return self

    def update_budget(
        self,
        current_turns: int = 0,
        max_turns: int = 100,
        current_tokens: int = 0,
        max_tokens: int = 1_000_000,
    ) -> SystemPromptBuilder:
        """Update budget information."""
        budget_remaining = 100.0
        if max_tokens > 0:
            token_usage = (current_tokens / max_tokens) * 100
            budget_remaining = min(budget_remaining, 100 - token_usage)
        if max_turns > 0:
            turn_usage = (current_turns / max_turns) * 100
            budget_remaining = min(budget_remaining, 100 - turn_usage)

        self._budget_info = {
            "max_turns": max_turns,
            "max_tokens": f"{max_tokens:,}",
            "current_turns": current_turns,
            "current_tokens": f"{current_tokens:,}",
            "budget_percent": round(budget_remaining, 1),
        }
        return self

    def build(self) -> str:
        """
        Build the complete system prompt using the new engine.

        Returns:
            The constructed system prompt string.
        """
        # Determine target and objective
        target = self._target_info.target if self._target_info else "Not specified"
        objective = self._objective.objective if self._objective else "General security assessment"
        scope = self._target_info.scope if self._target_info else "as provided"

        # Format rules
        rules = "\n".join(f"- {r}" for r in self._custom_rules) if self._custom_rules else "Standard penetration testing rules apply"

        # Get operation info
        operation_id = self._operation_context.operation_id if self._operation_context else ""
        current_step = self._budget_info.get("current_turns", 0)
        max_steps = self._budget_info.get("max_turns", 100)

        # Detect context type from target
        context_type = detect_context_type(target, objective)

        # Map persona to context type override
        if self._persona == AgentPersona.CTF:
            context_type = "ctf"

        # Build base prompt from engine
        base_prompt = engine_build_system_prompt(
            target=target,
            objective=objective,
            scope=scope,
            rules=rules,
            operation_id=operation_id,
            current_step=current_step,
            max_steps=max_steps,
            context_type=context_type,
        )

        # Add dynamic sections
        sections = [base_prompt]

        # AUTO-INJECT: Environment context (OS, IPs, tools, wordlists)
        # This is a CAI-inspired feature for better situational awareness
        env_section = self._build_environment_section()
        if env_section:
            sections.append(env_section)

        # Operation context (artifacts, previous runs)
        if self._operation_context:
            sections.append(self._build_operation_section())

        # Budget information
        if self._budget_info:
            sections.append(self._build_budget_section())

        # Available tools (if explicitly provided)
        if self._available_tools:
            sections.append(self._build_tools_section())

        # Success criteria
        if self._objective and self._objective.success_criteria:
            sections.append(self._build_criteria_section())

        # Swarm worker instructions - encourage parallel work
        sections.append(self._build_swarm_section())

        return "\n\n".join(sections)

    def _build_operation_section(self) -> str:
        """Build operation context section."""
        ctx = self._operation_context

        section = f"""## Current Operation

- **Operation ID**: {ctx.operation_id}
- **Started**: {ctx.start_time.isoformat()}
- **Artifacts Directory**: {ctx.artifacts_dir}

**IMPORTANT**: Save ALL files (scripts, cookies, outputs) to the artifacts directory `{ctx.artifacts_dir}` instead of /tmp. This ensures persistence and cleanup."""

        # Check for previous artifacts from the same target
        previous_artifacts = self._find_previous_artifacts(ctx.artifacts_dir)
        if previous_artifacts:
            section += f"""

### Previous Operation Artifacts
Previous operations on this target have artifacts you can reuse:
{previous_artifacts}

**IMPORTANT**: Check and reuse these artifacts instead of re-running tools. Use `cat` or `Read` to view files."""

        return section

    def _find_previous_artifacts(self, current_artifacts_dir: str) -> str:
        """Find artifacts from previous operations on the same target."""
        from pathlib import Path

        current_path = Path(current_artifacts_dir)
        target_dir = current_path.parent  # e.g., outputs/http_10.10.11.97/

        if not target_dir.exists():
            return ""

        artifacts_info = []
        current_op_id = current_path.name

        # Find previous operation directories
        for op_dir in sorted(target_dir.iterdir()):
            if not op_dir.is_dir() or op_dir.name == current_op_id:
                continue

            # Look for interesting files
            interesting_files = []
            for pattern in ["*.txt", "*.php", "*.py", "*.json", "*.xml", "*.yaml", "*.yml"]:
                interesting_files.extend(op_dir.rglob(pattern))

            # Check for specific valuable directories
            git_repo = op_dir / "outputs" / "git_repo"
            source_dir = op_dir / "outputs" / "source"

            if git_repo.exists():
                files = list(git_repo.glob("*.php"))
                if files:
                    artifacts_info.append(f"- **{op_dir.name}**: Git dump at `{git_repo}` ({len(files)} PHP files)")
            elif source_dir.exists():
                files = list(source_dir.rglob("*.php"))
                if files:
                    artifacts_info.append(f"- **{op_dir.name}**: Source code at `{source_dir}` ({len(files)} files)")
            elif interesting_files:
                artifacts_info.append(f"- **{op_dir.name}**: {len(interesting_files)} files at `{op_dir}`")

        return "\n".join(artifacts_info[:5]) if artifacts_info else ""  # Limit to 5 most recent

    def _build_budget_section(self) -> str:
        """Build budget information section."""
        info = self._budget_info
        return f"""## Resource Budget

- **Max Turns**: {info['max_turns']}
- **Max Tokens**: {info['max_tokens']}
- **Current Usage**: {info['current_turns']} turns, {info['current_tokens']} tokens
- **Budget Remaining**: {info['budget_percent']}%

Create checkpoints at 20%, 40%, 60%, and 80% budget usage."""

    def _build_tools_section(self) -> str:
        """Build available tools section."""
        tool_list = "\n".join(f"- {tool}" for tool in self._available_tools)
        return f"""## Available Security Tools

The following tools are installed and available:
{tool_list}

### Core Tools (Always Available)
- **shell**: Execute shell commands
- **http_request**: Make HTTP/HTTPS requests with full control
- **memory**: Store and retrieve findings
- **editor**: Create and edit files in artifacts directory
- **stop**: Signal assessment completion

### Security Scanner Wrappers (Use Tool Search)
- **nmap_scan**: Network scanning with structured output
- **gobuster**: Directory/subdomain enumeration with wordlist auto-resolution
- **sqlmap**: SQL injection detection and exploitation
- **nikto**: Web server vulnerability scanning
- **nuclei**: Template-based vulnerability scanning
- **hydra**: Network login brute-forcing (SSH, FTP, HTTP, SMB, MySQL, RDP)
- **git_dumper**: Dump exposed .git repositories

### Advanced Detection Tools (Use Tool Search)
- **response_analyzer**: Analyze HTTP responses for vulnerabilities
- **idor_scanner**: Detect insecure direct object references
- **parameter_miner**: Discover hidden parameters
- **endpoint_discovery**: Find hidden APIs and endpoints
- **ssrf_detector**: Detect SSRF vulnerabilities with OOB callbacks
- **graphql_tester**: Test GraphQL endpoints for security issues
- **cache_poison**: Detect web cache poisoning vulnerabilities
- **race_condition**: Test for race conditions with parallel requests

### Validation & Reporting Tools
- **validation_engine**: Validate and verify findings
- **poc_generator**: Generate proof-of-concept code
- **false_positive_filter**: Filter out false positives
- **severity_calibrator**: Calibrate vulnerability severity
- **report_writer**: Generate assessment reports

### Proxy & WAF Tools
- **proxy**: HTTP/HTTPS intercepting proxy (mitmproxy) - start/stop/capture/replay
- **waf_detect**: Detect and fingerprint WAF, suggest bypass techniques

### Wordlist Management
Wordlists auto-resolve from SecLists. Use presets:
- `common`, `big`, `raft-medium-directories` for web content
- `subdomains-top1million` for subdomain enumeration
- `passwords-common`, `rockyou-top10000` for credential attacks

Use Tool Search to discover additional specialized tools as needed."""

    def _build_criteria_section(self) -> str:
        """Build success criteria section."""
        criteria = "\n".join(f"- {c}" for c in self._objective.success_criteria)
        return f"""## Success Criteria

{criteria}"""

    def _build_swarm_section(self) -> str:
        """Build swarm worker instructions section."""
        return """## SWARM WORKERS - Parallelize Your Work!

You have access to the `swarm` tool to spawn specialized workers. **USE IT FREQUENTLY** for:

**When to spawn workers:**
- After initial recon → spawn `scanner` for parallel vulnerability scanning
- When you find potential vulnerabilities → spawn `analyzer` for deep investigation
- When stuck or blocked → spawn `exploiter` with specific bypass instructions
- To confirm findings → spawn `validator` for independent verification
- When WAF blocks you → spawn `waf_bypass` specialist

**Available worker types:**
| Type | Use For |
|------|---------|
| `reconnaissance` | Fast enumeration, tech stack discovery |
| `scanner` | Automated vulnerability scanning |
| `exploiter` | Deep exploitation of specific vulns |
| `analyzer` | Detailed analysis (SSTI, SQLi, XSS, etc.) |
| `validator` | Independent finding confirmation |
| `waf_bypass` | WAF/filter evasion techniques |
| `business_logic` | Logic flaw hunting, race conditions |
| `token_forgery` | JWT/session token attacks |

**Example usage:**
```
# After finding potential SSTI
swarm(agent_type="analyzer", task="Analyze SSTI in /render endpoint. Test Jinja2, Twig, Freemarker. If blocked, try encoding.")

# When SQLi found but need exploitation
swarm(agent_type="exploiter", task="Exploit SQL injection in /api/search?q=. Extract database contents.")

# For parallel scanning
swarm(agent_type="scanner", task="Scan /api/* endpoints for authentication bypass and IDOR.")
```

**IMPORTANT:** Don't try to do everything sequentially! Spawn workers for parallel efficiency."""

    def _build_environment_section(self) -> str:
        """
        Build environment context section (CAI-inspired).

        Auto-detects:
        - Operating system and hostname
        - IP addresses (including VPN tunnel)
        - Available security tools
        - Wordlist locations

        This gives the agent situational awareness without manual configuration.
        """
        import os
        import platform
        import shutil
        import subprocess

        sections = []

        # OS and hostname
        os_info = f"{platform.system()} {platform.release()}"
        hostname = platform.node()
        sections.append(f"- **OS**: {os_info}")
        sections.append(f"- **Hostname**: {hostname}")

        # IP addresses
        try:
            # Get all IP addresses
            result = subprocess.run(
                ["hostname", "-I"] if platform.system() == "Linux" else ["ipconfig", "getifaddr", "en0"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                ips = result.stdout.strip().split()[:3]  # Limit to 3 IPs
                sections.append(f"- **Local IPs**: {', '.join(ips)}")
        except Exception:
            pass

        # VPN tunnel (tun0) - critical for HTB/CTF
        try:
            result = subprocess.run(
                ["ip", "addr", "show", "tun0"],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "inet " in line:
                        vpn_ip = line.strip().split()[1].split("/")[0]
                        sections.append(f"- **VPN IP (tun0)**: {vpn_ip} ← Use this for reverse shells")
                        break
        except Exception:
            pass

        # Available security tools
        tools_available = []
        tools_to_check = [
            ("nmap", "Network scanning"),
            ("gobuster", "Directory enumeration"),
            ("ffuf", "Fast fuzzing"),
            ("sqlmap", "SQL injection"),
            ("nuclei", "Vulnerability scanning"),
            ("nikto", "Web server scanning"),
            ("hydra", "Password cracking"),
            ("hashcat", "Hash cracking"),
            ("john", "John the Ripper"),
            ("msfconsole", "Metasploit"),
            ("burpsuite", "Burp Suite"),
            ("wpscan", "WordPress scanning"),
            ("dirsearch", "Directory search"),
            ("feroxbuster", "Recursive content discovery"),
            ("curl", "HTTP client"),
            ("wget", "File download"),
            ("nc", "Netcat"),
            ("python3", "Python scripting"),
        ]

        for tool, desc in tools_to_check:
            if shutil.which(tool):
                tools_available.append(f"{tool}")

        if tools_available:
            # Group in chunks of 6 for readability
            tool_str = ", ".join(tools_available[:12])
            sections.append(f"- **Available Tools**: {tool_str}")

        # Wordlist locations
        wordlist_paths = [
            "/usr/share/wordlists",
            "/usr/share/seclists",
            "/opt/SecLists",
            os.path.expanduser("~/wordlists"),
            os.path.expanduser("~/SecLists"),
        ]

        found_wordlists = []
        for path in wordlist_paths:
            if os.path.isdir(path):
                found_wordlists.append(path)

        if found_wordlists:
            sections.append(f"- **Wordlists**: {', '.join(found_wordlists[:2])}")

        # Only return if we have meaningful content
        if len(sections) > 2:  # More than just OS and hostname
            return f"""## Environment Context (Auto-Detected)

{chr(10).join(sections)}

*This context is auto-injected to improve assessment accuracy.*"""

        return ""

    def build_for_checkpoint(self, checkpoint_percent: int) -> str:
        """
        Build a checkpoint reminder to inject into conversation.

        Uses the new engine-based checkpoint prompt system.

        Args:
            checkpoint_percent: The checkpoint percentage (20, 40, 60, 80, 90).

        Returns:
            Checkpoint reminder string.
        """
        # Get findings count if available from budget info
        findings_count = self._budget_info.get("findings_count", 0)

        # Determine current phase from percentage
        if checkpoint_percent <= 20:
            current_phase = "reconnaissance"
        elif checkpoint_percent <= 40:
            current_phase = "enumeration"
        elif checkpoint_percent <= 80:
            current_phase = "exploitation"
        else:
            current_phase = "post_exploit"

        return engine_get_checkpoint_prompt(
            percent_complete=checkpoint_percent,
            findings_count=findings_count,
            current_phase=current_phase,
        )


def build_default_prompt(
    target: str,
    objective: str,
    operation_context: OperationContext | None = None,
    available_tools: list[str] | None = None,
    persona: AgentPersona = AgentPersona.THOROUGH,
) -> str:
    """
    Build a default system prompt for a pentesting operation.

    Args:
        target: Target URL or IP.
        objective: Assessment objective.
        operation_context: Optional operation context.
        available_tools: Optional list of available tools.
        persona: Agent persona to use.

    Returns:
        Complete system prompt.
    """
    builder = SystemPromptBuilder(persona)

    builder.set_target(target)
    builder.set_objective(objective)

    if operation_context:
        builder.set_operation_context(operation_context)

    if available_tools:
        builder.set_available_tools(available_tools)

    return builder.build()


# Convenience function for CTF mode
def build_ctf_prompt(
    target: str,
    challenge_name: str = "CTF Challenge",
    operation_context: OperationContext | None = None,
) -> str:
    """
    Build a CTF-optimized system prompt.

    Args:
        target: Target URL or challenge endpoint.
        challenge_name: Name of the CTF challenge.
        operation_context: Optional operation context.

    Returns:
        CTF-optimized system prompt.
    """
    builder = SystemPromptBuilder(AgentPersona.CTF)

    builder.set_target(target, target_type="ctf")
    builder.set_objective(
        f"Capture the flag in: {challenge_name}",
        success_criteria=[
            "Find and capture the flag",
            "Document the solution approach",
        ],
    )

    if operation_context:
        builder.set_operation_context(operation_context)

    return builder.build()


# ==================== Minimal Prompt System ====================
# Generic, token-efficient prompt for container-based execution
# Uses only 3 tools: generic_linux_command, execute_code, web_request

MINIMAL_SYSTEM_PROMPT = """You are an autonomous penetration testing agent operating in a Kali Linux container.

## Objective
{objective}

## Target
{target}

## Environment
Kali Linux container with full network access and comprehensive toolkit:

**Network Scanning**: nmap, masscan
**Web Fuzzing**: gobuster, ffuf, dirb, feroxbuster
**Vulnerability Scanners**: nikto, sqlmap, nuclei, wpscan
**Password Attacks**: hydra, john, hashcat, medusa
**Exploitation**: searchsploit (exploitdb)
**Recon/OSINT**: subfinder, amass, dnsrecon, whatweb, wafw00f
**Utilities**: curl, wget, python3, netcat, jq, git

**Wordlists** (SecLists installed):
- Discovery: /usr/share/seclists/Discovery/Web-Content/
- Fuzzing: /usr/share/seclists/Fuzzing/
- Passwords: /usr/share/seclists/Passwords/
- Common: /usr/share/wordlists/

**Workspace**: /workspace/ (persistent storage)

## Tools
You have exactly 3 tools:

1. **generic_linux_command**: Execute ANY Linux command
   - All pentesting tools above are available
   - Returns: stdout, stderr, return_code

2. **execute_code**: Run Python/Bash scripts
   - Custom exploits, data processing, automation
   - Supports: python, bash

3. **web_request**: HTTP requests with full control
   - Method, headers, body, cookies, redirects
   - Returns: status, headers, body

## Strategy
1. Enumerate thoroughly (nmap, gobuster, ffuf)
2. Identify vulnerabilities (nuclei, nikto, sqlmap)
3. Exploit and validate findings
4. Document everything in /workspace/

## CORS Testing (MANDATORY)
When testing for CORS vulnerabilities:
1. Test with Origin headers: `curl -H "Origin: https://evil.com" -I <target>`
2. Check for `Access-Control-Allow-Origin: *` or reflection of Origin
3. Test null origin: `curl -H "Origin: null" -I <target>`
4. **ALWAYS create HTML PoC** for any CORS vulnerability found

CORS PoC template (save to /workspace/cors_poc.html):
```html
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Vulnerability PoC</h1>
<div id="result"></div>
<script>
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {{
    if (xhr.readyState == 4) {{
        document.getElementById("result").innerHTML =
            "<pre>Status: " + xhr.status + "\\n" + xhr.responseText + "</pre>";
    }}
}};
xhr.open("GET", "VULNERABLE_URL_HERE", true);
xhr.withCredentials = true;
xhr.send();
</script>
</body>
</html>
```

Be methodical. Think step-by-step. Get root."""


def build_minimal_prompt(target: str, objective: str) -> str:
    """
    Build a minimal, token-efficient system prompt (~500 tokens).

    This prompt is designed for container-based execution with only
    3 generic tools. No tool hints, no complex formatting.

    Args:
        target: Target URL or IP address.
        objective: What to accomplish.

    Returns:
        Minimal system prompt string.
    """
    return MINIMAL_SYSTEM_PROMPT.format(
        target=target,
        objective=objective,
    )


class MinimalPromptBuilder:
    """
    Minimal prompt builder for container-based execution.

    Unlike SystemPromptBuilder which uses the full engine-based
    prompt system, this builder creates lightweight prompts
    optimized for the 3-tool architecture.
    """

    def __init__(self) -> None:
        """Initialize the minimal prompt builder."""
        self._target: str = ""
        self._objective: str = "Perform security assessment"
        self._context: dict[str, Any] = {}

    def set_target(self, target: str) -> MinimalPromptBuilder:
        """Set the target."""
        self._target = target
        return self

    def set_objective(self, objective: str) -> MinimalPromptBuilder:
        """Set the objective."""
        self._objective = objective
        return self

    def add_context(self, key: str, value: Any) -> MinimalPromptBuilder:
        """Add optional context."""
        self._context[key] = value
        return self

    def build(self) -> str:
        """Build the minimal prompt."""
        prompt = build_minimal_prompt(self._target, self._objective)

        # Add optional context if provided
        if self._context:
            context_lines = ["\n## Additional Context"]
            for key, value in self._context.items():
                context_lines.append(f"- **{key}**: {value}")
            prompt += "\n".join(context_lines)

        return prompt
