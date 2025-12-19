"""
System prompt builder for Inferno.

This module provides the system prompt construction for the
pentesting agent using the dynamic prompt generation system.

Architecture (Dec 2025):
- Uses DynamicPromptGenerator for task-specific prompts
- NO static templates - everything generated based on context
- Integrates with MITRE ATT&CK for technique mapping
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from inferno.prompts import (
    AgentPersona,
    TaskContext,
    TaskType,
    TechStack,
    get_generator,
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


def detect_context_type(target: str, objective: str) -> str:
    """
    Detect the context type from target and objective.

    Args:
        target: Target URL or IP
        objective: Assessment objective

    Returns:
        Context type string (web, api, ctf, network, etc.)
    """
    target_lower = target.lower()
    objective_lower = objective.lower()

    # CTF detection
    if any(word in objective_lower for word in ["flag", "ctf", "capture", "hackthebox", "htb"]):
        return "ctf"

    # API detection
    if any(word in target_lower for word in ["/api/", "/v1/", "/v2/", "/graphql"]):
        return "api"
    if "api" in objective_lower:
        return "api"

    # Network detection
    if not target_lower.startswith(("http://", "https://")):
        if any(c.isdigit() for c in target):  # Likely an IP
            return "network"

    # Default to web
    return "web"


def detect_tech_stack(target: str) -> list[TechStack]:
    """
    Detect technology stack from target URL.

    This is a basic heuristic - the actual tech stack is
    discovered during reconnaissance.
    """
    target_lower = target.lower()
    techs = []

    # Framework hints from URL
    if "wordpress" in target_lower or "/wp-" in target_lower:
        techs.append(TechStack.WORDPRESS)
    if "drupal" in target_lower:
        techs.append(TechStack.DRUPAL)
    if "/api/" in target_lower or "/v1/" in target_lower:
        techs.append(TechStack.API)
    if "/graphql" in target_lower:
        techs.append(TechStack.GRAPHQL)

    # File extension hints
    if ".php" in target_lower:
        techs.append(TechStack.PHP)
    if ".aspx" in target_lower or ".asp" in target_lower:
        techs.append(TechStack.ASPNET)
    if ".jsp" in target_lower:
        techs.append(TechStack.JAVA)

    if not techs:
        techs.append(TechStack.GENERIC_WEB)

    return techs


class SystemPromptBuilder:
    """
    Builds dynamic system prompts for the Inferno agent.

    This builder uses the DynamicPromptGenerator that creates
    task-specific prompts based on context, tech stack, and
    MITRE ATT&CK technique mapping.
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
        self._generator = get_generator()

    @property
    def persona(self) -> AgentPersona:
        """Get the current persona."""
        return self._persona

    def set_persona(self, persona: AgentPersona) -> SystemPromptBuilder:
        """Set the agent persona."""
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
        Build the complete system prompt using DynamicPromptGenerator.

        Returns:
            The constructed system prompt string.
        """
        # Determine target and objective
        target = self._target_info.target if self._target_info else "Not specified"
        objective = self._objective.objective if self._objective else "General security assessment"
        scope = self._target_info.scope if self._target_info else "as provided"

        # Detect tech stack
        tech_stack = detect_tech_stack(target)

        # Build custom instructions from rules
        custom_instructions = ""
        if self._custom_rules:
            custom_instructions = "\n".join(f"- {r}" for r in self._custom_rules)

        # Create task context for initial reconnaissance
        task_context = TaskContext(
            task_type=TaskType.RECON,  # Start with recon
            target=target,
            scope=scope,
            objective=objective,
            tech_stack=tech_stack,
            custom_instructions=custom_instructions,
        )

        # Generate base prompt
        base_prompt = self._generator.generate(task_context)

        # Add dynamic sections
        sections = [base_prompt]

        # Environment context (auto-detected tools, IPs, wordlists)
        env_section = self._build_environment_section()
        if env_section:
            sections.append(env_section)

        # Operation context (artifacts, previous runs)
        if self._operation_context:
            sections.append(self._build_operation_section())

        # Budget information
        if self._budget_info:
            sections.append(self._build_budget_section())

        # Swarm worker instructions
        sections.append(self._build_swarm_section())

        return "\n\n".join(sections)

    def _build_operation_section(self) -> str:
        """Build operation context section."""
        ctx = self._operation_context

        section = f"""## Current Operation

- **Operation ID**: {ctx.operation_id}
- **Started**: {ctx.start_time.isoformat()}
- **Artifacts Directory**: {ctx.artifacts_dir}

**IMPORTANT**: Save ALL files to `{ctx.artifacts_dir}` for persistence."""

        return section

    def _build_budget_section(self) -> str:
        """Build budget information section."""
        info = self._budget_info
        return f"""## Resource Budget

- **Turns**: {info['current_turns']}/{info['max_turns']}
- **Budget Remaining**: {info['budget_percent']}%

Create checkpoints at 20%, 40%, 60%, and 80% budget usage."""

    def _build_swarm_section(self) -> str:
        """Build swarm worker instructions section."""
        return """## CRITICAL: SWARM + ALGORITHM-DRIVEN EXPLOITATION

**YOUR ROLE**: COORDINATOR. NEVER test manually. ALWAYS spawn workers.

### 🚨 SCORING PENALTY - EXPLOIT OR LOSE POINTS! 🚨

**VERIFIED-ONLY findings get 20% PENALTY!**
**EXPLOITED findings get FULL points!**

| Status | Score Formula | Example (DC=5, EC=8) |
|--------|---------------|---------------------|
| **EXPLOITED** | TC = DC + EC | 5 + 8 = **13.0** ✓ |
| VERIFIED | TC = DC + EC×0.8 | 5 + 6.4 = 11.4 (-1.6 pts!) |

**DO NOT just detect vulnerabilities - EXPLOIT them for full credit!**

### 🤖 USE ALGORITHMS FOR DECISIONS

Before EVERY action, call:
```
get_strategy(current_phase="scanning", endpoints_found=10, vulns_found=2, tech_stack="php,mysql")
```

After EVERY failure:
```
record_failure(endpoint="/login", attack_type="sqli", reason="waf_blocked")
```

After EVERY success:
```
record_success(endpoint="/search", attack_type="sqli", severity="high", exploited=true)
```

### 🔥 SPAWN SWARM WORKERS IN PARALLEL

| Type | When To Spawn |
|------|---------------|
| `reconnaissance` | New subdomain, new endpoint |
| `scanner` | EACH endpoint, parameter |
| `exploiter` | EACH confirmed vuln → GET FULL POINTS! |
| `validator` | EACH finding for verification |
| `waf_bypass` | Blocked payloads, 403s |

**Spawn 5-10 workers with background=true:**
```
swarm(agent_type="exploiter", task="Exploit SQLi in /search to dump DB", background=true)
swarm(agent_type="exploiter", task="Exploit XSS in /comment for session steal", background=true)
swarm(agent_type="scanner", task="Deep scan /api/users for IDOR, auth bypass", background=true)
```

### 📋 MANDATORY WORKFLOW

1. **Discover** → Spawn `reconnaissance` workers
2. **Scan** → Spawn `scanner` for EACH endpoint
3. **EXPLOIT** → Spawn `exploiter` for EACH finding (NOT optional!)
4. **Validate** → Spawn `validator` for cross-verification

### ⚠️ YOU LOSE POINTS IF YOU:
- Only detect but don't exploit
- Test manually instead of spawning workers
- Don't use `get_strategy` to guide decisions
- Don't call `record_failure` on failed attacks"""

    def _build_environment_section(self) -> str:
        """Build environment context section."""
        import os
        import platform
        import shutil

        sections = []

        # OS info
        sections.append(f"- **OS**: {platform.system()} {platform.release()}")
        sections.append(f"- **Hostname**: {platform.node()}")

        # Available security tools
        tools_to_check = [
            "nmap", "gobuster", "ffuf", "sqlmap", "nuclei", "nikto",
            "hydra", "wpscan", "curl", "nc", "python3",
        ]
        tools_available = [t for t in tools_to_check if shutil.which(t)]

        if tools_available:
            sections.append(f"- **Tools**: {', '.join(tools_available[:10])}")

        # Wordlist locations
        wordlist_paths = [
            "/usr/share/wordlists",
            "/usr/share/seclists",
            os.path.expanduser("~/wordlists"),
        ]
        found = [p for p in wordlist_paths if os.path.isdir(p)]
        if found:
            sections.append(f"- **Wordlists**: {', '.join(found[:2])}")

        if len(sections) > 2:
            return f"""## Environment (Auto-Detected)

{chr(10).join(sections)}"""

        return ""

    def build_for_checkpoint(self, checkpoint_percent: int) -> str:
        """
        Build a checkpoint reminder.

        Args:
            checkpoint_percent: The checkpoint percentage (20, 40, 60, 80, 90).

        Returns:
            Checkpoint reminder string.
        """
        findings_count = self._budget_info.get("findings_count", 0)

        if checkpoint_percent <= 20:
            phase = "reconnaissance"
            guidance = "Have you discovered all entry points? Time to start testing."
        elif checkpoint_percent <= 40:
            phase = "enumeration"
            guidance = "Focus on the most promising attack vectors."
        elif checkpoint_percent <= 80:
            phase = "exploitation"
            guidance = "Validate findings with PoC. Document everything."
        else:
            phase = "reporting"
            guidance = "Time to wrap up. Generate final report."

        return f"""## Checkpoint: {checkpoint_percent}% Budget Used

**Current Phase**: {phase}
**Findings So Far**: {findings_count}
**Guidance**: {guidance}

Review your progress and adjust strategy if needed."""


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
# For container-based execution with minimal tools

MINIMAL_SYSTEM_PROMPT = """You are an autonomous penetration testing agent in Kali Linux.

## Objective
{objective}

## Target
{target}

## Environment
Kali Linux with full toolkit: nmap, gobuster, sqlmap, nuclei, nikto, hydra, curl, python3

## Wordlists
/usr/share/seclists/ - Discovery, Fuzzing, Passwords

## 🚨 SCORING: 20% PENALTY FOR NOT EXPLOITING!

| Status | Score | Impact |
|--------|-------|--------|
| **EXPLOITED** | DC + EC | FULL POINTS ✓ |
| VERIFIED | DC + EC×0.8 | -20% PENALTY! |

**DO NOT just detect vulnerabilities - EXPLOIT them!**

## 🤖 USE ALGORITHMS (MANDATORY)

```
# Before EVERY action - get Q-learning recommendations:
get_strategy(current_phase="scanning", endpoints_found=5, vulns_found=2)

# After EVERY failure - feed the learning algorithm:
record_failure(endpoint="/login", attack_type="sqli", reason="waf_blocked")

# After EVERY success - reinforce good strategies:
record_success(endpoint="/api", attack_type="sqli", severity="high", exploited=true)
```

## 🔥 SPAWN SWARM WORKERS (MANDATORY)

You are the COORDINATOR - NEVER test manually! Spawn workers:

```
swarm(agent_type="reconnaissance", task="Enumerate subdomains", background=true)
swarm(agent_type="scanner", task="Test /login for SQLi, XSS", background=true)
swarm(agent_type="exploiter", task="Exploit SQLi - dump database", background=true)
swarm(agent_type="validator", task="Verify finding independently", background=true)
```

**For EACH endpoint → spawn scanner worker**
**For EACH vulnerability → spawn EXPLOITER worker (not optional!)**
**For EACH finding → spawn validator worker**

Spawn 5-10 workers in parallel with background=true!

## Strategy
1. `get_strategy` → Get algorithm recommendations
2. Spawn recon workers (subdomains, dirs, tech)
3. For each endpoint → spawn scanner
4. For each vuln → spawn **EXPLOITER** (for full points!)
5. Validate all findings, record successes/failures
6. Synthesize results and report

Be methodical. Parallelize. EXPLOIT. Get root."""


def build_minimal_prompt(target: str, objective: str) -> str:
    """Build a minimal, token-efficient system prompt."""
    return MINIMAL_SYSTEM_PROMPT.format(target=target, objective=objective)


class MinimalPromptBuilder:
    """Minimal prompt builder for container-based execution."""

    def __init__(self) -> None:
        self._target: str = ""
        self._objective: str = "Perform security assessment"
        self._context: dict[str, Any] = {}

    def set_target(self, target: str) -> MinimalPromptBuilder:
        self._target = target
        return self

    def set_objective(self, objective: str) -> MinimalPromptBuilder:
        self._objective = objective
        return self

    def add_context(self, key: str, value: Any) -> MinimalPromptBuilder:
        self._context[key] = value
        return self

    def build(self) -> str:
        prompt = build_minimal_prompt(self._target, self._objective)
        if self._context:
            context_lines = ["\n## Additional Context"]
            for key, value in self._context.items():
                context_lines.append(f"- **{key}**: {value}")
            prompt += "\n".join(context_lines)
        return prompt
