"""
Mako Template Engine for Inferno Prompts.

Extends the base prompt engine with Mako template support
for advanced dynamic prompt generation with:
- Template inheritance (<%inherit>)
- Conditional rendering (% if/elif/else)
- Loop constructs (% for)
- Template blocks and defs (<%def>)
- Python expressions (${expr})
- Includes (<%include>)

Inspired by CAI's flexible prompt system that uses Mako
for dynamic context-aware prompt assembly.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import structlog

# Try to import Mako, provide fallback if not available
try:
    from mako.exceptions import MakoException
    from mako.lookup import TemplateLookup
    from mako.template import Template
    MAKO_AVAILABLE = True
except ImportError:
    MAKO_AVAILABLE = False
    Template = None
    TemplateLookup = None
    MakoException = Exception

from inferno.prompts.engine import PROMPTS_DIR, PromptEngine, load_prompt_file

logger = structlog.get_logger(__name__)

T = TypeVar("T")


class TemplateContext:
    """
    Context object passed to templates for rendering.

    Provides access to common variables and helper functions
    within Mako templates.
    """

    def __init__(
        self,
        target: str = "",
        objective: str = "",
        scope: str = "",
        rules: str = "",
        operation_id: str = "",
        current_step: int = 0,
        max_steps: int = 100,
        context_type: str = "web",
        phase: str = "recon",
        findings: list[dict[str, Any]] = None,
        credentials: list[dict[str, Any]] = None,
        agent_role: str = "",
        agent_id: str = "",
        custom_vars: dict[str, Any] = None,
    ):
        self.target = target
        self.objective = objective
        self.scope = scope
        self.rules = rules
        self.operation_id = operation_id
        self.current_step = current_step
        self.max_steps = max_steps
        self.context_type = context_type
        self.phase = phase
        self.findings = findings or []
        self.credentials = credentials or []
        self.agent_role = agent_role
        self.agent_id = agent_id
        self.custom_vars = custom_vars or {}

        # Derived properties
        self.timestamp = datetime.utcnow().isoformat()
        self.budget_percent = (
            round((1 - current_step / max_steps) * 100, 1)
            if max_steps > 0 else 100
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for template rendering."""
        base = {
            "target": self.target,
            "objective": self.objective,
            "scope": self.scope,
            "rules": self.rules,
            "operation_id": self.operation_id,
            "current_step": self.current_step,
            "max_steps": self.max_steps,
            "context_type": self.context_type,
            "phase": self.phase,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "credentials": self.credentials,
            "credentials_count": len(self.credentials),
            "agent_role": self.agent_role,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "budget_percent": self.budget_percent,
            # Helper functions
            "severity_badge": self._severity_badge,
            "format_finding": self._format_finding,
            "truncate": self._truncate,
            "format_list": self._format_list,
        }
        base.update(self.custom_vars)
        return base

    @staticmethod
    def _severity_badge(severity: str) -> str:
        """Get a severity badge for display."""
        badges = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]",
            "medium": "[MEDIUM]",
            "low": "[LOW]",
            "info": "[INFO]",
        }
        return badges.get(severity.lower(), f"[{severity.upper()}]")

    @staticmethod
    def _format_finding(finding: dict[str, Any]) -> str:
        """Format a finding for display in prompts."""
        vuln_type = finding.get("vuln_type", "Unknown")
        severity = finding.get("severity", "unknown")
        target = finding.get("target", "N/A")
        return f"{TemplateContext._severity_badge(severity)} {vuln_type} @ {target}"

    @staticmethod
    def _truncate(text: str, length: int = 100) -> str:
        """Truncate text to specified length."""
        if len(text) <= length:
            return text
        return text[:length-3] + "..."

    @staticmethod
    def _format_list(items: list[Any], bullet: str = "-") -> str:
        """Format a list with bullets."""
        return "\n".join(f"{bullet} {item}" for item in items)


class MakoPromptEngine:
    """
    Mako-powered prompt engine for dynamic template rendering.

    Extends the base PromptEngine with full Mako template support
    for advanced prompt composition and conditional logic.
    """

    def __init__(
        self,
        templates_dir: Path | None = None,
        cache_enabled: bool = True,
        fallback_to_basic: bool = True,
    ):
        """
        Initialize the Mako prompt engine.

        Args:
            templates_dir: Directory containing Mako templates (.mako files)
            cache_enabled: Whether to cache compiled templates
            fallback_to_basic: Fall back to basic engine if Mako unavailable
        """
        self._templates_dir = templates_dir or PROMPTS_DIR / "mako"
        self._cache_enabled = cache_enabled
        self._fallback_to_basic = fallback_to_basic
        self._template_cache: dict[str, Any] = {}
        self._basic_engine = PromptEngine()

        # Set up Mako lookup if available
        self._lookup: TemplateLookup | None = None
        if MAKO_AVAILABLE:
            self._setup_lookup()
        elif not fallback_to_basic:
            raise ImportError(
                "Mako templates not available. Install with: pip install Mako"
            )

        logger.info(
            "mako_engine_init",
            templates_dir=str(self._templates_dir),
            mako_available=MAKO_AVAILABLE,
        )

    def _setup_lookup(self) -> None:
        """Set up Mako template lookup."""
        # Create templates directory if it doesn't exist
        self._templates_dir.mkdir(parents=True, exist_ok=True)

        # Configure template lookup
        self._lookup = TemplateLookup(
            directories=[str(self._templates_dir), str(PROMPTS_DIR)],
            module_directory="/tmp/mako_modules" if self._cache_enabled else None,
            collection_size=500,
            filesystem_checks=True,
            input_encoding="utf-8",
            output_encoding="utf-8",
            encoding_errors="replace",
            default_filters=["str"],
        )

    def _get_template(self, template_name: str) -> Template | None:
        """
        Get a Mako template by name.

        Args:
            template_name: Template filename (with or without .mako extension)

        Returns:
            Compiled Mako template or None.
        """
        if not MAKO_AVAILABLE or not self._lookup:
            return None

        # Add .mako extension if not present
        if not template_name.endswith(".mako"):
            template_name = f"{template_name}.mako"

        try:
            # Check cache first
            if self._cache_enabled and template_name in self._template_cache:
                return self._template_cache[template_name]

            # Load template
            template = self._lookup.get_template(template_name)

            # Cache if enabled
            if self._cache_enabled:
                self._template_cache[template_name] = template

            return template

        except Exception as e:
            logger.warning(
                "mako_template_load_error",
                template=template_name,
                error=str(e),
            )
            return None

    def render(
        self,
        template_name: str,
        context: TemplateContext,
        **extra_vars,
    ) -> str:
        """
        Render a Mako template with context.

        Args:
            template_name: Template filename
            context: Template context
            **extra_vars: Additional template variables

        Returns:
            Rendered template string.
        """
        # Get template variables
        template_vars = context.to_dict()
        template_vars.update(extra_vars)

        # Try Mako template first
        template = self._get_template(template_name)
        if template:
            try:
                rendered = template.render(**template_vars)
                # Decode if bytes
                if isinstance(rendered, bytes):
                    rendered = rendered.decode("utf-8")
                return rendered
            except MakoException as e:
                logger.error(
                    "mako_render_error",
                    template=template_name,
                    error=str(e),
                )
                if not self._fallback_to_basic:
                    raise

        # Fallback to basic template loading with variable substitution
        if self._fallback_to_basic:
            return self._render_basic(template_name, template_vars)

        return ""

    def _render_basic(
        self,
        template_name: str,
        variables: dict[str, Any],
    ) -> str:
        """
        Basic template rendering without Mako.

        Uses simple {{ variable }} substitution.

        Args:
            template_name: Template filename
            variables: Template variables

        Returns:
            Rendered template string.
        """
        # Remove .mako extension for basic lookup
        if template_name.endswith(".mako"):
            template_name = template_name[:-5] + ".md"

        # Try to load from templates dir
        template_path = self._templates_dir / template_name
        if template_path.exists():
            content = template_path.read_text(encoding="utf-8")
        else:
            # Try PROMPTS_DIR
            content = load_prompt_file(template_name)

        if not content:
            return ""

        # Simple variable substitution
        for key, value in variables.items():
            if not callable(value):
                # Handle both {{ var }} and ${var} syntax
                content = content.replace("{{ " + key + " }}", str(value))
                content = content.replace("{{" + key + "}}", str(value))
                content = re.sub(
                    r"\$\{" + re.escape(key) + r"\}",
                    str(value),
                    content
                )

        return content

    def render_string(
        self,
        template_string: str,
        context: TemplateContext,
        **extra_vars,
    ) -> str:
        """
        Render a Mako template from a string.

        Args:
            template_string: Template content as string
            context: Template context
            **extra_vars: Additional template variables

        Returns:
            Rendered string.
        """
        template_vars = context.to_dict()
        template_vars.update(extra_vars)

        if MAKO_AVAILABLE:
            try:
                template = Template(
                    template_string,
                    lookup=self._lookup,
                )
                rendered = template.render(**template_vars)
                if isinstance(rendered, bytes):
                    rendered = rendered.decode("utf-8")
                return rendered
            except MakoException as e:
                logger.error("mako_string_render_error", error=str(e))
                if not self._fallback_to_basic:
                    raise

        # Basic fallback
        return self._render_basic_string(template_string, template_vars)

    def _render_basic_string(
        self,
        template_string: str,
        variables: dict[str, Any],
    ) -> str:
        """Basic string template rendering."""
        result = template_string
        for key, value in variables.items():
            if not callable(value):
                result = result.replace("{{ " + key + " }}", str(value))
                result = result.replace("{{" + key + "}}", str(value))
                result = re.sub(
                    r"\$\{" + re.escape(key) + r"\}",
                    str(value),
                    result
                )
        return result

    def build_system_prompt(
        self,
        target: str,
        objective: str,
        scope: str = "Target and related assets",
        rules: str = "Standard penetration testing rules apply",
        operation_id: str = "",
        current_step: int = 0,
        max_steps: int = 100,
        context_type: str = "web",
        phase: str = "recon",
        include_behaviors: list[str] = None,
        findings: list[dict[str, Any]] = None,
        custom_vars: dict[str, Any] = None,
    ) -> str:
        """
        Build a system prompt using Mako templates.

        Args:
            target: Target identifier
            objective: Mission objective
            scope: Scope definition
            rules: Engagement rules
            operation_id: Operation identifier
            current_step: Current step number
            max_steps: Maximum steps
            context_type: Target context type
            phase: Current assessment phase
            include_behaviors: Behaviors to include
            findings: Current findings
            custom_vars: Custom template variables

        Returns:
            Complete system prompt.
        """
        context = TemplateContext(
            target=target,
            objective=objective,
            scope=scope,
            rules=rules,
            operation_id=operation_id,
            current_step=current_step,
            max_steps=max_steps,
            context_type=context_type,
            phase=phase,
            findings=findings or [],
            custom_vars=custom_vars or {},
        )

        # Try Mako system template first
        prompt = self.render("system.mako", context)
        if prompt:
            return prompt

        # Fallback to basic engine
        return self._basic_engine.build_system_prompt(
            target=target,
            objective=objective,
            scope=scope,
            rules=rules,
            operation_id=operation_id,
            current_step=current_step,
            max_steps=max_steps,
            context_type=context_type,
        )

    def build_agent_prompt(
        self,
        role: str,
        agent_id: str,
        objective: str,
        target: str,
        main_objective: str,
        max_turns: int = 50,
        turns_used: int = 0,
        shared_context: str = "",
        shared_findings: list[dict[str, Any]] = None,
        custom_vars: dict[str, Any] = None,
    ) -> str:
        """
        Build a swarm agent prompt using Mako templates.

        Args:
            role: Agent role (recon, scanner, exploiter, etc.)
            agent_id: Unique agent identifier
            objective: Agent's specific objective
            target: Target being assessed
            main_objective: Overall objective
            max_turns: Maximum turns for agent
            turns_used: Turns used so far
            shared_context: Context from other agents
            shared_findings: Findings from other agents
            custom_vars: Custom template variables

        Returns:
            Complete agent prompt.
        """
        context = TemplateContext(
            target=target,
            objective=objective,
            agent_role=role,
            agent_id=agent_id,
            current_step=turns_used,
            max_steps=max_turns,
            findings=shared_findings or [],
            custom_vars={
                "main_objective": main_objective,
                "shared_context": shared_context,
                **(custom_vars or {}),
            },
        )

        # Try role-specific Mako template
        prompt = self.render(f"agents/{role}.mako", context)
        if prompt:
            return prompt

        # Try generic agent template
        prompt = self.render("agents/base.mako", context)
        if prompt:
            return prompt

        # Fallback to basic engine
        from inferno.prompts.engine import build_swarm_agent_prompt
        return build_swarm_agent_prompt(
            role=role,
            agent_id=agent_id,
            objective=objective,
            target=target,
            main_objective=main_objective,
            max_turns=max_turns,
            turns_used=turns_used,
            shared_context=shared_context,
            shared_findings="\n".join(
                context._format_finding(f) for f in (shared_findings or [])
            ),
        )

    def create_template_file(
        self,
        name: str,
        content: str,
        overwrite: bool = False,
    ) -> Path:
        """
        Create a new Mako template file.

        Args:
            name: Template name (without .mako extension)
            content: Template content
            overwrite: Whether to overwrite existing

        Returns:
            Path to created template.
        """
        if not name.endswith(".mako"):
            name = f"{name}.mako"

        template_path = self._templates_dir / name

        # Create parent directories
        template_path.parent.mkdir(parents=True, exist_ok=True)

        if template_path.exists() and not overwrite:
            raise FileExistsError(f"Template {name} already exists")

        template_path.write_text(content, encoding="utf-8")

        # Clear cache for this template
        if name in self._template_cache:
            del self._template_cache[name]

        logger.info("mako_template_created", path=str(template_path))
        return template_path

    def clear_cache(self) -> None:
        """Clear template cache."""
        self._template_cache.clear()
        if self._lookup:
            # Recreate lookup to clear Mako's internal cache
            self._setup_lookup()
        logger.info("mako_cache_cleared")


# Sample Mako templates
SAMPLE_SYSTEM_TEMPLATE = '''<%doc>
System prompt template for Inferno penetration testing agent.
</%doc>
# Inferno Security Assessment Agent

## Target Information
- **Target**: ${target}
- **Objective**: ${objective}
- **Scope**: ${scope}

## Engagement Rules
${rules}

## Budget Status
- Step: ${current_step}/${max_steps}
- Remaining: ${budget_percent}%

% if findings_count > 0:
## Current Findings (${findings_count})
% for finding in findings:
- ${format_finding(finding)}
% endfor
% endif

## Phase: ${phase.upper()}
% if phase == "recon":
Focus on reconnaissance and information gathering.
% elif phase == "enumeration":
Focus on service enumeration and vulnerability discovery.
% elif phase == "exploitation":
Focus on exploiting discovered vulnerabilities.
% elif phase == "post_exploit":
Focus on post-exploitation and persistence.
% endif

## Core Directives
1. Always verify you're within scope before taking action
2. Document all findings immediately
3. Prioritize high-severity vulnerabilities
4. Chain vulnerabilities for maximum impact
'''

SAMPLE_AGENT_TEMPLATE = '''<%doc>
Base template for swarm agents.
</%doc>
# ${agent_role.upper()} Agent

**Agent ID**: ${agent_id}
**Objective**: ${objective}
**Target**: ${target}

## Mission Context
Main Objective: ${main_objective}

## Budget
- Turns: ${current_step}/${max_steps}
- Remaining: ${budget_percent}%

% if shared_context:
## Shared Context
${shared_context}
% endif

% if findings_count > 0:
## Shared Findings
% for finding in findings:
- ${format_finding(finding)}
% endfor
% endif

## Role-Specific Guidance
% if agent_role == "recon":
Focus on subdomain enumeration, OSINT, and attack surface mapping.
% elif agent_role == "scanner":
Focus on vulnerability scanning and CVE identification.
% elif agent_role == "exploiter":
Focus on exploiting identified vulnerabilities.
% elif agent_role == "auth":
Focus on authentication bypass and session attacks.
% elif agent_role == "api":
Focus on API security testing.
% endif

## Success Criteria
Report findings using memory_add() immediately upon discovery.
'''


def initialize_default_templates(engine: MakoPromptEngine) -> None:
    """
    Initialize default Mako templates.

    Args:
        engine: Mako engine instance
    """
    templates = {
        "system": SAMPLE_SYSTEM_TEMPLATE,
        "agents/base": SAMPLE_AGENT_TEMPLATE,
    }

    for name, content in templates.items():
        try:
            engine.create_template_file(name, content, overwrite=False)
        except FileExistsError:
            pass  # Template already exists


# Global engine instance
_mako_engine: MakoPromptEngine | None = None


def get_mako_engine() -> MakoPromptEngine:
    """Get the global Mako prompt engine instance."""
    global _mako_engine
    if _mako_engine is None:
        _mako_engine = MakoPromptEngine()
        initialize_default_templates(_mako_engine)
    return _mako_engine


def render_prompt(
    template_name: str,
    target: str = "",
    objective: str = "",
    **kwargs,
) -> str:
    """
    Convenience function to render a Mako prompt template.

    Args:
        template_name: Template name
        target: Target identifier
        objective: Mission objective
        **kwargs: Additional template variables

    Returns:
        Rendered prompt.
    """
    engine = get_mako_engine()
    context = TemplateContext(
        target=target,
        objective=objective,
        custom_vars=kwargs,
    )
    return engine.render(template_name, context)


class SystemPromptRenderer:
    """
    System prompt renderer using the master template.

    Inspired by CAI's system_master_template pattern, this renderer
    assembles the complete system prompt with:
    - Base system instructions
    - Compacted summary (optional)
    - Memory context (optional)
    - Reasoning content (optional)
    - Environment context (auto-injected)

    Example usage:
        renderer = create_system_prompt_renderer()
        prompt = renderer.render(
            system_prompt="You are a security agent...",
            compacted_summary="Previous session found SQLi on /api/users",
            memory="[Memory entries...]",
            reasoning_content="Reasoning about approach...",
        )
    """

    def __init__(
        self,
        engine: MakoPromptEngine | None = None,
        template_name: str = "system_master_template.mako",
        include_env_context: bool = True,
    ):
        """
        Initialize the system prompt renderer.

        Args:
            engine: MakoPromptEngine instance (uses global if None)
            template_name: Name of the master template file
            include_env_context: Whether to include environment context
        """
        self._engine = engine or get_mako_engine()
        self._template_name = template_name
        self._include_env_context = include_env_context
        self._env_context_enabled = os.environ.get(
            "INFERNO_ENV_CONTEXT", "true"
        ).lower() in ("true", "1", "yes")

    def _get_environment_info(self) -> dict[str, Any]:
        """
        Gather environment information for context injection.

        Returns:
            Dictionary with environment details.
        """
        import platform
        import socket

        env_info: dict[str, Any] = {}

        try:
            env_info["hostname"] = socket.gethostname()
            env_info["ip_addr"] = socket.gethostbyname(env_info["hostname"])
            env_info["os_name"] = platform.system()
            env_info["os_version"] = platform.release()
        except Exception:
            env_info["hostname"] = "localhost"
            env_info["ip_addr"] = "127.0.0.1"
            env_info["os_name"] = "Linux"
            env_info["os_version"] = "unknown"

        # Try to get tun0 address (VPN/CTF interface)
        env_info["tun0_addr"] = None
        try:
            import netifaces
            if "tun0" in netifaces.interfaces():
                addrs = netifaces.ifaddresses("tun0")
                if netifaces.AF_INET in addrs:
                    env_info["tun0_addr"] = addrs[netifaces.AF_INET][0].get("addr")
        except ImportError:
            pass
        except Exception:
            pass

        # Wordlist discovery
        wordlist_path = Path("/usr/share/wordlists")
        env_info["wordlist_files"] = []
        env_info["seclist_dirs"] = []

        if wordlist_path.exists():
            env_info["wordlist_files"] = [
                f.name for f in wordlist_path.iterdir() if f.is_file()
            ][:20]  # Limit to 20 entries

            seclists_path = wordlist_path / "seclists"
            if seclists_path.exists():
                env_info["seclist_dirs"] = [
                    d.name for d in seclists_path.iterdir() if d.is_dir()
                ]

        # Check for CTF environment
        env_info["ctf_inside"] = os.environ.get("CTF_INSIDE")
        env_info["ctf_name"] = os.environ.get("CTF_NAME")

        return env_info

    def _get_memory_context(self, query: str = "") -> str:
        """
        Retrieve memory context from vector database.

        Args:
            query: Search query for memory retrieval

        Returns:
            Memory context string or empty string.
        """
        memory_mode = os.environ.get("INFERNO_MEMORY", "").lower()

        if memory_mode not in ("episodic", "semantic", "all"):
            return ""

        try:
            import asyncio

            from inferno.tools.memory import memory_search

            # Run async function
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If already in async context, return empty
                # (caller should handle memory retrieval)
                return ""
            else:
                result = loop.run_until_complete(memory_search(query=query, limit=10))
                return result.output if result.success else ""
        except Exception as e:
            logger.warning("memory_retrieval_error", error=str(e))
            return ""

    def render(
        self,
        system_prompt: str,
        compacted_summary: str | None = None,
        memory: str | None = None,
        reasoning_content: str | None = None,
        target: str = "",
        objective: str = "",
        **extra_vars,
    ) -> str:
        """
        Render the system prompt using the master template.

        Args:
            system_prompt: Base system prompt/instructions
            compacted_summary: AI-generated summary from previous conversations
            memory: Past experiences from vector database
            reasoning_content: Reasoning from specialized models
            target: Target identifier (for memory retrieval)
            objective: Objective (for memory retrieval)
            **extra_vars: Additional template variables

        Returns:
            Fully rendered system prompt.
        """
        # Prepare template variables
        template_vars: dict[str, Any] = {
            "system_prompt": system_prompt,
            "compacted_summary": compacted_summary,
            "reasoning_content": reasoning_content,
            "target": target,
            "objective": objective,
        }

        # Handle memory - use provided or auto-retrieve
        if memory is not None:
            template_vars["memory"] = memory
            template_vars["rag_enabled"] = bool(memory)
        else:
            # Auto-retrieve from memory if enabled
            memory_mode = os.environ.get("INFERNO_MEMORY", "").lower()
            template_vars["rag_enabled"] = memory_mode in ("episodic", "semantic", "all")
            if template_vars["rag_enabled"]:
                query = target if memory_mode in ("semantic", "all") else ""
                template_vars["memory"] = self._get_memory_context(query)
            else:
                template_vars["memory"] = ""

        # Environment context
        template_vars["env_context"] = (
            "true" if self._include_env_context and self._env_context_enabled else "false"
        )
        if self._include_env_context and self._env_context_enabled:
            template_vars.update(self._get_environment_info())

        # Add extra variables
        template_vars.update(extra_vars)

        # Try to render with master template
        try:
            template_path = PROMPTS_DIR / "templates" / self._template_name
            if template_path.exists() and MAKO_AVAILABLE:
                template = Template(
                    filename=str(template_path),
                    lookup=self._engine._lookup,
                    input_encoding="utf-8",
                    output_encoding="utf-8",
                )
                rendered = template.render(**template_vars)
                if isinstance(rendered, bytes):
                    rendered = rendered.decode("utf-8")
                return rendered
        except Exception as e:
            logger.warning(
                "master_template_render_error",
                error=str(e),
                fallback="inline_render",
            )

        # Fallback: inline rendering without master template
        return self._render_inline(
            system_prompt=system_prompt,
            compacted_summary=compacted_summary,
            memory=template_vars.get("memory", ""),
            reasoning_content=reasoning_content,
            rag_enabled=template_vars["rag_enabled"],
            env_context=template_vars["env_context"],
            env_info=template_vars if self._include_env_context else {},
        )

    def _render_inline(
        self,
        system_prompt: str,
        compacted_summary: str | None,
        memory: str,
        reasoning_content: str | None,
        rag_enabled: bool,
        env_context: str,
        env_info: dict[str, Any],
    ) -> str:
        """
        Inline rendering fallback when master template is unavailable.

        Args:
            system_prompt: Base system prompt
            compacted_summary: Optional compacted summary
            memory: Memory context
            reasoning_content: Optional reasoning content
            rag_enabled: Whether RAG is enabled
            env_context: Whether to include env context
            env_info: Environment information dict

        Returns:
            Rendered prompt string.
        """
        parts = [system_prompt]

        # Compacted summary section
        if compacted_summary:
            parts.append(f"""
<compacted_context>
This is a summary of previous conversation context that has been compacted to save tokens:

{compacted_summary}

Use this summary to understand the context and continue from where the conversation left off.
</compacted_context>""")

        # Memory section
        if rag_enabled and memory:
            parts.append(f"""
<memory>
{memory}
</memory>

Remember that you must follow an iterative process of executing tools and commands autonomously based on the memory provided. The memory shows successful steps that were previously completed. Focus on reproducing the key tool calls and exploitation steps in a methodical way to reach the same goals. Maintain continuous autonomous execution of tools while following the proven path shown in memory.""")

        # Reasoning section
        if reasoning_content is not None:
            parts.append(f"""
<reasoning>
{reasoning_content}
</reasoning>""")

        # Environment context section
        if env_context.lower() == "true" and env_info:
            env_section = self._format_env_context(env_info)
            if env_section:
                parts.append(env_section)

        return "\n".join(parts)

    def _format_env_context(self, env_info: dict[str, Any]) -> str:
        """
        Format environment context for inline rendering.

        Args:
            env_info: Environment information dictionary

        Returns:
            Formatted environment context string.
        """
        lines = ["\nEnvironment context:"]

        # Seclists directories
        seclist_dirs = env_info.get("seclist_dirs", [])
        if seclist_dirs:
            lines.append("seclists")
            for d in seclist_dirs:
                lines.append(f"  {d}")
        else:
            lines.append("seclists")
            lines.append("  (No directories found in seclists)")

        lines.append("")
        lines.append("- When in doubt, list again.")
        lines.append("")
        lines.append("Attacker machine information:")
        lines.append(f"  OS: {env_info.get('os_name', 'Unknown')}")
        lines.append(f"  Hostname: {env_info.get('hostname', 'localhost')}")
        lines.append(f"  IP Attacker (default): {env_info.get('ip_addr', '127.0.0.1')}")

        tun0_addr = env_info.get("tun0_addr")
        if tun0_addr:
            lines.append(f"  IP tun0: {tun0_addr}")

        lines.append("  Role: Attacker")

        # Wordlists
        wordlist_files = env_info.get("wordlist_files", [])
        if wordlist_files:
            lines.append("")
            lines.append("Available wordlists (/usr/share/wordlists):")
            for f in wordlist_files:
                lines.append(f"  {f}")

        return "\n".join(lines)


def create_system_prompt_renderer(
    template_name: str = "system_master_template.mako",
    include_env_context: bool = True,
    engine: MakoPromptEngine | None = None,
) -> SystemPromptRenderer:
    """
    Create a system prompt renderer using the master template pattern.

    This is the primary factory function for creating a renderer that
    assembles system prompts following the CAI-inspired master template
    architecture with support for:

    - ${system_prompt} - Base agent instructions
    - % if compacted_summary - AI-generated conversation summary
    - % if memory - Past experiences from vector database (Mem0/Qdrant)
    - % if reasoning_content - Reasoning from specialized LLM models
    - Environment auto-injection - OS, IP, wordlists, etc.

    Example:
        ```python
        from inferno.prompts.mako_engine import create_system_prompt_renderer

        # Create renderer
        renderer = create_system_prompt_renderer()

        # Build base system prompt
        from inferno.prompts.engine import build_system_prompt
        base_prompt = build_system_prompt(
            target="https://example.com",
            objective="Find vulnerabilities",
        )

        # Render with all context
        final_prompt = renderer.render(
            system_prompt=base_prompt,
            compacted_summary="Previous session found SQLi...",
            memory="[Relevant memory entries]",
            reasoning_content="[Analysis from reasoning model]",
        )
        ```

    Args:
        template_name: Name of the master template file (default: system_master_template.mako)
        include_env_context: Whether to auto-inject environment context
        engine: Optional MakoPromptEngine instance (uses global if None)

    Returns:
        SystemPromptRenderer instance ready for rendering.
    """
    return SystemPromptRenderer(
        engine=engine,
        template_name=template_name,
        include_env_context=include_env_context,
    )
