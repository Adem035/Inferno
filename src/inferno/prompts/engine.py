"""
Inferno Prompt Engine.

This module dynamically assembles prompts from modular markdown files,
providing a clean, maintainable, and composable prompt system.

Architecture:
- templates/: Core identity and report templates
- behaviors/: Composable behavior modules (exploitation, CVE-driven, etc.)
- phases/: Phase-specific guidance (recon, enumeration, exploitation)
- contexts/: Target-type specific guidance (web, API, network, CTF)
- tools/: Tool usage protocols
- strategic/: Strategic intelligence (application models, attack plans, parameter analysis)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Base path for prompt files
PROMPTS_DIR = Path(__file__).parent


def load_prompt_file(relative_path: str) -> str:
    """
    Load a prompt file from the prompts directory.

    Args:
        relative_path: Path relative to prompts directory (e.g., "templates/system.md")

    Returns:
        File contents as string, or empty string if not found.
    """
    file_path = PROMPTS_DIR / relative_path
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("prompt_file_not_found", path=str(file_path))
        return ""
    except Exception as e:
        logger.error("prompt_file_error", path=str(file_path), error=str(e))
        return ""


def substitute_variables(template: str, variables: dict[str, Any]) -> str:
    """
    Substitute {{ variable }} placeholders in template.

    Args:
        template: Template string with {{ var }} placeholders
        variables: Dictionary of variable names to values

    Returns:
        Template with variables substituted.
    """
    result = template
    for key, value in variables.items():
        placeholder = "{{ " + key + " }}"
        result = result.replace(placeholder, str(value))
        # Also handle without spaces
        placeholder_no_space = "{{" + key + "}}"
        result = result.replace(placeholder_no_space, str(value))
    return result


class PromptEngine:
    """
    Dynamic prompt assembly engine.

    Composes system prompts from modular markdown files based on
    operation context (target type, phase, etc.).
    """

    def __init__(self) -> None:
        """Initialize the prompt engine."""
        self._cache: dict[str, str] = {}

    def _load_cached(self, path: str) -> str:
        """Load a prompt file with caching."""
        if path not in self._cache:
            self._cache[path] = load_prompt_file(path)
        return self._cache[path]

    def _load_strategic_template(self, template_name: str) -> str:
        """
        Load a strategic intelligence template.

        Args:
            template_name: Template filename (e.g., "application_model_context.md")

        Returns:
            Template content or empty string if not found.
        """
        template_path = PROMPTS_DIR / "strategic" / template_name
        try:
            return template_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.warning(
                "strategic_template_not_found",
                path=str(template_path),
            )
            return ""
        except Exception as e:
            logger.error(
                "strategic_template_error",
                path=str(template_path),
                error=str(e),
            )
            return ""

    def _render_application_model_context(self, model: Any) -> str:
        """
        Render application model strategic context.

        Args:
            model: ApplicationModel instance

        Returns:
            Rendered context section.
        """
        template = self._load_strategic_template("application_model_context.md")
        if not template:
            return ""

        # Build endpoints summary
        endpoints_summary = []
        for endpoint in model.endpoints:
            auth_str = f" (Auth: {endpoint.auth_type})" if endpoint.auth_type else ""
            endpoints_summary.append(
                f"- {endpoint.method} {endpoint.path}{auth_str}"
            )

        # Build auth flows summary
        auth_flows_summary = []
        for flow in model.auth_flows:
            steps_count = len(flow.steps)
            auth_flows_summary.append(
                f"- {flow.flow_type}: {steps_count} steps"
            )

        # Build data flows summary
        data_flows_summary = []
        for flow in model.data_flows:
            data_flows_summary.append(
                f"- {flow.source} -> {flow.sink} ({flow.flow_type})"
            )

        # Build state machines summary
        state_machines_summary = []
        for sm in model.state_machines:
            states_count = len(sm.states)
            transitions_count = len(sm.transitions)
            state_machines_summary.append(
                f"- {sm.name}: {states_count} states, {transitions_count} transitions"
            )

        # Build business logic summary
        business_logic_summary = []
        for rule in model.business_logic:
            business_logic_summary.append(
                f"- {rule.rule_type}: {rule.description}"
            )

        variables = {
            "endpoints_count": len(model.endpoints),
            "endpoints_summary": "\n".join(endpoints_summary) if endpoints_summary else "None discovered",
            "auth_flows_count": len(model.auth_flows),
            "auth_flows_summary": "\n".join(auth_flows_summary) if auth_flows_summary else "None discovered",
            "data_flows_count": len(model.data_flows),
            "data_flows_summary": "\n".join(data_flows_summary) if data_flows_summary else "None discovered",
            "state_machines_count": len(model.state_machines),
            "state_machines_summary": "\n".join(state_machines_summary) if state_machines_summary else "None discovered",
            "business_logic_count": len(model.business_logic),
            "business_logic_summary": "\n".join(business_logic_summary) if business_logic_summary else "None discovered",
        }

        return substitute_variables(template, variables)

    def _render_attack_plan_context(self, plan: Any) -> str:
        """
        Render attack plan strategic context.

        Args:
            plan: AttackPlan instance

        Returns:
            Rendered context section.
        """
        template = self._load_strategic_template("attack_plan_context.md")
        if not template:
            return ""

        # Build attack vectors summary
        attack_vectors_summary = []
        for vector in plan.attack_vectors[:5]:  # Top 5 vectors
            attack_vectors_summary.append(
                f"- {vector.vector_type} (Priority: {vector.priority:.2f})"
            )
            if vector.rationale:
                attack_vectors_summary.append(f"  Rationale: {vector.rationale}")

        # Build exploitation chains summary
        chains_summary = []
        for chain in plan.exploitation_chains[:3]:  # Top 3 chains
            steps_str = " -> ".join([s.attack_type for s in chain.steps])
            chains_summary.append(
                f"- Impact: {chain.impact_score:.2f} | {steps_str}"
            )

        # Build priority targets summary
        priority_targets_summary = []
        for target in plan.priority_targets[:5]:  # Top 5 targets
            priority_targets_summary.append(
                f"- {target.endpoint_pattern} (Score: {target.priority_score:.2f})"
            )
            if target.rationale:
                priority_targets_summary.append(f"  {target.rationale}")

        variables = {
            "attack_vectors_count": len(plan.attack_vectors),
            "attack_vectors_summary": "\n".join(attack_vectors_summary) if attack_vectors_summary else "None identified",
            "chains_count": len(plan.exploitation_chains),
            "chains_summary": "\n".join(chains_summary) if chains_summary else "None identified",
            "priority_targets_count": len(plan.priority_targets),
            "priority_targets_summary": "\n".join(priority_targets_summary) if priority_targets_summary else "None identified",
            "recommended_tools": ", ".join(plan.recommended_tools) if plan.recommended_tools else "Standard toolkit",
        }

        return substitute_variables(template, variables)

    def _render_parameter_guidance(self, analysis: dict) -> str:
        """
        Render parameter role analysis guidance.

        Args:
            analysis: Dictionary mapping parameters to their roles and metadata

        Returns:
            Rendered guidance section.
        """
        template = self._load_strategic_template("parameter_role_guidance.md")
        if not template:
            return ""

        # Import ParameterRole enum for comparison
        try:
            from inferno.core.parameter_role_analyzer import ParameterRole
        except ImportError:
            logger.warning("parameter_role_analyzer_not_found")
            return ""

        # Categorize parameters by role
        auth_params = []
        business_logic_params = []
        data_flow_params = []
        state_params = []
        injection_params = []

        for param_name, param_info in analysis.items():
            role = param_info.get("role")
            confidence = param_info.get("confidence", 0.0)
            evidence = param_info.get("evidence", [])

            param_entry = f"- `{param_name}` (Confidence: {confidence:.2f})"
            if evidence:
                param_entry += f"\n  Evidence: {', '.join(evidence[:3])}"

            if role == ParameterRole.AUTH:
                auth_params.append(param_entry)
            elif role == ParameterRole.BUSINESS_LOGIC:
                business_logic_params.append(param_entry)
            elif role == ParameterRole.DATA_FLOW:
                data_flow_params.append(param_entry)
            elif role == ParameterRole.STATE_TRANSITION:
                state_params.append(param_entry)
            elif role == ParameterRole.INJECTION_SINK:
                injection_params.append(param_entry)

        variables = {
            "auth_params_count": len(auth_params),
            "auth_params": "\n".join(auth_params) if auth_params else "None identified",
            "business_logic_count": len(business_logic_params),
            "business_logic_params": "\n".join(business_logic_params) if business_logic_params else "None identified",
            "data_flow_count": len(data_flow_params),
            "data_flow_params": "\n".join(data_flow_params) if data_flow_params else "None identified",
            "state_params_count": len(state_params),
            "state_params": "\n".join(state_params) if state_params else "None identified",
            "injection_params_count": len(injection_params),
            "injection_params": "\n".join(injection_params) if injection_params else "None identified",
        }

        return substitute_variables(template, variables)

    def _render_strategic_context(
        self,
        application_model: Any | None,
        attack_plan: Any | None,
        parameter_analysis: dict | None,
    ) -> str:
        """
        Render strategic intelligence context from all available sources.

        Args:
            application_model: Optional ApplicationModel instance
            attack_plan: Optional AttackPlan instance
            parameter_analysis: Optional parameter role analysis dict

        Returns:
            Combined strategic context section.
        """
        parts = []

        if application_model:
            context = self._render_application_model_context(application_model)
            if context:
                parts.append(context)

        if attack_plan:
            context = self._render_attack_plan_context(attack_plan)
            if context:
                parts.append(context)

        if parameter_analysis:
            context = self._render_parameter_guidance(parameter_analysis)
            if context:
                parts.append(context)

        return "\n\n".join(parts)

    def build_system_prompt(
        self,
        target: str,
        objective: str,
        scope: str = "Target and related assets",
        rules: str = "Standard penetration testing rules apply",
        operation_id: str = "",
        current_step: int = 0,
        max_steps: int = 100,
        context_type: str = "web",  # web, api, network, cloud, ctf
        include_phases: list[str] | None = None,  # recon, enumeration, exploitation, post_exploit
        # Strategic intelligence parameters
        application_model: Any | None = None,
        attack_plan: Any | None = None,
        parameter_analysis: dict | None = None,
    ) -> str:
        """
        Build a complete system prompt for an operation.

        Args:
            target: Target identifier (URL, IP, domain)
            objective: Mission objective
            scope: Scope definition
            rules: Engagement rules
            operation_id: Operation identifier
            current_step: Current step number
            max_steps: Maximum steps allowed
            context_type: Type of target (web, api, network, cloud, ctf)
            include_phases: Specific phases to include (None = all)
            application_model: Optional ApplicationModel for strategic context
            attack_plan: Optional AttackPlan for strategic guidance
            parameter_analysis: Optional parameter role analysis

        Returns:
            Complete assembled system prompt.
        """
        parts = []

        # 1. Base system template (identity + ethics)
        system_template = self._load_cached("templates/system.md")
        variables = {
            "target": target,
            "objective": objective,
            "scope": scope,
            "rules": rules,
            "operation_id": operation_id,
            "current_step": current_step,
            "max_steps": max_steps,
        }
        parts.append(substitute_variables(system_template, variables))

        # 2. Strategic Intelligence Section (NEW)
        if any([application_model, attack_plan, parameter_analysis]):
            parts.append("## Strategic Intelligence\n")
            strategic_context = self._render_strategic_context(
                application_model=application_model,
                attack_plan=attack_plan,
                parameter_analysis=parameter_analysis,
            )
            if strategic_context:
                parts.append(strategic_context)

        # 3. Behaviors (always include all)
        behaviors = [
            "behaviors/cognitive_loop.md",
            "behaviors/human_methodology.md",  # Human pentester behavior
            "behaviors/exploitation_escalation.md",
            "behaviors/creative_exploitation.md",  # Adversarial mindset and bypass techniques
            "behaviors/cve_driven.md",
            "behaviors/chaining.md",
            "behaviors/persistence.md",
            "behaviors/termination.md",
            # Bug bounty quality behaviors
            "behaviors/so_what_gate.md",
            "behaviors/escalation_requirements.md",
            "behaviors/severity_calibration.md",
            "behaviors/pre_report_checklist.md",
        ]
        loaded_behaviors = []
        for behavior in behaviors:
            content = self._load_cached(behavior)
            if content:
                parts.append(content)
                loaded_behaviors.append(behavior.split("/")[-1])

        # Log loaded behaviors
        logger.info(
            "prompt_behaviors_loaded",
            behaviors=loaded_behaviors,
            count=len(loaded_behaviors),
            includes_creative_exploitation="creative_exploitation.md" in loaded_behaviors,
        )

        # 4. Context-specific guidance
        context_file = f"contexts/{context_type}.md"
        context_content = self._load_cached(context_file)
        if context_content:
            parts.append(context_content)

        # 5. Phase guidance (if specified)
        if include_phases is None:
            include_phases = ["recon", "enumeration", "exploitation", "post_exploit"]

        for phase in include_phases:
            phase_file = f"phases/{phase}.md"
            phase_content = self._load_cached(phase_file)
            if phase_content:
                parts.append(phase_content)

        # 6. Tool guide
        tool_guide = self._load_cached("tools/tool_guide.md")
        if tool_guide:
            parts.append(tool_guide)

        # 7. Technique-specific guidance (exploitation, API security, etc.)
        # These are loaded based on context_type for relevance
        techniques = [
            "techniques/core_guidance.md",  # Core attack methodology
            "techniques/exploitation.md",   # Exploitation techniques
            "techniques/advanced_attacks.md",  # Race conditions, SSTI, HTTP smuggling, etc.
        ]

        # Add context-specific techniques
        if context_type in ["api", "web"]:
            techniques.append("techniques/api_security.md")
        if context_type in ["web", "ctf"]:
            techniques.append("techniques/reconnaissance.md")

        loaded_techniques = []
        for technique in techniques:
            content = self._load_cached(technique)
            if content:
                parts.append(content)
                loaded_techniques.append(technique.split("/")[-1])

        # Log loaded techniques
        logger.info(
            "prompt_techniques_loaded",
            techniques=loaded_techniques,
            count=len(loaded_techniques),
            includes_advanced_attacks="advanced_attacks.md" in loaded_techniques,
        )

        # Combine all parts
        return "\n\n".join(part for part in parts if part.strip())

    def build_report_prompt(
        self,
        target: str,
        objective: str,
    ) -> str:
        """
        Build a report generation prompt.

        Args:
            target: Target identifier
            objective: Mission objective

        Returns:
            Report generation prompt.
        """
        template = self._load_cached("templates/report.md")
        variables = {
            "target": target,
            "objective": objective,
        }
        return substitute_variables(template, variables)

    def build_continuation_prompt(
        self,
        target: str,
        segment_number: int,
        max_segments: int,
    ) -> str:
        """
        Build a prompt for conversation continuation (new segment).

        Args:
            target: Target identifier
            segment_number: Current segment number
            max_segments: Maximum segments allowed

        Returns:
            Continuation prompt with memory recall instructions.
        """
        return f"""[SEGMENT {segment_number}/{max_segments} STARTING]

⚠️ CRITICAL: Previous conversation context has been reset. You MUST recall your findings from memory.

## FIRST ACTION REQUIRED

Execute these memory commands IMMEDIATELY to recover your findings:

```
memory_list(memory_type="finding")
memory_list(memory_type="credential")
memory_list(memory_type="vulnerability")
memory_search(query="{target}")
```

## After Memory Recall

1. Review all findings from previous segments
2. Identify what exploitation chains are in progress
3. Continue from where you left off
4. DO NOT repeat reconnaissance already completed

## Segment Budget

You are in segment {segment_number} of {max_segments}. Manage your budget accordingly:
- If this is a later segment, focus on exploitation over recon
- Store findings immediately as you discover them
- At 90% of segment budget, dump all findings to memory
"""

    def get_checkpoint_prompt(
        self,
        percent_complete: int,
        findings_count: int,
        current_phase: str,
    ) -> str:
        """
        Build a checkpoint evaluation prompt.

        Args:
            percent_complete: Percentage of budget used
            findings_count: Number of findings so far
            current_phase: Current assessment phase

        Returns:
            Checkpoint prompt.
        """
        if percent_complete >= 90:
            return f"""[CHECKPOINT {percent_complete}% - CRITICAL MEMORY DUMP]

⚠️ You are at {percent_complete}% of budget. Segment may end soon.

## MANDATORY ACTIONS

1. Store ALL findings to memory NOW:
   - Every vulnerability discovered
   - Every credential extracted
   - Every important recon data

2. Current status:
   - Findings so far: {findings_count}
   - Current phase: {current_phase}

3. If you have unstored findings, store them IMMEDIATELY

4. Continue exploitation if time permits
"""
        else:
            return f"""[CHECKPOINT {percent_complete}%]

Current status:
- Budget used: {percent_complete}%
- Findings: {findings_count}
- Phase: {current_phase}

Questions to consider:
1. Am I making progress toward the objective?
2. Should I pivot to a different approach?
3. Have I stored important findings?

Continue with current approach or adapt as needed.
"""

    def clear_cache(self) -> None:
        """Clear the prompt file cache."""
        self._cache.clear()
        logger.info("prompt_cache_cleared")


# Global engine instance
_engine: PromptEngine | None = None


def get_engine() -> PromptEngine:
    """Get the global prompt engine instance."""
    global _engine
    if _engine is None:
        _engine = PromptEngine()
    return _engine


def build_system_prompt(
    target: str,
    objective: str,
    scope: str = "Target and related assets",
    rules: str = "Standard penetration testing rules apply",
    operation_id: str = "",
    current_step: int = 0,
    max_steps: int = 100,
    context_type: str = "web",
    include_phases: list[str] | None = None,
    application_model: Any | None = None,
    attack_plan: Any | None = None,
    parameter_analysis: dict | None = None,
) -> str:
    """
    Convenience function to build a system prompt.

    See PromptEngine.build_system_prompt for details.
    """
    return get_engine().build_system_prompt(
        target=target,
        objective=objective,
        scope=scope,
        rules=rules,
        operation_id=operation_id,
        current_step=current_step,
        max_steps=max_steps,
        context_type=context_type,
        include_phases=include_phases,
        application_model=application_model,
        attack_plan=attack_plan,
        parameter_analysis=parameter_analysis,
    )


def build_report_prompt(target: str, objective: str) -> str:
    """
    Convenience function to build a report prompt.

    See PromptEngine.build_report_prompt for details.
    """
    return get_engine().build_report_prompt(target=target, objective=objective)


def build_continuation_prompt(
    target: str,
    segment_number: int,
    max_segments: int,
) -> str:
    """
    Convenience function to build a continuation prompt.

    See PromptEngine.build_continuation_prompt for details.
    """
    return get_engine().build_continuation_prompt(
        target=target,
        segment_number=segment_number,
        max_segments=max_segments,
    )


def get_checkpoint_prompt(
    percent_complete: int,
    findings_count: int = 0,
    current_phase: str = "exploitation",
) -> str:
    """
    Convenience function to get a checkpoint prompt.

    See PromptEngine.get_checkpoint_prompt for details.
    """
    return get_engine().get_checkpoint_prompt(
        percent_complete=percent_complete,
        findings_count=findings_count,
        current_phase=current_phase,
    )


# Detect context type from target
def detect_context_type(target: str, objective: str = "") -> str:
    """
    Detect the appropriate context type from target and objective.

    Auto-detection logic:
    - Firmware files (.bin, .fw, .img) -> iot
    - Memory dumps (.dmp, .dump, .mem) -> iot
    - Binaries (.exe, .dll, .so) -> iot
    - IP ranges (CIDR) -> network
    - Single IPs -> iot
    - CTF keywords -> ctf
    - Cloud keywords -> cloud
    - API paths -> api
    - Default -> web

    Args:
        target: Target string
        objective: Objective string

    Returns:
        Context type: web, api, network, cloud, ctf, iot
    """
    from pathlib import Path

    target_lower = target.lower()
    objective_lower = objective.lower()

    # CTF detection
    if any(x in objective_lower for x in ["flag", "ctf", "capture the flag", "challenge"]):
        return "ctf"

    # IoT/Firmware detection - files for analysis
    firmware_extensions = ['.bin', '.fw', '.img', '.rom', '.hex', '.elf', '.srec', '.uf2']
    if any(target_lower.endswith(ext) for ext in firmware_extensions):
        return "iot"

    # Memory dump detection
    memory_extensions = ['.dmp', '.dump', '.mem', '.raw', '.vmem', '.lime']
    if any(target_lower.endswith(ext) for ext in memory_extensions):
        return "iot"

    # Binary reverse engineering detection
    binary_extensions = ['.exe', '.dll', '.so', '.dylib', '.apk', '.ipa', '.out']
    if any(target_lower.endswith(ext) for ext in binary_extensions):
        return "iot"

    # Check if it's an existing file (firmware/binary)
    if Path(target).exists() and Path(target).is_file():
        return "iot"

    # IP range detection (CIDR) - network/IoT assessment
    if re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', target):
        return "network"

    # Single IP detection - likely IoT device
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target) and "http" not in target_lower:
        return "iot"

    # IoT keyword detection in objective
    iot_keywords = ["iot", "firmware", "embedded", "smart", "device", "mqtt", "coap", "zigbee", "ble", "bluetooth"]
    if any(x in objective_lower for x in iot_keywords):
        return "iot"

    # Cloud detection
    if any(x in target_lower for x in ["aws", "azure", "gcp", "s3", "ec2", "lambda"]):
        return "cloud"

    # API detection
    if any(x in target_lower for x in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
        return "api"

    # Default to web
    return "web"


# ============================================================================
# SWARM AGENT PROMPT SYSTEM
# ============================================================================

# Map role names to role file paths
SWARM_ROLE_FILES = {
    "coordinator": "swarm/roles/coordinator.md",
    "recon": "swarm/roles/recon.md",
    "scanner": "swarm/roles/scanner.md",
    "exploiter": "swarm/roles/exploiter.md",
    "auth": "swarm/roles/auth.md",
    "api": "swarm/roles/api.md",
    "waf": "swarm/roles/waf.md",
    "reporter": "swarm/roles/reporter.md",
}


def build_swarm_agent_prompt(
    role: str,
    agent_id: str,
    objective: str,
    target: str,
    main_objective: str,
    max_turns: int = 50,
    turns_used: int = 0,
    shared_context: str = "",
    shared_findings: str = "",
) -> str:
    """
    Build a system prompt for a swarm agent.

    Args:
        role: Agent role (recon, scanner, exploiter, auth, api, waf, reporter, coordinator)
        agent_id: Unique agent identifier
        objective: This agent's specific objective
        target: Target being assessed
        main_objective: Overall swarm objective
        max_turns: Maximum turns for this agent
        turns_used: Turns already used
        shared_context: Context from other agents
        shared_findings: Findings from other agents

    Returns:
        Complete swarm agent system prompt.
    """
    engine = get_engine()
    parts = []

    # 1. Base swarm agent template
    base_template = engine._load_cached("swarm/base.md")
    if base_template:
        budget_percent = round((1 - turns_used / max_turns) * 100, 1) if max_turns > 0 else 100
        variables = {
            "role": role.upper(),
            "agent_id": agent_id,
            "objective": objective,
            "target": target,
            "main_objective": main_objective,
            "max_turns": max_turns,
            "turns_used": turns_used,
            "budget_percent": budget_percent,
        }
        parts.append(substitute_variables(base_template, variables))

    # 2. Role-specific guidance
    role_file = SWARM_ROLE_FILES.get(role.lower())
    if role_file:
        role_content = engine._load_cached(role_file)
        if role_content:
            parts.append(role_content)

    # 3. Key behaviors (subset for efficiency)
    # Swarm agents get the critical behaviors
    key_behaviors = [
        "behaviors/exploitation_escalation.md",  # Always exploit, don't just discover
        "behaviors/persistence.md",              # Don't give up
    ]
    for behavior in key_behaviors:
        content = engine._load_cached(behavior)
        if content:
            parts.append(content)

    # 4. Shared context section
    if shared_context:
        parts.append(f"""## Shared Context from Other Agents

{shared_context}""")

    # 5. Shared findings section
    if shared_findings:
        parts.append(f"""## Findings from Other Agents

{shared_findings}""")

    return "\n\n".join(part for part in parts if part.strip())


def build_coordinator_prompt(
    target: str,
    objective: str,
    max_total_turns: int = 500,
    total_turns_used: int = 0,
    agents_status: str = "",
    findings_summary: str = "",
) -> str:
    """
    Build a system prompt for the swarm coordinator.

    Args:
        target: Target being assessed
        objective: Overall assessment objective
        max_total_turns: Total swarm budget
        total_turns_used: Turns used so far
        agents_status: Status of all agents
        findings_summary: Summary of findings so far

    Returns:
        Coordinator system prompt.
    """
    return build_swarm_agent_prompt(
        role="coordinator",
        agent_id="coordinator_main",
        objective=f"Coordinate swarm to achieve: {objective}",
        target=target,
        main_objective=objective,
        max_turns=max_total_turns,
        turns_used=total_turns_used,
        shared_context=agents_status,
        shared_findings=findings_summary,
    )
