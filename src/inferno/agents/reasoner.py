"""
Reasoner Agent for Inferno Penetration Testing Framework.

This module provides a dedicated reasoning agent that enhances the main agent's
analytical capabilities without making tool calls. The reasoner specializes in
structured analysis of security situations, attack vectors, and exploitation
strategies.

Supports both OpenAI reasoning models (o1, o3-mini) and Claude models.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# Path to the system prompt
PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


@dataclass
class ReasonerOutput:
    """
    Structured output from the reasoner agent.

    Attributes:
        findings: Key security findings and vulnerabilities identified.
        learnings: Lessons learned from analysis that should inform future actions.
        observations: General observations about the target or situation.
        relationships: Relationships between different attack vectors.
        raw_response: The complete raw response from the model.
        model_used: The model that generated this output.
    """

    findings: list[str] = field(default_factory=list)
    learnings: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)
    raw_response: str = ""
    model_used: str = ""

    @classmethod
    def parse_response(cls, response: str, model: str = "") -> ReasonerOutput:
        """
        Parse a raw model response into structured output.

        Args:
            response: Raw text response from the model.
            model: The model that generated the response.

        Returns:
            Structured ReasonerOutput with parsed sections.
        """
        output = cls(raw_response=response, model_used=model)

        # Parse sections from response
        current_section: str | None = None
        section_content: list[str] = []

        for line in response.split("\n"):
            line = line.strip()

            # Check for section headers
            lower_line = line.lower()
            if lower_line.startswith("findings:"):
                if current_section and section_content:
                    output._add_to_section(current_section, section_content)
                current_section = "findings"
                section_content = []
                # Check if content is on the same line
                remaining = line[len("findings:"):].strip()
                if remaining:
                    section_content.append(remaining)
            elif lower_line.startswith("learnings:"):
                if current_section and section_content:
                    output._add_to_section(current_section, section_content)
                current_section = "learnings"
                section_content = []
                remaining = line[len("learnings:"):].strip()
                if remaining:
                    section_content.append(remaining)
            elif lower_line.startswith("observations:"):
                if current_section and section_content:
                    output._add_to_section(current_section, section_content)
                current_section = "observations"
                section_content = []
                remaining = line[len("observations:"):].strip()
                if remaining:
                    section_content.append(remaining)
            elif lower_line.startswith("relationships"):
                if current_section and section_content:
                    output._add_to_section(current_section, section_content)
                current_section = "relationships"
                section_content = []
                # Handle "Relationships:" or "Relationships between vectors:"
                if ":" in line:
                    remaining = line.split(":", 1)[1].strip()
                    if remaining:
                        section_content.append(remaining)
            elif line and current_section:
                # Remove bullet points and add to current section
                if line.startswith("- ") or line.startswith("* "):
                    section_content.append(line[2:].strip())
                elif line.startswith("-") or line.startswith("*"):
                    section_content.append(line[1:].strip())
                else:
                    section_content.append(line)

        # Don't forget the last section
        if current_section and section_content:
            output._add_to_section(current_section, section_content)

        return output

    def _add_to_section(self, section: str, content: list[str]) -> None:
        """Add parsed content to the appropriate section."""
        if section == "findings":
            self.findings.extend(content)
        elif section == "learnings":
            self.learnings.extend(content)
        elif section == "observations":
            self.observations.extend(content)
        elif section == "relationships":
            self.relationships.extend(content)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "findings": self.findings,
            "learnings": self.learnings,
            "observations": self.observations,
            "relationships": self.relationships,
            "raw_response": self.raw_response,
            "model_used": self.model_used,
        }

    def __str__(self) -> str:
        """Human-readable string representation."""
        sections = []

        if self.findings:
            sections.append("Findings:\n" + "\n".join(f"  - {f}" for f in self.findings))
        if self.learnings:
            sections.append("Learnings:\n" + "\n".join(f"  - {l}" for l in self.learnings))
        if self.observations:
            sections.append("Observations:\n" + "\n".join(f"  - {o}" for o in self.observations))
        if self.relationships:
            sections.append(
                "Relationships:\n" + "\n".join(f"  - {r}" for r in self.relationships)
            )

        return "\n\n".join(sections) if sections else self.raw_response


def load_reasoner_prompt() -> str:
    """
    Load the reasoner system prompt from the prompts directory.

    Returns:
        The system prompt content, or a default prompt if file not found.
    """
    prompt_path = PROMPTS_DIR / "system_reasoner.md"
    try:
        return prompt_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("reasoner_prompt_not_found", path=str(prompt_path))
        return _get_default_reasoner_prompt()


def _get_default_reasoner_prompt() -> str:
    """Return the default reasoner prompt if file is missing."""
    return """You are a specialized Reasoning Agent for penetration testing.

Your role is to analyze the current situation and provide structured reasoning
about potential attack vectors, vulnerabilities, and exploitation strategies.

DO NOT execute any commands or make tool calls. Your purpose is purely analytical.

Based on previous steps, you should:

1. Analyze the available information systematically
2. Identify potential security weaknesses and attack vectors
3. Suggest logical next steps for exploitation
4. Consider potential defenses and how to bypass them
5. Provide clear, structured reasoning about your analysis

OUTPUT FORMAT:

Findings:
Learnings:
Observations:
Relationships between vectors:
"""


class ReasonerAgent:
    """
    Dedicated reasoning agent for penetration testing analysis.

    This agent provides in-depth reasoning and analysis without making tool calls.
    It helps the main agent by offering structured thinking about pentesting
    strategies, attack vectors, and exploitation approaches.

    Supports both OpenAI reasoning models (o1, o3-mini) with reasoning_effort
    and Claude models.

    Example:
        ```python
        from inferno.agents.reasoner import ReasonerAgent

        # Create with default model (o3-mini)
        reasoner = ReasonerAgent()

        # Or specify model
        reasoner = ReasonerAgent(model="claude-opus-4-5-20251101")

        # Analyze a situation
        output = await reasoner.analyze(
            context="Found open port 22 (SSH) and 80 (HTTP)",
            question="What attack vectors should we explore?"
        )

        print(output.findings)
        print(output.observations)
        ```
    """

    # Models that support reasoning_effort parameter
    REASONING_MODELS = ("o1", "o3", "o1-mini", "o3-mini")

    def __init__(
        self,
        name: str = "Reasoner",
        model: str | None = None,
        instructions: str | Callable[[], str] | None = None,
        reasoning_effort: str = "high",
    ) -> None:
        """
        Initialize the reasoner agent.

        Args:
            name: Display name for the agent.
            model: Model to use. If None, uses INFERNO_REASONER_MODEL env var
                   or falls back to "o3-mini".
            instructions: Custom system instructions. If None, loads from
                          prompts/system_reasoner.md.
            reasoning_effort: Reasoning effort for o1/o3 models.
                              One of "low", "medium", "high".
        """
        self.name = name
        self.model = model or os.getenv("INFERNO_REASONER_MODEL", "o3-mini")
        self.reasoning_effort = reasoning_effort

        # Load instructions
        if instructions is None:
            self._instructions = load_reasoner_prompt()
        elif callable(instructions):
            self._instructions = instructions()
        else:
            self._instructions = instructions

        # Determine if this is a reasoning model
        self._is_reasoning_model = any(
            rm in self.model for rm in self.REASONING_MODELS
        )

        logger.info(
            "reasoner_agent_initialized",
            name=self.name,
            model=self.model,
            is_reasoning_model=self._is_reasoning_model,
            reasoning_effort=self.reasoning_effort if self._is_reasoning_model else "N/A",
        )

    @property
    def instructions(self) -> str:
        """Get the system instructions."""
        return self._instructions

    def _is_claude_model(self) -> bool:
        """Check if the configured model is a Claude model."""
        return "claude" in self.model.lower()

    def _is_openai_model(self) -> bool:
        """Check if the configured model is an OpenAI model."""
        return any(prefix in self.model.lower() for prefix in ["gpt", "o1", "o3"])

    async def analyze(
        self,
        context: str,
        question: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ReasonerOutput:
        """
        Analyze a security situation and provide structured reasoning.

        Args:
            context: The current context/situation to analyze (e.g., scan results,
                     discovered vulnerabilities, current progress).
            question: Optional specific question to answer about the context.
            history: Optional conversation history for context.

        Returns:
            ReasonerOutput with structured findings, learnings, and observations.

        Raises:
            RuntimeError: If no suitable client is available for the model.
        """
        # Build the user message
        user_content = f"## Context\n{context}"
        if question:
            user_content += f"\n\n## Question\n{question}"

        # Build messages
        messages: list[dict[str, Any]] = []

        # Add history if provided
        if history:
            messages.extend(history)

        # Add current message
        messages.append({"role": "user", "content": user_content})

        # Route to appropriate backend
        if self._is_claude_model():
            response = await self._analyze_with_claude(messages)
        elif self._is_openai_model():
            response = await self._analyze_with_openai(messages)
        else:
            # Default to Claude for unknown models
            logger.warning(
                "unknown_model_type",
                model=self.model,
                fallback="claude",
            )
            response = await self._analyze_with_claude(messages)

        return ReasonerOutput.parse_response(response, model=self.model)

    async def _analyze_with_claude(
        self,
        messages: list[dict[str, Any]],
    ) -> str:
        """
        Run analysis using Claude API.

        Args:
            messages: The conversation messages.

        Returns:
            The model's response text.
        """
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError(
                "anthropic package is required for Claude models. "
                "Install with: pip install anthropic"
            ) from e

        client = anthropic.AsyncAnthropic()

        # Convert messages format if needed
        api_messages = []
        for msg in messages:
            api_messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })

        logger.debug(
            "calling_claude_reasoner",
            model=self.model,
            message_count=len(api_messages),
        )

        response = await client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=self._instructions,
            messages=api_messages,
        )

        # Extract text from response
        text_content = ""
        for block in response.content:
            if hasattr(block, "text"):
                text_content += block.text

        return text_content

    async def _analyze_with_openai(
        self,
        messages: list[dict[str, Any]],
    ) -> str:
        """
        Run analysis using OpenAI API (for o1/o3 models).

        Args:
            messages: The conversation messages.

        Returns:
            The model's response text.
        """
        try:
            import openai
        except ImportError as e:
            raise RuntimeError(
                "openai package is required for OpenAI models. "
                "Install with: pip install openai"
            ) from e

        client = openai.AsyncOpenAI()

        # Build API messages with system prompt
        api_messages = [{"role": "system", "content": self._instructions}]
        for msg in messages:
            api_messages.append({
                "role": msg["role"],
                "content": msg["content"],
            })

        logger.debug(
            "calling_openai_reasoner",
            model=self.model,
            message_count=len(api_messages),
            reasoning_effort=self.reasoning_effort if self._is_reasoning_model else None,
        )

        # Build kwargs
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": api_messages,
        }

        # Add reasoning_effort for o1/o3 models
        if self._is_reasoning_model:
            kwargs["reasoning_effort"] = self.reasoning_effort

        response = await client.chat.completions.create(**kwargs)

        # Extract text from response
        return response.choices[0].message.content or ""

    def analyze_sync(
        self,
        context: str,
        question: str | None = None,
        history: list[dict[str, str]] | None = None,
    ) -> ReasonerOutput:
        """
        Synchronous wrapper for analyze().

        Args:
            context: The current context/situation to analyze.
            question: Optional specific question to answer.
            history: Optional conversation history.

        Returns:
            ReasonerOutput with structured analysis.
        """
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None:
            # We're in an async context, create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(
                    asyncio.run,
                    self.analyze(context, question, history)
                )
                return future.result()
        else:
            return asyncio.run(self.analyze(context, question, history))


def create_reasoner_agent(
    name: str = "Reasoner",
    model: str | None = None,
    instructions: str | Callable[[], str] | None = None,
    reasoning_effort: str = "high",
) -> ReasonerAgent:
    """
    Create a Reasoner Agent for autonomous pentesting.

    This agent provides in-depth reasoning and analysis without making tool calls.
    It helps the main agent by offering structured thinking about pentesting
    strategies and approaches.

    Args:
        name: The name of the reasoner agent.
        model: The model to use. If None, uses INFERNO_REASONER_MODEL env var
               or falls back to "o3-mini".
        instructions: Custom instructions for the reasoner agent.
                      If None, uses default reasoning instructions from
                      prompts/system_reasoner.md.
        reasoning_effort: Reasoning effort level for o1/o3 models.
                          One of "low", "medium", "high". Default is "high".

    Returns:
        A configured ReasonerAgent instance.

    Example:
        ```python
        # Default configuration (o3-mini with high reasoning)
        reasoner = create_reasoner_agent()

        # Use Claude instead
        reasoner = create_reasoner_agent(model="claude-opus-4-5-20251101")

        # Custom instructions
        reasoner = create_reasoner_agent(
            instructions="Focus on web application security..."
        )
        ```
    """
    return ReasonerAgent(
        name=name,
        model=model,
        instructions=instructions,
        reasoning_effort=reasoning_effort,
    )


# Module-level singleton for convenience
_reasoner_agent: ReasonerAgent | None = None


def get_reasoner_agent() -> ReasonerAgent:
    """
    Get the module-level reasoner agent singleton.

    Creates the agent on first call.

    Returns:
        The singleton ReasonerAgent instance.
    """
    global _reasoner_agent
    if _reasoner_agent is None:
        _reasoner_agent = create_reasoner_agent()
    return _reasoner_agent


def transfer_to_reasoner(
    context: str,
    question: str | None = None,
) -> ReasonerOutput:
    """
    Transfer analysis to the reasoner agent and get structured output.

    This is a convenience function for quick analysis without managing
    the agent instance directly.

    Args:
        context: The situation context to analyze.
        question: Optional specific question to answer.

    Returns:
        ReasonerOutput with findings, learnings, and observations.

    Example:
        ```python
        from inferno.agents.reasoner import transfer_to_reasoner

        output = transfer_to_reasoner(
            context="Nmap scan shows port 22 (SSH), 80 (HTTP), 3306 (MySQL)",
            question="What are the most promising attack vectors?"
        )

        for finding in output.findings:
            print(f"- {finding}")
        ```
    """
    agent = get_reasoner_agent()
    return agent.analyze_sync(context, question)
