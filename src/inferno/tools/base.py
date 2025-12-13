"""
Base tool interface for Inferno.

This module provides the abstract base class and types for all tools
in the Inferno pentesting agent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


class ToolCategory(str, Enum):
    """Categories of tools available in Inferno."""

    CORE = "core"  # Always loaded: shell, http, memory, stop, editor
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    UTILITY = "utility"
    INTELLIGENCE = "intelligence"  # CVE/vulnerability intelligence tools (NVD, etc.)


class ToolCallerType(str, Enum):
    """Types of callers that can invoke a tool."""

    DIRECT = "direct"  # Called directly by Claude
    CODE_EXECUTION = "code_execution_20250825"  # Called from sandbox


@dataclass
class ToolExample:
    """Example usage of a tool for improved accuracy."""

    description: str
    input: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API."""
        return {
            "description": self.description,
            "input": self.input,
        }


@dataclass
class ToolResult:
    """Result from a tool execution."""

    success: bool
    output: str
    error: str | None = None
    artifacts: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # Execution metrics
    execution_time_ms: float | None = None
    started_at: str | None = None
    ended_at: str | None = None

    def to_content(self) -> str:
        """Convert result to content string for Claude."""
        if self.success:
            return self._sanitize_output(self.output)
        else:
            error_msg = f"Error: {self.error}"
            if self.output:
                return f"{error_msg}\n\nOutput:\n{self._sanitize_output(self.output)}"
            return error_msg

    @staticmethod
    def _sanitize_output(text: str) -> str:
        """
        Sanitize tool output to prevent parsing issues.

        Some tools (like hydra) output text with square bracket tags like [OPT]
        which can be misinterpreted as BBCode/XML tags by parsers.
        This replaces [TAG] style markers with (TAG) to prevent parsing errors.
        """
        import re
        # Replace square bracket tags that look like BBCode (e.g., [OPT], [/OPT], [INFO])
        # with parentheses to prevent them being parsed as markup
        # Matches: [TAG], [/TAG], [22], [DATA], etc.
        text = re.sub(r'\[(/?)([A-Z0-9]{1,10})\]', r'(\1\2)', text)
        return text

    def with_timing(
        self,
        execution_time_ms: float,
        started_at: str,
        ended_at: str,
    ) -> "ToolResult":
        """Add timing information to the result."""
        self.execution_time_ms = execution_time_ms
        self.started_at = started_at
        self.ended_at = ended_at
        return self


@dataclass
class ToolDefinition:
    """Complete tool definition for the Claude API."""

    name: str
    description: str
    input_schema: dict[str, Any]
    category: ToolCategory = ToolCategory.UTILITY
    defer_loading: bool = False
    examples: list[ToolExample] = field(default_factory=list)
    allowed_callers: list[ToolCallerType] = field(
        default_factory=lambda: [ToolCallerType.DIRECT]
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for Claude API."""
        result: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

        if self.defer_loading:
            result["defer_loading"] = True

        if self.examples:
            result["examples"] = [ex.to_dict() for ex in self.examples]

        if self.allowed_callers != [ToolCallerType.DIRECT]:
            result["allowed_callers"] = [c.value for c in self.allowed_callers]

        return result


class BaseTool(ABC):
    """
    Abstract base class for all Inferno tools.

    All tools must implement:
    - name: Tool identifier
    - description: What the tool does
    - input_schema: JSON schema for inputs
    - execute: Tool execution logic
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique tool name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description for Claude."""
        ...

    @property
    @abstractmethod
    def input_schema(self) -> dict[str, Any]:
        """JSON schema for tool inputs."""
        ...

    @property
    def category(self) -> ToolCategory:
        """Tool category for organization."""
        return ToolCategory.UTILITY

    @property
    def defer_loading(self) -> bool:
        """Whether this tool should be deferred (loaded via search)."""
        return True

    @property
    def examples(self) -> list[ToolExample]:
        """Usage examples for improved accuracy."""
        return []

    @property
    def allowed_callers(self) -> list[ToolCallerType]:
        """Who can call this tool."""
        return [ToolCallerType.DIRECT]

    @abstractmethod
    async def execute(self, **kwargs: Any) -> ToolResult:
        """
        Execute the tool with given parameters.

        Args:
            **kwargs: Tool-specific parameters matching input_schema.

        Returns:
            ToolResult with execution output.
        """
        ...

    def get_definition(self) -> ToolDefinition:
        """Get the complete tool definition."""
        return ToolDefinition(
            name=self.name,
            description=self.description,
            input_schema=self.input_schema,
            category=self.category,
            defer_loading=self.defer_loading,
            examples=self.examples,
            allowed_callers=self.allowed_callers,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert tool to dictionary for API."""
        return self.get_definition().to_dict()

    def validate_input(self, **kwargs: Any) -> tuple[bool, str | None]:
        """
        Validate input against schema.

        Args:
            **kwargs: Input parameters to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        schema = self.input_schema
        required = schema.get("required", [])

        for field_name in required:
            if field_name not in kwargs:
                return False, f"Missing required field: {field_name}"

        properties = schema.get("properties", {})
        for field_name, value in kwargs.items():
            if field_name in properties:
                prop_schema = properties[field_name]
                prop_type = prop_schema.get("type")

                # Basic type validation
                if prop_type == "string" and not isinstance(value, str):
                    return False, f"Field {field_name} must be a string"
                elif prop_type == "integer" and not isinstance(value, int):
                    return False, f"Field {field_name} must be an integer"
                elif prop_type == "boolean" and not isinstance(value, bool):
                    return False, f"Field {field_name} must be a boolean"
                elif prop_type == "object" and not isinstance(value, dict):
                    return False, f"Field {field_name} must be an object"
                elif prop_type == "array" and not isinstance(value, list):
                    return False, f"Field {field_name} must be an array"

                # Enum validation
                if "enum" in prop_schema and value not in prop_schema["enum"]:
                    return False, f"Field {field_name} must be one of: {prop_schema['enum']}"

        return True, None


class CoreTool(BaseTool):
    """
    Base class for core tools that are always loaded.

    Core tools include: shell, http_request, memory, stop, editor
    These are never deferred and are always available.
    """

    @property
    def defer_loading(self) -> bool:
        """Core tools are never deferred."""
        return False

    @property
    def category(self) -> ToolCategory:
        """Core tools category."""
        return ToolCategory.CORE


class SecurityTool(BaseTool):
    """
    Base class for security-specific tools.

    Security tools are typically deferred and loaded on-demand
    via the Tool Search feature.
    """

    @property
    def defer_loading(self) -> bool:
        """Security tools are deferred by default."""
        return True


class ProgrammaticTool(BaseTool):
    """
    Base class for tools only callable from code execution.

    These tools are designed to be called from within the
    sandboxed Python environment during programmatic tool calling.
    """

    @property
    def allowed_callers(self) -> list[ToolCallerType]:
        """Only callable from code execution."""
        return [ToolCallerType.CODE_EXECUTION]


class HybridTool(BaseTool):
    """
    Base class for tools callable both directly and from code execution.

    These tools can be used in both contexts, useful for tools
    like memory storage that need to work in all scenarios.
    """

    @property
    def allowed_callers(self) -> list[ToolCallerType]:
        """Callable from both contexts."""
        return [ToolCallerType.DIRECT, ToolCallerType.CODE_EXECUTION]


class StopSignal(Exception):
    """
    Exception raised when the agent wants to stop execution.

    This is used by tools to signal that the assessment is complete
    or should be stopped for some reason.
    """

    def __init__(
        self,
        reason: str,
        objective_met: bool = False,
        findings_summary: str | None = None,
        confidence: int | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.objective_met = objective_met
        self.findings_summary = findings_summary
        self.confidence = confidence
