"""
Tool registry for Inferno.

This module provides centralized tool registration, routing, and management
with support for deferred loading via Tool Search and built-in Anthropic tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC
from typing import Any

import structlog

from inferno.config.settings import (
    CODE_EXECUTION_VERSION,
    AnthropicToolType,
    ToolSearchVariant,
)
from inferno.tools.base import (
    BaseTool,
    ToolCallerType,
    ToolCategory,
    ToolResult,
)

logger = structlog.get_logger(__name__)


@dataclass
class AnthropicToolConfig:
    """Configuration for built-in Anthropic tools (server-side tools)."""

    # Web Search
    enable_web_search: bool = False
    web_search_max_uses: int = 5
    web_search_allowed_domains: list[str] = field(default_factory=list)
    web_search_blocked_domains: list[str] = field(default_factory=list)

    # Web Fetch
    enable_web_fetch: bool = False
    web_fetch_max_uses: int = 5
    web_fetch_allowed_domains: list[str] = field(default_factory=list)
    web_fetch_blocked_domains: list[str] = field(default_factory=list)
    web_fetch_max_content_tokens: int = 100000

    # Memory Tool
    enable_memory: bool = False

    # Built-in Bash (server-side sandboxed)
    enable_anthropic_bash: bool = False

    # Built-in Text Editor (server-side)
    enable_anthropic_text_editor: bool = False
    text_editor_max_characters: int | None = None

    # Computer Use
    enable_computer_use: bool = False
    display_width_px: int = 1024
    display_height_px: int = 768
    display_number: int = 1
    enable_zoom: bool = False  # Opus 4.5 only


class ToolNotFoundError(Exception):
    """Raised when a requested tool is not found."""

    pass


class ToolExecutionError(Exception):
    """Raised when tool execution fails."""

    pass


class ToolRegistry:
    """
    Central registry for all Inferno tools.

    Features:
    - Separates core (always loaded) and deferred tools
    - Supports Tool Search integration
    - Supports Programmatic Tool Calling
    - Supports built-in Anthropic tools (server-side)
    - Unknown tool routing to shell
    - Dynamic tool registration
    """

    def __init__(
        self,
        search_variant: ToolSearchVariant = ToolSearchVariant.BM25,
        enable_code_execution: bool = True,
        route_unknown_to_shell: bool = True,
        anthropic_tools: AnthropicToolConfig | None = None,
        model: str = "",
    ) -> None:
        """
        Initialize the tool registry.

        Args:
            search_variant: Tool search algorithm variant.
            enable_code_execution: Enable programmatic tool calling.
            route_unknown_to_shell: Route unknown tools to shell.
            anthropic_tools: Configuration for built-in Anthropic tools.
            model: Model name for version-specific features.
        """
        self._core_tools: dict[str, BaseTool] = {}
        self._deferred_tools: dict[str, BaseTool] = {}
        self._programmatic_tools: dict[str, BaseTool] = {}
        self._search_variant = search_variant
        self._enable_code_execution = enable_code_execution
        self._route_unknown_to_shell = route_unknown_to_shell
        self._anthropic_tools = anthropic_tools or AnthropicToolConfig()
        self._model = model
        self._shell_tool: BaseTool | None = None

        logger.info(
            "registry_initialized",
            search_variant=search_variant.value,
            code_execution=enable_code_execution,
            anthropic_tools_enabled=bool(anthropic_tools),
        )

    @property
    def core_tools(self) -> list[BaseTool]:
        """Get all core (non-deferred) tools."""
        return list(self._core_tools.values())

    @property
    def deferred_tools(self) -> list[BaseTool]:
        """Get all deferred tools."""
        return list(self._deferred_tools.values())

    @property
    def all_tools(self) -> list[BaseTool]:
        """Get all registered tools."""
        return self.core_tools + self.deferred_tools + list(self._programmatic_tools.values())

    def register(self, tool: BaseTool) -> None:
        """
        Register a tool with the registry.

        Args:
            tool: The tool to register.
        """
        # Check for shell tool (needed for unknown routing)
        if tool.name == "shell":
            self._shell_tool = tool

        # Route to appropriate storage based on properties
        if ToolCallerType.CODE_EXECUTION in tool.allowed_callers and \
           ToolCallerType.DIRECT not in tool.allowed_callers:
            # Programmatic-only tool
            self._programmatic_tools[tool.name] = tool
            logger.debug("tool_registered", name=tool.name, type="programmatic")
        elif tool.defer_loading:
            # Deferred tool (loaded via search)
            self._deferred_tools[tool.name] = tool
            logger.debug("tool_registered", name=tool.name, type="deferred")
        else:
            # Core tool (always loaded)
            self._core_tools[tool.name] = tool
            logger.debug("tool_registered", name=tool.name, type="core")

    def register_many(self, tools: list[BaseTool]) -> None:
        """Register multiple tools at once."""
        for tool in tools:
            self.register(tool)

    def get_tool(self, name: str) -> BaseTool | None:
        """
        Get a tool by name.

        Args:
            name: Tool name.

        Returns:
            The tool if found, None otherwise.
        """
        if name in self._core_tools:
            return self._core_tools[name]
        if name in self._deferred_tools:
            return self._deferred_tools[name]
        if name in self._programmatic_tools:
            return self._programmatic_tools[name]
        return None

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return self.get_tool(name) is not None

    async def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        caller: ToolCallerType = ToolCallerType.DIRECT,
    ) -> ToolResult:
        """
        Execute a tool by name.

        Args:
            tool_name: Name of the tool to execute.
            tool_input: Input parameters for the tool.
            caller: Who is calling this tool.

        Returns:
            ToolResult from execution.

        Raises:
            ToolNotFoundError: If tool not found and shell routing disabled.
            ToolExecutionError: If tool execution fails.
        """
        tool = self.get_tool(tool_name)

        # Route unknown tools to shell if enabled
        if tool is None:
            if self._route_unknown_to_shell and self._shell_tool:
                logger.info(
                    "routing_unknown_tool_to_shell",
                    tool_name=tool_name,
                    input=tool_input,
                )
                return await self._route_to_shell(tool_name, tool_input)
            else:
                raise ToolNotFoundError(f"Tool '{tool_name}' not found")

        # Verify caller is allowed
        if caller not in tool.allowed_callers:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool '{tool_name}' cannot be called from {caller.value}",
            )

        # Validate input
        is_valid, error = tool.validate_input(**tool_input)
        if not is_valid:
            return ToolResult(
                success=False,
                output="",
                error=f"Invalid input: {error}",
            )

        # Execute tool with timing
        import time
        from datetime import datetime

        start_time = time.perf_counter()
        started_at = datetime.now(UTC).isoformat()

        try:
            logger.debug("executing_tool", name=tool_name, input=tool_input)
            result = await tool.execute(**tool_input)

            # Handle dict returns from advanced tools (convert to ToolResult)
            if isinstance(result, dict):
                import json
                success = result.get("success", True)
                error = result.get("error")
                # Remove meta keys to get the actual output
                output_dict = {k: v for k, v in result.items() if k not in ("success", "error")}
                result = ToolResult(
                    success=success,
                    output=json.dumps(output_dict, indent=2, default=str),
                    error=error,
                )

            # Add timing information
            end_time = time.perf_counter()
            ended_at = datetime.now(UTC).isoformat()
            execution_time_ms = (end_time - start_time) * 1000

            result.with_timing(
                execution_time_ms=execution_time_ms,
                started_at=started_at,
                ended_at=ended_at,
            )

            logger.debug(
                "tool_execution_complete",
                name=tool_name,
                success=result.success,
                execution_time_ms=round(execution_time_ms, 2),
            )

            # Log slow tools as warnings
            if execution_time_ms > 30000:  # 30 seconds
                logger.warning(
                    "slow_tool_execution",
                    name=tool_name,
                    execution_time_ms=round(execution_time_ms, 2),
                )

            return result
        except Exception as e:
            logger.error(
                "tool_execution_failed",
                name=tool_name,
                error=str(e),
                exc_info=True,
            )
            raise ToolExecutionError(f"Tool '{tool_name}' failed: {e}") from e

    async def _route_to_shell(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
    ) -> ToolResult:
        """
        Route an unknown tool to shell execution.

        Attempts to reconstruct a shell command from the tool name and input.

        Args:
            tool_name: The requested tool name.
            tool_input: The tool input parameters.

        Returns:
            ToolResult from shell execution.
        """
        if self._shell_tool is None:
            return ToolResult(
                success=False,
                output="",
                error="Shell tool not available for routing",
            )

        # Build command from tool name and common parameters
        command_parts = [tool_name]

        # Handle common parameter patterns
        if "command" in tool_input:
            # If there's an explicit command, use it
            command = tool_input["command"]
        else:
            # Try to construct command from parameters
            for key, value in tool_input.items():
                if key in ("target", "host", "url") or key in ("flags", "options", "args"):
                    command_parts.append(str(value))
                elif key in ("port",):
                    command_parts.extend(["-p", str(value)])
                elif isinstance(value, bool) and value:
                    command_parts.append(f"--{key}")
                elif isinstance(value, str) and value:
                    command_parts.extend([f"--{key}", value])

            command = " ".join(command_parts)

        logger.info("shell_routing_command", command=command)

        return await self._shell_tool.execute(command=command)

    def build_tool_list(self) -> list[dict[str, Any]]:
        """
        Build the complete tool list for Claude API.

        Includes:
        - Tool Search Tool (first)
        - Code Execution Tool (if enabled)
        - Built-in Anthropic tools (web_search, web_fetch, memory, etc.)
        - Core tools (non-deferred)
        - Deferred tools (with defer_loading: true)

        Returns:
            List of tool definitions for the API.
        """
        tools: list[dict[str, Any]] = []

        # Tool Search (always first)
        tools.append({
            "type": self._search_variant.value,
            "name": "tool_search",
        })

        # Code Execution (if enabled)
        if self._enable_code_execution:
            tools.append({
                "type": CODE_EXECUTION_VERSION,
                "name": "code_execution",
            })

        # Built-in Anthropic tools (server-side)
        tools.extend(self._build_anthropic_tools())

        # Core tools (non-deferred)
        for tool in self._core_tools.values():
            tools.append(tool.to_dict())

        # Deferred tools
        for tool in self._deferred_tools.values():
            tool_dict = tool.to_dict()
            tool_dict["defer_loading"] = True
            tools.append(tool_dict)

        # Programmatic-only tools
        for tool in self._programmatic_tools.values():
            tools.append(tool.to_dict())

        logger.debug(
            "tool_list_built",
            total=len(tools),
            core=len(self._core_tools),
            deferred=len(self._deferred_tools),
            programmatic=len(self._programmatic_tools),
        )

        return tools

    def _build_anthropic_tools(self) -> list[dict[str, Any]]:
        """
        Build definitions for built-in Anthropic tools.

        These are server-side tools handled by Anthropic's API.

        Returns:
            List of Anthropic tool definitions.
        """
        tools: list[dict[str, Any]] = []
        config = self._anthropic_tools

        # Web Search Tool
        if config.enable_web_search:
            web_search: dict[str, Any] = {
                "type": AnthropicToolType.WEB_SEARCH.value,
                "name": "web_search",
            }
            if config.web_search_max_uses:
                web_search["max_uses"] = config.web_search_max_uses
            if config.web_search_allowed_domains:
                web_search["allowed_domains"] = config.web_search_allowed_domains
            if config.web_search_blocked_domains:
                web_search["blocked_domains"] = config.web_search_blocked_domains
            tools.append(web_search)
            logger.debug("anthropic_tool_added", tool="web_search")

        # Web Fetch Tool
        if config.enable_web_fetch:
            web_fetch: dict[str, Any] = {
                "type": AnthropicToolType.WEB_FETCH.value,
                "name": "web_fetch",
            }
            if config.web_fetch_max_uses:
                web_fetch["max_uses"] = config.web_fetch_max_uses
            if config.web_fetch_allowed_domains:
                web_fetch["allowed_domains"] = config.web_fetch_allowed_domains
            if config.web_fetch_blocked_domains:
                web_fetch["blocked_domains"] = config.web_fetch_blocked_domains
            if config.web_fetch_max_content_tokens:
                web_fetch["max_content_tokens"] = config.web_fetch_max_content_tokens
            tools.append(web_fetch)
            logger.debug("anthropic_tool_added", tool="web_fetch")

        # Memory Tool
        if config.enable_memory:
            tools.append({
                "type": AnthropicToolType.MEMORY.value,
                "name": "memory",
            })
            logger.debug("anthropic_tool_added", tool="memory")

        # Built-in Bash Tool (server-side sandboxed)
        if config.enable_anthropic_bash:
            tools.append({
                "type": AnthropicToolType.BASH.value,
                "name": "bash",
            })
            logger.debug("anthropic_tool_added", tool="bash")

        # Built-in Text Editor (server-side)
        if config.enable_anthropic_text_editor:
            text_editor: dict[str, Any] = {
                "type": AnthropicToolType.TEXT_EDITOR.value,
                "name": "str_replace_based_edit_tool",
            }
            if config.text_editor_max_characters:
                text_editor["max_characters"] = config.text_editor_max_characters
            tools.append(text_editor)
            logger.debug("anthropic_tool_added", tool="text_editor")

        # Computer Use Tool
        if config.enable_computer_use:
            # Use Opus-specific version for Opus 4.5 with zoom support
            is_opus_45 = "opus-4-5" in self._model or "opus-4.5" in self._model
            computer: dict[str, Any] = {
                "type": (
                    AnthropicToolType.COMPUTER_USE_OPUS.value
                    if is_opus_45
                    else AnthropicToolType.COMPUTER_USE.value
                ),
                "name": "computer",
                "display_width_px": config.display_width_px,
                "display_height_px": config.display_height_px,
            }
            if config.display_number != 1:
                computer["display_number"] = config.display_number
            if config.enable_zoom and is_opus_45:
                computer["enable_zoom"] = True
            tools.append(computer)
            logger.debug("anthropic_tool_added", tool="computer")

        return tools

    def get_tools_by_category(self, category: ToolCategory) -> list[BaseTool]:
        """Get all tools in a specific category."""
        return [t for t in self.all_tools if t.category == category]

    def get_tool_names(self) -> list[str]:
        """Get names of all registered tools."""
        return [t.name for t in self.all_tools]

    def get_stats(self) -> dict[str, int]:
        """Get registry statistics."""
        return {
            "total": len(self.all_tools),
            "core": len(self._core_tools),
            "deferred": len(self._deferred_tools),
            "programmatic": len(self._programmatic_tools),
        }

    def clear(self) -> None:
        """Clear all registered tools."""
        self._core_tools.clear()
        self._deferred_tools.clear()
        self._programmatic_tools.clear()
        self._shell_tool = None
        logger.debug("registry_cleared")


# Global registry instance
_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def register_tool(tool: BaseTool) -> None:
    """Register a tool with the global registry."""
    get_registry().register(tool)


def get_tool(name: str) -> BaseTool | None:
    """Get a tool from the global registry."""
    return get_registry().get_tool(name)


async def execute_tool(
    tool_name: str,
    tool_input: dict[str, Any],
    caller: ToolCallerType = ToolCallerType.DIRECT,
) -> ToolResult:
    """Execute a tool from the global registry."""
    return await get_registry().execute(tool_name, tool_input, caller)
