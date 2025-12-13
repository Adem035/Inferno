"""
Inferno Tools Package - Simplified Architecture.

Core Philosophy: ONE unified command tool instead of 81 specialized tools.
Let the LLM decide what commands to run - it knows pentest tools.

Tools:
- execute_command: Run any command (nmap, sqlmap, curl, etc.)
- http_request: HTTP requests with advanced features
- memory: Persistent memory storage
- think: Structured reasoning

That's it. Simple.
"""

from inferno.tools.base import (
    BaseTool,
    CoreTool,
    HybridTool,
    ProgrammaticTool,
    SecurityTool,
    StopSignal,
    ToolCallerType,
    ToolCategory,
    ToolDefinition,
    ToolExample,
    ToolResult,
)
from inferno.tools.decorator import (
    FunctionTool,
    FunctionToolConfig,
    auto_register_function_tools,
    function_tool,
    get_registered_function_tools,
    register_function_tool,
    tool,
)

# Core tools
from inferno.tools.execute_command import (
    execute_code,  # Python/script execution
    execute_command,
    generic_linux_command,  # Docker-based execution
)
from inferno.tools.http import HTTPTool
from inferno.tools.memory import MemoryTool, MemoryToolWithFallback
from inferno.tools.registry import (
    AnthropicToolConfig,
    ToolExecutionError,
    ToolNotFoundError,
    ToolRegistry,
    execute_tool,
    get_registry,
    get_tool,
    register_tool,
)

# Shell session management
from inferno.tools.shell_session import (
    SessionEnvironment,
    SessionInfo,
    ShellSession,
    create_shell_session,
    format_sessions_table,
    get_session,
    get_session_output,
    list_shell_sessions,
    terminate_all_sessions,
    terminate_session,
)
from inferno.tools.think import ThinkTool

__all__ = [
    # Base classes
    "BaseTool",
    "CoreTool",
    "HybridTool",
    "ProgrammaticTool",
    "SecurityTool",
    "StopSignal",
    # Data classes
    "ToolCallerType",
    "ToolCategory",
    "ToolDefinition",
    "ToolExample",
    "ToolResult",
    # Decorator
    "FunctionTool",
    "FunctionToolConfig",
    "function_tool",
    "tool",
    "register_function_tool",
    "get_registered_function_tools",
    "auto_register_function_tools",
    # Registry
    "AnthropicToolConfig",
    "ToolRegistry",
    "ToolNotFoundError",
    "ToolExecutionError",
    "get_registry",
    "register_tool",
    "get_tool",
    "execute_tool",
    # Core tools
    "execute_command",        # Local/hybrid execution
    "generic_linux_command",  # Docker (Kali) execution - USE FOR PENTEST TOOLS
    "execute_code",           # Python/script execution
    "HTTPTool",               # HTTP requests
    "MemoryTool",             # Memory storage
    "MemoryToolWithFallback",
    "ThinkTool",              # Structured thinking
    # Shell session management
    "ShellSession",
    "SessionEnvironment",
    "SessionInfo",
    "create_shell_session",
    "list_shell_sessions",
    "get_session_output",
    "terminate_session",
    "terminate_all_sessions",
    "get_session",
    "format_sessions_table",
]


def get_core_tools(use_docker: bool = True, target: str | None = None) -> list:
    """
    Get all core tools that should always be loaded.

    Args:
        use_docker: If True, include Docker-based generic_linux_command
                   for pentest tools. Default True for pentesting.
        target: Optional target URL/IP for memory scoping.

    Returns:
        List of core tool instances.
    """
    # Create memory tool with target if provided
    memory_tool = MemoryToolWithFallback()
    if target:
        memory_tool.set_target(target)

    tools = [
        execute_command,  # Local/hybrid execution
        HTTPTool(),
        memory_tool,
        ThinkTool(),
    ]

    if use_docker:
        # Add Docker-based tool for pentest commands
        # This runs in Kali container with all tools installed
        tools.append(generic_linux_command)

    return tools
