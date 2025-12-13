"""
Function Tool Decorator - CAI-inspired auto-schema generation.

This module provides a decorator that converts regular Python functions
into Inferno tools with automatic JSON schema generation from type hints.

Usage:
    @function_tool(category=ToolCategory.EXPLOITATION)
    async def sql_inject(url: str, payload: str = "' OR '1'='1") -> ToolResult:
        '''Perform SQL injection testing.'''
        ...
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Type,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

import structlog

from inferno.tools.base import BaseTool, ToolCategory, ToolExample, ToolResult

logger = structlog.get_logger(__name__)

# Type mapping from Python types to JSON Schema types
PYTHON_TO_JSON_TYPE: Dict[Type, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
    type(None): "null",
}


def _get_json_type(python_type: Type) -> Dict[str, Any]:
    """Convert Python type hint to JSON Schema type definition."""
    # Handle None type
    if python_type is type(None):
        return {"type": "null"}

    # Handle basic types
    if python_type in PYTHON_TO_JSON_TYPE:
        return {"type": PYTHON_TO_JSON_TYPE[python_type]}

    # Handle Optional types (Union[X, None])
    origin = get_origin(python_type)
    args = get_args(python_type)

    if origin is Union:
        # Filter out NoneType for Optional handling
        non_none_args = [a for a in args if a is not type(None)]
        if len(non_none_args) == 1:
            # This is Optional[X]
            return _get_json_type(non_none_args[0])
        else:
            # Union of multiple types
            return {"oneOf": [_get_json_type(a) for a in non_none_args]}

    # Handle List types
    if origin is list or origin is List:
        if args:
            return {"type": "array", "items": _get_json_type(args[0])}
        return {"type": "array"}

    # Handle Dict types
    if origin is dict or origin is Dict:
        return {"type": "object"}

    # Default to string for unknown types
    return {"type": "string"}


def _extract_docstring_parts(docstring: str) -> tuple[str, Dict[str, str]]:
    """
    Extract description and parameter descriptions from docstring.

    Returns:
        Tuple of (main_description, {param_name: param_description})
    """
    if not docstring:
        return "", {}

    lines = docstring.strip().split("\n")
    description_lines = []
    param_descriptions = {}

    in_params = False
    current_param = None

    for line in lines:
        stripped = line.strip()

        # Check for Args/Parameters section
        if stripped.lower() in ("args:", "arguments:", "parameters:", "params:"):
            in_params = True
            continue

        # Check for Returns section (end of params)
        if stripped.lower().startswith(("returns:", "return:", "raises:", "example:")):
            in_params = False
            current_param = None
            continue

        if in_params:
            # Check for parameter definition (name: description or name (type): description)
            if ":" in stripped and not stripped.startswith(" "):
                parts = stripped.split(":", 1)
                param_name = parts[0].strip()
                # Remove type hint from param name if present
                if "(" in param_name:
                    param_name = param_name.split("(")[0].strip()
                param_descriptions[param_name] = parts[1].strip() if len(parts) > 1 else ""
                current_param = param_name
            elif current_param and stripped:
                # Continuation of previous param description
                param_descriptions[current_param] += " " + stripped
        else:
            if stripped:
                description_lines.append(stripped)

    return " ".join(description_lines), param_descriptions


def _generate_schema_from_function(
    func: Callable,
    param_descriptions: Dict[str, str],
) -> Dict[str, Any]:
    """Generate JSON Schema from function signature and type hints."""
    sig = inspect.signature(func)
    hints = get_type_hints(func) if hasattr(func, "__annotations__") else {}

    schema = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    for name, param in sig.parameters.items():
        # Skip self/cls parameters
        if name in ("self", "cls"):
            continue

        # Get type hint or default to string
        type_hint = hints.get(name, str)
        prop = _get_json_type(type_hint)

        # Add description from docstring
        if name in param_descriptions:
            prop["description"] = param_descriptions[name]

        # Handle default values
        if param.default is not inspect.Parameter.empty:
            if param.default is not None:
                prop["default"] = param.default
        else:
            # No default means required
            schema["required"].append(name)

        schema["properties"][name] = prop

    # Remove empty required list
    if not schema["required"]:
        del schema["required"]

    return schema


@dataclass
class FunctionToolConfig:
    """Configuration for function-based tools."""
    category: ToolCategory = ToolCategory.UTILITY
    defer_loading: bool = True
    examples: List[ToolExample] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    requires_auth: bool = False
    timeout: Optional[float] = None


class FunctionTool(BaseTool):
    """
    Tool implementation that wraps a function.

    Created by the @function_tool decorator.
    """

    def __init__(
        self,
        func: Callable,
        config: FunctionToolConfig,
        name: Optional[str] = None,
        description: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
    ):
        self._func = func
        self._config = config
        self._name = name or func.__name__
        self._description = description or ""
        self._schema = schema or {}
        self._is_async = asyncio.iscoroutinefunction(func)

        logger.debug(
            "function_tool_created",
            name=self._name,
            is_async=self._is_async,
            category=config.category.value,
        )

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def category(self) -> ToolCategory:
        return self._config.category

    @property
    def input_schema(self) -> Dict[str, Any]:
        return self._schema

    @property
    def examples(self) -> List[ToolExample]:
        return self._config.examples

    @property
    def defer_loading(self) -> bool:
        return self._config.defer_loading

    async def execute(self, **kwargs: Any) -> ToolResult:
        """Execute the wrapped function."""
        try:
            # Apply timeout if configured
            if self._config.timeout:
                if self._is_async:
                    result = await asyncio.wait_for(
                        self._func(**kwargs),
                        timeout=self._config.timeout,
                    )
                else:
                    # Run sync function in executor with timeout
                    loop = asyncio.get_event_loop()
                    result = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: self._func(**kwargs)),
                        timeout=self._config.timeout,
                    )
            else:
                if self._is_async:
                    result = await self._func(**kwargs)
                else:
                    # Run sync function in executor
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, lambda: self._func(**kwargs))

            # If result is already a ToolResult, return it
            if isinstance(result, ToolResult):
                return result

            # Otherwise, wrap in ToolResult
            return ToolResult(
                success=True,
                output=str(result) if result is not None else "",
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                output="",
                error=f"Tool execution timed out after {self._config.timeout}s",
            )
        except Exception as e:
            logger.error(
                "function_tool_error",
                tool=self._name,
                error=str(e),
                exc_info=True,
            )
            return ToolResult(
                success=False,
                output="",
                error=str(e),
            )


def function_tool(
    category: ToolCategory = ToolCategory.UTILITY,
    defer_loading: bool = True,
    examples: Optional[List[ToolExample]] = None,
    tags: Optional[List[str]] = None,
    requires_auth: bool = False,
    timeout: Optional[float] = None,
    name: Optional[str] = None,
    description: Optional[str] = None,
) -> Callable[[Callable], FunctionTool]:
    """
    Decorator to create a tool from a function with automatic schema generation.

    The decorator inspects the function's type hints and docstring to generate
    a JSON Schema for the tool's input parameters.

    Args:
        category: Tool category for organization.
        defer_loading: Whether to defer loading (for Tool Search).
        examples: List of usage examples.
        tags: Tags for categorization and search.
        requires_auth: Whether the tool requires authentication.
        timeout: Optional execution timeout in seconds.
        name: Override the tool name (defaults to function name).
        description: Override the description (defaults to docstring).

    Returns:
        A FunctionTool instance that can be registered with ToolRegistry.

    Example:
        @function_tool(category=ToolCategory.RECONNAISSANCE)
        async def port_scan(
            target: str,
            ports: str = "1-1000",
            timeout: int = 30,
        ) -> ToolResult:
            '''
            Scan ports on target host.

            Args:
                target: The target IP or hostname to scan.
                ports: Port range to scan (e.g., "1-1000" or "80,443,8080").
                timeout: Scan timeout in seconds.

            Returns:
                ToolResult with open ports found.
            '''
            ...
    """
    def decorator(func: Callable) -> FunctionTool:
        # Extract description and param docs from docstring
        docstring = inspect.getdoc(func) or ""
        main_description, param_descriptions = _extract_docstring_parts(docstring)

        # Generate schema
        schema = _generate_schema_from_function(func, param_descriptions)

        # Create config
        config = FunctionToolConfig(
            category=category,
            defer_loading=defer_loading,
            examples=examples or [],
            tags=tags or [],
            requires_auth=requires_auth,
            timeout=timeout,
        )

        # Create and return the tool
        tool = FunctionTool(
            func=func,
            config=config,
            name=name or func.__name__,
            description=description or main_description or f"Tool: {func.__name__}",
            schema=schema,
        )

        # Preserve function metadata
        tool.__doc__ = func.__doc__
        tool.__name__ = func.__name__
        tool.__module__ = func.__module__

        return tool

    return decorator


# Registry integration helper
_registered_function_tools: List[FunctionTool] = []


def register_function_tool(tool: FunctionTool) -> FunctionTool:
    """
    Register a function tool for later bulk registration with ToolRegistry.

    This is useful for collecting tools defined across multiple modules.
    """
    _registered_function_tools.append(tool)
    return tool


def get_registered_function_tools() -> List[FunctionTool]:
    """Get all registered function tools."""
    return _registered_function_tools.copy()


def auto_register_function_tools(registry: Any) -> int:
    """
    Auto-register all collected function tools with a registry.

    Returns:
        Number of tools registered.
    """
    count = 0
    for tool in _registered_function_tools:
        try:
            registry.register(tool)
            count += 1
            logger.debug("auto_registered_function_tool", name=tool.name)
        except Exception as e:
            logger.warning(
                "function_tool_registration_failed",
                name=tool.name,
                error=str(e),
            )
    return count


# Convenience decorator that also registers
def tool(
    category: ToolCategory = ToolCategory.UTILITY,
    **kwargs: Any,
) -> Callable[[Callable], FunctionTool]:
    """
    Convenience decorator that creates and registers a function tool.

    Combines @function_tool and register_function_tool().
    """
    def decorator(func: Callable) -> FunctionTool:
        ft = function_tool(category=category, **kwargs)(func)
        register_function_tool(ft)
        return ft
    return decorator
