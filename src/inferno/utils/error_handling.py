"""
Centralized error handling for Inferno tools.

This module provides decorators and utilities for consistent error handling
across all tools. This ensures:
- Consistent error message formatting
- Proper logging of all errors
- No silent failures
- Clean ToolResult returns on exceptions
"""

from __future__ import annotations

import asyncio
import functools
import traceback
from collections.abc import Callable
from typing import Any, TypeVar

import structlog

from inferno.tools.base import ToolResult

logger = structlog.get_logger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def handle_tool_error(
    tool_name: str | None = None,
    log_traceback: bool = False,
    include_args_in_log: bool = False,
) -> Callable[[F], F]:
    """
    Decorator for consistent error handling in tool execute methods.

    Wraps async tool execute methods to:
    - Catch all exceptions
    - Log errors consistently
    - Return proper ToolResult on failure
    - Never raise exceptions to caller

    Args:
        tool_name: Override tool name for logging. If None, extracts from class.
        log_traceback: Include full traceback in logs (useful for debugging).
        include_args_in_log: Include function arguments in error log.

    Usage:
        class MyTool(BaseTool):
            @handle_tool_error()
            async def execute(self, **kwargs):
                # Your code here - exceptions are handled automatically
                ...

        # With custom tool name:
        @handle_tool_error(tool_name="custom_scanner")
        async def execute(self, **kwargs):
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> ToolResult:
            # Determine tool name
            name = tool_name
            if name is None and args:
                # Try to get name from self (first arg for methods)
                self = args[0]
                if hasattr(self, "name"):
                    name = self.name
                elif hasattr(self, "tool_binary"):
                    name = self.tool_binary
                else:
                    name = self.__class__.__name__

            try:
                result = await func(*args, **kwargs)

                # Ensure we always return a ToolResult
                if not isinstance(result, ToolResult):
                    logger.warning(
                        f"{name}_invalid_return",
                        message="Tool did not return ToolResult",
                        return_type=type(result).__name__,
                    )
                    return ToolResult(
                        success=True,
                        output=str(result) if result else "",
                    )

                return result

            except asyncio.CancelledError:
                # Don't catch cancellation - let it propagate
                raise

            except TimeoutError as e:
                logger.warning(
                    f"{name}_timeout",
                    error=str(e),
                )
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Operation timed out: {e}",
                )

            except ConnectionError as e:
                logger.warning(
                    f"{name}_connection_error",
                    error=str(e),
                )
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Connection error: {e}",
                )

            except PermissionError as e:
                logger.warning(
                    f"{name}_permission_error",
                    error=str(e),
                )
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Permission denied: {e}",
                )

            except FileNotFoundError as e:
                logger.warning(
                    f"{name}_file_not_found",
                    error=str(e),
                )
                return ToolResult(
                    success=False,
                    output="",
                    error=f"File not found: {e}",
                )

            except ValueError as e:
                logger.warning(
                    f"{name}_value_error",
                    error=str(e),
                )
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Invalid value: {e}",
                )

            except Exception as e:
                # Log the error
                log_kwargs: dict[str, Any] = {
                    "error": str(e),
                    "error_type": type(e).__name__,
                }

                if include_args_in_log:
                    # Sanitize kwargs to avoid logging sensitive data
                    safe_kwargs = {
                        k: v for k, v in kwargs.items()
                        if k not in ("password", "secret", "token", "key", "auth", "credential")
                    }
                    log_kwargs["kwargs"] = safe_kwargs

                if log_traceback:
                    log_kwargs["traceback"] = traceback.format_exc()

                logger.error(f"{name}_error", **log_kwargs)

                return ToolResult(
                    success=False,
                    output="",
                    error=f"Tool execution failed: {e}",
                    metadata={"exception": type(e).__name__},
                )

        return wrapper  # type: ignore

    return decorator


def safe_execute(
    error_message: str = "Operation failed",
    default_return: Any = None,
    log_errors: bool = True,
) -> Callable[[F], F]:
    """
    Decorator for safely executing any async function.

    Unlike handle_tool_error, this is for general functions, not just tools.
    Returns a default value on error instead of ToolResult.

    Args:
        error_message: Message prefix for errors.
        default_return: Value to return on error.
        log_errors: Whether to log errors.

    Usage:
        @safe_execute(default_return=[])
        async def get_items():
            ...
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                if log_errors:
                    logger.error(
                        f"{func.__name__}_error",
                        error=str(e),
                        message=error_message,
                    )
                return default_return

        return wrapper  # type: ignore

    return decorator


class ToolError(Exception):
    """
    Custom exception for tool errors that should be handled specially.

    Use this to provide structured error information from within tools.
    """

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        recoverable: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.recoverable = recoverable
        self.metadata = metadata or {}

    def to_tool_result(self) -> ToolResult:
        """Convert to ToolResult."""
        return ToolResult(
            success=False,
            output="",
            error=self.message,
            metadata={
                "error_code": self.error_code,
                "recoverable": self.recoverable,
                **self.metadata,
            },
        )


def create_error_result(
    error: str | Exception,
    metadata: dict[str, Any] | None = None,
) -> ToolResult:
    """
    Create a standardized error ToolResult.

    Args:
        error: Error message or exception.
        metadata: Optional metadata to include.

    Returns:
        ToolResult with error set.
    """
    if isinstance(error, ToolError):
        result = error.to_tool_result()
        if metadata:
            result.metadata.update(metadata)
        return result

    error_msg = str(error)
    error_metadata = metadata or {}

    if isinstance(error, Exception):
        error_metadata["exception"] = type(error).__name__

    return ToolResult(
        success=False,
        output="",
        error=error_msg,
        metadata=error_metadata,
    )
