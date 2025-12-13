"""
Logging configuration for Inferno CLI.

This module provides utilities to control log verbosity during CLI operations.
By default, it configures structlog to show cleaner output without debug noise.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Generator
from contextlib import contextmanager

import structlog

# Suppress huggingface/tokenizers parallelism warning
# This warning appears when tokenizers is used before forking (e.g., in memory tools)
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

# Store original processors for restoration
_original_processors: list | None = None
_quiet_mode: bool = False


def configure_cli_logging(verbose: bool = False) -> None:
    """
    Configure logging for CLI usage.

    Args:
        verbose: If True, show all debug/info logs. If False, show only warnings/errors.
    """
    global _quiet_mode
    _quiet_mode = not verbose

    # Set minimum log level based on verbosity
    log_level = logging.DEBUG if verbose else logging.WARNING

    # Configure stdlib logging
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        stream=sys.stderr,
    )

    # Configure specific loggers
    for logger_name in [
        "inferno",
        "inferno.agent",
        "inferno.tools",
        "inferno.core",
        "inferno.swarm",
        "inferno.observability",
        "inferno.quality",
    ]:
        logging.getLogger(logger_name).setLevel(log_level)

    # Silence noisy third-party loggers
    for logger_name in [
        "httpx",
        "httpcore",
        "anthropic",
        "urllib3",
        "asyncio",
        "huggingface",
        "sentence_transformers",
        "tokenizers",
    ]:
        logging.getLogger(logger_name).setLevel(logging.ERROR)

    # Configure structlog
    if verbose:
        # Verbose mode - show everything with nice formatting
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.UnicodeDecoder(),
                structlog.dev.ConsoleRenderer(colors=True),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        # Quiet mode - minimal output
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.processors.UnicodeDecoder(),
                _quiet_renderer,
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )


def _quiet_renderer(
    logger: logging.Logger,
    method_name: str,
    event_dict: dict,
) -> str:
    """
    Quiet renderer that only shows errors and warnings.

    Filters out info/debug messages entirely.
    """
    level = event_dict.get("level", "info")
    if level in ("debug", "info"):
        return ""  # Suppress

    # For warnings/errors, show a clean message
    event = event_dict.get("event", "")
    return f"[{level.upper()}] {event}"


@contextmanager
def quiet_logging() -> Generator[None, None, None]:
    """
    Context manager for temporarily enabling quiet logging.

    Usage:
        with quiet_logging():
            # Run noisy operations
            pass
    """
    original_level = logging.root.level
    configure_cli_logging(verbose=False)
    try:
        yield
    finally:
        logging.root.setLevel(original_level)


@contextmanager
def verbose_logging() -> Generator[None, None, None]:
    """
    Context manager for temporarily enabling verbose logging.

    Usage:
        with verbose_logging():
            # Run operations with full logging
            pass
    """
    original_level = logging.root.level
    configure_cli_logging(verbose=True)
    try:
        yield
    finally:
        logging.root.setLevel(original_level)


def is_quiet_mode() -> bool:
    """Check if quiet mode is enabled."""
    return _quiet_mode


class QuietLogFilter(logging.Filter):
    """Filter that suppresses info/debug logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


def silence_logger(logger_name: str) -> None:
    """Silence a specific logger."""
    logging.getLogger(logger_name).setLevel(logging.ERROR)


def enable_logger(logger_name: str, level: int = logging.DEBUG) -> None:
    """Enable a specific logger."""
    logging.getLogger(logger_name).setLevel(level)
