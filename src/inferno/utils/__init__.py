"""
Inferno Utilities Package.

This module exports shared utility functions for parsing,
validation, formatting, HTTP client, and error handling.
"""

from inferno.utils.error_handling import (
    ToolError,
    create_error_result,
    handle_tool_error,
    safe_execute,
)
from inferno.utils.formatting import (
    format_bytes,
    format_duration,
    format_finding,
    format_findings_table,
    format_json_pretty,
    format_markdown_table,
    format_port_list,
    format_progress_bar,
    format_timestamp,
    truncate_string,
)
from inferno.utils.http_client import (
    HTTPClientConfig,
    HTTPError,
    HTTPResponse,
    InfernoHTTPClient,
    close_global_client,
    get_http_client,
    http_client,
)
from inferno.utils.parsing import (
    GenericParser,
    GobusterParser,
    NmapParser,
    ParsedHost,
    ParsedPort,
    ParsedVulnerability,
    SQLMapParser,
)
from inferno.utils.validation import (
    ValidationError,
    sanitize_command,
    validate_file_path,
    validate_hostname,
    validate_ip,
    validate_ip_network,
    validate_json,
    validate_port,
    validate_port_range,
    validate_target,
    validate_url,
)

__all__ = [
    # HTTP Client
    "HTTPClientConfig",
    "HTTPResponse",
    "HTTPError",
    "InfernoHTTPClient",
    "get_http_client",
    "close_global_client",
    "http_client",
    # Error Handling
    "handle_tool_error",
    "safe_execute",
    "ToolError",
    "create_error_result",
    # Parsing
    "GenericParser",
    "GobusterParser",
    "NmapParser",
    "ParsedHost",
    "ParsedPort",
    "ParsedVulnerability",
    "SQLMapParser",
    # Validation
    "ValidationError",
    "sanitize_command",
    "validate_file_path",
    "validate_hostname",
    "validate_ip",
    "validate_ip_network",
    "validate_json",
    "validate_port",
    "validate_port_range",
    "validate_target",
    "validate_url",
    # Formatting
    "format_bytes",
    "format_duration",
    "format_finding",
    "format_findings_table",
    "format_json_pretty",
    "format_markdown_table",
    "format_port_list",
    "format_progress_bar",
    "format_timestamp",
    "truncate_string",
]
