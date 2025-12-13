"""
Inferno Constants Module.

Centralizes all hardcoded values, magic numbers, and configuration defaults.
Import from here instead of hardcoding values throughout the codebase.
"""

from __future__ import annotations

# =============================================================================
# TIMEOUT CONSTANTS (in seconds)
# =============================================================================

class Timeouts:
    """Timeout values for various operations."""

    # Command execution timeouts
    FULL_SCAN = 1800        # 30 minutes - for comprehensive scans (nmap -A)
    SECURITY_TOOL = 600     # 10 minutes - for security tools (sqlmap, nikto)
    NETWORK_TOOL = 120      # 2 minutes - for network operations (curl, wget)
    QUICK_COMMAND = 30      # 30 seconds - for simple commands (ls, cat)

    # HTTP request timeouts
    HTTP_DEFAULT = 30       # Default HTTP request timeout
    HTTP_CONNECT = 10       # Connection timeout

    # Session timeouts
    SESSION_IDLE = 300      # 5 minutes - idle session timeout
    SESSION_CLEANUP = 2     # Seconds to wait for process cleanup

    # Docker operations
    DOCKER_SAVE = 10        # File save operations in Docker
    DOCKER_CHMOD = 5        # chmod operations


# =============================================================================
# SIZE LIMITS (in bytes/characters)
# =============================================================================

class SizeLimits:
    """Size limits for various data types."""

    # Output truncation
    MAX_OUTPUT_SIZE = 100_000           # 100KB - max tool output
    MAX_RESPONSE_SIZE = 500_000         # 500KB - max HTTP response body
    MAX_RESPONSE_SIZE_LARGE = 2_000_000 # 2MB - for large responses

    # Memory/storage
    MAX_MEMORY_ITEMS = 1000             # Max items in memory storage
    MAX_CACHE_SIZE = 10_000             # Max cache entries

    # Display
    TRUNCATION_PREVIEW = 50_000         # Truncate at this size with preview


# =============================================================================
# CONNECTION LIMITS
# =============================================================================

class ConnectionLimits:
    """Connection pool and rate limits."""

    # HTTP connection pool
    MAX_CONNECTIONS = 100
    MAX_KEEPALIVE_CONNECTIONS = 20

    # Rate limiting
    DEFAULT_RPS = 10                    # Requests per second
    BURST_MULTIPLIER = 1.15             # Allow 15% burst above limit


# =============================================================================
# AGENT CONFIGURATION
# =============================================================================

class AgentConfig:
    """Agent execution configuration."""

    # Token budgets
    THINKING_BUDGET = 32_000            # Max thinking tokens
    COMPACTION_THRESHOLD = 50           # Messages before compaction

    # Retry configuration
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0                   # seconds

    # Continuation
    MAX_CONTINUATIONS = 10
    CONTINUATION_THRESHOLD = 0.8        # Continue if >80% complete


# =============================================================================
# FILE PATHS (Docker container paths)
# =============================================================================

class DockerPaths:
    """Standard paths in the Kali Docker container."""

    WORDLISTS = "/wordlists/"
    WORKSPACE = "/workspace/"
    TOOLS = "/usr/share/"
    SECLISTS = "/usr/share/seclists/"


# =============================================================================
# MODEL NAMES
# =============================================================================

class Models:
    """Claude model identifiers."""

    # Available models
    OPUS = "claude-opus-4-5-20251101"
    SONNET = "claude-sonnet-4-20250514"
    HAIKU = "claude-haiku-4-5-20251001"

    # Default for different use cases - all default to Opus
    DEFAULT = OPUS
    FAST_RECON = OPUS
    DEEP_ANALYSIS = OPUS
    QUICK_TASKS = OPUS


# =============================================================================
# SECURITY PATTERNS
# =============================================================================

class SecurityPatterns:
    """Security-related patterns and lists."""

    # Commands that are dangerous with untrusted input
    DANGEROUS_WITH_HOMOGRAPHS = frozenset({
        'curl', 'wget', 'nc', 'bash', 'sh ', 'exec', 'eval',
        'python', 'perl', 'ruby', 'php', 'node'
    })

    # Commands that should be blocked entirely
    BLOCKED_COMMANDS = frozenset({
        'rm -rf /',
        'mkfs',
        'dd if=/dev/zero',
        ':(){:|:&};:',  # Fork bomb
    })


# =============================================================================
# QUALITY THRESHOLDS
# =============================================================================

class QualityThresholds:
    """Thresholds for quality checks and validation."""

    # Confidence scores
    HIGH_CONFIDENCE = 0.8
    MEDIUM_CONFIDENCE = 0.5
    LOW_CONFIDENCE = 0.3

    # Validation
    MIN_EVIDENCE_LENGTH = 50
    MIN_POC_LENGTH = 20


# Export all for convenience
__all__ = [
    "AgentConfig",
    "ConnectionLimits",
    "DockerPaths",
    "Models",
    "QualityThresholds",
    "SecurityPatterns",
    "SizeLimits",
    "Timeouts",
]
