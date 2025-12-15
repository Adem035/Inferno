"""
Inferno configuration settings using Pydantic.

This module provides type-safe configuration management with validation,
environment variable support, and nested configuration structures.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ModelProvider(str, Enum):
    """Supported Claude model providers."""

    ANTHROPIC = "anthropic"


class ModelTier(str, Enum):
    """Claude model tiers."""

    # Claude 4.5 models (latest)
    OPUS_4_5 = "claude-opus-4-5-20251101"
    SONNET_4_5 = "claude-sonnet-4-20250514"
    HAIKU_4_5 = "claude-haiku-4-5-20251001"

    # Claude 4 models
    OPUS_4 = "claude-opus-4-20250514"
    SONNET_4 = "claude-sonnet-4-20250514"


class ToolSearchVariant(str, Enum):
    """Tool search algorithm variants."""

    BM25 = "tool_search_tool_bm25_20251119"
    REGEX = "tool_search_tool_regex_20251119"


class AnthropicToolType(str, Enum):
    """Built-in Anthropic tool type identifiers."""

    # Tool Search
    TOOL_SEARCH_BM25 = "tool_search_tool_bm25_20251119"
    TOOL_SEARCH_REGEX = "tool_search_tool_regex_20251119"

    # Code Execution (sandboxed Python/JS environment)
    CODE_EXECUTION = "code_execution_20250825"

    # Computer Use
    COMPUTER_USE_OPUS = "computer_20251124"  # Opus 4.5 with zoom
    COMPUTER_USE = "computer_20250124"  # Claude 4/Sonnet 3.7

    # Text Editor
    TEXT_EDITOR = "text_editor_20250728"  # Claude 4.x
    TEXT_EDITOR_LEGACY = "text_editor_20250124"  # Sonnet 3.7

    # Bash Tool
    BASH = "bash_20250124"

    # Memory Tool
    MEMORY = "memory_20250818"

    # Web Tools
    WEB_SEARCH = "web_search_20250305"
    WEB_FETCH = "web_fetch_20250910"


class BetaFeature(str, Enum):
    """Beta feature headers for Anthropic API."""

    # Advanced Tool Use (Tool Search + Programmatic Calling)
    ADVANCED_TOOL_USE = "advanced-tool-use-2025-11-20"

    # Code Execution
    CODE_EXECUTION = "code-execution-2025-08-25"

    # Computer Use
    COMPUTER_USE_OPUS = "computer-use-2025-11-24"  # Opus 4.5
    COMPUTER_USE = "computer-use-2025-01-24"  # Claude 4/Sonnet 3.7

    # Memory/Context Management
    MEMORY = "context-management-2025-06-27"

    # Web Fetch
    WEB_FETCH = "web-fetch-2025-09-10"

    # Fine-Grained Tool Streaming
    FINE_GRAINED_STREAMING = "fine-grained-tool-streaming-2025-05-14"

    # Files API (for code execution file handling)
    FILES_API = "files-api-2025-04-14"


class ModelConfig(BaseModel):
    """Claude model configuration."""

    model_id: ModelTier = Field(
        default=ModelTier.SONNET_4_5,
        description="Claude model to use for the agent",
    )
    max_tokens: int = Field(
        default=4096,
        ge=1,
        le=200000,
        description="Maximum tokens in response",
    )
    temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Sampling temperature",
    )
    timeout: float = Field(
        default=420.0,
        ge=30.0,
        le=600.0,
        description="Request timeout in seconds",
    )
    max_retries: int = Field(
        default=10,
        ge=1,
        le=20,
        description="Maximum retry attempts for failed requests",
    )


class EmbeddingProvider(str, Enum):
    """Supported embedding providers."""

    # Free/Local options (no API key needed)
    SENTENCE_TRANSFORMERS = "sentence_transformers"  # Free, local
    OLLAMA = "ollama"  # Free, local

    # Cloud options (require API keys)
    OPENAI = "openai"
    VOYAGE = "voyage"  # Anthropic-recommended
    COHERE = "cohere"


# Default models for each embedding provider
EMBEDDING_DEFAULTS = {
    EmbeddingProvider.SENTENCE_TRANSFORMERS: {
        "model": "all-MiniLM-L6-v2",
        "dimension": 384,
    },
    EmbeddingProvider.OLLAMA: {
        "model": "nomic-embed-text",
        "dimension": 768,
    },
    EmbeddingProvider.OPENAI: {
        "model": "text-embedding-3-small",
        "dimension": 1536,
    },
    EmbeddingProvider.VOYAGE: {
        "model": "voyage-2",
        "dimension": 1024,
    },
    EmbeddingProvider.COHERE: {
        "model": "embed-english-v3.0",
        "dimension": 1024,
    },
}


class MemoryConfig(BaseModel):
    """Memory system configuration using Mem0 with Qdrant."""

    # Qdrant configuration
    qdrant_host: str = Field(
        default="localhost",
        description="Qdrant server hostname",
    )
    qdrant_port: int = Field(
        default=6333,
        ge=1,
        le=65535,
        description="Qdrant server port",
    )
    qdrant_api_key: SecretStr | None = Field(
        default=None,
        description="Qdrant API key for cloud deployments",
    )
    qdrant_collection: str = Field(
        default="inferno_memories",
        description="Qdrant collection name for memories",
    )

    # Embedding configuration
    embedding_provider: EmbeddingProvider = Field(
        default=EmbeddingProvider.SENTENCE_TRANSFORMERS,
        description="Embedding provider (sentence_transformers is free/local)",
    )
    embedding_model: str | None = Field(
        default=None,
        description="Embedding model (uses provider default if not specified)",
    )
    embedding_dimension: int | None = Field(
        default=None,
        description="Embedding dimension (uses provider default if not specified)",
    )

    # Ollama-specific settings
    ollama_host: str = Field(
        default="http://localhost:11434",
        description="Ollama server URL (for ollama provider)",
    )

    # Memory behavior
    use_mem0: bool = Field(
        default=True,
        description="Use Mem0 for memory (False uses simple in-memory storage)",
    )

    def get_embedding_model(self) -> str:
        """Get the embedding model for the configured provider."""
        if self.embedding_model:
            return self.embedding_model
        return EMBEDDING_DEFAULTS[self.embedding_provider]["model"]

    def get_embedding_dimension(self) -> int:
        """Get the embedding dimension for the configured provider."""
        if self.embedding_dimension:
            return self.embedding_dimension
        return EMBEDDING_DEFAULTS[self.embedding_provider]["dimension"]


class ToolConfig(BaseModel):
    """Tool system configuration."""

    search_variant: ToolSearchVariant = Field(
        default=ToolSearchVariant.BM25,
        description="Tool search algorithm variant",
    )
    enable_programmatic_calling: bool = Field(
        default=True,
        description="Enable programmatic tool calling via code execution",
    )
    enable_tool_examples: bool = Field(
        default=True,
        description="Include usage examples in tool definitions",
    )
    shell_timeout: int = Field(
        default=300,
        ge=10,
        le=3600,
        description="Default shell command timeout in seconds",
    )
    http_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Default HTTP request timeout in seconds",
    )


class ExecutionConfig(BaseModel):
    """Agent execution configuration."""

    max_steps: int = Field(
        default=500,
        ge=10,
        le=1000,
        description="Maximum execution steps before termination",
    )
    max_turns: int = Field(
        default=500,
        ge=10,
        le=2000,
        description="Maximum agent loop turns - high default lets token limit be real constraint",
    )
    max_continuations: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum auto-continuations when turns are exhausted",
    )
    max_total_tokens: int = Field(
        default=1_000_000,
        ge=100_000,
        le=10_000_000,
        description="Maximum total tokens before budget exhaustion",
    )
    checkpoint_intervals: list[int] = Field(
        default=[20, 40, 60, 80, 90],
        description="Step percentages for mandatory checkpoint evaluation (90% = segment boundary memory dump)",
    )
    stream: bool = Field(
        default=True,
        description="Enable streaming responses",
    )
    conversation_window_size: int = Field(
        default=50,
        ge=10,
        le=200,
        description="Sliding window size for conversation history",
    )

    # Extended Thinking Configuration
    # ENABLED BY DEFAULT - Critical for complex security reasoning
    thinking_enabled: bool = Field(
        default=True,
        description="Enable extended thinking mode for deeper reasoning on complex security tasks",
    )
    thinking_budget: int = Field(
        default=64000,
        ge=1024,
        le=100000,
        description="Maximum tokens for thinking budget (64k default for complex security analysis)",
    )
    thinking_only_output: bool = Field(
        default=False,
        description="When True, only show thinking blocks. When False, show both thinking and output.",
    )

    # Parallel Tool Execution Configuration
    # When Claude calls multiple tools in one turn, they can be executed concurrently
    parallel_tools: bool = Field(
        default=True,
        description="Enable parallel tool execution when Claude requests multiple tools in one turn",
    )
    max_parallel_tools: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum number of tools to execute in parallel per turn",
    )

    # Response handling
    max_response_size: int = Field(
        default=500_000,
        ge=10_000,
        le=10_000_000,
        description="Maximum HTTP response body size in bytes before truncation",
    )
    truncation_warning: bool = Field(
        default=True,
        description="Warn agent when responses are truncated",
    )

    @field_validator("checkpoint_intervals")
    @classmethod
    def validate_checkpoints(cls, v: list[int]) -> list[int]:
        """Validate checkpoint intervals are within valid range."""
        for interval in v:
            if not 0 < interval < 100:
                raise ValueError(f"Checkpoint interval {interval} must be between 0 and 100")
        return sorted(set(v))


class NetworkConfig(BaseModel):
    """Network and HTTP configuration."""

    default_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Default HTTP request timeout in seconds",
    )
    verify_ssl: bool = Field(
        default=True,
        description="Verify SSL certificates by default (disable for testing)",
    )
    requests_per_second: float = Field(
        default=2.0,
        ge=0.1,
        le=100.0,
        description="Default requests per second rate limit per domain",
    )
    rate_limit_mode: Literal["fixed", "adaptive", "aggressive", "stealth"] = Field(
        default="adaptive",
        description="Rate limiting strategy mode",
    )
    max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum retry attempts for failed requests",
    )
    user_agent_rotation: bool = Field(
        default=True,
        description="Rotate user agents for OpSec",
    )


class ErrorRecoveryConfig(BaseModel):
    """Error handling and recovery configuration."""

    max_tool_retries: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum retry attempts per tool before giving up",
    )
    error_threshold: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of errors before suppressing a tool",
    )
    enable_auto_recovery: bool = Field(
        default=True,
        description="Enable automatic error recovery strategies",
    )
    backoff_multiplier: float = Field(
        default=2.0,
        ge=1.0,
        le=5.0,
        description="Exponential backoff multiplier for retries",
    )
    max_backoff_seconds: float = Field(
        default=60.0,
        ge=5.0,
        le=300.0,
        description="Maximum backoff delay in seconds",
    )


class ObservabilityConfig(BaseModel):
    """Observability and tracing configuration."""

    enabled: bool = Field(
        default=True,
        description="Enable observability features",
    )
    langfuse_enabled: bool = Field(
        default=False,
        description="Enable Langfuse integration",
    )
    langfuse_host: str | None = Field(
        default=None,
        description="Langfuse server host",
    )
    langfuse_public_key: SecretStr | None = Field(
        default=None,
        description="Langfuse public key",
    )
    langfuse_secret_key: SecretStr | None = Field(
        default=None,
        description="Langfuse secret key",
    )
    trace_tool_calls: bool = Field(
        default=True,
        description="Include tool calls in traces",
    )
    trace_memory_ops: bool = Field(
        default=True,
        description="Include memory operations in traces",
    )


class OutputConfig(BaseModel):
    """Output and reporting configuration."""

    base_dir: Path = Field(
        default=Path.cwd() / "outputs",
        description="Base directory for all outputs (absolute path)",
    )

    @model_validator(mode="after")
    def resolve_base_dir(self) -> OutputConfig:
        """Ensure base_dir is an absolute path."""
        if not self.base_dir.is_absolute():
            # Resolve relative paths against current working directory
            object.__setattr__(self, "base_dir", Path.cwd() / self.base_dir)
        return self
    enable_unified_output: bool = Field(
        default=True,
        description="Use unified output directory structure",
    )
    report_format: Literal["markdown", "html", "json"] = Field(
        default="markdown",
        description="Default report output format",
    )
    save_artifacts: bool = Field(
        default=True,
        description="Save tool output artifacts",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        description="Logging level",
    )


class CredentialConfig(BaseModel):
    """API credential management configuration."""

    # Credential file path
    credentials_file: Path | None = Field(
        default=None,
        description="Path to JSON file with additional API credentials",
    )

    # Fallback behavior
    graceful_degradation: bool = Field(
        default=True,
        description="Enable graceful degradation when credentials unavailable",
    )
    warn_on_missing: bool = Field(
        default=True,
        description="Warn user when API credentials are missing",
    )
    auto_fallback: bool = Field(
        default=True,
        description="Automatically fallback to alternative services",
    )


class CacheConfig(BaseModel):
    """Response cache configuration."""

    enabled: bool = Field(
        default=True,
        description="Enable response caching",
    )
    max_size_mb: int = Field(
        default=100,
        ge=10,
        le=10000,
        description="Maximum cache size in megabytes",
    )
    default_ttl_seconds: int = Field(
        default=300,
        ge=10,
        le=86400,
        description="Default TTL for cached responses in seconds",
    )
    max_entries: int = Field(
        default=10000,
        ge=100,
        le=1000000,
        description="Maximum number of cache entries",
    )

    # Per-domain TTL overrides (in seconds)
    domain_ttls: dict[str, int] = Field(
        default_factory=lambda: {
            "api.shodan.io": 3600,  # 1 hour
            "crt.sh": 86400,  # 24 hours (rarely changes)
            "nvd.nist.gov": 3600,  # 1 hour
            "services.nvd.nist.gov": 3600,  # 1 hour
            "api.github.com": 900,  # 15 minutes
            "api.hunter.io": 1800,  # 30 minutes
            "*.virustotal.com": 7200,  # 2 hours
            "api.securitytrails.com": 3600,  # 1 hour
            "api.censys.io": 3600,  # 1 hour
            "*.archive.org": 86400,  # 24 hours (wayback machine)
        },
        description="Per-domain TTL overrides in seconds",
    )


class InfernoSettings(BaseSettings):
    """
    Main Inferno configuration.

    Settings are loaded from environment variables with the INFERNO_ prefix,
    or from a .env file in the current directory.

    Authentication options:
    - ANTHROPIC_API_KEY: Direct API key (pay per token)
    - OAuth: Use Claude subscription (run 'inferno auth login')

    Embedding options (for memory):
    - sentence_transformers: Free, local (default)
    - ollama: Free, local (requires Ollama running)
    - openai: Requires OPENAI_API_KEY
    - voyage: Requires VOYAGE_API_KEY (Anthropic-recommended)

    External API keys (optional but recommended):
    - SHODAN_API_KEY: Shodan Internet Intelligence
    - CENSYS_API_ID + CENSYS_API_SECRET: Censys Search
    - VIRUSTOTAL_API_KEY: VirusTotal File/URL Analysis
    - SECURITYTRAILS_API_KEY: SecurityTrails DNS Intelligence
    - GITHUB_TOKEN: GitHub API (5000 req/hr vs 60 req/hr)
    - NVD_API_KEY: NVD CVE lookups (50 req/s vs 5 req/30s)
    - HUNTER_API_KEY: Hunter Email Discovery
    - And many more (see credential_manager.py for full list)
    """

    model_config = SettingsConfigDict(
        env_prefix="INFERNO_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    # API Keys (optional if using OAuth)
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        description="Anthropic API key (optional if using OAuth)",
    )

    # External API Keys (loaded from environment by CredentialManager)
    # These are kept here for backwards compatibility
    nvd_api_key: SecretStr | None = Field(
        default=None,
        description="NVD API key for CVE lookups (get free at https://nvd.nist.gov/developers/request-an-api-key)",
    )

    # Embedding API keys (only needed for cloud embedding providers)
    openai_api_key: SecretStr | None = Field(
        default=None,
        description="OpenAI API key (for openai embedding provider)",
    )
    voyage_api_key: SecretStr | None = Field(
        default=None,
        description="Voyage AI API key (for voyage embedding provider)",
    )
    cohere_api_key: SecretStr | None = Field(
        default=None,
        description="Cohere API key (for cohere embedding provider)",
    )

    # Shodan API key (for passive reconnaissance)
    shodan_api_key: SecretStr | None = Field(
        default=None,
        description="Shodan API key for passive recon (get at https://shodan.io)",
    )

    # Censys API credentials
    censys_api_id: SecretStr | None = Field(
        default=None,
        description="Censys API ID (requires both ID and SECRET)",
    )
    censys_api_secret: SecretStr | None = Field(
        default=None,
        description="Censys API Secret (requires both ID and SECRET)",
    )

    # VirusTotal API key
    virustotal_api_key: SecretStr | None = Field(
        default=None,
        description="VirusTotal API key for file/URL analysis",
    )

    # SecurityTrails API key
    securitytrails_api_key: SecretStr | None = Field(
        default=None,
        description="SecurityTrails API key for DNS intelligence",
    )

    # GitHub token
    github_token: SecretStr | None = Field(
        default=None,
        description="GitHub API token for repository reconnaissance",
    )

    # Nested configurations
    model: ModelConfig = Field(default_factory=ModelConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    tools: ToolConfig = Field(default_factory=ToolConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    error_recovery: ErrorRecoveryConfig = Field(default_factory=ErrorRecoveryConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    credentials: CredentialConfig = Field(default_factory=CredentialConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)

    def get_api_key(self) -> str:
        """Get the Anthropic API key as a string."""
        return self.anthropic_api_key.get_secret_value()

    def get_openai_key(self) -> str | None:
        """Get the OpenAI API key as a string if configured."""
        if self.openai_api_key:
            return self.openai_api_key.get_secret_value()
        return None

    def get_nvd_key(self) -> str | None:
        """Get the NVD API key as a string if configured."""
        if self.nvd_api_key:
            return self.nvd_api_key.get_secret_value()
        return None

    def get_shodan_key(self) -> str | None:
        """Get the Shodan API key as a string if configured."""
        if self.shodan_api_key:
            return self.shodan_api_key.get_secret_value()
        return None

    @staticmethod
    def _sanitize_target_for_path(target: str) -> str:
        """Sanitize a target URL/hostname for use in filesystem paths.

        Converts URLs like 'https://example.com' to 'example.com'
        and handles special characters.
        """
        import re
        from urllib.parse import urlparse

        # Parse URL to extract hostname
        if "://" in target:
            parsed = urlparse(target)
            sanitized = parsed.netloc or parsed.path
        else:
            sanitized = target

        # Remove port if present
        sanitized = sanitized.split(":")[0]

        # Replace any remaining problematic characters
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', sanitized)

        # Remove leading/trailing dots and spaces
        sanitized = sanitized.strip(". ")

        return sanitized or "unknown_target"

    def get_output_dir(self, target: str, operation_id: str) -> Path:
        """Get the output directory for a specific operation."""
        sanitized_target = self._sanitize_target_for_path(target)
        if self.output.enable_unified_output:
            return self.output.base_dir / sanitized_target / operation_id
        return self.output.base_dir / operation_id

    def get_artifacts_dir(self, target: str, operation_id: str) -> Path:
        """Get the artifacts directory for a specific operation."""
        return self.get_output_dir(target, operation_id) / "artifacts"

    def get_memory_dir(self, target: str) -> Path:
        """Get the memory storage directory for a target."""
        sanitized_target = self._sanitize_target_for_path(target)
        return self.output.base_dir / sanitized_target / "memory"


# Beta headers for advanced tool features
# These are combined based on which features are enabled
BETA_HEADERS: list[str] = [
    BetaFeature.ADVANCED_TOOL_USE.value,  # Tool Search + Programmatic Calling
    BetaFeature.CODE_EXECUTION.value,  # Sandboxed code execution
]

# Additional beta headers that can be enabled
OPTIONAL_BETA_HEADERS: dict[str, str] = {
    "computer_use": BetaFeature.COMPUTER_USE.value,
    "computer_use_opus": BetaFeature.COMPUTER_USE_OPUS.value,
    "memory": BetaFeature.MEMORY.value,
    "web_fetch": BetaFeature.WEB_FETCH.value,
    "fine_grained_streaming": BetaFeature.FINE_GRAINED_STREAMING.value,
    "files_api": BetaFeature.FILES_API.value,
}

# Tool type versions (for reference)
CODE_EXECUTION_VERSION = AnthropicToolType.CODE_EXECUTION.value
TEXT_EDITOR_VERSION = AnthropicToolType.TEXT_EDITOR.value
BASH_VERSION = AnthropicToolType.BASH.value
MEMORY_VERSION = AnthropicToolType.MEMORY.value
WEB_SEARCH_VERSION = AnthropicToolType.WEB_SEARCH.value
WEB_FETCH_VERSION = AnthropicToolType.WEB_FETCH.value
COMPUTER_USE_VERSION = AnthropicToolType.COMPUTER_USE.value


def get_beta_headers(
    enable_code_execution: bool = True,
    enable_computer_use: bool = False,
    enable_memory: bool = False,
    enable_web_fetch: bool = False,
    enable_streaming: bool = False,
    model: str = "",
) -> list[str]:
    """
    Get the list of beta headers based on enabled features.

    Args:
        enable_code_execution: Enable sandboxed code execution.
        enable_computer_use: Enable computer use tool.
        enable_memory: Enable memory tool.
        enable_web_fetch: Enable web fetch tool.
        enable_streaming: Enable fine-grained tool streaming.
        model: Model name for version-specific headers.

    Returns:
        List of beta header strings.
    """
    headers = [BetaFeature.ADVANCED_TOOL_USE.value]

    if enable_code_execution:
        headers.append(BetaFeature.CODE_EXECUTION.value)

    if enable_computer_use:
        # Use Opus-specific header for Opus 4.5
        if "opus-4-5" in model or "opus-4.5" in model:
            headers.append(BetaFeature.COMPUTER_USE_OPUS.value)
        else:
            headers.append(BetaFeature.COMPUTER_USE.value)

    if enable_memory:
        headers.append(BetaFeature.MEMORY.value)

    if enable_web_fetch:
        headers.append(BetaFeature.WEB_FETCH.value)

    if enable_streaming:
        headers.append(BetaFeature.FINE_GRAINED_STREAMING.value)

    return headers
