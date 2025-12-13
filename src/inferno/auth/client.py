"""
Claude API client wrapper for Inferno.

This module provides a production-ready client wrapper around the Anthropic SDK
with support for:
- API key authentication (pay per token)
- OAuth authentication (Claude subscription - no extra cost)
- Advanced tool features (Tool Search, Programmatic Tool Calling)
- Automatic retry logic
- Token tracking
- Streaming
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

import httpx
import structlog
from anthropic import Anthropic, AsyncAnthropic
from anthropic.types import Message, RawMessageStreamEvent
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from inferno.auth.credentials import (
    CredentialManager,
    get_credential_manager,
)
from inferno.config.settings import (
    BETA_HEADERS,
    CODE_EXECUTION_VERSION,
    ModelTier,
    ToolSearchVariant,
)

if TYPE_CHECKING:
    from anthropic.types import MessageParam, ToolParam

logger = structlog.get_logger(__name__)


class ClientError(Exception):
    """Base exception for client errors."""

    pass


class RateLimitError(ClientError):
    """Raised when rate limited by the API."""

    pass


class TokenLimitError(ClientError):
    """Raised when token limit is exceeded."""

    pass


@dataclass
class TokenUsage:
    """Tracks token usage for a session."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        """Total tokens used."""
        return self.input_tokens + self.output_tokens

    def add(self, other: TokenUsage) -> TokenUsage:
        """Add another TokenUsage to this one."""
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_creation_input_tokens=self.cache_creation_input_tokens
            + other.cache_creation_input_tokens,
            cache_read_input_tokens=self.cache_read_input_tokens
            + other.cache_read_input_tokens,
        )


@dataclass
class TokenTracker:
    """Tracks token usage across multiple requests."""

    requests: list[TokenUsage] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def total(self) -> TokenUsage:
        """Get total token usage."""
        result = TokenUsage()
        for usage in self.requests:
            result = result.add(usage)
        return result

    @property
    def request_count(self) -> int:
        """Number of requests tracked."""
        return len(self.requests)

    def track(self, usage: TokenUsage) -> None:
        """Track a new request's token usage."""
        self.requests.append(usage)

    def estimate_cost(
        self,
        input_price_per_million: float = 3.0,
        output_price_per_million: float = 15.0,
    ) -> float:
        """
        Estimate the cost based on token usage.

        Args:
            input_price_per_million: Price per million input tokens.
            output_price_per_million: Price per million output tokens.

        Returns:
            Estimated cost in dollars.
        """
        total = self.total
        input_cost = (total.input_tokens / 1_000_000) * input_price_per_million
        output_cost = (total.output_tokens / 1_000_000) * output_price_per_million
        return input_cost + output_cost


class InfernoClient:
    """
    Synchronous Claude API client with advanced tool features.

    Features:
    - API key or OAuth authentication
    - Beta headers for Tool Search and Programmatic Tool Calling
    - Automatic retry with exponential backoff
    - Token tracking
    - Streaming support

    Authentication:
    - API Key: Uses X-Api-Key header (pay per token)
    - OAuth: Uses Authorization: Bearer header (Claude subscription)
    """

    def __init__(
        self,
        api_key: str | None = None,
        auth_token: str | None = None,
        model: ModelTier = ModelTier.SONNET_4_5,
        max_retries: int = 10,
        timeout: float = 420.0,
        credential_manager: CredentialManager | None = None,
    ) -> None:
        """
        Initialize the Inferno client.

        Args:
            api_key: Anthropic API key (for API billing).
            auth_token: OAuth token (for Claude subscription).
            model: Claude model to use.
            max_retries: Maximum retry attempts.
            timeout: Request timeout in seconds.
            credential_manager: Optional credential manager instance.

        Note:
            If neither api_key nor auth_token is provided, the credential
            manager is used to obtain credentials (OAuth first, then API key).
        """
        self._credential_manager = credential_manager or get_credential_manager()
        self._auth_type: str = "unknown"

        # Determine authentication method
        client_kwargs: dict[str, Any] = {
            "max_retries": max_retries,
            "timeout": httpx.Timeout(timeout, connect=60.0),
        }

        if auth_token:
            # Explicit OAuth token provided
            client_kwargs["auth_token"] = auth_token
            self._auth_type = "oauth"
        elif api_key:
            # Explicit API key provided
            client_kwargs["api_key"] = api_key
            self._auth_type = "api_key"
        else:
            # Use credential manager to get credentials
            credential = self._credential_manager.get_credential()
            if credential.is_oauth:
                client_kwargs["auth_token"] = credential.get_value()
                self._auth_type = "oauth"
            else:
                client_kwargs["api_key"] = credential.get_value()
                self._auth_type = "api_key"

        self._client = Anthropic(**client_kwargs)
        self._model = model
        self._token_tracker = TokenTracker()

        logger.info(
            "client_initialized",
            model=model.value,
            auth_type=self._auth_type,
            timeout=timeout,
            max_retries=max_retries,
        )

    @property
    def auth_type(self) -> str:
        """Get the authentication type (oauth or api_key)."""
        return self._auth_type

    @property
    def model(self) -> ModelTier:
        """Get the current model."""
        return self._model

    @property
    def token_tracker(self) -> TokenTracker:
        """Get the token tracker."""
        return self._token_tracker

    def _extract_usage(self, response: Message) -> TokenUsage:
        """Extract token usage from a response."""
        usage = response.usage
        return TokenUsage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        )

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
    )
    def create_message(
        self,
        messages: list[MessageParam],
        system: str | None = None,
        tools: list[ToolParam] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        stream: Literal[False] = False,
    ) -> Message:
        """
        Create a message with Claude.

        Args:
            messages: Conversation messages.
            system: System prompt.
            tools: Tool definitions.
            max_tokens: Maximum response tokens.
            temperature: Sampling temperature.
            stream: Whether to stream (must be False for this overload).

        Returns:
            Claude's response message.
        """
        kwargs: dict[str, Any] = {
            "model": self._model.value,
            "max_tokens": max_tokens,
            "messages": messages,
        }

        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        if temperature != 1.0:
            kwargs["temperature"] = temperature

        # Use beta endpoint for advanced features
        response = self._client.beta.messages.create(
            betas=BETA_HEADERS,
            **kwargs,
        )

        # Track usage
        usage = self._extract_usage(response)
        self._token_tracker.track(usage)

        logger.debug(
            "message_created",
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            stop_reason=response.stop_reason,
        )

        return response

    def create_message_stream(
        self,
        messages: list[MessageParam],
        system: str | None = None,
        tools: list[ToolParam] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> Iterator[RawMessageStreamEvent]:
        """
        Create a streaming message with Claude.

        Args:
            messages: Conversation messages.
            system: System prompt.
            tools: Tool definitions.
            max_tokens: Maximum response tokens.
            temperature: Sampling temperature.

        Yields:
            Stream events from Claude.
        """
        kwargs: dict[str, Any] = {
            "model": self._model.value,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": True,
        }

        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        if temperature != 1.0:
            kwargs["temperature"] = temperature

        with self._client.beta.messages.stream(
            betas=BETA_HEADERS,
            **kwargs,
        ) as stream:
            for event in stream:
                yield event

            # Track final usage
            final_message = stream.get_final_message()
            if final_message:
                usage = self._extract_usage(final_message)
                self._token_tracker.track(usage)

    def build_tools_with_search(
        self,
        core_tools: list[dict[str, Any]],
        deferred_tools: list[dict[str, Any]],
        search_variant: ToolSearchVariant = ToolSearchVariant.BM25,
        enable_code_execution: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Build tool list with search tool, code execution, and deferred tools.

        Args:
            core_tools: Tools that should always be loaded.
            deferred_tools: Tools that can be searched on-demand.
            search_variant: Tool search algorithm variant.
            enable_code_execution: Enable programmatic tool calling.

        Returns:
            Complete tool list for API request.
        """
        tools: list[dict[str, Any]] = []

        # Add Tool Search (always first)
        tools.append({
            "type": search_variant.value,
            "name": "tool_search",
        })

        # Add Code Execution if enabled
        if enable_code_execution:
            tools.append({
                "type": CODE_EXECUTION_VERSION,
                "name": "code_execution",
            })

        # Add core tools (non-deferred)
        for tool in core_tools:
            tool_def = tool.copy()
            tool_def["defer_loading"] = False
            tools.append(tool_def)

        # Add deferred tools
        for tool in deferred_tools:
            tool_def = tool.copy()
            tool_def["defer_loading"] = True
            tools.append(tool_def)

        logger.debug(
            "tools_built",
            core_count=len(core_tools),
            deferred_count=len(deferred_tools),
            total=len(tools),
        )

        return tools


class AsyncInfernoClient:
    """
    Asynchronous Claude API client with advanced tool features.

    Same features as InfernoClient but with async/await support.

    Authentication:
    - API Key: Uses X-Api-Key header (pay per token)
    - OAuth: Uses Authorization: Bearer header (Claude subscription)
    """

    def __init__(
        self,
        api_key: str | None = None,
        auth_token: str | None = None,
        model: ModelTier = ModelTier.SONNET_4_5,
        max_retries: int = 10,
        timeout: float = 420.0,
        credential_manager: CredentialManager | None = None,
    ) -> None:
        """
        Initialize the async Inferno client.

        Args:
            api_key: Anthropic API key (for API billing).
            auth_token: OAuth token (for Claude subscription).
            model: Claude model to use.
            max_retries: Maximum retry attempts.
            timeout: Request timeout in seconds.
            credential_manager: Optional credential manager instance.

        Note:
            If neither api_key nor auth_token is provided, the credential
            manager is used to obtain credentials (OAuth first, then API key).
        """
        self._credential_manager = credential_manager or get_credential_manager()
        self._auth_type: str = "unknown"

        # Determine authentication method
        client_kwargs: dict[str, Any] = {
            "max_retries": max_retries,
            "timeout": httpx.Timeout(timeout, connect=60.0),
        }

        if auth_token:
            # Explicit OAuth token provided
            client_kwargs["auth_token"] = auth_token
            self._auth_type = "oauth"
        elif api_key:
            # Explicit API key provided
            client_kwargs["api_key"] = api_key
            self._auth_type = "api_key"
        else:
            # Use credential manager to get credentials
            credential = self._credential_manager.get_credential()
            if credential.is_oauth:
                client_kwargs["auth_token"] = credential.get_value()
                self._auth_type = "oauth"
            else:
                client_kwargs["api_key"] = credential.get_value()
                self._auth_type = "api_key"

        self._client = AsyncAnthropic(**client_kwargs)
        self._model = model
        self._token_tracker = TokenTracker()

        logger.info(
            "async_client_initialized",
            model=model.value,
            auth_type=self._auth_type,
            timeout=timeout,
            max_retries=max_retries,
        )

    @property
    def auth_type(self) -> str:
        """Get the authentication type (oauth or api_key)."""
        return self._auth_type

    @property
    def model(self) -> ModelTier:
        """Get the current model."""
        return self._model

    @property
    def token_tracker(self) -> TokenTracker:
        """Get the token tracker."""
        return self._token_tracker

    def _extract_usage(self, response: Message) -> TokenUsage:
        """Extract token usage from a response."""
        usage = response.usage
        return TokenUsage(
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_creation_input_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            cache_read_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        )

    async def create_message(
        self,
        messages: list[MessageParam],
        system: str | None = None,
        tools: list[ToolParam] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> Message:
        """
        Create a message with Claude asynchronously.

        Args:
            messages: Conversation messages.
            system: System prompt.
            tools: Tool definitions.
            max_tokens: Maximum response tokens.
            temperature: Sampling temperature.

        Returns:
            Claude's response message.
        """
        kwargs: dict[str, Any] = {
            "model": self._model.value,
            "max_tokens": max_tokens,
            "messages": messages,
        }

        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        if temperature != 1.0:
            kwargs["temperature"] = temperature

        response = await self._client.beta.messages.create(
            betas=BETA_HEADERS,
            **kwargs,
        )

        usage = self._extract_usage(response)
        self._token_tracker.track(usage)

        logger.debug(
            "async_message_created",
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            stop_reason=response.stop_reason,
        )

        return response

    async def create_message_stream(
        self,
        messages: list[MessageParam],
        system: str | None = None,
        tools: list[ToolParam] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> AsyncIterator[RawMessageStreamEvent]:
        """
        Create a streaming message with Claude asynchronously.

        Args:
            messages: Conversation messages.
            system: System prompt.
            tools: Tool definitions.
            max_tokens: Maximum response tokens.
            temperature: Sampling temperature.

        Yields:
            Stream events from Claude.
        """
        kwargs: dict[str, Any] = {
            "model": self._model.value,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": True,
        }

        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools
        if temperature != 1.0:
            kwargs["temperature"] = temperature

        async with self._client.beta.messages.stream(
            betas=BETA_HEADERS,
            **kwargs,
        ) as stream:
            async for event in stream:
                yield event

            final_message = await stream.get_final_message()
            if final_message:
                usage = self._extract_usage(final_message)
                self._token_tracker.track(usage)

    def build_tools_with_search(
        self,
        core_tools: list[dict[str, Any]],
        deferred_tools: list[dict[str, Any]],
        search_variant: ToolSearchVariant = ToolSearchVariant.BM25,
        enable_code_execution: bool = True,
    ) -> list[dict[str, Any]]:
        """
        Build tool list with search tool, code execution, and deferred tools.

        Same implementation as sync client.
        """
        tools: list[dict[str, Any]] = []

        tools.append({
            "type": search_variant.value,
            "name": "tool_search",
        })

        if enable_code_execution:
            tools.append({
                "type": CODE_EXECUTION_VERSION,
                "name": "code_execution",
            })

        for tool in core_tools:
            tool_def = tool.copy()
            tool_def["defer_loading"] = False
            tools.append(tool_def)

        for tool in deferred_tools:
            tool_def = tool.copy()
            tool_def["defer_loading"] = True
            tools.append(tool_def)

        return tools

    async def __aenter__(self) -> AsyncInfernoClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self._client.close()
