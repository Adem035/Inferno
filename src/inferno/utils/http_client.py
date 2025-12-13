"""
Centralized HTTP client for Inferno.

This module provides a unified HTTP client that all tools should use for
making HTTP requests. This ensures:
- Consistent configuration (timeouts, SSL, user agents)
- Centralized error handling
- Easy debugging and logging
- Single place to configure proxies, rate limiting, etc.
- No duplication of httpx/aiohttp setup across tools
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class HTTPClientConfig:
    """Configuration for the HTTP client."""

    timeout: float = 30.0
    follow_redirects: bool = True
    verify_ssl: bool = False
    max_redirects: int = 20
    user_agent: str = "Inferno/1.0 (Security Assessment)"
    proxy: str | None = None
    retry_count: int = 0
    retry_delay: float = 1.0

    # Connection pool settings
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry: float = 30.0


@dataclass
class HTTPResponse:
    """Unified HTTP response object."""

    status_code: int
    headers: dict[str, str]
    content: bytes
    text: str
    url: str
    elapsed_ms: float
    redirected: bool = False

    @property
    def ok(self) -> bool:
        """Check if response status is 2xx."""
        return 200 <= self.status_code < 300

    @property
    def reason_phrase(self) -> str:
        """Get HTTP reason phrase for status code."""
        phrases = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return phrases.get(self.status_code, "Unknown")

    def json(self) -> Any:
        """Parse response as JSON."""
        import json
        return json.loads(self.text)


@dataclass
class HTTPError:
    """HTTP error details."""

    error_type: str  # "timeout", "connection", "ssl", "redirect", "unknown"
    message: str
    url: str
    details: dict[str, Any] = field(default_factory=dict)


class InfernoHTTPClient:
    """
    Centralized HTTP client for all Inferno tools.

    Usage:
        async with InfernoHTTPClient() as client:
            response = await client.get("https://example.com")
            if response:
                print(response.text)

        # Or with custom config:
        config = HTTPClientConfig(timeout=60.0, verify_ssl=True)
        async with InfernoHTTPClient(config) as client:
            response = await client.post("https://api.example.com", json={"key": "value"})
    """

    def __init__(self, config: HTTPClientConfig | None = None) -> None:
        """
        Initialize the HTTP client.

        Args:
            config: Optional configuration. Uses defaults if not provided.
        """
        self._config = config or HTTPClientConfig()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> InfernoHTTPClient:
        """Async context manager entry."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure client is initialized."""
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(
                max_connections=self._config.max_connections,
                max_keepalive_connections=self._config.max_keepalive_connections,
                keepalive_expiry=self._config.keepalive_expiry,
            )

            transport_kwargs: dict[str, Any] = {"limits": limits}
            if self._config.proxy:
                transport_kwargs["proxy"] = self._config.proxy

            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._config.timeout),
                follow_redirects=self._config.follow_redirects,
                max_redirects=self._config.max_redirects,
                verify=self._config.verify_ssl,
                headers={"User-Agent": self._config.user_agent},
                **transport_kwargs,
            )

        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        body: str | bytes | None = None,
        json: dict[str, Any] | None = None,
        form_data: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool | None = None,
        auth: tuple[str, str] | None = None,
    ) -> HTTPResponse | HTTPError:
        """
        Make an HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL
            headers: Optional headers
            cookies: Optional cookies
            params: Optional query parameters
            body: Raw body content
            json: JSON body (auto-sets Content-Type)
            form_data: Form data (auto-sets Content-Type)
            timeout: Override default timeout
            follow_redirects: Override default redirect behavior
            auth: Optional (username, password) tuple for basic auth

        Returns:
            HTTPResponse on success, HTTPError on failure.
        """
        client = await self._ensure_client()

        # Build request kwargs
        request_kwargs: dict[str, Any] = {
            "method": method.upper(),
            "url": url,
        }

        if headers:
            request_kwargs["headers"] = headers
        if cookies:
            request_kwargs["cookies"] = cookies
        if params:
            request_kwargs["params"] = params
        if json is not None:
            request_kwargs["json"] = json
        elif form_data is not None:
            request_kwargs["data"] = form_data
        elif body is not None:
            request_kwargs["content"] = body
        if auth:
            request_kwargs["auth"] = auth
        if timeout is not None:
            request_kwargs["timeout"] = timeout
        if follow_redirects is not None:
            request_kwargs["follow_redirects"] = follow_redirects

        # Execute with retry logic
        last_error: Exception | None = None
        for attempt in range(self._config.retry_count + 1):
            try:
                start_time = asyncio.get_event_loop().time()
                response = await client.request(**request_kwargs)
                elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000

                return HTTPResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    content=response.content,
                    text=response.text,
                    url=str(response.url),
                    elapsed_ms=elapsed_ms,
                    redirected=str(response.url) != url,
                )

            except httpx.TimeoutException as e:
                last_error = e
                logger.warning(
                    "http_timeout",
                    url=url,
                    attempt=attempt + 1,
                    timeout=timeout or self._config.timeout,
                )
                if attempt < self._config.retry_count:
                    await asyncio.sleep(self._config.retry_delay)

            except httpx.ConnectError as e:
                last_error = e
                logger.warning(
                    "http_connection_error",
                    url=url,
                    attempt=attempt + 1,
                    error=str(e),
                )
                if attempt < self._config.retry_count:
                    await asyncio.sleep(self._config.retry_delay)

            except httpx.TooManyRedirects:
                return HTTPError(
                    error_type="redirect",
                    message="Too many redirects",
                    url=url,
                    details={"max_redirects": self._config.max_redirects},
                )

            except Exception as e:
                logger.error(
                    "http_error",
                    url=url,
                    error=str(e),
                    error_type=type(e).__name__,
                )
                return HTTPError(
                    error_type="unknown",
                    message=str(e),
                    url=url,
                    details={"exception": type(e).__name__},
                )

        # All retries exhausted
        if isinstance(last_error, httpx.TimeoutException):
            return HTTPError(
                error_type="timeout",
                message=f"Request timed out after {timeout or self._config.timeout}s",
                url=url,
                details={"timeout": timeout or self._config.timeout},
            )
        elif isinstance(last_error, httpx.ConnectError):
            return HTTPError(
                error_type="connection",
                message=f"Connection failed: {last_error}",
                url=url,
            )
        else:
            return HTTPError(
                error_type="unknown",
                message=str(last_error) if last_error else "Unknown error",
                url=url,
            )

    # Convenience methods
    async def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> HTTPResponse | HTTPError:
        """Make a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(
        self,
        url: str,
        **kwargs: Any,
    ) -> HTTPResponse | HTTPError:
        """Make a POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(
        self,
        url: str,
        **kwargs: Any,
    ) -> HTTPResponse | HTTPError:
        """Make a PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(
        self,
        url: str,
        **kwargs: Any,
    ) -> HTTPResponse | HTTPError:
        """Make a DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(
        self,
        url: str,
        **kwargs: Any,
    ) -> HTTPResponse | HTTPError:
        """Make a HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def options(
        self,
        url: str,
        **kwargs: Any,
    ) -> HTTPResponse | HTTPError:
        """Make an OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)


# Global client instance for simple usage
_global_client: InfernoHTTPClient | None = None


def get_http_client(config: HTTPClientConfig | None = None) -> InfernoHTTPClient:
    """
    Get a shared HTTP client instance.

    For most tools, use this to avoid creating multiple client instances.
    The client is reused across calls for connection pooling benefits.

    Args:
        config: Optional config. Only used if creating a new client.

    Returns:
        Shared InfernoHTTPClient instance.
    """
    global _global_client
    if _global_client is None:
        _global_client = InfernoHTTPClient(config)
    return _global_client


async def close_global_client() -> None:
    """Close the global HTTP client."""
    global _global_client
    if _global_client:
        await _global_client.close()
        _global_client = None


@asynccontextmanager
async def http_client(
    config: HTTPClientConfig | None = None,
) -> AsyncIterator[InfernoHTTPClient]:
    """
    Context manager for creating a temporary HTTP client.

    Use this when you need a client with specific configuration
    that differs from the global client.

    Example:
        async with http_client(HTTPClientConfig(timeout=60)) as client:
            response = await client.get("https://slow-api.com")
    """
    client = InfernoHTTPClient(config)
    try:
        await client._ensure_client()
        yield client
    finally:
        await client.close()
