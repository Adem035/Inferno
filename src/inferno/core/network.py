"""
Global Network Manager for Inferno.

This module provides centralized network coordination for all agents,
solving the "loud" problem where multiple agents blast the target simultaneously.

Key features:
- Global singleton - one manager for entire swarm
- Per-domain rate limiting - prevent WAF triggers
- Proxy rotation - distribute requests across IPs
- Request queuing - orderly, coordinated requests
- OpSec coordination - jitter, delays, user-agent rotation
- CDN/geo-restriction tracking
"""

from __future__ import annotations

import asyncio
import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)


class RateLimitStrategy(str, Enum):
    """Rate limiting strategies."""

    FIXED = "fixed"  # Fixed delay between requests
    ADAPTIVE = "adaptive"  # Adapt based on response codes
    AGGRESSIVE = "aggressive"  # Minimal delays (for CTF)
    STEALTH = "stealth"  # Maximum delays, randomization


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    requests_per_second: float = 2.0  # Max RPS per domain
    burst_size: int = 5  # Allow burst of N requests
    min_delay: float = 0.1  # Minimum delay between requests (seconds)
    max_delay: float = 2.0  # Maximum delay
    jitter: float = 0.3  # Random jitter factor (0.0-1.0)
    backoff_multiplier: float = 2.0  # Backoff on rate limit
    max_backoff: float = 60.0  # Maximum backoff delay
    strategy: RateLimitStrategy = RateLimitStrategy.ADAPTIVE

    # Response code handling
    rate_limit_codes: list[int] = field(default_factory=lambda: [429, 503])
    waf_codes: list[int] = field(default_factory=lambda: [403, 406])

    @classmethod
    def aggressive(cls) -> RateLimitConfig:
        """Config for CTF/aggressive mode."""
        return cls(
            requests_per_second=20.0,
            burst_size=50,
            min_delay=0.01,
            max_delay=0.1,
            jitter=0.1,
            strategy=RateLimitStrategy.AGGRESSIVE,
        )

    @classmethod
    def stealth(cls) -> RateLimitConfig:
        """Config for stealth/evasion mode."""
        return cls(
            requests_per_second=0.5,
            burst_size=1,
            min_delay=1.0,
            max_delay=5.0,
            jitter=0.5,
            strategy=RateLimitStrategy.STEALTH,
        )


@dataclass
class ProxyConfig:
    """Configuration for a proxy."""

    url: str  # http://host:port or socks5://host:port
    username: str | None = None
    password: str | None = None

    # Health tracking
    is_healthy: bool = True
    last_used: datetime | None = None
    failure_count: int = 0
    success_count: int = 0

    # Performance
    avg_latency_ms: float = 0.0
    total_requests: int = 0

    @property
    def full_url(self) -> str:
        """Get full proxy URL with auth if needed."""
        if self.username and self.password:
            parsed = urlparse(self.url)
            return f"{parsed.scheme}://{self.username}:{self.password}@{parsed.netloc}"
        return self.url

    def record_success(self, latency_ms: float) -> None:
        """Record a successful request."""
        self.success_count += 1
        self.total_requests += 1
        self.failure_count = 0
        self.is_healthy = True
        self.last_used = datetime.now(UTC)
        # Rolling average latency
        self.avg_latency_ms = (
            (self.avg_latency_ms * (self.total_requests - 1) + latency_ms)
            / self.total_requests
        )

    def record_failure(self) -> None:
        """Record a failed request."""
        self.failure_count += 1
        self.total_requests += 1
        self.last_used = datetime.now(UTC)
        # Mark unhealthy after 3 consecutive failures
        if self.failure_count >= 3:
            self.is_healthy = False


@dataclass
class DomainState:
    """State tracking for a specific domain."""

    domain: str
    last_request_time: float = 0.0
    request_count: int = 0
    current_delay: float = 0.5
    backoff_until: float = 0.0  # Timestamp until which to back off
    consecutive_errors: int = 0
    waf_detected: bool = False
    rate_limited: bool = False

    # Token bucket for burst handling
    tokens: float = 5.0
    last_token_update: float = 0.0

    # CDN/geo-restriction tracking
    cdn_detected: str | None = None
    cdn_confidence: int = 0
    geo_blocked: bool = False
    geo_confidence: int = 0
    origin_ip: str | None = None


class ProxyRotator:
    """
    Manages proxy rotation for distributed requests.

    Features:
    - Round-robin rotation
    - Health-based selection
    - Latency-based prioritization
    - Automatic failover
    """

    def __init__(self) -> None:
        self._proxies: list[ProxyConfig] = []
        self._current_index: int = 0
        self._lock = threading.Lock()

    def add_proxy(
        self,
        url: str,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        """Add a proxy to the rotation pool."""
        proxy = ProxyConfig(url=url, username=username, password=password)
        with self._lock:
            self._proxies.append(proxy)
        logger.info("proxy_added", url=url, total=len(self._proxies))

    def add_proxies_from_list(self, proxy_list: list[str]) -> int:
        """
        Add proxies from a list of URLs.

        Format: http://host:port or http://user:pass@host:port
        """
        added = 0
        for proxy_url in proxy_list:
            try:
                parsed = urlparse(proxy_url)
                self.add_proxy(
                    url=f"{parsed.scheme}://{parsed.hostname}:{parsed.port}",
                    username=parsed.username,
                    password=parsed.password,
                )
                added += 1
            except Exception as e:
                logger.warning("invalid_proxy_url", url=proxy_url, error=str(e))
        return added

    def get_next(self) -> ProxyConfig | None:
        """Get the next healthy proxy in rotation."""
        with self._lock:
            if not self._proxies:
                return None

            # Try to find a healthy proxy
            attempts = len(self._proxies)
            while attempts > 0:
                proxy = self._proxies[self._current_index]
                self._current_index = (self._current_index + 1) % len(self._proxies)

                if proxy.is_healthy:
                    return proxy

                attempts -= 1

            # All proxies unhealthy - return first one anyway
            return self._proxies[0] if self._proxies else None

    def get_best(self) -> ProxyConfig | None:
        """Get the best proxy based on latency and health."""
        with self._lock:
            healthy = [p for p in self._proxies if p.is_healthy]
            if not healthy:
                return self._proxies[0] if self._proxies else None

            # Sort by latency (lowest first)
            return min(healthy, key=lambda p: p.avg_latency_ms)

    def mark_success(self, proxy: ProxyConfig, latency_ms: float) -> None:
        """Mark a proxy request as successful."""
        proxy.record_success(latency_ms)

    def mark_failure(self, proxy: ProxyConfig) -> None:
        """Mark a proxy request as failed."""
        proxy.record_failure()

    def get_healthy_count(self) -> int:
        """Get count of healthy proxies."""
        return sum(1 for p in self._proxies if p.is_healthy)

    def stats(self) -> dict[str, Any]:
        """Get proxy pool statistics."""
        return {
            "total": len(self._proxies),
            "healthy": self.get_healthy_count(),
            "proxies": [
                {
                    "url": p.url,
                    "healthy": p.is_healthy,
                    "success_rate": p.success_count / max(p.total_requests, 1),
                    "avg_latency_ms": p.avg_latency_ms,
                }
                for p in self._proxies
            ],
        }


class UserAgentRotator:
    """Rotates user agents for OpSec."""

    # Common browser user agents
    USER_AGENTS = [
        # Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ]

    # Security tool user agents (for when stealth isn't needed)
    SECURITY_AGENTS = [
        "Inferno/1.0 (Security Assessment)",
        "Mozilla/5.0 (compatible; InfernoScanner/1.0)",
    ]

    def __init__(self, stealth: bool = True) -> None:
        self._stealth = stealth
        self._current_index = 0

    def get_next(self) -> str:
        """Get the next user agent."""
        agents = self.USER_AGENTS if self._stealth else self.SECURITY_AGENTS
        agent = agents[self._current_index % len(agents)]
        self._current_index += 1
        return agent

    def get_random(self) -> str:
        """Get a random user agent."""
        agents = self.USER_AGENTS if self._stealth else self.SECURITY_AGENTS
        return random.choice(agents)


class NetworkManager:
    """
    Global network coordinator for all Inferno agents.

    This is a singleton that ALL agents must route requests through.
    It ensures coordinated, rate-limited, stealthy network access.

    Features:
    - Per-domain rate limiting
    - Proxy rotation
    - User-agent rotation
    - Request queuing
    - Automatic backoff on WAF/rate limits
    - OpSec coordination
    - CDN/geo-restriction tracking
    """

    # Singleton instance
    _instance: NetworkManager | None = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> NetworkManager:
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        rate_limit_config: RateLimitConfig | None = None,
        default_timeout: int | None = None,
        verify_ssl: bool | None = None,
    ) -> None:
        """Initialize the network manager."""
        if getattr(self, "_initialized", False):
            return

        self._config = rate_limit_config or RateLimitConfig()

        # Load from settings or use defaults
        try:
            from inferno.config.settings import InfernoSettings
            settings = InfernoSettings()
            self._default_timeout = default_timeout if default_timeout is not None else settings.network.default_timeout
            self._verify_ssl = verify_ssl if verify_ssl is not None else settings.network.verify_ssl
        except Exception:
            self._default_timeout = default_timeout if default_timeout is not None else 30
            self._verify_ssl = verify_ssl if verify_ssl is not None else True  # Default to secure

        # Domain state tracking
        self._domain_states: dict[str, DomainState] = {}

        # Proxy and user-agent rotation
        self._proxy_rotator = ProxyRotator()
        self._ua_rotator = UserAgentRotator(stealth=True)

        # Request queue and coordination
        self._request_queue: asyncio.Queue[tuple[str, asyncio.Future]] = asyncio.Queue()
        self._domain_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

        # Statistics
        self._total_requests: int = 0
        self._total_rate_limits: int = 0
        self._total_waf_blocks: int = 0

        self._initialized = True
        logger.info(
            "network_manager_initialized",
            strategy=self._config.strategy.value,
            rps=self._config.requests_per_second,
        )

    def configure(self, config: RateLimitConfig) -> None:
        """Update rate limiting configuration."""
        self._config = config
        logger.info(
            "network_config_updated",
            strategy=config.strategy.value,
            rps=config.requests_per_second,
        )

    def set_mode(self, mode: Literal["aggressive", "stealth", "adaptive"]) -> None:
        """Set rate limiting mode."""
        if mode == "aggressive":
            self._config = RateLimitConfig.aggressive()
            self._ua_rotator = UserAgentRotator(stealth=False)
        elif mode == "stealth":
            self._config = RateLimitConfig.stealth()
            self._ua_rotator = UserAgentRotator(stealth=True)
        else:
            self._config = RateLimitConfig()
            self._ua_rotator = UserAgentRotator(stealth=True)

        logger.info("network_mode_set", mode=mode)

    def add_proxy(
        self,
        url: str,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        """Add a proxy to the rotation pool."""
        self._proxy_rotator.add_proxy(url, username, password)

    def add_proxies(self, proxy_list: list[str]) -> int:
        """Add multiple proxies from a list."""
        return self._proxy_rotator.add_proxies_from_list(proxy_list)

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return url

    def _get_domain_state(self, domain: str) -> DomainState:
        """Get or create state for a domain."""
        if domain not in self._domain_states:
            self._domain_states[domain] = DomainState(
                domain=domain,
                tokens=self._config.burst_size,
                last_token_update=time.time(),
            )
        return self._domain_states[domain]

    def update_cdn_info(
        self,
        domain: str,
        cdn_name: str | None = None,
        cdn_confidence: int = 0,
        geo_blocked: bool = False,
        geo_confidence: int = 0,
        origin_ip: str | None = None,
    ) -> None:
        """
        Update CDN/geo-restriction information for a domain.

        Args:
            domain: Domain name.
            cdn_name: Detected CDN name.
            cdn_confidence: CDN detection confidence (0-100).
            geo_blocked: Whether domain is geo-blocked.
            geo_confidence: Geo-restriction confidence (0-100).
            origin_ip: Discovered origin IP.
        """
        state = self._get_domain_state(domain)
        state.cdn_detected = cdn_name
        state.cdn_confidence = cdn_confidence
        state.geo_blocked = geo_blocked
        state.geo_confidence = geo_confidence
        state.origin_ip = origin_ip

        logger.info(
            "domain_protection_updated",
            domain=domain,
            cdn=cdn_name,
            geo_blocked=geo_blocked,
            origin=origin_ip,
        )

    def get_domain_protection_info(self, domain: str) -> dict[str, Any]:
        """
        Get CDN/geo-restriction information for a domain.

        Args:
            domain: Domain name.

        Returns:
            Dictionary with protection information.
        """
        if domain not in self._domain_states:
            return {"domain": domain, "tracked": False}

        state = self._domain_states[domain]
        return {
            "domain": domain,
            "tracked": True,
            "cdn_detected": state.cdn_detected,
            "cdn_confidence": state.cdn_confidence,
            "geo_blocked": state.geo_blocked,
            "geo_confidence": state.geo_confidence,
            "origin_ip": state.origin_ip,
            "waf_detected": state.waf_detected,
            "rate_limited": state.rate_limited,
        }

    def _update_tokens(self, state: DomainState) -> None:
        """Update token bucket for a domain."""
        now = time.time()
        elapsed = now - state.last_token_update
        state.last_token_update = now

        # Add tokens based on time elapsed and RPS
        new_tokens = elapsed * self._config.requests_per_second
        state.tokens = min(
            self._config.burst_size,
            state.tokens + new_tokens,
        )

    def _calculate_delay(self, state: DomainState) -> float:
        """Calculate delay before next request."""
        now = time.time()

        # Check if in backoff period
        if state.backoff_until > now:
            return state.backoff_until - now

        # Check token availability
        self._update_tokens(state)

        if state.tokens >= 1.0:
            # We have a token - minimal delay
            base_delay = self._config.min_delay
        else:
            # Wait for token to replenish
            tokens_needed = 1.0 - state.tokens
            base_delay = tokens_needed / self._config.requests_per_second

        # Add jitter
        if self._config.jitter > 0:
            jitter_amount = base_delay * self._config.jitter
            base_delay += random.uniform(-jitter_amount, jitter_amount)

        # Ensure within bounds
        return max(self._config.min_delay, min(self._config.max_delay, base_delay))

    def _handle_response_code(self, state: DomainState, status_code: int) -> None:
        """Handle response codes and update state."""
        if status_code in self._config.rate_limit_codes:
            # Rate limited - exponential backoff
            state.rate_limited = True
            state.consecutive_errors += 1
            backoff = min(
                self._config.max_backoff,
                state.current_delay * (self._config.backoff_multiplier ** state.consecutive_errors),
            )
            state.backoff_until = time.time() + backoff
            state.current_delay = backoff
            self._total_rate_limits += 1
            logger.warning(
                "rate_limit_detected",
                domain=state.domain,
                backoff_seconds=backoff,
            )

        elif status_code in self._config.waf_codes:
            # WAF detected - longer backoff and mode adjustment
            state.waf_detected = True
            state.consecutive_errors += 1
            backoff = min(
                self._config.max_backoff,
                5.0 * (self._config.backoff_multiplier ** state.consecutive_errors),
            )
            state.backoff_until = time.time() + backoff
            self._total_waf_blocks += 1
            logger.warning(
                "waf_detected",
                domain=state.domain,
                backoff_seconds=backoff,
            )

        elif 200 <= status_code < 400:
            # Success - reset error count, reduce delay
            state.consecutive_errors = 0
            state.rate_limited = False
            if state.current_delay > self._config.min_delay:
                state.current_delay = max(
                    self._config.min_delay,
                    state.current_delay / self._config.backoff_multiplier,
                )

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        body: str | None = None,
        json_body: dict[str, Any] | None = None,
        form_data: dict[str, str] | None = None,
        timeout: int | None = None,
        follow_redirects: bool = True,
        use_proxy: bool = True,
        rotate_ua: bool = True,
        caller_id: str = "unknown",
    ) -> httpx.Response:
        """
        Make a coordinated HTTP request.

        This method handles rate limiting, proxy rotation, and OpSec automatically.
        ALL agents should use this instead of direct HTTP calls.

        Args:
            url: Target URL
            method: HTTP method
            headers: Custom headers
            cookies: Request cookies
            body: Raw body
            json_body: JSON body
            form_data: Form data
            timeout: Request timeout
            follow_redirects: Follow redirects
            use_proxy: Whether to use proxy rotation
            rotate_ua: Whether to rotate user agent
            caller_id: ID of calling agent (for logging)

        Returns:
            httpx.Response object

        Raises:
            httpx.TimeoutException: On timeout
            httpx.ConnectError: On connection failure
        """
        domain = self._get_domain(url)
        state = self._get_domain_state(domain)

        # Acquire domain-specific lock
        async with self._domain_locks[domain]:
            # Calculate and apply delay
            delay = self._calculate_delay(state)
            if delay > 0:
                logger.debug(
                    "request_delayed",
                    domain=domain,
                    delay_seconds=round(delay, 3),
                )
                await asyncio.sleep(delay)

            # Consume a token
            state.tokens -= 1.0
            state.last_request_time = time.time()
            state.request_count += 1
            self._total_requests += 1

        # Build request
        request_headers = headers.copy() if headers else {}

        # Rotate user agent if enabled
        if rotate_ua and "User-Agent" not in request_headers:
            request_headers["User-Agent"] = self._ua_rotator.get_random()

        # Get proxy if enabled
        proxy = None
        proxy_config = None
        if use_proxy:
            proxy_config = self._proxy_rotator.get_next()
            if proxy_config:
                proxy = proxy_config.full_url

        # Build client kwargs
        client_kwargs: dict[str, Any] = {
            "follow_redirects": follow_redirects,
            "timeout": httpx.Timeout(timeout or self._default_timeout),
            "verify": self._verify_ssl,
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        # Build request kwargs
        request_kwargs: dict[str, Any] = {
            "method": method.upper(),
            "url": url,
            "headers": request_headers,
        }
        if cookies:
            request_kwargs["cookies"] = cookies
        if json_body:
            request_kwargs["json"] = json_body
        elif form_data:
            request_kwargs["data"] = form_data
        elif body:
            request_kwargs["content"] = body

        start_time = time.time()

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.request(**request_kwargs)

            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000

            # Update proxy stats
            if proxy_config:
                self._proxy_rotator.mark_success(proxy_config, latency_ms)

            # Handle response code
            self._handle_response_code(state, response.status_code)

            logger.debug(
                "request_completed",
                url=url,
                method=method,
                status=response.status_code,
                latency_ms=round(latency_ms),
                caller=caller_id,
            )

            return response

        except Exception as e:
            # Update proxy stats on failure
            if proxy_config:
                self._proxy_rotator.mark_failure(proxy_config)

            # Update state
            state.consecutive_errors += 1

            logger.warning(
                "request_failed",
                url=url,
                method=method,
                error=str(e),
                caller=caller_id,
            )
            raise

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Convenience method for GET requests."""
        return await self.request(url, method="GET", **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Convenience method for POST requests."""
        return await self.request(url, method="POST", **kwargs)

    def is_domain_blocked(self, domain: str) -> bool:
        """Check if a domain is currently in backoff."""
        state = self._domain_states.get(domain)
        if not state:
            return False
        return state.backoff_until > time.time()

    def get_domain_wait_time(self, domain: str) -> float:
        """Get remaining wait time for a domain."""
        state = self._domain_states.get(domain)
        if not state:
            return 0.0
        if state.backoff_until > time.time():
            return state.backoff_until - time.time()
        return self._calculate_delay(state)

    def stats(self) -> dict[str, Any]:
        """Get network manager statistics."""
        return {
            "total_requests": self._total_requests,
            "rate_limits": self._total_rate_limits,
            "waf_blocks": self._total_waf_blocks,
            "strategy": self._config.strategy.value,
            "proxies": self._proxy_rotator.stats(),
            "domains": {
                domain: {
                    "requests": state.request_count,
                    "waf_detected": state.waf_detected,
                    "rate_limited": state.rate_limited,
                    "current_delay": state.current_delay,
                    "cdn_detected": state.cdn_detected,
                    "cdn_confidence": state.cdn_confidence,
                    "geo_blocked": state.geo_blocked,
                    "origin_ip": state.origin_ip,
                }
                for domain, state in self._domain_states.items()
            },
        }

    def reset_domain(self, domain: str) -> None:
        """Reset state for a specific domain."""
        if domain in self._domain_states:
            del self._domain_states[domain]
            logger.info("domain_state_reset", domain=domain)

    def reset_all(self) -> None:
        """Reset all state."""
        self._domain_states.clear()
        self._total_requests = 0
        self._total_rate_limits = 0
        self._total_waf_blocks = 0
        logger.info("network_manager_reset")


# Global singleton accessor
_network_manager: NetworkManager | None = None


def get_network_manager() -> NetworkManager:
    """Get the global network manager instance."""
    global _network_manager
    if _network_manager is None:
        _network_manager = NetworkManager()
    return _network_manager
