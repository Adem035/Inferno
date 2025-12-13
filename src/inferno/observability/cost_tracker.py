"""
Granular Cost Tracking - CAI-inspired hierarchical token/cost tracking.

This module provides per-tool, per-agent, and global cost tracking
with support for multiple pricing models and real-time cost limits.

Usage:
    tracker = CostTracker()
    tracker.record_tool_call("agent_1", "http_request", metrics)
    summary = tracker.get_summary()
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ModelTier(str, Enum):
    """Model pricing tiers."""
    OPUS = "opus"
    SONNET = "sonnet"
    HAIKU = "haiku"
    GPT4 = "gpt4"
    GPT4_TURBO = "gpt4_turbo"
    GPT35 = "gpt35"


# Pricing per 1M tokens (input, output) in USD
MODEL_PRICING: dict[str, tuple[float, float]] = {
    # Anthropic Models
    "claude-opus-4-5-20251101": (15.0, 75.0),
    "claude-sonnet-4-5-20250514": (3.0, 15.0),
    "claude-3-5-sonnet-20241022": (3.0, 15.0),
    "claude-3-opus-20240229": (15.0, 75.0),
    "claude-3-sonnet-20240229": (3.0, 15.0),
    "claude-3-haiku-20240307": (0.25, 1.25),
    # OpenAI Models
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-4": (30.0, 60.0),
    "gpt-3.5-turbo": (0.5, 1.5),
    # Defaults
    "default_opus": (15.0, 75.0),
    "default_sonnet": (3.0, 15.0),
    "default": (3.0, 15.0),
}


@dataclass
class CostMetrics:
    """
    Token and cost metrics for a single entity.

    Tracks input/output tokens, cache usage, and calculated costs.
    """
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    total_cost_usd: float = 0.0
    call_count: int = 0
    first_call: datetime | None = None
    last_call: datetime | None = None

    def add(self, other: CostMetrics) -> None:
        """Add another metrics instance to this one."""
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        self.total_cost_usd += other.total_cost_usd
        self.call_count += other.call_count

        if other.first_call:
            if self.first_call is None or other.first_call < self.first_call:
                self.first_call = other.first_call
        if other.last_call:
            if self.last_call is None or other.last_call > self.last_call:
                self.last_call = other.last_call

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "call_count": self.call_count,
            "first_call": self.first_call.isoformat() if self.first_call else None,
            "last_call": self.last_call.isoformat() if self.last_call else None,
        }

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.input_tokens + self.output_tokens


def calculate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str = "default",
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    """
    Calculate cost in USD for token usage.

    Args:
        input_tokens: Number of input tokens.
        output_tokens: Number of output tokens.
        model: Model name for pricing lookup.
        cache_read_tokens: Tokens read from cache (90% discount).
        cache_write_tokens: Tokens written to cache (25% premium).

    Returns:
        Cost in USD.
    """
    # Get pricing for model
    pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
    input_price, output_price = pricing

    # Calculate base cost
    input_cost = (input_tokens / 1_000_000) * input_price
    output_cost = (output_tokens / 1_000_000) * output_price

    # Cache adjustments (Anthropic pricing)
    cache_read_cost = (cache_read_tokens / 1_000_000) * input_price * 0.1  # 90% discount
    cache_write_cost = (cache_write_tokens / 1_000_000) * input_price * 1.25  # 25% premium

    return input_cost + output_cost + cache_read_cost + cache_write_cost


@dataclass
class CostAlert:
    """Alert triggered when cost threshold is exceeded."""
    threshold_usd: float
    current_cost_usd: float
    entity_type: str  # "global", "agent", "tool"
    entity_id: str
    triggered_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class CostTracker:
    """
    Hierarchical cost tracking: global → agent → tool.

    Thread-safe singleton that tracks costs at multiple levels.
    Supports cost limits with callbacks for alerting.
    """

    _instance: CostTracker | None = None
    _lock = threading.Lock()

    def __new__(cls) -> CostTracker:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self) -> None:
        """Initialize the tracker state."""
        self._global = CostMetrics()
        self._by_agent: dict[str, CostMetrics] = {}
        self._by_tool: dict[str, dict[str, CostMetrics]] = {}  # agent_id -> {tool_name -> metrics}
        self._by_model: dict[str, CostMetrics] = {}
        self._operation_id: str | None = None
        self._started_at: datetime | None = None

        # Cost limits and callbacks
        self._global_limit_usd: float | None = None
        self._agent_limit_usd: float | None = None
        self._on_limit_exceeded: Callable[[CostAlert], None] | None = None

        # Alert history
        self._alerts: list[CostAlert] = []

        self._data_lock = threading.Lock()

    def reset(self) -> None:
        """Reset all tracking data."""
        with self._data_lock:
            self._global = CostMetrics()
            self._by_agent.clear()
            self._by_tool.clear()
            self._by_model.clear()
            self._alerts.clear()
            self._started_at = datetime.now(UTC)

    def set_operation(self, operation_id: str) -> None:
        """Set the current operation ID and reset tracking."""
        self._operation_id = operation_id
        self.reset()

    def set_limits(
        self,
        global_limit_usd: float | None = None,
        agent_limit_usd: float | None = None,
        on_limit_exceeded: Callable[[CostAlert], None] | None = None,
    ) -> None:
        """
        Set cost limits and alert callback.

        Args:
            global_limit_usd: Maximum total cost.
            agent_limit_usd: Maximum cost per agent.
            on_limit_exceeded: Callback when limit exceeded.
        """
        self._global_limit_usd = global_limit_usd
        self._agent_limit_usd = agent_limit_usd
        self._on_limit_exceeded = on_limit_exceeded

    def record_api_call(
        self,
        agent_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> CostMetrics:
        """
        Record an API call's token usage.

        Args:
            agent_id: Identifier for the agent making the call.
            model: Model used for the call.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            cache_read_tokens: Tokens read from cache.
            cache_write_tokens: Tokens written to cache.

        Returns:
            CostMetrics for this call.
        """
        cost = calculate_cost(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=model,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
        )

        now = datetime.now(UTC)
        metrics = CostMetrics(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
            total_cost_usd=cost,
            call_count=1,
            first_call=now,
            last_call=now,
        )

        with self._data_lock:
            # Update global
            self._global.add(metrics)

            # Update by agent
            if agent_id not in self._by_agent:
                self._by_agent[agent_id] = CostMetrics()
            self._by_agent[agent_id].add(metrics)

            # Update by model
            if model not in self._by_model:
                self._by_model[model] = CostMetrics()
            self._by_model[model].add(metrics)

            # Check limits
            self._check_limits(agent_id)

        logger.debug(
            "cost_recorded_api",
            agent_id=agent_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
        )

        return metrics

    def record_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        metrics: CostMetrics,
    ) -> None:
        """
        Record cost for a tool call.

        Args:
            agent_id: Identifier for the agent.
            tool_name: Name of the tool called.
            metrics: Cost metrics for the call.
        """
        with self._data_lock:
            # Update global
            self._global.add(metrics)

            # Update by agent
            if agent_id not in self._by_agent:
                self._by_agent[agent_id] = CostMetrics()
            self._by_agent[agent_id].add(metrics)

            # Update by tool
            if agent_id not in self._by_tool:
                self._by_tool[agent_id] = {}
            if tool_name not in self._by_tool[agent_id]:
                self._by_tool[agent_id][tool_name] = CostMetrics()
            self._by_tool[agent_id][tool_name].add(metrics)

            # Check limits
            self._check_limits(agent_id)

        logger.debug(
            "cost_recorded_tool",
            agent_id=agent_id,
            tool_name=tool_name,
            cost_usd=metrics.total_cost_usd,
        )

    def _check_limits(self, agent_id: str) -> None:
        """Check if any cost limits have been exceeded."""
        # Check global limit
        if self._global_limit_usd and self._global.total_cost_usd > self._global_limit_usd:
            alert = CostAlert(
                threshold_usd=self._global_limit_usd,
                current_cost_usd=self._global.total_cost_usd,
                entity_type="global",
                entity_id="global",
            )
            self._alerts.append(alert)
            if self._on_limit_exceeded:
                self._on_limit_exceeded(alert)

        # Check agent limit
        if self._agent_limit_usd and agent_id in self._by_agent:
            agent_cost = self._by_agent[agent_id].total_cost_usd
            if agent_cost > self._agent_limit_usd:
                alert = CostAlert(
                    threshold_usd=self._agent_limit_usd,
                    current_cost_usd=agent_cost,
                    entity_type="agent",
                    entity_id=agent_id,
                )
                self._alerts.append(alert)
                if self._on_limit_exceeded:
                    self._on_limit_exceeded(alert)

    def get_global_cost(self) -> float:
        """Get total cost across all agents."""
        return self._global.total_cost_usd

    def get_agent_cost(self, agent_id: str) -> float:
        """Get cost for a specific agent."""
        with self._data_lock:
            if agent_id in self._by_agent:
                return self._by_agent[agent_id].total_cost_usd
            return 0.0

    def get_tool_cost(self, agent_id: str, tool_name: str) -> float:
        """Get cost for a specific tool on a specific agent."""
        with self._data_lock:
            if agent_id in self._by_tool and tool_name in self._by_tool[agent_id]:
                return self._by_tool[agent_id][tool_name].total_cost_usd
            return 0.0

    def get_summary(self) -> dict[str, Any]:
        """
        Get comprehensive cost summary at all levels.

        Returns:
            Dictionary with global, by_agent, by_tool, and by_model breakdowns.
        """
        with self._data_lock:
            return {
                "operation_id": self._operation_id,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "global": self._global.to_dict(),
                "by_agent": {
                    agent_id: metrics.to_dict()
                    for agent_id, metrics in self._by_agent.items()
                },
                "by_tool": {
                    agent_id: {
                        tool_name: metrics.to_dict()
                        for tool_name, metrics in tools.items()
                    }
                    for agent_id, tools in self._by_tool.items()
                },
                "by_model": {
                    model: metrics.to_dict()
                    for model, metrics in self._by_model.items()
                },
                "alerts": [
                    {
                        "threshold_usd": a.threshold_usd,
                        "current_cost_usd": a.current_cost_usd,
                        "entity_type": a.entity_type,
                        "entity_id": a.entity_id,
                        "triggered_at": a.triggered_at.isoformat(),
                    }
                    for a in self._alerts
                ],
            }

    def get_top_tools_by_cost(self, limit: int = 10) -> list[tuple[str, str, float]]:
        """
        Get tools with highest cost.

        Returns:
            List of (agent_id, tool_name, cost_usd) tuples.
        """
        tool_costs = []
        with self._data_lock:
            for agent_id, tools in self._by_tool.items():
                for tool_name, metrics in tools.items():
                    tool_costs.append((agent_id, tool_name, metrics.total_cost_usd))

        tool_costs.sort(key=lambda x: x[2], reverse=True)
        return tool_costs[:limit]

    def get_efficiency_metrics(self) -> dict[str, Any]:
        """
        Get efficiency metrics like cost per finding, tokens per turn.

        Returns:
            Dictionary with efficiency calculations.
        """
        with self._data_lock:
            total_calls = self._global.call_count
            total_tokens = self._global.total_tokens
            total_cost = self._global.total_cost_usd

            return {
                "total_api_calls": total_calls,
                "total_tokens": total_tokens,
                "total_cost_usd": total_cost,
                "avg_tokens_per_call": total_tokens / total_calls if total_calls > 0 else 0,
                "avg_cost_per_call": total_cost / total_calls if total_calls > 0 else 0,
                "cache_hit_rate": (
                    self._global.cache_read_tokens /
                    (self._global.input_tokens + self._global.cache_read_tokens)
                    if (self._global.input_tokens + self._global.cache_read_tokens) > 0
                    else 0
                ),
            }


# Global singleton access
def get_cost_tracker() -> CostTracker:
    """Get the global CostTracker singleton."""
    return CostTracker()
