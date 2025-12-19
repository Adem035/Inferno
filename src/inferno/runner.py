"""
Unified InfernoRunner - CAI-inspired Runner pattern for Inferno.

This module provides the main Runner class that orchestrates agent execution
with support for Claude SDK, OAuth authentication, guardrails, handoffs,
and distributed tracing.

Key features:
- Single Runner class with clean run() method
- Claude SDK with OAuth authentication support
- NextStep enum: FINAL, HANDOFF, RUN_AGAIN
- Parallel tool execution via asyncio.gather
- Input/output guardrails support
- Handoff support with message history transfer
- Tracing support
- RunConfig dataclass for configuration

Architecture ported from CAI SDK agents/run.py
"""

from __future__ import annotations

import asyncio
import copy
import os
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    TypeVar,
    cast,
)

import structlog

from inferno.config.settings import InfernoSettings, ModelTier

if TYPE_CHECKING:
    from anthropic import AsyncAnthropic
    from anthropic.types import MessageParam

logger = structlog.get_logger(__name__)

# Environment-based defaults
max_turns_env = os.getenv("INFERNO_MAX_TURNS")
if max_turns_env is not None:
    try:
        DEFAULT_MAX_TURNS = int(max_turns_env)
    except ValueError:
        try:
            DEFAULT_MAX_TURNS = float(max_turns_env)
        except ValueError:
            DEFAULT_MAX_TURNS = float("inf")
else:
    DEFAULT_MAX_TURNS = float("inf")

price_limit_env = os.getenv("INFERNO_PRICE_LIMIT")
if price_limit_env is not None:
    try:
        DEFAULT_PRICE_LIMIT = float(price_limit_env)
    except ValueError:
        DEFAULT_PRICE_LIMIT = float("inf")
else:
    DEFAULT_PRICE_LIMIT = float("inf")


# =============================================================================
# TYPE VARIABLES
# =============================================================================

TContext = TypeVar("TContext")
TOutput = TypeVar("TOutput")


# =============================================================================
# NEXT STEP TYPES
# =============================================================================

class NextStep(str, Enum):
    """Next step in the agent execution loop."""
    FINAL = "final"       # Agent produced final output
    HANDOFF = "handoff"   # Agent handed off to another agent
    RUN_AGAIN = "run_again"  # Agent needs another turn


@dataclass
class NextStepFinalOutput:
    """Agent produced a final output."""
    output: Any


@dataclass
class NextStepHandoff:
    """Agent handed off to another agent."""
    new_agent: Agent
    handoff_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class NextStepRunAgain:
    """Agent needs to run again."""
    pass


# =============================================================================
# EXCEPTIONS
# =============================================================================

class RunnerException(Exception):
    """Base exception for runner errors."""
    pass


class MaxTurnsExceeded(RunnerException):
    """Raised when max turns is exceeded."""
    pass


class InputGuardrailTriggered(RunnerException):
    """Raised when input guardrail blocks execution."""
    def __init__(self, result: InputGuardrailResult):
        self.result = result
        super().__init__(f"Input guardrail triggered: {result.guardrail_name}")


class OutputGuardrailTriggered(RunnerException):
    """Raised when output guardrail blocks execution."""
    def __init__(self, result: OutputGuardrailResult):
        self.result = result
        super().__init__(f"Output guardrail triggered: {result.guardrail_name}")


class ModelBehaviorError(RunnerException):
    """Raised when the model behaves unexpectedly."""
    pass


# =============================================================================
# GUARDRAILS
# =============================================================================

@dataclass
class GuardrailOutput:
    """Output from a guardrail check."""
    tripwire_triggered: bool = False
    message: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class InputGuardrailResult:
    """Result of an input guardrail check."""
    guardrail_name: str
    output: GuardrailOutput
    passed: bool = True


@dataclass
class OutputGuardrailResult:
    """Result of an output guardrail check."""
    guardrail_name: str
    output: GuardrailOutput
    passed: bool = True


class InputGuardrail(ABC, Generic[TContext]):
    """Abstract base class for input guardrails."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Guardrail name."""
        ...

    @abstractmethod
    async def run(
        self,
        agent: Agent,
        input_data: str | list[Any],
        context: RunContextWrapper[TContext],
    ) -> InputGuardrailResult:
        """Run the guardrail check."""
        ...

    def get_name(self) -> str:
        """Get the guardrail name."""
        return self.name


class OutputGuardrail(ABC, Generic[TContext]):
    """Abstract base class for output guardrails."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Guardrail name."""
        ...

    @abstractmethod
    async def run(
        self,
        agent: Agent,
        output_data: Any,
        context: RunContextWrapper[TContext],
    ) -> OutputGuardrailResult:
        """Run the guardrail check."""
        ...

    def get_name(self) -> str:
        """Get the guardrail name."""
        return self.name


# =============================================================================
# HANDOFFS
# =============================================================================

@dataclass
class HandoffInputData:
    """Input data for handoff filtering."""
    input_history: tuple[Any, ...] | str
    pre_handoff_items: tuple[RunItem, ...]
    new_items: tuple[RunItem, ...]


HandoffInputFilter = Callable[[HandoffInputData], HandoffInputData]


@dataclass
class Handoff:
    """Represents a handoff to another agent."""
    agent_name: str
    tool_name: str
    description: str
    agent: Agent
    input_filter: HandoffInputFilter | None = None

    async def on_invoke_handoff(
        self,
        context: RunContextWrapper,
        arguments: str,
    ) -> Agent:
        """Invoke the handoff and return the new agent."""
        return self.agent

    def get_transfer_message(self, agent: Agent) -> str:
        """Get the message to show on handoff."""
        return f"Transferred to {agent.name}"


def handoff(agent: Agent) -> Handoff:
    """Create a handoff to an agent."""
    tool_name = f"transfer_to_{agent.name.lower().replace(' ', '_')}"
    return Handoff(
        agent_name=agent.name,
        tool_name=tool_name,
        description=f"Transfer to {agent.name}",
        agent=agent,
    )


# =============================================================================
# RUN ITEMS
# =============================================================================

@dataclass
class RunItem:
    """Base class for items generated during a run."""
    agent: Agent

    def to_input_item(self) -> dict[str, Any]:
        """Convert to input item format."""
        return {}


@dataclass
class MessageOutputItem(RunItem):
    """A message output from the model."""
    raw_item: Any

    def to_input_item(self) -> dict[str, Any]:
        return {"type": "message", "content": self.raw_item}


@dataclass
class ToolCallItem(RunItem):
    """A tool call from the model."""
    raw_item: Any


@dataclass
class ToolCallOutputItem(RunItem):
    """Output from a tool call."""
    output: Any
    raw_item: Any


@dataclass
class HandoffCallItem(RunItem):
    """A handoff call from the model."""
    raw_item: Any


@dataclass
class HandoffOutputItem(RunItem):
    """Output from a handoff."""
    source_agent: Agent
    target_agent: Agent
    raw_item: Any


# =============================================================================
# MODEL RESPONSE
# =============================================================================

@dataclass
class Usage:
    """Token usage tracking."""
    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def add(self, other: Usage) -> None:
        """Add another usage to this one."""
        self.requests += other.requests
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.total_tokens += other.total_tokens


@dataclass
class ModelResponse:
    """Response from the model."""
    output: list[Any]
    usage: Usage
    referenceable_id: str | None = None


# =============================================================================
# TOOLS
# =============================================================================

@dataclass
class FunctionToolResult:
    """Result from executing a function tool."""
    tool: Tool
    output: Any
    run_item: ToolCallOutputItem


class Tool(ABC):
    """Abstract base class for tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Tool description."""
        ...

    @abstractmethod
    async def on_invoke_tool(
        self,
        context: RunContextWrapper,
        arguments: str,
    ) -> Any:
        """Execute the tool."""
        ...


class FunctionTool(Tool):
    """A tool backed by a Python function."""

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        input_schema: dict[str, Any] | None = None,
    ):
        self._name = name
        self._description = description
        self._func = func
        self._input_schema = input_schema or {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    async def on_invoke_tool(
        self,
        context: RunContextWrapper,
        arguments: str,
    ) -> Any:
        import json
        args = json.loads(arguments) if arguments else {}

        if asyncio.iscoroutinefunction(self._func):
            return await self._func(**args)
        return self._func(**args)


# =============================================================================
# AGENT
# =============================================================================

@dataclass
class ModelSettings:
    """Settings for the model."""
    model: str | None = None
    temperature: float = 0.7
    max_tokens: int = 4096
    tool_choice: str | None = None

    def resolve(self, other: ModelSettings | None) -> ModelSettings:
        """Resolve settings with another set of settings."""
        if not other:
            return self
        return ModelSettings(
            model=other.model or self.model,
            temperature=other.temperature if other.temperature != 0.7 else self.temperature,
            max_tokens=other.max_tokens if other.max_tokens != 4096 else self.max_tokens,
            tool_choice=other.tool_choice or self.tool_choice,
        )


@dataclass
class AgentHooks(Generic[TContext]):
    """Hooks for agent lifecycle events."""

    async def on_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
    ) -> None:
        """Called when agent starts."""
        pass

    async def on_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        output: Any,
    ) -> None:
        """Called when agent ends."""
        pass

    async def on_tool_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
    ) -> None:
        """Called before tool execution."""
        pass

    async def on_tool_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
        result: Any,
    ) -> None:
        """Called after tool execution."""
        pass

    async def on_handoff(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        source: Agent[TContext],
    ) -> None:
        """Called when receiving a handoff."""
        pass


class Agent(Generic[TContext]):
    """
    An agent that can use tools and hand off to other agents.

    This is the core unit of execution in the Runner pattern.
    """

    def __init__(
        self,
        name: str,
        instructions: str | Callable[[TContext], str] | None = None,
        tools: list[Tool] | None = None,
        handoffs: list[Agent | Handoff] | None = None,
        output_type: type | None = None,
        model: str | None = None,
        model_settings: ModelSettings | None = None,
        input_guardrails: list[InputGuardrail[TContext]] | None = None,
        output_guardrails: list[OutputGuardrail[TContext]] | None = None,
        hooks: AgentHooks[TContext] | None = None,
        reset_tool_choice: bool = True,
        tool_use_behavior: str = "run_llm_again",
    ):
        self.name = name
        self._instructions = instructions
        self._tools = tools or []
        self.handoffs = handoffs or []
        self.output_type = output_type
        self.model = model
        self.model_settings = model_settings or ModelSettings()
        self.input_guardrails = input_guardrails or []
        self.output_guardrails = output_guardrails or []
        self.hooks = hooks
        self.reset_tool_choice = reset_tool_choice
        self.tool_use_behavior = tool_use_behavior

    async def get_system_prompt(
        self,
        context: RunContextWrapper[TContext],
    ) -> str | None:
        """Get the system prompt for this agent."""
        if self._instructions is None:
            return None
        if callable(self._instructions):
            return self._instructions(context.context)
        return self._instructions

    async def get_all_tools(self) -> list[Tool]:
        """Get all tools available to this agent."""
        return list(self._tools)


# =============================================================================
# RUN CONTEXT
# =============================================================================

@dataclass
class RunContextWrapper(Generic[TContext]):
    """Wrapper around the run context."""
    context: TContext | None = None
    usage: Usage = field(default_factory=Usage)


# =============================================================================
# RUN HOOKS
# =============================================================================

@dataclass
class RunHooks(Generic[TContext]):
    """Hooks for run lifecycle events."""

    async def on_agent_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
    ) -> None:
        """Called when an agent starts."""
        pass

    async def on_agent_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        output: Any,
    ) -> None:
        """Called when an agent ends."""
        pass

    async def on_tool_start(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
    ) -> None:
        """Called before tool execution."""
        pass

    async def on_tool_end(
        self,
        context: RunContextWrapper[TContext],
        agent: Agent[TContext],
        tool: Tool,
        result: Any,
    ) -> None:
        """Called after tool execution."""
        pass

    async def on_handoff(
        self,
        context: RunContextWrapper[TContext],
        from_agent: Agent[TContext],
        to_agent: Agent[TContext],
    ) -> None:
        """Called when a handoff occurs."""
        pass


# =============================================================================
# TRACING
# =============================================================================

@dataclass
class SpanError:
    """Error information for a span."""
    message: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class SpanData:
    """Data for a span."""
    tools: list[str] = field(default_factory=list)
    handoffs: list[str] = field(default_factory=list)
    output_type: str = "str"


class Span:
    """A tracing span."""

    def __init__(
        self,
        name: str,
        span_id: str | None = None,
        parent_id: str | None = None,
    ):
        self.name = name
        self.span_id = span_id or uuid.uuid4().hex[:16]
        self.parent_id = parent_id
        self.span_data = SpanData()
        self._started_at: datetime | None = None
        self._ended_at: datetime | None = None
        self._error: SpanError | None = None

    def start(self, mark_as_current: bool = False) -> None:
        """Start the span."""
        self._started_at = datetime.now(UTC)

    def finish(self, reset_current: bool = False) -> None:
        """Finish the span."""
        self._ended_at = datetime.now(UTC)

    def set_error(self, error: SpanError) -> None:
        """Set error on the span."""
        self._error = error


class Trace:
    """A trace containing multiple spans."""

    def __init__(
        self,
        trace_id: str | None = None,
        workflow_name: str = "Agent workflow",
        group_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        disabled: bool = False,
    ):
        self.trace_id = trace_id or uuid.uuid4().hex
        self.workflow_name = workflow_name
        self.group_id = group_id
        self.metadata = metadata or {}
        self.disabled = disabled
        self._started = False

    def start(self, mark_as_current: bool = False) -> None:
        """Start the trace."""
        self._started = True

    def finish(self, reset_current: bool = False) -> None:
        """Finish the trace."""
        pass


def agent_span(
    name: str,
    handoffs: list[str] | None = None,
    output_type: str = "str",
) -> Span:
    """Create an agent span."""
    span = Span(name=name)
    span.span_data.handoffs = handoffs or []
    span.span_data.output_type = output_type
    return span


def trace(
    workflow_name: str = "Agent workflow",
    trace_id: str | None = None,
    group_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    disabled: bool = False,
) -> Trace:
    """Create a trace."""
    return Trace(
        trace_id=trace_id,
        workflow_name=workflow_name,
        group_id=group_id,
        metadata=metadata,
        disabled=disabled,
    )


_current_trace: Trace | None = None


def get_current_trace() -> Trace | None:
    """Get the current trace."""
    return _current_trace


class TraceCtxManager:
    """Context manager for traces."""

    def __init__(
        self,
        workflow_name: str,
        trace_id: str | None,
        group_id: str | None,
        metadata: dict[str, Any] | None,
        disabled: bool,
    ):
        self.trace: Trace | None = None
        self.workflow_name = workflow_name
        self.trace_id = trace_id
        self.group_id = group_id
        self.metadata = metadata
        self.disabled = disabled

    def __enter__(self) -> TraceCtxManager:
        global _current_trace
        current_trace = get_current_trace()
        if not current_trace:
            self.trace = trace(
                workflow_name=self.workflow_name,
                trace_id=self.trace_id,
                group_id=self.group_id,
                metadata=self.metadata,
                disabled=self.disabled,
            )
            self.trace.start(mark_as_current=True)
            _current_trace = self.trace
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        global _current_trace
        if self.trace:
            self.trace.finish(reset_current=True)
            _current_trace = None


# =============================================================================
# MODEL PROVIDER
# =============================================================================

class ModelProvider(ABC):
    """Abstract base class for model providers."""

    @abstractmethod
    def get_model(self, model_name: str) -> Model:
        """Get a model by name."""
        ...


class Model(ABC):
    """Abstract base class for models."""

    @abstractmethod
    async def get_response(
        self,
        system_instructions: str | None,
        input_items: list[Any],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: Any,
        handoffs: list[Handoff],
        tracing: Any,
    ) -> ModelResponse:
        """Get a response from the model."""
        ...


class AnthropicModelProvider(ModelProvider):
    """Anthropic model provider using Claude SDK."""

    def __init__(self, settings: InfernoSettings | None = None):
        self._settings = settings or InfernoSettings()
        self._models: dict[str, AnthropicModel] = {}

    def get_model(self, model_name: str) -> AnthropicModel:
        """Get an Anthropic model."""
        if model_name not in self._models:
            self._models[model_name] = AnthropicModel(model_name, self._settings)
        return self._models[model_name]


class AnthropicModel(Model):
    """Anthropic model implementation."""

    def __init__(self, model_name: str, settings: InfernoSettings):
        self.model_name = model_name
        self._settings = settings
        self._client: AsyncAnthropic | None = None

    async def _get_client(self) -> AsyncAnthropic:
        """Get or create the Anthropic client."""
        if self._client is None:
            from anthropic import AsyncAnthropic

            from inferno.auth.credentials import get_credential_manager

            cred_manager = get_credential_manager()
            credential = cred_manager.get_credential()

            if credential.is_oauth:
                self._client = AsyncAnthropic(auth_token=credential.get_value())
            else:
                self._client = AsyncAnthropic(api_key=credential.get_value())

        return self._client

    async def get_response(
        self,
        system_instructions: str | None,
        input_items: list[Any],
        model_settings: ModelSettings,
        tools: list[Tool],
        output_schema: Any,
        handoffs: list[Handoff],
        tracing: Any,
    ) -> ModelResponse:
        """Get a response from Claude."""
        client = await self._get_client()

        # Build messages
        messages = self._build_messages(input_items)

        # Build tool definitions
        tool_defs = self._build_tools(tools, handoffs)

        # Make API call
        from inferno.config.settings import get_beta_headers
        beta_headers = get_beta_headers(model=self.model_name)

        response = await client.beta.messages.create(
            model=model_settings.model or self.model_name,
            max_tokens=model_settings.max_tokens,
            temperature=model_settings.temperature,
            system=system_instructions or "",
            messages=messages,
            tools=tool_defs if tool_defs else None,
            betas=beta_headers,
        )

        # Extract usage
        usage = Usage(
            requests=1,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
        )

        return ModelResponse(
            output=list(response.content),
            usage=usage,
            referenceable_id=response.id,
        )

    def _build_messages(self, input_items: list[Any]) -> list[MessageParam]:
        """Build messages from input items."""
        messages = []
        for item in input_items:
            if isinstance(item, str):
                messages.append({"role": "user", "content": item})
            elif isinstance(item, dict):
                messages.append(item)
            elif hasattr(item, "to_input_item"):
                messages.append(item.to_input_item())
        return messages

    def _build_tools(
        self,
        tools: list[Tool],
        handoffs: list[Handoff],
    ) -> list[dict[str, Any]]:
        """Build tool definitions."""
        tool_defs = []

        for tool in tools:
            tool_defs.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": getattr(tool, "_input_schema", {"type": "object", "properties": {}}),
            })

        for handoff_item in handoffs:
            tool_defs.append({
                "name": handoff_item.tool_name,
                "description": handoff_item.description,
                "input_schema": {"type": "object", "properties": {}},
            })

        return tool_defs


# =============================================================================
# RUN CONFIG
# =============================================================================

@dataclass
class RunConfig:
    """Configuration for an agent run."""

    model: str | Model | None = None
    """The model to use for the entire agent run."""

    model_provider: ModelProvider = field(default_factory=AnthropicModelProvider)
    """The model provider to use when looking up string model names."""

    model_settings: ModelSettings | None = None
    """Configure global model settings."""

    handoff_input_filter: HandoffInputFilter | None = None
    """A global input filter to apply to all handoffs."""

    input_guardrails: list[InputGuardrail[Any]] | None = None
    """A list of input guardrails to run on the initial run input."""

    output_guardrails: list[OutputGuardrail[Any]] | None = None
    """A list of output guardrails to run on the final output of the run."""

    tracing_disabled: bool = False
    """Whether tracing is disabled for the agent run."""

    trace_include_sensitive_data: bool = True
    """Whether we include potentially sensitive data in traces."""

    workflow_name: str = "Agent workflow"
    """The name of the run, used for tracing."""

    trace_id: str | None = None
    """A custom trace ID to use for tracing."""

    group_id: str | None = None
    """A grouping identifier to use for tracing."""

    trace_metadata: dict[str, Any] | None = None
    """Additional metadata to include with the trace."""


# =============================================================================
# RUN RESULT
# =============================================================================

@dataclass
class RunResult:
    """Result of an agent run."""

    input: str | list[Any]
    """The original input."""

    new_items: list[RunItem]
    """Items generated during the run."""

    raw_responses: list[ModelResponse]
    """Raw model responses."""

    final_output: Any
    """The final output from the agent."""

    _last_agent: Agent
    """The last agent that ran."""

    input_guardrail_results: list[InputGuardrailResult] = field(default_factory=list)
    """Results from input guardrails."""

    output_guardrail_results: list[OutputGuardrailResult] = field(default_factory=list)
    """Results from output guardrails."""

    @property
    def last_agent(self) -> Agent:
        """Get the last agent that ran."""
        return self._last_agent

    @property
    def total_usage(self) -> Usage:
        """Get total token usage."""
        total = Usage()
        for response in self.raw_responses:
            total.add(response.usage)
        return total


# =============================================================================
# SINGLE STEP RESULT
# =============================================================================

@dataclass
class SingleStepResult:
    """Result of a single step in the agent loop."""

    original_input: str | list[Any]
    """The input items before run() was called."""

    model_response: ModelResponse
    """The model response for the current step."""

    pre_step_items: list[RunItem]
    """Items generated before the current step."""

    new_step_items: list[RunItem]
    """Items generated during this current step."""

    next_step: NextStepFinalOutput | NextStepHandoff | NextStepRunAgain
    """The next step to take."""

    @property
    def generated_items(self) -> list[RunItem]:
        """Items generated during the agent run."""
        return self.pre_step_items + self.new_step_items


# =============================================================================
# TOOL USE TRACKER
# =============================================================================

@dataclass
class AgentToolUseTracker:
    """Tracks tool usage by agents."""

    agent_to_tools: list[tuple[Agent, list[str]]] = field(default_factory=list)
    """Tuple of (agent, list of tools used)."""

    def add_tool_use(self, agent: Agent[Any], tool_names: list[str]) -> None:
        """Add tool usage for an agent."""
        existing_data = next(
            (item for item in self.agent_to_tools if item[0] == agent),
            None,
        )
        if existing_data:
            existing_data[1].extend(tool_names)
        else:
            self.agent_to_tools.append((agent, tool_names))

    def has_used_tools(self, agent: Agent[Any]) -> bool:
        """Check if an agent has used tools."""
        existing_data = next(
            (item for item in self.agent_to_tools if item[0] == agent),
            None,
        )
        return existing_data is not None and len(existing_data[1]) > 0


# =============================================================================
# ASYNC UTILITIES
# =============================================================================

async def noop_coroutine() -> None:
    """A no-op coroutine."""
    pass


# =============================================================================
# RUNNER
# =============================================================================

class Runner:
    """
    The main runner class for executing agents.

    This is the unified entry point for running agents with support for:
    - Claude SDK with OAuth authentication
    - Parallel tool execution
    - Input/output guardrails
    - Handoffs between agents
    - Distributed tracing

    Example:
        agent = Agent(
            name="pentest_agent",
            instructions="You are a penetration testing assistant.",
            tools=[execute_command_tool, http_request_tool],
        )

        result = await Runner.run(
            starting_agent=agent,
            input="Find vulnerabilities in https://target.com",
        )

        print(result.final_output)
    """

    @classmethod
    async def run(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[Any],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """
        Run a workflow starting at the given agent.

        The agent will run in a loop until a final output is generated.
        The loop runs like so:
        1. The agent is invoked with the given input.
        2. If there is a final output, the loop terminates.
        3. If there's a handoff, we run the loop again with the new agent.
        4. Else, we run tool calls (if any), and re-run the loop.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run.
            hooks: An object that receives callbacks on lifecycle events.
            run_config: Global settings for the entire agent run.

        Returns:
            A run result containing all the inputs, guardrail results and output.

        Raises:
            MaxTurnsExceeded: If max_turns is exceeded.
            InputGuardrailTriggered: If an input guardrail blocks execution.
            OutputGuardrailTriggered: If an output guardrail blocks execution.
        """
        if hooks is None:
            hooks = RunHooks[Any]()
        if run_config is None:
            run_config = RunConfig()

        tool_use_tracker = AgentToolUseTracker()

        with TraceCtxManager(
            workflow_name=run_config.workflow_name,
            trace_id=run_config.trace_id,
            group_id=run_config.group_id,
            metadata=run_config.trace_metadata,
            disabled=run_config.tracing_disabled,
        ):
            current_turn = 0
            original_input: str | list[Any] = copy.deepcopy(input)
            generated_items: list[RunItem] = []
            model_responses: list[ModelResponse] = []

            context_wrapper: RunContextWrapper[TContext] = RunContextWrapper(
                context=context,  # type: ignore
            )

            input_guardrail_results: list[InputGuardrailResult] = []

            current_span: Span | None = None
            current_agent = starting_agent
            should_run_agent_start_hooks = True

            try:
                while True:
                    # Start an agent span if we don't have one
                    if current_span is None:
                        handoff_names = [h.agent_name for h in cls._get_handoffs(current_agent)]
                        output_type_name = "str"
                        if current_agent.output_type:
                            output_type_name = current_agent.output_type.__name__

                        current_span = agent_span(
                            name=current_agent.name,
                            handoffs=handoff_names,
                            output_type=output_type_name,
                        )
                        current_span.start(mark_as_current=True)

                        all_tools = await cls._get_all_tools(current_agent)
                        current_span.span_data.tools = [t.name for t in all_tools]

                    current_turn += 1
                    if current_turn > max_turns:
                        current_span.set_error(SpanError(
                            message="Max turns exceeded",
                            data={"max_turns": max_turns},
                        ))
                        raise MaxTurnsExceeded(f"Max turns ({max_turns}) exceeded")

                    logger.debug(
                        f"Running agent {current_agent.name} (turn {current_turn})",
                    )

                    if current_turn == 1:
                        # Run input guardrails and first turn in parallel
                        input_guardrail_results, turn_result = await asyncio.gather(
                            cls._run_input_guardrails(
                                starting_agent,
                                starting_agent.input_guardrails
                                + (run_config.input_guardrails or []),
                                copy.deepcopy(input),
                                context_wrapper,
                            ),
                            cls._run_single_turn(
                                agent=current_agent,
                                all_tools=all_tools,
                                original_input=original_input,
                                generated_items=generated_items,
                                hooks=hooks,
                                context_wrapper=context_wrapper,
                                run_config=run_config,
                                should_run_agent_start_hooks=should_run_agent_start_hooks,
                                tool_use_tracker=tool_use_tracker,
                            ),
                        )
                    else:
                        turn_result = await cls._run_single_turn(
                            agent=current_agent,
                            all_tools=all_tools,
                            original_input=original_input,
                            generated_items=generated_items,
                            hooks=hooks,
                            context_wrapper=context_wrapper,
                            run_config=run_config,
                            should_run_agent_start_hooks=should_run_agent_start_hooks,
                            tool_use_tracker=tool_use_tracker,
                        )
                    should_run_agent_start_hooks = False

                    model_responses.append(turn_result.model_response)
                    original_input = turn_result.original_input
                    generated_items = turn_result.generated_items

                    if isinstance(turn_result.next_step, NextStepFinalOutput):
                        output_guardrail_results = await cls._run_output_guardrails(
                            current_agent.output_guardrails + (run_config.output_guardrails or []),
                            current_agent,
                            turn_result.next_step.output,
                            context_wrapper,
                        )
                        return RunResult(
                            input=original_input,
                            new_items=generated_items,
                            raw_responses=model_responses,
                            final_output=turn_result.next_step.output,
                            _last_agent=current_agent,
                            input_guardrail_results=input_guardrail_results,
                            output_guardrail_results=output_guardrail_results,
                        )
                    elif isinstance(turn_result.next_step, NextStepHandoff):
                        previous_agent = current_agent
                        current_agent = cast("Agent[TContext]", turn_result.next_step.new_agent)

                        current_span.finish(reset_current=True)
                        current_span = None
                        should_run_agent_start_hooks = True
                    elif isinstance(turn_result.next_step, NextStepRunAgain):
                        pass
                    else:
                        raise RunnerException(
                            f"Unknown next step type: {type(turn_result.next_step)}"
                        )
            finally:
                if current_span:
                    current_span.finish(reset_current=True)

    @classmethod
    def run_sync(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[Any],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
    ) -> RunResult:
        """
        Run a workflow synchronously.

        Note: This wraps the async run() method and will not work if there's
        already an event loop (e.g., inside an async function).
        """
        return asyncio.get_event_loop().run_until_complete(
            cls.run(
                starting_agent,
                input,
                context=context,
                max_turns=max_turns,
                hooks=hooks,
                run_config=run_config,
            )
        )

    @classmethod
    async def _run_input_guardrails(
        cls,
        agent: Agent[Any],
        guardrails: list[InputGuardrail[TContext]],
        input_data: str | list[Any],
        context: RunContextWrapper[TContext],
    ) -> list[InputGuardrailResult]:
        """Run input guardrails in parallel."""
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                guardrail.run(agent, input_data, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered
                for t in guardrail_tasks:
                    t.cancel()
                raise InputGuardrailTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _run_output_guardrails(
        cls,
        guardrails: list[OutputGuardrail[TContext]],
        agent: Agent[TContext],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> list[OutputGuardrailResult]:
        """Run output guardrails in parallel."""
        if not guardrails:
            return []

        guardrail_tasks = [
            asyncio.create_task(
                guardrail.run(agent, agent_output, context)
            )
            for guardrail in guardrails
        ]

        guardrail_results = []

        for done in asyncio.as_completed(guardrail_tasks):
            result = await done
            if result.output.tripwire_triggered:
                # Cancel all guardrail tasks if a tripwire is triggered
                for t in guardrail_tasks:
                    t.cancel()
                raise OutputGuardrailTriggered(result)
            else:
                guardrail_results.append(result)

        return guardrail_results

    @classmethod
    async def _run_single_turn(
        cls,
        *,
        agent: Agent[TContext],
        all_tools: list[Tool],
        original_input: str | list[Any],
        generated_items: list[RunItem],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        should_run_agent_start_hooks: bool,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        """Run a single turn of the agent loop."""
        # Run start hooks if needed
        if should_run_agent_start_hooks:
            await asyncio.gather(
                hooks.on_agent_start(context_wrapper, agent),
                (
                    agent.hooks.on_start(context_wrapper, agent)
                    if agent.hooks
                    else noop_coroutine()
                ),
            )

        system_prompt = await agent.get_system_prompt(context_wrapper)

        handoffs = cls._get_handoffs(agent)
        model = cls._get_model(agent, run_config)
        model_settings = agent.model_settings.resolve(run_config.model_settings)

        # Build input for model
        input_items = cls._build_input_items(original_input, generated_items)

        # Get model response
        new_response = await model.get_response(
            system_instructions=system_prompt,
            input_items=input_items,
            model_settings=model_settings,
            tools=all_tools,
            output_schema=None,
            handoffs=handoffs,
            tracing=None,
        )

        context_wrapper.usage.add(new_response.usage)

        # Process response
        return await cls._process_response(
            agent=agent,
            original_input=original_input,
            generated_items=generated_items,
            new_response=new_response,
            all_tools=all_tools,
            handoffs=handoffs,
            hooks=hooks,
            context_wrapper=context_wrapper,
            run_config=run_config,
            tool_use_tracker=tool_use_tracker,
        )

    @classmethod
    async def _process_response(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[Any],
        generated_items: list[RunItem],
        new_response: ModelResponse,
        all_tools: list[Tool],
        handoffs: list[Handoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
        tool_use_tracker: AgentToolUseTracker,
    ) -> SingleStepResult:
        """Process a model response."""
        pre_step_items = list(generated_items)
        new_step_items: list[RunItem] = []

        # Parse response for tool calls, messages, and handoffs
        tool_calls = []
        handoff_calls = []
        text_content = ""
        tools_used: list[str] = []

        tool_map = {tool.name: tool for tool in all_tools}
        handoff_map = {h.tool_name: h for h in handoffs}

        for block in new_response.output:
            if hasattr(block, "type"):
                if block.type == "text":
                    text_content += block.text
                    new_step_items.append(MessageOutputItem(
                        agent=agent,
                        raw_item=block,
                    ))
                elif block.type == "tool_use":
                    tools_used.append(block.name)
                    if block.name in handoff_map:
                        handoff_calls.append((block, handoff_map[block.name]))
                        new_step_items.append(HandoffCallItem(
                            agent=agent,
                            raw_item=block,
                        ))
                    elif block.name in tool_map:
                        tool_calls.append((block, tool_map[block.name]))
                        new_step_items.append(ToolCallItem(
                            agent=agent,
                            raw_item=block,
                        ))
                    else:
                        logger.warning(f"Unknown tool: {block.name}")

        tool_use_tracker.add_tool_use(agent, tools_used)

        # Execute tool calls in parallel
        if tool_calls:
            tool_results = await cls._execute_tool_calls(
                agent=agent,
                tool_calls=tool_calls,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )
            new_step_items.extend([r.run_item for r in tool_results])

        # Handle handoffs
        if handoff_calls:
            handoff_block, handoff_def = handoff_calls[0]  # Take first handoff
            new_agent = await handoff_def.on_invoke_handoff(
                context_wrapper,
                handoff_block.input if hasattr(handoff_block, 'input') else "{}",
            )

            new_step_items.append(HandoffOutputItem(
                agent=agent,
                source_agent=agent,
                target_agent=new_agent,
                raw_item=handoff_block,
            ))

            await asyncio.gather(
                hooks.on_handoff(context_wrapper, agent, new_agent),
                (
                    agent.hooks.on_handoff(context_wrapper, new_agent, agent)
                    if agent.hooks
                    else noop_coroutine()
                ),
            )

            return SingleStepResult(
                original_input=original_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepHandoff(new_agent),
            )

        # Check if we have a final output
        if not tool_calls:
            # No tool calls means final output
            await asyncio.gather(
                hooks.on_agent_end(context_wrapper, agent, text_content),
                (
                    agent.hooks.on_end(context_wrapper, agent, text_content)
                    if agent.hooks
                    else noop_coroutine()
                ),
            )

            return SingleStepResult(
                original_input=original_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepFinalOutput(text_content),
            )

        # Run again with tool results
        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepRunAgain(),
        )

    @classmethod
    async def _execute_tool_calls(
        cls,
        *,
        agent: Agent[TContext],
        tool_calls: list[tuple[Any, Tool]],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> list[FunctionToolResult]:
        """Execute tool calls in parallel."""

        async def run_single_tool(
            tool_block: Any,
            tool: Tool,
        ) -> FunctionToolResult:
            _, _, result = await asyncio.gather(
                hooks.on_tool_start(context_wrapper, agent, tool),
                (
                    agent.hooks.on_tool_start(context_wrapper, agent, tool)
                    if agent.hooks
                    else noop_coroutine()
                ),
                tool.on_invoke_tool(
                    context_wrapper,
                    tool_block.input if hasattr(tool_block, 'input') else "{}",
                ),
            )

            await asyncio.gather(
                hooks.on_tool_end(context_wrapper, agent, tool, result),
                (
                    agent.hooks.on_tool_end(context_wrapper, agent, tool, result)
                    if agent.hooks
                    else noop_coroutine()
                ),
            )

            return FunctionToolResult(
                tool=tool,
                output=result,
                run_item=ToolCallOutputItem(
                    agent=agent,
                    output=result,
                    raw_item={
                        "type": "tool_result",
                        "tool_use_id": tool_block.id if hasattr(tool_block, 'id') else "",
                        "content": str(result),
                    },
                ),
            )

        # Execute all tools in parallel
        tasks = [
            asyncio.create_task(run_single_tool(block, tool))
            for block, tool in tool_calls
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        tool_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Tool execution error: {result}")
                # Create error result
                block, tool = tool_calls[i]
                tool_results.append(FunctionToolResult(
                    tool=tool,
                    output=f"Error: {result}",
                    run_item=ToolCallOutputItem(
                        agent=agent,
                        output=f"Error: {result}",
                        raw_item={
                            "type": "tool_result",
                            "tool_use_id": block.id if hasattr(block, 'id') else "",
                            "content": f"Error: {result}",
                            "is_error": True,
                        },
                    ),
                ))
            else:
                tool_results.append(result)

        return tool_results

    @classmethod
    def _build_input_items(
        cls,
        original_input: str | list[Any],
        generated_items: list[RunItem],
    ) -> list[Any]:
        """Build input items for model call."""
        items = []

        if isinstance(original_input, str):
            items.append({"role": "user", "content": original_input})
        elif isinstance(original_input, list):
            items.extend(original_input)

        for item in generated_items:
            items.append(item.to_input_item())

        return items

    @classmethod
    def _get_handoffs(cls, agent: Agent[Any]) -> list[Handoff]:
        """Get handoffs for an agent."""
        handoffs = []
        for handoff_item in agent.handoffs:
            if isinstance(handoff_item, Handoff):
                handoffs.append(handoff_item)
            elif isinstance(handoff_item, Agent):
                handoffs.append(handoff(handoff_item))
        return handoffs

    @classmethod
    async def _get_all_tools(cls, agent: Agent[Any]) -> list[Tool]:
        """Get all tools for an agent."""
        return await agent.get_all_tools()

    @classmethod
    def _get_model(cls, agent: Agent[Any], run_config: RunConfig) -> Model:
        """Get the model for an agent."""
        if isinstance(run_config.model, Model):
            return run_config.model
        elif isinstance(run_config.model, str):
            return run_config.model_provider.get_model(run_config.model)
        elif isinstance(agent.model, Model):
            return agent.model
        elif agent.model:
            return run_config.model_provider.get_model(agent.model)
        else:
            # Default model
            return run_config.model_provider.get_model(ModelTier.SONNET_4_5.value)


# =============================================================================
# INFERNO RUNNER - SPECIALIZED VERSION
# =============================================================================

class InfernoRunner(Runner):
    """
    Inferno-specific runner with penetration testing features.

    Extends the base Runner with:
    - Integration with Inferno guardrails
    - Memory tool support
    - Branch tracking for systematic exploration
    - CTF mode optimizations

    Example:
        from inferno.runner import InfernoRunner, RunConfig
        from inferno.tools import execute_command, http_request, memory

        agent = Agent(
            name="pentest_agent",
            instructions="You are a penetration testing assistant.",
            tools=[execute_command, http_request, memory],
        )

        result = await InfernoRunner.run(
            starting_agent=agent,
            input="Find vulnerabilities in https://target.com",
            run_config=RunConfig(
                workflow_name="Pentest assessment",
            ),
        )
    """

    @classmethod
    async def run(
        cls,
        starting_agent: Agent[TContext],
        input: str | list[Any],
        *,
        context: TContext | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        hooks: RunHooks[TContext] | None = None,
        run_config: RunConfig | None = None,
        target: str | None = None,
        objective: str | None = None,
    ) -> RunResult:
        """
        Run an Inferno agent workflow.

        Args:
            starting_agent: The starting agent to run.
            input: The initial input to the agent.
            context: The context to run the agent with.
            max_turns: The maximum number of turns to run.
            hooks: An object that receives callbacks on lifecycle events.
            run_config: Global settings for the entire agent run.
            target: The target URL/hostname (for logging and memory).
            objective: The assessment objective.

        Returns:
            A run result containing all the inputs, guardrail results and output.
        """
        if run_config is None:
            run_config = RunConfig()

        # Add Inferno guardrails if available
        try:
            from inferno.core.guardrails import get_guardrail_engine

            engine = get_guardrail_engine()
            if engine.enabled:
                # Create guardrail adapters
                inferno_input_guardrail = InfernoInputGuardrail(engine)
                inferno_output_guardrail = InfernoOutputGuardrail(engine)

                if run_config.input_guardrails is None:
                    run_config.input_guardrails = []
                if run_config.output_guardrails is None:
                    run_config.output_guardrails = []

                run_config.input_guardrails.append(inferno_input_guardrail)
                run_config.output_guardrails.append(inferno_output_guardrail)
        except ImportError:
            pass

        # Set workflow name if not specified
        if run_config.workflow_name == "Agent workflow" and target:
            run_config.workflow_name = f"Inferno assessment: {target}"

        # Enhance input with objective if provided
        if objective and isinstance(input, str):
            enhanced_input = f"{input}\n\nObjective: {objective}"
        else:
            enhanced_input = input

        # Log start
        logger.info(
            "inferno_runner_start",
            target=target,
            objective=objective,
            max_turns=max_turns,
        )

        # Run the workflow
        return await super().run(
            starting_agent=starting_agent,
            input=enhanced_input,
            context=context,
            max_turns=max_turns,
            hooks=hooks,
            run_config=run_config,
        )


# =============================================================================
# INFERNO GUARDRAIL ADAPTERS
# =============================================================================

class InfernoInputGuardrail(InputGuardrail):
    """Adapter for Inferno guardrail engine as input guardrail."""

    def __init__(self, engine: Any):
        self._engine = engine

    @property
    def name(self) -> str:
        return "inferno_input_guardrail"

    async def run(
        self,
        agent: Agent,
        input_data: str | list[Any],
        context: RunContextWrapper,
    ) -> InputGuardrailResult:
        """Run the Inferno guardrail check."""
        content = str(input_data)
        result = self._engine.check_input(content)

        return InputGuardrailResult(
            guardrail_name=self.name,
            output=GuardrailOutput(
                tripwire_triggered=not result.allowed,
                message=result.message,
                data=result.context if hasattr(result, 'context') else {},
            ),
            passed=result.allowed,
        )


class InfernoOutputGuardrail(OutputGuardrail):
    """Adapter for Inferno guardrail engine as output guardrail."""

    def __init__(self, engine: Any):
        self._engine = engine

    @property
    def name(self) -> str:
        return "inferno_output_guardrail"

    async def run(
        self,
        agent: Agent,
        output_data: Any,
        context: RunContextWrapper,
    ) -> OutputGuardrailResult:
        """Run the Inferno guardrail check."""
        content = str(output_data)
        result = self._engine.check_output(content)

        return OutputGuardrailResult(
            guardrail_name=self.name,
            output=GuardrailOutput(
                tripwire_triggered=not result.allowed,
                message=result.message,
                data=result.context if hasattr(result, 'context') else {},
            ),
            passed=result.allowed,
        )


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Core types
    "NextStep",
    "NextStepFinalOutput",
    "NextStepHandoff",
    "NextStepRunAgain",

    # Exceptions
    "RunnerException",
    "MaxTurnsExceeded",
    "InputGuardrailTriggered",
    "OutputGuardrailTriggered",
    "ModelBehaviorError",

    # Guardrails
    "GuardrailOutput",
    "InputGuardrailResult",
    "OutputGuardrailResult",
    "InputGuardrail",
    "OutputGuardrail",

    # Handoffs
    "HandoffInputData",
    "HandoffInputFilter",
    "Handoff",
    "handoff",

    # Run items
    "RunItem",
    "MessageOutputItem",
    "ToolCallItem",
    "ToolCallOutputItem",
    "HandoffCallItem",
    "HandoffOutputItem",

    # Model types
    "Usage",
    "ModelResponse",
    "FunctionToolResult",
    "Tool",
    "FunctionTool",

    # Agent
    "ModelSettings",
    "AgentHooks",
    "Agent",

    # Context
    "RunContextWrapper",
    "RunHooks",

    # Tracing
    "SpanError",
    "SpanData",
    "Span",
    "Trace",
    "agent_span",
    "trace",
    "get_current_trace",
    "TraceCtxManager",

    # Model provider
    "ModelProvider",
    "Model",
    "AnthropicModelProvider",
    "AnthropicModel",

    # Config and result
    "RunConfig",
    "RunResult",
    "SingleStepResult",

    # Runner
    "Runner",
    "InfernoRunner",

    # Tool tracking
    "AgentToolUseTracker",

    # Constants
    "DEFAULT_MAX_TURNS",
    "DEFAULT_PRICE_LIMIT",
]
