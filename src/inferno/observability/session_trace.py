"""
Session Trace Log for Inferno.

Tracks complete session activity so users can see exactly what Inferno did,
how it made decisions, and what it found.

Features:
- Full session timeline
- Tool call tracking with inputs/outputs
- Agent reasoning capture
- Sub-agent spawn tracking
- Finding progression
- Exportable to JSON/HTML for review
"""

from __future__ import annotations

import json
import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class EventType(str, Enum):
    """Types of events in the session trace."""
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    AGENT_THINKING = "agent_thinking"
    AGENT_MESSAGE = "agent_message"
    SUBAGENT_SPAWN = "subagent_spawn"
    SUBAGENT_COMPLETE = "subagent_complete"
    FINDING = "finding"
    ERROR = "error"
    WAF_DETECTED = "waf_detected"
    BYPASS_ATTEMPT = "bypass_attempt"
    DECISION_POINT = "decision_point"
    BACKTRACK = "backtrack"
    USER_INPUT = "user_input"


@dataclass
class TraceEvent:
    """A single event in the session trace."""

    timestamp: str
    event_type: EventType
    title: str
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: float | None = None
    parent_id: str | None = None
    event_id: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%H%M%S%f"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "event_id": self.event_id,
            "title": self.title,
            "details": self.details,
            "duration_ms": self.duration_ms,
            "parent_id": self.parent_id,
        }


class SessionTrace:
    """
    Tracks a complete Inferno session for user review.

    Usage:
        trace = SessionTrace(target="example.com", objective="Find vulns")

        trace.log_tool_call("execute_command", {"command": "nmap ..."})
        trace.log_tool_result("execute_command", success=True, output="...")

        trace.log_thinking("Analyzing nmap results...")
        trace.log_finding("SQLi", severity="HIGH", endpoint="/api/users")

        trace.end_session()
        trace.save_json("session_trace.json")
        trace.save_html("session_trace.html")
    """

    def __init__(
        self,
        target: str,
        objective: str,
        operation_id: str | None = None,
        output_dir: Path | None = None,
    ) -> None:
        self._target = target
        self._objective = objective
        self._operation_id = operation_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._output_dir = output_dir or Path.home() / ".inferno" / "traces"
        self._output_dir.mkdir(parents=True, exist_ok=True)

        self._events: list[TraceEvent] = []
        self._start_time = datetime.now(timezone.utc)
        self._end_time: datetime | None = None

        # Tracking stats
        self._tool_calls = 0
        self._findings: list[dict] = []
        self._errors: list[dict] = []
        self._subagents_spawned = 0

        # Active tool tracking for duration
        self._active_tools: dict[str, datetime] = {}

        # Log session start
        self._log_event(
            EventType.SESSION_START,
            "Session Started",
            {
                "target": target,
                "objective": objective,
                "operation_id": self._operation_id,
            }
        )

        logger.info(
            "session_trace_started",
            operation_id=self._operation_id,
            target=target,
        )

    def _log_event(
        self,
        event_type: EventType,
        title: str,
        details: dict[str, Any] | None = None,
        duration_ms: float | None = None,
        parent_id: str | None = None,
    ) -> str:
        """Log an event and return its ID."""
        event = TraceEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            title=title,
            details=details or {},
            duration_ms=duration_ms,
            parent_id=parent_id,
        )
        self._events.append(event)
        return event.event_id

    # =========================================================================
    # TOOL TRACKING
    # =========================================================================

    def log_tool_call(
        self,
        tool_name: str,
        inputs: dict[str, Any],
        parent_id: str | None = None,
    ) -> str:
        """Log a tool being called."""
        self._tool_calls += 1
        self._active_tools[tool_name] = datetime.now(timezone.utc)

        # Truncate large inputs for readability
        clean_inputs = self._truncate_dict(inputs)

        return self._log_event(
            EventType.TOOL_CALL,
            f"Tool: {tool_name}",
            {
                "tool": tool_name,
                "inputs": clean_inputs,
                "call_number": self._tool_calls,
            },
            parent_id=parent_id,
        )

    def log_tool_result(
        self,
        tool_name: str,
        success: bool,
        output: str | None = None,
        error: str | None = None,
    ) -> str:
        """Log a tool's result."""
        # Calculate duration
        duration_ms = None
        if tool_name in self._active_tools:
            start = self._active_tools.pop(tool_name)
            duration_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        # Truncate large outputs
        clean_output = self._truncate_string(output, 2000) if output else None

        details = {
            "tool": tool_name,
            "success": success,
        }

        if clean_output:
            details["output"] = clean_output
        if error:
            details["error"] = error
            self._errors.append({"tool": tool_name, "error": error})

        return self._log_event(
            EventType.TOOL_RESULT,
            f"Result: {tool_name} ({'✓' if success else '✗'})",
            details,
            duration_ms=duration_ms,
        )

    # =========================================================================
    # AGENT TRACKING
    # =========================================================================

    def log_thinking(self, thought: str, context: str | None = None) -> str:
        """Log agent's reasoning/thinking."""
        return self._log_event(
            EventType.AGENT_THINKING,
            "Agent Thinking",
            {
                "thought": self._truncate_string(thought, 1000),
                "context": context,
            }
        )

    def log_message(self, message: str, role: str = "assistant") -> str:
        """Log an agent message."""
        return self._log_event(
            EventType.AGENT_MESSAGE,
            f"Message ({role})",
            {
                "message": self._truncate_string(message, 2000),
                "role": role,
            }
        )

    def log_decision(
        self,
        decision: str,
        options: list[str],
        chosen: str,
        reasoning: str | None = None,
    ) -> str:
        """Log a decision point."""
        return self._log_event(
            EventType.DECISION_POINT,
            f"Decision: {decision}",
            {
                "decision": decision,
                "options": options,
                "chosen": chosen,
                "reasoning": reasoning,
            }
        )

    def log_backtrack(self, from_path: str, to_path: str, reason: str) -> str:
        """Log a backtracking event."""
        return self._log_event(
            EventType.BACKTRACK,
            f"Backtrack: {reason}",
            {
                "from": from_path,
                "to": to_path,
                "reason": reason,
            }
        )

    # =========================================================================
    # SUB-AGENT TRACKING
    # =========================================================================

    def log_subagent_spawn(
        self,
        agent_type: str,
        task: str,
        context: str | None = None,
    ) -> str:
        """Log spawning a sub-agent."""
        self._subagents_spawned += 1

        return self._log_event(
            EventType.SUBAGENT_SPAWN,
            f"Spawn: {agent_type}",
            {
                "agent_type": agent_type,
                "task": self._truncate_string(task, 500),
                "context": context,
                "subagent_number": self._subagents_spawned,
            }
        )

    def log_subagent_complete(
        self,
        agent_type: str,
        success: bool,
        findings_count: int = 0,
        summary: str | None = None,
    ) -> str:
        """Log sub-agent completion."""
        return self._log_event(
            EventType.SUBAGENT_COMPLETE,
            f"Complete: {agent_type} ({'✓' if success else '✗'})",
            {
                "agent_type": agent_type,
                "success": success,
                "findings_count": findings_count,
                "summary": self._truncate_string(summary, 500) if summary else None,
            }
        )

    # =========================================================================
    # FINDING TRACKING
    # =========================================================================

    def log_finding(
        self,
        vuln_type: str,
        severity: str,
        endpoint: str,
        evidence: str | None = None,
        validated: bool = False,
    ) -> str:
        """Log a vulnerability finding."""
        finding = {
            "type": vuln_type,
            "severity": severity,
            "endpoint": endpoint,
            "evidence": self._truncate_string(evidence, 500) if evidence else None,
            "validated": validated,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._findings.append(finding)

        return self._log_event(
            EventType.FINDING,
            f"🔴 {severity}: {vuln_type}",
            finding,
        )

    def log_waf_detected(
        self,
        waf_type: str,
        endpoint: str,
        bypass_suggestions: list[str] | None = None,
    ) -> str:
        """Log WAF detection."""
        return self._log_event(
            EventType.WAF_DETECTED,
            f"WAF Detected: {waf_type}",
            {
                "waf_type": waf_type,
                "endpoint": endpoint,
                "bypass_suggestions": bypass_suggestions,
            }
        )

    def log_bypass_attempt(
        self,
        technique: str,
        success: bool,
        details: str | None = None,
    ) -> str:
        """Log a bypass attempt."""
        return self._log_event(
            EventType.BYPASS_ATTEMPT,
            f"Bypass: {technique} ({'✓' if success else '✗'})",
            {
                "technique": technique,
                "success": success,
                "details": details,
            }
        )

    # =========================================================================
    # ERROR TRACKING
    # =========================================================================

    def log_error(self, error: str, context: str | None = None) -> str:
        """Log an error."""
        self._errors.append({"error": error, "context": context})

        return self._log_event(
            EventType.ERROR,
            f"Error: {error[:50]}...",
            {
                "error": error,
                "context": context,
            }
        )

    # =========================================================================
    # SESSION MANAGEMENT
    # =========================================================================

    def end_session(self, summary: str | None = None) -> None:
        """End the session and calculate final stats."""
        self._end_time = datetime.now(timezone.utc)
        duration = (self._end_time - self._start_time).total_seconds()

        self._log_event(
            EventType.SESSION_END,
            "Session Ended",
            {
                "duration_seconds": round(duration, 2),
                "tool_calls": self._tool_calls,
                "findings_count": len(self._findings),
                "errors_count": len(self._errors),
                "subagents_spawned": self._subagents_spawned,
                "summary": summary,
            }
        )

        logger.info(
            "session_trace_ended",
            operation_id=self._operation_id,
            duration_seconds=round(duration, 2),
            findings=len(self._findings),
        )

    def get_summary(self) -> dict[str, Any]:
        """Get session summary statistics."""
        duration = 0
        if self._end_time:
            duration = (self._end_time - self._start_time).total_seconds()
        else:
            duration = (datetime.now(timezone.utc) - self._start_time).total_seconds()

        return {
            "operation_id": self._operation_id,
            "target": self._target,
            "objective": self._objective,
            "start_time": self._start_time.isoformat(),
            "end_time": self._end_time.isoformat() if self._end_time else None,
            "duration_seconds": round(duration, 2),
            "total_events": len(self._events),
            "tool_calls": self._tool_calls,
            "findings": self._findings,
            "findings_count": len(self._findings),
            "errors_count": len(self._errors),
            "subagents_spawned": self._subagents_spawned,
        }

    # =========================================================================
    # EXPORT METHODS
    # =========================================================================

    def save_json(self, filename: str | None = None) -> Path:
        """Save trace to JSON file."""
        if not filename:
            filename = f"trace_{self._operation_id}.json"

        filepath = self._output_dir / filename

        data = {
            "summary": self.get_summary(),
            "events": [e.to_dict() for e in self._events],
        }

        filepath.write_text(json.dumps(data, indent=2))
        logger.info("trace_saved_json", path=str(filepath))

        return filepath

    def save_html(self, filename: str | None = None) -> Path:
        """Save trace to interactive HTML file."""
        if not filename:
            filename = f"trace_{self._operation_id}.html"

        filepath = self._output_dir / filename

        html_content = self._generate_html()
        filepath.write_text(html_content)
        logger.info("trace_saved_html", path=str(filepath))

        return filepath

    def _generate_html(self) -> str:
        """Generate an interactive HTML trace viewer."""
        summary = self.get_summary()

        # Build events HTML
        events_html = []
        for event in self._events:
            event_class = self._get_event_class(event.event_type)
            icon = self._get_event_icon(event.event_type)

            details_html = ""
            if event.details:
                details_html = f"<pre class='details'>{html.escape(json.dumps(event.details, indent=2))}</pre>"

            duration_html = ""
            if event.duration_ms:
                duration_html = f"<span class='duration'>{event.duration_ms:.0f}ms</span>"

            events_html.append(f"""
            <div class="event {event_class}">
                <div class="event-header">
                    <span class="icon">{icon}</span>
                    <span class="time">{event.timestamp[11:19]}</span>
                    <span class="title">{html.escape(event.title)}</span>
                    {duration_html}
                </div>
                {details_html}
            </div>
            """)

        # Build findings HTML
        findings_html = ""
        if self._findings:
            findings_items = []
            for f in self._findings:
                severity_class = f['severity'].lower()
                findings_items.append(f"""
                <div class="finding {severity_class}">
                    <span class="severity">{f['severity']}</span>
                    <span class="type">{f['type']}</span>
                    <span class="endpoint">{html.escape(f['endpoint'])}</span>
                    {'<span class="validated">✓ Validated</span>' if f.get('validated') else ''}
                </div>
                """)
            findings_html = f"<div class='findings-list'>{''.join(findings_items)}</div>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inferno Session Trace - {html.escape(self._target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'SF Mono', 'Consolas', monospace;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            color: #ff6b35;
            font-size: 28px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .header h1::before {{ content: '🔥'; }}
        .target {{ color: #58a6ff; font-size: 18px; margin-bottom: 8px; }}
        .objective {{ color: #8b949e; font-size: 14px; }}

        /* Stats */
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }}
        .stat {{
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: 12px; color: #8b949e; text-transform: uppercase; }}
        .stat.findings .stat-value {{ color: #f85149; }}

        /* Findings Section */
        .findings-section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .findings-section h2 {{ color: #f85149; margin-bottom: 16px; }}
        .finding {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: #21262d;
            border-radius: 4px;
            margin-bottom: 8px;
        }}
        .finding .severity {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }}
        .finding.critical .severity {{ background: #f85149; color: white; }}
        .finding.high .severity {{ background: #db6d28; color: white; }}
        .finding.medium .severity {{ background: #d29922; color: black; }}
        .finding.low .severity {{ background: #3fb950; color: black; }}
        .finding .type {{ color: #c9d1d9; font-weight: bold; }}
        .finding .endpoint {{ color: #8b949e; font-family: monospace; }}
        .finding .validated {{ color: #3fb950; font-size: 12px; }}

        /* Timeline */
        .timeline {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
        }}
        .timeline h2 {{ color: #58a6ff; margin-bottom: 16px; }}

        /* Events */
        .event {{
            border-left: 3px solid #30363d;
            padding: 12px 16px;
            margin-left: 12px;
            margin-bottom: 8px;
            background: #21262d;
            border-radius: 0 6px 6px 0;
            transition: all 0.2s;
        }}
        .event:hover {{ background: #282e36; }}
        .event-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
        }}
        .event .icon {{ font-size: 16px; }}
        .event .time {{ color: #8b949e; font-size: 12px; }}
        .event .title {{ flex: 1; }}
        .event .duration {{
            color: #8b949e;
            font-size: 11px;
            background: #30363d;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        .event .details {{
            margin-top: 12px;
            padding: 12px;
            background: #0d1117;
            border-radius: 4px;
            font-size: 12px;
            overflow-x: auto;
            display: none;
        }}
        .event.expanded .details {{ display: block; }}

        /* Event Types */
        .event.tool_call {{ border-left-color: #58a6ff; }}
        .event.tool_result {{ border-left-color: #3fb950; }}
        .event.tool_result.error {{ border-left-color: #f85149; }}
        .event.agent_thinking {{ border-left-color: #a371f7; }}
        .event.finding {{ border-left-color: #f85149; background: #2d1f1f; }}
        .event.subagent_spawn {{ border-left-color: #d29922; }}
        .event.error {{ border-left-color: #f85149; background: #2d1f1f; }}
        .event.waf_detected {{ border-left-color: #db6d28; }}
        .event.session_start, .event.session_end {{ border-left-color: #ff6b35; }}

        /* Filter buttons */
        .filters {{
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 6px 12px;
            border: 1px solid #30363d;
            background: #21262d;
            color: #c9d1d9;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}
        .filter-btn:hover {{ background: #30363d; }}
        .filter-btn.active {{ background: #58a6ff; color: #0d1117; border-color: #58a6ff; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Inferno Session Trace</h1>
            <div class="target">Target: {html.escape(self._target)}</div>
            <div class="objective">Objective: {html.escape(self._objective)}</div>

            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{summary['duration_seconds']}s</div>
                    <div class="stat-label">Duration</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary['tool_calls']}</div>
                    <div class="stat-label">Tool Calls</div>
                </div>
                <div class="stat findings">
                    <div class="stat-value">{summary['findings_count']}</div>
                    <div class="stat-label">Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary['subagents_spawned']}</div>
                    <div class="stat-label">Sub-Agents</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary['total_events']}</div>
                    <div class="stat-label">Events</div>
                </div>
            </div>
        </div>

        {f'<div class="findings-section"><h2>🔴 Findings</h2>{findings_html}</div>' if self._findings else ''}

        <div class="timeline">
            <h2>📋 Session Timeline</h2>

            <div class="filters">
                <button class="filter-btn active" data-filter="all">All</button>
                <button class="filter-btn" data-filter="tool_call">Tools</button>
                <button class="filter-btn" data-filter="finding">Findings</button>
                <button class="filter-btn" data-filter="agent_thinking">Thinking</button>
                <button class="filter-btn" data-filter="subagent">Sub-Agents</button>
                <button class="filter-btn" data-filter="error">Errors</button>
            </div>

            <div class="events">
                {''.join(events_html)}
            </div>
        </div>
    </div>

    <script>
        // Toggle event details
        document.querySelectorAll('.event-header').forEach(header => {{
            header.addEventListener('click', () => {{
                header.parentElement.classList.toggle('expanded');
            }});
        }});

        // Filter events
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', () => {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');

                const filter = btn.dataset.filter;
                document.querySelectorAll('.event').forEach(event => {{
                    if (filter === 'all') {{
                        event.style.display = 'block';
                    }} else if (filter === 'subagent') {{
                        event.style.display = event.classList.contains('subagent_spawn') ||
                                              event.classList.contains('subagent_complete') ? 'block' : 'none';
                    }} else {{
                        event.style.display = event.classList.contains(filter) ? 'block' : 'none';
                    }}
                }});
            }});
        }});
    </script>
</body>
</html>"""

    def _get_event_class(self, event_type: EventType) -> str:
        """Get CSS class for event type."""
        return event_type.value

    def _get_event_icon(self, event_type: EventType) -> str:
        """Get icon for event type."""
        icons = {
            EventType.SESSION_START: "🚀",
            EventType.SESSION_END: "🏁",
            EventType.TOOL_CALL: "🔧",
            EventType.TOOL_RESULT: "📤",
            EventType.AGENT_THINKING: "💭",
            EventType.AGENT_MESSAGE: "💬",
            EventType.SUBAGENT_SPAWN: "🐝",
            EventType.SUBAGENT_COMPLETE: "✅",
            EventType.FINDING: "🔴",
            EventType.ERROR: "❌",
            EventType.WAF_DETECTED: "🛡️",
            EventType.BYPASS_ATTEMPT: "🔓",
            EventType.DECISION_POINT: "🔀",
            EventType.BACKTRACK: "↩️",
            EventType.USER_INPUT: "👤",
        }
        return icons.get(event_type, "•")

    def _truncate_string(self, s: str, max_len: int) -> str:
        """Truncate string to max length."""
        if not s:
            return s
        if len(s) <= max_len:
            return s
        return s[:max_len] + "..."

    def _truncate_dict(self, d: dict, max_str_len: int = 500) -> dict:
        """Truncate string values in a dict."""
        result = {}
        for k, v in d.items():
            if isinstance(v, str):
                result[k] = self._truncate_string(v, max_str_len)
            elif isinstance(v, dict):
                result[k] = self._truncate_dict(v, max_str_len)
            else:
                result[k] = v
        return result


# Global session trace
_session_trace: SessionTrace | None = None


def get_session_trace() -> SessionTrace | None:
    """Get the global session trace."""
    return _session_trace


def init_session_trace(
    target: str,
    objective: str,
    operation_id: str | None = None,
    output_dir: Path | None = None,
) -> SessionTrace:
    """Initialize the global session trace."""
    global _session_trace
    _session_trace = SessionTrace(
        target=target,
        objective=objective,
        operation_id=operation_id,
        output_dir=output_dir,
    )
    return _session_trace


def end_session_trace(summary: str | None = None) -> tuple[Path, Path] | None:
    """End the session trace and save files."""
    global _session_trace
    if _session_trace:
        _session_trace.end_session(summary)
        json_path = _session_trace.save_json()
        html_path = _session_trace.save_html()
        return json_path, html_path
    return None
