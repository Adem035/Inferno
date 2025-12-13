"""
Enhanced display components for Inferno CLI.

This module provides rich visual components for the CLI including
live dashboards, progress indicators, and formatted output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from rich.align import Align
from rich.box import DOUBLE, HEAVY, ROUNDED, SIMPLE
from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.layout import Layout
from rich.markdown import Markdown
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

# Security tool icons - more specific than generic
TOOL_ICONS = {
    # Core tools
    "shell": "🖥️",
    "Bash": "🖥️",
    "http_request": "🌐",
    "memory": "🧠",
    "editor": "📝",
    "stop": "🛑",
    # File operations
    "Read": "📖",
    "Write": "📝",
    "Edit": "✏️",
    "Glob": "📂",
    "Grep": "🔎",
    # Web tools
    "WebFetch": "🌐",
    "WebSearch": "🔍",
    "Task": "🤖",
    # Security tools - scanning
    "nmap_scan": "🔬",
    "nmap": "🔬",
    "masscan": "⚡",
    "rustscan": "🦀",
    # Security tools - web
    "gobuster": "🗂️",
    "ffuf": "💨",
    "feroxbuster": "🦊",
    "nikto": "🕷️",
    "wfuzz": "🌀",
    "dirsearch": "📁",
    # Security tools - vulnerability
    "nuclei": "☢️",
    "sqlmap": "💉",
    "xsstrike": "⚔️",
    # Security tools - credentials
    "hydra": "🐉",
    "john": "🔓",
    "hashcat": "🔨",
    # Security tools - git/secrets
    "git_dumper": "📦",
    "trufflehog": "🐷",
    "gitleaks": "🔐",
    # DNS/Subdomain
    "subfinder": "🔍",
    "amass": "🗺️",
    "dig": "⛏️",
    # Memory tools
    "mcp__inferno__memory_store": "💾",
    "mcp__inferno__memory_search": "🔎",
    "mcp__inferno__memory_list": "📃",
    "mcp__inferno__checkpoint": "✅",
    "mcp__inferno__store_evidence": "📸",
    # Default
    "default": "🔧",
}

# Severity colors and icons
SEVERITY_STYLES = {
    "critical": {"color": "bright_red", "icon": "🔴", "bg": "red"},
    "high": {"color": "red", "icon": "🟠", "bg": "dark_orange"},
    "medium": {"color": "yellow", "icon": "🟡", "bg": "yellow"},
    "low": {"color": "blue", "icon": "🔵", "bg": "blue"},
    "info": {"color": "cyan", "icon": "⚪", "bg": "cyan"},
}

# Assessment phases
PHASES = [
    ("🔍", "Reconnaissance", "recon"),
    ("📡", "Scanning", "scan"),
    ("🎯", "Enumeration", "enum"),
    ("💥", "Exploitation", "exploit"),
    ("📊", "Reporting", "report"),
]


def get_tool_icon(tool_name: str) -> str:
    """Get icon for a tool."""
    # Check direct match
    if tool_name in TOOL_ICONS:
        return TOOL_ICONS[tool_name]
    # Check lowercase
    if tool_name.lower() in TOOL_ICONS:
        return TOOL_ICONS[tool_name.lower()]
    # Check if it starts with known prefix
    for key in TOOL_ICONS:
        if tool_name.lower().startswith(key.lower()):
            return TOOL_ICONS[key]
    return TOOL_ICONS["default"]


@dataclass
class AssessmentMetrics:
    """Metrics for the current assessment."""

    target: str = ""
    objective: str = ""
    phase: str = "recon"
    turns: int = 0
    max_turns: int = 100
    tokens_used: int = 0
    max_tokens: int = 1_000_000
    tools_used: list[str] = field(default_factory=list)
    findings: dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    start_time: datetime = field(default_factory=datetime.now)
    current_tool: str = ""
    last_action: str = ""


class SeverityBar:
    """Visual bar showing findings by severity."""

    def __init__(self, findings: dict[str, int], width: int = 40):
        self.findings = findings
        self.width = width

    def __rich__(self) -> RenderableType:
        total = sum(self.findings.values())
        if total == 0:
            return Text("No findings yet", style="dim")

        # Build the bar
        bar_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = self.findings.get(severity, 0)
            if count > 0:
                proportion = count / total
                segment_width = max(1, int(proportion * self.width))
                style = SEVERITY_STYLES[severity]
                bar_parts.append(("█" * segment_width, style["color"]))

        # Create text with styled segments
        text = Text()
        for segment, color in bar_parts:
            text.append(segment, style=color)

        return text


class FindingsSummary:
    """Summary panel of findings by severity."""

    def __init__(self, findings: dict[str, int]):
        self.findings = findings

    def __rich__(self) -> Panel:
        total = sum(self.findings.values())

        # Create a mini table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Icon", width=2)
        table.add_column("Severity", width=10)
        table.add_column("Count", justify="right", width=4)

        for severity in ["critical", "high", "medium", "low", "info"]:
            count = self.findings.get(severity, 0)
            style = SEVERITY_STYLES[severity]
            if count > 0:
                table.add_row(
                    style["icon"],
                    Text(severity.upper(), style=f"bold {style['color']}"),
                    Text(str(count), style=style["color"]),
                )

        # Add total
        table.add_row("", Text("TOTAL", style="bold"), Text(str(total), style="bold"))

        return Panel(
            table,
            title="[bold]Findings[/bold]",
            border_style="cyan",
            box=ROUNDED,
        )


class PhaseIndicator:
    """Visual indicator of current assessment phase."""

    def __init__(self, current_phase: str = "recon"):
        self.current_phase = current_phase

    def __rich__(self) -> RenderableType:
        parts = []
        found_current = False

        for icon, name, phase_id in PHASES:
            if phase_id == self.current_phase:
                found_current = True
                parts.append(Text(f" {icon} {name} ", style="bold reverse cyan"))
            elif not found_current:
                parts.append(Text(f" {icon} {name} ", style="green dim"))
            else:
                parts.append(Text(f" {icon} {name} ", style="dim"))

            if phase_id != PHASES[-1][2]:
                parts.append(Text(" → ", style="dim"))

        text = Text()
        for part in parts:
            text.append(part)

        return text


class ToolCallDisplay:
    """Enhanced display for tool calls with full command visibility."""

    def __init__(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        verbose: bool = False,
        show_full_command: bool = True,  # Always show full command
    ):
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.verbose = verbose
        self.show_full_command = show_full_command

    def __rich__(self) -> RenderableType:
        icon = get_tool_icon(self.tool_name)
        clean_name = self.tool_name.replace("mcp__inferno__", "")

        # Build the display based on tool type
        if self.tool_name in ("Bash", "shell"):
            return self._format_bash()
        elif self.tool_name in ("Read", "Write", "Edit"):
            return self._format_file_op()
        elif self.tool_name in ("Glob", "Grep"):
            return self._format_search()
        elif self.tool_name == "WebFetch":
            return self._format_web()
        elif self.tool_name.startswith("nmap"):
            return self._format_nmap()
        elif self.tool_name == "gobuster":
            return self._format_gobuster()
        elif self.tool_name == "hydra":
            return self._format_hydra()
        elif self.tool_name == "git_dumper":
            return self._format_git_dumper()
        elif self.tool_name == "sqlmap":
            return self._format_sqlmap()
        else:
            return self._format_generic()

    def _format_bash(self) -> RenderableType:
        icon = get_tool_icon(self.tool_name)
        cmd = self.tool_input.get("command", "")
        desc = self.tool_input.get("description", "")

        # For multi-line or long commands, use a panel
        if "\n" in cmd or len(cmd) > 120:
            # Build title - keep it short
            title = f"[bold yellow]{icon} Shell[/bold yellow]"
            if desc:
                # Truncate description if too long for title
                desc_short = desc[:40] + "..." if len(desc) > 40 else desc
                title += f" [dim]({desc_short})[/dim]"

            # Show full command with syntax highlighting
            return Panel(
                Syntax(cmd, "bash", theme="monokai", line_numbers=False, word_wrap=True),
                title=title,
                border_style="yellow",
                box=ROUNDED,
                padding=(0, 1),
                width=min(100, len(cmd) + 6),  # Cap width at 100 chars
            )
        else:
            # Single line command - show inline but full
            text = Text()
            text.append(f"  {icon} ", style="bold")
            text.append("Shell", style="bold yellow")
            if desc:
                text.append(f" ({desc})", style="dim")
            text.append("\n")
            text.append("     $ ", style="green bold")
            text.append(cmd, style="white")  # Full command, no truncation
            return text

    def _format_file_op(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        path = self.tool_input.get("file_path", self.tool_input.get("path", ""))

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append(self.tool_name, style="bold yellow")
        text.append(" ")
        text.append(path, style="cyan")

        return text

    def _format_search(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        pattern = self.tool_input.get("pattern", "")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append(self.tool_name, style="bold yellow")
        text.append(" ")
        text.append(pattern, style="magenta")

        return text

    def _format_web(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        url = self.tool_input.get("url", "")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append("WebFetch", style="bold yellow")
        text.append(" ")
        text.append(url, style="blue underline")

        return text

    def _format_nmap(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        target = self.tool_input.get("target", "")
        scan_type = self.tool_input.get("scan_type", "service")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append("Nmap Scan", style="bold yellow")
        text.append(f" [{scan_type}] ", style="cyan")
        text.append(target, style="green")

        return text

    def _format_gobuster(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        url = self.tool_input.get("url", "")
        mode = self.tool_input.get("mode", "dir")
        wordlist = self.tool_input.get("wordlist", "common")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append("Gobuster", style="bold yellow")
        text.append(f" [{mode}] ", style="cyan")
        text.append(url, style="green")
        text.append(f" (wordlist: {wordlist})", style="dim")

        return text

    def _format_hydra(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        target = self.tool_input.get("target", "")
        protocol = self.tool_input.get("protocol", "ssh")
        username = self.tool_input.get("username", "")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append("Hydra", style="bold yellow")
        text.append(f" [{protocol}] ", style="red")
        text.append(target, style="green")
        if username:
            text.append(f" (user: {username})", style="dim")

        return text

    def _format_git_dumper(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        url = self.tool_input.get("url", "")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append("Git Dumper", style="bold yellow")
        text.append(" ")
        text.append(url, style="blue underline")

        return text

    def _format_sqlmap(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        url = self.tool_input.get("url", "")
        technique = self.tool_input.get("technique", "")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append("SQLMap", style="bold yellow")
        text.append(" ")
        text.append(url, style="blue")
        if technique:
            text.append(f" ({technique})", style="dim")

        return text

    def _format_generic(self) -> Text:
        icon = get_tool_icon(self.tool_name)
        clean_name = self.tool_name.replace("mcp__inferno__", "")

        text = Text()
        text.append(f"  {icon} ", style="bold")
        text.append(clean_name, style="bold yellow")

        # Show first meaningful parameter
        for key, value in self.tool_input.items():
            if value and key not in ("timeout", "verbose"):
                val_str = str(value)[:50]
                text.append(f" {key}=", style="dim")
                text.append(val_str, style="white")
                break

        return text


class ToolResultDisplay:
    """Enhanced display for tool results with full output in nice panels."""

    def __init__(
        self,
        tool_name: str,
        output: str,
        is_error: bool = False,
        max_lines: int = 0,  # 0 = show all (no truncation by default)
        show_panel: bool = True,  # Use panel for multi-line output
    ):
        self.tool_name = tool_name
        self.output = output
        self.is_error = is_error
        self.max_lines = max_lines  # 0 = unlimited
        self.show_panel = show_panel

    def __rich__(self) -> RenderableType:
        if not self.output.strip():
            return Text("     → (no output)", style="dim")

        lines = self.output.strip().split("\n")
        output_stripped = self.output.strip()

        if self.is_error:
            # Show full error in a red-bordered panel
            error_content = Text()
            for line in lines:
                error_content.append(f"{rich_escape(line)}\n", style="red")
            return Panel(
                error_content,
                title="[bold red]✗ Error[/bold red]",
                border_style="red",
                box=ROUNDED,
                padding=(0, 1),
            )

        # Check for JSON first (even if single line) - format nicely in panel
        if output_stripped.startswith("{") or output_stripped.startswith("["):
            try:
                import json
                # Pretty-print JSON
                parsed = json.loads(output_stripped)
                formatted_json = json.dumps(parsed, indent=2)
                return Panel(
                    Syntax(formatted_json, "json", theme="monokai", line_numbers=False, word_wrap=True),
                    title=f"[bold cyan]{get_tool_icon(self.tool_name)} Output (JSON)[/bold cyan]",
                    border_style="cyan",
                    box=ROUNDED,
                    padding=(0, 1),
                )
            except Exception:
                pass  # Not valid JSON, continue with normal display

        # Single line - show inline
        if len(lines) == 1:
            summary = Text()
            summary.append("     → ", style="dim green")
            summary.append(rich_escape(lines[0]), style="white")
            return summary

        # Multi-line output - determine best display format

        # Detect code/script output (common patterns)
        is_code = any([
            "#!/" in output_stripped[:50],  # Shebang
            "def " in output_stripped and ":" in output_stripped,  # Python
            "function " in output_stripped,  # JS/Bash
            output_stripped.startswith("<?php"),  # PHP
            "import " in output_stripped[:100],  # Python/JS imports
        ])

        # Apply truncation only if max_lines is set and > 0
        if self.max_lines > 0 and len(lines) > self.max_lines:
            display_lines = lines[:self.max_lines]
            remaining = len(lines) - self.max_lines
            truncated = True
        else:
            display_lines = lines
            remaining = 0
            truncated = False

        # Build output content
        if is_code:
            # Try to detect language for syntax highlighting
            lang = "python" if "def " in output_stripped else "bash"
            content = "\n".join(display_lines)
            if truncated:
                content += f"\n\n... ({remaining} more lines)"
            display = Syntax(content, lang, theme="monokai", line_numbers=True, word_wrap=True)
        else:
            # Regular output as text
            display_text = Text()
            for line in display_lines:
                # Highlight important patterns
                escaped_line = rich_escape(line)
                if any(kw in line.lower() for kw in ["error", "failed", "denied", "forbidden"]):
                    display_text.append(f"{escaped_line}\n", style="red")
                elif any(kw in line.lower() for kw in ["success", "found", "open", "200"]):
                    display_text.append(f"{escaped_line}\n", style="green")
                elif any(kw in line.lower() for kw in ["warning", "warn", "timeout"]):
                    display_text.append(f"{escaped_line}\n", style="yellow")
                elif line.startswith("[+]") or line.startswith("[*]"):
                    display_text.append(f"{escaped_line}\n", style="cyan")
                else:
                    display_text.append(f"{escaped_line}\n", style="white")

            if truncated:
                display_text.append(f"\n... ({remaining} more lines)", style="dim italic")
            display = display_text

        # Use panel for nicer display
        if self.show_panel and len(lines) > 3:
            icon = get_tool_icon(self.tool_name)
            clean_name = self.tool_name.replace("mcp__inferno__", "")
            line_info = f"{len(lines)} lines" if not truncated else f"{self.max_lines}/{len(lines)} lines"

            # Calculate reasonable width based on content
            max_line_len = max(len(line) for line in display_lines) if display_lines else 40
            panel_width = min(120, max(60, max_line_len + 4))  # Between 60-120 chars

            return Panel(
                display,
                title=f"[bold cyan]{icon} {clean_name}[/bold cyan]",
                subtitle=f"[dim]{line_info}[/dim]",
                border_style="blue",
                box=ROUNDED,
                padding=(0, 1),
                width=panel_width,
            )
        else:
            # Simple indented output for short results
            result = Text()
            result.append("     ", style="")
            for line in display_lines:
                result.append(f"     {rich_escape(line)}\n", style="dim")
            return result


class AssessmentDashboard:
    """Live dashboard for assessment progress."""

    def __init__(self, metrics: AssessmentMetrics):
        self.metrics = metrics

    def __rich__(self) -> Panel:
        # Create layout
        layout = Layout()

        # Top section: target and phase
        header = Table(show_header=False, box=None, expand=True)
        header.add_column("Label", style="dim", width=10)
        header.add_column("Value")

        header.add_row("Target:", Text(self.metrics.target, style="bold cyan"))
        header.add_row("Phase:", PhaseIndicator(self.metrics.phase))

        # Progress section
        budget_pct = 100 - (self.metrics.turns / max(self.metrics.max_turns, 1) * 100)
        progress_bar = Progress(
            TextColumn("[bold blue]Budget"),
            BarColumn(complete_style="green", finished_style="green"),
            TaskProgressColumn(),
            expand=True,
        )
        task = progress_bar.add_task("", total=100, completed=budget_pct)

        # Stats section
        stats = Table(show_header=False, box=None, padding=(0, 2))
        stats.add_column("Label", style="dim")
        stats.add_column("Value", justify="right")

        elapsed = (datetime.now() - self.metrics.start_time).total_seconds()
        stats.add_row("Turns:", f"{self.metrics.turns}/{self.metrics.max_turns}")
        stats.add_row("Elapsed:", f"{elapsed:.0f}s")
        stats.add_row("Tools:", str(len(set(self.metrics.tools_used))))

        # Current action
        action_text = Text()
        if self.metrics.current_tool:
            icon = get_tool_icon(self.metrics.current_tool)
            action_text.append(f"{icon} ", style="bold")
            action_text.append(self.metrics.current_tool, style="yellow")

        # Combine into group
        content = Group(
            header,
            Text(),
            progress_bar,
            Text(),
            Columns([stats, FindingsSummary(self.metrics.findings)]),
            Text(),
            Rule(style="dim"),
            action_text if self.metrics.current_tool else Text("Waiting...", style="dim"),
        )

        return Panel(
            content,
            title="[bold red]🔥 INFERNO[/bold red]",
            subtitle=f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim]",
            border_style="red",
            box=HEAVY,
        )


class CompletionSummary:
    """Beautiful completion summary card."""

    def __init__(
        self,
        objective_met: bool,
        findings: dict[str, int],
        duration_seconds: float,
        turns: int,
        cost_usd: float,
        confidence: int,
        artifacts_dir: str,
        findings_summary: str | None = None,
    ):
        self.objective_met = objective_met
        self.findings = findings
        self.duration = duration_seconds
        self.turns = turns
        self.cost = cost_usd
        self.confidence = confidence
        self.artifacts_dir = artifacts_dir
        self.findings_summary = findings_summary

    def __rich__(self) -> Group:
        # Status header
        if self.objective_met:
            status_text = Text("✓ OBJECTIVE ACHIEVED", style="bold green")
            status_style = "green"
        else:
            status_text = Text("○ ASSESSMENT COMPLETE", style="bold yellow")
            status_style = "yellow"

        # Stats table
        stats = Table(show_header=False, box=SIMPLE, padding=(0, 2))
        stats.add_column("Metric", style="dim")
        stats.add_column("Value", justify="right")

        stats.add_row("Duration", f"{self.duration:.1f}s")
        stats.add_row("Turns", str(self.turns))
        stats.add_row("Cost", f"${self.cost:.4f}")
        stats.add_row("Confidence", f"{self.confidence}%")
        stats.add_row("Artifacts", self.artifacts_dir)

        # Findings bar
        findings_total = sum(self.findings.values())
        findings_text = Text()
        findings_text.append(f"\n{findings_total} findings: ", style="bold")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self.findings.get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLES[sev]
                findings_text.append(f"{style['icon']}{count} ", style=style["color"])

        # Main panel
        main_panel = Panel(
            Group(
                Align.center(status_text),
                Text(),
                stats,
                SeverityBar(self.findings),
                findings_text,
            ),
            title="[bold]Assessment Complete[/bold]",
            border_style=status_style,
            box=DOUBLE,
        )

        elements = [main_panel]

        # Findings summary panel if available
        if self.findings_summary:
            summary_panel = Panel(
                Markdown(self.findings_summary[:2000]),
                title="[bold]Findings Summary[/bold]",
                border_style="cyan",
                box=ROUNDED,
            )
            elements.append(summary_panel)

        return Group(*elements)


def print_tool_call(
    console: Console,
    tool_name: str,
    tool_input: dict[str, Any],
    verbose: bool = False,
) -> None:
    """Print a formatted tool call."""
    display = ToolCallDisplay(tool_name, tool_input, verbose)
    console.print(display)


def print_tool_result(
    console: Console,
    tool_name: str,
    output: str,
    is_error: bool = False,
    max_lines: int = 10,
) -> None:
    """Print a formatted tool result."""
    display = ToolResultDisplay(tool_name, output, is_error, max_lines)
    console.print(display)


def print_phase_transition(console: Console, new_phase: str) -> None:
    """Print a phase transition indicator."""
    phase_info = next((p for p in PHASES if p[2] == new_phase), None)
    if phase_info:
        icon, name, _ = phase_info
        console.print()
        console.print(Rule(f"[bold cyan]{icon} {name} Phase[/bold cyan]", style="cyan"))
        console.print()


def print_finding(
    console: Console,
    title: str,
    severity: str,
    location: str,
    evidence: str | None = None,
) -> None:
    """Print a security finding."""
    style = SEVERITY_STYLES.get(severity.lower(), SEVERITY_STYLES["info"])

    finding_text = Text()
    finding_text.append(f"{style['icon']} ", style=style["color"])
    finding_text.append(f"[{severity.upper()}] ", style=f"bold {style['color']}")
    finding_text.append(title, style="bold")
    finding_text.append("\n   Location: ", style="dim")
    finding_text.append(location, style="cyan")

    if evidence:
        finding_text.append("\n   Evidence: ", style="dim")
        finding_text.append(evidence[:100], style="white")

    console.print(Panel(finding_text, border_style=style["color"], box=ROUNDED))


def create_scan_progress() -> Progress:
    """Create a progress bar for scanning operations."""
    return Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    )


class StartupDisplay:
    """Beautiful startup display for assessment initialization."""

    def __init__(
        self,
        target: str,
        objective: str,
        mode: str = "web",
        persona: str = "thorough",
        max_turns: int = 500,
    ):
        self.target = target
        self.objective = objective
        self.mode = mode
        self.persona = persona
        self.max_turns = max_turns
        self.features_enabled: list[str] = []
        self.subdomains: list[tuple[str, str]] = []  # (domain, ip)
        self.waf_detected: str | None = None
        self.memories_found: int = 0
        self.tools_available: int = 0
        self.tools_total: int = 0

    def add_feature(self, feature: str) -> None:
        """Add an enabled feature."""
        self.features_enabled.append(feature)

    def set_subdomains(self, subdomains: list[tuple[str, str]]) -> None:
        """Set discovered subdomains."""
        self.subdomains = subdomains

    def set_waf(self, waf: str | None) -> None:
        """Set detected WAF."""
        self.waf_detected = waf

    def set_memories(self, count: int) -> None:
        """Set number of relevant memories found."""
        self.memories_found = count

    def set_tools(self, available: int, total: int) -> None:
        """Set security tools count."""
        self.tools_available = available
        self.tools_total = total

    def __rich__(self) -> Panel:
        """Render startup display."""
        # Config table
        config_table = Table(show_header=False, box=None, padding=(0, 1))
        config_table.add_column("Label", style="dim", width=12)
        config_table.add_column("Value")

        config_table.add_row("Target", Text(self.target, style="bold cyan"))
        # Truncate objective if too long
        obj_display = self.objective[:80] + "..." if len(self.objective) > 80 else self.objective
        config_table.add_row("Objective", Text(obj_display, style="white"))
        config_table.add_row("Mode", Text(self.mode, style="yellow"))
        config_table.add_row("Persona", Text(self.persona, style="magenta"))
        config_table.add_row("Turns", Text(f"{self.max_turns} per segment", style="dim"))

        # Features line
        if self.features_enabled:
            features_text = Text()
            for i, f in enumerate(self.features_enabled):
                if i > 0:
                    features_text.append(", ", style="dim")
                features_text.append(f, style="green")
            config_table.add_row("AI Features", features_text)

        # Build content sections
        sections = [config_table]

        # Subdomains section
        if self.subdomains:
            subdomain_text = Text("\n")
            subdomain_text.append("🔍 Subdomains Found: ", style="bold")
            subdomain_text.append(f"{len(self.subdomains)}\n", style="cyan")
            for domain, ip in self.subdomains[:5]:  # Show max 5
                subdomain_text.append(f"   • {domain}", style="cyan")
                if ip:
                    subdomain_text.append(f" ({ip})", style="dim")
                subdomain_text.append("\n")
            if len(self.subdomains) > 5:
                subdomain_text.append(f"   ... and {len(self.subdomains) - 5} more\n", style="dim")
            sections.append(subdomain_text)

        # WAF detection
        waf_text = Text()
        waf_text.append("🛡️ WAF: ", style="bold")
        if self.waf_detected:
            waf_text.append(self.waf_detected, style="yellow")
        else:
            waf_text.append("None detected", style="green")
        sections.append(waf_text)

        # Memory section
        if self.memories_found > 0:
            mem_text = Text()
            mem_text.append("\n🧠 Memories: ", style="bold")
            mem_text.append(f"{self.memories_found} relevant findings from previous assessments", style="cyan")
            sections.append(mem_text)

        # Tools section
        if self.tools_available > 0:
            tools_text = Text()
            tools_text.append("\n🔧 Security Tools: ", style="bold")
            tools_text.append(f"{self.tools_available}/{self.tools_total} available", style="dim")
            sections.append(tools_text)

        return Panel(
            Group(*sections),
            title="[bold red]🔥 INFERNO[/bold red] [dim]Assessment Starting[/dim]",
            border_style="red",
            box=HEAVY,
        )


class MemoryDisplay:
    """Display for memory search results."""

    def __init__(self, memories: list[dict[str, Any]], max_display: int = 3):
        self.memories = memories
        self.max_display = max_display

    def __rich__(self) -> Panel:
        """Render memory display."""
        if not self.memories:
            return Panel(
                Text("No relevant memories found", style="dim"),
                title="[bold cyan]🧠 Memory Search[/bold cyan]",
                border_style="cyan",
                box=ROUNDED,
            )

        content = []
        for i, mem in enumerate(self.memories[:self.max_display]):
            mem_text = Text()
            score = mem.get("score", 0)
            content_preview = str(mem.get("content", ""))[:100]

            # Score indicator
            if score > 0.5:
                mem_text.append("● ", style="green")
            elif score > 0.3:
                mem_text.append("● ", style="yellow")
            else:
                mem_text.append("● ", style="dim")

            mem_text.append(f"[{score:.0%}] ", style="dim")
            mem_text.append(content_preview, style="white")
            if len(str(mem.get("content", ""))) > 100:
                mem_text.append("...", style="dim")

            content.append(mem_text)

        if len(self.memories) > self.max_display:
            remaining = len(self.memories) - self.max_display
            content.append(Text(f"\n... and {remaining} more memories", style="dim"))

        return Panel(
            Group(*content),
            title=f"[bold cyan]🧠 {len(self.memories)} Relevant Memories[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
        )


class InitProgressDisplay:
    """Progress display for initialization steps."""

    def __init__(self):
        self.steps: list[tuple[str, str, str | None]] = []  # (icon, label, status)

    def add_step(self, icon: str, label: str, status: str | None = None) -> None:
        """Add a completed step."""
        self.steps.append((icon, label, status))

    def __rich__(self) -> RenderableType:
        """Render progress display."""
        text = Text()
        for icon, label, status in self.steps:
            text.append(f"  {icon} ", style="bold")
            text.append(label, style="white")
            if status:
                text.append(f" {status}", style="dim")
            text.append("\n")
        return text


def print_startup_display(console: Console, display: StartupDisplay) -> None:
    """Print the startup display."""
    console.print(display)


def print_memory_results(console: Console, memories: list[dict[str, Any]]) -> None:
    """Print memory search results."""
    console.print(MemoryDisplay(memories))


def print_init_step(
    console: Console,
    icon: str,
    label: str,
    status: str | None = None,
    style: str = "white"
) -> None:
    """Print a single initialization step."""
    text = Text()
    text.append(f"  {icon} ", style="bold")
    text.append(label, style=style)
    if status:
        text.append(f" {status}", style="dim")
    console.print(text)
