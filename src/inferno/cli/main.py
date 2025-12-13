"""
CLI interface for Inferno.

This module provides the command-line interface for running
security assessments with the Inferno agent.

The CLI automatically handles setup on first run:
- Checks Docker is installed
- Starts Qdrant vector database container
- Guides through authentication
"""

from __future__ import annotations

import asyncio
import os
from typing import Annotated, Optional

# Suppress huggingface/tokenizers parallelism warning early
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import structlog
import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table

from inferno import __version__
from inferno.agent.sdk_executor import ExecutionResult
from inferno.auth.credentials import (
    CredentialError,
    CredentialManager,
    OAuthCredentialProvider,
)
from inferno.config.environment import discover_security_tools
from inferno.config.settings import InfernoSettings
from inferno.setup import DockerManager, SetupChecker, SetupStatus
from inferno.setup.checker import ComponentStatus

logger = structlog.get_logger(__name__)

# Create Typer app
app = typer.Typer(
    name="inferno",
    help="Inferno - Autonomous AI-powered Penetration Testing Agent",
    add_completion=False,
    rich_markup_mode="rich",
)

# Auth subcommand group
auth_app = typer.Typer(
    name="auth",
    help="Authentication management (OAuth login/logout)",
)
app.add_typer(auth_app, name="auth")

console = Console()


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"[bold blue]Inferno[/bold blue] version {__version__}")
        raise typer.Exit()


def print_banner() -> None:
    """Print the Inferno banner."""
    banner = """
[bold red]
    ██╗███╗   ██╗███████╗███████╗██████╗ ███╗   ██╗ ██████╗
    ██║████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║██╔═══██╗
    ██║██╔██╗ ██║█████╗  █████╗  ██████╔╝██╔██╗ ██║██║   ██║
    ██║██║╚██╗██║██╔══╝  ██╔══╝  ██╔══██╗██║╚██╗██║██║   ██║
    ██║██║ ╚████║██║     ███████╗██║  ██║██║ ╚████║╚██████╔╝
    ╚═╝╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝
[/bold red]
[dim]Autonomous AI-powered Penetration Testing Agent[/dim]
[dim]Version {version}[/dim]

[bold cyan]3 Tools[/bold cyan] [dim]•[/dim] [bold cyan]Kali Container[/bold cyan] [dim]•[/dim] [bold cyan]SecLists[/bold cyan] [dim]•[/dim] [bold cyan]Full Toolkit[/bold cyan]
    """.format(version=__version__)
    console.print(banner)


class OutputHandler:
    """Handler for formatting and displaying agent output."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.console = Console()
        self.tool_count = 0

    def on_message(self, message: str) -> None:
        """Handle assistant message."""
        if message.strip():
            self.console.print()
            self.console.print(Panel(
                Markdown(message),
                title="[bold cyan]Agent[/bold cyan]",
                border_style="cyan",
            ))

    def on_tool_call(self, tool_name: str, tool_input: dict) -> None:
        """Handle tool call."""
        self.tool_count += 1

        if self.verbose:
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Key", style="dim")
            table.add_column("Value")

            for key, value in tool_input.items():
                value_str = str(value)
                if len(value_str) > 100:
                    value_str = value_str[:100] + "..."
                table.add_row(key, value_str)

            self.console.print(Panel(
                table,
                title=f"[bold yellow]Tool: {tool_name}[/bold yellow]",
                border_style="yellow",
            ))
        else:
            self.console.print(
                f"  [yellow]>[/yellow] Using tool: [bold]{tool_name}[/bold]"
            )

    def on_checkpoint(self, percent: int, metrics: dict) -> None:
        """Handle checkpoint."""
        self.console.print()
        self.console.print(Panel(
            f"Progress: {percent}%\n"
            f"Turns: {metrics.get('turns', 0)}\n"
            f"Tokens: {metrics.get('total_tokens', 0):,}",
            title=f"[bold green]Checkpoint {percent}%[/bold green]",
            border_style="green",
        ))

    def on_complete(self, result: ExecutionResult) -> None:
        """Handle completion."""
        self.console.print()

        # Status
        if result.objective_met:
            status = "[bold green]OBJECTIVE MET[/bold green]"
        elif result.error:
            status = f"[bold red]ERROR: {result.error}[/bold red]"
        else:
            status = "[bold yellow]INCOMPLETE[/bold yellow]"

        # Build summary table
        table = Table(show_header=False, box=None)
        table.add_column("Key", style="dim")
        table.add_column("Value")

        table.add_row("Status", status)
        table.add_row("Operation ID", result.operation_id)
        table.add_row("Duration", f"{result.duration_seconds:.1f}s")
        table.add_row("Turns", str(result.turns))
        table.add_row("Tokens", f"{result.total_tokens:,}")
        table.add_row("Artifacts", result.artifacts_dir)

        if result.confidence is not None:
            table.add_row("Confidence", f"{result.confidence}%")

        self.console.print(Panel(
            table,
            title="[bold]Assessment Complete[/bold]",
            border_style="blue",
        ))

        # Findings summary
        if result.findings_summary:
            self.console.print()
            self.console.print(Panel(
                Markdown(result.findings_summary),
                title="[bold]Findings Summary[/bold]",
                border_style="cyan",
            ))


def ensure_ready(skip_qdrant: bool = False) -> bool:
    """
    Ensure the environment is ready to run assessments.

    This function:
    1. Checks if Docker is available
    2. Starts Qdrant if not running
    3. Validates authentication is configured

    Args:
        skip_qdrant: Skip Qdrant check (for commands that don't need memory).

    Returns:
        True if ready, False otherwise.
    """
    checker = SetupChecker()
    docker_manager = DockerManager()

    # Check Docker
    docker_check = checker.check_docker()
    if docker_check.status == ComponentStatus.MISSING:
        console.print("\n[bold red]Docker is not installed[/bold red]")
        console.print("\nInferno requires Docker to run the Qdrant vector database.")
        console.print("\n[dim]Install Docker from: https://docs.docker.com/get-docker/[/dim]")
        return False

    if docker_check.status == ComponentStatus.NOT_RUNNING:
        console.print("\n[bold yellow]Docker is not running[/bold yellow]")
        console.print("\n[dim]Please start Docker Desktop or run 'sudo systemctl start docker'[/dim]")
        return False

    # Check/Start Qdrant
    if not skip_qdrant:
        qdrant_check = checker.check_qdrant()
        if qdrant_check.status != ComponentStatus.OK:
            console.print("\n[dim]Starting Qdrant vector database...[/dim]")

            with console.status("[bold green]Starting Qdrant container..."):
                result = docker_manager.start_qdrant(wait=True, timeout=60)

            if result.status.value == "running":
                console.print("[green]Qdrant started successfully[/green]")
            else:
                console.print(f"[red]Failed to start Qdrant: {result.message}[/red]")
                return False

    # Check authentication
    cred_check = checker.check_credentials()
    if cred_check.status != ComponentStatus.OK:
        console.print("\n[bold yellow]Authentication required[/bold yellow]")
        console.print("\nChoose one of the following options:")
        console.print("  1. [cyan]inferno auth login[/cyan] - Use your Claude subscription (FREE)")
        console.print("  2. Set [cyan]ANTHROPIC_API_KEY[/cyan] in your environment")
        console.print("\n[dim]OAuth is recommended if you have Claude Max or Team subscription.[/dim]")
        return False

    return True


def print_status_table(status: SetupStatus) -> None:
    """Print a formatted status table."""
    table = Table(title="Inferno Status", show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    def status_icon(s: ComponentStatus) -> str:
        icons = {
            ComponentStatus.OK: "[green]OK[/green]",
            ComponentStatus.MISSING: "[red]MISSING[/red]",
            ComponentStatus.NOT_RUNNING: "[yellow]NOT RUNNING[/yellow]",
            ComponentStatus.ERROR: "[red]ERROR[/red]",
        }
        return icons.get(s, str(s))

    # Core components
    table.add_row(
        status.docker.name,
        status_icon(status.docker.status),
        status.docker.message,
    )
    table.add_row(
        status.qdrant.name,
        status_icon(status.qdrant.status),
        status.qdrant.message,
    )
    table.add_row(
        status.credentials.name,
        status_icon(status.credentials.status),
        status.credentials.message,
    )
    table.add_row(
        status.python_deps.name,
        status_icon(status.python_deps.status),
        status.python_deps.message,
    )

    console.print(table)

    # Security tools summary
    if status.security_tools:
        available = [t for t in status.security_tools if t.status == ComponentStatus.OK]
        console.print(f"\n[bold]Security Tools:[/bold] {len(available)}/{len(status.security_tools)} available")

        if available:
            tool_names = ", ".join(t.name for t in available)
            console.print(f"[dim]{tool_names}[/dim]")


@app.command()
def run(
    target: Annotated[
        str,
        typer.Argument(help="Target URL or IP address"),
    ],
    objective: Annotated[
        str,
        typer.Option(
            "--objective", "-o",
            help="Assessment objective",
        ),
    ] = "Perform security assessment and find vulnerabilities",
    max_turns: Annotated[
        int,
        typer.Option(
            "--max-turns",
            help="Maximum number of turns",
        ),
    ] = 100,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose", "-v",
            help="Verbose output",
        ),
    ] = False,
) -> None:
    """
    Run a security assessment against a target.

    Uses an isolated Kali Linux container with full pentesting toolkit.
    3 tools: generic_linux_command, execute_code, web_request.

    Examples:

        # Basic assessment
        inferno run https://target.com

        # CTF challenge
        inferno run 10.10.10.5 -o "Get root flag"

        # API testing
        inferno run https://api.target.com -o "Test API for SQLi"

        # Web application
        inferno run https://webapp.target.com -o "Find XSS and SQLi vulnerabilities"
    """
    print_banner()

    # Check Docker only (no Qdrant needed in minimal mode)
    from inferno.setup import DockerManager
    docker = DockerManager()

    if not docker.is_docker_available():
        console.print("[bold red]Docker is not available[/bold red]")
        console.print("\nMinimal mode requires Docker for the Kali container.")
        console.print("[dim]Install Docker from: https://docs.docker.com/get-docker/[/dim]")
        raise typer.Exit(1)

    # Check authentication
    cred_manager = CredentialManager()
    try:
        credential = cred_manager.get_credential()
        auth_type = "OAuth" if credential.is_oauth else "API Key"
        console.print(f"[dim]Authenticated via: {auth_type}[/dim]")
    except CredentialError:
        console.print("[bold yellow]Authentication required[/bold yellow]")
        console.print("Run [cyan]inferno auth login[/cyan] or set ANTHROPIC_API_KEY")
        raise typer.Exit(1)

    # Display configuration
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Objective:[/bold] {objective}")
    console.print(f"[bold]Max Turns:[/bold] {max_turns}")
    console.print()

    # Start Kali container
    console.print("[dim]Ensuring Kali container is running...[/dim]")
    with console.status("[bold green]Starting Kali container..."):
        kali_status = docker.start_kali(wait=True, timeout=120)

    if kali_status.status.value != "running":
        console.print(f"[red]Failed to start Kali container: {kali_status.message}[/red]")
        raise typer.Exit(1)

    console.print("[green]Kali container ready[/green]\n")

    # Create output handler
    handler = OutputHandler(verbose=verbose)

    # Run minimal assessment
    from inferno.agent.sdk_executor import MinimalConfig, MinimalSDKExecutor

    async def _run():
        config = MinimalConfig(
            target=target,
            objective=objective,
            max_turns=max_turns,
        )

        executor = MinimalSDKExecutor()
        executor.on_message(handler.on_message)
        executor.on_tool_call(handler.on_tool_call)
        executor.on_tool_result(lambda n, o, e: None)  # Suppress tool results in minimal mode

        return await executor.run(config)

    try:
        with console.status("[bold green]Running minimal assessment..."):
            result = asyncio.run(_run())

        # Display result
        handler.on_complete(result)

        if result.error:
            raise typer.Exit(1)

    except KeyboardInterrupt:
        console.print("\n[yellow]Assessment interrupted[/yellow]")
        raise typer.Exit(130)

    except Exception as e:
        console.print(f"\n[red]Error: {rich_escape(str(e))}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@app.command()
def tools() -> None:
    """
    List available security tools.

    Shows which security tools are installed and available on the system.
    """
    print_banner()

    console.print("\n[bold]Discovering security tools...[/bold]\n")

    available = discover_security_tools()

    if not available:
        console.print("[yellow]No security tools found in PATH[/yellow]")
        console.print("[dim]Install tools like nmap, sqlmap, nikto, etc.[/dim]")
        return

    table = Table(title="Available Security Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="green")

    for tool in sorted(available):
        table.add_row(tool, "Available")

    console.print(table)
    console.print(f"\n[dim]Total: {len(available)} tools available[/dim]")


@app.command()
def config() -> None:
    """
    Show current configuration.

    Displays the current Inferno configuration from environment and settings.
    """
    print_banner()

    # Try to load settings
    try:
        settings = InfernoSettings()
    except Exception:
        settings = None

    # Check authentication
    cred_manager = CredentialManager()
    try:
        credential = cred_manager.get_credential()
        if credential.is_oauth:
            auth_status = "[green]OAuth (Claude Subscription)[/green]"
        else:
            api_key = credential.get_value()
            masked_key = api_key[:8] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
            auth_status = f"API Key ({masked_key})"
    except CredentialError:
        auth_status = "[red]Not configured[/red]"

    table = Table(title="Current Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("Authentication", auth_status)

    if settings:
        table.add_row("Default Model", settings.model.model_id.value)
        table.add_row("Temperature", str(settings.model.temperature))
        table.add_row("Max Steps", str(settings.execution.max_steps))
        table.add_row("Embedding Provider", settings.memory.embedding_provider.value)
        table.add_row("Memory Backend", "Mem0 + Qdrant" if settings.memory.use_mem0 else "In-Memory")
        table.add_row("Qdrant Host", f"{settings.memory.qdrant_host}:{settings.memory.qdrant_port}")
        table.add_row("Output Directory", str(settings.output.base_dir))
    else:
        table.add_row("Settings", "[dim]Using defaults (no .env file)[/dim]")

    console.print(table)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"[bold blue]Inferno[/bold blue] version {__version__}")


@app.command()
def status() -> None:
    """
    Show system status and readiness.

    Checks all components required to run Inferno:
    - Docker installation and status
    - Qdrant vector database
    - Authentication configuration
    - Available security tools
    """
    print_banner()
    console.print("\n[bold]Checking system status...[/bold]\n")

    checker = SetupChecker()
    status_result = checker.check_all()

    print_status_table(status_result)

    # Overall readiness
    console.print()
    if status_result.is_ready:
        console.print("[bold green]Ready to run assessments![/bold green]")
        console.print("\n[dim]Run 'inferno run <target>' to start an assessment[/dim]")
    else:
        console.print("[bold yellow]Setup required[/bold yellow]")
        if status_result.needs_setup:
            console.print("\n[dim]Run 'inferno setup' to configure the environment[/dim]")
        elif status_result.needs_auth:
            console.print("\n[dim]Run 'inferno auth login' to authenticate[/dim]")


@app.command()
def setup(
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Force re-setup even if already configured"),
    ] = False,
) -> None:
    """
    Set up the Inferno environment.

    This command:
    1. Checks Docker is installed and running
    2. Starts the Qdrant vector database container
    3. Creates .env file from template if needed
    4. Guides you through authentication

    Run this once before your first assessment.
    """
    print_banner()
    console.print("\n[bold]Setting up Inferno...[/bold]\n")

    checker = SetupChecker()
    docker_manager = DockerManager()

    # Step 1: Check Docker
    console.print("[bold]Step 1/4:[/bold] Checking Docker...")
    docker_check = checker.check_docker()

    if docker_check.status == ComponentStatus.MISSING:
        console.print("[red]Docker is not installed[/red]")
        console.print("\nPlease install Docker from: https://docs.docker.com/get-docker/")
        console.print("Then run 'inferno setup' again.")
        raise typer.Exit(1)

    if docker_check.status == ComponentStatus.NOT_RUNNING:
        console.print("[yellow]Docker is not running[/yellow]")
        console.print("\nPlease start Docker and run 'inferno setup' again.")
        raise typer.Exit(1)

    console.print(f"[green]Docker OK[/green] ({docker_check.details.get('version', 'unknown')})")

    # Step 2: Start Qdrant
    console.print("\n[bold]Step 2/4:[/bold] Setting up Qdrant vector database...")
    qdrant_check = checker.check_qdrant()

    if qdrant_check.status == ComponentStatus.OK and not force:
        console.print("[green]Qdrant already running[/green]")
    else:
        with console.status("[bold green]Starting Qdrant container..."):
            result = docker_manager.start_qdrant(wait=True, timeout=60)

        if result.status.value == "running":
            console.print("[green]Qdrant started successfully[/green]")
        else:
            console.print(f"[red]Failed to start Qdrant: {result.message}[/red]")
            raise typer.Exit(1)

    # Step 3: Create .env file
    console.print("\n[bold]Step 3/4:[/bold] Checking configuration...")

    if not checker.env_file_exists():
        env_path = checker.create_env_file()
        console.print(f"[green]Created .env file[/green] at {env_path}")
        console.print("[dim]Edit this file to customize settings if needed[/dim]")
    else:
        console.print("[green].env file exists[/green]")

    # Step 4: Check authentication
    console.print("\n[bold]Step 4/4:[/bold] Checking authentication...")
    cred_check = checker.check_credentials()

    if cred_check.status == ComponentStatus.OK:
        console.print(f"[green]Authenticated[/green] ({cred_check.message})")
    else:
        console.print("[yellow]Authentication not configured[/yellow]")
        console.print("\nYou need to authenticate before running assessments.")
        console.print("\n[bold]Options:[/bold]")
        console.print("  1. [cyan]inferno auth login[/cyan] - Use your Claude subscription (FREE)")
        console.print("  2. Set [cyan]ANTHROPIC_API_KEY[/cyan] in .env file")

    # Summary
    console.print("\n" + "=" * 50)
    final_status = checker.check_all()

    if final_status.is_ready:
        console.print("\n[bold green]Setup complete! Inferno is ready.[/bold green]")
        console.print("\n[dim]Run 'inferno run <target>' to start an assessment[/dim]")
    else:
        console.print("\n[bold yellow]Setup partially complete[/bold yellow]")
        if final_status.needs_auth:
            console.print("\n[dim]Run 'inferno auth login' to complete authentication[/dim]")


@app.command()
def stop() -> None:
    """
    Stop Inferno services (Qdrant container).

    Use this to free up resources when not using Inferno.
    """
    console.print("[dim]Stopping Qdrant container...[/dim]")

    docker_manager = DockerManager()
    result = docker_manager.stop_qdrant()

    if result.status.value == "stopped":
        console.print("[green]Qdrant stopped[/green]")
    else:
        console.print(f"[yellow]{result.message}[/yellow]")


@app.command()
def reset(
    confirm: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Confirm reset without prompting"),
    ] = False,
) -> None:
    """
    Reset Inferno (remove containers and data).

    This removes:
    - Qdrant container
    - Qdrant data volume (all memories)

    Use with caution - this deletes all stored memories.
    """
    if not confirm:
        confirm = typer.confirm(
            "This will delete all Inferno data including memories. Continue?"
        )
        if not confirm:
            console.print("[dim]Cancelled[/dim]")
            raise typer.Exit(0)

    console.print("[dim]Removing Qdrant container and data...[/dim]")

    docker_manager = DockerManager()
    if docker_manager.remove_qdrant():
        console.print("[green]Reset complete[/green]")
    else:
        console.print("[yellow]Nothing to reset or Docker not available[/yellow]")


# =============================================================================
# Auth Commands
# =============================================================================


@auth_app.command("login")
def auth_login() -> None:
    """
    Authenticate with your Claude subscription via OAuth.

    This opens your browser to sign in with your Anthropic account.
    Once authenticated, you can use Inferno without API billing.
    """
    import http.server
    import socketserver
    import webbrowser
    from urllib.parse import parse_qs, urlparse

    console.print("\n[bold]OAuth Authentication[/bold]\n")

    oauth_provider = OAuthCredentialProvider()

    # Check if already logged in
    if oauth_provider.is_available():
        console.print("[yellow]Already logged in with OAuth.[/yellow]")
        console.print("[dim]Run 'inferno auth logout' to sign out first.[/dim]")
        return

    try:
        auth_url = oauth_provider.initiate_auth_flow()
    except CredentialError as e:
        console.print(f"[red]OAuth not configured: {e}[/red]")
        console.print("\n[dim]To enable OAuth, set INFERNO_OAUTH_CLIENT_ID environment variable.[/dim]")
        console.print("[dim]For now, use ANTHROPIC_API_KEY for authentication.[/dim]")
        raise typer.Exit(1)

    # Capture authorization code via callback server
    authorization_code = None
    server_error = None

    class CallbackHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            nonlocal authorization_code, server_error

            parsed = urlparse(self.path)
            if parsed.path == "/callback":
                params = parse_qs(parsed.query)
                if "code" in params:
                    authorization_code = params["code"][0]
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"""
                        <html><body style="font-family: sans-serif; text-align: center; padding: 50px;">
                        <h1>Authentication Successful!</h1>
                        <p>You can close this window and return to the terminal.</p>
                        </body></html>
                    """)
                elif "error" in params:
                    server_error = params.get("error_description", params["error"])[0]
                    self.send_response(400)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(f"<html><body><h1>Error: {server_error}</h1></body></html>".encode())

        def log_message(self, format, *args):
            pass  # Suppress HTTP logs

    # Start callback server
    PORT = 8765
    with socketserver.TCPServer(("", PORT), CallbackHandler) as httpd:
        console.print(f"[dim]Starting callback server on port {PORT}...[/dim]")

        # Open browser
        console.print("\n[bold cyan]Opening browser for authentication...[/bold cyan]")
        console.print(f"[dim]If browser doesn't open, visit:[/dim]")
        console.print(f"[link={auth_url}]{auth_url}[/link]\n")

        webbrowser.open(auth_url)

        # Wait for callback (with timeout)
        httpd.timeout = 120  # 2 minute timeout

        console.print("[dim]Waiting for authentication (timeout: 2 minutes)...[/dim]")
        httpd.handle_request()

    if server_error:
        console.print(f"\n[red]Authentication failed: {server_error}[/red]")
        raise typer.Exit(1)

    if not authorization_code:
        console.print("\n[red]Authentication timed out or was cancelled.[/red]")
        raise typer.Exit(1)

    # Exchange code for token
    with console.status("[bold green]Completing authentication..."):
        try:
            credential = oauth_provider.complete_auth_flow(authorization_code)
            console.print("\n[bold green]Successfully authenticated![/bold green]")
            console.print("[dim]You can now use Inferno with your Claude subscription.[/dim]")
        except CredentialError as e:
            console.print(f"\n[red]Failed to complete authentication: {e}[/red]")
            raise typer.Exit(1)


@auth_app.command("logout")
def auth_logout() -> None:
    """
    Sign out and remove saved OAuth credentials.
    """
    oauth_provider = OAuthCredentialProvider()

    if oauth_provider.logout():
        console.print("[green]Successfully logged out.[/green]")
    else:
        console.print("[yellow]No OAuth credentials found.[/yellow]")


@auth_app.command("status")
def auth_status() -> None:
    """
    Show current authentication status.
    """
    console.print("\n[bold]Authentication Status[/bold]\n")

    cred_manager = CredentialManager()

    table = Table(show_header=False, box=None)
    table.add_column("Key", style="dim")
    table.add_column("Value")

    # Check available providers
    available = cred_manager.get_available_providers()

    try:
        credential = cred_manager.get_credential()
        auth_type = "OAuth (Claude Subscription)" if credential.is_oauth else "API Key"
        status = "[green]Authenticated[/green]"

        table.add_row("Status", status)
        table.add_row("Method", auth_type)
        table.add_row("Source", credential.source)

        if credential.expires_at:
            from datetime import datetime, timezone
            remaining = credential.expires_at - datetime.now(timezone.utc)
            if remaining.total_seconds() > 0:
                table.add_row("Expires In", f"{remaining.seconds // 60} minutes")
            else:
                table.add_row("Status", "[red]Expired[/red]")

    except CredentialError:
        table.add_row("Status", "[red]Not Authenticated[/red]")
        table.add_row("Available Providers", ", ".join(available) if available else "None")

    console.print(table)

    console.print("\n[dim]Authentication options:[/dim]")
    console.print("  - [cyan]inferno auth login[/cyan]: Sign in with Claude subscription (OAuth)")
    console.print("  - Set [cyan]ANTHROPIC_API_KEY[/cyan] environment variable")


@app.command()
def shell() -> None:
    """
    Start interactive shell mode.

    This is the recommended way to use Inferno - provides a
    persistent interface where you can set targets, configure
    options, and run assessments without the CLI exiting.
    """
    from inferno.cli.shell import run_shell
    run_shell()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version", "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version",
        ),
    ] = None,
) -> None:
    """
    Inferno - Autonomous AI-powered Penetration Testing Agent

    Run authorized security assessments with Claude AI.

    Start with just 'inferno' to enter interactive mode.
    """
    # If no subcommand provided, start interactive shell
    if ctx.invoked_subcommand is None:
        from inferno.cli.shell import run_shell
        run_shell()


def cli() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    cli()
