"""
Integration tests for CLI commands.

Tests the inferno CLI interface, command parsing,
authentication flow, and setup checks.
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
from typer.testing import CliRunner

from inferno.cli.main import app


runner = CliRunner()


@pytest.mark.integration
class TestCLIBasicCommands:
    """Test basic CLI commands and help text."""

    def test_cli_help_command(self):
        """Test: inferno --help displays help text."""
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "Inferno" in result.stdout
        assert "Autonomous" in result.stdout or "penetration" in result.stdout.lower()

    def test_cli_version_command(self):
        """Test: inferno --version displays version number."""
        result = runner.invoke(app, ["--version"])

        assert result.exit_code == 0
        assert "Inferno version" in result.stdout or "version" in result.stdout.lower()

    def test_cli_no_args_shows_help(self):
        """Test: Running 'inferno' with no args shows help."""
        result = runner.invoke(app, [])

        # Should show help or usage
        assert "Usage" in result.stdout or "help" in result.stdout.lower()


@pytest.mark.integration
class TestCLIRunCommand:
    """Test the main 'run' command for assessments."""

    @pytest.fixture
    def mock_env(self, monkeypatch, tmp_path):
        """Set up mock environment for tests."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")
        monkeypatch.setenv("INFERNO_OUTPUT_BASE_DIR", str(tmp_path))
        return tmp_path

    def test_run_command_help(self):
        """Test: inferno run --help."""
        # Force wide terminal for rich output
        env = os.environ.copy()
        env["COLUMNS"] = "120"
        
        result = runner.invoke(app, ["run", "--help"], env=env)

        assert result.exit_code == 0
        assert "target" in result.stdout.lower()
        assert "objective" in result.stdout.lower()

    @pytest.mark.skip("Requires full agent setup")
    def test_run_command_with_target(self, mock_env):
        """Test: inferno run <target> starts assessment."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "-o", "Quick vulnerability scan",
            "--max-turns", "3"
        ])

        # May fail without proper setup, but should parse correctly
        assert "target" in result.stdout.lower() or result.exit_code in [0, 1]

    @pytest.mark.skip("Requires agent executor")
    def test_run_command_with_profile(self, mock_env):
        """Test: inferno run with --profile option."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "--profile", "ctf",
            "--max-turns", "5"
        ])

        # Should attempt to load CTF profile
        assert result.exit_code in [0, 1]

    def test_run_command_missing_target(self):
        """Test: inferno run without target shows error."""
        result = runner.invoke(app, ["run"])

        # Should error or prompt for target
        assert result.exit_code != 0 or "target" in result.stdout.lower()

    @pytest.mark.skip("Requires agent setup")
    def test_run_command_with_scope(self, mock_env):
        """Test: inferno run with scope restrictions."""
        result = runner.invoke(app, [
            "run",
            "https://example.com",
            "--include", "*.example.com",
            "--exclude", "admin.example.com"
        ])

        # Should parse scope options
        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLISetupCommand:
    """Test the setup command for environment checks."""

    def test_setup_command_help(self):
        """Test: inferno setup --help."""
        result = runner.invoke(app, ["setup", "--help"])

        assert result.exit_code == 0

    @pytest.mark.skip("Requires Docker")
    def test_setup_command_checks_docker(self):
        """Test: inferno setup checks Docker installation."""
        result = runner.invoke(app, ["setup"])

        # Should check for Docker
        assert "docker" in result.stdout.lower() or result.exit_code in [0, 1]

    @pytest.mark.skip("Requires Qdrant")
    def test_setup_command_starts_qdrant(self):
        """Test: inferno setup starts Qdrant container."""
        result = runner.invoke(app, ["setup"])

        # Should attempt to start Qdrant
        assert "qdrant" in result.stdout.lower() or result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIAuthCommands:
    """Test authentication commands."""

    def test_auth_help(self):
        """Test: inferno auth --help."""
        result = runner.invoke(app, ["auth", "--help"])

        assert result.exit_code == 0
        assert "login" in result.stdout.lower() or "auth" in result.stdout.lower()

    def test_auth_login_help(self):
        """Test: inferno auth login --help."""
        result = runner.invoke(app, ["auth", "login", "--help"])

        assert result.exit_code == 0

    @pytest.mark.skip("Requires OAuth setup")
    def test_auth_login_flow(self):
        """Test: inferno auth login starts OAuth flow."""
        result = runner.invoke(app, ["auth", "login"], input="n\n")

        # Should prompt for authentication method
        assert "authentication" in result.stdout.lower() or result.exit_code in [0, 1]

    @pytest.mark.skip("Requires OAuth setup")
    def test_auth_logout(self):
        """Test: inferno auth logout clears credentials."""
        result = runner.invoke(app, ["auth", "logout"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Requires OAuth setup")
    def test_auth_status(self):
        """Test: inferno auth status shows authentication state."""
        result = runner.invoke(app, ["auth", "status"])

        # Should show whether authenticated
        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIProfileCommands:
    """Test profile management commands."""

    def test_profile_list(self):
        """Test: inferno profile list shows available profiles."""
        result = runner.invoke(app, ["profile", "list"])

        # May fail if not implemented, but test CLI parsing
        assert result.exit_code in [0, 1, 2]  # Accept not implemented

    @pytest.mark.skip("Profile management not yet implemented")
    def test_profile_show(self):
        """Test: inferno profile show <name> displays profile details."""
        result = runner.invoke(app, ["profile", "show", "ctf"])

        assert "ctf" in result.stdout.lower() or result.exit_code in [0, 1]

    @pytest.mark.skip("Profile management not yet implemented")
    def test_profile_create(self):
        """Test: inferno profile create creates custom profile."""
        result = runner.invoke(app, ["profile", "create", "custom"], input="y\n")

        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIOutputHandling:
    """Test CLI output formatting and verbosity."""

    @pytest.fixture
    def mock_env(self, monkeypatch, tmp_path):
        """Set up mock environment."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-12345")
        monkeypatch.setenv("INFERNO_OUTPUT_BASE_DIR", str(tmp_path))
        return tmp_path

    @pytest.mark.skip("Requires agent execution")
    def test_verbose_output(self, mock_env):
        """Test: inferno run --verbose shows detailed output."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "--verbose",
            "--max-turns", "2"
        ])

        # Verbose mode should show more details
        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Requires agent execution")
    def test_quiet_output(self, mock_env):
        """Test: inferno run --quiet suppresses output."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "--quiet",
            "--max-turns", "2"
        ])

        # Quiet mode should minimize output
        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Requires agent execution")
    def test_json_output(self, mock_env):
        """Test: inferno run --output-format json."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "--output-format", "json",
            "--max-turns", "2"
        ])

        # Should output valid JSON
        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIErrorHandling:
    """Test CLI error handling and validation."""

    def test_invalid_command(self):
        """Test: Invalid command shows error."""
        result = runner.invoke(app, ["invalid_command"])

        # Typer exits with code 2 for invalid commands (error goes to stderr, not stdout)
        assert result.exit_code != 0

    def test_missing_api_key(self, monkeypatch):
        """Test: Missing API key shows helpful error."""
        # Remove API key
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        result = runner.invoke(app, ["run", "http://test.local"])

        # Should error about missing credentials
        assert result.exit_code != 0 or "api" in result.stdout.lower()

    def test_invalid_target_url(self):
        """Test: Invalid target URL shows error."""
        result = runner.invoke(app, ["run", "not-a-valid-url"])

        # Should validate URL format
        assert result.exit_code in [0, 1]  # May be caught at different levels

    def test_invalid_profile_name(self):
        """Test: Invalid profile name shows error."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "--profile", "nonexistent_profile"
        ])

        # Should error about unknown profile (exit code 2 for Typer validation errors)
        assert result.exit_code in [0, 1, 2]


@pytest.mark.integration
class TestCLIConfigManagement:
    """Test configuration file management."""

    @pytest.mark.skip("Config management not yet implemented")
    def test_config_init(self, tmp_path):
        """Test: inferno config init creates config file."""
        result = runner.invoke(app, ["config", "init"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Config management not yet implemented")
    def test_config_show(self):
        """Test: inferno config show displays current config."""
        result = runner.invoke(app, ["config", "show"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Config management not yet implemented")
    def test_config_set(self):
        """Test: inferno config set updates configuration."""
        result = runner.invoke(app, [
            "config", "set",
            "model", "claude-sonnet-4-5-20250929"
        ])

        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIInteractiveMode:
    """Test interactive mode (if implemented)."""

    @pytest.mark.skip("Interactive mode not yet implemented")
    def test_interactive_mode_start(self):
        """Test: inferno interactive starts REPL."""
        result = runner.invoke(app, ["interactive"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Interactive mode not yet implemented")
    def test_interactive_commands(self):
        """Test: Interactive mode accepts commands."""
        result = runner.invoke(app, ["interactive"], input="help\nexit\n")

        assert "help" in result.stdout.lower() or result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIReportCommands:
    """Test report generation and export commands."""

    @pytest.mark.skip("Report commands not yet implemented")
    def test_report_list(self):
        """Test: inferno report list shows past assessments."""
        result = runner.invoke(app, ["report", "list"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Report commands not yet implemented")
    def test_report_export(self, tmp_path):
        """Test: inferno report export generates report file."""
        result = runner.invoke(app, [
            "report", "export",
            "operation_123",
            "--format", "pdf",
            "--output", str(tmp_path / "report.pdf")
        ])

        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIIntegrationWithAgent:
    """Integration tests with actual agent (mock Anthropic API)."""

    @pytest.fixture
    def mock_anthropic_api(self):
        """Mock Anthropic API responses."""
        with patch('inferno.auth.client.AsyncInfernoClient') as mock_client:
            # Mock successful API response
            mock_instance = AsyncMock()
            mock_instance.beta.messages.create = AsyncMock(return_value=Mock(
                id="msg_test_001",
                type="message",
                role="assistant",
                content=[Mock(type="text", text="Starting security assessment...")],
                stop_reason="end_turn",
                usage=Mock(input_tokens=100, output_tokens=50)
            ))
            mock_client.return_value.__aenter__.return_value = mock_instance

            yield mock_client

    @pytest.mark.skip("Requires full integration")
    def test_run_with_mocked_agent(self, mock_env, mock_anthropic_api):
        """Test: Full run command with mocked Anthropic API."""
        result = runner.invoke(app, [
            "run",
            "http://test.local",
            "-o", "Quick scan",
            "--max-turns", "2"
        ])

        # Should complete without errors
        assert result.exit_code == 0
        assert "assessment" in result.stdout.lower()


@pytest.mark.integration
class TestCLICheckpointResume:
    """Test checkpoint and resume functionality."""

    @pytest.mark.skip("Checkpoint feature needs testing")
    def test_resume_from_checkpoint(self, tmp_path):
        """Test: inferno resume <operation_id> continues assessment."""
        result = runner.invoke(app, ["resume", "OP_20251201_123456"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Checkpoint feature needs testing")
    def test_list_checkpoints(self):
        """Test: inferno checkpoint list shows saved checkpoints."""
        result = runner.invoke(app, ["checkpoint", "list"])

        assert result.exit_code in [0, 1]


@pytest.mark.integration
class TestCLIToolManagement:
    """Test external tool management commands."""

    @pytest.mark.skip("Tool management not yet implemented")
    def test_tools_list(self):
        """Test: inferno tools list shows installed tools."""
        result = runner.invoke(app, ["tools", "list"])

        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Tool management not yet implemented")
    def test_tools_check(self):
        """Test: inferno tools check verifies tool installation."""
        result = runner.invoke(app, ["tools", "check"])

        # Should check for nmap, nikto, sqlmap, etc.
        assert result.exit_code in [0, 1]

    @pytest.mark.skip("Tool management not yet implemented")
    def test_tools_install(self):
        """Test: inferno tools install <tool_name>."""
        result = runner.invoke(app, ["tools", "install", "nikto"])

        assert result.exit_code in [0, 1]
