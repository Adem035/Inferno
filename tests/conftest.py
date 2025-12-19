"""
Pytest fixtures and configuration for Inferno-AI test suite.
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, Mock, MagicMock
from datetime import datetime, timezone, timedelta
import tempfile
import json
import os

# ============================================================================
# Core Fixtures
# ============================================================================

@pytest.fixture
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def temp_dir(tmp_path):
    """Provide a temporary directory for test artifacts."""
    return tmp_path

@pytest.fixture
def operation_dir(tmp_path):
    """Create a temporary operation directory structure."""
    op_dir = tmp_path / "operation_test_001"
    op_dir.mkdir()
    (op_dir / "reports").mkdir()
    (op_dir / "artifacts").mkdir()
    (op_dir / "logs").mkdir()
    return op_dir

# ============================================================================
# Mock API Clients
# ============================================================================

@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic API client for testing agent loops."""
    client = AsyncMock()
    client.beta = Mock()
    client.beta.messages = Mock()

    # Default successful response
    client.beta.messages.create = AsyncMock(return_value=Mock(
        id="msg_test_001",
        type="message",
        role="assistant",
        content=[Mock(type="text", text="Test response from Claude")],
        stop_reason="end_turn",
        usage=Mock(
            input_tokens=100,
            output_tokens=50,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0
        )
    ))

    return client

@pytest.fixture
def mock_anthropic_tool_response():
    """Mock Anthropic response with tool use."""
    return Mock(
        id="msg_test_002",
        type="message",
        role="assistant",
        content=[
            Mock(
                type="tool_use",
                id="tool_001",
                name="http_request",
                input={"url": "http://test.local", "method": "GET"}
            )
        ],
        stop_reason="tool_use",
        usage=Mock(input_tokens=150, output_tokens=80)
    )

# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def sample_scope_config():
    """Sample scope configuration for testing."""
    from inferno.core.scope import ScopeConfig, ScopeAction

    return ScopeConfig(
        targets=["https://test.example.com"],
        include_domains=["example.com", "*.example.com"],
        exclude_domains=["admin.example.com"],
        include_ips=["192.168.1.0/24"],
        exclude_paths=["/admin/*", "/api/internal/*"],
        violation_action=ScopeAction.BLOCK
    )

@pytest.fixture
def ctf_scope_config():
    """Permissive scope configuration for testing/challenges."""
    from inferno.core.scope import ScopeConfig, ScopeAction

    return ScopeConfig(
        targets=["http://ctf.htb:8080"],
        include_domains=["ctf.htb", "*.ctf.htb"],
        permissive_mode=True,
        violation_action=ScopeAction.LOG
    )

@pytest.fixture
def sample_settings(tmp_path, monkeypatch):
    """Create sample InfernoSettings for testing."""
    # Set required env vars
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-123")
    monkeypatch.setenv("INFERNO_OUTPUT_BASE_DIR", str(tmp_path))

    from inferno.config.settings import InfernoSettings
    return InfernoSettings()

# ============================================================================
# Memory/Storage Fixtures
# ============================================================================

@pytest.fixture
def mock_qdrant_client():
    """Mock Qdrant vector database client."""
    client = MagicMock()
    client.collection_exists = MagicMock(return_value=True)
    client.get_collection = MagicMock(return_value=Mock(points_count=100))
    client.search = MagicMock(return_value=[])
    client.upsert = MagicMock(return_value=None)
    client.delete = MagicMock(return_value=None)
    return client

@pytest.fixture
def mock_embedder():
    """Mock sentence transformer embedder."""
    embedder = MagicMock()
    # Return 384-dim embedding (all-MiniLM-L6-v2 dimension)
    embedder.encode = MagicMock(return_value=[0.1] * 384)
    return embedder

@pytest.fixture
def sample_memory_entries():
    """Sample memory entries for testing."""
    return [
        {
            "id": "mem_001",
            "content": "SQL injection found at /api/users?id=1",
            "memory_type": "findings",
            "severity": "high",
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": "mem_002",
            "content": "Admin credentials found: admin:password123",
            "memory_type": "findings",
            "severity": "critical",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    ]

# ============================================================================
# Tool Fixtures
# ============================================================================

@pytest.fixture
def mock_tool_registry():
    """Mock tool registry for testing."""
    from unittest.mock import MagicMock

    registry = MagicMock()
    registry.has_tool = MagicMock(return_value=True)
    registry.execute = AsyncMock(return_value=Mock(
        success=True,
        output="Tool executed successfully",
        metadata={"execution_time_ms": 150}
    ))
    return registry

@pytest.fixture
def sample_http_response():
    """Sample HTTP response for testing tools."""
    return {
        "status_code": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3"
        },
        "body": "<html><body>Test page</body></html>",
        "response_time_ms": 150,
        "url": "http://test.local/api/users"
    }

# ============================================================================
# Credential Fixtures
# ============================================================================

@pytest.fixture
def mock_credential():
    """Mock credential for testing."""
    from inferno.auth.credentials import Credential

    return Credential(
        value="sk-ant-test-api-key-12345",
        source="test",
        loaded_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        is_oauth=False
    )

@pytest.fixture
def expired_credential():
    """Expired credential for testing expiration handling."""
    from inferno.auth.credentials import Credential

    return Credential(
        value="sk-ant-expired-key",
        source="test",
        loaded_at=datetime.now(timezone.utc) - timedelta(hours=2),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        is_oauth=True
    )

# ============================================================================
# Agent/Loop Fixtures
# ============================================================================

@pytest.fixture
def sample_loop_config():
    """Sample LoopConfig for testing agent loops."""
    from inferno.agent.loop import LoopConfig

    return LoopConfig(
        max_turns=50,
        max_total_tokens=100000,
        temperature=0.7,
        model="claude-sonnet-4-5-20250929",
        enable_checkpoints=True,
        checkpoint_interval_percent=20
    )

@pytest.fixture
def sample_assessment_config():
    """Sample AssessmentConfig for testing."""
    return {
        "target": "http://test.local",
        "objective": "Find and exploit vulnerabilities",
        "context_type": "web",
        "max_turns": 100,
        "max_tokens": 500000,
        "permissive_mode": False
    }

# ============================================================================
# Algorithm Testing Fixtures
# ============================================================================

@pytest.fixture
def mab_empty_state():
    """Empty MAB state for cold start testing."""
    attack_vectors = [
        "sql_injection", "xss", "ssrf", "idor",
        "path_traversal", "rce", "auth_bypass", "file_upload"
    ]
    return {
        vector: {"pulls": 0, "rewards": 0.0, "successes": 0, "failures": 0}
        for vector in attack_vectors
    }

@pytest.fixture
def mab_initialized_state():
    """MAB state with historical data."""
    return {
        "sql_injection": {"pulls": 50, "rewards": 35.0, "successes": 35, "failures": 15},
        "xss": {"pulls": 40, "rewards": 20.0, "successes": 20, "failures": 20},
        "ssrf": {"pulls": 30, "rewards": 25.0, "successes": 25, "failures": 5},
        "idor": {"pulls": 25, "rewards": 15.0, "successes": 15, "failures": 10},
        "path_traversal": {"pulls": 20, "rewards": 8.0, "successes": 8, "failures": 12},
        "rce": {"pulls": 10, "rewards": 8.0, "successes": 8, "failures": 2},
        "auth_bypass": {"pulls": 15, "rewards": 10.0, "successes": 10, "failures": 5},
        "file_upload": {"pulls": 5, "rewards": 3.0, "successes": 3, "failures": 2},
    }

@pytest.fixture
def q_learning_config():
    """Q-Learning configuration for testing."""
    return {
        "learning_rate": 0.1,
        "discount_factor": 0.95,
        "epsilon": 0.1,
        "epsilon_decay": 0.995,
        "min_epsilon": 0.01,
    }

@pytest.fixture
def budget_config():
    """Budget allocation configuration for testing."""
    return {
        "total_budget": 500,
        "min_allocation": 5,
        "max_allocation": 50,
        "reserve_percentage": 0.1,
        "reallocation_threshold": 0.8,
    }

# ============================================================================
# Cleanup/Reset Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singleton instances between tests."""
    yield

    # Reset scope manager
    try:
        from inferno.core.scope import _scope_manager
        import inferno.core.scope as scope_module
        scope_module._scope_manager = None
    except (ImportError, AttributeError):
        pass

    # Reset credential manager
    try:
        from inferno.auth.credentials import _credential_manager
        import inferno.auth.credentials as cred_module
        cred_module._credential_manager = None
    except (ImportError, AttributeError):
        pass

@pytest.fixture
def clean_env(monkeypatch):
    """Clean environment for isolated tests."""
    # Remove potentially interfering env vars
    for key in list(os.environ.keys()):
        if key.startswith("INFERNO_") or key.startswith("ANTHROPIC_"):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch

# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure custom markers."""
    # Existing markers
    config.addinivalue_line("markers", "slow: marks tests as slow running")
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "e2e: marks end-to-end tests")
    config.addinivalue_line("markers", "security: marks security-focused tests")

    # Algorithm testing markers
    config.addinivalue_line("markers", "benchmark: marks benchmark/performance tests")
    config.addinivalue_line("markers", "ctf: marks CTF validation tests")
    config.addinivalue_line("markers", "algorithm: marks algorithm unit tests")
    config.addinivalue_line("markers", "mab: marks Multi-Armed Bandit tests")
    config.addinivalue_line("markers", "mcts: marks Monte Carlo Tree Search tests")
    config.addinivalue_line("markers", "bayesian: marks Bayesian confidence tests")
    config.addinivalue_line("markers", "qlearning: marks Q-Learning tests")
    config.addinivalue_line("markers", "budget: marks dynamic budget tests")

def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption(
        "--qdrant",
        action="store_true",
        default=False,
        help="Run tests requiring Qdrant"
    )
    parser.addoption(
        "--real-api",
        action="store_true",
        default=False,
        help="Run tests with real Anthropic API"
    )
    parser.addoption(
        "--ctf",
        action="store_true",
        default=False,
        help="Run CTF validation tests"
    )
    parser.addoption(
        "--benchmark",
        action="store_true",
        default=False,
        help="Run benchmark tests"
    )
    parser.addoption(
        "--algorithms",
        action="store_true",
        default=False,
        help="Run algorithm unit tests"
    )

def pytest_collection_modifyitems(config, items):
    """Skip tests based on markers and command line options."""
    # Skip CTF tests unless --ctf is provided
    if not config.getoption("--ctf"):
        skip_ctf = pytest.mark.skip(reason="need --ctf option to run")
        for item in items:
            if "ctf" in item.keywords:
                item.add_marker(skip_ctf)

    # Skip benchmark tests unless --benchmark is provided
    if not config.getoption("--benchmark"):
        skip_benchmark = pytest.mark.skip(reason="need --benchmark option to run")
        for item in items:
            if "benchmark" in item.keywords:
                item.add_marker(skip_benchmark)

    # Skip Qdrant tests unless --qdrant is provided
    if not config.getoption("--qdrant"):
        skip_qdrant = pytest.mark.skip(reason="need --qdrant option to run")
        for item in items:
            if "requires_qdrant" in item.keywords:
                item.add_marker(skip_qdrant)

# ============================================================================
# Test Result Collection
# ============================================================================

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Add custom summary for algorithm tests."""
    # Count algorithm test results
    algorithm_markers = ["mab", "mcts", "bayesian", "qlearning", "budget"]

    passed = 0
    failed = 0
    skipped = 0

    for marker in algorithm_markers:
        for report in terminalreporter.stats.get("passed", []):
            if marker in str(report.keywords):
                passed += 1
        for report in terminalreporter.stats.get("failed", []):
            if marker in str(report.keywords):
                failed += 1
        for report in terminalreporter.stats.get("skipped", []):
            if marker in str(report.keywords):
                skipped += 1

    if passed + failed + skipped > 0:
        terminalreporter.write_sep("=", "Algorithm Test Summary")
        terminalreporter.write_line(f"Algorithm tests: {passed} passed, {failed} failed, {skipped} skipped")
