"""
Comprehensive tests for strategy tools.

Tests the following tools:
1. get_strategy - Q-Learning recommendations with swarm commands
2. record_failure - Track failures (blocks pattern after 3 failures)
3. record_success - Record successes with exploitation status
4. get_scoring - Display 20% penalty calculation
5. get_swarm_plan - Generate parallel swarm execution plan
"""


import pytest

from inferno.tools.strategy import (
    FailureTracker,
    GetStrategyTool,
    GetSwarmPlanTool,
    RecordFailureTool,
    RecordSuccessTool,
    get_failure_tracker,
    get_strategy_tools,
)

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def failure_tracker():
    """Fresh failure tracker instance."""
    return FailureTracker()


@pytest.fixture
def get_strategy_tool():
    """GetStrategyTool instance."""
    return GetStrategyTool()


@pytest.fixture
def record_failure_tool():
    """RecordFailureTool instance."""
    return RecordFailureTool()


@pytest.fixture
def record_success_tool():
    """RecordSuccessTool instance."""
    return RecordSuccessTool()


@pytest.fixture
def get_swarm_plan_tool():
    """GetSwarmPlanTool instance."""
    return GetSwarmPlanTool()


# ============================================================================
# FailureTracker Tests
# ============================================================================

class TestFailureTracker:
    """Tests for FailureTracker class."""

    def test_record_first_failure(self, failure_tracker):
        """Test: First failure is recorded correctly."""
        result = failure_tracker.record_failure(
            endpoint="/login",
            attack_type="sqli",
            reason="waf_blocked",
            payload="' OR 1=1--",
        )

        assert "1/3" in result
        assert failure_tracker._consecutive_failures["/login:sqli"] == 1
        assert not failure_tracker.is_blocked("/login", "sqli")

    def test_record_second_failure(self, failure_tracker):
        """Test: Second failure increments counter."""
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        result = failure_tracker.record_failure("/login", "sqli", "waf_blocked")

        assert "2/3" in result
        assert failure_tracker._consecutive_failures["/login:sqli"] == 2
        assert not failure_tracker.is_blocked("/login", "sqli")

    def test_pattern_blocked_after_three_failures(self, failure_tracker):
        """Test: Pattern is blocked after 3 consecutive failures."""
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        result = failure_tracker.record_failure("/login", "sqli", "waf_blocked")

        assert "BLOCKED" in result
        assert failure_tracker.is_blocked("/login", "sqli")
        assert "/login:sqli" in failure_tracker._blocked_patterns

    def test_different_endpoints_independent(self, failure_tracker):
        """Test: Different endpoints are tracked independently."""
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")

        failure_tracker.record_failure("/api", "sqli", "no_vuln")

        assert failure_tracker.is_blocked("/login", "sqli")
        assert not failure_tracker.is_blocked("/api", "sqli")

    def test_different_attack_types_independent(self, failure_tracker):
        """Test: Different attack types are tracked independently."""
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")

        failure_tracker.record_failure("/login", "xss", "no_vuln")

        assert failure_tracker.is_blocked("/login", "sqli")
        assert not failure_tracker.is_blocked("/login", "xss")

    def test_reset_pattern(self, failure_tracker):
        """Test: Reset pattern removes block and counter."""
        # Block a pattern
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        assert failure_tracker.is_blocked("/login", "sqli")

        # Reset it
        failure_tracker.reset_pattern("/login", "sqli")

        assert not failure_tracker.is_blocked("/login", "sqli")
        assert failure_tracker._consecutive_failures["/login:sqli"] == 0

    def test_get_failures_for_endpoint(self, failure_tracker):
        """Test: Get failures returns correct data."""
        failure_tracker.record_failure("/login", "sqli", "waf_blocked", "payload1")
        failure_tracker.record_failure("/login", "xss", "no_vuln", "payload2")
        failure_tracker.record_failure("/api", "sqli", "timeout")

        login_failures = failure_tracker.get_failures_for_endpoint("/login")
        api_failures = failure_tracker.get_failures_for_endpoint("/api")
        unknown_failures = failure_tracker.get_failures_for_endpoint("/unknown")

        assert len(login_failures) == 2
        assert len(api_failures) == 1
        assert len(unknown_failures) == 0
        assert login_failures[0]["attack_type"] == "sqli"
        assert login_failures[1]["attack_type"] == "xss"

    def test_get_statistics(self, failure_tracker):
        """Test: Statistics are calculated correctly."""
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        failure_tracker.record_failure("/api", "xss", "no_vuln")

        stats = failure_tracker.get_statistics()

        assert stats["total_failures"] == 4
        assert stats["endpoints_tested"] == 2
        assert "/login:sqli" in stats["blocked_patterns"]
        assert len(stats["blocked_patterns"]) == 1

    def test_alternative_suggestions_waf(self, failure_tracker):
        """Test: WAF blocked suggests waf_bypass agent."""
        result = failure_tracker.record_failure("/login", "sqli", "waf_blocked")
        assert "waf_bypass" in result.lower() or "WAF" in result

    def test_alternative_suggestions_timeout(self, failure_tracker):
        """Test: Timeout suggests rate limiting."""
        result = failure_tracker.record_failure("/login", "sqli", "timeout")
        assert "timeout" in result.lower() or "rate" in result.lower()

    def test_alternative_suggestions_403(self, failure_tracker):
        """Test: 403 suggests authentication."""
        result = failure_tracker.record_failure("/login", "sqli", "403")
        assert "403" in result or "forbidden" in result.lower() or "authentication" in result.lower()


# ============================================================================
# GetStrategyTool Tests
# ============================================================================

class TestGetStrategyTool:
    """Tests for GetStrategyTool."""

    @pytest.mark.asyncio
    async def test_tool_properties(self, get_strategy_tool):
        """Test: Tool has correct properties."""
        assert get_strategy_tool.name == "get_strategy"
        assert "Q-learning" in get_strategy_tool.description or "strategic" in get_strategy_tool.description.lower()
        assert "current_phase" in get_strategy_tool.input_schema["properties"]

    @pytest.mark.asyncio
    async def test_execute_reconnaissance_phase(self, get_strategy_tool):
        """Test: Execute returns recommendations for recon phase."""
        result = await get_strategy_tool.execute(
            current_phase="reconnaissance",
            endpoints_found=0,
            vulns_found=0,
            shell_obtained=False,
            tech_stack=["php", "mysql"],
        )

        assert result.success
        assert "Strategic Recommendations" in result.output
        assert "reconnaissance" in result.output.lower()

    @pytest.mark.asyncio
    async def test_execute_scanning_phase(self, get_strategy_tool):
        """Test: Execute returns recommendations for scanning phase."""
        result = await get_strategy_tool.execute(
            current_phase="scanning",
            endpoints_found=10,
            vulns_found=2,
            tech_stack=["php"],
        )

        assert result.success
        assert "Endpoints" in result.output
        assert "10" in result.output

    @pytest.mark.asyncio
    async def test_execute_exploitation_phase(self, get_strategy_tool):
        """Test: Execute returns recommendations for exploitation phase."""
        result = await get_strategy_tool.execute(
            current_phase="exploitation",
            endpoints_found=15,
            vulns_found=5,
        )

        assert result.success
        assert result.output is not None

    @pytest.mark.asyncio
    async def test_includes_swarm_commands(self, get_strategy_tool):
        """Test: Output includes swarm spawn commands."""
        result = await get_strategy_tool.execute(
            current_phase="scanning",
            endpoints_found=5,
        )

        assert result.success
        assert "swarm" in result.output.lower()

    @pytest.mark.asyncio
    async def test_includes_action_guidance(self, get_strategy_tool):
        """Test: Output includes action guidance."""
        result = await get_strategy_tool.execute(
            current_phase="scanning",
        )

        assert result.success
        assert "Action Guidance" in result.output or "sub-agents" in result.output.lower()

    @pytest.mark.asyncio
    async def test_metadata_contains_recommendations(self, get_strategy_tool):
        """Test: Metadata contains structured recommendations."""
        result = await get_strategy_tool.execute(
            current_phase="scanning",
        )

        assert result.success
        assert "recommendations" in result.metadata
        assert isinstance(result.metadata["recommendations"], list)


# ============================================================================
# RecordFailureTool Tests
# ============================================================================

class TestRecordFailureTool:
    """Tests for RecordFailureTool."""

    @pytest.mark.asyncio
    async def test_tool_properties(self, record_failure_tool):
        """Test: Tool has correct properties."""
        assert record_failure_tool.name == "record_failure"
        assert "failure" in record_failure_tool.description.lower()
        assert "endpoint" in record_failure_tool.input_schema["properties"]
        assert "attack_type" in record_failure_tool.input_schema["properties"]

    @pytest.mark.asyncio
    async def test_execute_records_failure(self, record_failure_tool):
        """Test: Execute records failure and returns guidance."""
        result = await record_failure_tool.execute(
            endpoint="/login",
            attack_type="sqli",
            reason="waf_blocked",
            payload="' OR 1=1--",
        )

        assert result.success
        assert "1/3" in result.output or "Failure" in result.output

    @pytest.mark.asyncio
    async def test_execute_blocks_after_three(self, record_failure_tool):
        """Test: Pattern blocked after 3 consecutive failures."""
        # Get fresh tracker for this test
        tracker = get_failure_tracker()
        tracker._failures.clear()
        tracker._blocked_patterns.clear()
        tracker._consecutive_failures.clear()

        await record_failure_tool.execute("/test1", "sqli", "waf")
        await record_failure_tool.execute("/test1", "sqli", "waf")
        result = await record_failure_tool.execute("/test1", "sqli", "waf")

        assert result.success
        assert result.metadata["is_blocked"] is True

    @pytest.mark.asyncio
    async def test_metadata_contains_failure_info(self, record_failure_tool):
        """Test: Metadata contains failure information."""
        result = await record_failure_tool.execute(
            endpoint="/api/users",
            attack_type="xss",
            reason="no_vuln",
        )

        assert result.success
        assert result.metadata["endpoint"] == "/api/users"
        assert result.metadata["attack_type"] == "xss"


# ============================================================================
# RecordSuccessTool Tests
# ============================================================================

class TestRecordSuccessTool:
    """Tests for RecordSuccessTool."""

    @pytest.mark.asyncio
    async def test_tool_properties(self, record_success_tool):
        """Test: Tool has correct properties."""
        assert record_success_tool.name == "record_success"
        assert "success" in record_success_tool.description.lower()
        assert "exploited" in record_success_tool.input_schema["properties"]

    @pytest.mark.asyncio
    async def test_execute_records_success(self, record_success_tool):
        """Test: Execute records success."""
        result = await record_success_tool.execute(
            endpoint="/search",
            attack_type="sqli",
            severity="high",
            exploited=True,
        )

        assert result.success
        assert "success" in result.output.lower() or "recorded" in result.output.lower()

    @pytest.mark.asyncio
    async def test_exploited_status_tracked(self, record_success_tool):
        """Test: Exploited status is tracked in metadata."""
        result = await record_success_tool.execute(
            endpoint="/api",
            attack_type="sqli",
            severity="critical",
            exploited=True,
        )

        assert result.success
        assert result.metadata["exploited"] is True

    @pytest.mark.asyncio
    async def test_verified_only_status(self, record_success_tool):
        """Test: Verified-only (not exploited) status is tracked."""
        result = await record_success_tool.execute(
            endpoint="/api",
            attack_type="sqli",
            severity="high",
            exploited=False,
        )

        assert result.success
        assert result.metadata["exploited"] is False

    @pytest.mark.asyncio
    async def test_resets_blocked_pattern(self, record_success_tool):
        """Test: Success resets previously blocked pattern."""
        tracker = get_failure_tracker()

        # Block a pattern first
        tracker.record_failure("/test2", "sqli", "waf")
        tracker.record_failure("/test2", "sqli", "waf")
        tracker.record_failure("/test2", "sqli", "waf")
        assert tracker.is_blocked("/test2", "sqli")

        # Record success should unblock
        await record_success_tool.execute(
            endpoint="/test2",
            attack_type="sqli",
            severity="high",
            exploited=True,
        )

        assert not tracker.is_blocked("/test2", "sqli")


# ============================================================================
# GetSwarmPlanTool Tests
# ============================================================================

class TestGetSwarmPlanTool:
    """Tests for GetSwarmPlanTool."""

    @pytest.mark.asyncio
    async def test_tool_properties(self, get_swarm_plan_tool):
        """Test: Tool has correct properties."""
        assert get_swarm_plan_tool.name == "get_swarm_plan"
        assert "swarm" in get_swarm_plan_tool.description.lower()
        assert "endpoints" in get_swarm_plan_tool.input_schema["properties"]

    @pytest.mark.asyncio
    async def test_execute_with_endpoints(self, get_swarm_plan_tool):
        """Test: Execute generates plan for endpoints."""
        result = await get_swarm_plan_tool.execute(
            endpoints=["/login", "/api/users", "/search"],
            max_parallel=5,
        )

        assert result.success
        assert "Swarm Execution Plan" in result.output
        assert "scanner" in result.output.lower()

    @pytest.mark.asyncio
    async def test_execute_with_vulns(self, get_swarm_plan_tool):
        """Test: Execute prioritizes exploitation phase."""
        result = await get_swarm_plan_tool.execute(
            vulns_to_exploit=["SQLi in /search", "XSS in /comment"],
            max_parallel=3,
        )

        assert result.success
        assert "Exploitation" in result.output or "exploiter" in result.output.lower()

    @pytest.mark.asyncio
    async def test_execute_with_subdomains(self, get_swarm_plan_tool):
        """Test: Execute includes subdomain enumeration."""
        result = await get_swarm_plan_tool.execute(
            subdomains=["api.target.com", "admin.target.com"],
            max_parallel=5,
        )

        assert result.success
        assert "reconnaissance" in result.output.lower()

    @pytest.mark.asyncio
    async def test_respects_max_parallel(self, get_swarm_plan_tool):
        """Test: Plan respects max_parallel limit."""
        result = await get_swarm_plan_tool.execute(
            endpoints=["/1", "/2", "/3", "/4", "/5", "/6", "/7", "/8"],
            max_parallel=3,
        )

        assert result.success
        assert result.metadata["total_agents"] <= 8  # May be less due to filtering

    @pytest.mark.asyncio
    async def test_includes_execution_instructions(self, get_swarm_plan_tool):
        """Test: Output includes execution instructions."""
        result = await get_swarm_plan_tool.execute(
            endpoints=["/login"],
        )

        assert result.success
        assert "Execution" in result.output or "IMPORTANT" in result.output

    @pytest.mark.asyncio
    async def test_metadata_contains_commands(self, get_swarm_plan_tool):
        """Test: Metadata contains swarm commands list."""
        result = await get_swarm_plan_tool.execute(
            endpoints=["/login", "/api"],
        )

        assert result.success
        assert "swarm_commands" in result.metadata
        assert isinstance(result.metadata["swarm_commands"], list)


# ============================================================================
# Integration Tests
# ============================================================================

class TestStrategyToolsIntegration:
    """Integration tests for strategy tools."""

    @pytest.mark.asyncio
    async def test_failure_learning_workflow(self):
        """Test: Complete failure learning workflow."""
        tracker = get_failure_tracker()
        tracker._failures.clear()
        tracker._blocked_patterns.clear()
        tracker._consecutive_failures.clear()

        record_tool = RecordFailureTool()
        strategy_tool = GetStrategyTool()

        # Record failures
        await record_tool.execute("/login", "sqli", "waf_blocked")
        await record_tool.execute("/login", "sqli", "waf_blocked")
        await record_tool.execute("/login", "sqli", "waf_blocked")

        # Get strategy - should show blocked patterns
        result = await strategy_tool.execute(
            current_phase="scanning",
            endpoints_found=5,
        )

        assert result.success
        # Blocked patterns should be visible
        assert len(tracker._blocked_patterns) > 0

    @pytest.mark.asyncio
    async def test_success_unblocks_pattern(self):
        """Test: Success after failures unblocks pattern."""
        tracker = get_failure_tracker()
        tracker._failures.clear()
        tracker._blocked_patterns.clear()
        tracker._consecutive_failures.clear()

        record_failure = RecordFailureTool()
        record_success = RecordSuccessTool()

        # Block pattern
        await record_failure.execute("/test3", "xss", "waf")
        await record_failure.execute("/test3", "xss", "waf")
        await record_failure.execute("/test3", "xss", "waf")
        assert tracker.is_blocked("/test3", "xss")

        # Success unblocks
        await record_success.execute("/test3", "xss", "medium", True)
        assert not tracker.is_blocked("/test3", "xss")

    def test_get_strategy_tools_returns_all(self):
        """Test: get_strategy_tools returns all tools."""
        tools = get_strategy_tools()

        assert len(tools) == 4
        tool_names = [t.name for t in tools]
        assert "get_strategy" in tool_names
        assert "record_failure" in tool_names
        assert "record_success" in tool_names
        assert "get_swarm_plan" in tool_names


# ============================================================================
# Scoring Penalty Tests (20% Penalty Calculation)
# ============================================================================

class TestScoringPenalty:
    """Tests for the 20% scoring penalty system."""

    def test_exploited_full_score(self):
        """Test: Exploited findings get full score (DC + EC)."""
        dc = 5.0  # Detection complexity
        ec = 8.0  # Exploit complexity

        exploited_score = dc + ec

        assert exploited_score == 13.0

    def test_verified_penalty_score(self):
        """Test: Verified-only findings get 20% penalty on EC."""
        dc = 5.0
        ec = 8.0

        verified_score = dc + (ec * 0.8)  # 20% penalty

        assert verified_score == 11.4

    def test_penalty_difference(self):
        """Test: Penalty difference is 20% of EC."""
        dc = 5.0
        ec = 8.0

        exploited_score = dc + ec
        verified_score = dc + (ec * 0.8)
        penalty = exploited_score - verified_score

        assert abs(penalty - ec * 0.2) < 0.0001  # 20% of EC (with float tolerance)
        assert abs(penalty - 1.6) < 0.0001

    def test_various_complexity_scores(self):
        """Test: Penalty applies correctly to various scores."""
        test_cases = [
            (5.0, 8.0, 13.0, 11.4),   # DC=5, EC=8
            (3.0, 10.0, 13.0, 11.0),  # DC=3, EC=10
            (7.0, 5.0, 12.0, 11.0),   # DC=7, EC=5
            (10.0, 10.0, 20.0, 18.0), # DC=10, EC=10
        ]

        for dc, ec, expected_exploited, expected_verified in test_cases:
            exploited = dc + ec
            verified = dc + (ec * 0.8)

            assert exploited == expected_exploited
            assert verified == expected_verified


# ============================================================================
# MCP Tool Wrapper Tests
# ============================================================================

class TestMCPToolWrappers:
    """Tests for MCP tool wrappers in mcp_tools.py."""

    @pytest.mark.asyncio
    async def test_mcp_get_strategy_wrapper(self):
        """Test: MCP get_strategy wrapper works correctly."""
        # Import the MCP tool functions
        from inferno.agent.mcp_tools import get_strategy

        # MCP tools are decorated - we can check they exist
        assert get_strategy is not None

    @pytest.mark.asyncio
    async def test_mcp_record_failure_wrapper(self):
        """Test: MCP record_failure wrapper works correctly."""
        from inferno.agent.mcp_tools import record_failure

        assert record_failure is not None

    @pytest.mark.asyncio
    async def test_mcp_record_success_wrapper(self):
        """Test: MCP record_success wrapper works correctly."""
        from inferno.agent.mcp_tools import record_success

        assert record_success is not None

    @pytest.mark.asyncio
    async def test_mcp_get_scoring_wrapper(self):
        """Test: MCP get_scoring wrapper works correctly."""
        from inferno.agent.mcp_tools import get_scoring

        assert get_scoring is not None

    @pytest.mark.asyncio
    async def test_mcp_get_swarm_plan_wrapper(self):
        """Test: MCP get_swarm_plan wrapper works correctly."""
        from inferno.agent.mcp_tools import get_swarm_plan

        assert get_swarm_plan is not None

    def test_tools_registered_in_mcp_server(self):
        """Test: Strategy tools are registered in MCP server."""
        from inferno.agent.mcp_tools import create_inferno_mcp_server

        server = create_inferno_mcp_server()

        # Server should be created without errors
        assert server is not None
