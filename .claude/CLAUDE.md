# Inferno-AI

Autonomous Penetration Testing Agent powered by Claude with the Stanford paper multi-agent architecture, algorithm-driven decision making, and advanced coordination features.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        INFERNO AGENT                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │  Supervisor  │───▶│  Sub-Agents  │───▶│   Triage     │      │
│  │ (Coordinator)│    │  (Workers)   │    │ (Validator)  │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Algorithm & Strategy Layer                  │   │
│  │  • Q-Learning (action sequencing)                       │   │
│  │  • Multi-Armed Bandits (attack selection)               │   │
│  │  • 20% Penalty Scoring (exploit vs verify)              │   │
│  │  • Failure Tracking (blocks after 3 failures)           │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                   │                   │               │
│         ▼                   ▼                   ▼               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Intelligence Layer                          │   │
│  │  • HintExtractor    • ResponseAnalyzer                  │   │
│  │  • DifferentialAnalyzer    • AttackSelector             │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Strategy Tools (MCP)

Algorithm-driven decision making exposed via MCP tools:

| Tool | Purpose | Key Feature |
|------|---------|-------------|
| `get_strategy` | Q-Learning recommendations | Returns ranked actions with Q-values |
| `record_failure` | Track failed attacks | Blocks pattern after 3 consecutive failures |
| `record_success` | Record successful exploits | 20% penalty if not fully exploited |
| `get_scoring` | Display penalty calculation | Shows DC + EC vs DC + EC×0.8 |
| `get_swarm_plan` | Generate parallel spawn plan | Executable swarm commands |

### 2. 20% Scoring Penalty

**CRITICAL**: Verified-only findings are PENALIZED. Agents must EXPLOIT, not just detect.

```
| Status     | Formula          | Example (DC=5, EC=8) |
|------------|------------------|----------------------|
| EXPLOITED  | TC = DC + EC     | 13.0 ✓ FULL POINTS   |
| VERIFIED   | TC = DC + EC×0.8 | 11.4 (-1.6 penalty!) |
```

### 3. Intelligence Features

| Component | Integration | Purpose |
|-----------|-------------|---------|
| HintExtractor | sdk_executor.py, http.py | Technology fingerprints, CTF hints |
| ResponseAnalyzer | http.py, execute_command.py | WAF detection, bypass suggestions |
| DifferentialAnalyzer | http.py | Blind injection detection |
| AttackSelector | sdk_executor.py | Prioritized attack vectors |
| AlgorithmManager | strategy.py | MAB, Bayesian, MCTS, Budget |

### 4. Swarm Architecture

Sub-agents spawn with `max_turns=100` for complex tasks:

| Worker Type | Job | When to Spawn |
|-------------|-----|---------------|
| `reconnaissance` | nmap, gobuster, subfinder | Initial discovery |
| `scanner` | nuclei, vulnerability detection | Each endpoint |
| `exploiter` | sqlmap, XSS exploitation | Each confirmed vuln |
| `validator` | Independent verification | Each finding |
| `waf_bypass` | Bypass WAF/filters | When blocked |
| `post_exploitation` | Privilege escalation | After initial access |

## Tech Stack

- **Language**: Python 3.11+
- **AI Framework**: Claude API + Claude Agent SDK
- **Memory**: Mem0 with Qdrant vector database
- **CLI**: Typer + Rich
- **Configuration**: Pydantic + python-dotenv

## Project Structure

```
src/inferno/
├── agent/                   # Main agent execution
│   ├── sdk_executor.py      # SDKAgentExecutor (primary)
│   ├── prompts.py           # SystemPromptBuilder
│   ├── mcp_tools.py         # MCP server tools (incl. strategy tools)
│   └── strategic_planner.py # Strategic planning
├── algorithms/              # Learning algorithms
│   ├── manager.py           # AlgorithmManager (orchestrates all)
│   ├── qlearning.py         # Q-Learning for action sequencing
│   ├── bandits.py           # Multi-Armed Bandits
│   ├── bayesian.py          # Bayesian confidence
│   ├── mcts.py              # Monte Carlo Tree Search
│   └── budget.py            # Dynamic budget allocation
├── cli/                     # Command-line interface
│   ├── main.py              # Typer app
│   └── shell.py             # Interactive shell
├── core/                    # Core infrastructure
│   ├── scope.py             # CRITICAL: Scope enforcement
│   ├── guardrails.py        # Security policies
│   ├── attack_selector.py   # Technology-to-attack mapping
│   ├── hint_extractor.py    # Response hint extraction
│   ├── response_analyzer.py # WAF/filter detection
│   ├── differential_analyzer.py # Blind injection detection
│   ├── assessment_scoring.py # 20% penalty scoring
│   └── payload_mutator.py   # Bypass payload generation
├── tools/                   # Core tools
│   ├── execute_command.py   # Command execution
│   ├── http.py              # HTTP requests
│   ├── memory.py            # Mem0 integration
│   ├── think.py             # Structured reasoning
│   └── strategy.py          # Strategy tools (Q-Learning, failure tracking)
├── swarm/                   # Sub-agent coordination
│   ├── tool.py              # SwarmTool
│   ├── agents.py            # SubAgentConfig (max_turns=100)
│   ├── parallel_orchestrator.py # Parallel task execution
│   ├── coordination.py      # Coordination modules
│   └── message_bus.py       # Inter-agent communication
├── prompts/                 # Prompt system
│   └── dynamic_generator.py # Task-specific prompt generation
└── runner.py                # InfernoRunner (unified runner)
```

## CLI Usage

```bash
# Interactive mode
inferno shell

# Then in shell:
inferno> target https://target.com
inferno> objective Find vulnerabilities
inferno> run           # Uses Stanford architecture (Supervisor + SubAgents)
inferno> run-legacy    # Uses old single-agent architecture
```

## Agent Behavior

### Mandatory Workflow

1. **Call `get_strategy`** before deciding what to do
2. **Spawn swarm workers** for parallel execution (not manual testing)
3. **Record failures** with `record_failure` (algorithm learns)
4. **Exploit findings** to get full points (not just detect)
5. **Record successes** with `record_success(exploited=true)`

### Prompts Enforce

```
🚨 SCORING: 20% PENALTY FOR NOT EXPLOITING!

🤖 USE ALGORITHMS (MANDATORY)
- get_strategy() before every action
- record_failure() after every failed attack
- record_success(exploited=true) for full points

🔥 SPAWN SWARM WORKERS (MANDATORY)
- Never test manually - spawn workers
- 5-10 workers in parallel with background=true
```

## Configuration

### Authentication

```bash
# If using Claude Code, just login there first:
claude login

# Or set API key directly:
export ANTHROPIC_API_KEY=sk-ant-...
```

### Environment Variables

```bash
INFERNO_API_KEY=sk-ant-...
INFERNO_MODEL=claude-sonnet-4-20250514
INFERNO_GUARDRAILS=true
```

## Development

### Setup
```bash
pip install -e ".[dev]"
inferno setup
```

### Running Tests
```bash
pytest tests/                    # All tests
pytest tests/unit/               # Unit tests (321 tests)
pytest tests/integration/        # Integration tests
pytest tests/unit/tools/test_strategy_tools.py  # Strategy tool tests (47 tests)
```

## Key Differentiators

| Feature | Inferno | Traditional Agents |
|---------|---------|-------------------|
| Algorithm-driven decisions | ✓ (Q-Learning, MAB) | ✗ |
| 20% exploitation penalty | ✓ | ✗ |
| Failure pattern blocking | ✓ (after 3 failures) | ✗ |
| Parallel sub-agents | ✓ (8 concurrent, 100 turns each) | ✗ |
| WAF bypass intelligence | ✓ (ResponseAnalyzer) | ✗ |
| Blind injection detection | ✓ (DifferentialAnalyzer) | ✗ |
| Cross-session memory | ✓ (Mem0 + Qdrant) | ✗ |
| Real-time coordination | ✓ (MessageBus) | ✗ |

## Testing Against Real CTFs

```python
from inferno.runner import InfernoRunner, RunConfig

runner = InfernoRunner()
result = await runner.run(RunConfig(
    target="10.10.10.x",
    objective="Obtain root flag",
))

# Agents will:
# 1. Use get_strategy() to decide attack order
# 2. Spawn parallel workers for recon/scanning
# 3. Exploit findings (not just detect) for full points
# 4. Learn from failures via record_failure()
# 5. Validate all findings before reporting
```

If it can't get root on machines that humans solve, it's broken. Ship when it works.
