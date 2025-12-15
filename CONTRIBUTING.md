# Contributing to Inferno-AI

Thank you for your interest in contributing to Inferno-AI! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Focus on constructive feedback
- Accept responsibility for mistakes
- Prioritize security and ethical use

### Unacceptable Behavior

- Harassment or discriminatory language
- Sharing malicious code or techniques
- Violating others' privacy
- Promoting unauthorized hacking

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- Docker (for testing)
- Familiarity with security concepts

### First Contribution

Good first issues are labeled `good-first-issue`. These are typically:
- Documentation improvements
- Bug fixes
- Small feature additions
- Test coverage improvements

## Development Setup

### 1. Fork and Clone

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/Inferno.git
cd Inferno
```

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### 4. Install Pre-commit Hooks

```bash
pre-commit install
```

### 5. Start Required Services

```bash
# Start Qdrant for testing
docker run -d -p 6333:6333 --name inferno-dev-qdrant qdrant/qdrant
```

### 6. Verify Setup

```bash
# Run tests
pytest tests/

# Run type checking
mypy src/inferno

# Run linting
ruff check src/
```

## Making Changes

### Branch Naming

Use descriptive branch names:

```bash
# Features
git checkout -b feature/add-nuclei-support

# Bug fixes
git checkout -b fix/oauth-token-refresh

# Documentation
git checkout -b docs/improve-installation-guide
```

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

Examples:
```
feat(tools): add nuclei scanner support
fix(auth): handle expired OAuth tokens gracefully
docs(readme): add macOS installation steps
```

## Code Style

### Python Style

We use:
- **Ruff** for linting
- **Black** for formatting
- **isort** for import sorting
- **mypy** for type checking

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/inferno
```

### Style Guidelines

1. **Type hints** - All functions should have type hints
   ```python
   def process_target(url: str, timeout: int = 30) -> dict[str, Any]:
       ...
   ```

2. **Docstrings** - Use Google style
   ```python
   def execute_command(command: str) -> ToolResult:
       """Execute a shell command.

       Args:
           command: The command to execute.

       Returns:
           ToolResult with command output.

       Raises:
           CommandError: If execution fails.
       """
   ```

3. **Constants** - Use UPPER_SNAKE_CASE
   ```python
   MAX_RETRIES = 3
   DEFAULT_TIMEOUT = 30
   ```

4. **Classes** - Use PascalCase
   ```python
   class ToolRegistry:
       ...
   ```

### Project Structure

```
src/inferno/
├── agent/          # Agent execution logic
├── auth/           # Authentication providers
├── cli/            # Command-line interface
├── config/         # Configuration management
├── core/           # Core infrastructure
├── handlers/       # Event handlers
├── memory/         # Memory system
├── prompts/        # Prompt templates
├── reporting/      # Report generation
├── swarm/          # Multi-agent coordination
├── tools/          # Tool implementations
└── utils/          # Utilities
```

## Testing

### Running Tests

```bash
# All tests
pytest tests/

# Specific test file
pytest tests/test_tools.py

# With coverage
pytest tests/ --cov=src/inferno --cov-report=html

# Only unit tests
pytest tests/ -m "not integration"

# Only integration tests
pytest tests/ -m integration
```

### Writing Tests

1. **Location** - Tests go in `tests/` mirroring `src/inferno/` structure
2. **Naming** - `test_<module>.py` or `<module>_test.py`
3. **Functions** - `test_<what_is_being_tested>`

Example:
```python
# tests/test_tools.py
import pytest
from inferno.tools import execute_command

@pytest.mark.asyncio
async def test_execute_command_returns_output():
    """Test that execute_command returns command output."""
    result = await execute_command("echo hello")
    assert result.success
    assert "hello" in result.output

@pytest.mark.asyncio
async def test_execute_command_blocks_dangerous():
    """Test that dangerous commands are blocked."""
    result = await execute_command("rm -rf /")
    assert not result.success
    assert "blocked" in result.error.lower()
```

### Test Categories

Mark tests appropriately:
```python
@pytest.mark.slow
def test_full_scan():
    ...

@pytest.mark.integration
def test_qdrant_connection():
    ...

@pytest.mark.e2e
def test_complete_workflow():
    ...
```

## Submitting Changes

### Pull Request Process

1. **Update documentation** - If adding features, update docs
2. **Add tests** - New code should have tests
3. **Pass CI** - All checks must pass
4. **Request review** - Tag maintainers

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Refactoring

## Testing
How was this tested?

## Checklist
- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] No sensitive data in commits
```

### Review Process

1. Automated checks run (lint, test, type check)
2. Maintainer reviews code
3. Address feedback
4. Merge when approved

## Reporting Issues

### Bug Reports

Include:
- Inferno version (`inferno --version`)
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

Template:
```markdown
**Describe the bug**
A clear description of the bug.

**To Reproduce**
1. Run `inferno shell`
2. Execute `target https://...`
3. Run `run`
4. See error

**Expected behavior**
What should happen.

**Environment**
- Inferno version: 0.1.0
- Python version: 3.11.4
- OS: macOS 14.0

**Logs**
```
Paste relevant logs here
```
```

### Feature Requests

Include:
- Use case description
- Proposed solution
- Alternatives considered

### Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead, email security concerns privately to the maintainers.

## Adding New Tools

### Philosophy

Remember: Inferno's philosophy is "4 core tools." Before adding a new tool, consider:

1. Can `execute_command` handle this?
2. Does it provide unique value not achievable otherwise?
3. Is it general enough to warrant inclusion?

### If a New Tool is Needed

1. Create in `src/inferno/tools/`
2. Use the `@function_tool` decorator
3. Implement `ToolResult` return type
4. Add comprehensive tests
5. Document in tool docstring

```python
from inferno.tools.base import ToolCategory, ToolResult
from inferno.tools.decorator import function_tool

@function_tool(
    category=ToolCategory.CORE,
    name="new_tool",
    description="Description of what this tool does."
)
async def new_tool(
    param: str,
    optional_param: int = 10,
) -> ToolResult:
    """
    Detailed description.

    Args:
        param: Description of param.
        optional_param: Description with default.

    Returns:
        ToolResult with output.
    """
    # Implementation
    return ToolResult(success=True, output="result")
```

## Questions?

- Open a GitHub Discussion for questions
- Check existing issues before creating new ones
- Join community channels (if available)

Thank you for contributing!
