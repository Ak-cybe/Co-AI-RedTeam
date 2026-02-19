# Contributing to Co-AI-RedTeam

Thank you for your interest in contributing! This document provides guidelines for contributing effectively.

## 🚀 Getting Started

```bash
# Clone the repository
git clone https://github.com/co-ai-redteam/co-ai-redteam.git
cd co-ai-redteam

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install development dependencies
pip install -e ".[dev]"
```

## 🧪 Development Workflow

### Running Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=co_redteam --cov-report=term-missing

# Specific test file
pytest tests/test_memory.py -v
```

### Linting & Formatting

```bash
# Check lint
ruff check src/ tests/

# Auto-fix linting issues
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/

# Type check
mypy src/co_redteam/ --ignore-missing-imports
```

### Pre-commit

```bash
pip install pre-commit
pre-commit install
```

## 📁 Project Structure

```
co-ai-redteam/
├── src/co_redteam/
│   ├── agents/          # Specialized AI agents
│   │   ├── base.py      # Base agent class + role-aware tools
│   │   ├── analysis.py  # Vulnerability discovery
│   │   ├── critique.py  # Evidence validation
│   │   ├── planner.py   # Exploit planning
│   │   ├── executor.py  # Sandboxed execution
│   │   ├── evaluator.py # Execution assessment
│   │   └── patcher.py   # Patch generation
│   ├── memory/          # 3-layer experience storage
│   ├── reporting/       # SARIF + Markdown generators
│   ├── cli.py           # Command-line interface
│   ├── config.py        # Pydantic configuration
│   └── orchestrator.py  # Central pipeline coordinator
├── tests/               # Test suite
└── .github/workflows/   # CI/CD
```

## 🏗️ Architecture Guidelines

### Adding a New Agent

1. Create `src/co_redteam/agents/your_agent.py`
2. Inherit from `BaseAgent`
3. Define the agent's role in `AgentRole` enum
4. Set tool permissions in `ROLE_TOOL_MAP`
5. Implement `_reason()` method
6. Add tests in `tests/test_agents.py`
7. Register in `agents/__init__.py`

### Adding a New Report Format

1. Create `src/co_redteam/reporting/your_format.py`
2. Accept `list[VulnerabilityDraft]` as input
3. Add to `reporting/__init__.py`
4. Add CLI flag in `cli.py`

## 📝 Code Standards

- **Type annotations** on all public functions
- **Docstrings** on all classes and public methods
- **Pydantic models** for structured data (not raw dicts)
- **No hardcoded credentials** — use env vars or SecretStr
- **Descriptive names** — no single-letter variables
- **Tests required** for all new features

## 🔒 Security

- Never commit API keys, passwords, or secrets
- All exploit execution must be sandboxed
- Memory store must never persist credentials
- Report generation must sanitize sensitive data

## 📬 Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with tests
4. Run `ruff check` and `pytest`
5. Commit with descriptive messages
6. Open a Pull Request with:
   - Description of the change
   - Related issue number
   - Test results

## 📜 License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
