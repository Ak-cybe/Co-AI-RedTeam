<div align="center">

# 🛡️ Co-AI-RedTeam

### AI-Powered Multi-Agent Red Teaming Framework

[![CI](https://github.com/Ak-cybe/Co-AI-RedTeam/actions/workflows/ci.yml/badge.svg)](https://github.com/Ak-cybe/Co-AI-RedTeam/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

*Autonomous vulnerability discovery, exploitation, and patching using coordinated AI agents.*

[Quickstart](#-quickstart) · [Architecture](#-architecture) · [Documentation](#-documentation) · [Contributing](#-contributing)

</div>

---

## 🎯 What is Co-AI-RedTeam?

**Co-AI-RedTeam** (CART) is a production-grade framework that orchestrates multiple specialized AI agents to perform end-to-end security assessments. It automates the full red team pipeline — from reconnaissance to patching — using research-backed multi-agent architectures.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Co-AI-RedTeam Pipeline                          │
│                                                                     │
│  📁 Recon    🔍 Discovery    💣 Exploitation    🔧 Patching    📄 Report  │
│  ───────>>> ────────────>>> ───────────────>>> ───────────>>> ─────>>> │
│              Analysis ↕       Plan → Validate   RCA → Gen      SARIF  │
│              Critique         → Execute          → Validate      MD    │
│              (3 rounds)       → Evaluate         (5 retries)           │
│                               (20 iterations)                         │
│                                                                     │
│  🧠 Long-Term Memory: Patterns │ Strategies │ Actions               │
└─────────────────────────────────────────────────────────────────────┘
```

### Why CART?

| Feature | Traditional SAST | Generic AI Scanner | **Co-AI-RedTeam** |
|---------|:---:|:---:|:---:|
| Multi-agent analysis-critique loop | ❌ | ❌ | ✅ |
| Execution-grounded exploitation | ❌ | ❌ | ✅ |
| Automated patch generation | ❌ | Partial | ✅ |
| CWE/OWASP grounded reasoning | ✅ | Partial | ✅ |
| Evidence chain construction | ❌ | ❌ | ✅ |
| Cross-assessment memory | ❌ | ❌ | ✅ |
| SARIF + GitHub integration | ✅ | Partial | ✅ |
| Sandboxed execution | N/A | ❌ | ✅ |

## 📚 Based on Research

CART implements techniques from two peer-reviewed papers:

- **[Co-RedTeam](https://arxiv.org/abs/2602.02164)** — "Orchestrated Security Discovery and Exploitation with LLM Agents" — Multi-agent framework with Analysis-Critique loop (Stage I) and Plan-Execute-Evaluate loop (Stage II)
- **[AIxCC SoK](https://arxiv.org/abs/2602.07666)** — "SoK: DARPA's AI Cyber Challenge" — CRS architectures for vulnerability discovery and patch generation

---

## 🚀 Quickstart

### Installation

```bash
pip install co-ai-redteam
```

Or install from source:

```bash
git clone https://github.com/Ak-cybe/Co-AI-RedTeam.git
cd Co-AI-RedTeam
pip install -e ".[dev]"
```

### Set Up API Key

```bash
# Gemini (default)
export GEMINI_API_KEY="your-api-key"

# Or OpenAI
export OPENAI_API_KEY="your-api-key"
```

### Run Your First Scan

```bash
# Full red team assessment
co-redteam scan ./your-project

# Or use the short alias
cart scan ./your-project

# Discovery only (no exploitation)
cart scan ./your-project --no-exploit --no-patch

# Check only Critical/High
cart scan ./your-project --severity high

# With a vulnerability hint
cart scan ./your-project --hint "Check the authentication module for bypass"

# Custom output directory
cart scan ./your-project --output ./security-reports
```

### Example Output

```
   ____              _    ___   ____          _ _____
  / ___|___         / \  |_ _| |  _ \ ___  __| |_   _|__  __ _ _ __ ___
 | |   / _ \ _____ / _ \  | |  | |_) / _ \/ _` | | |/ _ \/ _` | '_ ` _ \
 | |__| (_) |_____/ ___ \ | |  |  _ <  __/ (_| | | |  __/ (_| | | | | | |
  \____\___/     /_/   \_\___| |_| \_\___|\__,_| |_|\___|\__,_|_| |_| |_|

⟐ Phase 1: Reconnaissance
  📁 Files scanned: 47
  🔧 Tech stack: Python, Flask   

⟐ Phase 2: Vulnerability Discovery
  🔍 Analysis Agent found 5 candidates
  ✓ Critique 1: 3 approved, 2 rejected
  ✓ Critique 2: 3 approved, 0 rejected
  📊 Final: 3 confirmed vulnerabilities

⟐ Phase 3: Exploitation
  🎯 Targeting: VULN-001 — SQL Injection in user query
    📋 Plan: 5 steps
    → Step 1: Identify injection point ✅
    → Step 2: Craft payload ✅
    → Step 3: Execute PoC ✅
    ✅ Exploited (3 iterations)

⟐ Phase 4: Security Patching
  🔧 Patching: VULN-001 — SQL Injection in user query
    📍 RCA: f-string interpolation in cursor.execute()
    ✅ Patch generated (attempt 1, confidence: 92%)

⟐ Phase 5: Reporting
  📄 Markdown: reports/assessment_report.md
  📄 SARIF: reports/findings.sarif

⟐ Phase 6: Memory Accumulation
  🧠 Memory: 3 patterns, 1 strategies, 2 actions

┌──────────────────────────────┐
│      Assessment Summary      │
├──────────────┬───────────────┤
│ Duration     │         42.5s │
│ Files Scanned│            47 │
│ Vulns Found  │             3 │
│   Critical   │             1 │
│   High       │             1 │
│   Medium     │             1 │
│ Patches      │             3 │
└──────────────┴───────────────┘
```

---

## 🏗️ Architecture

### Multi-Agent System

```
┌─────────────────────────────────────────────────────────────┐
│                       ORCHESTRATOR                          │
│  Manages pipeline flow, agent lifecycle, state transitions  │
└──────────┬────────────┬──────────────┬──────────────┬───────┘
           │            │              │              │
    ┌──────▼──────┐  ┌──▼───────┐  ┌──▼──────┐  ┌───▼──────┐
    │  DISCOVERY  │  │ EXPLOIT  │  │ PATCH   │  │ REPORT   │
    │             │  │          │  │         │  │          │
    │ ┌─────────┐ │  │ Planner  │  │ RCA     │  │ SARIF    │
    │ │Analysis │ │  │ Validator│  │ Generate│  │ Markdown │
    │ │  Agent  │ │  │ Executor │  │ Validate│  │ HTML     │
    │ └────┬────┘ │  │ Evaluator│  │ Reflect │  │          │
    │      ↕      │  │          │  │         │  │          │
    │ ┌────┴────┐ │  │          │  │         │  │          │
    │ │Critique │ │  │          │  │         │  │          │
    │ │  Agent  │ │  │          │  │         │  │          │
    │ └─────────┘ │  │          │  │         │  │          │
    └─────────────┘  └──────────┘  └─────────┘  └──────────┘
                                                     │
                        ┌────────────────────────────┘
                        ▼
                 ┌──────────────┐
                 │   MEMORY     │
                 │ ┌──────────┐ │
                 │ │ Patterns │ │  Layer 1: What vulnerabilities look like
                 │ │Strategies│ │  Layer 2: How to approach exploitation
                 │ │ Actions  │ │  Layer 3: Concrete commands that work
                 │ └──────────┘ │
                 └──────────────┘
```

### Role-Aware Tool Assignment

Each agent is granted **only the tools it needs** (principle of least privilege):

| Agent | Code Browse | Vuln Docs | Memory | Execute | Edit | Build/Test | Safety |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Analysis | ✅ | ✅ | 📖 | ❌ | ❌ | ❌ | ❌ |
| Critique | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Planner | ✅ | ✅ | 📖 | ❌ | ❌ | ❌ | ❌ |
| Validator | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Executor | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Evaluator | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Patcher | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |

### Key Innovations

1. **Analysis-Critique Loop** — Internal debate between specialized agents eliminates false positives
2. **Explicit Exploit Plans** — Inspectable, revisable step-by-step exploitation strategies  
3. **Execution-Grounded Reasoning** — Real sandbox output drives plan revision, not hallucination
4. **3-Layer Memory** — Patterns (what), Strategies (how), Actions (concrete commands) evolve over time
5. **Reflection-Based Patching** — Failed patches inform subsequent attempts via the AIxCC RCA→Generate→Validate loop

---

## 📖 Documentation

### Configuration

Generate a config file:

```bash
cart init ./my-project
```

This creates `.co-redteam.yml`:

```yaml
target_path: ./my-project
scope: full

llm:
  provider: gemini
  model: gemini-2.5-pro
  temperature: 0.1

discovery:
  max_critique_iterations: 3
  min_confidence: 0.6

exploit:
  max_iterations: 20
  sandbox_execution: true

patch:
  max_retry_attempts: 5

memory:
  enabled: true
  storage_dir: .cart_memory

report:
  generate_sarif: true
  generate_markdown: true
```

### Python API

```python
import asyncio
from co_redteam import Orchestrator, RedTeamConfig

async def main():
    config = RedTeamConfig(target_path="./vulnerable-app")
    orchestrator = Orchestrator(config)
    result = await orchestrator.run()
    
    print(f"Found {result['vulnerabilities_found']} vulnerabilities")
    print(f"Generated {result['patches_generated']} patches")

asyncio.run(main())
```

### Memory System

```bash
# View memory statistics
cart memory stats

# List all stored patterns
cart memory list --layer patterns

# Query by CWE
cart memory query CWE-89
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: Run CART Security Scan
  run: |
    pip install co-ai-redteam
    cart scan . --severity high --no-exploit --output reports/
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/findings.sarif
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Setup development environment
git clone https://github.com/Ak-cybe/Co-AI-RedTeam.git
cd Co-AI-RedTeam
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linter
ruff check src/ tests/

# Type check
mypy src/co_redteam/
```

### Priority Areas

- 🧪 Agent prompt engineering improvements
- 🐛 False positive reduction in critique agent
- 🔌 Additional LLM provider support
- 📊 Enhanced SARIF code flow generation
- 🧠 Embedding-based memory retrieval
- 🐳 Pre-built Docker sandbox images

---

## ⚠️ Responsible Use

Co-AI-RedTeam is designed for **authorized security testing only**. 

- ✅ Test your own codebases and applications
- ✅ Run assessments with proper authorization
- ✅ Use in CI/CD pipelines for automated security checks
- ❌ Do NOT use against systems without explicit permission
- ❌ Do NOT use for offensive operations against unauthorized targets

All exploitation occurs within **isolated Docker sandboxes** by default.

---

## 📜 License

[Apache 2.0](LICENSE) — Free for commercial and personal use.

---

## 📊 Project Status

| Component | Status |
|-----------|--------|
| Core Orchestrator | ✅ Complete |
| Analysis Agent | ✅ Complete |
| Critique Agent | ✅ Complete |
| Planner Agent | ✅ Complete |
| Validator Agent | ✅ Complete |
| Executor Agent | ✅ Complete |
| Evaluator Agent | ✅ Complete |
| Patcher Agent | ✅ Complete |
| Memory System (3-Layer) | ✅ Complete |
| SARIF Reports | ✅ Complete |
| Markdown Reports | ✅ Complete |
| CLI Interface | ✅ Complete |
| CI/CD Pipeline | ✅ Complete |
| Docker Sandbox | ✅ Complete |
| Test Suite (46 tests) | ✅ Complete |

---

<div align="center">

**Built with ❤️ using [Co-RedTeam](https://arxiv.org/abs/2602.02164) & [AIxCC](https://arxiv.org/abs/2602.07666) research**

⭐ Star this repo if you find it useful!

</div>
