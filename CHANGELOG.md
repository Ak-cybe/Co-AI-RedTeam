# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-18

### Added

- **Core Orchestrator** — 6-phase pipeline: Recon → Discovery → Exploitation → Patching → Reporting → Memory
- **Analysis Agent** — Code-aware vulnerability discovery with CWE/OWASP grounding and evidence chain generation
- **Critique Agent** — Independent validation with false positive filtering and risk assessment
- **Planner Agent** — Explicit, revisable exploit plans with step-by-step strategies
- **Executor Agent** — Sandboxed command execution via Docker with local fallback
- **Evaluator Agent** — Execution assessment with deviation detection and actionable feedback
- **Patcher Agent** — RCA-driven patch generation with reflection-based retry loop
- **3-Layer Memory System** — Persistent storage for vulnerability patterns, strategies, and technical actions
- **SARIF v2.1.0 Reporter** — GitHub Code Scanning compatible output with code flows and fix suggestions
- **Markdown Reporter** — Executive-ready assessment reports with severity breakdowns
- **CLI Interface** — `co-redteam` / `cart` commands for scan, init, and memory management
- **Role-Aware Tool Assignment** — Principle of least privilege for all agents
- **CI/CD Pipeline** — GitHub Actions for lint, test, security scan, and automated releases
- **Test Suite** — Comprehensive tests for config, memory, reporting, and agents

### Research Foundation

- Implements [Co-RedTeam](https://arxiv.org/abs/2602.02164) multi-agent architecture
- Implements [AIxCC](https://arxiv.org/abs/2602.07666) CRS patch pipeline techniques
