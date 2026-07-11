# USAF — Ubuntu Security Audit Framework

[![CI](https://github.com/type-3-studio/usaf/actions/workflows/ci.yml/badge.svg)](https://github.com/type-3-studio/usaf/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](http://mypy-lang.org/)

Production-grade security auditing for Ubuntu Linux. Modular plugin architecture with data collection, analysis, and reporting — all in one CLI.

## Features

- **25+ security checks** — SSH, kernel, users, permissions, network, services, containers, and more
- **15 collectors** — gather data from `/proc`, systemd, APT, auditd, Docker/Podman, and more
- **CIS & MITRE ATT&CK mappings** — findings mapped to compliance frameworks
- **Evidence-based findings** — every finding includes actual evidence (file, process, network, registry, etc.)
- **Multiple reporters** — terminal (Rich), JSON, Markdown
- **Scoring engine** — weighted, confidence-aware scoring from A+ to F-
- **Baseline tracking** — diff scans against known-good snapshots
- **Correlation engine** — detect attack patterns across findings
- **Policy engine** — YAML-based policy overrides
- **Zero false-positive philosophy** — default behavior is not a finding; known-safe allowlists built in

## Quick Start

```bash
# Install from source
git clone https://github.com/type-3-studio/usaf.git
cd usaf
pip install -e ".[dev]"

# Run a full scan
usaf scan

# List available checks
usaf list-checks

# Run specific checks
usaf scan --checks SSH-001 KERN-001

# Output as JSON
usaf scan --format json

# Initialize default config
usaf init
```

## Documentation

| Resource | Description |
|----------|-------------|
| [AGENTS.md](AGENTS.md) | Complete guide for developers and AI agents |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add checks and contribute |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [STATE.md](STATE.md) | Project state, roadmap, and technical debt log |
| [ADR/](ADR/) | Architecture Decision Records |

## Requirements

- **Python 3.13+**
- **Ubuntu Linux** (tested on 20.04, 22.04, 24.04, 26.04)
- Some checks require root for full system visibility

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type check
mypy src/usaf

# Lint
ruff check src/usaf

# Format
ruff format src/usaf
```

## Project Structure

```
src/usaf/
├── cli/            # Typer CLI interface
├── core/           # Plugin system, registry, runner
├── models/         # Pydantic data models
├── collectors/     # Data gathering (system, network, users, etc.)
├── checks/         # Security check plugins (25+)
├── reporting/      # Terminal, JSON, Markdown reporters
├── scoring/        # Risk scoring engine
├── baseline/       # Baseline snapshots and diff
├── correlation/    # Correlation engine and rules
├── compliance/     # CIS/NIST compliance mappings
├── profiles/       # System profile matching
├── severity/       # Context-aware severity
├── knowledge/      # Knowledge base YAML files
├── policies/       # YAML policy engine
├── config/         # Configuration loading
└── cache/          # In-memory caching
```

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 Type-3 Studio.
