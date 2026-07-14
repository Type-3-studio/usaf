# USAF — Ubuntu Security Audit Framework

[![CI](https://github.com/Type-3-studio/usaf/actions/workflows/ci.yml/badge.svg)](https://github.com/Type-3-studio/usaf/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](http://mypy-lang.org/)

**389+ security checks, 26 collectors, 1942+ tests** — production-grade security auditing for Ubuntu Linux. Modular plugin architecture with data collection, analysis, correlation, and reporting — all in one CLI.

## Features

- **389+ security checks** — SSH, kernel, users, permissions, network, filesystem, services, containers, secrets, boot, firewall, cloud, compliance, compromise, persistence, AppArmor, USB, password policy, forensics, and more
- **26 collectors** — gather data from `/proc`, systemd, APT, auditd, Docker/Podman, journald, PAM, SSH config, cert stores, boot/firmware, cloud metadata, Flatpak, Snap, and more
- **Correlation Engine 2.0** — YAML-defined rules, temporal correlation, risk accumulation, counter-evidence filtering, 8 core attack scenarios (ransomware, cryptominer, persistence, supply chain, bootkit, container escape, data theft, active breach)
- **CIS, NIST, PCI DSS, SOC2 & HIPAA mappings** — compliance framework with gap analysis across 7 frameworks
- **Evidence-based findings** — 8 evidence types (File, Process, Network, Command, Registry, Log, User, Package)
- **Context-aware severity** — adjusts severity based on SSH exposure, file path, user type, network context
- **Trust scoring** — evidence-quality-adjusted confidence with multi-evidence bonuses
- **Knowledge base** — 93 YAML entries with threat, exploit, impact, remediation, and CVSS for each check
- **Policy engine** — YAML-based policy overrides for severity, enable/disable, max findings
- **Multiple reporters** — terminal (Rich), JSON, Markdown
- **Scoring engine** — weighted, confidence-aware scoring from A+ to F-, with per-category breakdown
- **Baseline tracking** — create, diff, and drift-detect against known-good snapshots
- **Validation Lab** — reproducible, known-vulnerable Ubuntu VMs for validating detection accuracy (5 scenarios)

## Quick Start

```bash
# Install from source
git clone https://github.com/Type-3-studio/usaf.git
cd usaf
pip install -e ".[dev]"

# Run a full scan
usaf scan

# List available checks
usaf list-checks

# Run specific checks
usaf scan --checks SSH-101 KERN-101

# Output as JSON
usaf scan --format json

# Initialize default config
usaf init

# Check compliance against frameworks
usaf compliance check --framework cis

# Baseline management
usaf baseline init
usaf baseline diff
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
├── cli/            # Typer CLI interface (scan, list, baseline, compliance, profile)
├── core/           # Plugin system, registry, runner, interfaces
├── models/         # Pydantic data models (finding, evidence, result, score, scenario)
├── collectors/     # Data gathering (26 collectors across 8 categories)
│   ├── system/     #   Kernel, boot, hardware
│   ├── network/    #   Sockets, interfaces, DNS, SSH config
│   ├── users/      #   Passwd, shadow, groups, sudo
│   ├── packages/   #   APT, dpkg, snap, flatpak
│   ├── processes/  #   /proc parsing
│   ├── services/   #   systemd, cron
│   ├── security/   #   PAM, auditd
│   ├── filesystem/ #   File walker, cert store
│   └── cloud/      #   Cloud metadata
├── checks/         # Security check plugins (389+ across 20+ categories)
├── reporting/      # Terminal, JSON, Markdown reporters
├── scoring/        # Scoring engine + trust scoring
├── baseline/       # Baseline snapshots and drift detection
├── correlation/    # Correlation engine 2.0 (16 Python rules, 4 YAML rules, 8 scenarios)
├── compliance/     # CIS/NIST/PCI DSS/SOC2/HIPAA compliance evaluator
├── severity/       # Context-aware severity engine
├── profiles/       # System profile matching
├── knowledge/      # Knowledge base (93 YAML files)
├── policies/       # YAML policy engine + correlation rules
├── config/         # YAML configuration loading
└── cache/          # In-memory caching

test_lab/           # Validation Lab — reproducible vulnerable VMs (Phase 7a)
├── run.py          # CLI: provision/validate/run scenarios
├── scenarios/      # 5 composite vulnerability profiles
├── harness/        # Provisioner, runner, validator, reporter
└── shared/         # Reusable vulnerability shell scripts
```

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 Type-3 Studio.
