# USAF — Project State & Roadmap

> **Vision:** A modular, scalable security analysis platform that grows from a CLI audit tool into an intelligent, multi-surface security knowledge engine — capable of local audits, fleet-wide monitoring, real-time drift detection, and AI-assisted analysis, all built on clean interfaces and deterministic pipelines.

---

## Current Implementation Status

### Legend
| Icon | Meaning |
|------|---------|
| ✅ | Complete and tested |
| ◐ | Implemented but incomplete |
| ⬜ | Stubbed / config exists |
| 🔴 | Not implemented |

### Architecture Layer

```
┌──────────────────────────────────────────────────────────────┐
│                         CLI (Typer)                     ✅    │
├──────────────────────────────────────────────────────────────┤
│                  Scan Orchestrator (Runner)              ✅    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Collectors│  │  Checks  │  │Reporters │  │ Scoring  │    │
│  │    ✅    │  │    ✅    │  │    ✅    │  │    ✅    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Registry │  │  Cache   │  │  Config  │  │Evidence  │    │
│  │    ✅    │  │    ✅    │  │    ✅    │  │    ✅    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Baselines │  │Correlat. │  │Compliance│  │ Profiles │    │
│  │    ✅    │  │    ✅    │  │    ✅    │  │    ✅    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Severity  │  │Knowledge │  │ TrustSc. │  │ Policies │    │
│  │Context   │  │  Base    │  │  (P3-3)  │  │  (P2-3)  │    │
│  │    ✅    │  │    ✅    │  │    ✅    │  │    ✅    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Parallel  │  │ Remote   │  │  LLM AI  │  │Timeline  │    │
│  │  Exec    │  │  Fleet   │  │  (P5)    │  │    DB    │    │
│  │   🔴    │  │   🔴    │  │   🔴    │  │   🔴    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Detailed Status

#### Collectors (11 total)
| Collector | Status | Notes |
|-----------|--------|-------|
| `KernelCollector` | ✅ | `/proc/sys`, sysctl, uname |
| `KernelParametersCollector` | ✅ | Depends on KernelCollector |
| `SocketCollector` | ✅ | `/proc/net/tcp`, `/proc/net/udp` |
| `InterfaceCollector` | ✅ | `/proc/net/dev`, `/sys/class/net` |
| `ProcessCollector` | ✅ | `/proc` parsing |
| `UserCollector` | ✅ | `/etc/passwd`, `/etc/shadow` |
| `GroupCollector` | ✅ | `/etc/group` |
| `SudoCollector` | ✅ | `/etc/sudoers`, sudoers.d/ |
| `APTCollector` | ✅ | dpkg query, package DB, file→package cache |
| `SystemdCollector` | ✅ | systemctl, unit files |
| `CronCollector` | ✅ | crontabs, cron.d, cron.daily |
| `container/` | ⬜ | Placeholder directory, no collectors yet |
| `filesystem/` | ⬜ | Placeholder directory, no collectors yet |
| `security/` | ⬜ | Placeholder directory, no collectors yet |

#### Checks (22 total)
| Check | Status | Severity | Evidence |
|-------|--------|----------|----------|
| KERN-001 (ASLR) | ✅ | HIGH | RegistryEvidence |
| KERN-002 (Pointer Restriction) | ✅ | MEDIUM | RegistryEvidence |
| KERN-003 (Core Dump) | ✅ | MEDIUM | RegistryEvidence |
| SSH-001 (Protocol) | ✅ | HIGH | RegistryEvidence |
| SSH-002 (Root Login) | ✅ | HIGH | RegistryEvidence |
| SSH-003 (KEX Algorithms) | ✅ | MEDIUM | RegistryEvidence |
| USR-001 (Duplicate UID 0) | ✅ | CRITICAL | UserEvidence |
| USR-002 (Empty Passwords) | ✅ | CRITICAL | UserEvidence |
| USR-003 (Shadowed Passwords) | ✅ | HIGH | FileEvidence |
| NET-001 (Listening Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-002 (Promiscuous Mode) | ✅ | MEDIUM | NetworkEvidence |
| PRM-001 (SUID Binaries) | ✅ | HIGH | FileEvidence |
| PRM-002 (World-Writable) | ✅ | HIGH | FileEvidence |
| CMP-001 (Ubuntu Support) | ✅ | MEDIUM | CommandEvidence |
| COM-001 (Bad Processes) | ✅ | HIGH | ProcessEvidence |
| CTN-001 (Docker Socket) | ✅ | HIGH | FileEvidence |
| FOR-001 (Audit Logs) | ✅ | MEDIUM | FileEvidence |
| KRN-001 (Module Loading) | ✅ | MEDIUM | RegistryEvidence |
| PKG-001 (Unnecessary Pkgs) | ✅ | MEDIUM | PackageEvidence |
| PER-001 (Unauth Services) | ✅ | HIGH | FileEvidence |
| SEC-001 (AppArmor) | ✅ | HIGH | CommandEvidence |
| SVC-001 (Insecure Svcs) | ✅ | HIGH | FileEvidence |

#### Reporters (3 total)
| Reporter | Status | Features |
|----------|--------|----------|
| `TerminalReporter` | ✅ | Rich tables, color, severity badges, score panel |
| `JSONReporter` | ✅ | Full structured output with metadata |
| `MarkdownReporter` | ✅ | Code blocks, severity emoji indicators |

#### CLI
| Command | Status | Notes |
|---------|--------|-------|
| `usaf scan` | ✅ | Full scan pipeline with all Phase 2 features |
| `usaf scan --baseline-diff` | ✅ | Compare scan against stored baseline |
| `usaf scan --compliance` | ✅ | Evaluate against CIS/NIST framework |
| `usaf scan --profile` | ✅ | Match system against profile |
| `usaf list-checks` | ✅ | With `--category` filter |
| `usaf init` | ✅ | Config file bootstrapping |
| `usaf baseline init/update/diff/list/delete` | ✅ | Full baseline lifecycle |
| `usaf compliance check/gaps` | ✅ | Compliance evaluation and gap analysis |
| `usaf profile list/match/load` | ✅ | Profile management |

#### Evidence System (8 types)
| Type | Status | Fields |
|------|--------|--------|
| `FileEvidence` | ✅ | path, line, content, permission, owner, group, size, modified, hash_sha256 |
| `ProcessEvidence` | ✅ | pid, name, binary, cmdline, user, state, ppid, threads, memory_mbytes, cpu_percent, started, environment, open_fds |
| `NetworkEvidence` | ✅ | protocol, local_address, local_port, remote_address, remote_port, state, pid, process_name, uid, inode |
| `CommandEvidence` | ✅ | command, stdout, stderr, exit_code, executed_at |
| `RegistryEvidence` | ✅ | key, value, expected, source |
| `LogEvidence` | ✅ | log_path, lines, pattern, match_count, time_range |
| `UserEvidence` | ✅ | username, uid, gid, home, shell, groups, ssh_keys, last_login, password_expires, is_locked |
| `PackageEvidence` | ✅ | name, version, architecture, repository, status, installed_size, is_update_available |

#### Scoring Engine (P1-1 + P3-3)
| Feature | Status | Notes |
|---------|--------|-------|
| Per-category scoring | ✅ | 20 categories, weighted |
| Overall score (0-10) | ✅ | Letter grades A+ to F- |
| Confidence multiplier | ✅ | Applied in `_calculate_categories` |
| False positive probability | ✅ | Applied as `(1.0 - FP)` factor |
| **Trust scoring (P3-3)** | ✅ | Evidence quality bonuses, no-evidence clamp |
| Evidence quality bonus | ✅ | File/Process/User=0.15, Network/Pkg/Registry=0.10, Log=0.08, Cmd=0.05 |
| Multi-evidence bonus | ✅ | +0.10 for >=5 populated fields |
| No-evidence clamp | ✅ | Effective confidence clamped to LOW (max 0.3) |
| Context-aware severity | ✅ | SSH exposure, file path, user type, network context |

#### Plugin System
| Feature | Status | Notes |
|---------|--------|-------|
| Registry | ✅ | Singleton, CRUD, lifecycle |
| Dependency resolution | ✅ | Topological sort with cycle detection |
| Instance caching | ✅ | Per-check singleton |
| Auto-discovery | ✅ | `pkgutil.walk_packages` via `discover_checks()` |
| Plugin isolation | 🔴 | No sandbox for 3rd-party plugins |

#### Phase 2 Modules
| Module | Status | Lines | Notes |
|--------|--------|-------|-------|
| Baseline | ✅ | 300 | store/load/diff, CLI integration |
| Correlation | ✅ | 506 | 4 rules (SSH brute, persistence, unauth svc, exfil), engine |
| Compliance | ✅ | 335 | CIS 27 controls, NIST 6 controls, gap analysis |
| Profiles | ✅ | 451 | Desktop/server reference profiles, auto-detect |
| Context Severity | ✅ | 201 | SSH, file perms, users, network context evaluators |
| Knowledge Base | ✅ | 174 + 13 YAML | One YAML per check with threat/exploit/impact/fix/CVSS |
| Trust Scoring | ✅ | 106 | Evidence-quality adjusted confidence |
| Policies | ✅ | 86 | YAML policy loading, check overrides, severity overrides |

#### Models
| Model | Status | Fields |
|-------|--------|--------|
| `Finding` | ✅ | 24 fields including all compliance mappings |
| `CheckResult` | ✅ | pass/fail, findings, error, timing |
| `ScanResult` | ✅ | metadata, results, collector_data |
| `ScanScore` | ✅ | overall, per-category, grade, severity counts |
| `ScanMetadata` | ✅ | host, OS, version, timing, check counts |
| `CorrelatedFinding` | ✅ | extends Finding with source_findings, correlation_rule |
| `BaselineSnapshot` | ✅ | 8 system state sections |
| `Profile` | ✅ | 14 fields including expected packages/services/suid |

#### Config
| Feature | Status | Notes |
|---------|--------|-------|
| YAML loading | ✅ | XDG, home, CWD resolution |
| Deep merge defaults | ✅ | |
| Plugin overrides | ✅ | enable/disable per check |
| Ignore patterns | ✅ | fnmatch-based |
| Baseline config | ✅ | Model + implementation |
| Policy config | ✅ | PolicyEngine with YAML loading |

#### Testing
| Area | Tests | Lines | Notes |
|------|-------|-------|-------|
| Unit tests | 242 | 3,724 | 26 test files across all modules |
| Integration tests | 5 | 112 | Pipeline smoke tests |
| Golden tests | 🔴 | 0 | Marker exists, no tests |
| Kernel checks | ✅ | 131 | test_kernel_checks.py |
| SSH checks | ✅ | 127 | test_ssh_checks.py |
| Network checks | ✅ | 113 | test_network_checks.py |
| Permission checks | ✅ | 115 | test_permission_checks.py |
| User checks | ✅ | 156 | test_user_checks.py |
| Scoring engine | ✅ | 286 | test_scoring_engine.py |
| Trust scoring | ✅ | 231 | test_trust_scoring.py |
| Baseline | ✅ | 246 | test_baseline_manager.py |
| Correlation | ✅ | 518 | engine + rules |
| Compliance | ✅ | 134 | test_compliance_framework.py |
| Knowledge | ✅ | 216 | test_knowledge_base.py |
| Profiles | ✅ | 161 | test_profile_manager.py |
| Severity | ✅ | 235 | test_context_severity.py |

#### Developer Infrastructure
| Tool | Status | Notes |
|------|--------|-------|
| `ruff` config | ✅ | pyproject.toml, strict |
| `mypy` config | ✅ | strict mode |
| Pre-commit hooks | ✅ | ruff, mypy, trailing whitespace, YAML/TOML check |
| CI/CD | ✅ | GitHub Actions: ruff lint+format, mypy, pytest on push/PR |
| Versioning | ✅ | 0.3.0 — semver |

---

## What Remains

### P4: Scale & Distribution
| Feature | Priority | Notes |
|---------|----------|-------|
| Parallel execution | MEDIUM | Config has `parallel=True` but no impl. Use ThreadPoolExecutor. |
| Plugin isolation | LOW | No sandbox for 3rd-party plugins |
| Remote / Fleet scanning | LOW | SSH transport for remote collectors |
| Agent mode / MQ | LOW | Periodic publishing to NATS/MQTT |
| Timeline DB | LOW | SQLite history of baseline changes |

### P5: Intelligence & AI
| Feature | Priority | Notes |
|---------|----------|-------|
| LLM analysis (Ollama) | LOW | Executive summaries, priority ranking |
| Remediation agent | LOW | Autonomous fix with rollback |
| Anomaly detection (ML) | LOW | Learn normal patterns over time |

### Filling Empty Placeholders
| Area | Priority | Notes |
|------|----------|-------|
| Golden report tests | LOW | Config + marker exist, no tests |
| Container collectors | LOW | `collectors/container/` empty |
| Filesystem collectors | LOW | `collectors/filesystem/` empty |
| Security collectors | LOW | `collectors/security/` empty |

---

## Technical Debt Log

| ID | Description | Severity | Status |
|----|-------------|----------|--------|
| TD-001 | `metadata.configuration_file` set to `scan_name` instead of config path | LOW | Open |
| TD-002 | `metadata.end_time` set to `scan_start_dt` instead of actual end time | LOW | Open |
| TD-003 | No integration tests (5 added, more needed) | MEDIUM | ◐ |
| TD-004 | ~~Scoring ignores confidence~~ → **Fixed** (P1-1 + P3-3) | HIGH | ✅ |
| TD-005 | Collectors hardcoded in runner → **Fixed** (auto-discovered) | MEDIUM | ✅ |
| TD-006 | No parallel execution despite `parallel=True` in config | LOW | Open |
| TD-007 | `mypy --strict` likely fails — never run in CI | MEDIUM | Open |

---

## Decision Records Index

| ADR | Title | Status |
|-----|-------|--------|
| 001 | Project Goals and Scope | ✅ |
| 002 | Architecture Overview | ✅ |
| 003 | Plugin System | ✅ |
| 004 | Finding Model | ✅ |
| 005 | Collector Architecture | ✅ |
| 006 | Scoring Engine | ✅ (updated) |
| 007 | Reporting Framework | ✅ |
| 008 | Configuration Management | ✅ |

---

## Quick Reference: Where Code Lives

```
src/usaf/
├── cli/app.py                 # Typer CLI — 15+ commands
├── core/
│   ├── interfaces.py          # All ABCs (10 interfaces)
│   ├── plugin.py              # AuditCheck base class
│   ├── registry.py            # Plugin registry + auto-discovery
│   └── runner.py              # ScanRunner orchestrator (5 phases)
├── models/
│   ├── evidence.py            # 8 evidence types
│   ├── finding.py             # Finding model (24 fields)
│   ├── severity.py            # Severity, Confidence, CheckCategory enums
│   ├── result.py              # CheckResult, ScanResult, ScanMetadata
│   ├── score.py               # ScanScore, CategoryScore
│   └── references.py          # CVE, CIS, MITRE, OWASP models
├── collectors/                # 11 collectors (+3 placeholder dirs)
├── checks/                    # 22 checks across 13 categories
├── reporting/                 # 3 reporters
├── scoring/
│   ├── engine.py              # Scoring engine (with confidence*FP)
│   └── trust.py               # Trust scoring (evidence quality)
├── baseline/manager.py        # Baseline snapshots
├── correlation/               # Correlation engine + 4 rules
├── compliance/framework.py    # CIS + NIST mappings
├── profiles/manager.py        # Profile matching
├── severity/engine.py         # Context-aware severity
├── knowledge/                 # KB + 13 YAML entries
├── policies/engine.py         # Policy loading + overrides
├── config/                    # YAML config loading
└── cache/engine.py            # In-memory cache
```

---

## Metrics & Targets

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Checks | 22 | 25+ | ◐ (near target) |
| Collectors | 11 | 15+ | ◐ |
| Unit tests | 242 | 300+ | ◐ |
| Integration tests | 5 | 15+ | ◐ |
| Test coverage | ~40% | 85%+ | ◐ |
| CI pipeline | Green on push | Green on push | ✅ |
| False positive rate (SUID) | ~80% | <10% | 🔴 (P1-2) |
| Confidence scoring | Applied | Applied | ✅ |
| Correlation rules | 4 | 4+ | ✅ |
| Baseline support | Full | Full + timeline | ◐ |
| Remote scanning | None | SSH transport | 🔴 |
| LLM integration | None | Ollama + agent | 🔴 |

---

## Contributing to This Document

This is a living document. Update it when:
- New features are completed (move to ✅, note date)
- Technical debt is resolved (move to ✅)
- Targets are met (update Metrics & Targets)
