# USAF — Project State & Roadmap

> **Vision:** A modular, scalable security audit framework for Ubuntu — capable of local audits, fleet-wide monitoring, real-time drift detection, and compliance reporting, all built on clean interfaces and deterministic pipelines.

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
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │Parallel  │  │ Remote   │  │Timeline  │                  │
│  │  Exec    │  │  Fleet   │  │    DB    │                  │
│  │   ✅    │  │   🔴    │  │   🔴    │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Detailed Status

#### Collectors (15 total)
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
| `FirewallCollector` | ✅ | ufw, nftables, iptables status |
| `MountCollector` | ✅ | `/proc/mounts`, `/etc/fstab` parsing |
| `ContainerCollector` | ✅ | Docker/Podman runtime, running containers |
| `AuditdCollector` | ✅ | Auditd status, rules, log statistics |

#### Checks (25 total)
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
| USR-003 (Shadowed Passwords) | ✅ | HIGH | RegistryEvidence |
| NET-001 (Listening Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-002 (Promiscuous Mode) | ✅ | MEDIUM | NetworkEvidence |
| PRM-001 (SUID Binaries) | ✅ | HIGH | FileEvidence (config allowlist + 60 known-safe packages auto-allowlisted) |
| PRM-002 (World-Writable) | ✅ | HIGH | FileEvidence |
| CMP-001 (Ubuntu Support) | ✅ | MEDIUM | RegistryEvidence |
| COM-001 (Bad Processes) | ✅ | HIGH | ProcessEvidence |
| CTN-001 (Docker Socket) | ✅ | HIGH | FileEvidence |
| FOR-001 (Audit Logs) | ✅ | MEDIUM | FileEvidence |
| KRN-001 (Module Loading) | ✅ | MEDIUM | RegistryEvidence |
| PKG-001 (Unnecessary Pkgs) | ✅ | MEDIUM | PackageEvidence |
| PER-001 (Unauth Services) | ✅ | HIGH | FileEvidence |
| SEC-001 (AppArmor) | ✅ | HIGH | FileEvidence |
| SVC-001 (Insecure Svcs) | ✅ | HIGH | FileEvidence |
| FIREWALL-001 (Firewall Active) | ✅ | HIGH | CommandEvidence |
| USB-001 (USB Storage Restriction) | ✅ | MEDIUM | FileEvidence |
| PWD-001 (Password Policy Strength) | ✅ | HIGH | FileEvidence |

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
| Correlation | ✅ | 720 | 7 rules (SSH brute, persistence, unauth svc, exfil, SUID-ARM, DEF-EVADE, EXPO-VULN), engine |
| Compliance | ✅ | 335 | CIS 27 controls, NIST 6 controls, gap analysis |
| Profiles | ✅ | 451 | Desktop/server reference profiles, auto-detect |
| Context Severity | ✅ | 201 | SSH, file perms, users, network context evaluators |
| Knowledge Base | ✅ | 171 + 25 YAML | YAML for all 25 checks with threat/exploit/impact/fix/CVSS; KB wired into runner pipeline for finding enrichment |
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
| SUID allowlist | ✅ | suid_allowlist in config YAML, injected via _usaf_config key |
| SUID known-safe packages | ✅ | 60+ packages auto-allowlisted (coreutils, sudo, shadow, util-linux, etc.) |

#### Testing
| Area | Tests | Lines | Notes |
|------|-------|-------|-------|
| Unit tests | 490 | 7,150+ | **48 test files** across all modules (organized in subdirectories) |
| Integration tests | 93 | 1,700+ | Pipeline, scoring, reporter, checks (all 25), collectors, and pipeline edge cases |
| Golden tests | ✅ | 80 | JSON and Markdown golden report snapshot tests |
| Kernel checks | ✅ | 131 | tests/unit/checks/test_kernel_checks.py |
| SSH checks | ✅ | 127 | tests/unit/checks/test_ssh_checks.py |
| Network checks | ✅ | 113 | tests/unit/checks/test_network_checks.py |
| Permission checks | ✅ | 193 | tests/unit/checks/test_permission_checks.py |
| User checks | ✅ | 156 | tests/unit/checks/test_user_checks.py |
| Scoring engine | ✅ | 330 | tests/unit/scoring/test_scoring_engine.py |
| Trust scoring | ✅ | 259 | tests/unit/scoring/test_trust_scoring.py |
| Baseline | ✅ | 246 | tests/unit/baseline/test_baseline_manager.py |
| Correlation engine | ✅ | 518 | tests/unit/correlation/test_correlation_engine.py |
| Correlation rules | ✅ | — | tests/unit/correlation/test_correlation_rules.py |
| Compliance | ✅ | 134 | tests/unit/compliance/test_compliance_framework.py |
| Knowledge | ✅ | 216 | tests/unit/knowledge/test_knowledge_base.py |
| Profiles | ✅ | 161 | tests/unit/profiles/test_profile_manager.py |
| Severity | ✅ | 305 | tests/unit/severity/test_context_severity.py |
| Compromise checks (COM-001) | ✅ | 48 | tests/unit/checks/test_compromise_checks.py |
| Compliance checks (CMP-001) | ✅ | 55 | tests/unit/checks/test_compliance_checks.py |
| Container checks (CTN-001) | ✅ | 56 | tests/unit/checks/test_container_checks.py |
| Forensics checks (FOR-001) | ✅ | 48 | tests/unit/checks/test_forensics_checks.py |
| Kernel module checks (KRN-001) | ✅ | 25 | tests/unit/checks/test_krn_checks.py |
| Package checks (PKG-001) | ✅ | 50 | tests/unit/checks/test_package_checks.py |
| Persistence checks (PER-001) | ✅ | 48 | tests/unit/checks/test_persistence_checks.py |
| Security checks (FIREWALL/SEC/USB) | ✅ | 94 | tests/unit/checks/test_security_checks.py |
| Service checks (SVC-001) | ✅ | 42 | tests/unit/checks/test_service_checks.py |
| Password policy (PWD-001) | ✅ | 60 | tests/unit/checks/test_password_policy_checks.py |
| Cache engine | ✅ | 56 | tests/unit/test_cache.py |
| Config loader/model | ✅ | 118 | tests/unit/test_config.py |
| Policy engine | ✅ | 136 | tests/unit/test_policy_engine.py |
| JSON reporter | ✅ | — | tests/unit/reporting/test_json_reporter.py |
| Terminal reporter | ✅ | 43 | tests/unit/reporting/test_terminal_reporter.py |
| Markdown reporter | ✅ | 41 | tests/unit/reporting/test_markdown_reporter.py |
| Base reporter | ✅ | 26 | tests/unit/reporting/test_base_reporter.py |
| Deep checks integration | ✅ | 520 | tests/integration/test_checks_deep_integration.py — all 25 checks with pass/fail scenarios |
| Collectors integration | ✅ | 115 | tests/integration/test_collectors_integration.py — manager, registry, lifecycle |
| Pipeline edge cases | ✅ | 150 | tests/integration/test_pipeline_edge_cases.py — errors, parallel, config, filtering |
| Finding model | ✅ | — | tests/unit/models/test_finding.py |
| References model | ✅ | 66 | tests/unit/models/test_references.py |
| Severity model | ✅ | — | tests/unit/models/test_severity.py |
| Base collector | ✅ | 75 | tests/unit/collectors/test_collector_base.py |
| Collector manager | ✅ | 130 | tests/unit/core/test_collector_manager.py |
| Collector registry | ✅ | — | tests/unit/core/test_collector_registry.py |
| Plugin registry | ✅ | — | tests/unit/core/test_registry.py |
| Kernel collector | ✅ | 74 | tests/unit/collectors/test_kernel_collector.py |
| Socket/Interface collector | ✅ | 91 | tests/unit/collectors/test_socket_collector.py |
| User/Group/Sudo collector | ✅ | 68 | tests/unit/collectors/test_user_collectors.py |
| Process collector | ✅ | 55 | tests/unit/collectors/test_process_collector.py |
| Systemd/Cron collector | ✅ | 67 | tests/unit/collectors/test_systemd_collector.py |
| Mount collector | ✅ | 36 | tests/unit/collectors/test_mount_collector.py |
| Firewall collector | ✅ | 50 | tests/unit/collectors/test_firewall_collector.py |
| APT collector | ✅ | 40 | tests/unit/collectors/test_apt_collector.py |
| Container collector | ✅ | — | tests/unit/collectors/test_container_collector.py |
| Auditd collector | ✅ | — | tests/unit/collectors/test_auditd_collector.py |

#### Developer Infrastructure
| Tool | Status | Notes |
|------|--------|-------|
| `ruff` config | ✅ | pyproject.toml, strict |
| `mypy` config | ✅ | strict mode |
| Pre-commit hooks | ✅ | ruff, mypy (0 errors ✅), trailing whitespace, YAML/TOML check |
| CI/CD | ✅ | GitHub Actions: ruff lint+format, mypy (0 errors ✅), pytest on push/PR |
| Versioning | ✅ | 0.3.0 — semver |

---

## What Remains

### P4: Scale & Distribution
| Feature | Priority | Notes |
|---------|----------|-------|
| Parallel execution | ✅ | `ThreadPoolExecutor` with `max_workers` from config |
| Plugin isolation | LOW | No sandbox for 3rd-party plugins |
| Remote / Fleet scanning | LOW | SSH transport for remote collectors |
| Agent mode / MQ | LOW | Periodic publishing to NATS/MQTT |
| Timeline DB | LOW | SQLite history of baseline changes |

### Filling Empty Placeholders
| Area | Priority | Notes |
|------|----------|-------|
| Golden report tests | LOW | ✅ Implemented |
| Container collectors | LOW | ✅ `ContainerCollector` added |
| Filesystem collectors | LOW | ✅ `MountCollector` implemented |
| Security collectors | LOW | ✅ `FirewallCollector`, `AuditdCollector` implemented |
| Knowledge YAML coverage | MEDIUM | ✅ All 25 checks have knowledge YAML files |
| Reference URLs in findings | MEDIUM | ✅ All 25 checks include reference URLs |
| MITRE ATT&CK coverage | MEDIUM | ✅ All 25 checks include mitre_attack_ids |
| `scoring/__init__.py` exports | LOW | ✅ Populated with `ScoringEngine`, `TrustScorer` |
| `models/__init__.py` exports | LOW | ✅ Populated with all model exports |

---

## Technical Debt Log

| ID | Description | Severity | Status |
|----|-------------|----------|--------|
| TD-001 | `metadata.configuration_file` set to `scan_name` instead of config path | LOW | ✅ |
| TD-002 | `metadata.end_time` set to `scan_start_dt` instead of actual end time | LOW | ✅ |
| TD-003 | Integration tests coverage expanded from 21→93 tests (8 test files, 3 new) | MEDIUM | ✅ |
| TD-004 | ~~Scoring ignores confidence~~ → **Fixed** (P1-1 + P3-3) | HIGH | ✅ |
| TD-005 | Collectors hardcoded in runner → **Fixed** (auto-discovered) | MEDIUM | ✅ |
| TD-006 | No parallel execution despite `parallel=True` in config | LOW | ✅ |
| TD-007 | ~~`mypy --strict` fails (245→15 errors)~~ → **Fixed: 0 errors across 100 source files** | MEDIUM | ✅ |
| TD-008 | ~~SUID FP rate ~80%~~ → **Resolved** (expanded whitelist, config allowlist, MEDIUM/LOW confidence tiers based on 60 known-safe packages) | HIGH | ✅ |
| TD-009 | Severity context `apply_all()` computed adjustments but never applied them to findings (dead data pipeline) | HIGH | ✅ |
| TD-010 | Knowledge Base YAML coverage was 16/25 checks (64%); 9 missing files added + KB wired into runner pipeline | MEDIUM | ✅ |
| TD-011 | CMP-001 (Ubuntu version check) missing `mitre_attack_ids` entirely | MEDIUM | ✅ |
| TD-012 | `scoring/__init__.py` and `models/__init__.py` were empty (no exports) | LOW | ✅ |
| TD-013 | 9 checks missing `reference` URL in findings | MEDIUM | ✅ |
| TD-014 | Systemd collector doesn't strip `●` bullet char → service names corrupted for failed/degraded units | HIGH | ✅ |
| TD-015 | `get_package_for_file()` doesn't resolve symlinks → `/bin/*` and `/sbin/*` show "Not owned by any installed package" (merged-usr layout) | HIGH | ✅ |
| TD-016 | CMP-001 supported versions hardcoded to 20.04/22.04/24.04 → 26.04 flagged as unsupported | MEDIUM | ✅ |
| TD-017 | PKG-001 flags desktop packages (cups, avahi, whoopsie, xorg) on desktop systems | MEDIUM | ✅ |
| TD-018 | PER-001 doesn't filter snap-managed services → false positives for snap.svc names | MEDIUM | ✅ |
| TD-019 | PER-001 doesn't filter known-legitimate services (e.g., switcheroo-control → "proxy" match) | LOW | ✅ |

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
├── checks/                    # 25 checks across 14 categories
├── reporting/                 # 3 reporters
├── scoring/
│   ├── engine.py              # Scoring engine (with confidence*FP)
│   └── trust.py               # Trust scoring (evidence quality)
├── baseline/manager.py        # Baseline snapshots
├── correlation/               # Correlation engine + 4 rules
├── compliance/framework.py    # CIS + NIST mappings
├── profiles/manager.py        # Profile matching
├── severity/engine.py         # Context-aware severity
├── knowledge/                 # KB + 25 YAML entries (one per check)
├── policies/engine.py         # Policy loading + overrides
├── config/                    # YAML config loading
└── cache/engine.py            # In-memory cache
```

---

## Metrics & Targets

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Checks | 25 | 25+ | ✅ (target met) |
| Findings (real desktop scan) | 29→**22** | — | ✅ (-7 false findings eliminated) |
| Collectors | 15 | 15+ | ✅ (target met) |
| Unit tests | 490→**511** | 300+ | ✅ (+21 correlation rule tests added) |
| Unit test files | 48 | 40+ | ✅ (target exceeded) |
| Integration tests | 21→**93** | 15+ | ✅ (72 new tests across 3 new files) |
| Test coverage (stmt) | ~40% → **85%** | 85%+ | ✅ (target met) |
| Test coverage (branch) | ~29% → **82%** | 80%+ | ✅ (target met) |
| CI pipeline | Green on push | Green on push | ✅ |
| mypy --strict | **0 errors** | 0 errors | ✅ |
| Knowledge YAML coverage | 16/25 (64%) → **25/25 (100%)** | 100% | ✅ (9 missing files created) |
| Knowledge enrichment in pipeline | Off → **Enabled** | Enabled | ✅ (wired into runner Phase 3.8) |
| Severity pipeline dead data | Yes → **Fixed** | Fixed | ✅ (adjustments now applied to findings) |
| False positive rate (SUID) | ~80% → ~30% → **~5% → ~2%** | <10% | ✅ (known-safe + symlink resolution + sudo-rs added) |
| Desktop package false positives | 4 per scan → **0** | 0 | ✅ (desktop detection in PKG-001) |
| Service detection false positives | varied → **eliminated** | 0 | ✅ (bullet fix + benign/snap filter) |
| Total findings (desktop, after config) | 29 → **4** | — | ✅ (SUID allowlist eliminated 18 false positives) |
| Confidence scoring | Applied | Applied | ✅ |
| Correlation rules | 4→**7** | 4+ | ✅ (3 new: SUID-ARM, DEF-EVADE, EXPO-VULN) |
| Baseline support | Full | Full + timeline | ◐ |
| Remote scanning | None | SSH transport | 🔴 |

---

## Contributing to This Document

This is a living document. Update it when:
- New features are completed (move to ✅, note date)
- Technical debt is resolved (move to ✅)
- Targets are met (update Metrics & Targets)
