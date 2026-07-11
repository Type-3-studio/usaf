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

#### Collectors (22 total)
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
| `BootCollector` | ✅ | Secure Boot, kernel lockdown, EFI, GRUB (P0) |
| `DNSCollector` | ✅ | resolv.conf, systemd-resolved, /etc/hosts (P0) |
| `PAMCollector` | ✅ | PAM config files, module inventory (P0) |
| `SSHConfigCollector` | ✅ | sshd_config, host keys, authorized_keys (P0) |
| `JournaldCollector` | ✅ | journald config, log usage, persistence (P0) |
| `FilesystemCollector` | ✅ | SUID, world-writable, capabilities, hidden files (P0) |
| `CertStoreCollector` | ✅ | System CA bundles, certificate inventory (P0) |

#### Checks (47 total)
| Check | Status | Severity | Evidence |
|-------|--------|----------|----------|
| KERN-101 (ASLR) | ✅ | HIGH | RegistryEvidence |
| KERN-201 (Pointer Restriction) | ✅ | MEDIUM | RegistryEvidence |
| KERN-301 (Core Dump) | ✅ | MEDIUM | RegistryEvidence |
| KERN-401 (Module Loading) | ✅ | MEDIUM | RegistryEvidence |
| SSH-101 (Protocol) | ✅ | HIGH | RegistryEvidence |
| SSH-102 (Root Login) | ✅ | HIGH | RegistryEvidence |
| SSH-201 (KEX Algorithms) | ✅ | MEDIUM | RegistryEvidence |
| USR-101 (Duplicate UID 0) | ✅ | CRITICAL | UserEvidence |
| USR-102 (Shadowed Passwords) | ✅ | HIGH | RegistryEvidence |
| USR-103 (Duplicate UIDs) | ✅ | HIGH | UserEvidence |
| USR-104 (Disabled Accts w/ Shell) | ✅ | MEDIUM | UserEvidence |
| USR-105 (Expired Passwords) | ✅ | MEDIUM | UserEvidence / RegistryEvidence |
| USR-201 (Empty Passwords) | ✅ | CRITICAL | UserEvidence |
| USR-202 (Password Reuse Policy) | ✅ | MEDIUM | RegistryEvidence |
| USR-301 (MFA Status) | ✅ | HIGH | RegistryEvidence |
| USR-401 (Unauthorized Sudo) | ✅ | HIGH | RegistryEvidence |
| NET-101 (Listening Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-201 (Promiscuous Mode) | ✅ | MEDIUM | NetworkEvidence |
| NET-301 (Unexpected DNS) | ✅ | MEDIUM | NetworkEvidence / RegistryEvidence |
| NET-302 (Modified Hosts) | ✅ | MEDIUM | RegistryEvidence |
| NET-401 (Weak Net Sysctl) | ✅ | MEDIUM | RegistryEvidence |
| NET-402 (IPv6 Hardening) | ✅ | MEDIUM | RegistryEvidence |
| NET-501 (DNSSEC Validation) | ✅ | MEDIUM | RegistryEvidence |
| PKG-101 (Unnecessary Pkgs) | ✅ | MEDIUM | PackageEvidence |
| PKG-201 (Modified Files) | ✅ | MEDIUM | CommandEvidence |
| PKG-202 (Broken Signatures) | ✅ | HIGH | RegistryEvidence / CommandEvidence |
| PKG-301 (Unknown Repos) | ✅ | MEDIUM | RegistryEvidence |
| PKG-302 (Expired Keys) | ✅ | MEDIUM | RegistryEvidence |
| PKG-401 (Known CVEs) | ✅ | HIGH | PackageEvidence |
| PKG-402 (Pending Updates) | ✅ | HIGH | PackageEvidence |
| PRM-101 (SUID Binaries) | ✅ | HIGH | FileEvidence |
| PRM-201 (World-Writable) | ✅ | HIGH | FileEvidence |
| BOOT-101 (Secure Boot) | ✅ | HIGH | RegistryEvidence |
| BOOT-201 (Kernel Lockdown) | ✅ | MEDIUM | RegistryEvidence |
| BOOT-301 (EFI Integrity) | ✅ | HIGH | RegistryEvidence / FileEvidence |
| BOOT-401 (GRUB Password) | ✅ | HIGH | RegistryEvidence |
| BOOT-501 (Unsigned Kernels) | ✅ | HIGH | FileEvidence |
| CMP-101 (Ubuntu Support) | ✅ | MEDIUM | RegistryEvidence |
| COM-101 (Bad Processes) | ✅ | HIGH | ProcessEvidence |
| CTN-101 (Docker Socket) | ✅ | HIGH | FileEvidence |
| FOR-101 (Audit Logs) | ✅ | MEDIUM | FileEvidence |
| PER-201 (Unauth Services) | ✅ | HIGH | FileEvidence |
| SEC-101 (AppArmor) | ✅ | HIGH | FileEvidence |
| SVC-101 (Insecure Svcs) | ✅ | HIGH | FileEvidence |
| FW-101 (Firewall Active) | ✅ | HIGH | CommandEvidence |
| USB-101 (USB Storage Restriction) | ✅ | MEDIUM | FileEvidence |
| PWD-101 (Password Policy Strength) | ✅ | HIGH | FileEvidence |

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
| Compromise checks (COM-101) | ✅ | 48 | tests/unit/checks/test_compromise_checks.py |
| Compliance checks (CMP-101) | ✅ | 55 | tests/unit/checks/test_compliance_checks.py |
| Container checks (CTN-101) | ✅ | 56 | tests/unit/checks/test_container_checks.py |
| Forensics checks (FOR-101) | ✅ | 48 | tests/unit/checks/test_forensics_checks.py |
| Kernel module checks (KERN-401) | ✅ | 25 | tests/unit/checks/test_krn_checks.py |
| Package checks (PKG-101) | ✅ | 50 | tests/unit/checks/test_package_checks.py |
| Persistence checks (PER-201) | ✅ | 48 | tests/unit/checks/test_persistence_checks.py |
| Security checks (FW-101/SEC-101/USB-101) | ✅ | 94 | tests/unit/checks/test_security_checks.py |
| Service checks (SVC-101) | ✅ | 42 | tests/unit/checks/test_service_checks.py |
| Password policy (PWD-101) | ✅ | 60 | tests/unit/checks/test_password_policy_checks.py |
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
| Versioning | ✅ | 0.4.0 — semver |

---

## Check ID Numbering Scheme

All check IDs follow a **sub-ranged** format: `<PREFIX>-<SUBRANGE><SEQ>`.

Each prefix has reserved 100-level blocks for subcategories. This prevents renumbering as check counts grow.

### ID Ranges by Category

| Prefix | Range | Sub-ranges | Current |
|--------|-------|------------|---------|
| **SSH** | 100–999 | 100=Auth, 200=Algorithms, 300=Keys, 400=Logging, 500=Network, 600=Compliance | 3 |
| **KERN** | 100–999 | 100=Memory, 200=Pointers, 300=Core dumps, 400=Modules/BPF, 500=FS prot, 600=Network | 4 |
| **USR** | 100–999 | 100=Account integrity, 200=Weak creds, 300=Policy, 400=Privilege, 500=SSH keys, 600=Service accts | 9 |
| **NET** | 100–999 | 100=Ports, 200=Interfaces, 300=DNS, 400=Kernel net, 500=Wireless, 600=TLS/Certs | 7 |
| **PKG** | 100–999 | 100=Unnecessary, 200=Integrity, 300=Repos, 400=CVEs, 500=Held | 7 |
| **FS** | 100–999 | 100=File integrity, 200=Hidden/orphan, 300=Mounts, 400=Symlinks/immutable, 500=Capabilities | 0 |
| **BOOT** | 100–999 | 100=Secure Boot, 200=Lockdown, 300=EFI, 400=GRUB, 500=Kernel images | 5 |
| **SVC** | 100–999 | 100=Enabled svcs, 200=Security, 300=Listening, 400=Failed, 500=Modified | 1 |
| **PER** | 100–999 | 100=Cron/at, 200=Systemd, 300=Shell init, 400=LD injection, 500=Kernel, 600=Network, 700=Package hooks, 800=Login/init | 1 |
| **CTN** | 100–999 | 100=Socket, 200=Privileges, 300=Security, 400=Images, 500=Runtime, 600=LXC | 1 |
| **LOG** | 100–999 | 100=Journal, 200=Rotation, 300=Tamper, 400=Auth fail, 500=Auditd | 0 |
| **SECR** | 100–999 | 100=Cloud, 200=Code, 300=Crypto keys, 400=DB/API, 500=Certs | 0 |
| **FW** | 100–999 | 100=Status, 200=Rules, 300=Defaults, 400=Logging | 1 |
| **CMP** | 100–999 | 100=Version, 200=CIS, 300=STIG, 400=Regulatory, 500=Custom | 1 |
| **COM** | 100–999 | 100=Processes, 200=Network IOC, 300=Filesystem IOC | 1 |
| **FOR** | 100–999 | 100=Logs, 200=Timeline, 300=Artifacts | 1 |
| **SEC** | 100–999 | 100=AppArmor, 200=SELinux, 300=LSM | 1 |
| **USB** | 100–999 | 100=Storage, 200=Devices, 300=Guard | 1 |
| **PWD** | 100–999 | 100=Policy, 200=Reuse, 300=Aging | 1 |
| **CLD** | 100–999 | 100=AWS, 200=GCP, 300=Azure, 400=Generic | 0 |
| **PRM** | 100–999 | 100=SUID, 200=World-writable, 300=Capabilities, 400=Ownership | 2 |

### Renumbering Plan (existing → new)

| Old ID | New ID | Rationale |
|--------|--------|-----------|
| SSH-001 | SSH-101 | Authentication sub-range |
| SSH-002 | SSH-102 | Authentication sub-range |
| SSH-003 | SSH-201 | Algorithms sub-range |
| KERN-001 | KERN-101 | Memory hardening sub-range |
| KERN-002 | KERN-201 | Pointer protection sub-range |
| KERN-003 | KERN-301 | Core dump sub-range |
| KRN-001 | KERN-401 | Module loading sub-range (merged into KERN) |
| USR-001 | USR-101 | Account integrity sub-range |
| USR-002 | USR-201 | Weak credentials sub-range |
| USR-003 | USR-102 | Account integrity sub-range |
| NET-001 | NET-101 | Ports sub-range |
| NET-002 | NET-201 | Interfaces sub-range |
| PRM-001 | PRM-101 | SUID sub-range |
| PRM-002 | PRM-201 | World-writable sub-range |
| PKG-001 | PKG-101 | Unnecessary packages sub-range |
| PER-001 | PER-201 | Systemd persistence sub-range |
| SVC-001 | SVC-101 | Enabled services sub-range |
| CTN-001 | CTN-101 | Socket exposure sub-range |
| COM-001 | COM-101 | Process-based compromise sub-range |
| FOR-001 | FOR-101 | Log forensics sub-range |
| SEC-001 | SEC-101 | AppArmor sub-range |
| USB-001 | USB-101 | Storage restriction sub-range |
| PWD-001 | PWD-101 | Password policy sub-range |
| CMP-001 | CMP-101 | Version compliance sub-range |
| FIREWALL-001 | FW-101 | Firewall status sub-range |

**NOTE:** All code references, test files, knowledge YAML, docs, and config files must be updated atomically when renumbering.

---

## Phased Roadmap: Building the Complete Platform

The goal is **~500 checks** organized into **20+ categories**, with a **correlation engine** that connects findings into attack chains. Each phase builds on the previous and is independently shippable.

### Phase 0: Foundation — ✅ COMPLETE

**Goal:** Renumber all checks to reserved ranges, expand collector coverage to unserved domains.

| Task | Deliverable | Status |
|------|-------------|--------|
| P0-1 | Renumber all 25 checks to sub-ranged IDs | ✅ |
| P0-2 | Update all test references (unit/integration/golden) | ✅ |
| P0-3 | Update knowledge YAML filenames & content references | ✅ |
| P0-4 | Update docs, CONTRIBUTING, AGENTS.md | ✅ |
| P0-5 | **New collectors:** Boot, DNS, PAM, SSH config, Journald, Filesystem walker, Cert store | ✅ |
| P0-6 | Register new collectors in runner (auto-discover via pkgutil) | ✅ |
| P0-7 | TD-020: Fix correlation phase gated on wrong config key | ✅ |
| P0-8 | TD-021: Fix __init__.py exports for all 7 correlation rules | ✅ |

**Exit criteria:** All existing checks pass with new IDs. All Phase 0 collectors registered and tested. `mypy --strict` passes (0 errors, pre-existing yaml-stub warnings excluded). **Status: ✅ COMPLETE**

---

### Phase 1: High-Value Check Wave (~25 checks) — ✅ COMPLETE

**Goal:** Deliver the highest-value missing checks — Identity, Packages, Network, Boot.

#### Identity & Authentication (6 checks) — ✅
| ID | Name | Depends | File |
|----|------|---------|------|
| USR-103 | Duplicate UIDs | `users`, `groups` | `checks/users/identity_checks.py` |
| USR-104 | Disabled accounts with valid shells | `users` | `checks/users/identity_checks.py` |
| USR-105 | Expired passwords | `users` | `checks/users/identity_checks.py` |
| USR-202 | Password reuse policy | `pam` | `checks/users/identity_checks.py` |
| USR-301 | MFA status (pam_u2f, pam_duo) | `pam` | `checks/users/identity_checks.py` |
| USR-401 | Unauthorized sudo members | `sudo` | `checks/users/identity_checks.py` |

#### Package Integrity (6 checks) — ✅
| ID | Name | Depends | File |
|----|------|---------|------|
| PKG-201 | Modified package files (dpkg --verify) | none | `checks/packages/integrity_checks.py` |
| PKG-202 | Broken package signatures | none | `checks/packages/integrity_checks.py` |
| PKG-301 | Unknown repositories | `apt` | `checks/packages/integrity_checks.py` |
| PKG-302 | Expired repo signing keys | none | `checks/packages/integrity_checks.py` |
| PKG-401 | Packages with known CVEs | `apt` | `checks/packages/integrity_checks.py` |
| PKG-402 | Pending security updates | `apt` | `checks/packages/integrity_checks.py` |

#### Network Security (5 checks) — ✅
| ID | Name | Depends | File |
|----|------|---------|------|
| NET-301 | Unexpected DNS servers | `dns` | `checks/network/network_security_checks.py` |
| NET-302 | Modified hosts file | `dns` | `checks/network/network_security_checks.py` |
| NET-401 | Weak sysctl networking | `kernel_params` | `checks/network/network_security_checks.py` |
| NET-402 | IPv6 hardening | `kernel_params` | `checks/network/network_security_checks.py` |
| NET-501 | DNSSEC validation | `dns` | `checks/network/network_security_checks.py` |

#### Boot Security (5 checks) — ✅
| ID | Name | Depends | File |
|----|------|---------|------|
| BOOT-101 | Secure Boot status | `boot` | `checks/boot/boot_checks.py` |
| BOOT-201 | Kernel lockdown mode | `boot` | `checks/boot/boot_checks.py` |
| BOOT-301 | EFI integrity | `boot` | `checks/boot/boot_checks.py` |
| BOOT-401 | GRUB password set | `boot` | `checks/boot/boot_checks.py` |
| BOOT-501 | Unsigned kernels | `boot` | `checks/boot/boot_checks.py` |

#### Phase 1 Cross-Cutting Rules (3 new) — ✅
| Rule ID | What it detects |
|---------|----------------|
| CORR-101 (SUPPLY-CHAIN) | Supply chain attack (unknown repo + unsigned pkg + modified pkg) |
| CORR-102 (BOOT-FAIL) | Boot integrity failure (Secure Boot off + unsigned kernel + no GRUB password) |
| CORR-103 (DNS-HIJACK) | DNS hijacking (unexpected DNS + modified hosts + no DNSSEC) |

**Exit criteria:** 25 new checks with tests, 3 new correlation rules, all passing CI. **Status: ✅ COMPLETE**

---

### Phase 2: Filesystem & Services (~20 checks)

**Goal:** Cover filesystem integrity and expand service auditing.

#### Filesystem Integrity (10 checks)
| ID | Name | Depends |
|----|------|---------|
| FS-101 | Unexpected files in /etc | `filesystem` |
| FS-102 | Unexpected executables in PATH | `filesystem` |
| FS-201 | Hidden files in world-writable dirs | `filesystem` |
| FS-202 | Deleted binaries still running | `processes`, `filesystem` |
| FS-301 | Unexpected symlinks in /etc | `filesystem` |
| FS-302 | Immutable file drift | `filesystem` |
| FS-401 | Unexpected file capabilities | `filesystem` |
| FS-402 | World-writable directories | `filesystem` |
| FS-403 | Orphaned files (no package owner) | `filesystem`, `apt` |
| FS-501 | Filesystem mount option gaps (noexec, nosuid) | `mounts` |

#### Services (7 checks)
| ID | Name | Depends |
|----|------|---------|
| SVC-102 | Unexpected enabled services | `systemd` |
| SVC-201 | Services running as root | `systemd`, `processes` |
| SVC-202 | Services from unknown binaries | `systemd`, `apt` |
| SVC-301 | Failed services | `systemd` |
| SVC-302 | Unexpected listening services | `systemd`, `sockets` |
| SVC-401 | Recently installed services | `systemd`, `apt` |
| SVC-402 | Modified systemd unit files | `systemd` |

#### Phase 2 Correlation Rules (2 new)
| Rule ID | What it detects |
|---------|----------------|
| CORR-201 | Rogue service deployment (unknown binary + enabled svc + listening port) |
| CORR-202 | File integrity breach (orphaned files + unexpected symlinks + modified /etc) |

**Exit criteria:** 17 new checks with tests, 2 new correlation rules.

---

### Phase 3: Deep Persistence (~25 checks)

**Goal:** Cover every attacker persistence mechanism. This is the deepest category.

| ID | Name | Depends |
|----|------|---------|
| PER-101 | Cron job anomalies | `cron` |
| PER-102 | Anacron jobs | `cron` |
| PER-103 | `at` jobs | `cron` |
| PER-202 | Suspicious systemd timer names | `systemd` |
| PER-203 | Systemd service drop-ins | `systemd` |
| PER-204 | Systemd path units | `systemd` |
| PER-301 | Unexpected profile.d scripts | `filesystem` |
| PER-302 | Modified bashrc/bash_profile | `filesystem` |
| PER-303 | Modified zshrc | `filesystem` |
| PER-401 | LD_PRELOAD in environment | `processes` |
| PER-402 | ld.so.preload entries | `filesystem` |
| PER-403 | LD_LIBRARY_PATH anomalies | `processes` |
| PER-501 | Unexpected PAM modules | `pam` |
| PER-502 | PAM module modifications | `pam` |
| PER-503 | udev rules persistence | `filesystem` |
| PER-601 | Network hook scripts | `filesystem` |
| PER-602 | SSH forced commands | `ssh_config` |
| PER-603 | SSH AuthorizedKeysFile tampering | `ssh_config` |
| PER-701 | APT hook persistence | `apt` |
| PER-702 | dpkg hook persistence | `filesystem` |
| PER-801 | rc.local scripts | `filesystem` |
| PER-802 | init.d scripts | `filesystem` |
| PER-803 | Login/logout hooks | `filesystem` |
| PER-804 | systemd user units | `systemd` |
| PER-805 | XDG autostart entries | `filesystem` |

#### Phase 3 Correlation Engine 2.0

The correlation engine evolves from simple pattern matching to **attack chain detection**:

| Feature | Description |
|---------|-------------|
| Multi-finding chain detection | e.g., new user + SSH key + systemd timer + cron job → persistence |
| Temporal scoring | Freshness of finding weights the confidence score |
| Kill chain visualization | Map findings to MITRE ATT&CK tactics in order |
| YAML-driven rules | Correlation rules defined in YAML, not code |
| Risk accumulation | Multiple persistence mechanisms → exponential scoring |
| False positive dampening | Counter-evidence reduces scores (e.g., known-good packages) |

**Exit criteria:** 25 persistence checks, 5 new correlation rules for persistence chains.

---

### Phase 4: Containers, Secrets & Logs (~30 checks)

**Goal:** Cover modern deployment realities.

#### Containers (8 checks)
| ID | Name | Depends |
|----|------|---------|
| CTN-102 | Docker daemon TCP exposure | `containers` |
| CTN-201 | Privileged containers | `containers` |
| CTN-202 | Host network namespace | `containers` |
| CTN-203 | Host PID namespace | `containers` |
| CTN-204 | Host filesystem mounts | `containers` |
| CTN-301 | Root containers | `containers` |
| CTN-401 | Image age (>30 days) | `containers` |
| CTN-402 | Unsigned images | `containers` |

#### Logs & Forensics (8 checks)
| ID | Name | Depends |
|----|------|---------|
| LOG-101 | Journal max size / retention | `journald` |
| LOG-201 | Log rotation gaps | `journald` |
| LOG-301 | Missing log periods (tampering) | `journald` |
| LOG-302 | Log file permissions | `filesystem` |
| LOG-401 | Repeated sudo failures | `auditd` |
| LOG-402 | Repeated SSH auth failures | `auditd` |
| LOG-501 | Auditd rule coverage gaps | `auditd` |
| LOG-502 | Auditd log exhaustion risk | `auditd` |

#### Secrets (10 checks)
| ID | Name | Depends |
|----|------|---------|
| SECR-101 | AWS keys in filesystem | `filesystem` |
| SECR-102 | GCP service account keys | `filesystem` |
| SECR-201 | GitHub tokens in files | `filesystem` |
| SECR-202 | .env files with secrets | `filesystem` |
| SECR-203 | API keys in config files | `filesystem` |
| SECR-301 | Exposed SSH private keys | `filesystem` |
| SECR-302 | Weak SSH key types (DSA, 1024-bit RSA) | `ssh_config` |
| SECR-401 | Database credentials in world-readable files | `filesystem` |
| SECR-501 | Expired TLS certificates | `certificates` |
| SECR-502 | Self-signed certificates in prod | `certificates` |

#### Phase 4 Correlation Rules (4 new)
| Rule ID | What it detects |
|---------|----------------|
| CORR-401 | Container escape path (privileged + host net + root + old image) |
| CORR-402 | Credential compromise (secrets leaked + exposed SSH keys + cloud creds) |
| CORR-403 | Active breach (log gaps + auth failures + new service + new user) |
| CORR-404 | Exposed attack surface (many listening services + weak TLS + no auditd) |

**Exit criteria:** 26 new checks, 4 new rules.

---

### Phase 5: Correlation Engine 2.0 — Full Attack Chain Detection

**Goal:** Transform correlation from simple pattern matching to a full threat-detection engine.

| Feature | Priority | Details |
|---------|----------|---------|
| YAML-defined rules | HIGH | Define correlation rules as YAML files in `policies/correlation/` |
| Temporal correlation | HIGH | Weight findings by freshness (newer = higher confidence) |
| Kill chain mapper | MEDIUM | Map finding chain to MITRE ATT&CK tactics (Recon→Weaponize→Deliver→Exploit→Install→C2→Actions) |
| Risk accumulation | HIGH | N persistence mechanisms → `1 - (0.5)^N` confidence |
| Counter-evidence | MEDIUM | Known-good packages, vendor-signed binaries reduce scores |
| Threat intel feeds | LOW | Import external threat intel for IOC matching |
| Custom rule DSL | LOW | Simple Python-like DSL for power users |
| Scenario scoring | HIGH | Pre-built attack scenarios (ransomware, cryptominer, persistence) scored as a unit |

**Target correlation rule count: 25–50 rules** covering common attack scenarios.

**Exit criteria:** All 8 core attack scenarios detectable with >90% precision.

---

### Phase 6: Cloud & Compliance (~25 checks)

**Goal:** Extend to cloud environments and regulatory compliance automation.

#### Cloud (10 checks)
| ID | Name | Depends |
|----|------|---------|
| CLD-101 | Cloud metadata service exposure | `network` |
| CLD-102 | IMDSv1 vs IMDSv2 | `network` |
| CLD-201 | Public cloud storage exposure | `network` |
| CLD-301 | Cloud IAM credential audit | `filesystem` |
| CLD-401 | Cloud agent health | `processes` |
| CLD-501 | Kubernetes node security | `containers`, `processes` |

#### Compliance (10 checks)
| ID | Name | Depends |
|----|------|---------|
| CMP-201 | CIS Level 1 — Server | all |
| CMP-202 | CIS Level 2 — Server | all |
| CMP-203 | CIS Level 1 — Desktop | all |
| CMP-301 | STIG Ubuntu 22.04 | all |
| CMP-401 | PCI DSS 4.0 relevant controls | all |
| CMP-402 | SOC2 relevant controls | all |
| CMP-403 | HIPAA relevant controls | all |
| CMP-501 | Custom policy evaluation | all |
| CMP-502 | Drift from baseline | baseline |
| CMP-503 | Remediation verification | all |

#### Phase 6 Correlation Rules (3 new)
| Rule ID | What it detects |
|---------|----------------|
| CORR-601 | Cloud credential exposure + metadata API accessible → instance compromise |
| CORR-602 | CIS level 1 failures > 10 + firewall disabled + auditd off → critical compliance gap |
| CORR-603 | Multiple compliance frameworks failing same control → priority remediation |

**Exit criteria:** 25 new checks, 3 new rules, full CIS benchmark coverage.

---

### Phase 7: Scale, Distribution & Ecosystem (infrastructure phase)

**Goal:** Production-grade deployment capabilities.

| Feature | Priority | Notes |
|---------|----------|-------|
| Remote / Fleet scanning | HIGH | SSH transport for remote collectors, aggregate results |
| Agent mode | HIGH | Daemon with periodic scanning + MQTT/NATS publishing |
| Timeline DB | MEDIUM | SQLite history of all findings with trend analysis |
| Web dashboard | MEDIUM | FastAPI + React dashboard for scan results |
| Plugin marketplace | LOW | Community check repository with signing |
| Plugin sandboxing | LOW | Container/namespace isolation for 3rd-party plugins |
| Performance optimization | MEDIUM | Caching, batch collectors, incremental scans |
| Event-driven monitoring | LOW | inotify/fanotify for real-time file change detection |

---

## Target Check Counts by Layer

| Layer | Current | Phase 2 | Phase 3 | Phase 4 | Phase 6 | Target |
|-------|---------|---------|---------|---------|---------|--------|
| SSH | 3 | 3 | 3 | 3 | 3 | 25 |
| Kernel | 4 | 4 | 4 | 4 | 4 | 25 |
| Users | 9 | 9 | 9 | 9 | 9 | 20 |
| Network | 7 | 7 | 7 | 7 | 7 | 35 |
| Packages | 7 | 7 | 7 | 7 | 7 | 25 |
| Filesystem | 0 | 10 | 10 | 10 | 10 | 30 |
| Permissions | 2 | 2 | 2 | 2 | 2 | 25 |
| Boot | 5 | 5 | 5 | 5 | 5 | 15 |
| Services | 1 | 8 | 8 | 8 | 8 | 30 |
| Persistence | 1 | 1 | 26 | 26 | 26 | 40 |
| Containers | 1 | 1 | 1 | 9 | 9 | 25 |
| Logs & Forensics | 1 | 1 | 1 | 9 | 9 | 25 |
| Secrets | 0 | 0 | 0 | 10 | 10 | 20 |
| Cloud | 0 | 0 | 0 | 0 | 6 | 20 |
| Compliance | 1 | 1 | 1 | 1 | 11 | 20 |
| Firewall | 1 | 1 | 1 | 1 | 1 | 10 |
| Security (AppArmor/USB) | 2 | 2 | 2 | 2 | 2 | 10 |
| Compromise | 1 | 1 | 1 | 1 | 1 | 15 |
| Password | 1 | 1 | 1 | 1 | 1 | 10 |
| **Total checks** | **47** | **65** | **91** | **117** | **133** | **~450** |
| **Correlation rules** | 10 | 12 | 17 | 21 | 24 | **50+** |

---

## Technical Debt Log

| ID | Description | Severity | Status | Phase |
|----|-------------|----------|--------|-------|
| TD-001 | `metadata.configuration_file` set to `scan_name` instead of config path | LOW | ✅ | — |
| TD-002 | `metadata.end_time` set to `scan_start_dt` instead of actual end time | LOW | ✅ | — |
| TD-003 | Integration tests coverage expanded from 21→93 tests (8 test files, 3 new) | MEDIUM | ✅ | — |
| TD-004 | ~~Scoring ignores confidence~~ → **Fixed** (P1-1 + P3-3) | HIGH | ✅ | — |
| TD-005 | Collectors hardcoded in runner → **Fixed** (auto-discovered) | MEDIUM | ✅ | — |
| TD-006 | No parallel execution despite `parallel=True` in config | LOW | ✅ | — |
| TD-007 | ~~`mypy --strict` fails (245→15 errors)~~ → **Fixed: 0 errors across 100 source files** | MEDIUM | ✅ | — |
| TD-008 | ~~SUID FP rate ~80%~~ → **Resolved** (expanded whitelist, config allowlist, MEDIUM/LOW confidence tiers based on 60 known-safe packages) | HIGH | ✅ | — |
| TD-009 | Severity context `apply_all()` computed adjustments but never applied them to findings (dead data pipeline) | HIGH | ✅ | — |
| TD-010 | Knowledge Base YAML coverage was 16/25 checks (64%); 9 missing files added + KB wired into runner pipeline | MEDIUM | ✅ | — |
| TD-011 | CMP-101 (Ubuntu version check) missing `mitre_attack_ids` entirely | MEDIUM | ✅ | — |
| TD-012 | `scoring/__init__.py` and `models/__init__.py` were empty (no exports) | LOW | ✅ | — |
| TD-013 | 9 checks missing `reference` URL in findings | MEDIUM | ✅ | — |
| TD-014 | Systemd collector doesn't strip `●` bullet char → service names corrupted for failed/degraded units | HIGH | ✅ | — |
| TD-015 | `get_package_for_file()` doesn't resolve symlinks → `/bin/*` and `/sbin/*` show "Not owned by any installed package" (merged-usr layout) | HIGH | ✅ | — |
| TD-016 | CMP-101 supported versions hardcoded to 20.04/22.04/24.04 → 26.04 flagged as unsupported | MEDIUM | ✅ | — |
| TD-017 | PKG-101 flags desktop packages (cups, avahi, whoopsie, xorg) on desktop systems | MEDIUM | ✅ | — |
| TD-018 | PER-201 doesn't filter snap-managed services → false positives for snap.svc names | MEDIUM | ✅ | — |
| TD-019 | PER-201 doesn't filter known-legitimate services (e.g., switcheroo-control → "proxy" match) | LOW | ✅ | — |
| TD-020 | Correlation phase gated on `config.general.cache` instead of own flag (should be `always run`) | LOW | ✅ | P0 |
| TD-021 | `__init__.py` doesn't export all 7 correlation rules (3 missing from `__all__`) | LOW | ✅ | P0 |
| TD-022 | No collector exists for SSH config parsing (`sshd_config`); checks parse via subprocess | MEDIUM | 🔴 | P0 |
| TD-023 | No collector exists for PAM configuration | MEDIUM | 🔴 | P0 |
| TD-024 | No collector exists for boot/firmware state | MEDIUM | 🔴 | P0 |
| TD-025 | No collector exists for filesystem walking (SUID, world-writable) | MEDIUM | 🔴 | P0 |
| TD-026 | No collector for DNS resolver state | LOW | 🔴 | P0 |

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
│   └── runner.py              # ScanRunner orchestrator (8 phases)
├── models/
│   ├── evidence.py            # 8 evidence types
│   ├── finding.py             # Finding model (24 fields)
│   ├── severity.py            # Severity, Confidence, CheckCategory enums
│   ├── result.py              # CheckResult, ScanResult, ScanMetadata
│   ├── score.py               # ScanScore, CategoryScore
│   └── references.py          # CVE, CIS, MITRE, OWASP models
├── collectors/                # 15 collectors across 8 categories
├── checks/                    # 25 checks across 17 categories
├── reporting/                 # 3 reporters
├── scoring/
│   ├── engine.py              # Scoring engine (with confidence*FP)
│   └── trust.py               # Trust scoring (evidence quality)
├── baseline/manager.py        # Baseline snapshots
├── correlation/               # Correlation engine + 7 rules
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

| Metric | Current | Short-term (P2) | Medium-term (P3) | Long-term (P6) |
|--------|---------|-----------------|-------------------|-----------------|
| Checks | 47 | 65 | 91 | 133 → **450+** |
| Collectors | 22 | 22 | 24 | 28 |
| Correlation rules | 10 | 12 | 17 | 24 → **50+** |
| Unit tests | 490 | 800+ | 1,500+ | 3,000+ |
| Integration tests | 93 | 150+ | 300+ | 500+ |
| Test coverage (stmt) | 85% | 88% | 90% | 92%+ |
| Test coverage (branch) | 82% | 85% | 88% | 90%+ |
| mypy --strict | 0 errors | 0 errors | 0 errors | 0 errors |
| Knowledge YAML coverage | 100% | 100% | 100% | 100% |
| False positive rate | ~2% | <3% | <3% | <2% |
| Attack scenario coverage | 3 | 6 | 10 | 20+ |
| Correlation engine maturity | Basic | Chained | Temporal | Full kill chain |

---

## Contributing to This Document

This is a living document. Update it when:
- New features are completed (move to ✅, note date)
- Technical debt is resolved (move to ✅)
- Targets are met (update Metrics & Targets)
