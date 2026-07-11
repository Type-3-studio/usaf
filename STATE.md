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
| 🔷 | External dependency |

### Architecture Layer

```
┌──────────────────────────────────────────────────────────────┐
│                         CLI (Typer)                    ✅    │
├──────────────────────────────────────────────────────────────┤
│                    Scan Orchestrator (Runner)           ✅    │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Collectors│  │  Checks  │  │Reporters │  │ Scoring  │    │
│  │    ✅    │  │    ✅    │  │    ✅    │  │    ◐    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Registry │  │  Cache   │  │  Config  │  │ Evidence │    │
│  │    ✅    │  │    ✅    │  │    ✅    │  │    ✅    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │Baselines │  │Correlat. │  │ Policies │  │ Profiles │    │
│  │    ⬜    │  │   🔴    │  │   🔴    │  │   🔴    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Rules   │  │  LLM AI  │  │  Agents  │  │Fleet/MQ  │    │
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
| `APTCollector` | ✅ | dpkg query, package DB |
| `SystemdCollector` | ✅ | systemctl, unit files |
| `CronCollector` | ✅ | crontabs, cron.d, cron.daily |

#### Checks (13 total)
| Check | Status | Severity | Evidence |
|-------|--------|----------|----------|
| KERN-001 (ASLR) | ✅ | HIGH | RegistryEvidence |
| KERN-002 (Pointer Restriction) | ✅ | MEDIUM | RegistryEvidence |
| KERN-003 (Core Dump) | ✅ | MEDIUM | RegistryEvidence |
| SSH-001 (Protocol) | ✅ | HIGH | FileEvidence |
| SSH-002 (Root Login) | ✅ | HIGH | FileEvidence |
| SSH-003 (KEX Algorithms) | ✅ | MEDIUM | FileEvidence |
| USR-001 (Duplicate UID 0) | ✅ | CRITICAL | UserEvidence |
| USR-002 (Empty Passwords) | ✅ | CRITICAL | UserEvidence |
| USR-003 (Shadowed Passwords) | ✅ | HIGH | FileEvidence |
| NET-001 (Listening Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-002 (Promiscuous Mode) | ✅ | MEDIUM | NetworkEvidence |
| PRM-001 (SUID Binaries) | ✅ | HIGH | FileEvidence |
| PRM-002 (World-Writable) | ✅ | HIGH | FileEvidence |

#### Reporters (3 total)
| Reporter | Status | Features |
|----------|--------|----------|
| `TerminalReporter` | ✅ | Rich tables, color, severity badges, score panel |
| `JSONReporter` | ✅ | Full structured output with metadata |
| `MarkdownReporter` | ✅ | Code blocks, severity emoji indicators |

#### CLI
| Command | Status | Notes |
|---------|--------|-------|
| `usaf scan` | ✅ | Full scan pipeline |
| `usaf list-checks` | ✅ | With `--category` filter |
| `usaf init` | ✅ | Config file bootstrapping |

#### Evidence System (8 types)
| Type | Status | Fields |
|------|--------|--------|
| `FileEvidence` | ✅ | path, line, content, perms, owner, group, size, hash, modified |
| `ProcessEvidence` | ✅ | pid, name, binary, cmdline, user, state, ppid, threads, mem, cpu, fds |
| `NetworkEvidence` | ✅ | protocol, addr, port, state, pid, process |
| `CommandEvidence` | ✅ | command, stdout, stderr, exit_code |
| `RegistryEvidence` | ✅ | key, value, expected, source |
| `LogEvidence` | ✅ | log_path, lines, pattern, match_count |
| `UserEvidence` | ✅ | username, uid, gid, home, shell, groups, keys, login, expiry |
| `PackageEvidence` | ✅ | name, version, arch, repo, status, size |

#### Scoring Engine
| Feature | Status | Notes |
|---------|--------|-------|
| Per-category scoring | ✅ | 19 categories, weighted |
| Overall score (0-10) | ✅ | Letter grades A+ to F- |
| **Confidence multiplier** | 🔴 | `Confidence` enum defined, **never applied** |
| False positive probability | 🔴 | Field exists, **never applied** |
| Context-aware severity | 🔴 | Severity hardcoded per check |

#### Plugin System
| Feature | Status | Notes |
|---------|--------|-------|
| Registry | ✅ | Singleton, CRUD, lifecycle |
| Dependency resolution | ✅ | Topological sort |
| Instance caching | ✅ | Per-check singleton |
| Auto-discovery | 🔴 | Manual imports in `__init__.py` |
| Plugin isolation | 🔴 | No sandbox for 3rd-party plugins |

#### Models
| Model | Status | Fields |
|-------|--------|--------|
| `Finding` | ✅ | 24 fields including all compliance mappings |
| `CheckResult` | ✅ | pass/fail, findings, error, timing |
| `ScanResult` | ✅ | metadata, results, collector_data |
| `ScanScore` | ✅ | overall, per-category, grade |
| `ScanMetadata` | ✅ | host, OS, version, timing |

#### Config
| Feature | Status | Notes |
|---------|--------|-------|
| YAML loading | ✅ | XDG, home, CWD resolution |
| Deep merge defaults | ✅ | |
| Plugin overrides | ✅ | enable/disable per check |
| Ignore patterns | ✅ | fnmatch-based |
| **Baseline config** | ⬜ | Model exists, no implementation |
| **Policy config** | ⬜ | Model exists, no implementation |
| **Profile config** | 🔴 | Not designed yet |

#### Testing
| Area | Coverage | Notes |
|------|----------|-------|
| Unit tests | 1,205 lines | 10 files |
| **Integration tests** | 🔴 | None exist |
| **Golden tests** | 🔴 | Config + marker exist, no tests |
| SSH checks | 🔴 | Untested |
| Network checks | 🔴 | Untested |
| Permission checks | 🔴 | Untested |
| CLI | 🔴 | Untested |

#### Developer Infrastructure
| Tool | Status | Notes |
|------|--------|-------|
| `ruff` config | ✅ | pyproject.toml |
| `mypy` config | ✅ | strict mode |
| Pre-commit hooks | 🔴 | Not configured |
| CI/CD | 🔴 | No pipeline |
| Versioning | ⬜ | 0.1.0.dev1 — no semver enforcement |

---

## Phase 1: Foundation Hardening (Now — Current Sprint)

These are the immediate gaps that undermine credibility. Fix these before adding features.

### P1-1: Wire Confidence Into Scoring Engine
- **Problem:** `Confidence` enum and `false_positive_probability` field exist on every finding but are completely ignored by `ScoringEngine.calculate()`.
- **Impact:** A LOW confidence finding counts the same as HIGH confidence. This makes the score meaningless.
- **Changes:**
  - `scoring/engine.py`: Multiply each finding's penalty by `finding.confidence.multiplier` and `(1.0 - finding.false_positive_probability)`
  - Verify existing tests pass, add test for confidence-weighted scoring
- **Effort:** ~20 lines of code, 2 test cases

### P1-2: Package Ownership Integration for SUID and World-Writable Checks
- **Problem:** PRM-001 (SUID Binaries) and PRM-002 (World-Writable Files) report every unexpected file they find. On Ubuntu, most SUID files are package-owned and expected (e.g., `ping`, `sudo`, `mount`). Without filtering by package ownership, ~80-90% of findings are false positives.
- **Impact:** The tool will be dismissed as noisy by anyone who runs it on a real system.
- **Changes:**
  - `checks/permissions/suid_checks.py`: Accept `apt` collector data, cross-reference each SUID file against package ownership via `dpkg -S` (already collected by `APTCollector`)
  - Add `PackageEvidence` to findings showing the owning package
  - Set `confidence = Confidence.LOW` and `false_positive_probability = 0.8` for package-owned files
  - Same for PRM-002
- **Effort:** ~80 lines per check, 2 test files

### P1-3: No-Findings Test Suite
- **Problem:** SSH, network, and permission checks have zero unit tests.
- **Impact:** Regressions go undetected.
- **Changes:**
  - `tests/unit/checks/test_ssh_checks.py` — test SSH-001, SSH-002, SSH-003 with mock configs
  - `tests/unit/checks/test_network_checks.py` — test NET-001, NET-002 with mock sockets
  - `tests/unit/checks/test_permission_checks.py` — test PRM-001, PRM-002 with mock files
  - `tests/unit/test_scan_runner.py` — test runner orchestration
  - `tests/unit/test_cli.py` — test CLI commands
- **Effort:** ~400 lines total

### P1-4: Plugin Auto-Discovery
- **Problem:** Every new check must be manually imported in `checks/__init__.py` and every new collector must be manually registered in `ScanRunner._setup_collectors()`.
- **Impact:** Adding a check requires touching 2-3 files. Impedes community contributions.
- **Changes:**
  - `core/registry.py`: Add `discover(package)` that walks `checks/` subdirectories via `importlib.metadata` / `pkgutil.walk_packages`
  - `core/runner.py`: Replace hardcoded collector registration with auto-discovery via `collectors/base.py` metaclass or decorator
  - Keep manual registration as an override option for explicit ordering
- **Effort:** ~100 lines

### P1-5: Developer Experience CI
- **Problem:** `ruff` and `mypy` are configured but never run. No pre-commit hooks.
- **Impact:** Code quality degrades with every commit.
- **Changes:**
  - `.pre-commit-config.yaml` with `ruff check`, `ruff format`, `mypy`, trailing whitespace
  - `.github/workflows/ci.yml` with pytest, ruff, mypy on push/PR
  - Add `make lint`, `make typecheck`, `make test` convenience commands (or in pyproject.toml `[tool.task]`)
- **Effort:** ~60 lines

---

## Phase 2: Professional-Grade Features (Next 2-3 Sprints)

### P2-1: Correlation Engine

The single biggest differentiator between a script and a professional tool.

**Design:**
- New directory: `src/usaf/correlation/`
- `CorrelationRule` base class with same interface style as `AuditCheck`:

```python
class CorrelationRule:
    id: str
    name: str
    description: str
    severity: Severity

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        ...
```

- Registry for correlation rules (reuse `PluginRegistry` or create lightweight variant)
- `CorrelationEngine` that receives all findings and returns synthetic findings
- Orchestrated by `ScanRunner` after all checks complete, before scoring

**Initial Correlation Rules:**

| Rule | Input Findings | Output |
|------|---------------|--------|
| `SSHBruteForceSurface` | SSH-001 + SSH-002 + SSH-003 + NET-001(port 22) | **CRITICAL**: "SSH Attack Surface — remote root brute-force possible" |
| `SuspiciousPersistence` | USR-001 + unexpected systemd service + SSH key change | **HIGH**: "Potential persistence mechanism detected" |
| `UnauthorizedService` | NET-001(unexpected port) + PRM-001 + unknown systemd service | **HIGH**: "Likely unauthorized service running" |
| `DataExfilSurface` | NET-002(promiscuous) + unexpected outbound connections | **MEDIUM**: "Network sniffing indicators present" |

**Implementation details:**
- `CorrelatedFinding` extends `Finding` with `source_findings: list[str]` (IDs of findings that triggered it)
- Correlation rules receive a `findings` list and return either empty list or synthetic findings
- The engine runs rules in dependency order (if A needs B's output)
- Correlation operates on the **current scan's findings** — no state across scans

**Effort:** ~300 lines core + ~200 lines rules + tests

### P2-2: Baseline Engine

Change detection is often more valuable than absolute state.

**Design:**
- New directory: `src/usaf/baseline/`
- `BaselineManager` with three operations:

```
store(path, scan_result)   → save baseline hash to JSON
diff(baseline, current)    → compare states, return changes
load(path)                 → restore baseline from file
```

**What to baseline:**
```
packages:   {name: version} for all dpkg-managed packages
users:      {username: {uid, gid, groups, shell, ssh_keys}}
services:   {unit_name: {state, enabled, exec_start}}
ports:      {(proto, port, addr): {pid, process}}
suid_files: {path: {owner, group, perms, hash}}
cron_jobs:  {file: [jobs]}
kernel_params: {param: value}
sshd_config: {directive: value}
```

**Baseline storage format:** Deterministic JSON (sorted keys, no timestamps)

```
~/.config/usaf/baselines/
├── default-baseline.json
├── 2026-07-11T00:00:00Z.json
└── profiles/
    └── production-web.json
```

**Diff output:**
```json
{
  "added": {"users": ["backdoor_user"]},
  "removed": {},
  "modified": {
    "sshd_config": {
      "old": {"PasswordAuthentication": "no"},
      "new": {"PasswordAuthentication": "yes"}
    }
  }
}
```

**CLI integration:**
```
usaf baseline init           # Create initial baseline
usaf baseline update         # Update to current state
usaf baseline diff           # Show changes since last baseline
usaf scan --baseline-diff    # Scan + compare to baseline
```

**Effort:** ~500 lines core + CLI + tests

### P2-3: Context-Aware Severity (Smart Severity)

Severity depends on context, not just the check.

**Design:**
- `checks/ssh_checks.py`: Detect if SSH port is exposed on a public interface (vs. localhost/private)
- `checks/port_checks.py`: Detect container vs. bare-metal context
- Configurable via `severity_overrides` in `config/model.py`:

```yaml
severity:
  context_rules:
    SSH-001:
      internet_exposed: CRITICAL
      private_network: HIGH
      localhost: MEDIUM
    USR-002:
      service_account: MEDIUM
      human_user: CRITICAL
```

- `severity/engine.py` (new): Evaluate context rules to adjust severity before scoring

**Effort:** ~150 lines

### P2-4: Compliance Framework

**Design:**
- `compliance/` directory with framework-level queries:

```python
compliance = ComplianceFramework()
compliance.get_findings_for("CIS Ubuntu 22.04 L2")
compliance.get_coverage("NIST 800-53")
compliance.report_gap_analysis()
```

- Profile-based compliance: `usaf scan --compliance cis-level-2`
- Report generation: separate section in terminal/markdown/JSON showing which controls passed/failed

**Effort:** ~200 lines (leverages existing CIS/MITRE fields on findings)

### P2-5: Profiles System

**Design:**
- `profiles/` directory with YAML files describing expected system state per role:

```yaml
# profiles/desktop-ubuntu.yaml
name: Ubuntu Desktop 24.04
distro: ubuntu
version: "24.04"
expected_packages:
  - ubuntu-desktop
  - firefox
  - libreoffice
expected_services:
  - gdm
  - NetworkManager
expected_suid:
  - /usr/bin/sudo
  - /usr/bin/ping
  - /usr/bin/mount
  - /usr/bin/umount
  - /usr/bin/passwd
  - /usr/bin/newgrp
  - /usr/bin/gpasswd
  - /usr/bin/chsh
  - /usr/bin/chfn
```

- Profile matcher (auto-detect based on `/etc/os-release` and installed packages)
- `prm_checks.py`: Compare against profile instead of hardcoded list
- Drastically reduces false positives for SUID and world-writable checks

**Effort:** ~300 lines + profile definitions

---

## Phase 3: Intelligence Layer (Mid-Term)

### P3-1: Rule Engine (Optional Abstraction)

**Not a priority.** Current Python-based checks are already expressive, testable, and easy to add. A YAML rule DSL would need to match Python's expressiveness to be useful, which means it would essentially be a Python interpreter in YAML — a well-known antipattern.

**If added, it should be limited to:**
- A config layer for **parameterizing** existing checks (e.g., allowed SUID lists, expected port ranges)
- An override mechanism for severity thresholds
- NOT a replacement for the check system

```yaml
# policies/custom-params.yaml
checks:
  PRM-001:
    allowed_suid:
      - /usr/bin/sudo
      - /usr/bin/ping
    severity_if_not_allowed: HIGH
  NET-001:
    allowed_ports:
      22: {purpose: ssh, owner: root}
      80: {purpose: http, owner: www-data}
      443: {purpose: https, owner: www-data}
```

### P3-2: Knowledge Base (Metadata Store)

**Design:**
- `knowledge/` directory with YAML/JSON files mapping check IDs to rich metadata:

```yaml
# knowledge/USR-002.yaml
id: USR-002
title: Empty Password Accounts
threat: Local or remote authentication with no password required.
exploit: "ssh user@host with empty password, or su with empty password"
impact: Complete account takeover, privilege escalation
fix: "passwd -l <user> or passwd <user> to set a password"
breakage: "Service accounts may stop working if they rely on empty passwords"
cvss: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (8.4)"
affected_versions: ["Ubuntu 20.04", "Ubuntu 22.04", "Ubuntu 24.04"]
false_positive_rate: 0.01
known_exceptions:
  - "Root account intentionally locked for sudo-only access (usermod -p '!' root)"
related_findings: ["USR-001", "USR-003"]
```

- Integrate into `Finding` via `reference` field and reporter lookup
- Reporters can render KB content inline for richer output

**Effort:** ~150 lines + knowledge base YAML files

### P3-3: Trust Scoring (Confidence-Aware Risk)

Build on P1-1 with a more sophisticated model:

```python
trust_score = confidence.multiplier * (1.0 - false_positive_probability)
```

Combine with context and evidence quality:
- **File evidence present** → +0.1 to confidence
- **Command evidence present** → +0.05
- **Multiple evidence sources** → +0.1
- **No evidence** → clamp confidence to LOW

This automatically rewards checks that provide solid evidence and penalizes those that don't, incentivizing check authors to include evidence.

---

## Phase 4: Scale & Distribution (Long-Term)

### P4-1: Parallel Execution

Config has `parallel=True` but no implementation. Use `concurrent.futures.ThreadPoolExecutor` for:
- Collector execution (independent collectors run in parallel)
- Check execution (checks without dependencies run in parallel)

Add `max_workers` to config.

**Effort:** ~100 lines

### P4-2: Remote / Fleet Scanning

**Design:**
- New transport layer: `remote/`
- SSH-based collector transport:

```python
class SSHTransport:
    def collect(self, host: str, collector_names: list[str]) -> dict:
        # SSH to host, run collectors via usaf remote-collect
        # Return serialized data
```

- `usaf remote scan --hosts inventory.yaml` where inventory.yaml lists hosts:

```yaml
hosts:
  - hostname: web-01
    user: audit
    port: 22
    profile: production-web
  - hostname: db-01
    user: audit
    port: 22
    profile: production-db
```

- Aggregate results into a fleet report

### P4-3: Message Queue / Agent Mode

**Design:**
- `usaf agent` mode that runs periodically and publishes results to MQ (NATS, MQTT, or Redis pub/sub)
- `usaf server` that subscribes, aggregates, stores in DB
- Configurable interval and alert thresholds

### P4-4: Historical Timeline DB

Build on P2-2 (Baselines):
- Store all baselines in SQLite (or DuckDB for analytics)
- `usaf timeline` command queries history:

```
usaf timeline sshd_config        # Show all changes to sshd_config
usaf timeline users              # Show user account history
usaf timeline port 22            # Show SSH port history
usaf timeline --since 30d        # All changes in last 30 days
```

- Each timeline entry: `{timestamp, finding_id, old_value, new_value, scan_id}`

---

## Phase 5: Intelligence & AI (Advanced)

### P5-1: Local LLM Integration (Ollama)

**Design:**

```python
class LLMAnalyzer:
    def __init__(self, model: str = "llama3", endpoint: str = "http://localhost:11434"):
        self.model = model
        self.endpoint = endpoint

    def analyze_findings(self, findings: list[Finding]) -> LLMInsight:
        """Generate natural-language security analysis from findings."""

    def prioritize(self, findings: list[Finding]) -> list[RankedFinding]:
        """Ask LLM to rank findings by actual business risk."""

    def summarize(self, scan_result: ScanResult) -> str:
        """One-paragraph executive summary of the scan."""
```

**Use cases:**
- **Executive summary:** "Your system has 3 critical issues: SSH allows password-based root login, there's an unknown SUID binary at /opt/backdoor, and a user account has no password set."
- **Priority ranking:** Not all CRITICAL findings matter equally. The LLM can order findings by actual exploitability.
- **Remediation generation:** Contextual fix instructions accounting for the system's specific configuration.
- **False positive review:** "This SUID binary is owned by a snap package from the official store — likely low risk."
- **Natural language queries:** `usaf ask "What changed since last week?"` or `usaf ask "Is this system PCI compliant?"`

**Architecture:**
```
findings → prompt template → Ollama API → structured output → LLMInsight
```

Prompt engineering is critical. Each analysis type needs a well-crafted prompt with:
- System role: "You are a Linux security expert analyzing audit findings. Be concise, cite evidence, and flag uncertainties."
- Structured finding input (JSON subset)
- Output format specification (JSON schema)

### P5-2: AI Agent for Autonomous Remediation

**Design:**
- `usaf fix SSH-002` → agent evaluates options, creates backup, applies change, verifies, rolls back on failure
- Safety constraints:
  - `--dry-run` by default (show commands without executing)
  - `--apply` flag for actual execution
  - Configurable allow/deny list for remediation actions
  - Always create backups before changes
  - Auto-rollback on verification failure

```python
class RemediationAgent:
    def plan(self, finding: Finding) -> RemediationPlan:
        """Generate step-by-step remediation plan with rollback steps."""

    def execute(self, plan: RemediationPlan) -> RemediationResult:
        """Execute plan, creating backups, verifying each step."""

    def rollback(self, plan: RemediationPlan) -> None:
        """Undo all changes, restore from backup."""
```

### P5-3: AI Skills / Dataset Generation

**Design:**
- `usaf dataset generate` — creates a curated dataset of (finding, risk_score, priority) pairs from multiple scans
- Dataset can fine-tune a small LLM or train a classifier
- `skills/` directory with LLM skill definitions:

```yaml
# skills/compliance-checker.yaml
name: compliance-checker
model: llama3
prompt: |
  Given these audit findings, identify which CIS controls are violated:
  {findings_json}
output_format: json_schema
schema:
  type: object
  properties:
    violated_controls:
      type: array
      items:
        type: object
        properties:
          cis_id: string
          status: enum(passed, failed, not_applicable)
```

### P5-4: Anomaly Detection (ML)

Build on P2-2 (Baselines):
- Collect baseline data over time (weeks/months)
- Train simple anomaly detection (isolation forest, Z-score, or statistical profiling)
- `usaf scan --anomaly-detect` flags deviations from learned patterns
- Lowers false positives by learning what "normal" means for this specific system

---

## Architectural Principles (Always Enforce)

### Interface Stability
Every integration point must be an abstract interface:

```
core/interfaces.py  ←  AuditCheckInterface, CollectorInterface, ReporterInterface, etc.
```

New components (correlation, baseline, LLM, etc.) follow the same pattern: define interface in `core/interfaces.py`, implement in their own directory.

### No Circular Dependencies
```
Core → Models ← everything else
```
This is already enforced. Maintain it.

### Determinism
Same system → same output (modulo timestamps which are explicit metadata). Critical for:
- Baseline comparisons
- CI/CD integration
- Regression testing
- Golden file tests

### Collectors Never Analyze, Checks Never Collect
Already enforced. The correlation engine is the one exception — it analyzes analysis results. This is acceptable because:
- Correlation rules receive findings (not raw data)
- Correlation output is additional findings (same type as check output)
- Correlation doesn't collect data

### Evidence Is Mandatory
If a check returns a finding without evidence, it should log a warning and the finding should have `confidence=LOW` automatically.

---

## Technical Debt Log

| ID | Description | Severity | Entered |
|----|-------------|----------|---------|
| TD-001 | `metadata.configuration_file` is set to `scan_name` instead of actual config path (`runner.py:71`) | LOW | |
| TD-002 | `metadata.end_time` is set to `scan_start_dt` instead of actual end time (`runner.py:132`) | LOW | |
| TD-003 | No integration tests — collectors can break without test failures | MEDIUM | |
| TD-004 | Scoring engine ignores confidence and false_positive_probability | HIGH | |
| TD-005 | Collectors hardcoded in runner.py instead of auto-discovered | MEDIUM | |
| TD-006 | No parallel execution despite `parallel=True` in config | LOW | |
| TD-007 | `mypy --strict` likely fails — never run in CI | MEDIUM | |

---

## Decision Records Index

| ADR | Title | Status |
|-----|-------|--------|
| 001 | Project Goals and Scope | ✅ |
| 002 | Architecture Overview | ✅ |
| 003 | Plugin System | ✅ |
| 004 | Finding Model | ✅ |
| 005 | Collector Architecture | ✅ |
| 006 | Scoring Engine | ◐ (needs update for confidence) |
| 007 | Reporting Framework | ✅ |
| 008 | Configuration Management | ✅ |

---

## Quick Reference: Where Code Lives

```
src/usaf/
├── cli/app.py                 # Typer CLI — 3 commands
├── core/
│   ├── interfaces.py          # All ABCs (6 interfaces)
│   ├── plugin.py              # AuditCheck base class
│   ├── registry.py            # Plugin registry singleton
│   └── runner.py              # ScanRunner orchestrator
├── models/
│   ├── evidence.py            # 8 evidence types
│   ├── finding.py             # Finding model (24 fields)
│   ├── severity.py            # Severity, Confidence, CheckCategory enums
│   ├── result.py              # CheckResult, ScanResult, ScanMetadata
│   ├── score.py               # ScanScore, CategoryScore
│   └── references.py          # CVE, CIS, MITRE, OWASP models
├── collectors/                # 11 collectors
├── checks/                    # 13 checks
├── reporting/                 # 3 reporters
├── scoring/engine.py          # Scoring engine
├── config/                    # YAML config loading
└── cache/engine.py            # In-memory cache
```

---

## Metrics & Targets

| Metric | Current | Target | By |
|--------|---------|--------|----|
| Checks | 13 | 25+ | Phase 2 end |
| Collectors | 11 | 20+ | Phase 2 end |
| Test coverage | ~40% (estimated) | 85%+ | Phase 1 end |
| CI pipeline | None | Green on push | Phase 1 end |
| False positive rate (SUID) | ~80% | <10% | P1-2 |
| Confidence scoring | Not applied | Applied | P1-1 |
| Integration tests | 0 | 15+ | Phase 1 end |
| Correlation rules | 0 | 4+ | Phase 2 end |
| Baseline support | Stub only | Full + timeline | Phase 2 end |
| Remote scanning | None | SSH transport | Phase 4 |
| LLM integration | None | Ollama + agent | Phase 5 |

---

## How to Add a New Check (Updated)

```python
# src/usaf/checks/<category>/my_check.py
from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class MyCheck(AuditCheck):
    id = "MYC-001"
    name = "My Security Check"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Verifies that something is configured correctly"
    depends = ["kernel_params"]          # Collector dependencies
    tags = ["hardening"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        actual = params.get("some.key", "")
        if actual != "expected":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Something is misconfigured",
                    description=f"Found {actual!r}, expected 'expected'",
                    rationale="Why this matters for security",
                    remediation="How to fix it",
                    evidence=FileEvidence(path="/proc/sys/some/key", content=actual),
                    detected_value=actual,
                    expected_value="expected",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 22.04: 1.2.3"],
                    mitre_attack_ids=["T1548"],
                    tags=["hardening"],
                )
            )
        return findings
```

No need to touch `__init__.py` if auto-discovery is implemented (P1-4).

---

## Contributing to This Document

This is a living document. Update it when:
- A Phase 1-5 item is completed (move to ✅, note date)
- A new architectural decision is made (create ADR, add to index)
- Technical debt is discovered (add to TD log)
- Targets are met or change (update Metrics & Targets)
