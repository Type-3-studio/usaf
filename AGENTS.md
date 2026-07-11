# USAF: AI / Coding Agent Guide

This document helps AI coding agents (OpenCode, Claude Code, Codex CLI, Gemini CLI, Cursor, etc.) work effectively with the Ubuntu Security Audit Framework (USAF).

## Project Overview

USAF is a production-grade security auditing framework for Ubuntu Linux. It uses a modular plugin architecture where every audit is a plugin. The framework separates data collection (collectors) from analysis (checks) and reporting (reporters).

## Quick Start for Agents

```bash
# Install dependencies
uv pip install -e ".[dev]"

# Run all checks
usaf scan

# Run specific checks
usaf scan --checks SSH-101 KERN-101

# Output as JSON
usaf scan --format json

# List available checks
usaf list-checks

# Initialize config
usaf init
```

## Repository Structure

```
usaf/
├── ADR/                        # Architecture Decision Records
├── src/usaf/
│   ├── cli/                    # Typer CLI interface
│   ├── config/                 # YAML configuration management
│   ├── core/                   # Plugin system, registry, runner
│   ├── models/                 # Pydantic data models (finding, evidence)
│   ├── collectors/             # Data gathering layer
│   │   ├── system/             #   Kernel, boot, hardware
│   │   ├── network/            #   Sockets, interfaces, DNS
│   │   ├── users/              #   Passwd, shadow, groups, sudo
│   │   ├── packages/           #   APT, dpkg, snap
│   │   ├── processes/          #   /proc parsing
│   │   └── services/           #   systemd, cron
│   ├── checks/                 # Security check plugins
│   │   ├── system/             #   SSH, kernel, boot
│   │   ├── users/              #   Accounts, permissions
│   │   ├── network/            #   Ports, interfaces
│   │   ├── permissions/        #   SUID, world-writable
│   │   ...                     #   (extend here)
│   ├── parsers/                # Configuration parsers
│   ├── reporting/              # Terminal, JSON, Markdown
│   ├── scoring/                # Risk scoring engine
│   └── cache/                  # In-memory caching
├── tests/
│   ├── unit/                   # Unit tests
│   ├── integration/            # Integration tests
│   └── golden/                 # Golden report tests
└── policies/                   # YAML policies
```

## How to Add a New Security Check

The goal is **zero modifications to core code**. You only need to create one file.

### Step 1: Create the check file

```python
# src/usaf/checks/<category>/my_check.py
from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class MyNewCheck(AuditCheck):
    id = "MYC-101"          # Use sub-ranged ID: 100-level for first sub-category
    name = "My Security Check"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "What this check verifies"
    depends = ["kernel_params"]          # Collector dependencies
    tags = ["my-tag"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        actual = params.get("some.key", "")
        if actual != "expected":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Descriptive title",
                    description=f"Found {actual!r}, expected 'expected'",
                    rationale="Why this matters for security",
                    remediation="How to fix it",
                    evidence=RegistryEvidence(
                        key="some.key",
                        value=actual,
                        expected="expected",
                        source="/proc/sys/some/key",
                    ),
                    detected_value=actual,
                    expected_value="expected",
                    affected_component="kernel",
                    mitre_attack_ids=["T1xxx"],
                    tags=["hardening"],
                )
            )
        return findings
```

### Step 2: Import in `__init__.py`

```python
# src/usaf/checks/__init__.py (or category __init__.py)
from usaf.checks.system import my_check
```

### Check ID Numbering Scheme

All check IDs use sub-ranged format `<PREFIX>-<SUBRANGE><SEQ>`. Each prefix has reserved 100-level blocks:

| Prefix | Range | Sub-ranges | Example |
|--------|-------|------------|---------|
| SSH | 100–999 | 100=Auth, 200=Algorithms, 300=Keys, 400=Logging, 500=Network, 600=Compliance | SSH-101 |
| KERN | 100–999 | 100=Memory, 200=Pointers, 300=Core dumps, 400=Modules/BPF | KERN-101 |
| USR | 100–999 | 100=Account integrity, 200=Weak creds, 300=Policy, 400=Privilege, 500=SSH keys | USR-101 |
| NET | 100–999 | 100=Ports, 200=Interfaces, 300=DNS, 400=Kernel net, 500=Wireless, 600=TLS/Certs | NET-101 |
| PKG | 100–999 | 100=Unnecessary, 200=Integrity, 300=Repos, 400=CVEs, 500=Held | PKG-101 |
| FS | 100–999 | 100=File integrity, 200=Hidden/orphan, 300=Mounts, 400=Symlinks, 500=Capabilities | FS-101 |
| BOOT | 100–999 | 100=Secure Boot, 200=Lockdown, 300=EFI, 400=GRUB, 500=Kernel images | BOOT-101 |
| SVC | 100–999 | 100=Enabled, 200=Security, 300=Listening, 400=Failed, 500=Modified | SVC-101 |
| PER | 100–999 | 100=Cron, 200=Systemd, 300=Shell init, 400=LD injection, 500=Kernel, 600=Network, 700=Hooks | PER-201 |
| CTN | 100–999 | 100=Socket, 200=Privileges, 300=Security, 400=Images, 500=Runtime, 600=LXC | CTN-101 |
| LOG | 100–999 | 100=Journal, 200=Rotation, 300=Tamper, 400=Auth fail, 500=Auditd | LOG-101 |
| SECR | 100–999 | 100=Cloud creds, 200=Code secrets, 300=Crypto keys, 400=DB/API, 500=Certs | SECR-101 |
| FW | 100–999 | 100=Status, 200=Rules, 300=Defaults, 400=Logging | FW-101 |
| CMP | 100–999 | 100=Version, 200=CIS, 300=STIG, 400=Regulatory, 500=Custom | CMP-101 |
| COM | 100–999 | 100=Processes, 200=Network IOC, 300=Filesystem IOC | COM-101 |
| PRM | 100–999 | 100=SUID, 200=World-writable, 300=Capabilities, 400=Ownership | PRM-101 |

Always use the correct sub-range for new checks. See `STATE.md` for the full ID map.

### Step 3: Run it

```bash
usaf scan --checks MYC-101
```

## How to Add a New Collector

```python
# src/usaf/collectors/<category>/my_collector.py
from usaf.collectors.base import BaseCollector


class MyCollector(BaseCollector):
    name = "my_data"
    description = "Gathers specific data"
    depends = []            # Other collectors this needs

    def _do_collect(self) -> dict:
        return {
            "key1": "value1",
            "key2": ["a", "b"],
        }
```

Then register it in `ScanRunner._setup_collectors()` in `src/usaf/core/runner.py`.

## Design Rules

1. **Collectors never analyze.** They gather data, return dicts.
2. **Checks never collect.** They analyze, return findings.
3. **Reporters never analyze.** They format findings.
4. **No circular dependencies.** Core -> Models <- everything else.
5. **Every finding must have evidence.** No evidence = no finding.
6. **Every finding must explain WHY it matters.** Context is mandatory.
7. **Use Python APIs over shell.** Use `os.stat()`, not `ls`. Use `/proc`, not `ps`.
8. **Never parse `ls` output.** Never parse human-readable `ps`.
9. **Minimize subprocess calls.** Collectors run once. Checks reuse data.
10. **False positive reduction is priority.** Default behavior is not a finding.

## Key Principles

### Findings Must Be:
- **ID'd**: Unique, check-specific ID (e.g., `SSH-101-001`)
- **Evidenced**: Include the actual bad line/permission/process
- **Justified**: Explain the threat model and exploit scenario
- **Remediated**: Provide exact commands to fix
- **Mapped**: CIS, MITRE ATT&CK, CVE where applicable
- **Confidence-rated**: HIGH/MEDIUM/LOW with false positive probability

### Performance:
- One subprocess call per collector, not per check
- `/proc` parsing preferred over command execution
- Cache expensive operations with `CacheEngine`
- Parallel execution planned via `concurrent.futures`

## Testing

```bash
# Run all tests
pytest

# Unit tests only
pytest tests/unit

# Specific test file
pytest tests/unit/checks/test_kernel_checks.py -v

# With coverage
pytest --cov=usaf

# Integration tests (requires root or Docker)
pytest tests/integration
```

## Code Quality

```bash
# Type checking
mypy src/usaf

# Linting
ruff check src/usaf

# Formatting
ruff format src/usaf
```

## Adding Compliance Mappings

When adding CIS, MITRE ATT&CK, or OWASP mappings to findings:

- **CIS**: Use format `CIS Ubuntu 20.04: <section>.<subsection>` (e.g., `CIS Ubuntu 20.04: 5.2.2`)
- **MITRE ATT&CK**: Use technique IDs like `T1548.001` (not just `T1548`)
- **OWASP**: Use top-level IDs like `A1:2017-Injection`
- **CVE**: Use full CVE ID (`CVE-2024-12345`)

## Architecture Decision Records

See `ADR/` directory for major design decisions:
- `001-project-goals-and-scope.md`
- `002-architecture-overview.md`
- `003-plugin-system.md`
- `004-finding-model.md`
- `005-collector-architecture.md`
- `006-scoring-engine.md`
- `007-reporting-framework.md`
- `008-configuration-management.md`

## Working with the Codebase

### Understanding a Check Plugin
Start with `src/usaf/checks/` — find the check by ID or category. Every check:
1. Defines `id`, `name`, `category`, `severity`, `description`
2. Lists `depends` (collector names)
3. Implements `_run_check()` that returns `list[Finding]`
4. Uses `self.finding()` to create structured findings with evidence

### Understanding Data Flow
1. CLI (`cli/app.py`) creates `ScanRunner`
2. `ScanRunner.run()` calls collectors to gather data
3. Collectors return `dict[str, Any]` via `CollectorManager`
4. Registry resolves check dependencies
5. Each check receives collector data and returns `CheckResult`
6. Scoring engine computes `ScanScore`
7. Reporter formats the output

### Debugging
```bash
usaf scan --verbose           # See progress and collector output
usaf scan --checks SSH-101    # Run one check in isolation
usaf scan --format json       # Structured output for inspection
```

## Adding a New Check Checklist

- [ ] Does the check have a unique ID?
- [ ] Does every finding include evidence?
- [ ] Does every finding explain WHY it matters?
- [ ] Is the confidence level appropriate?
- [ ] Is the false positive probability estimated?
- [ ] Are MITRE/CIS/OWASP mappings included where applicable?
- [ ] Is the remediation actionable (includes commands)?
- [ ] Does the check depend on the right collectors?
- [ ] Are tags relevant and consistent?
- [ ] Is there a unit test?

## Common Mistakes to Avoid

- ❌ Adding findings for default Ubuntu behavior (expected configurations)
- ❌ Running subprocess commands inside a check (use collectors)
- ❌ Returning findings without evidence
- ❌ Using vague descriptions like "SSH is misconfigured"
- ❌ Suggesting remediations without specific commands
- ❌ Setting confidence to HIGH for probabilistic detections
- ❌ Forgetting to update `__init__.py` imports
- ❌ Using `ls`, `ps`, `ifconfig` output parsing

## Future Extensibility Points

The framework is designed for these future additions without core changes:
- **Remote scanning**: SSH-based collector transport
- **Agent mode**: Daemon with periodic scanning
- **Web dashboard**: FastAPI backend reading JSON reports
- **Distributed deployments**: Central collector aggregation
- **Plugin marketplace**: Community check repository
- **Real-time monitoring**: Inotify/fanotify collectors

## STATE.md — Mandatory Update Rule

**Every agent that modifies the codebase MUST update STATE.md to match reality.**

STATE.md (`STATE.md`) is the single source of truth for project status. It tracks:
- What's implemented vs. stubbed vs. not started
- Check/collector/module counts
- Technical debt status
- Test coverage status
- Version number

### When to update STATE.md:
1. **A new check/collector/module is added** — update the count and status table
2. **A feature is completed** — move from ◐/🔴 to ✅
3. **Technical debt is resolved** — update TD log
4. **The version changes** — update the version field
5. **Any claim in the document becomes false** — fix it immediately

### How to update:
- Read STATE.md first before making changes
- After implementing, update the relevant sections
- If unsure about a status, verify against the actual code (don't guess)
- Commit STATE.md changes alongside the code changes

## Need Help?

- Check existing checks in `src/usaf/checks/` for patterns
- Check existing collectors in `src/usaf/collectors/` for API usage
- Read ADRs in `ADR/` for design rationale
- Check `tests/` for test patterns
