# ADR 008: Configuration Management

## Status
Accepted

## Context
Security auditing requires flexible configuration. Different environments have different policies. Some findings need severity overrides. Some checks need to be disabled. Baselines enable drift detection. All of this must be manageable without code changes.

## Decision

### Configuration Sources (ordered by priority)

1. CLI flags (highest)
2. Environment variables
3. User config file (`~/.config/usaf/config.yaml`)
4. Project config file (`./usaf.yaml`)
5. Default configuration (lowest)

### Configuration Model

```yaml
# usaf.yaml
general:
  scan_name: "production-scan-2026-07-11"
  parallel: true
  max_workers: 8
  timeout: 300
  cache: true
  cache_dir: ~/.cache/usaf

plugins:
  enabled: ["*"]           # Enable all, or list specific
  disabled: []             # Explicitly disable
  overrides:
    SSH-101:
      severity: HIGH       # Override default severity
      enabled: true

severity:
  CRITICAL: 10.0
  HIGH: 7.5
  MEDIUM: 5.0
  LOW: 2.5
  INFO: 0.0

ignore:
  - SSH-101-003           # Ignore specific findings
  - "SSH-*"               # Glob patterns supported

baseline:
  path: /etc/usaf/baseline.json
  compare: true
  fail_on_drift: false

reporting:
  format: terminal
  verbose: false
  output: /tmp/report.md
  sections: [summary, findings, remediation]

policies:
  - name: server-hardening
    path: policies/server-hardening.yaml
```

### Baselines

- JSON snapshot of a "known good" state
- Stores finding IDs, expected values, timestamps
- Comparison detects drift (new users, ports, services, etc.)
- Diff output highlights what changed

## Consequences
- Environment-specific policies without code changes
- CI/CD pipelines define policy in repository
- Severity overrides for organizational priorities
- Baseline comparison enables continuous compliance
- Glob patterns make ignore lists manageable
