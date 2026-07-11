DEFAULT_CONFIG_YAML = """# USAF - Ubuntu Security Audit Framework
# Default configuration file

general:
  scan_name: usaf-scan
  parallel: true
  max_workers: 8
  timeout: 300
  cache: true
  cache_dir: ~/.cache/usaf
  offline: false

plugins:
  enabled: ["*"]
  disabled: []
  overrides: {}

severity:
  CRITICAL: 10.0
  HIGH: 7.5
  MEDIUM: 5.0
  LOW: 2.5
  INFO: 0.0

ignore: []

baseline:
  path: null
  compare: false
  fail_on_drift: false
  auto_baseline: false

reporting:
  format: terminal
  verbose: false
  output: null
  sections:
    - summary
    - findings
    - remediation
  color: true
  show_passed: false

policies: []

# Phase 2: Professional-Grade Features
correlation:
  enabled: true
  rules: ["*"]

severity_context:
  enabled: true
  rules: {}

compliance:
  enabled: false
  frameworks:
    - cis

profile:
  name: null
  auto_detect: true
  path: null

# SUID binaries to consider expected (beyond the built-in allowlist)
# Add paths here to suppress false positives for legitimate SUID binaries
# installed by packages like virtualbox, docker, flatpak, etc.
suid_allowlist: []
"""
