# USAF Validation Lab

Reproducible, known-vulnerable Ubuntu VMs for validating USAF detection accuracy.

## Prerequisites

```bash
sudo apt install vagrant virtualbox
vagrant plugin install vagrant-scp  # optional
```

## Quick Start

```bash
# List available scenarios
python3 run.py list

# Provision and validate a scenario
python3 run.py run insecure-server

# Provision only (skip validation)
python3 run.py provision insecure-server

# Validate an already-provisioned VM
python3 run.py validate insecure-server

# Destroy a VM
python3 run.py destroy insecure-server

# Run all scenarios
python3 run.py run-all
```

## Scenarios

| Scenario | Vulnerabilities | Targets |
|----------|----------------|---------|
| `insecure-server` | 15+ (SSH, kernel, firewall, packages, passwords) | SSH-*, KERN-*, FW-*, PKG-*, PWD-*, NET-* |
| `backdoored-host` | 15+ (SUID, cron, LD_PRELOAD, systemd, reverse shell) | PRM-*, PER-*, COM-*, FS-*, NET-* |
| `container-escape` | 10+ (Docker socket, privileged containers, host mounts) | CTN-*, PRM-*, SVC-* |
| `secrets-exposed` | 10+ (AWS keys, .env, SSH keys, DB creds, tokens) | SECR-*, FS-*, USR-* |
| `desktop-insecure` | 10+ (legacy services, weak auth, world-writable PATH) | CMP-*, PWD-*, PRM-*, FW-*, SVC-* |

## Validation Metrics

| Metric | Target |
|--------|--------|
| Detection rate | >90% |
| False negatives per scenario | < 3 |
| False positives per scenario | < 5 |
