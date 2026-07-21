# USAF Validation Lab

Reproducible, known-vulnerable Ubuntu VMs for validating USAF detection accuracy.
Uses KVM/libvirt with cloud-init for fast, scriptable VM provisioning.

## Prerequisites

```bash
sudo apt install qemu-system-x86 libvirt-daemon-system virt-install cloud-image-utils
sudo adduser $USER libvirt
# Log out and back in for group change to take effect
```

## Quick Start

```bash
# List available scenarios
python3 run.py list

# Provision and validate a scenario (creates VM, applies vulns, scans, validates, destroys)
python3 run.py run insecure-server

# Create VM and apply vulnerabilities only
python3 run.py provision insecure-server

# Validate an already-provisioned VM (install USAF + scan + compare)
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

## How It Works

1. **`up()`** — Downloads Ubuntu 24.04 Noble cloud image, creates a cloud-init seed ISO with SSH key injection, launches VM via `virt-install`
2. **`provision()`** — Uploads vulnerability scripts via SCP, runs `provision.sh` to introduce known security issues
3. **`install_usaf()`** — Installs USAF from GitHub on the VM
4. **`run_scan()`** — Executes `usaf scan --format json` via SSH
5. **`validate()`** — Compares findings against `expected.yaml` manifest
6. **`destroy()`** — `virsh destroy + undefine`, removes disk image

## Adding a Scenario

1. Create `scenarios/<name>/` directory
2. Write a `scenario.py` with a class extending `BaseScenario`
3. Write `provision.sh` that applies vulnerabilities
4. Write `expected.yaml` with the list of findings USAF should detect
