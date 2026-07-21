# USAF Multi-Distro Portability Report

> **Context:** USAF is published as a Snap package. Snaps can be installed on any Linux
> distribution with `snapd` support. This report identifies the platform families we must
> support and the changes needed to port USAF beyond Ubuntu.

---

## 1. Platforms We Must Support

| Family | Distros | Package Mgr | Default Firewall | MAC System |
|--------|---------|-------------|-----------------|------------|
| **Debian** | Ubuntu, Debian, Pop!_OS, Mint, Kali | `apt`/`dpkg` | ufw (Ubuntu) / nftables (Debian) | AppArmor |
| **RHEL** | Fedora, RHEL, CentOS, Rocky, Alma | `dnf`/`rpm` | firewalld | SELinux |
| **Arch** | Arch, Manjaro, EndeavourOS | `pacman` | nftables / iptables | None / AppArmor |
| **SUSE** | openSUSE, SLES | `zypper`/`rpm` | firewalld | AppArmor |

---

## 2. What Stays (Fully Portable)

All of these contain **zero OS-specific code** and run unchanged on any Linux:

- Core engine: interfaces, plugin base, registry, runner orchestration
- All models: Finding, CheckResult, ScanResult, evidence types
- Scoring engine (pure math)
- Reporting: terminal, JSON, Markdown
- Correlation engine, baselines, compliance evaluator, profiles
- Cache engine, configuration system, knowledge base
- SecretsCollector (regex-based, no OS calls)
- ContainerCollector (Docker/Podman — cross-platform)
- SudoCollector, UserCollector, GroupCollector (POSIX-standard)
- Kernel hardening checks (sysctl via `/proc/sys` — Linux-generic)
- Permission checks (SUID, capabilities, world-writable — syscall-based)
- Network socket checks (procfs — Linux-generic)
- Compromise detection checks (process analysis — Linux-generic)

---

## 3. What Needs Changing

### 3.1 Distro Detection Layer — new file

Read `/etc/os-release` and build a `SystemProfile` object consumed by all downstream
components. This single source of truth drives every platform decision.

**Fields:**
- `distro_id`: `"ubuntu"`, `"debian"`, `"fedora"`, `"rhel"`, `"arch"`, `"opensuse"`
- `distro_family`: `"debian"`, `"rhel"`, `"arch"`, `"suse"`
- `package_manager`: `"apt"`, `"dnf"`, `"pacman"`, `"zypper"`
- `firewall`: `"ufw"`, `"firewalld"`, `"nftables"`, `"iptables"`
- `mac_system`: `"apparmor"`, `"selinux"`, `"none"`

### 3.2 Package Manager Abstraction — ~3 new files, 1 refactor

**Problem:** `APTCollector` + `get_package_for_file()` are Debian-locked. 14+ checks
call `dpkg`, `apt-get`, `apt-mark` directly.

**Solution:** `PackageManager` ABC with common methods, then platform impls:

| Implementation | Target | Status |
|----------------|--------|--------|
| `AptPackageManager` | Debian family | Wraps existing `APTCollector` |
| `DnfPackageManager` | RHEL family | New |
| `PacmanPackageManager` | Arch family | New |
| `ZypperPackageManager` | SUSE family | New |

**Files affected:** `collectors/packages/apt.py`, `collectors/packages/resolver.py`,
`checks/packages/*.py` (6 files)

### 3.3 Remediation Command Templating — ~30 check files

**Problem:** 84 occurrences of `"apt install"`, `"apt-get"`, `"add-apt-repository"`,
`"dpkg -S"`, `"dpkg --verify"` hardcoded in check finding remediation strings.

**Solution:** `DistroContext` class passed to every check. Key template variables:

| Template Var | Debian | RHEL | Arch | SUSE |
|---|---|---|---|---|
| `{pkg_install}` | `apt install` | `dnf install` | `pacman -S` | `zypper install` |
| `{pkg_remove}` | `apt purge` | `dnf remove` | `pacman -Rns` | `zypper rm` |
| `{pkg_verify}` | `dpkg --verify` | `rpm -V` | `pacman -Qk` | `rpm -V` |
| `{pkg_owner}` | `dpkg -S` | `rpm -qf` | `pacman -Qo` | `rpm -qf` |
| `{pkg_update}` | `apt update` | `dnf check-update` | `pacman -Sy` | `zypper refresh` |
| `{grub_update}` | `update-grub` | `grub2-mkconfig -o /boot/grub2/grub.cfg` | `grub-mkconfig -o /boot/grub/grub.cfg` | `grub2-mkconfig -o /boot/grub2/grub.cfg` |

**Files affected:** All check files with remediation strings (~30+ files)

### 3.4 Firewalld Collector — new file

**Problem:** `FirewallCollector` checks ufw, nftables, iptables. No firewalld support,
but RHEL/Fedora/SUSE use firewalld as their default.

**Solution:** Add `firewalld` detection via `firewall-cmd --state`. Existing nftables
and iptables fallbacks still serve as secondary checks.

**Files affected:** `collectors/security/firewall.py`

### 3.5 SELinux Checks — 1-2 new files

**Problem:** AppArmor checks (SEC-101 through SEC-208) will fire false positives on
RHEL/Fedora where SELinux is the default MAC system and AppArmor is absent.

**Solution:** Add SELinux status checks. Auto-select based on detected MAC system so
the right checks run and the wrong ones are silently skipped.

**Files affected:** New checks under `checks/security/`

### 3.6 Distro-Aware Allowlists — ~5 check files

**Problem:** `KNOWN_SAFE_SERVICES`, `KNOWN_SAFE_REPOS`, `RISKY_PACKAGES`, and similar
lists hardcode Ubuntu-specific entries (`whoopsie`, `apport`, `netplan-configure`,
`snapd`, `ubuntu-desktop`, `archive.ubuntu.com`).

**Solution:** Make allowlists distro-aware. For example, `ubuntu-desktop` should not
be flagged as "suspicious" on a Fedora system where it wouldn't exist anyway.

**Files affected:** `checks/services/service_checks.py`, `checks/packages/unnecessary_packages.py`,
`checks/packages/integrity_checks.py`, `checks/packages/package_security_checks.py`,
`checks/users/identity_checks.py`

### 3.7 Boot Path Tweaks — 1 file

**Problem:** `mokutil` is Ubuntu-specific (shim/MOK). `update-grub` is Debian-specific.
GRUB config paths differ.

**Solution:** Already partial coverage (`/boot/grub/` vs `/boot/grub2/`). Add
distro-aware dispatch for `mokutil` (graceful fail on other distros — already works
via `subprocess` exception handling). Template `update-grub` via remediation system.

**Files affected:** `collectors/system/boot.py`, `checks/boot/boot_checks.py`

### 3.8 CIS Benchmark References — no change needed

`CIS Ubuntu 20.04:` references in findings are correct. CIS benchmarks are
distro-specific by design. No change required.

---

## 4. Summary of Changes

| Component | New Files | Files Modified | Effort |
|-----------|-----------|----------------|--------|
| Distro detection | 1 | 0 | Small |
| Package manager abstraction | 3 | 7 | Medium |
| Remediation templating | 0 | ~30 | Large (mechanical) |
| Firewalld collector | 0 | 1 | Small |
| SELinux checks | 1-2 | 0 | Medium |
| Service allowlists | 0 | 5 | Small |
| Boot paths | 0 | 2 | Trivial |

**Totals:** ~5 new files, ~35 modified files. Estimated 2-3 days of focused work.

---

## 5. Design Recommendation

Create a **`SystemProfile`** singleton built at scan startup. All collectors and checks
reference it. Collectors use it to select implementation; checks use it to format
remediation strings. No changes to the core architecture needed.

The profile is derived from `/etc/os-release`:

```
ID=ubuntu          → family=debian,  pkg=apt,    fw=ufw,        mac=apparmor
ID=debian          → family=debian,  pkg=apt,    fw=nftables,   mac=apparmor
ID=fedora          → family=rhel,    pkg=dnf,    fw=firewalld,  mac=selinux
ID=rhel            → family=rhel,    pkg=dnf,    fw=firewalld,  mac=selinux
ID=arch            → family=arch,    pkg=pacman, fw=nftables,   mac=none
ID=opensuse-tumbleweed → family=suse, pkg=zypper, fw=firewalld, mac=apparmor
```

---

## 6. Non-Goals (Out of Scope)

- BSD/macOS support (Snap doesn't run on these)
- Real-time monitoring
- Windows support
