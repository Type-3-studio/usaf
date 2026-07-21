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

#### Collectors (26 total)
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
| `FlatpakCollector` | ✅ | Flatpak app/runtime inventory, file→package resolution |
| `SecretsCollector` | ✅ | Credential scanning: AWS/GCP keys, GitHub tokens, API keys, .env files, DB creds |
| `SnapCollector` | ✅ | Snap package inventory, file→package resolution |
| `CloudMetadataCollector` | ✅ | Cloud provider detection, IMDS, agents, K8s, credentials (P6) |

#### Checks (389 total)
| Check | Status | Severity | Evidence |
|-------|--------|----------|----------|
| KERN-101 (ASLR) | ✅ | HIGH | RegistryEvidence |
| KERN-201 (Pointer Restriction) | ✅ | MEDIUM | RegistryEvidence |
| KERN-301 (Core Dump) | ✅ | MEDIUM | RegistryEvidence |
| KERN-401 (Module Loading) | ✅ | MEDIUM | RegistryEvidence |
| KERN-151 (TTY Ldisc Autoload) | ✅ | LOW | RegistryEvidence |
| KERN-251 (Ptrace Scope) | ✅ | MEDIUM | RegistryEvidence |
| KERN-351 (Core Dump PID) | ✅ | LOW | RegistryEvidence |
| KERN-451 (Unprivileged BPF) | ✅ | MEDIUM | RegistryEvidence |
| KERN-511 (Link Protections) | ✅ | MEDIUM | RegistryEvidence |
| KERN-512 (Special File Protections) | ✅ | MEDIUM | RegistryEvidence |
| KERN-513 (Userfaultfd) | ✅ | MEDIUM | RegistryEvidence |
| KERN-514 (mmap Min Addr) | ✅ | MEDIUM | RegistryEvidence |
| KERN-152 (Console Log Level) | ✅ | LOW | RegistryEvidence |
| KERN-252 (Ctrl-Alt-Del) | ✅ | LOW | RegistryEvidence |
| KERN-352 (SysRq Key) | ✅ | MEDIUM | RegistryEvidence |
| KERN-452 (Kexec Disabled) | ✅ | MEDIUM | RegistryEvidence |
| KERN-552 (Perf Event Paranoid) | ✅ | MEDIUM | RegistryEvidence |
| KERN-652 (Boot Security Params) | ✅ | MEDIUM | RegistryEvidence |
| KERN-752 (Module Signing) | ✅ | MEDIUM | RegistryEvidence |
| KERN-852 (IOMMU Protection) | ✅ | LOW | RegistryEvidence |
| KERN-901 (ASLR Effectiveness) | ✅ | LOW | RegistryEvidence |
| KERN-902 (Debug Filesystem) | ✅ | MEDIUM | RegistryEvidence |
| KERN-903 (Module Blacklist) | ✅ | MEDIUM | RegistryEvidence |
| KERN-904 (SysRq Restriction) | ✅ | LOW | RegistryEvidence |
| SSH-101 (Protocol) | ✅ | HIGH | RegistryEvidence |
| SSH-102 (Root Login) | ✅ | HIGH | RegistryEvidence |
| SSH-103 (MaxAuthTries) | ✅ | HIGH | RegistryEvidence |
| SSH-104 (Empty Passwords) | ✅ | CRITICAL | RegistryEvidence |
| SSH-105 (ClientAlive Timeout) | ✅ | MEDIUM | RegistryEvidence |
| SSH-106 (Banner) | ✅ | LOW | RegistryEvidence |
| SSH-107 (PermitUserEnvironment) | ✅ | MEDIUM | RegistryEvidence |
| SSH-108 (MaxStartups) | ✅ | MEDIUM | RegistryEvidence |
| SSH-109 (HostbasedAuthentication) | ✅ | HIGH | RegistryEvidence |
| SSH-201 (KEX Algorithms) | ✅ | MEDIUM | RegistryEvidence |
| SSH-202 (Ciphers) | ✅ | MEDIUM | RegistryEvidence |
| SSH-301 (Host Key Type) | ✅ | MEDIUM | RegistryEvidence |
| SSH-302 (Authorized Keys Perms) | ✅ | HIGH | RegistryEvidence |
| SSH-401 (LogLevel) | ✅ | LOW | RegistryEvidence |
| SSH-501 (X11Forwarding) | ✅ | MEDIUM | RegistryEvidence |
| SSH-502 (TcpForwarding) | ✅ | MEDIUM | RegistryEvidence |
| SSH-503 (Compression) | ✅ | LOW | RegistryEvidence |
| SSH-504 (PermitTunnel) | ✅ | MEDIUM | RegistryEvidence |
| SSH-505 (GSSAPIAuth) | ✅ | LOW | RegistryEvidence |
| SSH-601 (SSH MAC Algorithms) | ✅ | MEDIUM | RegistryEvidence |
| SSH-602 (SSH Host Key Strength) | ✅ | MEDIUM | RegistryEvidence |
| SSH-603 (SSH Agent Forwarding) | ✅ | MEDIUM | RegistryEvidence |
| SSH-604 (SSH Pubkey Auth Only) | ✅ | HIGH | RegistryEvidence |
| SSH-605 (SSH Port) | ✅ | LOW | RegistryEvidence |
| SSH-606 (SSH Session Termination) | ✅ | MEDIUM | RegistryEvidence |
| USR-101 (Duplicate UID 0) | ✅ | CRITICAL | UserEvidence |
| USR-102 (Shadowed Passwords) | ✅ | HIGH | RegistryEvidence |
| USR-103 (Duplicate UIDs) | ✅ | HIGH | UserEvidence |
| USR-104 (Disabled Accts w/ Shell) | ✅ | MEDIUM | UserEvidence |
| USR-105 (Expired Passwords) | ✅ | MEDIUM | UserEvidence / RegistryEvidence |
| USR-201 (Empty Passwords) | ✅ | CRITICAL | UserEvidence |
| USR-202 (Password Reuse Policy) | ✅ | MEDIUM | RegistryEvidence |
| USR-301 (MFA Status) | ✅ | HIGH | RegistryEvidence |
| USR-401 (Unauthorized Sudo) | ✅ | HIGH | RegistryEvidence |
| USR-402 (Sudo Password Enforcement) | ✅ | HIGH | RegistryEvidence |
| USR-403 (Sudo Timestamp Timeout) | ✅ | MEDIUM | RegistryEvidence |
| USR-404 (Sudo Logging Configuration) | ✅ | MEDIUM | RegistryEvidence |
| USR-501 (Service Accounts With Shell) | ✅ | MEDIUM | UserEvidence |
| USR-502 (Users in Privileged Groups) | ✅ | HIGH | UserEvidence |
| USR-503 (Inactive User Accounts) | ✅ | MEDIUM | UserEvidence |
| USR-504 (Non-Standard Home Dirs) | ✅ | LOW | UserEvidence |
| USR-505 (Empty Groups) | ✅ | LOW | RegistryEvidence |
| USR-506 (Duplicate Group Entries) | ✅ | HIGH | RegistryEvidence |
| USR-507 (UID-GID Mismatch) | ✅ | MEDIUM | UserEvidence |
| USR-508 (World-Readable SSH Dirs) | ✅ | HIGH | FileEvidence |
| NET-101 (Listening Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-201 (Promiscuous Mode) | ✅ | MEDIUM | NetworkEvidence |
| NET-301 (Unexpected DNS) | ✅ | MEDIUM | NetworkEvidence / RegistryEvidence |
| NET-302 (Modified Hosts) | ✅ | MEDIUM | RegistryEvidence |
| NET-401 (Weak Net Sysctl) | ✅ | MEDIUM | RegistryEvidence |
| NET-402 (IPv6 Hardening) | ✅ | MEDIUM | RegistryEvidence |
| NET-501 (DNSSEC Validation) | ✅ | MEDIUM | RegistryEvidence |
| NET-102 (Exposed Sensitive Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-202 (Interface Carrier) | ✅ | LOW | NetworkEvidence |
| NET-203 (ALLMULTI Interfaces) | ✅ | MEDIUM | NetworkEvidence |
| NET-303 (mDNS/Avahi) | ✅ | MEDIUM | RegistryEvidence |
| NET-304 (DNS Search Domain) | ✅ | LOW | RegistryEvidence |
| NET-601 (Untrusted CAs) | ✅ | MEDIUM | FileEvidence |
| NET-602 (Expiring Certs) | ✅ | MEDIUM | FileEvidence |
| NET-603 (Cert Store Integrity) | ✅ | LOW | FileEvidence |
| NET-104 (Admin Ports Exposed) | ✅ | HIGH | NetworkEvidence |
| NET-205 (Loopback Status) | ✅ | MEDIUM | NetworkEvidence |
| NET-504 (Wireless Interfaces) | ✅ | MEDIUM | NetworkEvidence |
| NET-505 (Ephemeral Ports) | ✅ | MEDIUM | NetworkEvidence |
| NET-604 (Single DNS) | ✅ | LOW | RegistryEvidence |
| NET-605 (No DNS) | ✅ | MEDIUM | RegistryEvidence |
| NET-606 (SSH Default Port) | ✅ | LOW | NetworkEvidence |
| NET-607 (Down Interfaces) | ✅ | LOW | NetworkEvidence |
| NET-701 (Listening on All Interfaces) | ✅ | MEDIUM | NetworkEvidence |
| NET-702 (World-Writable UNIX Sockets) | ✅ | HIGH | NetworkEvidence |
| NET-703 (Loopback-Only Services) | ✅ | LOW | NetworkEvidence |
| NET-704 (Exposed UDP Services) | ✅ | MEDIUM | NetworkEvidence |
| NET-705 (Non-Root Privileged Ports) | ✅ | HIGH | NetworkEvidence |
| NET-706 (TIME_WAIT Connections) | ✅ | LOW | RegistryEvidence |
| NET-707 (Duplicate Listening Ports) | ✅ | MEDIUM | RegistryEvidence |
| NET-708 (Ephemeral Port Range) | ✅ | LOW | RegistryEvidence |
| NET-709 (Promiscuous Interfaces) | ✅ | HIGH | RegistryEvidence |
| NET-710 (DNS Config Mismatch) | ✅ | MEDIUM | RegistryEvidence |
| PKG-101 (Unnecessary Pkgs) | ✅ | MEDIUM | PackageEvidence |
| PKG-201 (Modified Files) | ✅ | MEDIUM | CommandEvidence |
| PKG-202 (Broken Signatures) | ✅ | HIGH | RegistryEvidence / CommandEvidence |
| PKG-210 (Flatpak Integrity) | ✅ | MEDIUM | RegistryEvidence |
| PKG-301 (Unknown Repos) | ✅ | MEDIUM | RegistryEvidence |
| PKG-310 (Snap Integrity) | ✅ | MEDIUM | RegistryEvidence |
| PKG-302 (Expired Keys) | ✅ | MEDIUM | RegistryEvidence |
| PKG-401 (Known CVEs) | ✅ | HIGH | PackageEvidence |
| PKG-402 (Pending Updates) | ✅ | HIGH | PackageEvidence |
| PKG-102 (HTTP Repos) | ✅ | MEDIUM | RegistryEvidence |
| PKG-103 (Source Repos) | ✅ | LOW | RegistryEvidence |
| PKG-203 (Third-Party Repos) | ✅ | MEDIUM | RegistryEvidence |
| PKG-303 (Held Packages) | ✅ | LOW | RegistryEvidence |
| PKG-304 (Outdated Kernel) | ✅ | MEDIUM | RegistryEvidence |
| PKG-403 (Auto-Removable) | ✅ | LOW | RegistryEvidence |
| PKG-501 (Many Third-Party Repos) | ✅ | MEDIUM | RegistryEvidence |
| PKG-502 (PM Integrity) | ✅ | MEDIUM | RegistryEvidence |
| PKG-601 (Missing Security Pkgs) | ✅ | MEDIUM | RegistryEvidence |
| PKG-602 (Obsolete Kernels) | ✅ | MEDIUM | RegistryEvidence |
| PKG-603 (Development Pkgs) | ✅ | LOW | PackageEvidence |
| PKG-604 (Auto-Removable Pkgs) | ✅ | LOW | RegistryEvidence |
| PKG-605 (Duplicate Repos) | ✅ | MEDIUM | RegistryEvidence |
| PKG-606 (Unused Snap Pkgs) | ✅ | LOW | RegistryEvidence |
| PKG-607 (Large Pkgs) | ✅ | LOW | PackageEvidence |
| PKG-608 (Repo Consistency) | ✅ | MEDIUM | RegistryEvidence |
| PRM-101 (SUID Binaries) | ✅ | HIGH | FileEvidence |
| PRM-201 (World-Writable) | ✅ | HIGH | FileEvidence |
| PRM-301 (SGID Binaries) | ✅ | MEDIUM | FileEvidence |
| PRM-302 (Dangerous Capabilities) | ✅ | HIGH | FileEvidence |
| PRM-303 (Missing Sticky Bit) | ✅ | MEDIUM | FileEvidence |
| PRM-304 (World-Writable PATH Executables) | ✅ | CRITICAL | FileEvidence |
| PRM-305 (Setuid Shell Scripts) | ✅ | HIGH | FileEvidence |
| PRM-306 (Non-Root Setuid Ownership) | ✅ | MEDIUM | FileEvidence |
| PRM-307 (Unexpected Capabilities) | ✅ | MEDIUM | FileEvidence |
| PRM-308 (World-Writable Setuid Files) | ✅ | CRITICAL | FileEvidence |
| PRM-401 (Group-Writable SUID/SGID) | ✅ | HIGH | FileEvidence |
| PRM-402 (SGID on World-Writable Dirs) | ✅ | HIGH | FileEvidence |
| PRM-403 (SUID Files with Capabilities) | ✅ | MEDIUM | FileEvidence |
| PRM-404 (Weak Default Umask) | ✅ | MEDIUM | RegistryEvidence |
| PRM-405 (Critical Directory Ownership) | ✅ | HIGH | FileEvidence |
| PRM-406 (SUID/SGID Without Execute) | ✅ | MEDIUM | FileEvidence |
| PRM-407 (SGID on Non-Executable Files) | ✅ | LOW | FileEvidence |
| PRM-408 (Dangerous Capability Combos) | ✅ | HIGH | FileEvidence |
| FS-101 (Unexpected Files in /etc) | ✅ | MEDIUM | FileEvidence |
| FS-102 (Unexpected PATH Executables) | ✅ | MEDIUM | FileEvidence |
| FS-201 (Hidden World-Writable Files) | ✅ | MEDIUM | FileEvidence |
| FS-202 (Deleted Running Binaries) | ✅ | HIGH | ProcessEvidence |
| FS-301 (Unexpected /etc Symlinks) | ✅ | LOW | FileEvidence |
| FS-302 (Immutable File Drift) | ✅ | HIGH | CommandEvidence |
| FS-401 (Unexpected Capabilities) | ✅ | MEDIUM | FileEvidence |
| FS-402 (World-Writable Directories) | ✅ | MEDIUM | FileEvidence |
| FS-403 (Orphaned Files) | ✅ | MEDIUM | FileEvidence |
| FS-501 (Mount Option Gaps) | ✅ | MEDIUM | RegistryEvidence |
| FS-601 (Sensitive File Permissions) | ✅ | HIGH | FileEvidence |
| FS-602 (Home Directory Permissions) | ✅ | MEDIUM | FileEvidence |
| FS-603 (Sticky Bit on World-Writable Dirs) | ✅ | MEDIUM | FileEvidence |
| FS-604 (Temp Directory Mount Security) | ✅ | HIGH | RegistryEvidence |
| FS-605 (Filesystem Space Exhaustion) | ✅ | MEDIUM | RegistryEvidence |
| FS-606 (Dot-File Permission Hijacking) | ✅ | HIGH | FileEvidence |
| FS-607 (System Binary Root Ownership) | ✅ | HIGH | FileEvidence |
| FS-608 (World-Writable Cron/Script Dirs) | ✅ | HIGH | FileEvidence |
| BOOT-101 (Secure Boot) | ✅ | HIGH | RegistryEvidence |
| BOOT-201 (Kernel Lockdown) | ✅ | MEDIUM | RegistryEvidence |
| BOOT-301 (EFI Integrity) | ✅ | HIGH | RegistryEvidence / FileEvidence |
| BOOT-401 (GRUB Password) | ✅ | HIGH | RegistryEvidence |
| BOOT-501 (Unsigned Kernels) | ✅ | HIGH | FileEvidence |
| BOOT-601 (SBAT Status) | ✅ | HIGH | RegistryEvidence |
| BOOT-602 (Kernel Image Count) | ✅ | MEDIUM | RegistryEvidence |
| BOOT-603 (Latest Kernel Running) | ✅ | MEDIUM | RegistryEvidence |
| BOOT-604 (EFI Boot Entry Changes) | ✅ | HIGH | FileEvidence |
| BOOT-605 (Kernel Lockdown Mode) | ✅ | MEDIUM | RegistryEvidence |
| BOOT-606 (GRUB Config Permissions) | ✅ | HIGH | FileEvidence |
| BOOT-607 (Boot Partition Mount) | ✅ | MEDIUM | RegistryEvidence |
| BOOT-608 (Initramfs Presence) | ✅ | MEDIUM | FileEvidence |
| CLD-101 (Cloud Metadata Exposure) | ✅ | HIGH | RegistryEvidence |
| CLD-102 (IMDSv2 Enforcement) | ✅ | MEDIUM | RegistryEvidence |
| CLD-201 (Cloud Storage Exposure) | ✅ | MEDIUM | RegistryEvidence |
| CLD-301 (Cloud IAM Credentials) | ✅ | HIGH | RegistryEvidence |
| CLD-401 (Cloud Agent Health) | ✅ | MEDIUM | RegistryEvidence |
| CLD-501 (K8s Node Security) | ✅ | HIGH | RegistryEvidence |
| CLD-502 (Creds in Env) | ✅ | HIGH | RegistryEvidence |
| CLD-503 (Kubelet Anon Auth) | ✅ | HIGH | RegistryEvidence |
| CLD-504 (Kubelet Read-Only Port) | ✅ | MEDIUM | RegistryEvidence |
| CLD-505 (Kubelet Seccomp) | ✅ | MEDIUM | RegistryEvidence |
| CLD-506 (Kubelet Kernel Prot) | ✅ | MEDIUM | RegistryEvidence |
| CLD-507 (Cloud Provider Info) | ✅ | LOW | RegistryEvidence |
| CLD-508 (K8s Secrets on Node) | ✅ | HIGH | RegistryEvidence |
| CLD-509 (Multi-Cloud Creds) | ✅ | MEDIUM | RegistryEvidence |
| CLD-601 (Cloud CLI Tools) | ✅ | MEDIUM | RegistryEvidence |
| CLD-602 (Cloud Env Credentials) | ✅ | CRITICAL | RegistryEvidence |
| CLD-603 (Cloud Metadata Service) | ✅ | HIGH | RegistryEvidence |
| CLD-604 (Cloud Storage Tools) | ✅ | MEDIUM | RegistryEvidence |
| CLD-605 (Cloud Agent Health) | ✅ | MEDIUM | RegistryEvidence |
| CLD-606 (Kubelet Security) | ✅ | HIGH | RegistryEvidence |
| CMP-101 (Ubuntu Support) | ✅ | MEDIUM | RegistryEvidence |
| CMP-102 (Login Banner) | ✅ | LOW | FileEvidence |
| CMP-103 (Separate Partitions) | ✅ | MEDIUM | RegistryEvidence |
| CMP-104 (Mount Options) | ✅ | MEDIUM | RegistryEvidence |
| CMP-105 (Time Sync) | ✅ | HIGH | RegistryEvidence |
| CMP-106 (File Integrity Tool) | ✅ | MEDIUM | RegistryEvidence |
| CMP-107 (GRUB Password) | ✅ | HIGH | FileEvidence |
| CMP-108 (Root TTY) | ✅ | MEDIUM | FileEvidence |
| CMP-109 (Auditd Service) | ✅ | HIGH | RegistryEvidence |
| CMP-201 (Legacy Network Services) | ✅ | HIGH | RegistryEvidence |
| CMP-202 (X Window System) | ✅ | MEDIUM | RegistryEvidence |
| CMP-203 (Avahi/mDNS Service) | ✅ | MEDIUM | RegistryEvidence |
| CMP-204 (CUPS Print Service) | ✅ | MEDIUM | RegistryEvidence |
| CMP-205 (DHCP Client) | ✅ | MEDIUM | RegistryEvidence |
| CMP-206 (NFS Services) | ✅ | HIGH | RegistryEvidence |
| CMP-207 (Rsync Service) | ✅ | MEDIUM | RegistryEvidence |
| CMP-208 (SMTP Configuration) | ✅ | MEDIUM | RegistryEvidence |
| CMP-209 (Web Server) | ✅ | MEDIUM | RegistryEvidence |
| CMP-210 (Cron Permissions) | ✅ | MEDIUM | FileEvidence |
| CMP-211 (SSH Compliance) | ✅ | HIGH | FileEvidence |
| COM-101 (Bad Processes) | ✅ | HIGH | ProcessEvidence |
| COM-201 (Suspicious Binary Location) | ✅ | HIGH | ProcessEvidence |
| COM-202 (Malicious Process Names) | ✅ | HIGH | ProcessEvidence |
| COM-203 (Anomalous PPID) | ✅ | MEDIUM | ProcessEvidence |
| COM-204 (World-Writable Binary) | ✅ | HIGH | ProcessEvidence |
| COM-205 (Suspicious Cmdline) | ✅ | HIGH | ProcessEvidence |
| COM-206 (Misleading Names) | ✅ | MEDIUM | ProcessEvidence |
| COM-207 (Unexpected Root Process) | ✅ | MEDIUM | ProcessEvidence |
| COM-208 (High Memory Usage) | ✅ | MEDIUM | ProcessEvidence |
| COM-301 (Suspicious Connections) | ✅ | HIGH | ProcessEvidence |
| COM-302 (Reverse Shell Detection) | ✅ | CRITICAL | ProcessEvidence |
| COM-303 (Unusual Outbound) | ✅ | MEDIUM | ProcessEvidence |
| COM-304 (High Memory Detection) | ✅ | MEDIUM | ProcessEvidence |
| COM-305 (Hidden Process Detection) | ✅ | CRITICAL | ProcessEvidence |
| COM-306 (Anomalous Process Names) | ✅ | HIGH | ProcessEvidence |
| CTN-101 (Docker Socket) | ✅ | HIGH | FileEvidence |
| CTN-102 (Docker TCP Exposure) | ✅ | CRITICAL | NetworkEvidence |
| CTN-201 (Privileged Containers) | ✅ | CRITICAL | RegistryEvidence |
| CTN-202 (Host Network) | ✅ | HIGH | RegistryEvidence |
| CTN-203 (Host PID) | ✅ | HIGH | RegistryEvidence |
| CTN-204 (Host Mounts) | ✅ | HIGH | RegistryEvidence |
| CTN-301 (Root Containers) | ✅ | HIGH | RegistryEvidence |
| CTN-401 (Old Images) | ✅ | MEDIUM | RegistryEvidence |
| CTN-402 (Unsigned Images) | ✅ | MEDIUM | RegistryEvidence |
| CTN-303 (Dangerous Caps) | ✅ | HIGH | RegistryEvidence |
| CTN-304 (Missing Security Opts) | ✅ | MEDIUM | RegistryEvidence |
| CTN-305 (Writable RootFS) | ✅ | MEDIUM | RegistryEvidence |
| CTN-306 (Host IPC) | ✅ | HIGH | RegistryEvidence |
| CTN-307 (Exposed Ports) | ✅ | MEDIUM | RegistryEvidence |
| CTN-501 (Socket Exposure) | ✅ | HIGH | FileEvidence |
| CTN-502 (Multiple Runtimes) | ✅ | LOW | RegistryEvidence |
| CTN-601 (Restart Loop) | ✅ | MEDIUM | RegistryEvidence |
| CTN-701 (Added Capabilities) | ✅ | HIGH | RegistryEvidence |
| CTN-702 (Security Opts Dropped) | ✅ | HIGH | RegistryEvidence |
| CTN-703 (Latest Tag) | ✅ | MEDIUM | RegistryEvidence |
| CTN-704 (Long-Running Containers) | ✅ | LOW | RegistryEvidence |
| CTN-705 (Excessive Bind Mounts) | ✅ | MEDIUM | RegistryEvidence |
| CTN-706 (No User Namespace) | ✅ | HIGH | RegistryEvidence |
| CTN-707 (Restart Policy) | ✅ | MEDIUM | RegistryEvidence |
| FOR-101 (Audit Log Availability) | ✅ | MEDIUM | FileEvidence |
| FOR-201 (Shell History Audit) | ✅ | MEDIUM | FileEvidence |
| FOR-301 (Forensic Artifact Exposure) | ✅ | MEDIUM | FileEvidence |
| LOG-101 (Journal Max Size) | ✅ | MEDIUM | RegistryEvidence |
| LOG-201 (Log Rotation) | ✅ | MEDIUM | FileEvidence / RegistryEvidence |
| LOG-301 (Log Tamper Detection) | ✅ | HIGH | LogEvidence |
| LOG-302 (Log File Perms) | ✅ | MEDIUM | FileEvidence |
| LOG-401 (Sudo Failures) | ✅ | HIGH | RegistryEvidence |
| LOG-402 (SSH Failures) | ✅ | HIGH | RegistryEvidence |
| LOG-501 (Audit Rule Gaps) | ✅ | MEDIUM | RegistryEvidence |
| LOG-502 (Audit Log Exhaustion) | ✅ | MEDIUM | FileEvidence / RegistryEvidence |
| LOG-503 (Auditd MITRE ATT&CK Coverage) | ✅ | HIGH | LogEvidence |
| LOG-601 (Journald Compression) | ✅ | LOW | RegistryEvidence |
| LOG-602 (Journald Log Forwarding) | ✅ | MEDIUM | RegistryEvidence |
| LOG-603 (Journald Sync Interval) | ✅ | LOW | RegistryEvidence |
| LOG-604 (Journald Max File Size) | ✅ | MEDIUM | RegistryEvidence |
| LOG-605 (Journald Keep Free Space) | ✅ | MEDIUM | RegistryEvidence |
| LOG-606 (Journald Runtime-Only Logging) | ✅ | HIGH | RegistryEvidence |
| LOG-607 (Log Retention Freshness) | ✅ | MEDIUM | RegistryEvidence |
| LOG-608 (Journald Log File Count) | ✅ | LOW | RegistryEvidence |
| PER-201 (Unauth Services) | ✅ | HIGH | FileEvidence |
| SEC-101 (AppArmor) | ✅ | HIGH | FileEvidence |
| SECR-101 (AWS Keys) | ✅ | CRITICAL | FileEvidence |
| SECR-102 (GCP Keys) | ✅ | CRITICAL | FileEvidence |
| SECR-201 (GitHub Tokens) | ✅ | CRITICAL | FileEvidence |
| SECR-202 (.env Secrets) | ✅ | MEDIUM | FileEvidence |
| SECR-203 (API Keys) | ✅ | HIGH | FileEvidence |
| SECR-301 (Exposed SSH Keys) | ✅ | CRITICAL | FileEvidence |
| SECR-302 (Weak SSH Keys) | ✅ | MEDIUM | FileEvidence |
| SECR-401 (DB Credentials) | ✅ | CRITICAL | FileEvidence |
| SECR-501 (Expired Certs) | ✅ | MEDIUM | FileEvidence |
| SECR-502 (Self-Signed Certs) | ✅ | MEDIUM | FileEvidence |
| SECR-601 (GitLab Token Detection) | ✅ | CRITICAL | FileEvidence |
| SECR-602 (Slack Token Detection) | ✅ | CRITICAL | FileEvidence |
| SECR-603 (NPM Token Detection) | ✅ | CRITICAL | FileEvidence |
| SECR-604 (Azure DevOps Credential) | ✅ | HIGH | FileEvidence |
| SECR-605 (Docker Credential) | ✅ | CRITICAL | FileEvidence |
| SECR-606 (Stripe API Key) | ✅ | CRITICAL | FileEvidence |
| SECR-607 (Twilio Credential) | ✅ | CRITICAL | FileEvidence |
| SECR-608 (Password in Code) | ✅ | HIGH | FileEvidence |
| SVC-101 (Insecure Svcs) | ✅ | HIGH | FileEvidence |
| SVC-102 (Unexpected Enabled Svcs) | ✅ | MEDIUM | RegistryEvidence |
| SVC-201 (Services Running as Root) | ✅ | MEDIUM | ProcessEvidence |
| SVC-202 (Svcs from Unknown Binaries) | ✅ | HIGH | FileEvidence |
| SVC-301 (Failed Services) | ✅ | MEDIUM | RegistryEvidence |
| SVC-302 (Unexpected Listening Svcs) | ✅ | MEDIUM | NetworkEvidence |
| SVC-401 (Recently Installed Svcs) | ✅ | MEDIUM | FileEvidence |
| SVC-402 (Modified Systemd Units) | ✅ | HIGH | FileEvidence |
| SVC-103 (Missing Hardening) | ✅ | MEDIUM | FileEvidence |
| SVC-203 (Missing ExecStart Binary) | ✅ | HIGH | RegistryEvidence |
| SVC-303 (Orphaned Timer Units) | ✅ | MEDIUM | RegistryEvidence |
| SVC-501 (World-Writable ExecStart) | ✅ | CRITICAL | FileEvidence |
| SVC-502 (Suspicious Descriptions) | ✅ | MEDIUM | RegistryEvidence |
| SVC-503 (Stopped Enabled Services) | ✅ | LOW | RegistryEvidence |
| SVC-504 (Masked With Unit File) | ✅ | LOW | FileEvidence |
| SVC-601 (Service Load Failures) | ✅ | HIGH | RegistryEvidence |
| SVC-602 (Socket Units Not Running) | ✅ | MEDIUM | RegistryEvidence |
| SVC-603 (Timer-Service Mismatch) | ✅ | MEDIUM | RegistryEvidence |
| SVC-604 (Unit File Ownership) | ✅ | HIGH | FileEvidence |
| SVC-605 (World-Writable Unit Files) | ✅ | CRITICAL | FileEvidence |
| SVC-606 (Static Services Not Running) | ✅ | MEDIUM | RegistryEvidence |
| SVC-607 (Duplicate Unit Files) | ✅ | MEDIUM | RegistryEvidence |
| SVC-608 (Timers Without Calendar) | ✅ | LOW | RegistryEvidence |
| FW-101 (Firewall Active) | ✅ | HIGH | CommandEvidence |
| FW-201 (Default Policy) | ✅ | MEDIUM | RegistryEvidence |
| FW-202 (Minimal Rules) | ✅ | MEDIUM | RegistryEvidence |
| FW-203 (IPv6 Rules) | ✅ | MEDIUM | RegistryEvidence |
| FW-204 (Competing Firewalls) | ✅ | LOW | RegistryEvidence |
| FW-205 (Outgoing Policy) | ✅ | LOW | RegistryEvidence |
| FW-206 (Logging) | ✅ | LOW | RegistryEvidence |
| FW-207 (SSH Rate Limit) | ✅ | MEDIUM | RegistryEvidence |
| FW-208 (Boot Persistence) | ✅ | MEDIUM | RegistryEvidence |
| FW-209 (Firewall Boot Persistence) | ✅ | MEDIUM | CommandEvidence |
| SEC-201 (AppArmor Complain Mode) | ✅ | MEDIUM | CommandEvidence |
| SEC-202 (AppArmor Profile Integrity) | ✅ | MEDIUM | CommandEvidence |
| SEC-203 (AppArmor Extra Profiles) | ✅ | LOW | RegistryEvidence |
| SEC-204 (Seccomp Status) | ✅ | MEDIUM | RegistryEvidence |
| SEC-205 (LSM Stacking) | ✅ | LOW | RegistryEvidence |
| SEC-206 (AppArmor Cache Status) | ✅ | LOW | FileEvidence |
| SEC-207 (Module Loading Restrictions) | ✅ | HIGH | RegistryEvidence |
| SEC-208 (Unconfined Root Processes) | ✅ | HIGH | RegistryEvidence |
| USB-101 (USB Storage Restriction) | ✅ | MEDIUM | FileEvidence |
| USB-201 (USB Device Authorization Policy) | ✅ | MEDIUM | FileEvidence |
| USB-301 (USBGuard Daemon Configuration) | ✅ | MEDIUM | FileEvidence |
| PWD-101 (Password Policy Strength) | ✅ | HIGH | FileEvidence |
| PWD-201 (Password History) | ✅ | MEDIUM | RegistryEvidence |
| PWD-202 (Password Min Age) | ✅ | MEDIUM | RegistryEvidence |
| PWD-203 (Password Max Age) | ✅ | HIGH | RegistryEvidence |
| PWD-204 (Password Expiry Warning) | ✅ | LOW | RegistryEvidence |
| PWD-301 (Account Lockout) | ✅ | HIGH | RegistryEvidence |
| PWD-302 (Password Hashing) | ✅ | HIGH | RegistryEvidence |
| PWD-303 (Password Quality) | ✅ | MEDIUM | RegistryEvidence |
| PWD-304 (Default Passwords) | ✅ | CRITICAL | RegistryEvidence |
| PER-101 (Cron Job Anomalies) | ✅ | HIGH | FileEvidence |
| PER-102 (Anacron Job Anomalies) | ✅ | MEDIUM | FileEvidence |
| PER-103 (At Job Anomalies) | ✅ | MEDIUM | FileEvidence |
| PER-202 (Suspicious Systemd Timers) | ✅ | MEDIUM | FileEvidence |
| PER-203 (Systemd Service Drop-Ins) | ✅ | MEDIUM | FileEvidence |
| PER-204 (Systemd Path Units) | ✅ | MEDIUM | FileEvidence |
| PER-301 (Unexpected Profile.d Scripts) | ✅ | MEDIUM | FileEvidence |
| PER-302 (Modified Bash Init Files) | ✅ | MEDIUM | FileEvidence |
| PER-303 (Modified Zsh Init Files) | ✅ | MEDIUM | FileEvidence |
| PER-401 (LD_PRELOAD in Environment) | ✅ | HIGH | ProcessEvidence |
| PER-402 (ld.so.preload Entries) | ✅ | CRITICAL | FileEvidence |
| PER-403 (LD_LIBRARY_PATH Anomalies) | ✅ | MEDIUM | ProcessEvidence |
| PER-501 (Unexpected PAM Modules) | ✅ | HIGH | FileEvidence |
| PER-502 (PAM Module Modifications) | ✅ | HIGH | FileEvidence |
| PER-503 (Udev Rules Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-601 (Network Hook Scripts) | ✅ | MEDIUM | FileEvidence |
| PER-602 (SSH Forced Commands) | ✅ | HIGH | FileEvidence |
| PER-603 (SSH AuthorizedKeysFile Tamper) | ✅ | HIGH | RegistryEvidence |
| PER-701 (APT Hook Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-702 (Dpkg Hook Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-801 (rc.local Script Persistence) | ✅ | HIGH | FileEvidence |
| PER-802 (Init.d Script Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-803 (Login/Logout Hook Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-804 (Systemd User Units) | ✅ | MEDIUM | FileEvidence |
| PER-805 (XDG Autostart Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-901 (Persistence Directory Audit) | ✅ | MEDIUM | FileEvidence |
| PER-902 (World-Writable Persistence) | ✅ | HIGH | FileEvidence |
| PER-903 (Systemd Generators) | ✅ | HIGH | FileEvidence |
| PER-904 (D-Bus Activated Services) | ✅ | MEDIUM | FileEvidence |
| PER-905 (Polkit Rule Persistence) | ✅ | HIGH | FileEvidence |
| PER-906 (Tmpfiles Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-907 (Module Load Persistence) | ✅ | MEDIUM | RegistryEvidence |
| PER-908 (Extended Shell Init) | ✅ | MEDIUM | FileEvidence |
| PER-909 (Initramfs Hook Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-910 (Library Path Config) | ✅ | HIGH | FileEvidence |
| PER-911 (Sysctl Persistence) | ✅ | MEDIUM | FileEvidence |
| PER-912 (User Timer Persistence) | ✅ | MEDIUM | FileEvidence |

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
| Correlation | ✅ | 860→1500+ | 16 Python rules + 4 YAML rules + 8 scenarios + engine with Phase 5 features |
| Compliance | ✅ | 335 | CIS 27 controls, NIST 6 controls, gap analysis |
| Profiles | ✅ | 451 | Desktop/server reference profiles, auto-detect |
| Context Severity | ✅ | 201 | SSH, file perms, users, network context evaluators |
| Knowledge Base | ✅ | 171 + 93 YAML | YAML for all 93 checks with threat/exploit/impact/fix/CVSS; KB wired into runner pipeline |
| Trust Scoring | ✅ | 106 | Evidence-quality adjusted confidence |
| Policies | ✅ | 86 | YAML policy loading, check overrides, severity overrides |

#### Phase 5 Modules (Correlation Engine 2.0)
| Module | Status | Lines | Notes |
|--------|--------|-------|-------|
| YAML Rule Loader | ✅ | 230 | `CorrelationRuleYAML` + `YamlRuleLoader` |
| Attack Scenarios | ✅ | 180 | 8 core scenarios (ransomware, cryptominer, persistence, supply chain, bootkit, container escape, data theft, active breach) |
| Scenario Model | ✅ | 110 | `KillChainPhase`, `AttackScenario`, `ScenarioResult`, `CounterEvidence` |
| YAML Rule Files | ✅ | 4 rules | DNS manipulation, credential dump, privilege escalation, network recon |
| Engine Upgrades | ✅ | 340→400+ | Temporal correlation, risk accumulation, counter-evidence filtering, scenario evaluation |
| Scenario Injection | ✅ | — | Phase 3.6 in runner, `_inject_scenario_results` method |

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
| SUID allowlist | ✅ | suid_allowlist in config YAML, accessed via AuditCheck._config |
| SUID known-safe packages | ✅ | 60+ packages auto-allowlisted (coreutils, sudo, shadow, util-linux, etc.) |

#### Testing
| Area | Tests | Lines | Notes |
|------|-------|-------|-------|
| Unit tests | 927 | 7,650+ | **65 test files** across all modules (organized in subdirectories) |
| Integration tests | 155 | 3,000+ | Pipeline, scoring, reporter, checks (all 25), collectors, pipeline edge cases, **Phase 6 cloud & compliance**, **new 50 check deep integration** |
| Golden tests | ✅ | 80 | JSON and Markdown golden report snapshot tests |
| Kernel checks | ✅ | 186 | tests/unit/checks/test_kernel_checks.py, tests/unit/checks/test_kernel_hardening_checks.py, tests/unit/checks/test_kernel_extra_checks.py |
| SSH checks | ✅ | 185 | tests/unit/checks/test_ssh_checks.py, tests/unit/checks/test_ssh_security_checks.py |
| Network checks | ✅ | 168 | tests/unit/checks/test_network_checks.py, tests/unit/checks/test_network_security_checks.py, tests/unit/checks/test_network_extended_checks.py |
| Permission checks | ✅ | 51 | tests/unit/checks/test_permission_checks.py |
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
| Compromise checks (COM-101) | ✅ | 77 | tests/unit/checks/test_compromise_checks.py, tests/unit/checks/test_compromise_security_checks.py |
| Compliance checks (CMP-101) | ✅ | 78 | tests/unit/checks/test_compliance_checks.py, tests/unit/checks/test_compliance_security_checks.py |
| Container checks (CTN-101) | ✅ | 77 | tests/unit/checks/test_container_checks.py, tests/unit/checks/test_ctn_security_checks.py |
| Forensics checks (FOR-101) | ✅ | 48 | tests/unit/checks/test_forensics_checks.py |
| Kernel module checks (KERN-401) | ✅ | 25 | tests/unit/checks/test_krn_checks.py |
| Package checks (PKG-101) | ✅ | 67 | tests/unit/checks/test_package_checks.py, tests/unit/checks/test_package_security_checks.py |
| Persistence checks (PER-201) | ✅ | 48 | tests/unit/checks/test_persistence_checks.py |
| Security checks (FW-101/SEC-101/USB-101) | ✅ | 118 | tests/unit/checks/test_security_checks.py, tests/unit/checks/test_firewall_security_checks.py |
| Service checks (SVC-101) | ✅ | 61 | tests/unit/checks/test_service_checks.py, tests/unit/checks/test_service_security_checks.py |
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
| Versioning | ✅ | 0.25.0 — semver |

---

## Check ID Numbering Scheme

All check IDs follow a **sub-ranged** format: `<PREFIX>-<SUBRANGE><SEQ>`.

Each prefix has reserved 100-level blocks for subcategories. This prevents renumbering as check counts grow.

### ID Ranges by Category

| Prefix | Range | Sub-ranges | Current |
|--------|-------|------------|---------|
| **SSH** | 100–999 | 100=Auth, 200=Algorithms, 300=Keys, 400=Logging, 500=Network, 600=Compliance | 19 |
| **KERN** | 100–999 | 100=Memory, 200=Pointers, 300=Core dumps, 400=Modules/BPF, 500=FS prot, 600=Network | 21 |
| **USR** | 100–999 | 100=Account integrity, 200=Weak creds, 300=Policy, 400=Privilege, 500=SSH keys, 600=Service accts | 20 |
| **NET** | 100–999 | 100=Ports, 200=Interfaces, 300=DNS, 400=Kernel net, 500=Wireless, 600=TLS/Certs | 24 |
| **PKG** | 100–999 | 100=Unnecessary, 200=Integrity, 300=Repos, 400=CVEs, 500=Held | 17 |
| **FS** | 100–999 | 100=File integrity, 200=Hidden/orphan, 300=Mounts, 400=Symlinks/immutable, 500=Capabilities | 10 |
| **BOOT** | 100–999 | 100=Secure Boot, 200=Lockdown, 300=EFI, 400=GRUB, 500=Kernel images | 5 |
| **SVC** | 100–999 | 100=Enabled svcs, 200=Security, 300=Listening, 400=Failed, 500=Modified | 16 |
| **PER** | 100–999 | 100=Cron/at, 200=Systemd, 300=Shell init, 400=LD injection, 500=PAM/udev, 600=Network, 700=Package hooks, 800=Login/init | 26 |
| **CTN** | 100–999 | 100=Socket, 200=Privileges, 300=Security, 400=Images, 500=Runtime, 600=LXC | 18 |
| **LOG** | 100–999 | 100=Journal, 200=Rotation, 300=Tamper, 400=Auth fail, 500=Auditd | 0 |
| **SECR** | 100–999 | 100=Cloud, 200=Code, 300=Crypto keys, 400=DB/API, 500=Certs | 0 |
| **FW** | 100–999 | 100=Status, 200=Rules, 300=Defaults, 400=Logging | 9 |
| **CMP** | 100–999 | 100=Version, 200=CIS, 300=STIG, 400=Regulatory, 500=Custom | 11 |
| **COM** | 100–999 | 100=Processes, 200=Network IOC, 300=Filesystem IOC | 9 |
| **FOR** | 100–999 | 100=Logs, 200=Timeline, 300=Artifacts | 3 |
| **SEC** | 100–999 | 100=AppArmor, 200=SELinux, 300=LSM | 1 |
| **USB** | 100–999 | 100=Storage, 200=Devices, 300=Guard | 3 |
| **PWD** | 100–999 | 100=Policy, 200=Reuse, 300=Aging | 1 |
| **CLD** | 100–999 | 100=AWS, 200=GCP, 300=Azure, 400=Generic | 0 |
| **PRM** | 100–999 | 100=SUID, 200=World-writable, 300=Capabilities, 400=Ownership | 10 |

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

### Phase 2: Filesystem & Services (~20 checks) — ✅ COMPLETE

**Goal:** Cover filesystem integrity and expand service auditing.

#### Filesystem Integrity (10 checks) — ✅
| ID | Name | Depends | File |
|----|------|---------|------|
| FS-101 | Unexpected files in /etc | `filesystem` | `checks/filesystem/checks.py` |
| FS-102 | Unexpected executables in PATH | `filesystem` | `checks/filesystem/checks.py` |
| FS-201 | Hidden files in world-writable dirs | `filesystem` | `checks/filesystem/checks.py` |
| FS-202 | Deleted binaries still running | `processes` | `checks/filesystem/checks.py` |
| FS-301 | Unexpected symlinks in /etc | `filesystem` | `checks/filesystem/checks.py` |
| FS-302 | Immutable file drift | none | `checks/filesystem/checks.py` |
| FS-401 | Unexpected file capabilities | `filesystem` | `checks/filesystem/checks.py` |
| FS-402 | World-writable directories | `filesystem` | `checks/filesystem/checks.py` |
| FS-403 | Orphaned files (no package owner) | `filesystem`, `apt` | `checks/filesystem/checks.py` |
| FS-501 | Mount option gaps (noexec, nosuid) | `mounts` | `checks/filesystem/checks.py` |

#### Services (7 checks) — ✅
| ID | Name | Depends | File |
|----|------|---------|------|
| SVC-102 | Unexpected enabled services | `systemd` | `checks/services/service_checks.py` |
| SVC-201 | Services running as root | `systemd`, `processes` | `checks/services/service_checks.py` |
| SVC-202 | Services from unknown binaries | `systemd` | `checks/services/service_checks.py` |
| SVC-301 | Failed services | `systemd` | `checks/services/service_checks.py` |
| SVC-302 | Unexpected listening services | `systemd`, `sockets` | `checks/services/service_checks.py` |
| SVC-401 | Recently installed services | `systemd` | `checks/services/service_checks.py` |
| SVC-402 | Modified systemd unit files | `systemd` | `checks/services/service_checks.py` |

#### Phase 2 Correlation Rules (2 new) — ✅
| Rule ID | What it detects |
|---------|----------------|
| ROGUE-SVC | Rogue service deployment (unknown binary + enabled svc + listening port) |
| FILE-INTEGRITY | File integrity breach (orphaned files + unexpected symlinks + modified /etc) |

**Exit criteria:** 17 new checks with tests, 2 new correlation rules, all tests passing. **Status: ✅ COMPLETE**

---

### Phase 3: Deep Persistence (~25 checks) — ✅ COMPLETE

**Goal:** Cover every attacker persistence mechanism. This is the deepest category.

| ID | Name | Depends | File |
|----|------|---------|------|
| PER-101 | Cron job anomalies | `cron` | `persistence/cron_persistence.py` |
| PER-102 | Anacron jobs | `cron` | `persistence/cron_persistence.py` |
| PER-103 | `at` jobs | `cron` | `persistence/cron_persistence.py` |
| PER-202 | Suspicious systemd timer names | `systemd` | `persistence/systemd_persistence.py` |
| PER-203 | Systemd service drop-ins | `systemd` | `persistence/systemd_persistence.py` |
| PER-204 | Systemd path units | `systemd` | `persistence/systemd_persistence.py` |
| PER-301 | Unexpected profile.d scripts | (none) | `persistence/shell_init_persistence.py` |
| PER-302 | Modified bashrc/bash_profile | `users` | `persistence/shell_init_persistence.py` |
| PER-303 | Modified zshrc | `users` | `persistence/shell_init_persistence.py` |
| PER-401 | LD_PRELOAD in environment | `processes` | `persistence/ld_injection_persistence.py` |
| PER-402 | ld.so.preload entries | (none) | `persistence/ld_injection_persistence.py` |
| PER-403 | LD_LIBRARY_PATH anomalies | `processes` | `persistence/ld_injection_persistence.py` |
| PER-501 | Unexpected PAM modules | `pam` | `persistence/pam_udev_persistence.py` |
| PER-502 | PAM module modifications | `pam` | `persistence/pam_udev_persistence.py` |
| PER-503 | udev rules persistence | (none) | `persistence/pam_udev_persistence.py` |
| PER-601 | Network hook scripts | (none) | `persistence/network_persistence.py` |
| PER-602 | SSH forced commands | `ssh_config` | `persistence/network_persistence.py` |
| PER-603 | SSH AuthorizedKeysFile tampering | `ssh_config` | `persistence/network_persistence.py` |
| PER-701 | APT hook persistence | `apt` | `persistence/package_hook_persistence.py` |
| PER-702 | dpkg hook persistence | (none) | `persistence/package_hook_persistence.py` |
| PER-801 | rc.local scripts | (none) | `persistence/init_autorun_persistence.py` |
| PER-802 | init.d scripts | (none) | `persistence/init_autorun_persistence.py` |
| PER-803 | Login/logout hooks | `users` | `persistence/init_autorun_persistence.py` |
| PER-804 | systemd user units | `users` | `persistence/init_autorun_persistence.py` |
| PER-805 | XDG autostart entries | `users` | `persistence/init_autorun_persistence.py` |

**Exit criteria:** 25 persistence checks with tests, all passing CI. **Status: ✅ COMPLETE**

**Exit criteria:** 25 persistence checks, 5 new correlation rules for persistence chains.

---

### Phase 4: Containers, Secrets & Logs (~30 checks)

**Goal:** Cover modern deployment realities.

#### Phase 4a: Secrets (10 checks) — ✅ COMPLETE
| ID | Name | Depends | Status |
|----|------|---------|--------|
| SECR-101 | AWS keys in filesystem | `secrets` | ✅ |
| SECR-102 | GCP service account keys | `secrets` | ✅ |
| SECR-201 | GitHub tokens in files | `secrets` | ✅ |
| SECR-202 | .env files with secrets | `secrets` | ✅ |
| SECR-203 | API keys in config files | `secrets` | ✅ |
| SECR-301 | Exposed SSH private keys | `ssh_config` | ✅ |
| SECR-302 | Weak SSH key types | `ssh_config` | ✅ |
| SECR-401 | Database credentials in files | `secrets` | ✅ |
| SECR-501 | Expired TLS certificates | `certificates` | ✅ |
| SECR-502 | Self-signed certificates | `certificates` | ✅ |

#### Containers (8 checks) — ✅ COMPLETE
| ID | Name | Depends | Status |
|----|------|---------|--------|
| CTN-102 | Docker daemon TCP exposure | `containers` | ✅ |
| CTN-201 | Privileged containers | `containers` | ✅ |
| CTN-202 | Host network namespace | `containers` | ✅ |
| CTN-203 | Host PID namespace | `containers` | ✅ |
| CTN-204 | Host filesystem mounts | `containers` | ✅ |
| CTN-301 | Root containers | `containers` | ✅ |
| CTN-401 | Image age (>30 days) | `containers` | ✅ |
| CTN-402 | Unsigned images | `containers` | ✅ |

#### Logs & Forensics (8 checks) — ✅ COMPLETE
| ID | Name | Depends | Status |
|----|------|---------|--------|
| LOG-101 | Journal max size / retention | `journald` | ✅ |
| LOG-201 | Log rotation / persistence | `journald` | ✅ |
| LOG-301 | Log tamper detection (timeline gaps) | `journald` | ✅ |
| LOG-302 | Log file permissions | (none) | ✅ |
| LOG-401 | Repeated sudo failures | `auditd` | ✅ |
| LOG-402 | Repeated SSH auth failures | `auditd` | ✅ |
| LOG-501 | Auditd rule coverage gaps | `auditd` | ✅ |
| LOG-502 | Auditd log exhaustion risk | `auditd` | ✅ |

_Secrets completed in Phase 4a above._

#### Phase 4 Correlation Rules (4 new) — ✅ COMPLETE
| Rule ID | What it detects | Status |
|---------|----------------|--------|
| CORR-401 | Container escape path (Docker socket + SUID/root svcs) | ✅ |
| CORR-402 | Credential compromise (cloud + SSH + app creds ≥ 2 categories) | ✅ |
| CORR-403 | Active breach (log gaps + auth failures + new/failed services) | ✅ |
| CORR-404 | Exposed attack surface (listening ports + weak TLS + no audit/fw) | ✅ |
| CORR-405 | Sudo privilege escalation path (no password + no timeout + no logging + ALL) | ✅ |

**Exit criteria:** 34 new checks, 4 new rules. **Phase 4 complete! ✅**

---

### Phase 5: Correlation Engine 2.0 — Full Attack Chain Detection — ✅ COMPLETE

**Goal:** Transform correlation from simple pattern matching to a full threat-detection engine.

| Feature | Priority | Status | Details |
|---------|----------|--------|---------|
| YAML-defined rules | HIGH | ✅ | `policies/correlation/*.yaml` loaded by `YamlRuleLoader` via `CorrelationRuleYAML` |
| Temporal correlation | HIGH | ✅ | Freshness-based confidence boost via `temporal_weight` config on rules |
| Kill chain mapper | MEDIUM | ✅ | `KillChainPhase` enum with 14 MITRE ATT&CK phases mapped per scenario |
| Risk accumulation | HIGH | ✅ | `1 - (0.5)^N` confidence formula applied in `_apply_risk_accumulation` |
| Counter-evidence | MEDIUM | ✅ | `CounterEvidence` model with package/binary/service/file known-good lists |
| Scenario scoring | HIGH | ✅ | 8 core attack scenarios: ransomware, cryptominer, persistence, supply chain, bootkit, container escape, data theft, active breach |
| Threat intel feeds | LOW | 🔴 | Not yet implemented — future enhancement |
| Custom rule DSL | LOW | 🔴 | Not yet implemented — future enhancement |

**New modules:**
| File | Purpose |
|------|---------|
| `models/scenario.py` | `KillChainPhase` enum, `AttackScenario`, `ScenarioResult`, `CounterEvidence` models |
| `correlation/yaml_loader.py` | `CorrelationRuleYAML` (YAML-defined rule class), `YamlRuleLoader` (directory scanner + loader) |
| `correlation/scenarios.py` | 8 core attack scenarios as `AttackScenario` instances |
| `policies/correlation/dns-manipulation.yaml` | YAML rule: DNS manipulation detection |
| `policies/correlation/credential-dump.yaml` | YAML rule: credential dumping detection |
| `policies/correlation/privilege-escalation.yaml` | YAML rule: privilege escalation path detection |
| `policies/correlation/network-scanning.yaml` | YAML rule: network reconnaissance detection |

**Enhanced modules:**
| Module | Changes |
|--------|---------|
| `correlation/engine.py` | Added `temporal_weight`, `kill_chain_phases` to `CorrelationRule`; `evaluate_scenarios()`; `_apply_counter_evidence()`; `_apply_risk_accumulation()`; `set_counter_evidence()`; `register_scenario()`/`register_scenarios()` |
| `correlation/__init__.py` | Added `CORE_SCENARIOS`, `CorrelationRuleYAML`, `YamlRuleLoader` exports |
| `models/__init__.py` | Added `AttackScenario`, `CounterEvidence`, `KillChainPhase`, `ScenarioResult` exports |
| `core/runner.py` | Phase 3.6 scenario evaluation; YAML rule auto-loading; `_inject_scenario_results()` |

**Attack scenarios (8 total):**
| ID | Name | Rules | Severity |
|----|------|-------|----------|
| SCEN-RANSOM | Ransomware Deployment | DEF-EVADE, FILE-INTEGRITY, ROGUE-SVC, PERSIST-DETECT | CRITICAL |
| SCEN-MINER | Cryptominer Deployment | SUID-ARM, UNAUTH-SVC, EXPO-VULN, EXFIL-SURFACE | HIGH |
| SCEN-PERSIST | Persistence & Backdoor | PERSIST-DETECT, CORR-402, CORR-403, ROGUE-SVC | CRITICAL |
| SCEN-SUPPLY | Supply Chain Compromise | SUPPLY-CHAIN | CRITICAL |
| SCEN-BOOTKIT | Bootkit Installation | BOOT-FAIL | CRITICAL |
| SCEN-ESCAPE | Container Escape | CORR-401, EXPO-VULN | CRITICAL |
| SCEN-THEFT | Data Exfiltration / Theft | EXFIL-SURFACE, CORR-402, CORR-404 | CRITICAL |
| SCEN-BREACH | Active Security Breach | CORR-403, CORR-402, SSH-BRUTE, PERSIST-DETECT | CRITICAL |

**Configuration:**
- YAML correlation rules are loaded automatically from `policies/correlation/*.yaml`
- Counter-evidence can be injected via `engine.set_counter_evidence(CounterEvidence(...))`
- Temporal weighting per-rule via `temporal_weight: {max_age_hours: 24, boost_max: 0.15}`

**Exit criteria:** 8 core attack scenarios scored as units. YAML-defined rules operational. Temporal/risk accumulation/counter-evidence all wired into pipeline. **Status: ✅ COMPLETE** (threat intel feeds and custom DSL deferred to later phase)

---

### Phase 6: Cloud & Compliance (~25 checks) — ✅ COMPLETE

**Goal:** Extend to cloud environments and regulatory compliance automation.

#### Cloud (14 checks)
| ID | Name | Depends | Status |
|----|------|---------|--------|
| CLD-101 | Cloud metadata service exposure | `cloud` | ✅ |
| CLD-102 | IMDSv1 vs IMDSv2 | `cloud` | ✅ |
| CLD-201 | Public cloud storage exposure | `cloud` | ✅ |
| CLD-301 | Cloud IAM credential audit | `cloud` | ✅ |
| CLD-401 | Cloud agent health | `cloud` | ✅ |
| CLD-501 | Kubernetes node security | `cloud`, `processes` | ✅ |

#### Compliance Frameworks (10 checks via Phase 3.9 evaluator)
| ID | Name | Framework | Status |
|----|------|-----------|--------|
| CMP-201 | CIS Level 1 — Server | CIS mapping (63 controls) | ✅ |
| CMP-202 | CIS Level 2 — Server | CIS mapping (97 controls) | ✅ |
| CMP-203 | CIS Level 1 — Desktop | CIS mapping (65 controls) | ✅ |
| CMP-301 | STIG Ubuntu 22.04 | 15 STIG controls | ✅ |
| CMP-401 | PCI DSS 4.0 | 20 PCI DSS controls | ✅ |
| CMP-402 | SOC2 | 13 SOC2 controls | ✅ |
| CMP-403 | HIPAA | 18 HIPAA controls | ✅ |
| CMP-501 | Custom policy evaluation | YAML policy engine | ✅ |
| CMP-502 | Drift from baseline | Baseline comparison | ✅ |
| CMP-503 | Remediation verification | Pending remediation | ✅ |

#### Phase 6 Correlation Rules (3 new)
| Rule ID | What it detects | Status |
|---------|----------------|--------|
| CORR-601 | Cloud credential exposure + metadata API accessible → instance compromise | ✅ |
| CORR-602 | CIS level 1 failures > 10 + firewall disabled + auditd off → critical compliance gap | ✅ |
| CORR-603 | Multiple compliance frameworks failing same control → priority remediation | ✅ |

#### Phase 6 Modules

| Module | Status | Details |
|--------|--------|---------|
| `collectors/cloud/metadata.py` | ✅ | CloudMetadataCollector with IMDS, agent, K8s, credential detection |
| `checks/cloud/cloud_checks.py`, `cloud_security_checks.py` | ✅ | 14 cloud check classes (CLD-101 to CLD-509) |
| `core/compliance/evaluator.py` | ✅ | ComplianceEvaluator: Phase 3.9 meta-evaluation across 7 frameworks |
| `core/compliance/mappings.py` | ✅ | CIS L1/L2 Server/Desktop, STIG, PCI DSS, SOC2, HIPAA control mappings |
| `correlation/rules.py` | ✅ | CloudCompromiseRule, ComplianceGapRule, PriorityRemediationRule |
| `policies/correlation/cloud-compromise.yaml` | ✅ | YAML-defined CORR-601 |
| `policies/correlation/compliance-gap.yaml` | ✅ | YAML-defined CORR-602 |
| `policies/correlation/priority-remediation.yaml` | ✅ | YAML-defined CORR-603 |
| Knowledge YAML files | ✅ | 16 new files (6 CLD + 10 CMP) |

**Exit criteria:** 6 cloud checks, 10 compliance framework evaluations, 3 correlation rules, all
registered in pipeline, all tested. **Status: ✅ COMPLETE**

---

### Phase 7a: Validation Lab — Known-Vulnerable VM Testing ✅

**Goal:** Build reproducible, known-vulnerable Ubuntu VMs to validate USAF detection accuracy and close false-negative gaps through iterative fix cycles.

**Completed (2026-07-21):**
- ✅ Switched from Vagrant+VirtualBox to **KVM/libvirt + cloud-init** (Ubuntu-native virtualization)
- ✅ `LibvirtProvisioner` — VM lifecycle via `virt-install`, cloud-init seed ISOs, `virsh` management
- ✅ All 5 scenarios fully implemented: `insecure-server`, `backdoored-host`, `container-escape`, `secrets-exposed`, `desktop-insecure`
- ✅ 11 reusable vulnerability scripts (638 lines total) covering SSH, kernel, users, firewall, SUID, LD_PRELOAD, cron, systemd, Docker, secrets
- ✅ Validation harness: provisioner, SSH runner (fragile JSON fixed), findings validator, gap reporter
- ✅ `expected.yaml` manifests aligned with `scenario.py` for all 5 scenarios (9 missing check IDs added)
- ✅ Dead code removed (`get_vagrantfile_content`, `get_provision_commands`, Vagrantfile templates)
- ✅ CLI: `python3 run.py list | provision | validate | run | destroy | run-all`

#### Approach
1. Define composite vulnerability scenarios (realistic VM profiles with 10–20 vulns each)
2. Provision VMs via **KVM/libvirt** with cloud-init + SSH-provisioned vulnerabilities
3. Run USAF scan against each VM via SSH
4. Compare actual findings to an **expected findings manifest** (YAML)
5. Report gaps: false negatives (missed vulns), false positives (noise)
6. Fix checks to close gaps → revalidate → iterate

#### Composite Scenarios (5 complete)

| Scenario | Vulnerabilities (~15 per VM) | Targets |
|----------|------------------------------|---------|
| `insecure_server` | Weak SSH, no firewall, weak kernel params, old packages, weak passwords, exposed ports | SSH-*, FW-*, KERN-*, PKG-*, PWD-*, NET-* |
| `backdoored_host` | SUID backdoors, cron persistence, LD_PRELOAD, rogue systemd, modified /etc/hosts, reverse shell | PRM-*, PER-*, COM-*, FS-*, NET-* |
| `container_escape` | Docker socket exposed, privileged containers, host mounts, root containers, old images | CTN-*, PRM-*, SVC-* |
| `secrets_exposed` | AWS keys in files, .env secrets, exposed SSH keys, DB creds, GitHub tokens | SECR-*, FS-*, USR-* |
| `desktop_insecure` | Legacy services, weak auth, world-writable PATH, no screensaver, no firewall | CMP-*, PWD-*, PRM-*, FW-*, SVC-* |

#### Deliverables

```
test_lab/
├── run.py                     # CLI: `python run.py provision insecure-server`
├── scenarios/                  # Composite vulnerability profiles
│   ├── __init__.py
│   ├── registry.py             # Scenario registry (discover + register)
│   ├── base.py                 # BaseScenario ABC
│   ├── expected_schema.py      # YAML loading for expected findings
│   ├── insecure_server/        # Scenario 1
│   │   ├── scenario.py         # Scenario definition
│   │   ├── provision.sh        # ~15 vuln setup commands
│   │   └── expected.yaml       # Expected findings manifest
│   ├── backdoored_host/        # Scenario 2
│   │   └── ...
│   ├── container_escape/       # Scenario 3
│   │   └── ...
│   ├── secrets_exposed/        # Scenario 4
│   │   └── ...
│   └── desktop_insecure/       # Scenario 5
│       └── ...
├── harness/
│   ├── __init__.py
│   ├── provisioner.py          # KVM/libvirt lifecycle (up, provision, destroy, ssh)
│   ├── runner.py               # USAF scan execution (via SSH)
│   ├── validator.py            # Compare actual findings vs expected manifest
│   └── reporter.py             # Gap analysis: false negatives, false positives, detection rate
└── shared/
    └── vulnerabilities/        # Reusable shell snippets for common vulns
        ├── ssh_misconfig.sh
        ├── kernel_weak_params.sh
        ├── user_misconfigs.sh
        ├── suid_backdoor.sh
        ├── cron_persistence.sh
        ├── systemd_trojan.sh
        ├── docker_exposure.sh
        ├── secret_injection.sh
        ├── ld_preload_injection.sh
        ├── firewall_off.sh
        └── network_suspicious.sh
```

#### Validation Metrics

| Metric | Target |
|--------|--------|
| Detection rate per scenario | >90% |
| False negatives per scenario | < 3 |
| False positives per scenario | < 5 |
| Iteration cycles to close gaps | ≤ 2 per missing finding |
| VM provision time | < 3 min |

#### Required tooling

```bash
sudo apt install qemu-system-x86 libvirt-daemon-system virt-install cloud-image-utils
sudo adduser $USER libvirt
```

**Exit criteria:** 5 composite scenarios with >90% detection rate, gap analysis tooling, iterative fixes applied. **Status: ✅ COMPLETE (framework), needs iterative detection tuning**

---

### Phase 7b: Snap Store Publishing 🔴

**Goal:** Package USAF as a Snap and publish to the Snap Store for one-command installation on any Ubuntu system.

#### Packaging Plan

| Component | Approach |
|-----------|----------|
| **Confinement** | `classic` (needs full system access for `/proc`, `/etc`, `/sys`, auditd, systemctl) |
| **Base** | `core24` (Ubuntu 24.04 LTS) |
| **Python runtime** | Bundled via `python3` part with pip deps |
| **Entry point** | `bin/usaf` → `usaf.cli.app:main` |
| **Plugs** | `network`, `network-bind`, `system-probe`, `hardware-observe`, `process-control`, `system-observe` |
| **Auto-connect** | All plugs auto-connected (classic confinement) |
| **Post-install** | Post-init hook for `usaf init`, man page installation |

#### Snapshot Process

```yaml
# snapcraft.yaml (planned structure)
name: usaf
base: core24
adopt-info: usaf
grade: stable
confinement: classic

apps:
  usaf:
    command: bin/usaf
    plugs:
      - network
      - network-bind
      - system-probe
      - hardware-observe
      - system-observe
      - process-control

parts:
  usaf:
    plugin: python
    source: https://github.com/Type-3-studio/usaf.git
    source-tag: v0.25.0
    python-packages:
      - typer>=0.15
      - rich>=13.0
      - pydantic>=2.0
      - pyyaml>=6.0
      - requests>=2.31
      - packaging>=24.0
```

#### Pre-Publishing Checklist

- [ ] CLI polished: `--help` output comprehensive, no bare `print()`, rich table formatting
- [ ] `usaf init` writes default config to `$SNAP_USER_DATA/etc/usaf.yaml`
- [ ] All file paths use XDG base dirs (respect `$SNAP_USER_DATA`, `$SNAP_COMMON`)
- [ ] Reports write to `$SNAP_USER_DATA/reports/` by default
- [ ] Baselines store in `$SNAP_USER_DATA/baselines/`
- [ ] `usaf.yaml` configurable via `$SNAP_USER_DATA/usaf.yaml`
- [ ] Man page generation (or `--help` suffices)
- [ ] CI pipeline publishes edge builds on push to main
- [ ] Snap store listing with screenshots, description, category (Security)

#### Snap Store Listing

| Field | Value |
|-------|-------|
| **Name** | `usaf` |
| **Title** | Ubuntu Security Audit Framework |
| **Summary** | Production-grade security auditing for Ubuntu Linux |
| **Categories** | security, sysadmin, monitoring |
| **License** | MIT |

**Prerequisites:** Snapcraft account, `snapcraft` CLI, GitHub integration for automated builds.

**Exit criteria:** Snap published in store at `stable` channel, CI auto-publishes `edge` on commits, `sudo snap install usaf` works on fresh Ubuntu. **Status: 🔴 NOT STARTED**

---

### Phase 7c: Scale, Distribution & Ecosystem (infrastructure phase)

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

| Layer | Current | Phase 7 | Target |
|-------|---------|---------|--------|
| SSH | 25 | 25 | 25 |
| Kernel | 25 | 25 | 25 |
| Users | 17 | 17 | 20 |
| Network | 34 | 34 | 35 |
| Packages | 25 | 25 | 25 |
| Filesystem | 18 | 18 | 30 |
| Permissions | 18 | 18 | 25 |
| Boot | 13 | 13 | 15 |
| Services | 23 | 23 | 30 |
| Persistence | 38 | 38 | 40 |
| Containers | 25 | 25 | 25 |
| Logs & Forensics | 18 | 18 | 25 |
| Secrets | 18 | 18 | 20 |
| Cloud | 20 | 20 | 20 |
| Compliance | 20 | 20 | 20 |
| Firewall | 10 | 10 | 10 |
| Security (AppArmor/USB) | 10 | 10 | 10 |
| Compromise | 15 | 15 | 15 |
| Password | 9 | 9 | 10 |
| **Total checks** | **389** | **389** | **~450** |
| **Correlation rules** | 19 | 19 | **50+** |

---

### v0.6.1 — False Positive Reduction & Noise Fixes (2026-07-12)

**P0 — Bug fixes (false positives identified by real-world audit validation):**
- **COM-306**: Kernel thread detection fixed — 50 false positives eliminated. Real kernel threads (kthreadd, kworker/*) are now correctly identified by checking for empty binary path and ppid==2 before flagging as "masquerading"
- **BOOT-604**: EFI boot entry allowlist expanded — added `mmx64` (MOK manager) and `fbx64` (fallback bootloader) to skip list. These are standard `shim-signed` package files, not bootkits
- **FS-402**: World-writable directory check now skips symlinks (always 0777). `/etc/xdg/systemd/user -> ../../systemd/user` was incorrectly flagged
- **FS-101**: Added `.pwd.lock` and `.resolv.conf.systemd-resolved.bak` to known `/etc` files. These are standard system-generated files
- **SECR-301**: DSA SSH key detection changed from `endswith("dsa_key")` to `endswith("_dsa_key")` — was incorrectly matching ECDSA keys (e.g., `ssh_host_ecdsa_key` ends with "dsa_key")
- **BOOT-601**: SBAT variable detection changed from case-sensitive `glob("SBAT*")` to case-insensitive `iterdir()` + `"sbat" in name.lower()`. Systems with `SbatLevelRT-*` variables were missed
- **BOOT-401**: GRUB check now distinguishes "file not found" from "permission denied". When `/boot/grub/grub.cfg` exists but is unreadable (0600, root-only), the finding now states the actual issue

**P1 — Reporting quality:**
- **CMP-201**: Separated legacy services into SERVER_PACKAGES vs CLIENT_PACKAGES. Client-only packages (telnet, rsh-client, tftp-hpa) now get LOW confidence (fp=0.6) instead of HIGH. Server packages get HIGH confidence
- **PWD-203**: Password max age message now shows actual value (e.g., "99999 (274+ years)") instead of misleading "Password never expires"

**Infrastructure:**
- **Tests**: 1761 total, all passing
- **False positive rate**: Reduced from ~12%+ to ~3% based on real-world audit validation
- **Version**: 0.6.1

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
| TD-022 | ~~No collector exists for SSH config parsing~~ → `SSHConfigCollector` implemented in `collectors/network/ssh_config.py` | MEDIUM | ✅ | P0 |
| TD-023 | ~~No collector exists for PAM configuration~~ → `PAMCollector` implemented in `collectors/security/pam.py` | MEDIUM | ✅ | P0 |
| TD-024 | ~~No collector exists for boot/firmware state~~ → `BootCollector` implemented in `collectors/system/boot.py` | MEDIUM | ✅ | P0 |
| TD-025 | ~~No collector exists for filesystem walking~~ → `FilesystemCollector` implemented in `collectors/filesystem/walker.py` | MEDIUM | ✅ | P0 |
| TD-026 | ~~No collector for DNS resolver state~~ → `DNSCollector` implemented in `collectors/network/dns.py` | LOW | ✅ | P0 |
| TD-027 | ~~No cloud metadata collector~~ → `CloudMetadataCollector` implemented in `collectors/cloud/metadata.py` | MEDIUM | ✅ | P6 |
| TD-028 | ~~CIS benchmark coverage limited to 27 controls~~ → Expanded to 63+ L1 controls | MEDIUM | ✅ | P6 |
| TD-029 | ~~No PCI DSS/SOC2/HIPAA compliance evaluation~~ → Added 51 controls across 3 frameworks | MEDIUM | ✅ | P6 |
| TD-030 | ~~No runner-level compliance meta-evaluation~~ → Phase 3.9 with `ComplianceEvaluator` | MEDIUM | ✅ | P6 |

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
│   ├── scenario.py            # KillChainPhase, AttackScenario, ScenarioResult, CounterEvidence
│   └── references.py          # CVE, CIS, MITRE, OWASP models
├── collectors/                # 15 collectors across 8 categories
├── checks/                    # 25 checks across 17 categories
├── reporting/                 # 3 reporters
├── scoring/
│   ├── engine.py              # Scoring engine (with confidence*FP)
│   └── trust.py               # Trust scoring (evidence quality)
├── baseline/manager.py        # Baseline snapshots
├── correlation/               # Correlation engine + 16 Python + 4 YAML rules + 8 scenarios
│   ├── engine.py              # CorrelationEngine (Phase 5: temporal, risk, counter-evidence, scenarios)
│   ├── rules.py               # 16 built-in correlation rules
│   ├── yaml_loader.py         # YAML-defined rule loader (CorrelationRuleYAML, YamlRuleLoader)
│   └── scenarios.py           # 8 core attack scenarios
├── compliance/framework.py    # CIS + NIST mappings
├── profiles/manager.py        # Profile matching
├── severity/engine.py         # Context-aware severity
├── knowledge/                 # KB + 93 YAML entries (one per check)
├── policies/engine.py         # Policy loading + overrides
├── config/                    # YAML config loading
└── cache/engine.py            # In-memory cache

test_lab/                      # Phase 7a: Validation Lab
├── run.py                     # CLI: provision/validate/run scenarios
├── scenarios/                 # 5 composite vulnerability profiles
├── harness/                   # Provisioner, runner, validator, reporter
└── shared/                    # Reusable vulnerability scripts
```

---

## Metrics & Targets

| Metric | Current | Short-term (P7a) | Medium-term (P7c) | Long-term |
|--------|---------|------------------|---------------------|-----------|
| Checks | 389 | 389 | 389 | **450+** |
| Collectors | 26 | 26 | 30 | 35 |
| Correlation rules | 20 (16 Python + 4 YAML) | 20 | 40 | **50+** |
| Attack scenarios | **8** | 8 | 16 | 20+ |
| Unit tests | 1,782+ | 1,800+ | 2,000+ | 3,000+ |
| Integration tests | 155+ | 160+ | 300+ | 500+ |
| Golden tests | 80 | 80 | 100+ | 150+ |
| Validation scenarios | **5** | **5** | 10 | 20+ |
| Detection rate | N/A | **>90%** | >90% | >95% |
| Test coverage (stmt) | 85% | 85% | 90% | 92%+ |
| Test coverage (branch) | 82% | 82% | 88% | 90%+ |
| mypy --strict | 0 errors | 0 errors | 0 errors | 0 errors |
| False positive rate | ~3% | <3% | <2% | <1% |
| False negative rate | N/A | **<10%** | <5% | <2% |
| Snap Store availability | N/A | **edge** | **stable** | — |
| Attack scenario coverage | 8 | 8 | 16 | 20+ |
| Correlation engine maturity | **Full chain** | Validated | Temporal + YAML | Full kill chain |

### v0.5.1 — Stabilization + P2 Gaps (2026-07-12)

**P0 — Bug fixes:**
- **FS-202**: Fixed kernel thread false positives — 299 noise findings eliminated by filtering ppid==2 and /proc/ binary paths
- **SECR-502**: Fixed system CA certificate false positives — 245 findings eliminated by excluding `/etc/ssl/certs/` and `/usr/share/ca-certificates/`

**P1 — Noise reduction:**
- **FS-402**: Excluded `/node_modules/` paths from world-writable directory checks (~810 → realistic count)
- **FS-201**: Added `._` Apple Double and `__MACOSX` path exclusions for hidden file checks
- **PER-503**: Skipped `/usr/lib/udev/rules.d/` (package-managed system rules) from udev persistence check
- **SVC-102**: Added 30+ missing standard Ubuntu services + `snap.` prefix matching

**P2 — New checks (5 added, 122 total):**
- **KERN-501**: Dangerous kernel modules loaded (bluetooth, firewire, obsolete protocols)
- **CTN-302**: Docker daemon security config (userns-remap, no-new-privileges, icc, etc.)
- **NET-550**: Listening port to process mapping (cross-references /proc/net with /proc/*/fd/)
- **SEC-102**: AppArmor profile coverage per service (detects unconfined services)
- **LOG-503**: Auditd MITRE ATT&CK coverage gaps (maps rules to 15 techniques)

**Infrastructure:**
- **STATE.md**: Resolved TD-022–TD-026 (all collectors exist, entries were stale)
- **Tests**: 1024 total, all passing (was 1020)

---

### v0.6.0 — Correlation Engine 2.0 (2026-07-12)

**Phase 5 — Full Attack Chain Detection:** ✅

**YAML-defined rules:**
- `YamlRuleLoader` auto-loads rules from `policies/correlation/*.yaml`
- `CorrelationRuleYAML` class supports pattern-matching conditions, field filtering, evidence type filtering
- 4 sample YAML rules shipped: DNS manipulation, credential dump, privilege escalation, network recon

**Temporal correlation:**
- `temporal_weight` config per rule (`max_age_hours`, `boost_max`)
- Fresh findings (< max_age_hours) boost confidence proportionally

**Risk accumulation:**
- `1 - (0.5)^N` formula applied to correlated findings
- Severity escalation: MEDIUM→HIGH at 5+ signals, HIGH→CRITICAL at 8+

**Counter-evidence:**
- `CounterEvidence` model with known-good package/binary/service/file path lists
- Filtering applied before rule evaluation to reduce false positives

**Attack scenario scoring (8 scenarios):**
- Ransomware, cryptominer, persistence/backdoor, supply chain, bootkit, container escape, data theft, active breach
- Scenarios scored as units with kill chain phase mapping (14 MITRE ATT&CK phases)
- Injected as synthetic `SCENARIO-*` check results with COMPROMISE category

**Infrastructure:**
- **Tests**: 1022 total, all passing
- **mypy --strict**: 0 new errors (pre-existing yaml-stubs/runner attr errors unchanged)
- **Version**: 0.6.1

---

### v0.23.0 — Phase P1: Framework Hardening (2026-07-12)

**Phase P1 — 3 P3 framework hardening tasks:**

**P1.1 — Fix `datetime.utcnow()` deprecation warnings:**
- `terminal.py:261`: Changed `datetime.datetime.utcnow()` → `datetime.datetime.now(datetime.UTC)`
- `markdown.py:190`: Changed `datetime.utcnow()` → `datetime.now(UTC)` with `UTC` import
- Eliminates 2 DeprecationWarning instances; Python 3.13 `datetime.UTC` available

**P1.2 — Enable drift detection by default in config:**
- `BaselineConfig.compare` default changed from `False` → `True`
- `BaselineConfig.fail_on_drift` wired into CLI: exits with code 1 on drift
- `BaselineConfig.auto_baseline` wired into CLI: auto-creates baseline if missing
- `--baseline-diff` CLI flag still works; config `compare` flag is checked first
- All 3 fields were previously defined in the model but dead (never read anywhere)

**P1.3 — Default config with high-FP checks pre-limited:**
- Added 8 `plugins.overrides.max_findings` entries to shipped `usaf.yaml`:
  - `PRM-201` → 100, `FS-601` → 100, `FS-101` → 100, `FS-102` → 100
  - `PKG-101` → 50, `PER-101` → 50, `NET-101` → 50, `SVC-102` → 50
- Targets checks WITHOUT internal `max_findings` that can produce large volumes

**Infrastructure:**
- **Tests**: 1942 passed, 0 failed, 0 deprecation warnings (down from 14)
- **mypy --strict**: 0 new errors (24 pre-existing unchanged)
- **ruff**: 0 new errors (pre-existing PLR0911/T201/E402/F401 unchanged)
- **Version**: 0.23.0

---

### v0.22.0 — Phase P0 Completion & Architectural Hardening (2026-07-12)

**Phase P0 — Architectural Violations Resolved:**
- **P0.1 (SSH Collector)**: Verified SSH checks (`SSH-101/102/201` and `SSH-103..606`) already use the `ssh_config` collector — no checks directly parse `/etc/ssh/sshd_config`. Architecture rule "checks never collect" is enforced.
- **P0.2 (Config Access)**: Verified `_usaf_config` backdoor is fully removed from source code. Config is properly passed via `AuditCheck.evaluate(collectors, config)` type-safe API.

**Dead code elimination:**
- `SeverityConfig` (defined in `config/model.py`) was defined but never consumed by the scoring engine. Now wired into `ScoringEngine.__init__(severity_config=...)` with the same defaults. Users can override severity score weights via `usaf.yaml`.
- `PluginOverride.severity` type fixed from `str` to `Severity` enum.

**Version alignment:**
- `__about__.py`: 0.6.0 → 0.22.0 (synced with `pyproject.toml`)
- `STATE.md`: Versioning line updated to 0.22.0
- `STATE.md`: `_usaf_config` documentation updated

**Test cleanup:**
- Removed `_usaf_config` dead data from `test_phase2_integration.py` mock fixtures

**Infrastructure:**
- Added `ClassVar` annotations to `ScoringEngine.SEVERITY_WEIGHTS` and `CATEGORY_WEIGHTS` (ruff RUF012 fix)
- **Tests**: 1942 passed, 0 failed, 14 warnings (pre-existing `datetime.utcnow()` deprecation)
- **mypy --strict**: 0 new errors (24 pre-existing errors unchanged)
- **ruff**: 0 new errors (pre-existing PLR0911/E402/F401 unchanged)
- **False positive rate**: Pre-existing ~3% (no regressions)

---

### v0.23.1 — FP Reduction: Quick Fixes (2026-07-12)

**P0 — Placeholder / artifact removal:**
- **PKG-XXX**: Removed `cve_ids=["CVE-XXXX-XXXX"]` placeholder from `PendingSecurityUpdatesCheck` in `integrity_checks.py:560`. The check doesn't know the specific CVEs fixed by an update, so the placeholder was misleading.
- **PER-303**: Removed `"DEBUG.sh"` from `KNOWN_PROFILE_SCRIPTS` in `shell_init_persistence.py:39`. Verified `DEBUG.sh` is not shipped by any Ubuntu package, so it should be flagged for review if present.

**Infrastructure:**
- **Tests**: All 1942 passed, 0 regressions
- **mypy --strict**: 0 new errors
- **ruff**: 0 new errors (pre-existing only)
- **Version**: 0.23.1

---

### v0.25.0 — Phase 7a: KVM Validation Lab + Snap Prep (2026-07-21)

**Phase 7a — Validation Lab (KVM/libvirt rewrite):**
- Switched from Vagrant+VirtualBox to **KVM/libvirt + cloud-init** (Ubuntu native)
- Rewrote `provisioner.py` → `LibvirtProvisioner` using `virt-install`, cloud-init seed ISOs, `virsh`
- All 5 scenarios fully implemented; 11 shared vulnerability scripts (638 total lines)
- Fixed 9 expected-finding mismatches across `insecure-server` and `backdoored-host`
- Removed dead code: `get_vagrantfile_content()`, `get_provision_commands()`, Vagrant templates
- Hardened `runner.py` JSON parsing (regex fallback for stderr contamination)
- Added explicit `provision()` step between VM creation and USAF install
- Updated docs: KVM prerequisites, Ubuntu 24.04 Noble cloud images

**Problems encountered and resolved during implementation:**

1. **`qemu-kvm` is a virtual package** — on newer Ubuntu releases (26.04+) it requires explicit selection of `qemu-system-x86` or `qemu-system-x86-hwe`. Fixed: documented `qemu-system-x86` as the concrete package.

2. **`cloud-localds --version` not supported** — tool exits with code 1 when given `--version`. The dep checker used `subprocess.run([cmd, "--version"], check=True)` which falsely flagged it as missing. Fixed: switched to `shutil.which()` which just verifies the binary exists in PATH.

3. **`cloud-localds --filesystem vfat` requires `mtools`** — the vfat filesystem mode needs `mcopy` from the `mtools` package, which isn't installed by default. Fixed: removed `--filesystem vfat`, falling back to default iso9660 which works without extra deps.

4. **Permission denied on `/var/lib/libvirt/images/`** — writing qcow2 disks and running `virt-install` requires root. Fixed: added `sudo=True` parameter to `_run()` method, applied to all `virsh`, `virt-install`, and `qemu-img` calls.

5. **libvirt-qemu user can't access backing files in user home** — qcow2 overlay disks with backing files in `~/.cache/usaf-lab/` are inaccessible to the `libvirt-qemu` system user (uid:64055, gid:991). Fixed: copy the base cloud image to `/var/lib/libvirt/images/noble-server-cloudimg-amd64.img` and use that as the backing file.

6. **Stale qcow2 overlays from failed runs** — when `virt-install` fails midway, the overlay disk remains with a backing file pointer to an old (possibly deleted) path. Re-running `up()` skips creation because the file exists. Fixed: always delete and re-create the overlay disk in `up()`.

7. **Partial `virt-install` leaves orphan domains** — a failed `virt-install` may create a libvirt domain that is shut off. Next `up()` call sees `_vm_exists() == True` and tries to `virsh start` it, which fails. Fixed: `up()` now calls `destroy()` first if the VM exists but isn't running with a valid IP.

8. **SSH `StrictHostKeyChecking` warnings contaminate JSON output** — when SCP first connects to a new VM, `ssh` prints "Warning: Permanently added 'X' (ED25519) to the list of known hosts." to stderr. The `2>&1` merge contaminated JSON parsing. Fixed: use `--output` file-based approach or suppress stderr with `2>/dev/null` where appropriate.

9. **Cloud-init not ready when IP is available** — after `virt-install`, the VM gets a DHCP IP before cloud-init finishes package installation. Early SSH connections fail or return partial state. Fixed: added `_wait_for_cloud_init()` that polls `cloud-init status` with retry.

10. **`sudo usaf: command not found`** — `pip install -e .` puts `usaf` in `/usr/local/bin/` but `sudo` has a restricted `secure_path` that doesn't include it. Fixed: use `sudo env PATH=$PATH usaf` to pass the user's PATH through sudo.

11. **`/opt/` requires root for write** — uploading vulnerability scripts to `/opt/usaf-lab/` via SCP failed because the `ubuntu` user can't create directories there. Fixed: `provision()` now does `sudo mkdir -p && sudo chown ubuntu:ubuntu` before uploading, and `scp_to()` uses `sudo mkdir -p` for the parent directory.

12. **`pip3 install` dependency pre-install step was fragile** — pre-installing `typer rich pydantic...` separately failed on version conflicts. Fixed: removed the separate pip install step; `pip install -e .` handles all dependencies via `pyproject.toml`.

13. **Temp file permission conflicts** — writing user-data to `/tmp/usaf-<scenario>-user-data` used the same filename across runs, causing PermissionError when a previous run left root-owned files. Fixed: always write new temp files (no reuse).

14. **`subprocess.run()` `check` parameter conflict** — `ssh_execute()` passed `check=check` to `_run()`, which forwarded it to `subprocess.run(cmd, check=False, **kw)`, causing "multiple values for keyword argument 'check'". Fixed: moved `check=False` into the `kw` dict before `**kwargs` update.

15. **`usaf scan --format json` outputs only to stdout** — no stderr output means `2>&1` is harmless but `2>/dev/null` suppresses everything. Fixed: use `2>&1` to merge streams, parse JSON from combined output.

**Infrastructure:**
- **Tests**: 1942 passed (unchanged)
- **mypy --strict**: 0 new errors
- **ruff**: 0 new errors (pre-existing only)
- **Version**: 0.25.0
- **Requires**: `qemu-system-x86 libvirt-daemon-system virt-install cloud-image-utils` for VM provisioning

---

## Contributing to This Document

This is a living document. Update it when:
- New features are completed (move to ✅, note date)
- Technical debt is resolved (move to ✅)
- Targets are met (update Metrics & Targets)
