from __future__ import annotations

from typing import Any

# CIS Level 1 - Server controls
# These are the core CIS controls for Ubuntu 22.04 L1 Server
CIS_LEVEL1_SERVER_CONTROLS: dict[str, dict[str, Any]] = {
    "CIS Ubuntu 22.04: 1.1.1": {
        "title": "Ensure mounting of unused filesystems is disabled",
        "check_ids": ["KERN-301"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 1.5.1": {
        "title": "Ensure address space layout randomization (ASLR) is enabled",
        "check_ids": ["KERN-101"],
        "mitre_attack_ids": ["T1574"],
    },
    "CIS Ubuntu 22.04: 1.5.2": {
        "title": "Ensure ptrace_scope is restricted",
        "check_ids": ["KERN-201"],
        "mitre_attack_ids": ["T1055"],
    },
    "CIS Ubuntu 22.04: 1.5.3": {
        "title": "Ensure core dumps are restricted",
        "check_ids": ["KERN-301"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 1.6.1": {
        "title": "Ensure AppArmor is enabled",
        "check_ids": ["SEC-101"],
        "mitre_attack_ids": ["T1562.001"],
    },
    "CIS Ubuntu 22.04: 3.1.1": {
        "title": "Ensure IPv6 status is identified",
        "check_ids": ["NET-402"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.2.1": {
        "title": "Ensure packet redirect sending is disabled",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": ["T1090"],
    },
    "CIS Ubuntu 22.04: 3.3.1": {
        "title": "Ensure source routed packets are not accepted",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": ["T1021"],
    },
    "CIS Ubuntu 22.04: 3.3.2": {
        "title": "Ensure ICMP redirects are not accepted",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.3.3": {
        "title": "Ensure secure ICMP redirects are not accepted",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.3.4": {
        "title": "Ensure suspicious packets are logged",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.4.1": {
        "title": "Ensure broadcast ICMP requests are ignored",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.4.2": {
        "title": "Ensure bogus ICMP responses are ignored",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.4.3": {
        "title": "Ensure TCP SYN cookies is enabled",
        "check_ids": ["NET-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.5.1": {
        "title": "Ensure ufw or nftables is installed and active",
        "check_ids": ["FW-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.1.1": {
        "title": "Ensure cron daemon is enabled and running",
        "check_ids": ["PER-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.1": {
        "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
        "check_ids": ["SSH-101", "SSH-102", "SSH-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.2": {
        "title": "Ensure SSH Protocol is set to 2",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": ["T1190"],
    },
    "CIS Ubuntu 22.04: 5.2.3": {
        "title": "Ensure SSH LogLevel is appropriate",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.4": {
        "title": "Ensure SSH X11 forwarding is disabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.5": {
        "title": "Ensure SSH MaxAuthTries is set to 4 or less",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": ["T1110"],
    },
    "CIS Ubuntu 22.04: 5.2.6": {
        "title": "Ensure SSH IgnoreRhosts is enabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.7": {
        "title": "Ensure SSH HostbasedAuthentication is disabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.8": {
        "title": "Ensure SSH root login is disabled",
        "check_ids": ["SSH-102"],
        "mitre_attack_ids": ["T1078"],
    },
    "CIS Ubuntu 22.04: 5.2.9": {
        "title": "Ensure SSH PermitEmptyPasswords is disabled",
        "check_ids": ["SSH-102"],
        "mitre_attack_ids": ["T1110"],
    },
    "CIS Ubuntu 22.04: 5.2.10": {
        "title": "Ensure SSH PermitUserEnvironment is disabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.11": {
        "title": "Ensure only approved MAC algorithms are used",
        "check_ids": ["SSH-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.12": {
        "title": "Ensure SSH Idle Timeout Interval is configured",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.13": {
        "title": "Ensure SSH LoginGraceTime is set to one minute or less",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.14": {
        "title": "Ensure SSH warning banner is configured",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.3.1": {
        "title": "Ensure sudo authentication timeout is configured",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.3.2": {
        "title": "Ensure sudo authentication timeout is configured correctly",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.4.1": {
        "title": "Ensure password creation requirements are configured",
        "check_ids": ["PWD-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.4.2": {
        "title": "Ensure lockout for failed password attempts is configured",
        "check_ids": ["PWD-101"],
        "mitre_attack_ids": ["T1110"],
    },
    "CIS Ubuntu 22.04: 5.4.3": {
        "title": "Ensure password hashing algorithm is SHA-512 or yescrypt",
        "check_ids": ["PWD-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.5.1": {
        "title": "Ensure password expiration is 365 days or less",
        "check_ids": ["USR-105"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.5.2": {
        "title": "Ensure minimum days between password changes is configured",
        "check_ids": ["USR-105"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.5.3": {
        "title": "Ensure password expiration warning days is 7 or more",
        "check_ids": ["USR-105"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.5.4": {
        "title": "Ensure inactive password lock is configured",
        "check_ids": ["USR-105"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.6.1": {
        "title": "Ensure access to the su command is restricted",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.1": {
        "title": "Ensure permissions on /etc/passwd are configured",
        "check_ids": ["USR-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.2": {
        "title": "Ensure permissions on /etc/shadow are configured",
        "check_ids": ["USR-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.3": {
        "title": "Ensure permissions on /etc/group are configured",
        "check_ids": ["USR-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.4": {
        "title": "Ensure permissions on /etc/gshadow are configured",
        "check_ids": ["USR-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.5": {
        "title": "Ensure permissions on /etc/passwd- are configured",
        "check_ids": ["FS-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.6": {
        "title": "Ensure permissions on /etc/shadow- are configured",
        "check_ids": ["FS-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.7": {
        "title": "Ensure permissions on /etc/group- are configured",
        "check_ids": ["FS-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.8": {
        "title": "Ensure permissions on /etc/gshadow- are configured",
        "check_ids": ["FS-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.9": {
        "title": "Ensure permissions on /etc/shells are configured",
        "check_ids": ["FS-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.10": {
        "title": "Ensure no duplicate UIDs exist",
        "check_ids": ["USR-103"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.11": {
        "title": "Ensure no duplicate GIDs exist",
        "check_ids": ["USR-103"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.12": {
        "title": "Ensure no duplicate user names exist",
        "check_ids": ["USR-103"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.13": {
        "title": "Ensure no duplicate group names exist",
        "check_ids": ["USR-103"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.1": {
        "title": "Ensure accounts in /etc/passwd use shadowed passwords",
        "check_ids": ["USR-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.2": {
        "title": "Ensure password fields are not empty",
        "check_ids": ["USR-201"],
        "mitre_attack_ids": ["T1110"],
    },
    "CIS Ubuntu 22.04: 6.2.3": {
        "title": "Ensure all users' home directories exist",
        "check_ids": ["USR-104"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.4": {
        "title": "Ensure no legacy '+' entries exist in /etc/passwd",
        "check_ids": ["USR-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.5": {
        "title": "Ensure no legacy '+' entries exist in /etc/shadow",
        "check_ids": ["USR-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.6": {
        "title": "Ensure no legacy '+' entries exist in /etc/group",
        "check_ids": ["USR-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.7": {
        "title": "Ensure root is the only UID 0 account",
        "check_ids": ["USR-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.8": {
        "title": "Ensure root PATH integrity",
        "check_ids": ["FS-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.9": {
        "title": "Ensure all users' dot files are not group/world-writable",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.10": {
        "title": "Ensure no users have .netrc files",
        "check_ids": ["FS-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.11": {
        "title": "Ensure no users have .forward files",
        "check_ids": ["FS-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.12": {
        "title": "Ensure no users have .rhosts files",
        "check_ids": ["FS-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.13": {
        "title": "Ensure users' netrc files are not group/world accessible",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.2.14": {
        "title": "Ensure no users have duplicate UIDs in /etc/passwd",
        "check_ids": ["USR-103"],
        "mitre_attack_ids": [],
    },
}

# CIS Level 2 - Server controls (includes all Level 1 + additional Level 2)
CIS_LEVEL2_SERVER_CONTROLS: dict[str, dict[str, Any]] = {
    **CIS_LEVEL1_SERVER_CONTROLS,
    "CIS Ubuntu 22.04: 1.1.2": {
        "title": "Ensure /tmp is configured on a separate partition with nodev/noexec/nosuid",
        "check_ids": ["FS-501"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 1.1.3": {
        "title": "Ensure /var is configured on a separate partition",
        "check_ids": ["FS-501"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 1.2.1": {
        "title": "Ensure package manager repositories are configured",
        "check_ids": ["PKG-301"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 1.3.1": {
        "title": "Ensure sudo is installed",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.1.2": {
        "title": "Ensure wireless interfaces are disabled",
        "check_ids": ["NET-402"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.1.1": {
        "title": "Ensure auditd is installed and active",
        "check_ids": ["FOR-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.1.2": {
        "title": "Ensure audit logs are not automatically deleted",
        "check_ids": ["LOG-502"],
        "mitre_attack_ids": ["T1070"],
    },
    "CIS Ubuntu 22.04: 4.1.3": {
        "title": "Ensure auditd is configured to use contiguous disk space",
        "check_ids": ["LOG-502"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.4.1": {
        "title": "Ensure permissions on /etc/cron.d are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.4.2": {
        "title": "Ensure permissions on /etc/cron.daily are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.4.3": {
        "title": "Ensure permissions on /etc/cron.hourly are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.4.4": {
        "title": "Ensure permissions on /etc/cron.monthly are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.4.5": {
        "title": "Ensure permissions on /etc/cron.weekly are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.4.6": {
        "title": "Ensure permissions on /etc/crontab are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.5.1": {
        "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 4.5.2": {
        "title": "Ensure permissions on SSH host keys are configured",
        "check_ids": ["PRM-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.1.2": {
        "title": "Ensure permissions on /etc/crontab are configured",
        "check_ids": ["PRM-201"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.1.3": {
        "title": "Ensure cron is restricted to authorized users",
        "check_ids": ["PER-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.1.4": {
        "title": "Ensure at/cron is restricted to authorized users",
        "check_ids": ["PER-101", "PER-103"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.15": {
        "title": "Ensure SSH MaxStartups is configured",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.16": {
        "title": "Ensure SSH MaxSessions is configured",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.17": {
        "title": "Ensure SSH PAM is enabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.18": {
        "title": "Ensure SSH AllowTcpForwarding is disabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.19": {
        "title": "Ensure SSH AllowAgentForwarding is disabled",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.2.20": {
        "title": "Ensure SSH ClientAliveCountMax is configured",
        "check_ids": ["SSH-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.3.3": {
        "title": "Ensure sudo log file exists",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.3.4": {
        "title": "Ensure users must provide password for privilege escalation",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.3.5": {
        "title": "Ensure re-authentication for privilege escalation is not disabled globally",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.4.5": {
        "title": "Ensure default user umask is configured",
        "check_ids": ["PWD-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 5.6.2": {
        "title": "Ensure root login is restricted to system console",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.14": {
        "title": "Ensure audit log files are mode 0640 or less permissive",
        "check_ids": ["LOG-302"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 6.1.15": {
        "title": "Ensure audit log files are owned by root:root",
        "check_ids": ["LOG-302"],
        "mitre_attack_ids": [],
    },
}

# CIS Level 1 - Desktop controls
CIS_LEVEL1_DESKTOP_CONTROLS: dict[str, dict[str, Any]] = {
    **CIS_LEVEL1_SERVER_CONTROLS,
    "CIS Ubuntu 22.04: 1.8.1": {
        "title": "Ensure GNOME Display Manager is removed or configured",
        "check_ids": ["SVC-102"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 1.8.2": {
        "title": "Ensure XDMCP is disabled",
        "check_ids": ["NET-101"],
        "mitre_attack_ids": [],
    },
    "CIS Ubuntu 22.04: 3.1.2": {
        "title": "Ensure wireless interfaces are disabled",
        "check_ids": ["NET-402"],
        "mitre_attack_ids": [],
    },
}

# STIG controls for Ubuntu 22.04
STIG_CONTROLS: dict[str, dict[str, Any]] = {
    "STIG: UBTU-22-255010": {
        "title": "The Ubuntu operating system must enforce password complexity",
        "check_ids": ["PWD-101"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255020": {
        "title": "The Ubuntu OS must configure auditd with proper rules",
        "check_ids": ["LOG-501"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255030": {
        "title": "The Ubuntu OS must disable kernel core dumps",
        "check_ids": ["KERN-301"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255040": {
        "title": "The Ubuntu OS must enable ASLR",
        "check_ids": ["KERN-101"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255050": {
        "title": "The Ubuntu OS must disable SSH root login",
        "check_ids": ["SSH-102"],
        "mitre_attack_ids": ["T1078"],
    },
    "STIG: UBTU-22-255060": {
        "title": "The Ubuntu OS must employ FIPS-validated cryptography",
        "check_ids": ["SSH-201"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255070": {
        "title": "The Ubuntu OS must configure auditd to record system calls",
        "check_ids": ["LOG-501"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255080": {
        "title": "The Ubuntu OS must restrict privilege escalation",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": ["T1548"],
    },
    "STIG: UBTU-22-255090": {
        "title": "The Ubuntu OS must configure firewall to restrict network traffic",
        "check_ids": ["FW-101"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255100": {
        "title": "The Ubuntu OS must ensure audit log files are protected",
        "check_ids": ["LOG-302"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255110": {
        "title": "The Ubuntu OS must remove unnecessary packages",
        "check_ids": ["PKG-101"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255120": {
        "title": "The Ubuntu OS must enforce password expiration",
        "check_ids": ["USR-105"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255130": {
        "title": "The Ubuntu OS must ensure AppArmor is enabled",
        "check_ids": ["SEC-101"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255140": {
        "title": "The Ubuntu OS must disable unused filesystem modules",
        "check_ids": ["KERN-401"],
        "mitre_attack_ids": [],
    },
    "STIG: UBTU-22-255150": {
        "title": "The Ubuntu OS must monitor SUID programs",
        "check_ids": ["PRM-101"],
        "mitre_attack_ids": ["T1548"],
    },
}

# PCI DSS 4.0 controls
PCI_DSS_CONTROLS: dict[str, dict[str, Any]] = {
    "PCI DSS 4.0: 1.1": {
        "title": "Firewall configuration standards are maintained",
        "check_ids": ["FW-101"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 1.2": {
        "title": "Firewall rules restrict inbound/outbound traffic",
        "check_ids": ["FW-101", "NET-101"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 2.1": {
        "title": "System configuration standards are applied",
        "check_ids": ["KERN-101", "KERN-201", "KERN-301"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 2.2": {
        "title": "Unnecessary services are disabled",
        "check_ids": ["SVC-102", "SVC-101"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 2.3": {
        "title": "Unnecessary default accounts are removed or disabled",
        "check_ids": ["USR-104"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 4.1": {
        "title": "Strong cryptography is used for transmission",
        "check_ids": ["SSH-201"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 4.2": {
        "title": "SSH is configured securely",
        "check_ids": ["SSH-101", "SSH-102", "SSH-201"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 7.1": {
        "title": "Access to cardholder data is restricted",
        "check_ids": ["USR-401", "PRM-101"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 7.2": {
        "title": "Access control system is in place",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 8.1": {
        "title": "Users are identified and authenticated",
        "check_ids": ["USR-101", "USR-102"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 8.2": {
        "title": "Strong password policies are enforced",
        "check_ids": ["PWD-101", "USR-201"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 8.3": {
        "title": "MFA is implemented",
        "check_ids": ["USR-301"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 10.1": {
        "title": "Audit trails are enabled",
        "check_ids": ["FOR-101", "LOG-501"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 10.2": {
        "title": "Audit logging covers all system components",
        "check_ids": ["LOG-501"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 10.3": {
        "title": "Audit logs are protected from modification",
        "check_ids": ["LOG-302", "LOG-301"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 10.4": {
        "title": "Audit logs are reviewed regularly",
        "check_ids": ["LOG-401", "LOG-402"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 10.5": {
        "title": "Audit log retention is configured",
        "check_ids": ["LOG-101", "LOG-201"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 11.1": {
        "title": "File integrity monitoring is in place",
        "check_ids": ["FS-302", "PKG-201"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 11.3": {
        "title": "Vulnerability scanning is performed",
        "check_ids": ["PKG-401", "PKG-402"],
        "mitre_attack_ids": [],
    },
    "PCI DSS 4.0: 12.1": {
        "title": "Security policies are documented and maintained",
        "check_ids": [],
        "mitre_attack_ids": [],
    },
}

# SOC2 controls
SOC2_CONTROLS: dict[str, dict[str, Any]] = {
    "SOC2: CC1.1": {
        "title": "Control environment — security policies exist",
        "check_ids": ["CMP-101"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC2.1": {
        "title": "Communication and information — security incidents are logged",
        "check_ids": ["FOR-101", "LOG-501"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC3.1": {
        "title": "Risk assessment — vulnerabilities are identified",
        "check_ids": ["PKG-401", "PKG-402"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC4.1": {
        "title": "Monitoring activities — system monitoring is active",
        "check_ids": ["LOG-401", "LOG-402"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC5.1": {
        "title": "Control activities — access controls are enforced",
        "check_ids": ["USR-401", "USR-301"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC6.1": {
        "title": "Logical and physical access controls — authentication required",
        "check_ids": ["USR-101", "USR-102", "PWD-101"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC6.2": {
        "title": "Logical and physical access — least privilege principle",
        "check_ids": ["PRM-101", "PRM-201"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC6.3": {
        "title": "Logical and physical access — data encryption in transit",
        "check_ids": ["SSH-201"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC7.1": {
        "title": "System operations — detection and monitoring procedures",
        "check_ids": ["COM-101"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC7.2": {
        "title": "System operations — incident response procedures",
        "check_ids": ["LOG-301"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC7.3": {
        "title": "System operations — configuration management",
        "check_ids": ["PKG-301", "PKG-201"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC8.1": {
        "title": "Change management — system changes are authorized",
        "check_ids": ["FS-302", "FS-101"],
        "mitre_attack_ids": [],
    },
    "SOC2: CC9.1": {
        "title": "Risk mitigation — controls address identified risks",
        "check_ids": ["KERN-101", "KERN-201", "KERN-301"],
        "mitre_attack_ids": [],
    },
}

# HIPAA controls
HIPAA_CONTROLS: dict[str, dict[str, Any]] = {
    "HIPAA: 164.308(a)(1)": {
        "title": "Security management process — risk analysis",
        "check_ids": ["PKG-401", "PKG-402"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.308(a)(3)": {
        "title": "Workforce security — authorized access",
        "check_ids": ["USR-401", "USR-104"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.308(a)(4)": {
        "title": "Information access management — access controls",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.308(a)(5)": {
        "title": "Security awareness and training — password management",
        "check_ids": ["PWD-101"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.308(a)(6)": {
        "title": "Security incident procedures — incident detection",
        "check_ids": ["COM-101", "LOG-301"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.308(a)(7)": {
        "title": "Contingency plan — data backup and recovery",
        "check_ids": ["LOG-101"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.308(a)(8)": {
        "title": "Evaluation — periodic security evaluation",
        "check_ids": ["CMP-101"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.310(a)(1)": {
        "title": "Facility access controls — physical safeguards",
        "check_ids": ["BOOT-101", "BOOT-201"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.310(b)": {
        "title": "Workstation use — workstation security",
        "check_ids": ["PRM-101", "PRM-201"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.310(c)": {
        "title": "Workstation security — device and media controls",
        "check_ids": ["USB-101"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(a)(1)": {
        "title": "Access control — unique user identification",
        "check_ids": ["USR-101", "USR-103", "PWD-101"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(a)(2)": {
        "title": "Access control — emergency access procedure",
        "check_ids": ["USR-401"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(a)(4)": {
        "title": "Access control — encryption and decryption",
        "check_ids": ["SSH-201", "SSH-101"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(b)": {
        "title": "Audit controls — audit logs",
        "check_ids": ["FOR-101", "LOG-501", "LOG-401"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(c)(1)": {
        "title": "Integrity controls — protect ePHI from improper alteration",
        "check_ids": ["FS-302", "PKG-201"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(c)(2)": {
        "title": "Integrity controls — mechanism to authenticate ePHI",
        "check_ids": ["PKG-202"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(d)": {
        "title": "Person or entity authentication — user authentication",
        "check_ids": ["USR-301", "USR-201"],
        "mitre_attack_ids": [],
    },
    "HIPAA: 164.312(e)(1)": {
        "title": "Transmission security — integrity and encryption controls",
        "check_ids": ["SSH-201", "NET-402"],
        "mitre_attack_ids": [],
    },
}
