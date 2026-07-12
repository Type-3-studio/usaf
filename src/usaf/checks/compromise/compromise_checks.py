from __future__ import annotations

import os
import re
import stat
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import ProcessEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

SUSPICIOUS_BINARY_DIRS: tuple[str, ...] = (
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user",
    "/proc",
)

EXPANDED_MALICIOUS_NAMES: dict[str, str] = {
    "minerd": "Cryptocurrency miner (CryptoNight)",
    "xmrig": "Cryptocurrency miner (Monero)",
    "xmr-stak": "Cryptocurrency miner",
    "cryptonight": "Cryptocurrency miner",
    "kdevtmpfsi": "Known miner malware",
    "kinsing": "Cloud malware (container exploitation)",
    "donut": "Malware loader/runner",
    "mbrt": "Rootkit component",
    "sliver": "C2 implant (Sliver framework)",
    "merlin": "C2 agent (Merlin)",
    "pwnxd": "Known backdoor",
    "csclient": "Cobalt Strike beacon",
    "cstrike": "Cobalt Strike beacon",
    "beacon": "C2 beacon",
    "eggdrop": "IRC bot/malware",
    "mirai": "Mirai botnet variant",
    "bashirc": "IRC-based backdoor",
    "sadog": "Miner malware",
    "watchdog": "Miner malware (watchdog component)",
    "pnscan": "Port scanner (malware propagation)",
    "masscan": "Port scanner (often abused by malware)",
    "zgrab": "Network scanner (often abused)",
    "systat": "Remote access tool",
    "inetd": "Often spoofed by malware",
    "ntpd": "Often spoofed by malware",
    "crond": "Often spoofed by persistence malware",
    "rsync": "Often abused for data exfiltration",
}

SUSPICIOUS_CMDLINE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bcurl\s+\S+\s*\|\s*(bash|sh)\b", re.IGNORECASE),
    re.compile(r"\bwget\s+\S+\s*\|\s*(bash|sh)\b", re.IGNORECASE),
    re.compile(r"(base64|echo)\s+[A-Za-z0-9+/]{50,}={0,2}\s*\|", re.IGNORECASE),
    re.compile(r"dev/tcp/", re.IGNORECASE),
    re.compile(r"dev/udp/", re.IGNORECASE),
    re.compile(r"exec\s+5<>", re.IGNORECASE),
    re.compile(r"mkfifo\s", re.IGNORECASE),
    re.compile(r"nmap\s+--script\s+.*brute", re.IGNORECASE),
    re.compile(r"python\s+-c\s+['\"].{100,}", re.IGNORECASE),
    re.compile(r"msfconsole|msfvenom|metasploit", re.IGNORECASE),
    re.compile(r"chmod\s+\S*suid\S*\s", re.IGNORECASE),
    re.compile(r"nohup\s+.*minerd|xmrig", re.IGNORECASE),
]

WELL_KNOWN_BINARIES: dict[str, str] = {
    "sshd": "/usr/sbin/sshd",
    "ssh": "/usr/bin/ssh",
    "cron": "/usr/sbin/cron",
    "crond": "/usr/sbin/cron",
    "ntpd": "/usr/sbin/ntpd",
    "ntp": "/usr/sbin/ntpd",
    "systemd": "/lib/systemd/systemd",
    "bash": "/usr/bin/bash",
    "sh": "/usr/bin/sh",
    "python3": "/usr/bin/python3",
    "python": "/usr/bin/python3",
    "nginx": "/usr/sbin/nginx",
    "apache2": "/usr/sbin/apache2",
    "httpd": "/usr/sbin/httpd",
    "dockerd": "/usr/bin/dockerd",
    "docker": "/usr/bin/docker",
    "containerd": "/usr/bin/containerd",
    "kubelet": "/usr/bin/kubelet",
    "node": "/usr/bin/node",
    "npm": "/usr/bin/npm",
    "java": "/usr/bin/java",
    "mysqld": "/usr/sbin/mysqld",
    "postgres": "/usr/lib/postgresql/*/bin/postgres",
    "redis-server": "/usr/bin/redis-server",
}


@register_check
class SuspiciousBinaryLocationCheck(AuditCheck):
    id = "COM-201"
    name = "Processes From Suspicious Locations"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Detects processes running from suspicious directories like /tmp or /dev/shm"
    depends = ["processes"]
    tags = ["compromise", "malware", "incident-response"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            binary: str | None = p.get("binary", None)
            if not binary:
                continue
            for suspicious_dir in SUSPICIOUS_BINARY_DIRS:
                if binary.startswith(suspicious_dir):
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Process running from suspicious location: {binary}",
                            description=(
                                f"PID {p.get('pid')} ({p.get('name')}) is running "
                                f"from '{binary}' in a suspicious directory"
                            ),
                            rationale=(
                                "Processes running from /tmp, /dev/shm, or /var/tmp "
                                "are highly suspicious. Malware often executes from "
                                "world-writable directories. Legitimate software "
                                "should run from /usr/bin, /usr/sbin, or similar."
                            ),
                            remediation=(
                                f"Investigate PID {p.get('pid')}: "
                                f"'ls -la {binary}' and 'cat /proc/{p.get('pid')}/cmdline'. "
                                f"Kill if malicious: 'kill -9 {p.get('pid')}'."
                            ),
                            evidence=ProcessEvidence(
                                pid=p.get("pid", 0),
                                name=p.get("name", ""),
                                binary=binary,
                                cmdline=p.get("cmdline", ""),
                                user=str(p.get("uid", "")),
                                state=p.get("state", ""),
                            ),
                            detected_value=f"{binary} (PID {p.get('pid')})",
                            expected_value="Processes from /usr/bin, /usr/sbin, etc.",
                            affected_component=binary,
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.15,
                            mitre_attack_ids=["T1059", "T1204"],
                            tags=["compromise", "malware"],
                        )
                    )
                    break

        return findings


@register_check
class MaliciousProcessNameCheck(AuditCheck):
    id = "COM-202"
    name = "Known Malicious Process Detection (Extended)"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Detects processes with names matching known malware, miners, and C2 implants"
    depends = ["processes"]
    tags = ["compromise", "malware", "incident-response"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            name: str = p.get("name", "").lower()
            if not name:
                continue
            if name in EXPANDED_MALICIOUS_NAMES:
                description = EXPANDED_MALICIOUS_NAMES[name]
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Known malicious process: {name}",
                        description=(
                            f"Process '{name}' (PID {p.get('pid')}) "
                            f"matches known {description}"
                        ),
                        rationale=(
                            f"The process name '{name}' is associated with {description}. "
                            "This is a strong indicator of compromise."
                        ),
                        remediation=(
                            f"Immediately investigate PID {p.get('pid')}: "
                            f"'cat /proc/{p.get('pid')}/cmdline'. "
                            f"Kill: 'kill -9 {p.get('pid')}'. "
                            f"Remove binary and scan for persistence mechanisms."
                        ),
                        evidence=ProcessEvidence(
                            pid=p.get("pid", 0),
                            name=name,
                            binary=p.get("binary", ""),
                            cmdline=p.get("cmdline", ""),
                            user=str(p.get("uid", "")),
                            state=p.get("state", ""),
                        ),
                        detected_value=name,
                        expected_value="No known malicious process names",
                        affected_component=f"PID {p.get('pid')}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1071", "T1059", "T1496"],
                        tags=["compromise", "malware"],
                    )
                )

        return findings


@register_check
class AnomalousProcessParentageCheck(AuditCheck):
    id = "COM-203"
    name = "Anomalous Process Parentage"
    category = CheckCategory.COMPROMISE
    severity = Severity.MEDIUM
    description = "Detects processes with unexpected parent-child relationships"
    depends = ["processes"]
    tags = ["compromise", "malware", "incident-response"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        procs = proc_data.get("processes", [])
        pid_map: dict[int, dict[str, Any]] = {}
        for p in procs:
            pid: int = p.get("pid", 0)
            pid_map[pid] = p

        for p in procs:
            ppid: int | None = p.get("ppid")
            name: str = p.get("name", "")
            pid = p.get("pid", 0)

            if ppid is None or ppid == 0:
                continue

            parent = pid_map.get(ppid)
            if parent is None:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Orphaned process: {name} (PID {pid})",
                        description=(
                            f"Process '{name}' (PID {pid}) has parent PID {ppid} "
                            f"which no longer exists"
                        ),
                        rationale=(
                            "An orphaned process whose parent has exited may indicate "
                            "a process spawned by a short-lived script or a malware "
                            "process that daemonized poorly."
                        ),
                        remediation=(
                            f"Investigate PID {pid}: 'cat /proc/{pid}/cmdline'. "
                            f"Review process ancestry and resource usage."
                        ),
                        evidence=ProcessEvidence(
                            pid=pid,
                            name=name,
                            binary=p.get("binary", ""),
                            cmdline=p.get("cmdline", ""),
                            user=str(p.get("uid", "")),
                            ppid=ppid,
                        ),
                        detected_value=f"PID {pid} ({name}) orphaned",
                        expected_value="All processes have valid parent PIDs",
                        affected_component=f"PID {pid}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1059"],
                        tags=["compromise", "anomaly"],
                    )
                )

        return findings


@register_check
class WorldWritableProcessBinaryCheck(AuditCheck):
    id = "COM-204"
    name = "Processes With World-Writable Binaries"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Detects running processes whose binary is world-writable"
    depends = ["processes"]
    tags = ["compromise", "privilege-escalation", "malware"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            binary: str | None = p.get("binary", None)
            if not binary:
                continue
            if not binary.startswith("/"):
                continue
            try:
                st = os.stat(binary)
                if st.st_mode & stat.S_IWOTH:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"World-writable binary in use: {binary}",
                            description=(
                                f"Process '{p.get('name')}' (PID {p.get('pid')}) "
                                f"is running a world-writable binary at {binary}"
                            ),
                            rationale=(
                                "A running process whose binary is world-writable "
                                "can be replaced by any user. When the process "
                                "restarts, arbitrary code executes with the "
                                "process's privileges."
                            ),
                            remediation=(
                                f"Fix permissions: 'chmod o-w {binary}'. "
                                f"Verify binary integrity."
                            ),
                            evidence=ProcessEvidence(
                                pid=p.get("pid", 0),
                                name=p.get("name", ""),
                                binary=binary,
                                cmdline=p.get("cmdline", ""),
                                user=str(p.get("uid", "")),
                            ),
                            detected_value=f"World-writable: {binary}",
                            expected_value="Non-world-writable binary",
                            affected_component=binary,
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.0,
                            mitre_attack_ids=["T1574.002"],
                            tags=["compromise", "privilege-escalation"],
                        )
                    )
            except OSError:
                continue

        return findings


@register_check
class SuspiciousCmdlineCheck(AuditCheck):
    id = "COM-205"
    name = "Suspicious Command Line Patterns"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Detects processes with command lines containing suspicious patterns"
    depends = ["processes"]
    tags = ["compromise", "malware", "incident-response"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            cmdline: str = p.get("cmdline", "")
            if not cmdline:
                continue
            for pattern in SUSPICIOUS_CMDLINE_PATTERNS:
                if pattern.search(cmdline):
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Suspicious command line in PID {p.get('pid')}",
                            description=(
                                f"Process '{p.get('name')}' (PID {p.get('pid')}) "
                                f"has a suspicious command line matching: {pattern.pattern}"
                            ),
                            rationale=(
                                "The command line pattern suggests malware delivery "
                                "(curl|bash), obfuscated execution (base64), or "
                                "offensive tooling (metasploit, port scanners)."
                            ),
                            remediation=(
                                f"Investigate PID {p.get('pid')}: "
                                f"'cat /proc/{p.get('pid')}/cmdline'. "
                                f"Kill if malicious: 'kill -9 {p.get('pid')}'."
                            ),
                            evidence=ProcessEvidence(
                                pid=p.get("pid", 0),
                                name=p.get("name", ""),
                                binary=p.get("binary", ""),
                                cmdline=cmdline[:500],
                                user=str(p.get("uid", "")),
                                state=p.get("state", ""),
                            ),
                            detected_value=f"Pattern match on PID {p.get('pid')}",
                            expected_value="No suspicious command line patterns",
                            affected_component=f"PID {p.get('pid')}",
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.15,
                            mitre_attack_ids=["T1059", "T1204"],
                            tags=["compromise", "malware"],
                        )
                    )
                    break

        return findings


@register_check
class MisleadingProcessNamesCheck(AuditCheck):
    id = "COM-206"
    name = "Misleading Process Names"
    category = CheckCategory.COMPROMISE
    severity = Severity.MEDIUM
    description = "Detects processes named like system binaries but running from different paths"
    depends = ["processes"]
    tags = ["compromise", "masquerading", "defense-evasion"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            name: str = p.get("name", "")
            binary: str | None = p.get("binary", None)
            if not name or not binary:
                continue
            name_lower = name.lower()
            if name_lower in WELL_KNOWN_BINARIES:
                expected = WELL_KNOWN_BINARIES[name_lower]
                if "*" in expected:
                    continue
                if os.path.basename(binary) != os.path.basename(expected) or binary != expected:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Misleading process name: {name}",
                            description=(
                                f"Process named '{name}' (PID {p.get('pid')}) "
                                f"is running from '{binary}', not the expected "
                                f"'{expected}'"
                            ),
                            rationale=(
                                "A process using the name of a legitimate system "
                                "binary but running from a different path is a "
                                "common masquerading technique used by malware "
                                "to evade casual inspection."
                            ),
                            remediation=(
                                f"Investigate PID {p.get('pid')}: "
                                f"'ls -la {binary}' and 'cat /proc/{p.get('pid')}/cmdline'. "
                                f"Compare with: 'which {name}'."
                            ),
                            evidence=ProcessEvidence(
                                pid=p.get("pid", 0),
                                name=name,
                                binary=binary,
                                cmdline=p.get("cmdline", ""),
                                user=str(p.get("uid", "")),
                            ),
                            detected_value=f"{binary} (expected {expected})",
                            expected_value=expected,
                            affected_component=binary,
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.2,
                            mitre_attack_ids=["T1036"],
                            tags=["compromise", "masquerading"],
                        )
                    )

        return findings


@register_check
class SuspiciousProcessUidCheck(AuditCheck):
    id = "COM-207"
    name = "Non-Root Process Running as UID 0"
    category = CheckCategory.COMPROMISE
    severity = Severity.MEDIUM
    description = "Detects processes not named as root processes but running with UID 0"
    depends = ["processes"]
    tags = ["compromise", "privilege-escalation", "anomaly"]

    _expected_root_processes: set[str] = {
        "systemd", "init", "journald", "sshd", "cron", "crond",
        "ntpd", "rsyslogd", "networkd", "resolved", "udevd",
        "logind", "containerd", "dockerd", "kubelet",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            uid: int | None = p.get("uid")
            name: str = p.get("name", "").lower()
            pid: int = p.get("pid", 0)

            if uid != 0:
                continue
            if name in self._expected_root_processes:
                continue
            if pid == 1:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected process running as root: {name} (PID {pid})",
                    description=(
                        f"Process '{p.get('name')}' (PID {pid}) is running "
                        f"as UID 0 (root) but is not a standard root process"
                    ),
                    rationale=(
                        "Processes running as root have full system privileges. "
                        "Unexpected processes with root access may indicate "
                        "a backdoor, cryptominer, or unauthorized service."
                    ),
                    remediation=(
                        f"Investigate PID {pid}: "
                        f"'cat /proc/{pid}/cmdline'. "
                        f"Kill if unauthorized: 'kill -9 {pid}'."
                    ),
                    evidence=ProcessEvidence(
                        pid=pid,
                        name=p.get("name", ""),
                        binary=p.get("binary", ""),
                        cmdline=p.get("cmdline", ""),
                        user="root",
                        state=p.get("state", ""),
                    ),
                    detected_value=f"Process '{name}' PID {pid} running as root",
                    expected_value="Only standard processes run as root",
                    affected_component=f"PID {pid}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1068"],
                    tags=["compromise", "privilege-escalation"],
                )
            )

        return findings


@register_check
class HighMemoryUsageCheck(AuditCheck):
    id = "COM-208"
    name = "Processes With High Memory Usage"
    category = CheckCategory.COMPROMISE
    severity = Severity.MEDIUM
    description = "Detects processes using excessive memory, a common cryptominer indicator"
    depends = ["processes"]
    tags = ["compromise", "malware", "cryptominer"]

    _min_memory_mb: int = 500

    def _run_check(self, collectors: dict[str, Any]) -> list:
        proc_data = self._get_data(collectors, "processes")
        findings: list = []

        for p in proc_data.get("processes", []):
            name: str = p.get("name", "").lower()
            vm_rss_kb: int | None = p.get("vm_rss_kb", 0)
            pid: int = p.get("pid", 0)

            if not vm_rss_kb:
                continue

            memory_mb = vm_rss_kb / 1024
            if memory_mb < self._min_memory_mb:
                continue

            if name in ("java", "python3", "python", "node", "mysqld", "postgres"):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"High memory usage: {name} (PID {pid})",
                    description=(
                        f"Process '{name}' (PID {pid}) is using "
                        f"{memory_mb:.0f} MB of RSS memory"
                    ),
                    rationale=(
                        "Processes consuming excessive memory may indicate "
                        "a cryptominer (Monero miners typically use >500MB), "
                        "memory scraping malware, or a memory leak. "
                        "Known cryptominers xmrig and minerd typically "
                        "consume significant memory."
                    ),
                    remediation=(
                        f"Investigate PID {pid} for cryptomining: "
                        f"'cat /proc/{pid}/cmdline'. "
                        f"Check CPU usage: 'top -p {pid}'."
                    ),
                    evidence=ProcessEvidence(
                        pid=pid,
                        name=p.get("name", ""),
                        binary=p.get("binary", ""),
                        cmdline=p.get("cmdline", ""),
                        user=str(p.get("uid", "")),
                        memory_mbytes=round(memory_mb, 1),
                    ),
                    detected_value=f"{memory_mb:.0f} MB RSS by {name} (PID {pid})",
                    expected_value=f"Less than {self._min_memory_mb} MB per non-Java/Python process",
                    affected_component=f"PID {pid}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.35,
                    mitre_attack_ids=["T1496"],
                    tags=["compromise", "cryptominer"],
                )
            )

        return findings
