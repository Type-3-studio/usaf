from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import ProcessEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


SUSPICIOUS_CONNECTIONS: list[str] = [
    "pastebin.com", "ssh", "443", "1337",
]


@register_check
class SuspiciousNetworkConnectionsCheck(AuditCheck):
    id = "COM-301"
    name = "Suspicious Network Connections"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Detects processes with suspicious outbound network connections"
    depends = ["processes"]
    tags = ["compromise", "network", "c2", "malware"]
    max_findings = 100

    SUSPICIOUS_PORTS: set[int] = {4444, 6666, 6667, 1337, 31337, 5555, 8081, 9001, 4443}
    SUSPICIOUS_IP_PATTERNS: list[str] = [".ru.", ".cn.", ".kp."]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            cmdline = proc.get("cmdline", "") or ""
            if not any(str(p) in cmdline for p in self.SUSPICIOUS_PORTS):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Suspicious connection: {proc.get('name', '?')} (PID {proc.get('pid', 0)})",
                    description=f"Process '{proc.get('name')}' (PID {proc.get('pid')}) uses a suspicious port in its command line: '{cmdline[:120]}'.",
                    rationale="Connections to known C2 ports or unusual ports may indicate compromise. Attackers often use non-standard ports for command and control.",
                    remediation=f"Investigate process: 'lsof -p {proc.get('pid')}'. Check network connections: 'ss -tanp | grep {proc.get('pid')}'.",
                    evidence=ProcessEvidence(pid=proc.get("pid", 0), name=proc.get("name", ""), cmdline=cmdline[:200]),
                    detected_value=f"Suspicious port usage by PID {proc.get('pid')}",
                    expected_value="No suspicious network connections",
                    affected_component=f"PID {proc.get('pid')}: {proc.get('name', '')}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1071"],
                    tags=["compromise", "network", "c2", "malware"],
                )
            )
        return findings


@register_check
class ReverseShellDetectionCheck(AuditCheck):
    id = "COM-302"
    name = "Reverse Shell Detection"
    category = CheckCategory.COMPROMISE
    severity = Severity.CRITICAL
    description = "Detects potential reverse shell processes"
    depends = ["processes"]
    tags = ["compromise", "reverse-shell", "malware"]
    max_findings = 50

    REVERSE_SHELL_PATTERNS: list[str] = [
        "/dev/tcp/", "/dev/udp/", "bash -i", "sh -i",
        "exec 5<>/dev/tcp", "python -c 'import socket",
        "ncat ", "nc -e ", "nc.exe -e ",
        "socat", "mkfifo", "mknod",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            cmdline = proc.get("cmdline", "") or ""

            matched = [p for p in self.REVERSE_SHELL_PATTERNS if p in cmdline.lower()]
            if not matched:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Reverse shell detected: {proc.get('name', '?')} (PID {proc.get('pid', 0)})",
                    description=f"Process '{proc.get('name')}' (PID {proc.get('pid')}) matches reverse shell patterns: {', '.join(matched)}.",
                    rationale="Reverse shell patterns indicate an attacker has established interactive remote access. This is a critical compromise indicator requiring immediate response.",
                    remediation=f"IMMEDIATE ACTION: Kill process 'kill -9 {proc.get('pid')}'. Investigate and contain the compromised host.",
                    evidence=ProcessEvidence(pid=proc.get("pid", 0), name=proc.get("name", ""), cmdline=cmdline[:200]),
                    detected_value=f"Reverse shell: PID {proc.get('pid')}",
                    expected_value="No reverse shell indicators",
                    affected_component=f"PID {proc.get('pid')}: {proc.get('name', '')}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1059", "T1071"],
                    tags=["compromise", "reverse-shell", "malware"],
                )
            )
        return findings


@register_check
class UnusualOutboundConnectionsCheck(AuditCheck):
    id = "COM-303"
    name = "Unusual Outbound Connections"
    category = CheckCategory.COMPROMISE
    severity = Severity.MEDIUM
    description = "Detects processes making unusual outbound network connections"
    depends = ["sockets", "processes"]
    tags = ["compromise", "network", "c2", "monitoring"]
    max_findings = 100

    COMMON_OUTBOUND: set[str] = {
        "apt", "dpkg", "snapd", "systemd-resolve",
        "chronyd", "ntpd", "unattended-upgrades",
        "sshd", "sshd:", "systemd", "netdata",
        "prometheus", "node_exporter",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")
        proc_data = self._get_data(collectors, "processes")

        proc_names: dict[int, str] = {}
        for p in proc_data.get("processes", []):
            pid = p.get("pid", 0)
            name = p.get("name", "") or ""
            proc_names[pid] = name

        for proto in ("tcp", "tcp6"):
            for entry in sock_data.get(proto, []):
                remote = entry.get("remote_address", "")
                remote_port = int(entry.get("remote_port", 0))
                pid = int(entry.get("pid", 0)) if entry.get("pid") else 0
                local_port = int(entry.get("local_port", 0))

                if remote in ("00000000:00000000", "0000000000000000000000000000000000000000:00000000"):
                    continue
                if local_port < 1024:
                    continue

                proc_name = proc_names.get(pid, "")
                if any(common in proc_name for common in self.COMMON_OUTBOUND):
                    continue
                if not proc_name:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unusual outbound connection: {proc_name} (PID {pid})",
                        description=f"Process '{proc_name}' (PID {pid}) has an outbound connection to {remote}:{remote_port}.",
                        rationale="Unexpected outbound connections may indicate data exfiltration, C2 communication, or unauthorized remote access.",
                        remediation=f"Investigate process: 'lsof -p {pid}'. Check connection: 'ss -tanp | grep {pid}'.",
                        evidence=ProcessEvidence(pid=pid, name=proc_name),
                        detected_value=f"Outbound: {proc_name} -> {remote}:{remote_port}",
                        expected_value="No unexpected outbound connections",
                        affected_component=f"PID {pid}: {proc_name}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.4,
                        mitre_attack_ids=["T1041"],
                        tags=["compromise", "network", "c2", "monitoring"],
                    )
                )
        return findings


@register_check
class HighMemoryProcessesCheck(AuditCheck):
    id = "COM-304"
    name = "High Memory Usage Detection"
    category = CheckCategory.COMPROMISE
    severity = Severity.MEDIUM
    description = "Detects processes using excessive memory (potential cryptominer)"
    depends = ["processes"]
    tags = ["compromise", "memory", "cryptominer", "malware"]
    max_findings = 20

    MEMORY_THRESHOLD_MB = 500

    KNOWN_SYSTEM: set[str] = {
        "java", "python3", "node", "chrome", "firefox",
        "mysqld", "postgres", "redis-server", "mongod",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            name = proc.get("name", "") or ""
            memory_mb = proc.get("memory_mbytes")

            if memory_mb is None:
                continue
            if memory_mb < self.MEMORY_THRESHOLD_MB:
                continue
            if name in self.KNOWN_SYSTEM:
                continue
            if name.startswith("python") or name.startswith("java"):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"High memory process: {name} (PID {proc.get('pid', 0)})",
                    description=f"Process '{name}' (PID {proc.get('pid')}) is using {memory_mb}MB of memory.",
                    rationale="Cryptominers and other malicious processes consume significant memory. Unexpected high memory usage is a common cryptominer indicator.",
                    remediation=f"Investigate process: 'ps aux | grep {proc.get('pid')}'. Check CPU: 'top -p {proc.get('pid')}'.",
                    evidence=ProcessEvidence(pid=proc.get("pid", 0), name=name, memory_mbytes=int(memory_mb)),
                    detected_value=f"{memory_mb}MB used by {name}",
                    expected_value="Memory usage under threshold",
                    affected_component=f"PID {proc.get('pid')}: {name}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.4,
                    mitre_attack_ids=["T1496"],
                    tags=["compromise", "memory", "cryptominer", "malware"],
                )
            )
        return findings


@register_check
class HiddenProcessCheck(AuditCheck):
    id = "COM-305"
    name = "Hidden Process Detection"
    category = CheckCategory.COMPROMISE
    severity = Severity.CRITICAL
    description = "Detects processes with characteristics of rootkit hiding attempts"
    depends = ["processes"]
    tags = ["compromise", "rootkit", "hidden", "malware"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            name = proc.get("name", "") or ""
            pid = proc.get("pid", 0)
            binary = proc.get("binary") or ""

            if name and not binary:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Process with no binary: {name} (PID {pid})",
                        description=f"Process '{name}' (PID {pid}) has no binary path. This may indicate a hidden or memory-resident process.",
                        rationale="Processes without a binary path are suspicious. Rootkits and memory-resident malware often hide their executable path.",
                        remediation=f"Immediate investigation required: 'ls -la /proc/{pid}/exe'. Dump process: 'cat /proc/{pid}/exe > /tmp/dump.bin'.",
                        evidence=ProcessEvidence(pid=pid, name=name),
                        detected_value=f"PID {pid}: no binary",
                        expected_value="All processes have valid binaries",
                        affected_component=f"PID {pid}: {name}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1014"],
                        tags=["compromise", "rootkit", "hidden", "malware"],
                    )
                )
        return findings


@register_check
class AnomalousProcessNameCheck(AuditCheck):
    id = "COM-306"
    name = "Anomalous Process Names"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Detects processes with suspicious or masquerading names"
    depends = ["processes"]
    tags = ["compromise", "masquerading", "malware"]
    max_findings = 50

    def _is_kernel_thread(self, proc: dict[str, Any]) -> bool:
        binary = proc.get("binary")
        cmdline = proc.get("cmdline", "") or ""
        ppid = proc.get("ppid")
        return (not binary) and (not cmdline) and (ppid == 2)

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            name = proc.get("name", "") or ""
            pid = proc.get("pid", 0)

            if not name:
                continue

            if self._is_kernel_thread(proc):
                continue

            name_lower = name.lower()

            flags: list[str] = []
            if "[" in name and "]" in name and not name.startswith("["):
                flags.append("brackets in name (masquerading as kernel thread)")
            if (name_lower in ("kworker", "kthreadd") or (name_lower.startswith("kworker/") and not name_lower.startswith("[kworker"))):
                flags.append("masquerading as kernel worker")
            if name_lower in ("sshd", "cron", "systemd", "apache2", "nginx") and pid > 100:
                ppid = proc.get("ppid", 0)
                if ppid is not None and ppid > 1:
                    flags.append("common service name from non-standard parent")

            if not flags:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Suspicious process name: {name} (PID {pid})",
                    description=f"Process '{name}' (PID {pid}) has suspicious characteristics: {'; '.join(flags)}.",
                    rationale="Attackers often masquerade processes with names similar to legitimate system processes to evade detection.",
                    remediation=f"Investigate process: 'ls -la /proc/{pid}/exe && cat /proc/{pid}/cmdline'.",
                    evidence=ProcessEvidence(pid=pid, name=name),
                    detected_value=f"Suspicious: {name} (PID {pid})",
                    expected_value="No masquerading processes",
                    affected_component=f"PID {pid}: {name}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1036"],
                    tags=["compromise", "masquerading", "malware"],
                )
            )
        return findings
