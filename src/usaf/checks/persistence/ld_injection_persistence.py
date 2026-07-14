import os

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, ProcessEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

SYSTEM_LD_PATHS = {
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
}

KNOWN_LD_SO_CONF = {
    "/etc/ld.so.conf.d/x86_64-linux-gnu.conf",
    "/etc/ld.so.conf.d/libc.conf",
}

KNOWN_LD_LIBRARY_DIRS = {
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib",
    "/lib/x86_64-linux-gnu",
    "/lib",
    "/usr/local/lib",
}


@register_check
class LdPreloadEnvironmentCheck(AuditCheck):
    id = "PER-401"
    name = "LD_PRELOAD in Process Environment"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects processes with LD_PRELOAD environment variable set"
    depends = ["processes"]
    tags = ["persistence", "ld-preload", "injection"]

    def _run_check(self, collectors: dict) -> list:
        process_data = self._get_data(collectors, "processes")
        findings: list = []

        processes = process_data.get("processes", [])
        preload_processes = []
        for proc in processes:
            env = proc.get("environment", {})
            ld_preload: str | None = None
            if isinstance(env, dict):
                ld_preload = env.get("LD_PRELOAD") or env.get("ld_preload")
            elif isinstance(env, str):
                for line in env.split("\n"):
                    line_lower = line.lower()
                    if line_lower.startswith("ld_preload="):
                        ld_preload = line.split("=", 1)[1]
                        break

            if ld_preload:
                preload_processes.append({
                    "pid": proc.get("pid"),
                    "name": proc.get("name", ""),
                    "binary": proc.get("binary", ""),
                    "cmdline": proc.get("cmdline", ""),
                    "user": proc.get("uid", ""),
                    "ld_preload": ld_preload,
                })

        for pp in preload_processes:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"LD_PRELOAD set in process {pp['name']} (PID {pp['pid']})",
                    description=(
                        f"Process {pp['name']} (PID {pp['pid']}, binary: {pp['binary']}) "
                        f"has LD_PRELOAD={pp['ld_preload']}. "
                        "LD_PRELOAD causes libraries to be loaded before all others, "
                        "enabling function hooking."
                    ),
                    rationale=(
                        "LD_PRELOAD is a powerful environment variable that forces the "
                        "dynamic linker to load specified shared libraries before all "
                        "others. Attackers use LD_PRELOAD to hook system calls, "
                        "hide files/processes, intercept network traffic, and subvert "
                        "security controls (e.g., libprocesshider, Jynx-rootkit). "
                        "Benign uses are extremely rare in production environments."
                    ),
                    remediation=(
                        f"Investigate: 'cat /proc/{pp['pid']}/environ | tr \\\\0 \\\\n | grep LD_PRELOAD'\n"
                        f"Check the library path and verify its legitimacy\n"
                        f"Kill and restart the process without LD_PRELOAD\n"
                        f"Audit for rootkits: 'apt install rkhunter && rkhunter --check'"
                    ),
                    evidence=ProcessEvidence(
                        pid=pp["pid"],
                        name=pp["name"],
                        binary=pp["binary"],
                        cmdline=pp.get("cmdline", ""),
                        user=pp.get("user", ""),
                    ),
                    detected_value=f"LD_PRELOAD={pp['ld_preload']}",
                    expected_value="LD_PRELOAD should not be set",
                    affected_component=f"PID {pp['pid']} ({pp['name']})",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1574.006"],
                    tags=["ld-preload", "injection", "rootkit"],
                )
            )

        return findings


@register_check
class LdSoPreloadCheck(AuditCheck):
    id = "PER-402"
    name = "LD_PRELOAD via ld.so.preload"
    category = CheckCategory.PERSISTENCE
    severity = Severity.CRITICAL
    description = "Detects entries in /etc/ld.so.preload for global library injection"
    depends = []
    tags = ["persistence", "ld-preload", "rootkit", "injection"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        if not os.path.exists("/etc/ld.so.preload"):
            return findings

        try:
            with open("/etc/ld.so.preload") as f:
                content = f.read().strip()
        except (OSError, PermissionError):
            return findings

        if not content:
            return findings

        preload_paths = [line.strip() for line in content.split("\n") if line.strip()]

        for lib_path in preload_paths:
            if not os.path.isabs(lib_path):
                continue
            exists = os.path.exists(lib_path)
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"ld.so.preload entry: {lib_path}",
                    description=(
                        f"Global LD_PRELOAD entry in /etc/ld.so.preload: "
                        f"'{lib_path}'. File exists: {exists}. "
                        "This affects ALL dynamically-linked processes system-wide."
                    ),
                    rationale=(
                        "/etc/ld.so.preload is the most powerful LD_PRELOAD vector — it "
                        "applies to ALL dynamically-linked executables system-wide. "
                        "This file is almost never used legitimately on Ubuntu. "
                        "Rootkits like Jynx2, Azazel, and libprocesshider use this "
                        "file for global function hooking to hide files, processes, "
                        "and network connections."
                    ),
                    remediation=(
                        f"Inspect the library: 'file {lib_path}' and 'strings {lib_path}'\n"
                        f"Check for known rootkit signatures\n"
                        f"Remove the preload entry and the library file\n"
                        f"Run rootkit detection: 'rkhunter --check'"
                    ),
                    evidence=FileEvidence(
                        path="/etc/ld.so.preload",
                        content=content,
                        owner="",
                        group="",
                    ),
                    detected_value=content,
                    expected_value="Empty file (should contain no entries)",
                    affected_component=lib_path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1574.006"],
                    tags=["ld-preload", "rootkit", "injection", "critical"],
                )
            )

        return findings


@register_check
class LdLibraryPathAnomalyCheck(AuditCheck):
    id = "PER-403"
    name = "LD_LIBRARY_PATH Anomalies"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects processes with unusual LD_LIBRARY_PATH settings"
    depends = ["processes"]
    tags = ["persistence", "ld-library-path", "injection"]

    def _run_check(self, collectors: dict) -> list:
        process_data = self._get_data(collectors, "processes")
        findings: list = []

        processes = process_data.get("processes", [])
        anomalous_processes: list[dict] = []

        for proc in processes:
            env = proc.get("environment", {})
            ld_library_path: str | None = None
            if isinstance(env, dict):
                ld_library_path = env.get("LD_LIBRARY_PATH") or env.get("ld_library_path")
            elif isinstance(env, str):
                for line in env.split("\n"):
                    if line.lower().startswith("ld_library_path="):
                        ld_library_path = line.split("=", 1)[1]
                        break

            if ld_library_path:
                paths = ld_library_path.split(":")
                nonstandard = [p for p in paths if not any(
                    known_dir in p for known_dir in KNOWN_LD_LIBRARY_DIRS
                )]
                if nonstandard:
                    anomalous_processes.append({
                        "pid": proc.get("pid"),
                        "name": proc.get("name", ""),
                        "binary": proc.get("binary", ""),
                        "cmdline": proc.get("cmdline", ""),
                        "ld_library_path": ld_library_path,
                        "nonstandard_paths": nonstandard,
                    })

        for ap in anomalous_processes:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"LD_LIBRARY_PATH with non-standard paths in {ap['name']} (PID {ap['pid']})",
                    description=(
                        f"Process {ap['name']} (PID {ap['pid']}) has "
                        f"LD_LIBRARY_PATH={ap['ld_library_path']}. "
                        f"Non-standard paths: {', '.join(ap['nonstandard_paths'][:5])}"
                    ),
                    rationale=(
                        "LD_LIBRARY_PATH overrides the standard library search path. "
                        "Attackers use it to load malicious shared libraries instead of "
                        "legitimate ones (DLL hijacking equivalent on Linux). "
                        "Non-standard paths like /tmp, /dev/shm, or user-writable "
                        "directories are particularly suspicious."
                    ),
                    remediation=(
                        f"Investigate the process: 'ps aux | grep {ap['pid']}'\n"
                        f"Check library paths for rogue .so files\n"
                        f"Remove LD_LIBRARY_PATH from the process environment\n"
                        f"Check startup scripts that may set this variable"
                    ),
                    evidence=ProcessEvidence(
                        pid=ap["pid"],
                        name=ap["name"],
                        binary=ap["binary"],
                        cmdline=ap.get("cmdline", ""),
                    ),
                    detected_value=f"LD_LIBRARY_PATH={ap['ld_library_path']}",
                    expected_value="LD_LIBRARY_PATH should not contain non-standard paths",
                    affected_component=f"PID {ap['pid']} ({ap['name']})",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.4,
                    mitre_attack_ids=["T1574.006"],
                    tags=["ld-library-path", "injection", "persistence"],
                )
            )

        return findings
