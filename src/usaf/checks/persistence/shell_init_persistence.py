import os
import stat
from datetime import datetime

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

SUSPICIOUS_INIT_PATTERNS = [
    "wget",
    "curl",
    "nc ",
    "ncat",
    "bash -c",
    "python",
    "perl -e",
    "mkfifo",
    "/dev/tcp/",
    "chmod +x",
    "base64 -d",
    "openssl",
    "socat",
    "nohup",
]

PROFILE_D_DIR = "/etc/profile.d"
BASH_BASHRC = "/etc/bash.bashrc"
BASH_PROFILE = "/etc/profile"
ZSHRC_SKEL = "/etc/zsh/zshrc"
ZSHRC_ALTERNATE = "/etc/zshrc"

KNOWN_PROFILE_SCRIPTS = {
    "01-locale-fix.sh",
    "bash_completion.sh",
    "apps-bin-path.sh",
    "cedilla-portuguese.sh",
    "gawk.sh",
    "gpg-agent.sh",
    "input-method-config.sh",
    "lang.sh",
    "less.sh",
    "mariadb-client.sh",
    "pkg-config.sh",
    "Z97-byobu.sh",
    "Z98-gnuplot.sh",
    "Z99-cloudimg.sh",
    "vim.sh",
    "which2.sh",
    "zzz-texlive-bin.sh",
    "zzz-unity-greeter.sh",
    "zzz-iptables.sh",
}

KNOWN_SYSTEM_INIT_FILES = {
    "/etc/bash.bashrc",
    "/etc/profile",
    "/etc/zsh/zshrc",
    "/etc/zshrc",
    "/etc/skel/.bashrc",
    "/etc/skel/.profile",
    "/etc/skel/.zshrc",
}


@register_check
class UnexpectedProfileScriptsCheck(AuditCheck):
    id = "PER-301"
    name = "Unexpected Profile.d Scripts"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected scripts in /etc/profile.d"
    depends = []
    tags = ["persistence", "shell", "profile", "init"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        if not os.path.isdir(PROFILE_D_DIR):
            return findings

        profile_scripts: list[dict] = []
        try:
            entries = sorted(os.listdir(PROFILE_D_DIR))
        except (OSError, PermissionError):
            return findings

        for entry in entries:
            if entry in KNOWN_PROFILE_SCRIPTS:
                continue
            if not (entry.endswith(".sh") or "." not in entry or entry.endswith(".csh")):
                continue
            fp = os.path.join(PROFILE_D_DIR, entry)
            try:
                st = os.stat(fp)
                if not stat.S_ISREG(st.st_mode):
                    continue
                with open(fp) as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue
            suspicious_matches = [
                p for p in SUSPICIOUS_INIT_PATTERNS if p in content
            ]
            suspicious_by_comment = any(
                kw in content.lower()
                for kw in ["backdoor", "reverse shell", "beacon", "implant"]
            )
            profile_scripts.append({
                "name": entry,
                "path": fp,
                "content": content,
                "suspicious_matches": suspicious_matches,
                "suspicious_by_comment": suspicious_by_comment,
                "size": st.st_size,
                "modified": st.st_mtime,
            })

        for ps in profile_scripts:
            if ps["suspicious_matches"]:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Suspicious content in {ps['name']}",
                        description=(
                            f"Profile script {ps['name']} contains suspicious "
                            f"patterns: {', '.join(ps['suspicious_matches'])}"
                        ),
                        rationale=(
                            "Profile.d scripts execute for every user login. "
                            "Attackers place malicious scripts here to maintain "
                            "persistence. Any script with download/execute patterns "
                            "or reverse shell indicators is highly suspicious."
                        ),
                        remediation=(
                            f"Investigate: 'cat {ps['path']}'\n"
                            f"Check package ownership: 'dpkg -S {ps['path']}'\n"
                            f"Remove if unauthorized: 'rm {ps['path']}'"
                        ),
                        evidence=FileEvidence(
                            path=ps["path"],
                            content=ps["content"][:500],
                            owner="",
                            group="",
                            size=ps["size"],
                            modified=ps["modified"],
                        ),
                        detected_value="Unknown profile script with suspicious content",
                        expected_value="Known scripts only",
                        affected_component=ps["name"],
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1546.004"],
                        tags=["persistence", "profile", "shell-init"],
                    )
                )

        for ps in profile_scripts:
            if not ps["suspicious_matches"] and ps["name"] not in KNOWN_PROFILE_SCRIPTS:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"Unknown profile script: {ps['name']}",
                        description=(
                            f"Profile script {ps['name']} is not in the known-safe list. "
                            f"Size: {ps['size']} bytes, modified: {ps['modified']}"
                        ),
                        rationale=(
                            "Any script in /etc/profile.d that is not a known system "
                            "script should be investigated. Attackers deploy persistence "
                            "scripts here that execute for all users on login."
                        ),
                        remediation=(
                            f"Investigate: 'cat {ps['path']}'\n"
                            f"Check package ownership: 'dpkg -S {ps['path']}'\n"
                            f"Remove if unauthorized: 'rm {ps['path']}'"
                        ),
                        evidence=FileEvidence(
                            path=ps["path"],
                            content=ps["content"][:200],
                            owner="",
                            group="",
                            size=ps["size"],
                            modified=ps["modified"],
                        ),
                        detected_value=ps["name"],
                        expected_value="Only known system profile scripts",
                        affected_component=ps["name"],
                        confidence=Confidence.LOW,
                        false_positive_probability=0.7,
                        mitre_attack_ids=["T1546.004"],
                        tags=["persistence", "profile", "shell-init"],
                    )
                )

        return findings


@register_check
class ModifiedBashInitCheck(AuditCheck):
    id = "PER-302"
    name = "Modified Bash Initialization Files"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects suspicious modifications to bash initialization files"
    depends = ["users"]
    tags = ["persistence", "shell", "bash", "init"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        system_bash_files = [
            ("/etc/bash.bashrc", "System-wide bashrc"),
            ("/etc/profile", "System-wide profile"),
        ]

        for fp, _desc in system_bash_files:
            if not os.path.exists(fp):
                continue
            try:
                with open(fp) as f:
                    content = f.read()
                st = os.stat(fp)
            except (OSError, PermissionError):
                continue

            suspicious_matches = [
                p for p in SUSPICIOUS_INIT_PATTERNS if p in content
            ]

            inetd_style = "exec" in content and ("/dev/tcp/" in content or "nc " in content)

            if suspicious_matches or inetd_style:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Suspicious content in {os.path.basename(fp)}",
                        description=(
                            f"System bash init file {fp} contains suspicious patterns: "
                            f"{', '.join(suspicious_matches[:5])}. "
                            f"Size: {st.st_size} bytes."
                        ),
                        rationale=(
                            "System-wide bash initialization files execute for every "
                            "user's bash shell. Attackers modify these files to "
                            "maintain persistence by injecting malicious commands "
                            "that run on every terminal session."
                        ),
                        remediation=(
                            f"Inspect: 'cat {fp}'\n"
                            f"Check package ownership: 'dpkg -S {fp}'\n"
                            f"Restore from package: 'dpkg --verify {fp}' or reinstall"
                        ),
                        evidence=FileEvidence(
                            path=fp,
                            content=content[:500],
                            owner="",
                            group="",
                            size=st.st_size,
                            modified=datetime.fromtimestamp(st.st_mtime),
                        ),
                        detected_value="Suspicious content in bash init file",
                        expected_value="No suspicious patterns in bash init files",
                        affected_component=fp,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1546.004"],
                        tags=["persistence", "bash", "shell-init"],
                    )
                )

        user_data = self._get_optional_data(collectors, "users") or {}
        users = user_data.get("users", [])
        for user_entry in users:
            home = user_entry.get("home", "")
            if not home or home == "/nonexistent":
                continue
            user_bashrc = os.path.join(home, ".bashrc")
            user_bash_profile = os.path.join(home, ".bash_profile")
            user_profile = os.path.join(home, ".profile")

            for user_fp in [user_bashrc, user_bash_profile, user_profile]:
                if not os.path.exists(user_fp):
                    continue
                try:
                    with open(user_fp) as f:
                        content = f.read()
                    st = os.stat(user_fp)
                except (OSError, PermissionError):
                    continue

                user_suspicious = [
                    p for p in SUSPICIOUS_INIT_PATTERNS if p in content
                ]

                if user_suspicious:
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"Suspicious content in {os.path.basename(user_fp)} for {user_entry.get('username', 'unknown')}",
                            description=(
                                f"User file {user_fp} contains: "
                                f"{', '.join(user_suspicious[:3])}"
                            ),
                            rationale=(
                                "Per-user bash init files execute when the user logs in. "
                                "Attackers modify these files for user-level persistence "
                                "that persists across terminal sessions."
                            ),
                            remediation=(
                                f"Inspect: 'cat {user_fp}'\n"
                                f"Remove malicious lines. Restore from backup if available. "
                                f"Consider rotating the user's credentials if compromise is confirmed."
                            ),
                            evidence=FileEvidence(
                                path=user_fp,
                                content=content[:500],
                                owner=user_entry.get("username", ""),
                                group="",
                                size=st.st_size,
                                modified=datetime.fromtimestamp(st.st_mtime),
                            ),
                            detected_value="Suspicious content in user bash init",
                            expected_value="No suspicious patterns",
                            affected_component=user_fp,
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.3,
                            mitre_attack_ids=["T1546.004"],
                            tags=["persistence", "bash", "shell-init"],
                        )
                    )

        return findings


@register_check
class ModifiedZshInitCheck(AuditCheck):
    id = "PER-303"
    name = "Modified Zsh Initialization Files"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects suspicious modifications to zsh initialization files"
    depends = ["users"]
    tags = ["persistence", "shell", "zsh", "init"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        system_zsh_files = [
            ("/etc/zsh/zshrc", "System-wide zshrc"),
            ("/etc/zshrc", "Alternative zshrc"),
        ]

        for fp, _desc in system_zsh_files:
            if not os.path.exists(fp):
                continue
            try:
                with open(fp) as f:
                    content = f.read()
                st = os.stat(fp)
            except (OSError, PermissionError):
                continue

            suspicious_matches = [
                p for p in SUSPICIOUS_INIT_PATTERNS if p in content
            ]

            if suspicious_matches:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Suspicious content in {os.path.basename(fp)}",
                        description=(
                            f"System zsh initialization file {fp} contains "
                            f"suspicious patterns: {', '.join(suspicious_matches[:5])}"
                        ),
                        rationale=(
                            "Zsh is the default shell in Ubuntu since 24.04. "
                            "System-wide zsh init files execute for every zsh user. "
                            "Attackers modify these files to maintain persistence "
                            "across all zsh sessions."
                        ),
                        remediation=(
                            f"Inspect: 'cat {fp}'\n"
                            f"Check package ownership: 'dpkg -S {fp}'\n"
                            "Remove malicious lines or restore from package."
                        ),
                        evidence=FileEvidence(
                            path=fp,
                            content=content[:500],
                            owner="",
                            group="",
                            size=st.st_size,
                            modified=datetime.fromtimestamp(st.st_mtime),
                        ),
                        detected_value="Suspicious content in zsh init file",
                        expected_value="No suspicious patterns in zsh init files",
                        affected_component=fp,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1546.004"],
                        tags=["persistence", "zsh", "shell-init"],
                    )
                )

        user_data = self._get_optional_data(collectors, "users") or {}
        users = user_data.get("users", [])
        for user_entry in users:
            home = user_entry.get("home", "")
            if not home or home == "/nonexistent":
                continue
            user_zshrc = os.path.join(home, ".zshrc")
            user_zprofile = os.path.join(home, ".zprofile")
            user_zlogin = os.path.join(home, ".zlogin")

            for user_fp in [user_zshrc, user_zprofile, user_zlogin]:
                if not os.path.exists(user_fp):
                    continue
                try:
                    with open(user_fp) as f:
                        content = f.read()
                    st = os.stat(user_fp)
                except (OSError, PermissionError):
                    continue

                user_suspicious = [
                    p for p in SUSPICIOUS_INIT_PATTERNS if p in content
                ]

                if user_suspicious:
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"Suspicious content in {os.path.basename(user_fp)} for {user_entry.get('username', 'unknown')}",
                            description=(
                                f"User file {user_fp} contains: "
                                f"{', '.join(user_suspicious[:3])}"
                            ),
                            rationale=(
                                "Per-user zsh init files execute when the user starts zsh. "
                                "Attackers modify these for user-level persistence."
                            ),
                            remediation=(
                                f"Inspect: 'cat {user_fp}'\n"
                                "Remove malicious lines. Restore from backup if available."
                            ),
                            evidence=FileEvidence(
                                path=user_fp,
                                content=content[:500],
                                owner=user_entry.get("username", ""),
                                group="",
                                size=st.st_size,
                                modified=datetime.fromtimestamp(st.st_mtime),
                            ),
                            detected_value="Suspicious content in user zsh init",
                            expected_value="No suspicious patterns",
                            affected_component=user_fp,
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.3,
                            mitre_attack_ids=["T1546.004"],
                            tags=["persistence", "zsh", "shell-init"],
                        )
                    )

        return findings
