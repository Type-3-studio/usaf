from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class ShellHistoryCheck(AuditCheck):
    """Check that shell history is properly configured for forensic traceability."""

    id = "FOR-201"
    name = "Shell History Audit"
    category = CheckCategory.FORENSICS
    severity = Severity.MEDIUM
    description = "Checks that shell history files exist and are properly configured for forensic timeline reconstruction"
    depends: ClassVar[list[str]] = ["users"]
    tags: ClassVar[list[str]] = ["forensics", "shell", "history", "timeline"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            home = entry.get("home", "")
            shell = entry.get("shell", "")

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            history_files: list[Path] = []

            if "bash" in shell:
                history_files.append(Path(home) / ".bash_history")
            elif "zsh" in shell:
                history_files.append(Path(home) / ".zsh_history")

            for hf in history_files:
                finding = self._check_history_file(hf, username)
                if finding:
                    findings.append(finding)

            for rc_file in (".bashrc", ".bash_profile", ".zshrc", ".zshenv"):
                rc_path = Path(home) / rc_file
                if rc_path.exists():
                    finding = self._check_shell_config(rc_path, username)
                    if finding:
                        findings.append(finding)

        return findings

    def _check_history_file(
        self, hf: Path, username: str
    ) -> Finding | None:
        if not hf.exists():
            return self.finding(
                finding_id="001",
                title=f"Missing shell history: {username}",
                description=(
                    f"Shell history file '{hf}' does not exist for user '{username}'. "
                    "Without shell history, forensic timeline reconstruction is limited."
                ),
                rationale=(
                    "Shell history files are critical for forensic investigation. They "
                    "record commands executed by users, providing a timeline of attacker "
                    "activity. Missing history files may indicate anti-forensic measures, "
                    "such as history being disabled or explicitly deleted."
                ),
                remediation=(
                    "Ensure HISTFILE is set in the user's shell configuration. "
                    "For bash, verify .bashrc contains: 'HISTFILE=~/.bash_history'. "
                    "History files are created automatically when a command is run."
                ),
                evidence=FileEvidence(
                    path=str(hf),
                    content="File does not exist",
                ),
                detected_value=f"No history file for {username}",
                expected_value=f"{hf} exists with command history",
                affected_component=f"User: {username}",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1070", "T1562"],
                tags=["forensics", "history", "anti-forensics"],
            )

        if hf.is_symlink():
            target = hf.resolve()
            if target == Path("/dev/null"):
                return self.finding(
                    finding_id="002",
                    title=f"Shell history redirected to /dev/null: {username}",
                    description=(
                        f"History file '{hf}' for user '{username}' is a symlink to "
                        "/dev/null. This is a known anti-forensic technique."
                    ),
                    rationale=(
                        "Redirecting shell history to /dev/null is a deliberate "
                        "anti-forensic technique used by attackers to avoid leaving "
                        "a command history trail. Legitimate users rarely do this."
                    ),
                    remediation=(
                        "Remove the symlink: 'rm {hf}'. "
                        "Ensure HISTFILE points to a real file in the user's home "
                        "directory. Investigate why this was set up."
                    ),
                    evidence=FileEvidence(
                        path=str(hf),
                        content="Symlink to /dev/null (anti-forensic)",
                    ),
                    detected_value="History redirected to /dev/null",
                    expected_value=f"Real history file at {hf}",
                    affected_component=f"User: {username}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1070", "T1562.001", "T1654"],
                    tags=["forensics", "history", "anti-forensics"],
                )

        try:
            if hf.stat().st_size == 0:
                return self.finding(
                    finding_id="003",
                    title=f"Empty shell history: {username}",
                    description=f"History file '{hf}' for user '{username}' exists but is empty.",
                    rationale=(
                        "An empty history file while the shell is actively used may indicate "
                        "that history was cleared (history -c) or HISTSIZE was set to 0. "
                        "This reduces forensic value for timeline reconstruction."
                    ),
                    remediation=(
                        "Ensure HISTSIZE and HISTFILESIZE are set to reasonable positive "
                        "values in shell configuration. Avoid running 'history -c'."
                    ),
                    evidence=FileEvidence(
                        path=str(hf),
                        size=0,
                        content="Empty history file",
                    ),
                    detected_value=f"Empty history file for {username}",
                    expected_value="Non-empty history file with command history",
                    affected_component=f"User: {username}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1070", "T1654"],
                    tags=["forensics", "history"],
                )
        except OSError:
            return None

        return None

    def _check_shell_config(
        self, rc_path: Path, username: str
    ) -> Finding | None:
        try:
            content = rc_path.read_text()
        except OSError:
            return None

        issues: list[str] = []

        if "HISTSIZE=0" in content or "HISTSIZE = 0" in content:
            issues.append("HISTSIZE=0 (history disabled)")

        if "HISTFILESIZE=0" in content or "HISTFILESIZE = 0" in content:
            issues.append("HISTFILESIZE=0 (history file truncated)")

        if "unset HISTFILE" in content:
            issues.append("HISTFILE unset (history disabled)")

        if not issues:
            return None

        return self.finding(
            finding_id="004",
            title=f"Shell history disabled in config: {username}",
            description=(
                f"Configuration file '{rc_path}' for user '{username}' contains "
                f"settings that disable or limit shell history: {'; '.join(issues)}."
            ),
            rationale=(
                "Disabling shell history is a common anti-forensic technique. "
                "Without command history, investigators cannot reconstruct the "
                "sequence of commands executed by an attacker."
            ),
            remediation=(
                "Remove or comment out lines that disable history in "
                f"'{rc_path}'. Set HISTSIZE=2000 and HISTFILESIZE=2000 "
                "for reasonable history retention."
            ),
            evidence=FileEvidence(
                path=str(rc_path),
                content="; ".join(issues),
            ),
            detected_value=f"History disabled: {'; '.join(issues)}",
            expected_value="Shell history enabled with positive size limits",
            affected_component=f"User: {username}",
            confidence=Confidence.HIGH,
            false_positive_probability=0.1,
            mitre_attack_ids=["T1070", "T1562.001", "T1654"],
            tags=["forensics", "history", "anti-forensics"],
        )


@register_check
class ForensicArtifactExposureCheck(AuditCheck):
    """Check for forensic artifacts that may expose sensitive data or indicate tampering."""

    id = "FOR-301"
    name = "Forensic Artifact Exposure"
    category = CheckCategory.FORENSICS
    severity = Severity.MEDIUM
    description = "Checks for leftover forensic artifacts (core dumps, editor backups, Trash dirs) that may expose sensitive data"
    depends: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = ["forensics", "artifacts", "data-exposure", "cleanup"]

    CORE_PATTERN_PATHS: ClassVar[list[Path]] = [
        Path("/var/crash"),
        Path("/var/spool/abrt"),
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = collectors.get("users", {})

        findings.extend(self._check_core_dumps())
        findings.extend(self._check_user_artifacts(users_data))

        return findings

    def _check_core_dumps(self) -> list:
        findings: list = []
        for dump_dir in self.CORE_PATTERN_PATHS:
            if not dump_dir.is_dir():
                continue
            try:
                cores = [f for f in dump_dir.iterdir() if f.is_file()]
                if not cores:
                    continue
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Core dump files in {dump_dir}",
                        description=(
                            f"Found {len(cores)} core dump file(s) in {dump_dir}. "
                            "Core dumps may contain sensitive data from crashed processes."
                        ),
                        rationale=(
                            "Core dumps contain the memory state of crashed processes, "
                            "potentially including passwords, cryptographic keys, and "
                            "other sensitive data. They should be cleaned up regularly "
                            "and restricted to authorized users only."
                        ),
                        remediation=(
                            f"Delete core dumps: 'rm -f {dump_dir}/*'. "
                            "Configure core dump limits in /etc/security/limits.conf: "
                            "'* hard core 0'."
                        ),
                        evidence=FileEvidence(
                            path=str(dump_dir),
                            content=f"{len(cores)} core dump file(s) present",
                        ),
                        detected_value=f"{len(cores)} core dump(s) in {dump_dir}",
                        expected_value="No core dump files present",
                        affected_component=str(dump_dir),
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1070", "T1005"],
                        tags=["forensics", "core-dump", "data-exposure"],
                    )
                )
            except OSError:
                continue
        return findings

    def _check_user_artifacts(self, users_data: dict[str, Any]) -> list:
        findings: list = []
        for user_entry in users_data.get("users", []):
            username = user_entry.get("username", "")
            uid = user_entry.get("uid", 0)
            home = user_entry.get("home", "")

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            home_path = Path(home)
            finding = self._check_trash_dir(home_path, username)
            if finding:
                findings.append(finding)
            findings.extend(self._check_swap_files(home_path, username))
        return findings

    def _check_trash_dir(self, home_path: Path, username: str) -> Finding | None:
        trash_dir = home_path / ".local/share/Trash"
        if not trash_dir.is_dir():
            return None
        try:
            trash_files = list(trash_dir.rglob("*"))
            if not trash_files:
                return None
        except OSError:
            return None
        return self.finding(
            finding_id="002",
            title=f"Trash directory contains files: {username}",
            description=(
                f"Recycle/Trash directory for user '{username}' "
                f"contains {len(trash_files)} file(s). "
                "Deleted files may persist and contain sensitive data."
            ),
            rationale=(
                "Trash directories retain deleted files that may contain "
                "sensitive information. In forensic investigations, these "
                "files can be recovered."
            ),
            remediation=(
                f"Empty trash: 'rm -rf {trash_dir}/*'. "
                "Or use 'shred' for sensitive files before deletion."
            ),
            evidence=FileEvidence(
                path=str(trash_dir),
                content=f"{len(trash_files)} file(s) in trash",
            ),
            detected_value=f"{len(trash_files)} trashed files for {username}",
            expected_value="Trash directory empty or absent",
            affected_component=f"User: {username}",
            confidence=Confidence.LOW,
            false_positive_probability=0.5,
            mitre_attack_ids=["T1070", "T1005"],
            tags=["forensics", "trash", "data-exposure"],
        )

    def _check_swap_files(self, home_path: Path, username: str) -> list:
        findings: list = []
        swp_files: list[Path] = []
        for swp_pattern in (".swp", ".swo", ".swn"):
            try:
                for f in home_path.glob(f"*.{swp_pattern}"):
                    swp_files.append(f)
                    if len(swp_files) >= 5:
                        break
            except OSError:
                continue
            if len(swp_files) >= 5:
                break

        for swp in swp_files:
            findings.append(
                self.finding(
                    finding_id="003",
                    title=f"Editor swap file found: {swp}",
                    description=(
                        f"Editor swap/backup file '{swp}' found for user '{username}'. "
                        "Swap files contain unsaved edits and may include sensitive data."
                    ),
                    rationale=(
                        "Editor swap files (.swp, .swo, .swn) contain the in-memory "
                        "state of edited files, potentially including passwords, "
                        "configuration secrets, or other sensitive data."
                    ),
                    remediation=(
                        f"Remove swap files: "
                        f"'find {home_path} -maxdepth 1 -name '*.swp' -o -name '*.swo' -o -name '*.swn' -delete'. "
                        "Configure editor to store swap files in a private directory."
                    ),
                    evidence=FileEvidence(
                        path=str(swp),
                    ),
                    detected_value=f"Editor swap file: {swp}",
                    expected_value="No editor swap files present",
                    affected_component=f"User: {username}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.4,
                    mitre_attack_ids=["T1070", "T1005"],
                    tags=["forensics", "swap", "data-exposure"],
                )
            )
        return findings
