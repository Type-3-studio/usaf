import os
import re

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

NETWORK_HOOK_DIRS = [
    "/etc/network/if-up.d",
    "/etc/network/if-down.d",
    "/etc/network/if-pre-up.d",
    "/etc/network/if-post-down.d",
    "/etc/NetworkManager/dispatcher.d",
    "/usr/lib/NetworkManager/dispatcher.d",
    "/etc/dhcp/dhclient-enter-hooks.d",
    "/etc/dhcp/dhclient-exit-hooks.d",
]

KNOWN_NETWORK_HOOKS = {
    "avahi-autoipd",
    "ethtool",
    "ifenslave",
    "ipv6-privacy",
    "ntpdate",
    "openssh-server",
    "postfix",
    "resolvconf",
    "smartmontools",
    "samba",
    "wpasupplicant",
    "nfs-common",
    "apt",
    "chrony",
    "cloud-init",
    "dhclient",
    "ntp",
    "ppp",
    "wireless-tools",
    "acpi-support",
    "pm-utils",
    "01-ifupdown",
    "02-cron",
    "03-samba",
    "04-ntpdate",
}

SUSPICIOUS_HOOK_PATTERNS = [
    "wget ",
    "curl ",
    "nc ",
    "ncat",
    "bash -c",
    "python",
    "perl -e",
    "mkfifo",
    "/dev/tcp/",
    "base64 -d",
    "chmod +x",
    "nohup",
    "setsid",
    "socat",
    "openssl",
    "tsocks",
    "proxychains",
]


KNOWN_SSH_FORCED_COMMANDS: dict[str, str] = {
    "rsync": "Remote file sync",
    "rrsync": "Restricted rsync",
    "borg": "Borg backup",
    "borg1": "Borg backup v1",
    "restic": "Restic backup",
    "git-receive-pack": "Git push",
    "git-upload-pack": "Git pull",
    "git-upload-archive": "Git archive",
    "svnserve": "SVN server",
    "unison": "File sync",
    "cvs": "CVS server",
    "/usr/lib/openssh/sftp-server": "SFTP server",
    "/usr/libexec/openssh/sftp-server": "SFTP server",
    "/usr/lib/openssh/ssh-keysign": "SSH key sign",
}


@register_check
class NetworkHookScriptsCheck(AuditCheck):
    id = "PER-601"
    name = "Network Hook Scripts"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects suspicious network hook scripts that trigger on network events"
    depends = []
    tags = ["persistence", "network", "hooks", "trigger"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        for hook_dir in NETWORK_HOOK_DIRS:
            if not os.path.isdir(hook_dir):
                continue
            try:
                entries = sorted(os.listdir(hook_dir))
            except (OSError, PermissionError):
                continue

            for entry in entries:
                if not os.path.isfile(os.path.join(hook_dir, entry)):
                    continue
                if entry in KNOWN_NETWORK_HOOKS:
                    continue
                if not os.access(os.path.join(hook_dir, entry), os.X_OK):
                    continue

                fp = os.path.join(hook_dir, entry)
                try:
                    with open(fp) as f:
                        content = f.read()
                except (OSError, PermissionError):
                    content = ""

                suspicious = [p for p in SUSPICIOUS_HOOK_PATTERNS if p in content]

                findings.append(
                    self.finding(
                        finding_id="001" if suspicious else "002",
                        title=(
                            f"Suspicious network hook: {entry}"
                            if suspicious
                            else f"Unknown network hook script: {entry}"
                        ),
                        description=(
                            f"Network hook script '{entry}' in {hook_dir} "
                            f"is executable and unknown.{' Contains suspicious patterns: ' + ', '.join(suspicious[:5]) if suspicious else ''}"
                        ),
                        rationale=(
                            "Network hook scripts execute automatically when network "
                            "interfaces go up/down. Attackers use these hooks for "
                            "network-triggered persistence — the script executes "
                            "whenever the system connects to a network, which is "
                            "ideal for laptops and cloud instances that change "
                            "networks frequently."
                        ),
                        remediation=(
                            f"Investigate: 'cat {fp}'\n"
                            f"Check purpose with: 'dpkg -S {fp}'\n"
                            f"Remove if unauthorized: 'rm {fp}'"
                        ),
                        evidence=FileEvidence(
                            path=fp,
                            content=content[:500],
                            owner="",
                            group="",
                        ),
                        detected_value=entry,
                        expected_value="Only known network hook scripts should exist",
                        affected_component=entry,
                        confidence=Confidence.HIGH if suspicious else Confidence.LOW,
                        false_positive_probability=0.2 if suspicious else 0.6,
                        mitre_attack_ids=["T1546.010"],
                        tags=["persistence", "network", "hook", "trigger"],
                    )
                )

        return findings


@register_check
class SshForcedCommandsCheck(AuditCheck):
    id = "PER-602"
    name = "SSH Forced Commands in Authorized Keys"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects SSH authorized keys with forced commands"
    depends = ["ssh_config"]
    tags = ["persistence", "ssh", "authorized-keys", "forced-command"]

    def _run_check(self, collectors: dict) -> list:
        ssh_data = self._get_data(collectors, "ssh_config")
        findings: list = []

        auth_dirs = ssh_data.get("authorized_keys_dirs", [])
        for entry in auth_dirs:
            path = entry.get("path", "")
            user = entry.get("user", "unknown")
            if not path or not os.path.exists(path):
                continue
            try:
                with open(path) as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue

            for line in content.split("\n"):
                line_stripped = line.strip()
                if not line_stripped or line_stripped.startswith("#"):
                    continue
                if line_stripped.startswith("command=") or line_stripped.startswith('command="'):
                    cmd_match = re.search(r'command="([^"]*)"', line_stripped)
                    if not cmd_match:
                        cmd_match = re.search(r"command='([^']*)'", line_stripped)
                    if not cmd_match:
                        cmd_match = re.search(r"command=(\S+)", line_stripped)
                    forced_cmd = cmd_match.group(1) if cmd_match else "<unknown>"

                    is_known = forced_cmd in KNOWN_SSH_FORCED_COMMANDS or any(
                        forced_cmd.startswith(k) for k in KNOWN_SSH_FORCED_COMMANDS
                    )
                    is_suspicious = any(
                        p in forced_cmd.lower()
                        for p in ["bash ", "sh ", "python", "perl", "wget", "curl", "nc ", "ncat"]
                    )
                    severity_level = Severity.CRITICAL if is_suspicious and not is_known else Severity.MEDIUM

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Forced command in SSH key for {user}",
                            description=(
                                f"Authorized key file {path} for user '{user}' "
                                f"has forced command: '{forced_cmd}'. "
                                f"Known: {is_known}, Suspicious: {is_suspicious}"
                            ),
                            rationale=(
                                "SSH forced commands override the client's requested "
                                "command, executing only the specified command instead. "
                                "This is used legitimately for restricted tools (rsync, "
                                "borg, git), but attackers abuse forced commands to "
                                "execute arbitrary code when a specific key authenticates, "
                                "bypassing the user's shell entirely."
                            ),
                            remediation=(
                                f"Inspect: 'cat {path}'\n"
                                f"Remove the forced command prefix if unauthorized\n"
                                f"Rotate the SSH key pair\n"
                                f"Audit the user account for compromise"
                            ),
                            evidence=FileEvidence(
                                path=path,
                                content=line_stripped[:500],
                                owner=user,
                                group="",
                            ),
                            detected_value=f"Forced command: {forced_cmd}",
                            expected_value="No forced commands in authorized keys",
                            affected_component=path,
                            confidence=Confidence.HIGH if is_suspicious else Confidence.MEDIUM,
                            false_positive_probability=0.1 if is_suspicious else 0.3,
                            mitre_attack_ids=["T1562.003"],
                            tags=["persistence", "ssh", "authorized-keys", "forced-command"],
                            severity=severity_level,
                        )
                    )

        return findings


@register_check
class SshAuthorizedKeysFileTamperCheck(AuditCheck):
    id = "PER-603"
    name = "SSH AuthorizedKeysFile Tampering"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects tampering with AuthorizedKeysFile directive in sshd_config"
    depends = ["ssh_config"]
    tags = ["persistence", "ssh", "authorized-keys", "tampering"]

    def _run_check(self, collectors: dict) -> list:
        ssh_data = self._get_data(collectors, "ssh_config")
        findings: list = []

        sshd_config = ssh_data.get("sshd_config", {})
        directives = sshd_config.get("directives", {})

        auth_keys_file = directives.get("authorizedkeysfile", ".ssh/authorized_keys")

        expected_default = ".ssh/authorized_keys"

        if auth_keys_file != expected_default:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AuthorizedKeysFile directive modified",
                    description=(
                        f"sshd_config AuthorizedKeysFile is set to "
                        f"'{auth_keys_file}' instead of default "
                        f"'{expected_default}'."
                    ),
                    rationale=(
                        "The AuthorizedKeysFile directive controls which file sshd "
                        "reads for authorized public keys. Attackers can change this "
                        "to point to a world-writable or unexpected location, allowing "
                        "them to add their SSH key without modifying the user's "
                        "authorized_keys file. This is a stealthy persistence "
                        "mechanism that evades normal authorized_keys audits."
                    ),
                    remediation=(
                        f"Check sshd_config: 'grep AuthorizedKeysFile /etc/ssh/sshd_config'\n"
                        f"Revert to default: sed -i "
                        f"'s/^AuthorizedKeysFile.*/AuthorizedKeysFile {expected_default}/' "
                        f"/etc/ssh/sshd_config\n"
                        f"Restart sshd: 'systemctl restart sshd'"
                    ),
                    evidence=RegistryEvidence(
                        key="AuthorizedKeysFile",
                        value=auth_keys_file,
                        expected=expected_default,
                        source=sshd_config.get("path", "/etc/ssh/sshd_config"),
                    ),
                    detected_value=auth_keys_file,
                    expected_value=expected_default,
                    affected_component="sshd_config",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1562.003"],
                    tags=["persistence", "ssh", "authorized-keys", "tampering"],
                )
            )

        auth_dirs = ssh_data.get("authorized_keys_dirs", [])
        for entry in auth_dirs:
            path = entry.get("path", "")
            try:
                if os.path.exists(path):
                    st = os.stat(path)
                    file_perms = oct(st.st_mode)[-3:]
                    if file_perms > "600" and not path.startswith("/root/"):
                        pass
            except (OSError, PermissionError):
                continue

        return findings
