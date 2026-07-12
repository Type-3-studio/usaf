from __future__ import annotations

from typing import Any, ClassVar

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class SudoPasswordEnforcementCheck(AuditCheck):
    """Check that sudo password authentication is enforced globally."""

    id = "USR-402"
    name = "Sudo Password Enforcement"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Checks that sudo requires password authentication globally and is not bypassed via Defaults !authenticate"
    depends: ClassVar[list[str]] = ["sudo"]
    tags: ClassVar[list[str]] = ["sudo", "authentication", "privilege", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sudo_data = self._get_data(collectors, "sudo")
        entries = sudo_data.get("sudoers_entries", [])

        for entry in entries:
            content = entry.get("content", "")
            if not content or not content.startswith("Defaults"):
                continue

            if "!authenticate" in content:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="Sudo password authentication globally disabled",
                        description=(
                            f"Sudoers Defaults entry disables password authentication: "
                            f"'{content}'. Sudo will not prompt for a password."
                        ),
                        rationale=(
                            "The '!authenticate' Defaults setting disables password "
                            "verification for all sudo commands globally. This means any "
                            "user with sudo access can execute privileged commands without "
                            "providing their password. If an attacker compromises a sudo "
                            "user's session, they immediately gain root without needing "
                            "to know the user's password."
                        ),
                        remediation=(
                            "Remove '!authenticate' from the Defaults line in sudoers. "
                            "Use 'visudo' to edit. If password-less sudo is needed for "
                            "specific use cases, grant NOPASSWD only to specific commands "
                            "for specific users rather than disabling globally."
                        ),
                        evidence=RegistryEvidence(
                            key=entry.get("file", "sudoers"),
                            value=content,
                            expected="Defaults authenticate (or no !authenticate)",
                            source=entry.get("file", "sudoers"),
                        ),
                        detected_value="sudo authenticate disabled globally",
                        expected_value="Password required for all sudo commands",
                        affected_component="sudoers configuration",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1548.003"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                        tags=["sudo", "authentication", "hardening"],
                    )
                )
                break

        return findings


@register_check
class SudoTimestampTimeoutCheck(AuditCheck):
    """Check that sudo timestamp timeout is not excessive."""

    id = "USR-403"
    name = "Sudo Timestamp Timeout"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Checks that sudo timestamp_timeout is set to a reasonable value (max 15 minutes)"
    depends: ClassVar[list[str]] = ["sudo"]
    tags: ClassVar[list[str]] = ["sudo", "authentication", "timeout", "hardening"]

    MAX_TIMEOUT_MINUTES = 15

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sudo_data = self._get_data(collectors, "sudo")
        entries = sudo_data.get("sudoers_entries", [])

        timeout_value: int | None = None
        timeout_source: str | None = None

        for entry in entries:
            content = entry.get("content", "")
            if not content or not content.startswith("Defaults"):
                continue

            if "timestamp_timeout" not in content:
                continue

            parts = content.split()
            for part in parts:
                if part.startswith("timestamp_timeout"):
                    val_str = part.split("=")[1].strip()
                    try:
                        timeout_value = int(val_str)
                        timeout_source = entry.get("file", "sudoers")
                    except (ValueError, IndexError):
                        pass

        if timeout_value is None:
            return findings

        description = ""
        detected = ""
        expected = ""

        if timeout_value == 0:
            description = (
                f"Sudo timestamp_timeout is set to 0 in {timeout_source}. "
                "Sudo will prompt for a password on every command."
            )
            detected = "timestamp_timeout=0 (prompt always)"
            expected = "timestamp_timeout between 1 and 15"
        elif timeout_value == -1:
            description = (
                f"Sudo timestamp_timeout is set to -1 in {timeout_source}. "
                "The sudo timestamp never expires — a single authentication "
                "grants unlimited sudo access."
            )
            detected = "timestamp_timeout=-1 (never expires)"
            expected = "timestamp_timeout between 1 and 15"
        elif timeout_value > self.MAX_TIMEOUT_MINUTES:
            description = (
                f"Sudo timestamp_timeout is set to {timeout_value} minutes in "
                f"{timeout_source}. CIS recommends a maximum of {self.MAX_TIMEOUT_MINUTES} "
                "minutes."
            )
            detected = f"timestamp_timeout={timeout_value} minutes"
            expected = f"timestamp_timeout <= {self.MAX_TIMEOUT_MINUTES}"
        else:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"Sudo timestamp timeout is{' too long' if timeout_value != 0 else ' set to prompt always'}: {timeout_value}",
                description=description,
                rationale=(
                    "The sudo timestamp caches successful authentication so users "
                    "do not re-enter their password. An excessively long timeout (or "
                    "infinite with -1) increases the window of opportunity for an "
                    "attacker who gains access to an authenticated session. A timeout "
                    "of 0 forces re-authentication for every command, which is overly "
                    "burdensome. CIS recommends 5-15 minutes."
                ),
                remediation=(
                    "Set timestamp_timeout to a reasonable value: "
                    "'Defaults timestamp_timeout=5' in sudoers. "
                    "Use 'visudo' to edit. Value 0 prompts always; "
                    "values 1-15 are reasonable; -1 disables timeout entirely."
                ),
                evidence=RegistryEvidence(
                    key=timeout_source or "sudoers",
                    value=f"timestamp_timeout={timeout_value}",
                    expected=f"timestamp_timeout between 1 and {self.MAX_TIMEOUT_MINUTES}",
                    source=timeout_source or "sudoers",
                ),
                detected_value=detected,
                expected_value=expected,
                affected_component="sudoers configuration",
                confidence=Confidence.HIGH if timeout_value == -1 else Confidence.MEDIUM,
                false_positive_probability=0.05 if timeout_value == -1 else 0.15,
                mitre_attack_ids=["T1548.003"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                tags=["sudo", "timeout", "hardening"],
            )
        )

        return findings


@register_check
class SudoLoggingCheck(AuditCheck):
    """Check that sudo logging is properly configured."""

    id = "USR-404"
    name = "Sudo Logging Configuration"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Checks that sudo commands are logged (log_input/log_output or syslog configured)"
    depends: ClassVar[list[str]] = ["sudo"]
    tags: ClassVar[list[str]] = ["sudo", "logging", "auditing", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sudo_data = self._get_data(collectors, "sudo")
        entries = sudo_data.get("sudoers_entries", [])

        has_log_input = False
        has_log_output = False
        has_syslog = False
        log_options_found: list[str] = []

        for entry in entries:
            content = entry.get("content", "")
            if not content:
                continue

            if "log_input" in content:
                has_log_input = True
                log_options_found.append(f"log_input ({entry.get('file', '')})")
            if "log_output" in content:
                has_log_output = True
                log_options_found.append(f"log_output ({entry.get('file', '')})")
            if content.startswith("Defaults") and "syslog" in content:
                has_syslog = True
                log_options_found.append(f"syslog ({entry.get('file', '')})")

        if not has_log_input and not has_log_output and not has_syslog:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Sudo command logging is not configured",
                    description=(
                        "No sudo logging options found (log_input, log_output, or syslog). "
                        "Sudo commands are not being logged to any audit destination."
                    ),
                    rationale=(
                        "Without sudo logging, there is no record of who executed which "
                        "privileged commands. This severely hinders incident investigation "
                        "and compliance auditing. Sudo's log_input and log_output record "
                        "the actual I/O of sudo sessions, while syslog sends events to "
                        "the system logging facility. Both should be enabled."
                    ),
                    remediation=(
                        "Add to sudoers: 'Defaults log_input, log_output'. "
                        "Also enable syslog logging: 'Defaults syslog=auth'. "
                        "Use 'visudo' to edit. Verify logs appear in /var/log/auth.log."
                    ),
                    evidence=RegistryEvidence(
                        key="sudoers",
                        value="No logging options configured",
                        expected="log_input, log_output, and/or syslog configured",
                        source="sudoers entries",
                    ),
                    detected_value="No sudo logging",
                    expected_value="sudo logging enabled (log_input/log_output/syslog)",
                    affected_component="sudoers configuration",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1070", "T1562"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                    tags=["sudo", "logging", "auditing", "hardening"],
                )
            )
        elif not has_log_input and not has_log_output:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Sudo I/O logging is not enabled",
                    description=(
                        "Sudo syslog is configured but log_input/log_output are not. "
                        "Command input and output are not recorded, limiting forensic detail."
                    ),
                    rationale=(
                        "Sudo syslog logging records the command executed but not the "
                        "input/output of the session. log_input and log_output capture "
                        "the full terminal session, providing complete forensic evidence "
                        "of what occurred during privileged operations."
                    ),
                    remediation=(
                        "Add to sudoers: 'Defaults log_input, log_output'. "
                        "Use 'visudo' to edit. Ensure /var/log/sudo-io exists."
                    ),
                    evidence=RegistryEvidence(
                        key="sudoers",
                        value="syslog only, no log_input/log_output",
                        expected="log_input, log_output, and syslog configured",
                        source="sudoers entries",
                    ),
                    detected_value="Only syslog logging configured",
                    expected_value="Full I/O logging (log_input + log_output)",
                    affected_component="sudoers configuration",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1070"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                    tags=["sudo", "logging", "auditing"],
                )
            )

        return findings
