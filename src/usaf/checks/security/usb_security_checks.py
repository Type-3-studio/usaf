from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class USBDeviceAuthorizationCheck(AuditCheck):
    """Check that USBGuard has a device authorization policy configured."""

    id = "USB-201"
    name = "USB Device Authorization Policy"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Checks that USBGuard has a device authorization policy with explicit allow/block rules"
    depends: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = ["usb", "usbguard", "authorization", "hardening"]

    USBGUARD_RULES = Path("/etc/usbguard/rules.conf")

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        if not self._usbguard_installed():
            return findings

        rules_exist = self.USBGUARD_RULES.exists()

        if not rules_exist:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="USBGuard rules file missing",
                    description="USBGuard is installed but /etc/usbguard/rules.conf does not exist. No device authorization policy is configured.",
                    rationale=(
                        "Without a rules file, USBGuard has no device policy to enforce. "
                        "USBGuard can only block or allow devices if rules define which devices "
                        "are authorized. An empty or missing rules file means no USB devices "
                        "are explicitly authorized, which may leave the system unprotected or "
                        "overly permissive depending on the ImplicitPolicyTarget setting."
                    ),
                    remediation=(
                        "Generate a policy: 'usbguard generate-policy > /etc/usbguard/rules.conf'. "
                        "Review and customize the rules before activating."
                    ),
                    evidence=FileEvidence(
                        path="/etc/usbguard/rules.conf",
                        content="File does not exist",
                    ),
                    detected_value="No USBGuard rules file",
                    expected_value="/etc/usbguard/rules.conf exists with device rules",
                    affected_component="USBGuard policy",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1091", "T1200"],
                    tags=["usb", "usbguard", "authorization"],
                )
            )
            return findings

        rules = self._read_rules()
        if not rules:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="USBGuard rules file is empty",
                    description="/etc/usbguard/rules.conf exists but contains no device rules.",
                    rationale=(
                        "An empty rules file provides no authorization policy. "
                        "USBGuard relies on device rules to determine which USB devices "
                        "are allowed, blocked, or rejected. Without rules, the "
                        "ImplicitPolicyTarget determines behavior, which may default to "
                        "a permissive stance."
                    ),
                    remediation=(
                        "Generate a policy: 'usbguard generate-policy > /etc/usbguard/rules.conf'. "
                        "Then review and customize: 'nano /etc/usbguard/rules.conf'."
                    ),
                    evidence=FileEvidence(
                        path="/etc/usbguard/rules.conf",
                        content="File is empty",
                        size=0,
                    ),
                    detected_value="Empty USBGuard rules file",
                    expected_value="Rules file with device authorization entries",
                    affected_component="USBGuard policy",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1091", "T1200"],
                    tags=["usb", "usbguard", "authorization"],
                )
            )

        return findings

    @staticmethod
    def _usbguard_installed() -> bool:
        return Path("/usr/sbin/usbguard").exists()

    def _read_rules(self) -> list[str]:
        if not self.USBGUARD_RULES.exists():
            return []
        try:
            content = self.USBGUARD_RULES.read_text()
            return [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        except OSError:
            return []


@register_check
class USBGuardConfigurationCheck(AuditCheck):
    """Check USBGuard daemon configuration for security settings."""

    id = "USB-301"
    name = "USBGuard Daemon Configuration"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Checks that the USBGuard daemon is configured with secure settings"
    depends: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = ["usb", "usbguard", "configuration", "hardening"]

    USBGUARD_CONF = Path("/etc/usbguard/usbguard-daemon.conf")

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        if not self._usbguard_installed():
            return findings

        if not self.USBGUARD_CONF.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="USBGuard configuration file missing",
                    description="/etc/usbguard/usbguard-daemon.conf does not exist. The USBGuard daemon cannot operate without a configuration.",
                    rationale=(
                        "Without a daemon configuration file, USBGuard cannot start. "
                        "This means no USB device authorization is enforced, leaving "
                        "the system vulnerable to unauthorized USB device connections."
                    ),
                    remediation=(
                        "Create configuration: 'usbguard generate-config > /etc/usbguard/usbguard-daemon.conf'. "
                        "Review and customize, then start: 'systemctl start usbguard'."
                    ),
                    evidence=FileEvidence(
                        path="/etc/usbguard/usbguard-daemon.conf",
                        content="File does not exist",
                    ),
                    detected_value="No USBGuard configuration",
                    expected_value="/etc/usbguard/usbguard-daemon.conf exists",
                    affected_component="USBGuard daemon",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1091", "T1200"],
                    tags=["usb", "usbguard", "configuration"],
                )
            )
            return findings

        config = self._read_config()

        implicit_policy = config.get("ImplicitPolicyTarget", "").lower()
        if implicit_policy not in ("block", "reject"):
            findings.append(
                self.finding(
                    finding_id="002",
                    title="USBGuard ImplicitPolicyTarget is not restrictive",
                    description=(
                        f"USBGuard ImplicitPolicyTarget is set to '{implicit_policy or 'not configured'}'. "
                        "It should be 'block' or 'reject' to deny unauthorized devices by default."
                    ),
                    rationale=(
                        "The ImplicitPolicyTarget determines what happens to USB devices "
                        "that don't match any explicit rule. 'block' silently ignores the "
                        "device, while 'reject' actively denies it. A permissive default "
                        "allows unauthorized USB devices to connect."
                    ),
                    remediation=(
                        "Set ImplicitPolicyTarget=block in /etc/usbguard/usbguard-daemon.conf "
                        "and restart: 'systemctl restart usbguard'."
                    ),
                    evidence=FileEvidence(
                        path="/etc/usbguard/usbguard-daemon.conf",
                        content=f"ImplicitPolicyTarget={implicit_policy}",
                    ),
                    detected_value=f"ImplicitPolicyTarget={implicit_policy}",
                    expected_value="ImplicitPolicyTarget=block or reject",
                    affected_component="USBGuard policy",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1091", "T1200"],
                    tags=["usb", "usbguard", "configuration"],
                )
            )

        audit_events = config.get("AuditBackend", "").lower()
        if audit_events == "none":
            findings.append(
                self.finding(
                    finding_id="003",
                    title="USBGuard audit logging is disabled",
                    description="USBGuard AuditBackend is set to 'none'. USB device connection events are not being logged.",
                    rationale=(
                        "Without audit logging, USB device connection attempts are not recorded. "
                        "This hinders forensic investigation of physical access attacks and "
                        "violates compliance requirements for auditing."
                    ),
                    remediation=(
                        "Set AuditBackend=LinuxAudit in /etc/usbguard/usbguard-daemon.conf "
                        "and restart: 'systemctl restart usbguard'."
                    ),
                    evidence=FileEvidence(
                        path="/etc/usbguard/usbguard-daemon.conf",
                        content="AuditBackend=none",
                    ),
                    detected_value="USBGuard audit logging disabled",
                    expected_value="AuditBackend=LinuxAudit",
                    affected_component="USBGuard audit",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1070", "T1562"],
                    tags=["usb", "usbguard", "auditing"],
                )
            )

        return findings

    @staticmethod
    def _usbguard_installed() -> bool:
        return Path("/usr/sbin/usbguard").exists()

    def _read_config(self) -> dict[str, str]:
        config: dict[str, str] = {}
        if not self.USBGUARD_CONF.exists():
            return config
        try:
            for raw_line in self.USBGUARD_CONF.read_text().splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    config[key.strip()] = value.strip()
        except OSError:
            pass
        return config
