from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class USBGuardCheck(AuditCheck):
    """Check that USB storage is restricted."""

    id = "USB-101"
    name = "USB Storage Restriction"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Checks that USB mass storage is disabled or restricted via kernel module blacklisting or usbguard"
    depends = []
    tags = ["usb", "physical-security", "data-exfiltration"]

    USB_STORAGE_BLACKLIST = Path("/etc/modprobe.d/usb-storage-blacklist.conf")
    USBGUARD_CONF = Path("/etc/usbguard/usbguard-daemon.conf")
    USBGUARD_RULES = Path("/etc/usbguard/rules.conf")

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        usb_storage_blocked = self._is_usb_storage_blacklisted()
        usbguard_installed = self._is_usbguard_installed()
        usbguard_active = self._is_usbguard_active()

        if usb_storage_blocked:
            return findings

        if usbguard_active:
            return findings

        if not usb_storage_blocked and not usbguard_installed and not usbguard_active:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="USB mass storage is not restricted",
                    description="USB storage driver is not blacklisted and usbguard is not installed. Unauthorized USB devices can be used to exfiltrate data or introduce malware.",
                    rationale=(
                        "Without USB storage restrictions, an attacker with physical access can "
                        "exfiltrate sensitive data using a USB drive, or introduce malware via a "
                        "malicious USB device (e.g., BadUSB, Rubber Ducky). USBGuard provides "
                        "device-level authorization; kernel module blacklisting prevents USB mass "
                        "storage entirely. Both controls are defense-in-depth against physical attacks."
                    ),
                    remediation=(
                        "Option 1 - Blacklist USB storage: "
                        "echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage-blacklist.conf && "
                        "update-initramfs -u. "
                        "Option 2 - Install USBGuard: 'apt install usbguard && usbguard generate-policy && systemctl enable --now usbguard'."
                    ),
                    evidence=FileEvidence(
                        path="/etc/modprobe.d/",
                        content="USB storage blacklist not found; usbguard not installed",
                    ),
                    detected_value="USB storage not blocked, usbguard not active",
                    expected_value="USB storage blacklisted OR usbguard active",
                    affected_component="kernel (USB subsystem)",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1091", "T1200"],
                    tags=["usb", "physical-security", "data-exfiltration"],
                )
            )

        return findings

    def _is_usb_storage_blacklisted(self) -> bool:
        if not self.USB_STORAGE_BLACKLIST.exists():
            return False
        try:
            content = self.USB_STORAGE_BLACKLIST.read_text()
            return "blacklist usb-storage" in content
        except OSError:
            return False

    def _is_usbguard_installed(self) -> bool:
        return Path("/usr/sbin/usbguard").exists()

    def _is_usbguard_active(self) -> bool:
        if not self.USBGUARD_CONF.exists():
            return False
        try:
            content = self.USBGUARD_CONF.read_text()
            return "ImplicitPolicyTarget=block" in content or "ImplicitPolicyTarget=reject" in content
        except OSError:
            return False
