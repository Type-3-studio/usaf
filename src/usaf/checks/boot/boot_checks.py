from __future__ import annotations

import subprocess

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class SecureBootStatusCheck(AuditCheck):
    """Check if Secure Boot is enabled."""

    id = "BOOT-101"
    name = "Secure Boot Status"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks that UEFI Secure Boot is enabled"
    depends = ["boot"]
    tags = ["boot", "secure-boot", "hardening"]

    def _run_check(self, collectors: dict) -> list:
        boot_data = self._get_data(collectors, "boot")
        findings = []

        secure_boot = boot_data.get("secure_boot", {})
        sb_enabled = secure_boot.get("enabled")

        if sb_enabled is False:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Secure Boot is disabled",
                    description=(
                        "UEFI Secure Boot is disabled on this system. "
                        "The firmware will boot unsigned or improperly signed bootloaders."
                    ),
                    rationale=(
                        "Secure Boot ensures only cryptographically signed bootloaders, "
                        "kernels, and drivers are loaded during boot. Without Secure Boot, "
                        "an attacker with physical access or OS-level root can install a "
                        "bootkit or rootkit that persists across OS reinstalls. Bootkits "
                        "like BootHole, BlackLotus, and ESPecter target the boot process "
                        "and can bypass full-disk encryption."
                    ),
                    remediation=(
                        "Enable Secure Boot in UEFI firmware settings. "
                        "Then verify: 'mokutil --sb-state'. "
                        "Ensure SBAT (Secure Boot Advanced Targeting) is up to date: "
                        "'apt update && apt upgrade'."
                    ),
                    evidence=RegistryEvidence(
                        key="/sys/kernel/security/secureboot",
                        value="0",
                        expected="1",
                        source="/sys/kernel/security/secureboot",
                    ),
                    detected_value="Secure Boot disabled",
                    expected_value="Secure Boot enabled",
                    affected_component="UEFI Secure Boot",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1542", "T1542.001"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
                    tags=["secure-boot", "boot", "firmware"],
                )
            )
        elif sb_enabled is None:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Secure Boot status unknown",
                    description=(
                        "Could not determine Secure Boot status. "
                        "System may not be UEFI-based."
                    ),
                    rationale=(
                        "Unable to verify Secure Boot state. Non-UEFI systems (legacy BIOS) "
                        "lack Secure Boot capability entirely, which means the boot chain "
                        "cannot be cryptographically verified."
                    ),
                    remediation=(
                        "Verify firmware type: 'ls /sys/firmware/efi'. "
                        "If BIOS/legacy, consider migrating to UEFI with Secure Boot. "
                        "If UEFI, ensure the 'secureboot' sysfs file is accessible."
                    ),
                    evidence=RegistryEvidence(
                        key="secure_boot.enabled",
                        value="None (unknown)",
                        expected="True",
                        source="sysfs/subprocess",
                    ),
                    detected_value="Secure Boot: unknown/unavailable",
                    expected_value="Secure Boot enabled",
                    affected_component="Boot firmware",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1542"],
                    tags=["secure-boot", "boot"],
                )
            )

        return findings


@register_check
class KernelLockdownCheck(AuditCheck):
    """Check kernel lockdown mode."""

    id = "BOOT-201"
    name = "Kernel Lockdown Mode"
    category = CheckCategory.BOOT
    severity = Severity.MEDIUM
    description = "Checks if kernel lockdown is enabled"
    depends = ["boot"]
    tags = ["boot", "kernel", "lockdown"]

    def _run_check(self, collectors: dict) -> list:
        boot_data = self._get_data(collectors, "boot")
        findings = []

        lockdown = boot_data.get("kernel_lockdown", {})
        mode = lockdown.get("mode", "")
        enabled = lockdown.get("enabled", False)

        if not enabled:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Kernel lockdown not enabled (mode: {mode or 'none'})",
                    description=(
                        "Kernel lockdown mode is not enabled. "
                        "The kernel allows unrestricted access to its internals."
                    ),
                    rationale=(
                        "Kernel lockdown restricts access to kernel memory and "
                        "/dev/mem, /dev/kmem, /dev/port, and /proc/kcore. When "
                        "lockdown is enabled, even root cannot modify the running "
                        "kernel or read sensitive kernel memory. This prevents "
                        "rootkits and kernel-level tampering even from privileged users."
                    ),
                    remediation=(
                        "Enable kernel lockdown: add 'lockdown=confidentiality' to "
                        "kernel command line in /etc/default/grub: "
                        "GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX lockdown=confidentiality\". "
                        "Then: 'update-grub' and reboot."
                    ),
                    evidence=RegistryEvidence(
                        key="/sys/kernel/security/lockdown",
                        value=mode or "none",
                        expected="confidentiality",
                        source="/sys/kernel/security/lockdown",
                    ),
                    detected_value=f"Lockdown: {mode or 'none'}",
                    expected_value="Lockdown: confidentiality",
                    affected_component="Kernel security",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1562", "T1055"],
                    tags=["kernel", "lockdown", "hardening"],
                )
            )

        return findings


@register_check
class EFIIntegrityCheck(AuditCheck):
    """Check EFI partition integrity."""

    id = "BOOT-301"
    name = "EFI Partition Integrity"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks that the EFI system partition is properly configured"
    depends = ["boot"]
    tags = ["boot", "efi", "integrity"]

    def _run_check(self, collectors: dict) -> list:
        boot_data = self._get_data(collectors, "boot")
        findings = []

        efi = boot_data.get("efi", {})
        efi_available = efi.get("available", False)
        efivars_available = efi.get("efivars", False)
        boot_entries = efi.get("boot_entries", [])

        if not efi_available:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="EFI not detected (legacy BIOS boot)",
                    description=(
                        "System appears to be booting in legacy BIOS mode. "
                        "EFI system partition not found."
                    ),
                    rationale=(
                        "Legacy BIOS boot lacks Secure Boot, measured boot, and "
                        "other UEFI security features. Booting in UEFI mode is a "
                        "prerequisite for Secure Boot, TPM measurements, and "
                        "attestation. Systems without UEFI are more vulnerable to "
                        "bootkits and firmware attacks."
                    ),
                    remediation=(
                        "Convert to UEFI boot if hardware supports it. "
                        "Requires OS reinstall or conversion tools. "
                        "Verify: 'ls /sys/firmware/efi'."
                    ),
                    evidence=RegistryEvidence(
                        key="/sys/firmware/efi",
                        value="not found",
                        expected="directory exists",
                        source="boot collector",
                    ),
                    detected_value="Legacy BIOS boot",
                    expected_value="UEFI boot",
                    affected_component="Boot firmware",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1542"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
                    tags=["efi", "boot", "firmware"],
                )
            )
            return findings

        if not efivars_available:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="EFI variable access not available",
                    description=(
                        "EFI system partition exists but efivars filesystem is "
                        "not mounted or accessible."
                    ),
                    rationale=(
                        "The efivars filesystem (/sys/firmware/efi/efivars) provides "
                        "runtime access to UEFI variables. Without it, boot configuration "
                        "changes and Secure Boot key management are not possible. "
                        "This may indicate the efivarfs module is not loaded."
                    ),
                    remediation=(
                        "Mount efivarfs: 'mount -t efivarfs efivarfs /sys/firmware/efi/efivars'. "
                        "Ensure efivarfs is loaded: 'modprobe efivarfs'."
                    ),
                    evidence=RegistryEvidence(
                        key="/sys/firmware/efi/efivars",
                        value="not accessible",
                        expected="accessible",
                        source="/sys/firmware/efi",
                    ),
                    detected_value="efivars not available",
                    expected_value="efivars accessible",
                    affected_component="EFI firmware",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1542"],
                    tags=["efi", "efivars"],
                )
            )

        if not boot_entries:
            findings.append(
                self.finding(
                    finding_id="003",
                    title="No EFI boot entries found",
                    description=(
                        "No .efi boot entries found on the EFI system partition. "
                        "The system may not have bootloaders installed correctly."
                    ),
                    rationale=(
                        "Missing EFI boot entries can indicate a compromised or "
                        "incomplete boot chain. Attackers who delete legitimate "
                        "boot entries can replace them with malicious ones."
                    ),
                    remediation=(
                        "Reinstall the bootloader: 'grub-install --target=x86_64-efi'. "
                        "Verify: 'efibootmgr -v'."
                    ),
                    evidence=FileEvidence(
                        path="/boot/efi/EFI",
                        content="No .efi files found",
                    ),
                    detected_value="No EFI boot entries",
                    expected_value="Boot entries present",
                    affected_component="EFI boot entries",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1542"],
                    tags=["efi", "bootloader"],
                )
            )

        return findings


@register_check
class GRUBPasswordCheck(AuditCheck):
    """Check if GRUB has a password set."""

    id = "BOOT-401"
    name = "GRUB Password Protection"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks that GRUB bootloader is password-protected"
    depends = ["boot"]
    tags = ["boot", "grub", "authentication"]

    def _run_check(self, collectors: dict) -> list:
        boot_data = self._get_data(collectors, "boot")
        findings = []

        grub = boot_data.get("grub", {})
        password_protected = grub.get("password_protected")

        if password_protected is False:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="GRUB bootloader not password-protected",
                    description=(
                        "GRUB bootloader configuration does not contain "
                        "password or superusers settings."
                    ),
                    rationale=(
                        "Without GRUB password protection, anyone with physical or "
                        "console access can edit kernel boot parameters at startup. "
                        "This allows booting into single-user mode without authentication, "
                        "setting 'init=/bin/bash' to bypass login, or disabling security "
                        "features like module loading and SELinux. Physical access becomes "
                        "root access."
                    ),
                    remediation=(
                        "Set a GRUB password: 'grub-mkpasswd-pbkdf2' to generate hash, "
                        "then add to /etc/grub.d/40_custom: "
                        "'set superusers=\"admin\"' and "
                        "'password_pbkdf2 admin <hash>'. "
                        "Run: 'update-grub'."
                    ),
                    evidence=RegistryEvidence(
                        key="grub.cfg",
                        value="no password/superusers directive",
                        expected="password_pbkdf2 or superusers set",
                        source=grub.get("cfg_path", "/boot/grub/grub.cfg"),
                    ),
                    detected_value="GRUB not password protected",
                    expected_value="GRUB password and superusers configured",
                    affected_component="GRUB bootloader",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1542", "T1059"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.6"],
                    tags=["grub", "bootloader", "authentication"],
                )
            )
        elif password_protected is None:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="GRUB password status unknown",
                    description=(
                        "GRUB configuration file was not found or could not be read. "
                        "Unable to determine if GRUB is password-protected."
                    ),
                    rationale=(
                        "If GRUB is installed but the configuration is inaccessible, "
                        "it may indicate missing bootloader configuration or a system "
                        "that doesn't use GRUB. Verify the bootloader in use."
                    ),
                    remediation=(
                        "Check bootloader: 'ls /boot/grub' or 'ls /boot/grub2'. "
                        "If GRUB is the bootloader, ensure /boot/grub/grub.cfg exists "
                        "and is readable."
                    ),
                    evidence=RegistryEvidence(
                        key="grub.cfg",
                        value="not found or unreadable",
                        expected="readable config file",
                        source="/boot/grub/",
                    ),
                    detected_value="GRUB config status unknown",
                    expected_value="GRUB config accessible",
                    affected_component="GRUB bootloader",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1542"],
                    tags=["grub", "bootloader"],
                )
            )

        return findings


@register_check
class UnsignedKernelsCheck(AuditCheck):
    """Check for unsigned kernel images."""

    id = "BOOT-501"
    name = "Unsigned Kernel Images"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks that kernel images are properly signed"
    depends = ["boot"]
    tags = ["boot", "kernel", "signatures"]

    def _run_check(self, collectors: dict) -> list:
        boot_data = self._get_data(collectors, "boot")
        findings: list = []

        kernel_images = boot_data.get("kernel_images", {})
        images = kernel_images.get("images", [])
        secure_boot = boot_data.get("secure_boot", {})
        sb_enabled = secure_boot.get("enabled")

        if not images:
            return findings

        for image in images:
            path = image.get("path", "")
            if not path:
                continue
            try:
                result = subprocess.run(
                    ["sbverify", "--list", path],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != 0:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Unsigned kernel: {image.get('name', 'unknown')}",
                            description=(
                                f"Kernel image {path} is not signed or signature "
                                "verification failed. It cannot be verified by Secure Boot."
                            ),
                            rationale=(
                                "Unsigned kernels cannot be verified by Secure Boot. "
                                "If Secure Boot is enabled, unsigned kernels will not "
                                "boot. If Secure Boot is disabled, unsigned kernels "
                                "allow attackers to boot tampered kernels. "
                                "All kernels should be signed by a trusted key."
                            ),
                            remediation=(
                                "Install the signed kernel package: "
                                "'apt install linux-image-generic-signed' or "
                                "use 'sbsign' to sign the kernel with a custom key. "
                                "Verify: 'sbverify --list <kernel>'."
                            ),
                            evidence=FileEvidence(
                                path=path,
                            ),
                            detected_value=(
                                f"Unsigned kernel: {image.get('name', 'unknown')}"
                            ),
                            expected_value="Kernel signed with trusted key",
                            affected_component=(
                                f"Kernel: {image.get('name', 'unknown')}"
                            ),
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.1,
                            mitre_attack_ids=["T1542"],
                            tags=["kernel", "signatures", "secure-boot"],
                        )
                    )
            except (OSError, subprocess.SubprocessError):
                if sb_enabled is True:
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=(
                                "Could not verify kernel signature: "
                                f"{image.get('name', 'unknown')}"
                            ),
                            description=(
                                f"Could not verify signature of {path}. "
                                "sbverify tool is not available."
                            ),
                            rationale=(
                                "Without sbverify, kernel signature status is unknown. "
                                "Install sbsigntool to verify kernel signatures."
                            ),
                            remediation=(
                                "Install sbsigntool: 'apt install sbsigntool'. "
                                "Then verify: 'sbverify --list <kernel>'."
                            ),
                            evidence=FileEvidence(
                                path=path,
                            ),
                            detected_value="Signature verification unavailable",
                            expected_value="sbverify available",
                            affected_component=(
                                f"Kernel: {image.get('name', 'unknown')}"
                            ),
                            confidence=Confidence.LOW,
                            false_positive_probability=0.2,
                            mitre_attack_ids=["T1542"],
                            tags=["kernel", "signatures"],
                        )
                    )
                break

        return findings
