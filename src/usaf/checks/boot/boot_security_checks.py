from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class SbatStatusCheck(AuditCheck):
    id = "BOOT-601"
    name = "SBAT Status"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks if SBAT (Secure Boot Advanced Targeting) revocation data is current"
    depends = []
    tags = ["boot", "secure-boot", "sbat", "hardening"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []
        sbat_found = False
        sbat_dir = Path("/sys/firmware/efi/efivars")
        if sbat_dir.exists():
            try:
                for p in sbat_dir.iterdir():
                    if "sbat" in p.name.lower():
                        sbat_found = True
                        break
            except OSError:
                pass

        if sbat_found:
            return findings

        if not Path("/sys/firmware/efi").is_dir():
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="SBAT revocation data not found",
                description=(
                    "No SBAT (Secure Boot Advanced Targeting) EFI variable found. "
                    "SBAT provides revocation for signed bootloaders and shims."
                ),
                rationale=(
                    "SBAT allows revocation of specific bootloader versions without "
                    "revoking the entire signing key. Without SBAT, attackers can "
                    "downgrade to old, vulnerable bootloader versions with known "
                    "exploits (e.g., BootHole, BlackLotus). SBAT is critical for "
                    "maintaining Secure Boot security over time."
                ),
                remediation=(
                    "Update shim-signed and grub-efi packages: "
                    "'apt update && apt install --reinstall shim-signed grub-efi-amd64-signed'. "
                    "Verify: 'mokutil --sb-state' and check 'sbctl status'."
                ),
                evidence=RegistryEvidence(
                    key="efi.sbat_variable",
                    value="not found",
                    expected="SBAT EFI variable present",
                    source="/sys/firmware/efi/efivars/",
                ),
                detected_value="No SBAT variable in EFI vars",
                expected_value="SBAT variable present",
                affected_component="UEFI Secure Boot",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1542"],
                tags=["boot", "secure-boot", "sbat", "hardening"],
            )
        )
        return findings


@register_check
class KernelImageCountCheck(AuditCheck):
    id = "BOOT-602"
    name = "Kernel Image Count"
    category = CheckCategory.BOOT
    severity = Severity.MEDIUM
    description = "Checks that the number of installed kernel images is within reasonable limits"
    depends = ["boot"]
    tags = ["boot", "kernels", "disk-space", "housekeeping"]

    MAX_KERNELS = 5

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        boot_data = self._get_data(collectors, "boot")
        images = boot_data.get("kernel_images", {}).get("images", [])

        kernel_count = len(images)

        if kernel_count <= self.MAX_KERNELS:
            return findings

        kernel_names = [img.get("name", "") for img in images]

        findings.append(
            self.finding(
                finding_id="001",
                title=f"Excessive kernel images: {kernel_count}",
                description=(
                    f"There are {kernel_count} kernel images in /boot. "
                    f"Recommended maximum is {self.MAX_KERNELS}. "
                    f"Installed: {', '.join(kernel_names)}."
                ),
                rationale=(
                    "Each kernel image consumes space in /boot, which is often a "
                    "small, separate partition. Accumulated old kernels can fill /boot, "
                    "causing boot failures, failed package updates, and system instability. "
                    "Old kernels also increase the attack surface if they have known "
                    "vulnerabilities."
                ),
                remediation=(
                    "Remove old kernels: 'apt autoremove --purge'. "
                    "Or manually: 'dpkg --purge linux-image-X.X.X-X-generic'. "
                    "Keep only the current and one previous kernel."
                ),
                evidence=RegistryEvidence(
                    key="boot.kernel_count",
                    value=str(kernel_count),
                    expected=f"<={self.MAX_KERNELS}",
                    source="/boot/",
                ),
                detected_value=f"{kernel_count} kernel images",
                expected_value=f"{self.MAX_KERNELS} or fewer",
                affected_component="/boot",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1499"],
                tags=["boot", "kernels", "disk-space", "housekeeping"],
            )
        )
        return findings


@register_check
class LatestKernelRunningCheck(AuditCheck):
    id = "BOOT-603"
    name = "Latest Kernel Running"
    category = CheckCategory.BOOT
    severity = Severity.MEDIUM
    description = "Checks that the system is running the latest installed kernel"
    depends = ["kernel", "boot"]
    tags = ["boot", "kernels", "updates", "security"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        kernel_data = self._get_data(collectors, "kernel")
        boot_data = self._get_data(collectors, "boot")

        running_release = kernel_data.get("kernel", {}).get("release", "")
        images = boot_data.get("kernel_images", {}).get("images", [])

        if not running_release or not images:
            return findings

        installed_versions: list[str] = []
        for img in images:
            name = img.get("name", "")
            ver = name.replace("vmlinuz-", "", 1)
            installed_versions.append(ver)

        if not installed_versions:
            return findings

        sorted_versions = sorted(installed_versions, key=self._version_key, reverse=True)
        latest_version = sorted_versions[0]

        if running_release == latest_version:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Not running the latest kernel",
                description=(
                    f"Running kernel: {running_release}. "
                    f"Latest installed: {latest_version}. "
                    f"Reboot required to activate the new kernel."
                ),
                rationale=(
                    "Running an older kernel means the system lacks the latest security "
                    "fixes and vulnerability patches. Kernel updates often address critical "
                    "CVEs that can only be remediated by rebooting into the new kernel."
                ),
                remediation=(
                    "Reboot the system to load the latest kernel: 'reboot'. "
                    "Check if services need restart: 'needrestart'."
                ),
                evidence=RegistryEvidence(
                    key="kernel.running",
                    value=running_release,
                    expected=latest_version,
                    source="uname -r / /boot",
                ),
                detected_value=f"Running {running_release}",
                expected_value=f"Running {latest_version}",
                affected_component="Kernel",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1499"],
                tags=["boot", "kernels", "updates", "security"],
            )
        )
        return findings

    def _version_key(self, version: str) -> tuple:
        import re
        nums = re.findall(r"\d+", version)
        return tuple(int(n) for n in nums)


@register_check
class EfiBootEntryCheck(AuditCheck):
    id = "BOOT-604"
    name = "EFI Boot Entry Changes"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks for unexpected EFI boot entries that may indicate tampering"
    depends = ["boot"]
    tags = ["boot", "efi", "integrity", "persistence"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        boot_data = self._get_data(collectors, "boot")
        efi = boot_data.get("efi", {})
        boot_entries = efi.get("boot_entries", [])

        if not boot_entries:
            return findings

        SHIM_ALLOWLIST: set[str] = {"shim", "mmx64", "fbx64", "shimx64"}

        for entry in boot_entries:
            name = Path(entry).name if entry else entry
            name_lower = name.lower().replace(".efi", "")
            if any(k in name_lower for k in SHIM_ALLOWLIST):
                continue
            if name_lower.startswith("boot") or "grub" in name_lower or "systemd" in name_lower or "microsoft" in name_lower:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected EFI boot entry: {name}",
                    description=(
                        f"Unexpected EFI boot entry found: '{entry}'. "
                        f"This boot entry is not a standard Ubuntu/systemd-boot entry."
                    ),
                    rationale=(
                        "Unexpected EFI boot entries may indicate bootkit installation, "
                        "dual-boot configuration changes, or firmware tampering. "
                        "Attackers like BlackLotus and BootHole install malicious EFI "
                        "binaries that persist across OS reinstalls."
                    ),
                    remediation=(
                        f"Review EFI entry: 'ls -la /boot/efi/EFI/{entry}'. "
                        f"Check with 'efibootmgr -v'. "
                        f"Remove if unauthorized: 'efibootmgr -B -b <bootnum>'."
                    ),
                    evidence=FileEvidence(
                        path=f"/boot/efi/EFI/{entry}",
                        content="Unexpected EFI boot entry",
                    ),
                    detected_value=f"EFI entry: {entry}",
                    expected_value="Only standard boot entries",
                    affected_component=f"EFI: {entry}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1542", "T1542.001"],
                    tags=["boot", "efi", "integrity", "persistence"],
                )
            )
        return findings


@register_check
class KernelLockdownConfidentialityCheck(AuditCheck):
    id = "BOOT-605"
    name = "Kernel Lockdown Mode"
    category = CheckCategory.BOOT
    severity = Severity.MEDIUM
    description = "Checks if kernel lockdown is set to confidentiality mode (strongest)"
    depends = ["boot"]
    tags = ["boot", "lockdown", "kernel", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        boot_data = self._get_data(collectors, "boot")
        lockdown = boot_data.get("kernel_lockdown", {})

        mode = lockdown.get("mode", "").strip()

        if not mode or mode == "none":
            return findings

        if "confidentiality" in mode.lower():
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Kernel lockdown not at confidentiality mode",
                description=(
                    f"Kernel lockdown is at '{mode}' level, not 'confidentiality'. "
                    f"The lockdown feature restricts user-space access to kernel features."
                ),
                rationale=(
                    "Kernel lockdown 'integrity' mode prevents modification of the "
                    "running kernel but still allows reading kernel memory. The "
                    "'confidentiality' mode additionally restricts read access, "
                    "preventing extraction of kernel secrets, memory contents, and "
                    "cryptographic keys via /proc/kcore, /dev/mem, and debugfs."
                ),
                remediation=(
                    "Add lockdown=confidentiality to the kernel cmdline in /etc/default/grub: "
                    "GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX lockdown=confidentiality\". "
                    "Then: update-grub && reboot."
                ),
                evidence=RegistryEvidence(
                    key="/sys/kernel/security/lockdown",
                    value=mode,
                    expected="confidentiality",
                    source="/sys/kernel/security/lockdown",
                ),
                detected_value=f"Lockdown mode: {mode}",
                expected_value="Lockdown mode: confidentiality",
                affected_component="Kernel lockdown",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1542"],
                tags=["boot", "lockdown", "kernel", "hardening"],
            )
        )
        return findings


@register_check
class GrubConfigPermissionsCheck(AuditCheck):
    id = "BOOT-606"
    name = "GRUB Configuration Permissions"
    category = CheckCategory.BOOT
    severity = Severity.HIGH
    description = "Checks that GRUB configuration files are not world-readable"
    depends = ["boot"]
    tags = ["boot", "grub", "permissions", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        boot_data = self._get_data(collectors, "boot")
        grub = boot_data.get("grub", {})

        cfg_path = grub.get("cfg_path")
        if not cfg_path:
            return findings

        path = Path(cfg_path)
        try:
            st = path.stat()
        except OSError:
            return findings

        mode = stat.S_IMODE(st.st_mode)

        if not (mode & stat.S_IROTH):
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="GRUB config is world-readable",
                description=(
                    f"GRUB configuration '{cfg_path}' has permissions {oct(mode)[2:]}, "
                    f"making it readable by all users. GRUB configs may contain "
                    f"password hashes."
                ),
                rationale=(
                    "GRUB configuration files may contain password hashes for "
                    "boot-time authentication. World-readable permissions expose "
                    "these hashes to local users, enabling offline password cracking "
                    "and potential boot manipulation."
                ),
                remediation=(
                    f"Restrict permissions: 'chmod 640 {cfg_path}'. "
                    f"Ensure GRUB password is set: 'grub-mkpasswd-pbkdf2'."
                ),
                evidence=FileEvidence(
                    path=cfg_path,
                    permission=oct(mode)[2:],
                    owner=str(st.st_uid),
                    size=st.st_size,
                    content="World-readable GRUB config",
                ),
                detected_value=f"Permissions {oct(mode)[2:]}",
                expected_value="Not world-readable (e.g., 640)",
                affected_component=cfg_path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1542"],
                tags=["boot", "grub", "permissions", "hardening"],
            )
        )
        return findings


@register_check
class BootPartitionMountCheck(AuditCheck):
    id = "BOOT-607"
    name = "Boot Partition Mount Options"
    category = CheckCategory.BOOT
    severity = Severity.MEDIUM
    description = "Checks that /boot is mounted with nosuid and nodev"
    depends = ["mounts"]
    tags = ["boot", "mounts", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        mounts_data = self._get_data(collectors, "mounts")
        mounts = mounts_data.get("mounts", [])

        boot_mount = None
        for m in mounts:
            if m.get("mount_point") in ("/boot", "/boot/efi"):
                boot_mount = m
                break

        if boot_mount is None:
            return findings

        options = set(boot_mount.get("options", "").split(","))

        missing: list[str] = []
        for opt in ("nosuid", "nodev"):
            if opt not in options:
                missing.append(opt)

        if not missing:
            return findings

        mount_point = boot_mount.get("mount_point", "/boot")

        findings.append(
            self.finding(
                finding_id="001",
                title=f"Missing mount options on {mount_point}",
                description=(
                    f"'{mount_point}' is mounted without {', '.join(missing)}. "
                    f"Current options: {boot_mount.get('options', '')}."
                ),
                rationale=(
                    "The boot partition contains kernel images and bootloader "
                    "configuration. Without nosuid, SUID binaries could be placed "
                    "on /boot. Without nodev, device nodes could be created. While "
                    "/boot is often mounted read-only, these options provide defense "
                    "in depth against tampering."
                ),
                remediation=(
                    f"Add {', '.join(missing)} to /etc/fstab for {mount_point} and "
                    f"remount: 'mount -o remount,{','.join(missing)} {mount_point}'."
                ),
                evidence=RegistryEvidence(
                    key=f"mount.{mount_point}.options",
                    value=boot_mount.get("options", ""),
                    expected=f"defaults,{','.join(missing)}",
                    source="/proc/mounts",
                ),
                detected_value=f"Missing {', '.join(missing)} on {mount_point}",
                expected_value=f"nosuid,nodev on {mount_point}",
                affected_component=mount_point,
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1222"],
                tags=["boot", "mounts", "hardening"],
            )
        )
        return findings


@register_check
class InitramfsPresentCheck(AuditCheck):
    id = "BOOT-608"
    name = "Initramfs Image Presence"
    category = CheckCategory.BOOT
    severity = Severity.MEDIUM
    description = "Checks that each kernel image has a matching initramfs/initrd"
    depends = ["boot"]
    tags = ["boot", "initramfs", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        boot_data = self._get_data(collectors, "boot")
        images = boot_data.get("kernel_images", {}).get("images", [])

        for img in images:
            kernel_name = img.get("name", "")
            kernel_path = img.get("path", "")

            version = kernel_name.replace("vmlinuz-", "", 1)

            initrd_found = False
            for initrd_pattern in (f"initrd.img-{version}", f"initramfs-{version}.img"):
                if Path(f"/boot/{initrd_pattern}").exists():
                    initrd_found = True
                    break

            if initrd_found:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Missing initramfs for {version}",
                    description=(
                        f"Kernel '{kernel_name}' has no matching initramfs/initrd "
                        f"file in /boot. The system may fail to boot with this kernel."
                    ),
                    rationale=(
                        "Each installed kernel requires a corresponding initramfs "
                        "image to boot. Missing initramfs indicates an incomplete "
                        "kernel installation or accidental deletion, which can cause "
                        "boot failures."
                    ),
                    remediation=(
                        f"Generate initramfs: 'update-initramfs -k {version} -u'. "
                        f"Or reconfigure: 'dpkg-reconfigure linux-image-{version}'."
                    ),
                    evidence=FileEvidence(
                        path=kernel_path,
                        content=f"No matching initrd found for {version}",
                    ),
                    detected_value=f"No initrd for {kernel_name}",
                    expected_value="Initramfs present for each kernel",
                    affected_component=kernel_path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1499"],
                    tags=["boot", "initramfs", "integrity"],
                )
            )
        return findings
