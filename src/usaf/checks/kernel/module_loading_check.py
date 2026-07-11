from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


DANGEROUS_MODULES: dict[str, str] = {
    "bluetooth": "Bluetooth stack — attack surface for wireless exploits",
    "btusb": "Bluetooth USB driver — enables Bluetooth attacks",
    "firewire-core": "FireWire — allows direct memory access (DMA) attacks",
    "firewire_ohci": "FireWire OHCI — DMA attack vector",
    "pktgen": "Packet generator — can be used for DoS attacks",
    "dccp": "Datagram Congestion Control Protocol — rarely needed, known vulnerabilities",
    "sctp": "Stream Control Transmission Protocol — attack surface",
    "rds": "Reliable Datagram Sockets — obsolete, attack surface",
    "tipc": "Transparent Inter Process Communication — cluster only, attack surface",
    "ax25": "Amateur Radio X.25 — obsolete protocol",
    "netrom": "NET/ROM — obsolete protocol",
    "rose": "ROSE — obsolete protocol",
    "decnet": "DECnet — obsolete protocol",
    "nfc": "Near Field Communication — wireless attack surface",
    "irda": "Infrared — obsolete wireless protocol",
    "uvcvideo": "USB Video Class — webcam access for attackers",
    "usb-storage": "USB storage — data exfiltration via USB",
    "joydev": "Joystick — game controller, can be abused for input capture",
    "pcspkr": "PC speaker — information leakage via beep timing",
    "can": "CAN bus — vehicle network protocol, not needed on servers",
}


@register_check
class KernelModuleLoadingCheck(AuditCheck):
    id = "KERN-401"
    name = "Kernel Module Loading Restrictions"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that kernel module loading is restricted to prevent unauthorized kernel code execution"
    depends = []
    tags = ["kernel", "hardening", "module-loading"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []
        value = self._read_sysctl("kernel.modules_disabled")
        if value == "1":
            return findings
        findings.append(
            self.finding(
                finding_id="001",
                title="Kernel module loading is not disabled",
                description=f"kernel.modules_disabled={value or 'unreadable'} (expected 1)",
                rationale=(
                    "When modules_disabled=1, no kernel modules can be loaded or unloaded after "
                    "boot. This prevents attackers from loading rootkits or malicious kernel "
                    "modules. For most production systems, this is a strong hardening measure. "
                    "This should only be set after verifying all required modules are loaded."
                ),
                remediation=(
                    "Add 'kernel.modules_disabled=1' to /etc/sysctl.d/99-hardening.conf. "
                    "Apply: 'sysctl -w kernel.modules_disabled=1'. "
                    "Ensure all required hardware drivers are loaded before enabling."
                ),
                evidence=RegistryEvidence(
                    key="kernel.modules_disabled",
                    value=value or "unreadable",
                    expected="1",
                    source="/proc/sys/kernel/modules_disabled",
                ),
                detected_value=value or "unreadable",
                expected_value="1",
                affected_component="kernel",
                reference="https://ubuntu.com/security/cis",
                confidence=Confidence.LOW,
                false_positive_probability=0.4,
                mitre_attack_ids=["T1214"],
                cis_benchmarks=["CIS Ubuntu 20.04: 3.5"],
                tags=["kernel-hardening", "rootkit-prevention"],
            )
        )
        return findings

    def _read_sysctl(self, key: str) -> str | None:
        path = Path("/proc/sys") / key.replace(".", "/")
        try:
            return path.read_text().strip()
        except OSError:
            return None


@register_check
class DangerousKernelModulesCheck(AuditCheck):
    id = "KERN-501"
    name = "Dangerous Kernel Modules Loaded"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Detects loaded kernel modules that increase attack surface"
    depends = []
    tags = ["kernel", "modules", "attack-surface", "hardening"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []
        loaded = self._get_loaded_modules()

        for mod_name, mod_info in loaded.items():
            if mod_name in DANGEROUS_MODULES:
                reason = DANGEROUS_MODULES[mod_name]
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Dangerous kernel module loaded: {mod_name}",
                        description=(
                            f"The '{mod_name}' kernel module is currently loaded ({mod_info}). "
                            f"{reason}"
                        ),
                        rationale=(
                            "Unnecessary kernel modules increase the attack surface available to "
                            "attackers. Even if a module is not actively exploitable today, it "
                            "widens the kernel attack surface and may contain future vulnerabilities. "
                            "Each loaded module consumes kernel memory and can be targeted by "
                            "privilege escalation or denial-of-service exploits."
                        ),
                        remediation=(
                            f"Blacklist '{mod_name}': echo 'blacklist {mod_name}' >> "
                            f"/etc/modprobe.d/blacklist-dangerous.conf. "
                            f"Unload now: 'rmmod {mod_name}' if not in use. "
                            f"Review all modules: 'lsmod | sort'"
                        ),
                        evidence=FileEvidence(
                            path=f"/proc/modules",
                            content=f"{mod_name}: {mod_info}",
                        ),
                        detected_value=f"Module '{mod_name}' loaded: {mod_info}",
                        expected_value="Module not loaded or blacklisted",
                        affected_component=f"kernel-module:{mod_name}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1214"],
                        tags=["kernel-hardening", "module-blacklist"],
                    )
                )
        return findings

    @staticmethod
    def _get_loaded_modules() -> dict[str, str]:
        result: dict[str, str] = {}
        try:
            lines = Path("/proc/modules").read_text().splitlines()
        except OSError:
            return result
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                mod_name = parts[0]
                mod_size = parts[1]
                mod_used = parts[2]
                result[mod_name] = f"size={mod_size}, used={mod_used}"
        return result
