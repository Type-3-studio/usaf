from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import PackageEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class UnnecessaryPackagesCheck(AuditCheck):
    id = "PKG-101"
    name = "Unnecessary or Risky Installed Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Checks for installed packages that are unnecessary or present a security risk"
    depends = ["apt"]
    tags = ["packages", "attack-surface", "hardening"]

    RISKY_PACKAGES = {
        "telnetd": "Telnet server (unencrypted remote access)",
        "telnetd-hpa": "Telnet server (unencrypted remote access)",
        "rsh-server": "Rsh server (unauthenticated remote access)",
        "rsh-redone-server": "Rsh server (unauthenticated remote access)",
        "tftpd": "TFTP server (unauthenticated file transfer)",
        "tftpd-hpa": "TFTP server (unauthenticated file transfer)",
        "nis": "Network Information Service (legacy authentication)",
        "ypserv": "YP/NIS server (legacy authentication)",
        "cups": "CUPS printing service (unnecessary on servers)",
        "avahi-daemon": "mDNS/Bonjour service (unnecessary on servers)",
        "samba": "SMB/CIFS server (attack surface if not needed)",
        "snmpd": "SNMP daemon (information disclosure risk)",
        "whoopsie": "Ubuntu error reporter (data exfiltration risk)",
        "xserver-xorg-core": "X11 server (unnecessary on headless servers)",
    }

    DESKTOP_PACKAGES = {"cups", "avahi-daemon", "whoopsie", "xserver-xorg-core"}
    DESKTOP_META_PACKAGES = {"ubuntu-desktop", "kubuntu-desktop", "xubuntu-desktop", "lubuntu-desktop", "ubuntu-desktop-minimal"}

    def _is_desktop(self, installed_names: set[str]) -> bool:
        return bool(installed_names & self.DESKTOP_META_PACKAGES)

    def _run_check(self, collectors: dict) -> list:
        apt_data = self._get_data(collectors, "apt")
        packages = apt_data.get("packages", [])
        findings: list = []

        installed_names = {p.get("name", "") for p in packages}
        is_desktop = self._is_desktop(installed_names)
        for pkg_name, reason in self.RISKY_PACKAGES.items():
            if is_desktop and pkg_name in self.DESKTOP_PACKAGES:
                continue
            if pkg_name not in installed_names:
                continue
            pkg_info: dict = next((p for p in packages if p.get("name") == pkg_name), {})
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Risky package installed: {pkg_name}",
                    description=f"Package '{pkg_name}' is installed: {reason}",
                    rationale=(
                        "Every installed service increases the attack surface of the system. "
                        f"{reason}. On a production server, these packages should not be present "
                        "unless explicitly required and documented in the architecture."
                    ),
                    remediation=(
                        f"Remove the package: 'apt purge {pkg_name}'. "
                        f"Verify no dependencies need it: 'apt autoremove'."
                    ),
                evidence=PackageEvidence(
                    name=pkg_name,
                    version=pkg_info.get("version"),
                    status=pkg_info.get("status"),
                ),
                detected_value=f"{pkg_name} is installed",
                expected_value=f"{pkg_name} is not installed",
                affected_component=f"Package: {pkg_name}",
                reference="https://ubuntu.com/security/cis",
                confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1190"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.1"],
                    tags=["attack-surface", "hardening", "packages"],
                )
            )
        return findings
