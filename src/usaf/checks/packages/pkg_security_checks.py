from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import PackageEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

RECOMMENDED_PACKAGES: list[str] = [
    "ufw", "auditd", "aide", "aide-common",
    "rkhunter", "chkrootkit", "lynis",
    "needrestart", "unattended-upgrades",
    "debsums", "apt-listchanges",
    "fail2ban", "crowdsec",
]

DEV_PACKAGE_SUFFIXES: list[str] = [
    "-dev", "-dbg", "-dbgsym", "-dbg",
    "-doc", "-static",
]


@register_check
class MissingRecommendedPackagesCheck(AuditCheck):
    id = "PKG-601"
    name = "Missing Security Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Checks for missing recommended security tools"
    depends = ["apt"]
    tags = ["packages", "security", "tools", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        installed = {p.get("name", "") for p in apt_data.get("packages", [])}

        missing = [pkg for pkg in RECOMMENDED_PACKAGES if pkg not in installed]

        if len(missing) < 3:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"{len(missing)} recommended security packages missing",
                description=f"Missing recommended packages: {', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}.",
                rationale="Security tools like auditd, ufw, and fail2ban provide critical detection and prevention capabilities. CIS benchmarks recommend their installation.",
                remediation=f"Install: 'apt install {' '.join(missing)}'.",
                evidence=RegistryEvidence(key="packages.recommended_missing", value=", ".join(missing), expected="all installed", source="dpkg"),
                detected_value=f"Missing: {len(missing)} packages",
                expected_value="Core security packages installed",
                affected_component="Package management",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1070"],
                cis_benchmarks=["CIS Ubuntu 20.04: 4.2"],
                tags=["packages", "security", "tools", "hardening"],
            )
        )
        return findings


@register_check
class ObsoleteKernelPackagesCheck(AuditCheck):
    id = "PKG-602"
    name = "Obsolete Kernel Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Detects old kernel packages that should be removed"
    depends = ["apt"]
    tags = ["packages", "kernels", "housekeeping"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        packages = apt_data.get("packages", [])

        kernels = [p for p in packages if p.get("name", "").startswith("linux-image-") and "generic" in p.get("name", "")]
        kernel_names = sorted([p.get("name", "") for p in kernels])

        if len(kernel_names) <= 2:
            return findings

        removable = kernel_names[:-2]

        findings.append(
            self.finding(
                finding_id="001",
                title=f"{len(removable)} obsolete kernel packages",
                description=f"Old kernel packages can be removed: {', '.join(removable[:5])}{'...' if len(removable) > 5 else ''}.",
                rationale="Old kernel packages consume disk space and may contain unpatched vulnerabilities. Only the current and previous kernel should be kept.",
                remediation=f"Remove old kernels: 'apt purge {' '.join(removable)}'.",
                evidence=RegistryEvidence(key="packages.obsolete_kernels", value=", ".join(removable), expected="keep only 2 most recent", source="dpkg"),
                detected_value=f"{len(removable)} old kernels",
                expected_value="Only current and previous kernel",
                affected_component="Kernel packages",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1499"],
                tags=["packages", "kernels", "housekeeping"],
            )
        )
        return findings


@register_check
class DevPackagesInstalledCheck(AuditCheck):
    id = "PKG-603"
    name = "Development Packages Installed"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects development and debug packages installed on production systems"
    depends = ["apt"]
    tags = ["packages", "development", "hardening"]
    max_findings = 100

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")

        for pkg in apt_data.get("packages", []):
            name = pkg.get("name", "")
            if not any(name.endswith(suffix) for suffix in DEV_PACKAGE_SUFFIXES):
                continue
            if name.startswith("lib") and name.endswith("-dev") and name.count("-") == 1:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Development package installed: {name}",
                    description=f"Package '{name}' is a development/debug package. Remove from production systems.",
                    rationale="Development packages contain headers, debug symbols, and static libraries. They increase the attack surface and are unnecessary in production.",
                    remediation=f"Remove: 'apt purge {name}'.",
                    evidence=PackageEvidence(name=name, version=pkg.get("version", ""), status="installed"),
                    detected_value=f"{name} installed",
                    expected_value="No development packages on production",
                    affected_component=name,
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1070"],
                    tags=["packages", "development", "hardening"],
                )
            )
        return findings


@register_check
class PackageAutoRemovableCheck(AuditCheck):
    id = "PKG-604"
    name = "Auto-Removable Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects packages that are no longer needed and can be auto-removed"
    depends = ["apt"]
    tags = ["packages", "housekeeping", "disk-space"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")

        obsolete = [p for p in apt_data.get("packages", []) if p.get("status") == "obsolete" or "auto-removable" in str(p.get("status", "")).lower()]

        if len(obsolete) < 5:
            return findings

        names = [p.get("name", "") for p in obsolete[:10]]

        findings.append(
            self.finding(
                finding_id="001",
                title=f"{len(obsolete)} auto-removable packages",
                description=f"Packages that can be removed: {', '.join(names)}{'...' if len(obsolete) > 10 else ''}.",
                rationale="Auto-removable packages are no longer needed by any installed package. They waste disk space and may include old libraries with unpatched vulnerabilities.",
                remediation="Run 'apt autoremove --purge' to remove unused packages.",
                evidence=RegistryEvidence(key="packages.auto_removable", value=str(len(obsolete)), expected="< 5", source="dpkg"),
                detected_value=f"{len(obsolete)} removable packages",
                expected_value="Fewer than 5 removable packages",
                affected_component="Package management",
                confidence=Confidence.LOW,
                false_positive_probability=0.4,
                mitre_attack_ids=["T1070"],
                tags=["packages", "housekeeping", "disk-space"],
            )
        )
        return findings


@register_check
class DuplicateRepositoriesCheck(AuditCheck):
    id = "PKG-605"
    name = "Duplicate Repositories"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Detects duplicate APT repository entries"
    depends = ["apt"]
    tags = ["packages", "repositories", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        repos = apt_data.get("repositories", [])

        url_seen: dict[str, list[str]] = {}
        for repo in repos:
            url = repo.get("url", "")
            suite = repo.get("suite", "")
            if url and suite:
                key = f"{url} {suite}"
                if key not in url_seen:
                    url_seen[key] = []
                url_seen[key].append(repo.get("source", ""))

        for key, sources in url_seen.items():
            if len(sources) < 2:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Duplicate repository: {key}",
                    description=f"Repository '{key}' appears in {len(sources)} sources: {', '.join(sources)}.",
                    rationale="Duplicate repository entries can cause inconsistent package versions, signature warnings, and update failures.",
                    remediation=f"Remove duplicate entries from {', '.join(sources)}.",
                    evidence=RegistryEvidence(key="repositories.duplicates", value=", ".join(sources), expected="single source per repo", source="apt sources"),
                    detected_value=f"Duplicate: {key}",
                    expected_value="Each repo listed once",
                    affected_component="APT sources",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    tags=["packages", "repositories", "integrity"],
                )
            )
        return findings


@register_check
class UnusedSnapPackagesCheck(AuditCheck):
    id = "PKG-606"
    name = "Unused Snap Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects Snap packages that may be unused or unnecessary"
    depends = ["snap"]
    tags = ["packages", "snap", "housekeeping"]

    KNOWN_SAFE_SNAPS: set[str] = {
        "core", "core18", "core20", "core22",
        "snapd", "lxd", "bare",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        snap_data = self._get_data(collectors, "snap")
        installed = snap_data.get("installed", [])

        for entry in installed:
            name = entry.get("name", "")
            if name in self.KNOWN_SAFE_SNAPS:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Snap package installed: {name}",
                    description=f"Snap package '{name}' (revision {entry.get('current_revision', '?')}) is installed.",
                    rationale="Snap packages run in sandboxed environments but may introduce unnecessary services and auto-update behavior. Review each non-system snap for necessity.",
                    remediation=f"Review snap '{name}': 'snap info {name}'. Remove if unused: 'snap remove {name}'.",
                    evidence=RegistryEvidence(key=f"snap.{name}", value="installed", expected="review usage", source="snap list"),
                    detected_value=f"Snap: {name} installed",
                    expected_value="Only necessary snaps installed",
                    affected_component=f"snap:{name}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    tags=["packages", "snap", "housekeeping"],
                )
            )
        return findings


@register_check
class PackageDownloadSizeCheck(AuditCheck):
    id = "PKG-607"
    name = "Large Installed Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects unusually large installed packages that may be unnecessary"
    depends = ["apt"]
    tags = ["packages", "disk-space", "housekeeping"]
    max_findings = 20

    MAX_SIZE_MB = 500

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")

        for pkg in apt_data.get("packages", []):
            size_str = pkg.get("installed_size", "0")
            try:
                size_bytes = int(size_str) if size_str else 0
            except (ValueError, TypeError):
                continue

            size_mb = size_bytes / (1024 * 1024)
            if size_mb < self.MAX_SIZE_MB:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Large package: {pkg.get('name', '?')}",
                    description=f"Package '{pkg.get('name')}' is {size_mb:.0f}MB. Review if this large package is necessary.",
                    rationale="Unusually large packages may include data files, firmware, or documentation that is unnecessary on the target system.",
                    remediation=f"Review if '{pkg.get('name')}' is needed. Consider 'apt remove {pkg.get('name')}' if not required.",
                    evidence=PackageEvidence(name=pkg.get("name", ""), version=pkg.get("version", ""), installed_size=int(size_str or "0")),
                    detected_value=f"{size_mb:.0f}MB",
                    expected_value=f"Under {self.MAX_SIZE_MB}MB",
                    affected_component=pkg.get("name", ""),
                    confidence=Confidence.LOW,
                    false_positive_probability=0.6,
                    tags=["packages", "disk-space", "housekeeping"],
                )
            )
        return findings


@register_check
class PackageSourceConsistencyCheck(AuditCheck):
    id = "PKG-608"
    name = "Package Repository Consistency"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Checks for inconsistencies in package sources (mixed Ubuntu versions)"
    depends = ["apt"]
    tags = ["packages", "repositories", "consistency"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        repos = apt_data.get("repositories", [])

        suites: dict[str, list[str]] = {}
        for repo in repos:
            suite = repo.get("suite", "")
            source = repo.get("source", "")
            if suite and source:
                if suite not in suites:
                    suites[suite] = []
                suites[suite].append(source)

        if len(suites) <= 1:
            return findings

        suite_names = sorted(suites.keys())
        if any("updates" in s for s in suite_names) and any("security" in s for s in suite_names):
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Multiple repository suites configured",
                description=f"APT sources reference multiple suites: {', '.join(suite_names)}. This may cause mixed-version installations.",
                rationale="Mixing Ubuntu release suites (e.g., focal + jammy) can lead to incompatible package versions, dependency conflicts, and system instability.",
                remediation="Review APT sources to ensure only the target Ubuntu release and its updates/security suites are enabled.",
                evidence=RegistryEvidence(key="repositories.suites", value=", ".join(suite_names), expected="single release suite + updates/security", source="apt sources"),
                detected_value=f"Multiple suites: {', '.join(suite_names)}",
                expected_value="Single Ubuntu release suite",
                affected_component="APT sources",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                    mitre_attack_ids=["T1070"],
                    tags=["packages", "repositories", "consistency"],
                )
            )
        return findings
