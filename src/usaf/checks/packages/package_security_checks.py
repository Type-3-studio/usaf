from __future__ import annotations

import os
import subprocess
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import PackageEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

UBUNTU_ARCHIVE_PATTERNS: tuple[str, ...] = (
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "esm.ubuntu.com",
    "azure.archive.ubuntu.com",
    "old-releases.ubuntu.com",
)


@register_check
class InsecureRepoURLCheck(AuditCheck):
    id = "PKG-102"
    name = "Insecure APT Repository URLs"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Detects APT repositories using HTTP instead of HTTPS"
    depends = ["apt"]
    tags = ["packages", "repositories", "tls"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []
        repos: list[dict[str, Any]] = apt_data.get("repositories", [])

        for repo in repos:
            url: str = repo.get("url", "")
            source: str = repo.get("source", "")
            if url.startswith("http://"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Insecure HTTP repository: {url}",
                        description=(
                            f"Repository '{url}' in {source} uses HTTP instead of HTTPS. "
                            "Package downloads and metadata are unencrypted."
                        ),
                        rationale=(
                            "APT repositories accessed over HTTP are vulnerable to "
                            "man-in-the-middle attacks. An attacker can intercept "
                            "package metadata and serve malicious packages. "
                            "Ubuntu's signed release files mitigate this partially, "
                            "but HTTPS provides defense-in-depth."
                        ),
                        remediation=(
                            f"Change '{url}' to use HTTPS in {source}. "
                            "Replace http:// with https:// in the repository URL."
                        ),
                        evidence=RegistryEvidence(
                            key=f"repo:{url}",
                            value="http://",
                            expected="https://",
                            source=source,
                        ),
                        detected_value=url,
                        expected_value="HTTPS URL",
                        affected_component=f"repository: {url}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        mitre_attack_ids=["T1553"],
                        tags=["packages", "repositories", "tls"],
                    )
                )

        return findings


@register_check
class SourceReposEnabledCheck(AuditCheck):
    id = "PKG-103"
    name = "Source Repositories Enabled"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects enabled deb-src source repositories"
    depends = ["apt"]
    tags = ["packages", "repositories"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []
        repos: list[dict[str, Any]] = apt_data.get("repositories", [])

        source_repos = [r for r in repos if r.get("type") == "deb-src"]
        if not source_repos:
            return findings

        urls = sorted(set(r["url"] for r in source_repos if "url" in r))
        findings.append(
            self.finding(
                finding_id="001",
                title=f"{len(source_repos)} source repositories enabled",
                description=(
                    f"{len(source_repos)} deb-src repositories are enabled: "
                    f"{', '.join(urls[:5])}{'...' if len(urls) > 5 else ''}"
                ),
                rationale=(
                    "Source (deb-src) repositories are not needed on production "
                    "systems. They increase attack surface and metadata download "
                    "time. Source repos should only be enabled on development "
                    "systems that build packages."
                ),
                remediation=(
                    "Comment out deb-src lines in /etc/apt/sources.list "
                    "and files in /etc/apt/sources.list.d/"
                ),
                evidence=RegistryEvidence(
                    key="repositories.deb-src",
                    value=str(len(source_repos)),
                    expected="0",
                    source="/etc/apt/sources.list",
                ),
                detected_value=f"{len(source_repos)} deb-src repos",
                expected_value="0 source repos",
                affected_component="APT source repositories",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                tags=["packages", "repositories"],
            )
        )

        return findings


@register_check
class NonStandardReposCheck(AuditCheck):
    id = "PKG-203"
    name = "Non-Standard APT Repositories"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Detects APT repositories that are not standard Ubuntu archives"
    depends = ["apt"]
    tags = ["packages", "repositories", "supply-chain"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []
        repos: list[dict[str, Any]] = apt_data.get("repositories", [])

        for repo in repos:
            url: str = repo.get("url", "")
            source: str = repo.get("source", "")
            suite: str = repo.get("suite", "")

            if not url:
                continue
            is_standard = any(pattern in url for pattern in UBUNTU_ARCHIVE_PATTERNS)
            if is_standard:
                continue
            if "ppa." in url or "launchpad.net" in url:
                repo_type = "PPA"
            elif "download.docker.com" in url or "docker.com" in url:
                repo_type = "vendor (Docker)"
            elif "deb.nodesource.com" in url or "nodesource" in url:
                repo_type = "vendor (NodeSource)"
            elif "packages.microsoft.com" in url or "microsoft.com" in url:
                repo_type = "vendor (Microsoft)"
            elif "dl.google.com" in url or "google.com" in url:
                repo_type = "vendor (Google)"
            elif "nginx.org" in url or "nginx.com" in url:
                repo_type = "vendor (NGINX)"
            elif "mysql.com" in url or "mysql.dev" in url:
                repo_type = "vendor (MySQL)"
            elif "postgresql.org" in url or "apt.postgresql" in url:
                repo_type = "vendor (PostgreSQL)"
            elif "mariadb.org" in url:
                repo_type = "vendor (MariaDB)"
            elif "elastic.co" in url:
                repo_type = "vendor (Elastic)"
            elif "grafana.com" in url or "grafana" in url:
                repo_type = "vendor (Grafana)"
            elif "gitlab.com" in url or "gitlab" in url:
                repo_type = "vendor (GitLab)"
            elif "jenkins.io" in url or "jenkins" in url:
                repo_type = "vendor (Jenkins)"
            elif "packagecloud.io" in url:
                repo_type = "third-party (PackageCloud)"
            elif "deb.icij.org" in url:
                repo_type = "third-party"
            else:
                repo_type = "unknown third-party"

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Non-standard repository: {repo_type}",
                    description=(
                        f"Repository '{url}' ({suite}) from {source} is "
                        f"a {repo_type} source, not a standard Ubuntu archive."
                    ),
                    rationale=(
                        "Third-party and PPA repositories are not vetted by Ubuntu "
                        "security and may contain outdated, vulnerable, or malicious "
                        "packages. Each third-party repo represents supply chain risk."
                    ),
                    remediation=(
                        f"Review whether the {repo_type} repository at {url} "
                        f"is still needed. Remove if unused: "
                        f"comment out the repo in {source} and run 'apt update'."
                    ),
                    evidence=RegistryEvidence(
                        key=f"repo:{url}",
                        value=repo_type,
                        expected="standard Ubuntu archive",
                        source=source,
                    ),
                    detected_value=f"{repo_type}: {url}",
                    expected_value="Ubuntu archive repository",
                    affected_component=f"repository: {url}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1195", "T1475"],
                    tags=["packages", "repositories", "supply-chain"],
                )
            )

        return findings


@register_check
class HeldPackagesCheck(AuditCheck):
    id = "PKG-303"
    name = "Held Packages Blocking Updates"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects packages on hold that may block security updates"
    depends = []
    tags = ["packages", "updates", "patching"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        held = self._get_held_packages()

        if not held:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"{len(held)} package(s) on hold",
                description=(
                    f"The following packages are on hold: {', '.join(held)}. "
                    "Held packages will not receive updates."
                ),
                rationale=(
                    "Packages on hold are excluded from all updates, including "
                    "security patches. While holds are sometimes necessary for "
                    "compatibility, they create a security gap. Each held package "
                    "should be reviewed and unheld as soon as possible."
                ),
                remediation=(
                    "Review each held package: 'apt-mark showhold'. "
                    "Remove hold: 'apt-mark unhold <package>'. "
                    f"Current held: {', '.join(held)}"
                ),
                evidence=RegistryEvidence(
                    key="packages.held",
                    value=", ".join(held),
                    expected="0 held packages",
                    source="apt-mark showhold",
                ),
                detected_value=f"{len(held)} held: {', '.join(held)}",
                expected_value="No packages on hold",
                affected_component="APT package management",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1562.001"],
                tags=["packages", "updates"],
            )
        )

        return findings

    @staticmethod
    def _get_held_packages() -> list[str]:
        try:
            r = subprocess.run(
                ["apt-mark", "showhold"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                return [p.strip() for p in r.stdout.splitlines() if p.strip()]
        except (OSError, subprocess.SubprocessError):
            pass
        return []


@register_check
class OutdatedKernelCheck(AuditCheck):
    id = "PKG-304"
    name = "Running Kernel Not Latest Installed"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Detects when the running kernel version is older than the latest installed kernel package"
    depends = ["apt"]
    tags = ["packages", "kernel", "patching"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []
        packages: list[dict[str, Any]] = apt_data.get("packages", [])

        running_version = self._get_running_kernel()
        if not running_version:
            return findings

        installed_kernel_names: list[str] = []
        for pkg in packages:
            name: str = pkg.get("name", "")
            if name.startswith("linux-image-") and name != "linux-image-generic":
                installed_kernel_names.append(name)

        if not installed_kernel_names:
            return findings

        installed_kernel_names.sort(reverse=True)
        latest_kernel_name = installed_kernel_names[0]
        latest_abi_version = latest_kernel_name.replace("linux-image-", "", 1)

        if running_version != latest_abi_version:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Running kernel is not the latest installed",
                    description=(
                        f"Running kernel: {running_version}. "
                        f"Latest installed: {latest_abi_version}. "
                        "A reboot is required to use the newer kernel."
                    ),
                    rationale=(
                        "Running an older kernel after a kernel update means the "
                        "system is not protected by the latest security fixes. "
                        "Kernel vulnerabilities often have high severity and "
                        "require a reboot to apply the fix."
                    ),
                    remediation=(
                        "Reboot the system to load the latest kernel: "
                        "'sudo reboot'. Verify: 'uname -r' after reboot."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.running",
                        value=running_version,
                        expected=latest_abi_version,
                        source="uname -r / dpkg",
                    ),
                    detected_value=f"Running: {running_version}, Latest: {latest_abi_version}",
                    expected_value="Running kernel matches latest installed kernel",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1204.002"],
                    tags=["packages", "kernel", "patching"],
                )
            )

        return findings

    @staticmethod
    def _get_running_kernel() -> str | None:
        try:
            r = subprocess.run(
                ["uname", "-r"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode == 0:
                return r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None


@register_check
class AutoRemovablePackagesCheck(AuditCheck):
    id = "PKG-403"
    name = "Auto-Removable Packages"
    category = CheckCategory.PACKAGES
    severity = Severity.LOW
    description = "Detects packages that are no longer needed and can be autoremoved"
    depends = []
    tags = ["packages", "cleanup", "maintenance"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        removable = self._get_auto_removable()

        if not removable:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"{len(removable)} packages can be autoremoved",
                description=(
                    f"The following {len(removable)} packages are no longer "
                    f"needed: {', '.join(removable[:10])}"
                    f"{'...' if len(removable) > 10 else ''}"
                ),
                rationale=(
                    "Packages that are no longer needed accumulate over time. "
                    "While not a direct security risk, they increase the attack "
                    "surface by providing additional code that may contain "
                    "vulnerabilities. Removing them reduces the system footprint."
                ),
                remediation=(
                    "Run 'apt autoremove --dry-run' to review, then "
                    "'apt autoremove' to remove unneeded packages."
                ),
                evidence=RegistryEvidence(
                    key="packages.auto-removable",
                    value=str(len(removable)),
                    expected="0",
                    source="apt-get --dry-run autoremove",
                ),
                detected_value=f"{len(removable)} auto-removable packages",
                expected_value="0 auto-removable packages",
                affected_component="APT package management",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                tags=["packages", "cleanup"],
            )
        )

        return findings

    @staticmethod
    def _get_auto_removable() -> list[str]:
        try:
            r = subprocess.run(
                ["apt-get", "--dry-run", "autoremove"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            packages: list[str] = []
            in_removal = False
            for line in r.stdout.splitlines():
                stripped = line.strip()
                if "The following packages will be REMOVED" in stripped:
                    in_removal = True
                    continue
                if in_removal:
                    if not stripped or stripped.startswith("0 upgraded"):
                        break
                    for pkg in stripped.replace(",", "").split():
                        pkg_clean = pkg.strip()
                        if pkg_clean and pkg_clean not in ("packages.", "packages:"):
                            packages.append(pkg_clean.lstrip("(").rstrip(")"))
            return packages
        except (OSError, subprocess.SubprocessError):
            return []


@register_check
class ThirdPartyPackageCountCheck(AuditCheck):
    id = "PKG-501"
    name = "Packages From Third-Party Repositories"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Counts packages installed from non-standard repositories"
    depends = ["apt"]
    tags = ["packages", "repositories", "supply-chain"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []
        repos: list[dict[str, Any]] = apt_data.get("repositories", [])

        non_standard_repos = [
            r for r in repos
            if not any(p in r.get("url", "") for p in UBUNTU_ARCHIVE_PATTERNS)
        ]

        if len(non_standard_repos) > 2:
            urls = sorted(set(r["url"] for r in non_standard_repos if "url" in r))
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"{len(non_standard_repos)} non-standard repositories configured",
                    description=(
                        f"The system has {len(non_standard_repos)} non-standard "
                        f"repositories: {', '.join(urls[:5])}"
                        f"{'...' if len(urls) > 5 else ''}"
                    ),
                    rationale=(
                        "Having many third-party repositories increases supply chain "
                        "risk. Each repository is an additional trust point — if "
                        "compromised, it can serve malicious packages. Review "
                        "whether all repositories are still needed."
                    ),
                    remediation=(
                        "Review and remove unused repositories from "
                        "/etc/apt/sources.list.d/ and /etc/apt/sources.list."
                    ),
                    evidence=RegistryEvidence(
                        key="repositories.non-standard",
                        value=str(len(non_standard_repos)),
                        expected="2 or fewer",
                        source="apt sources",
                    ),
                    detected_value=f"{len(non_standard_repos)} non-standard repos",
                    expected_value="2 or fewer non-standard repos",
                    affected_component="APT repositories",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1195", "T1475"],
                    tags=["packages", "repositories", "supply-chain"],
                )
            )

        return findings


@register_check
class PackageIntegritySummaryCheck(AuditCheck):
    id = "PKG-502"
    name = "Package Manager Integrity Summary"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Summarizes package manager configuration issues"
    depends = ["apt"]
    tags = ["packages", "integrity", "maintenance"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []
        issues: list[str] = []

        packages: list[dict[str, Any]] = apt_data.get("packages", [])
        updates: list[dict[str, Any]] = apt_data.get("updates", [])
        repos: list[dict[str, Any]] = apt_data.get("repositories", [])

        if not packages:
            issues.append("No packages found — package cache may be stale")
        if not repos:
            issues.append("No repositories configured")
        else:
            http_repos = [r for r in repos if r.get("url", "").startswith("http://")]
            if http_repos:
                issues.append(f"{len(http_repos)} repository(s) use HTTP")

        update_packages = {u.get("name", "") for u in updates if u.get("name")}
        if update_packages:
            security_related = {
                "linux", "linux-image", "linux-headers", "openssl",
                "openssh", "libssl", "systemd", "glibc", "libc",
                "nginx", "apache", "php", "mysql", "postgresql",
                "python", "node", "ruby",
            }
            security_updates = [
                p for p in update_packages
                if any(s in p for s in security_related)
            ]
            if security_updates:
                issues.append(
                    f"{len(security_updates)} security-related packages "
                    f"have pending updates"
                )

        if issues:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Package manager issues found",
                    description="; ".join(issues),
                    rationale=(
                        "Package manager issues can compromise system security "
                        "by preventing security updates or introducing untrusted "
                        "software. Each issue should be addressed."
                    ),
                    remediation="Address the listed issues: " + "; ".join(
                        "run 'apt update' for stale cache" if "stale" in i
                        else "remove HTTP repos" if "HTTP" in i
                        else "apply pending updates" if "updates" in i
                        else "configure repositories" for i in issues
                    ),
                    evidence=RegistryEvidence(
                        key="packages.integrity",
                        value="; ".join(issues),
                        expected="No issues",
                        source="apt collector",
                    ),
                    detected_value="; ".join(issues),
                    expected_value="No package manager issues",
                    affected_component="APT package management",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    tags=["packages", "integrity"],
                )
            )

        return findings
