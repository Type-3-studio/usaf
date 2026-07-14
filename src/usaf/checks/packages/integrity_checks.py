from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence, PackageEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

KNOWN_SAFE_REPOS = [
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "esm.ubuntu.com",
    "extras.ubuntu.com",
    "old-releases.ubuntu.com",
    "ppa.launchpadcontent.net",
    "ppa.launchpad.net",
]

KNOWN_SAFE_REPO_PREFIXES = [
    "http://archive.ubuntu.com",
    "https://archive.ubuntu.com",
    "http://security.ubuntu.com",
    "https://security.ubuntu.com",
    "http://ports.ubuntu.com",
    "https://ports.ubuntu.com",
    "http://esm.ubuntu.com",
    "https://esm.ubuntu.com",
    "http://extras.ubuntu.com",
    "https://extras.ubuntu.com",
    "http://old-releases.ubuntu.com",
    "https://old-releases.ubuntu.com",
    "http://ppa.launchpad.net",
    "https://ppa.launchpad.net",
    "http://ppa.launchpadcontent.net",
    "https://ppa.launchpadcontent.net",
]


@register_check
class ModifiedPackageFilesCheck(AuditCheck):
    """Check for modified package files using dpkg --verify."""

    id = "PKG-201"
    name = "Modified Package Files"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Checks for package files that have been modified since installation"
    depends = []
    tags = ["packages", "integrity", "tampering"]

    def _run_check(self, _collectors: dict) -> list:
        findings = []
        try:
            result = subprocess.run(
                ["dpkg", "--verify"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Unable to verify package integrity",
                    description=f"dpkg --verify failed: {e}",
                    rationale="Package integrity verification is critical for detecting tampering.",
                    remediation="Ensure dpkg is installed and functional.",
                    evidence=CommandEvidence(
                        command="dpkg --verify",
                        stderr=str(e),
                        exit_code=-1,
                    ),
                    detected_value="Verification failed",
                    expected_value="All packages verified",
                    affected_component="dpkg verification",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                )
            )
            return findings

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split(maxsplit=1)
            if len(parts) < 2:
                continue
            flags = parts[0]
            filepath = parts[1].strip()

            if filepath.startswith("c "):
                continue

            if "(Permission denied)" in filepath:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Modified package file: {filepath}",
                    description=(
                        f"File '{filepath}' has been modified since package installation "
                        f"(flags: {flags}). Expected content from package has changed."
                    ),
                    rationale=(
                        "Modified package files indicate unauthorized changes to system files. "
                        "Attackers commonly replace legitimate binaries, libraries, or "
                        "configuration files with malicious versions. Configuration files "
                        "marked with 'c' flag are excluded as expected admin modifications."
                    ),
                    remediation=(
                        f"Investigate why '{filepath}' was modified: 'apt-get --reinstall install "
                        f"<package>' to restore original. Use 'dpkg -S {filepath}' to identify "
                        f"the owning package. Check /var/log/auth.log for related activity."
                    ),
                    evidence=CommandEvidence(
                        command="dpkg --verify",
                        stdout=line,
                        exit_code=result.returncode,
                    ),
                    detected_value=f"Modified: {filepath} ({flags})",
                    expected_value="File matches package checksums",
                    affected_component=filepath,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1565.001", "T1070"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
                    tags=["integrity", "tampering", "files"],
                )
            )

        return findings


@register_check
class UnknownRepositoriesCheck(AuditCheck):
    """Check for unknown or suspicious APT repositories."""

    id = "PKG-301"
    name = "Unknown APT Repositories"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Checks for APT repositories that are not standard Ubuntu sources"
    depends = ["apt"]
    tags = ["packages", "repositories", "supply-chain"]

    def _run_check(self, collectors: dict) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings = []

        repos = apt_data.get("repositories", [])

        for repo in repos:
            url = repo.get("url", "")
            source = repo.get("source", "")

            if any(url.startswith(prefix) for prefix in KNOWN_SAFE_REPO_PREFIXES):
                continue

            if "ppa.launchpad.net" in url or "ppa.launchpadcontent.net" in url:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"PPA repository configured: {url}",
                        description=(
                            f"Personal Package Archive (PPA) configured from {url} "
                            f"in {source}. PPAs are community-maintained and not "
                            "vetted by Ubuntu Security Team."
                        ),
                        rationale=(
                            "PPAs are third-party repositories without security guarantees. "
                            "Packages from PPAs may contain malware, have delayed security "
                            "updates, or introduce conflicting dependencies. Each PPA should "
                            "be reviewed and documented."
                        ),
                        remediation=(
                            f"Review the PPA at {url}. If not needed: "
                            f"'add-apt-repository --remove {url}'. "
                            "If needed, ensure only trusted PPAs from verified sources."
                        ),
                        evidence=RegistryEvidence(
                            key=source,
                            value=url,
                            expected="Only standard Ubuntu repositories",
                            source=source,
                        ),
                        detected_value=f"PPA: {url}",
                        expected_value="Standard Ubuntu repositories only",
                        affected_component=f"Repo: {url}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.5,
                        mitre_attack_ids=["T1195", "T1584"],
                        tags=["repository", "supply-chain", "ppa"],
                    )
                )
                continue

            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Unknown repository: {url}",
                    description=(
                        f"Repository '{url}' from {source} is not a standard Ubuntu "
                        "repository and not a known PPA."
                    ),
                    rationale=(
                        "Unknown repositories may host malicious or unpatched packages. "
                        "They bypass Ubuntu's security update process and can introduce "
                        "vulnerable or backdoored software. Supply chain attacks through "
                        "compromised repositories are an increasing threat vector."
                    ),
                    remediation=(
                        f"Verify the legitimacy of '{url}'. If unauthorized, remove: "
                        "'add-apt-repository --remove <repo>'. "
                        "If legitimate, document the exception."
                    ),
                    evidence=RegistryEvidence(
                        key=source,
                        value=url,
                        expected="Standard Ubuntu repository URL",
                        source=source,
                    ),
                    detected_value=f"Non-standard repo: {url}",
                    expected_value="Standard Ubuntu repository",
                    affected_component=f"Repo: {url}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1195", "T1584"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.3"],
                    tags=["repository", "supply-chain"],
                )
            )

        return findings


@register_check
class PendingSecurityUpdatesCheck(AuditCheck):
    """Check for pending security updates."""

    id = "PKG-402"
    name = "Pending Security Updates"
    category = CheckCategory.PACKAGES
    severity = Severity.HIGH
    description = "Checks for packages with available security updates"
    depends = ["apt"]
    tags = ["packages", "updates", "cve"]

    def _run_check(self, collectors: dict) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings: list = []

        updates = apt_data.get("updates", [])

        if not updates:
            return findings

        for update in updates[:10]:
            pkg_name = update.get("name", "unknown")
            new_version = update.get("new_version", "unknown")

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Update available: {pkg_name}",
                    description=(
                        f"Package '{pkg_name}' has an available update to version "
                        f"{new_version}. This may include security fixes."
                    ),
                    rationale=(
                        "Outdated packages may contain known vulnerabilities. Attackers "
                        "actively scan for systems running unpatched software. While not all "
                        "updates are security-related, unpatched systems are a primary "
                        "initial access vector. Regular patching is the single most "
                        "effective security control."
                    ),
                    remediation=(
                        f"Update the package: 'apt update && apt install {pkg_name}' "
                        "or apply all updates: 'apt update && apt upgrade'. "
                        "For critical systems, test updates in staging first."
                    ),
                    evidence=PackageEvidence(
                        name=pkg_name,
                        version=None,
                        is_update_available=True,
                    ),
                    detected_value=f"Update {new_version} available",
                    expected_value="All packages up to date",
                    affected_component=f"Package: {pkg_name}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1190"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.4"],
                    tags=["updates", "patching", "vulnerability"],
                )
            )

        return findings


@register_check
class BrokenPackageSignaturesCheck(AuditCheck):
    """Check for packages with broken or missing signatures."""

    id = "PKG-202"
    name = "Broken Package Signatures"
    category = CheckCategory.PACKAGES
    severity = Severity.HIGH
    description = "Checks for APT packages with missing or invalid signatures"
    depends = []
    tags = ["packages", "integrity", "signatures"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        trusted_gpg_dir = Path("/etc/apt/trusted.gpg.d")
        if not trusted_gpg_dir.is_dir():
            return findings

        key_count = 0
        try:
            for f in trusted_gpg_dir.iterdir():
                if f.suffix in (".gpg", ".asc") or f.name.endswith(".keyring"):
                    key_count += 1
        except OSError:
            pass

        if key_count == 0:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="No trusted GPG keys found",
                    description=(
                        "No GPG keys found in /etc/apt/trusted.gpg.d. "
                        "APT cannot verify package authenticity."
                    ),
                    rationale=(
                        "Without GPG verification, APT cannot authenticate packages. "
                        "Attackers could serve malicious packages through a MITM attack "
                        "or compromised repository without detection."
                    ),
                    remediation=(
                        "Reinstall ubuntu-keyring: 'apt install --reinstall ubuntu-keyring'. "
                        "Verify trusted keys: 'apt-key list'."
                    ),
                    evidence=RegistryEvidence(
                        key="/etc/apt/trusted.gpg.d",
                        value="0 keys",
                        expected="Ubuntu archive signing keys present",
                        source="/etc/apt/trusted.gpg.d",
                    ),
                    detected_value="No trusted GPG keys",
                    expected_value="Ubuntu archive signing keys",
                    affected_component="APT signature verification",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1195", "T1554"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.2"],
                    tags=["signatures", "integrity", "supply-chain"],
                )
            )

        try:
            result = subprocess.run(
                ["apt-key", "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            expired_count = result.stdout.count("expired:")
            if expired_count > 0:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"{expired_count} expired GPG key(s) found",
                        description=(
                            f"Found {expired_count} expired GPG key(s) in APT keyring. "
                            "Expired keys prevent APT from verifying package signatures."
                        ),
                        rationale=(
                            "Expired GPG keys mean APT cannot verify packages from "
                            "repositories signed with those keys. This may prevent "
                            "security updates from being installed or may indicate "
                            "neglected repository maintenance."
                        ),
                        remediation=(
                            "Update expired keys: 'apt-key adv --keyserver keyserver.ubuntu.com "
                            "--refresh-keys' or update the keyring package: "
                            "'apt install --reinstall ubuntu-keyring'."
                        ),
                        evidence=CommandEvidence(
                            command="apt-key list",
                            stdout=f"{expired_count} expired keys found",
                            exit_code=result.returncode,
                        ),
                        detected_value=f"{expired_count} expired GPG keys",
                        expected_value="No expired GPG keys",
                        affected_component="APT GPG keyring",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1195"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 2.2"],
                        tags=["signatures", "gpg", "keys"],
                    )
                )
        except (OSError, subprocess.SubprocessError):
            pass

        return findings


@register_check
class ExpiredRepoKeysCheck(AuditCheck):
    """Check for expired repository signing keys."""

    id = "PKG-302"
    name = "Expired Repository Signing Keys"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Checks for expired signing keys in APT trusted keyrings"
    depends = []
    tags = ["packages", "repositories", "keys"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []
        try:
            result = subprocess.run(
                ["apt-key", "list", "--keyid-format", "long"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return findings

        current_section = ""
        for line in result.stdout.splitlines():
            if line.startswith("/etc/apt/trusted.gpg") or line.startswith("/etc/apt/keyrings"):
                current_section = line.strip()
            if "expired:" in line.lower():
                key_id = ""
                uid = ""
                parts = line.split()
                for i, p in enumerate(parts):
                    if "/" in p and len(p.split("/")[0]) >= 8:
                        key_id = p
                        if i + 1 < len(parts):
                            uid = parts[i + 1]
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Expired signing key: {key_id or 'unknown'}",
                        description=(
                            f"An expired GPG signing key was found in {current_section or 'keyring'}. "
                            f"Key: {key_id}. UID: {uid}. Expired keys prevent APT verification."
                        ),
                        rationale=(
                            "Expired repository signing keys prevent APT from authenticating "
                            "packages from that repository. This can lead to failed updates, "
                            "outdated packages with known vulnerabilities, or force users to "
                            "disable signature verification, exposing the system to supply chain attacks."
                        ),
                        remediation=(
                            "Update the keyring: 'apt install --reinstall ubuntu-keyring' "
                            "or refresh the specific key: 'apt-key adv --keyserver "
                            "keyserver.ubuntu.com --recv-keys <KEYID>'."
                        ),
                        evidence=RegistryEvidence(
                            key=current_section or "keyring",
                            value=f"Expired key: {key_id}",
                            expected="All keys valid and unexpired",
                            source=current_section or "apt-key",
                        ),
                        detected_value=f"Expired key: {key_id}",
                        expected_value="No expired keys",
                        affected_component=f"GPG key: {key_id}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1195"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 2.2"],
                        tags=["signatures", "gpg", "keys", "expired"],
                    )
                )

        return findings


@register_check
class KnownCVEVulnerabilitiesCheck(AuditCheck):
    """Check for packages with known CVEs via Ubuntu Security Tracker."""

    id = "PKG-401"
    name = "Packages With Known CVEs"
    category = CheckCategory.PACKAGES
    severity = Severity.HIGH
    description = "Checks for installed packages tracked with known vulnerabilities"
    depends = ["apt"]
    tags = ["packages", "cve", "vulnerability"]

    def _run_check(self, collectors: dict) -> list:
        apt_data = self._get_data(collectors, "apt")
        findings = []

        updates = apt_data.get("updates", [])
        packages = apt_data.get("packages", [])

        update_names = {u.get("name") for u in updates if u.get("name")}

        for pkg_name in update_names:
            pkg_info = next(
                (p for p in packages if p.get("name") == pkg_name),
                None,
            )

            if pkg_info is None:
                continue

            update_info = next(
                (u for u in updates if u.get("name") == pkg_name),
                None,
            )
            new_ver = (update_info or {}).get("new_version", "unknown")

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Package may have known CVEs: {pkg_name}",
                    description=(
                        f"Package '{pkg_name}' has an available update ({new_ver}) "
                        "which may include security fixes for known CVEs."
                    ),
                    rationale=(
                        "Packages with pending updates may contain known vulnerabilities. "
                        "Ubuntu's security team tracks CVEs and releases patched versions. "
                        "Running outdated packages is a common initial access vector. "
                        "Check https://ubuntu.com/security for specific CVE details."
                    ),
                    remediation=(
                        f"Update: 'apt update && apt install {pkg_name}'. "
                        "Check specific CVEs: 'apt changelog {pkg_name}' or "
                        "visit https://ubuntu.com/security."
                    ),
                    evidence=PackageEvidence(
                        name=pkg_name,
                        version=pkg_info.get("version"),
                        is_update_available=True,
                    ),
                    detected_value=f"Update {new_ver} available for {pkg_name}",
                    expected_value="Latest patched version installed",
                    affected_component=f"Package: {pkg_name}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1190"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.4"],
                    tags=["cve", "vulnerability", "updates"],
                )
            )

        return findings
