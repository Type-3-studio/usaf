from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class GitlabTokensCheck(AuditCheck):
    id = "SECR-601"
    name = "GitLab Token Detection"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects exposed GitLab tokens in files"
    depends = ["secrets"]
    tags = ["secrets", "gitlab", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        for match in data.get("gitlab_tokens", []):
            findings.append(self._finding(match, "GitLab token"))
        return findings

    def _finding(self, match: dict, label: str) -> Any:
        path = match.get("path", "")
        line = match.get("line", 0)
        return self.finding(
            finding_id="001",
            title=f"Exposed {label}: {path}:{line}",
            description=f"A {label} was found in '{path}' at line {line}. Match: '{match.get('match', '')[:80]}'.",
            rationale=f"Exposed {label} credentials allow unauthorized access. Credentials in files can be harvested by automated scanning.",
            remediation=f"Revoke the exposed {label} immediately. Remove it from '{path}'. Use a secrets manager instead.",
            evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
            detected_value=f"{label} at {path}:{line}",
            expected_value=f"No {label} in files",
            affected_component=path,
            confidence=Confidence.HIGH,
            false_positive_probability=0.1,
            mitre_attack_ids=["T1552.001"],
            tags=["secrets", "gitlab", "credentials", "exposure"],
        )


@register_check
class SlackTokensCheck(AuditCheck):
    id = "SECR-602"
    name = "Slack Token Detection"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects exposed Slack tokens in files"
    depends = ["secrets"]
    tags = ["secrets", "slack", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for match in self._get_data(collectors, "secrets").get("slack_tokens", []):
            path, line = match.get("path", ""), match.get("line", 0)
            findings.append(self.finding(
                finding_id="001",
                title=f"Exposed Slack token: {path}:{line}",
                description=f"Slack token found in '{path}' at line {line}: '{match.get('match', '')[:80]}'.",
                rationale="Exposed Slack tokens allow unauthorized API access to Slack workspaces. Attackers can read messages, exfiltrate data, and pivot to connected services.",
                remediation=f"Revoke the Slack token immediately. Remove from '{path}'. Rotate via Slack API console.",
                evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
                detected_value=f"Slack token at {path}:{line}",
                expected_value="No Slack tokens in files",
                affected_component=path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.001"],
                tags=["secrets", "slack", "credentials", "exposure"],
            ))
        return findings


@register_check
class NpmTokensCheck(AuditCheck):
    id = "SECR-603"
    name = "NPM Token Detection"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects exposed NPM tokens in files"
    depends = ["secrets"]
    tags = ["secrets", "npm", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for match in self._get_data(collectors, "secrets").get("npm_tokens", []):
            path, line = match.get("path", ""), match.get("line", 0)
            findings.append(self.finding(
                finding_id="001",
                title=f"Exposed NPM token: {path}:{line}",
                description=f"NPM token found in '{path}' at line {line}: '{match.get('match', '')[:80]}'.",
                rationale="Exposed NPM tokens allow attackers to publish malicious packages under your organization's name or download private packages without authorization.",
                remediation=f"Revoke the NPM token immediately via npmjs.com. Remove from '{path}'. Use .npmrc with restricted permissions.",
                evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
                detected_value=f"NPM token at {path}:{line}",
                expected_value="No NPM tokens in files",
                affected_component=path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.001"],
                tags=["secrets", "npm", "credentials", "exposure"],
            ))
        return findings


@register_check
class AzureDevopsCheck(AuditCheck):
    id = "SECR-604"
    name = "Azure DevOps Credential Detection"
    category = CheckCategory.SECURITY
    severity = Severity.HIGH
    description = "Detects exposed Azure DevOps credentials in files"
    depends = ["secrets"]
    tags = ["secrets", "azure", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for match in self._get_data(collectors, "secrets").get("azure_devops", []):
            path, line = match.get("path", ""), match.get("line", 0)
            findings.append(self.finding(
                finding_id="001",
                title=f"Exposed Azure DevOps credential: {path}:{line}",
                description=f"Azure DevOps credential found in '{path}' at line {line}: '{match.get('match', '')[:80]}'.",
                rationale="Exposed Azure DevOps tokens grant access to source code, pipelines, and infrastructure configurations. Attackers can inject malicious build steps or exfiltrate secrets.",
                remediation=f"Revoke the Azure DevOps PAT via dev.azure.com. Remove from '{path}'. Use Azure Key Vault or Managed Identities instead.",
                evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
                detected_value=f"Azure DevOps credential at {path}:{line}",
                expected_value="No Azure DevOps credentials in files",
                affected_component=path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.001"],
                tags=["secrets", "azure", "credentials", "exposure"],
            ))
        return findings


@register_check
class DockerCredsCheck(AuditCheck):
    id = "SECR-605"
    name = "Docker Credential Detection"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects exposed Docker credentials in files"
    depends = ["secrets"]
    tags = ["secrets", "docker", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for match in self._get_data(collectors, "secrets").get("docker_creds", []):
            path, line = match.get("path", ""), match.get("line", 0)
            findings.append(self.finding(
                finding_id="001",
                title=f"Exposed Docker credential: {path}:{line}",
                description=f"Docker credential found in '{path}' at line {line}: '{match.get('match', '')[:80]}'.",
                rationale="Exposed Docker Hub credentials allow attackers to push malicious images to your repositories or pull private images. Container registry access can lead to supply chain compromise.",
                remediation=f"Revoke Docker Hub access token via hub.docker.com. Remove from '{path}'. Use docker login with credential helpers.",
                evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
                detected_value=f"Docker credential at {path}:{line}",
                expected_value="No Docker credentials in files",
                affected_component=path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.001"],
                tags=["secrets", "docker", "credentials", "exposure"],
            ))
        return findings


@register_check
class StripeKeysCheck(AuditCheck):
    id = "SECR-606"
    name = "Stripe API Key Detection"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects exposed Stripe API keys in files"
    depends = ["secrets"]
    tags = ["secrets", "stripe", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for match in self._get_data(collectors, "secrets").get("stripe_keys", []):
            path, line = match.get("path", ""), match.get("line", 0)
            findings.append(self.finding(
                finding_id="001",
                title=f"Exposed Stripe API key: {path}:{line}",
                description=f"Stripe key found in '{path}' at line {line}: '{match.get('match', '')[:80]}'.",
                rationale="Exposed Stripe live keys allow attackers to make unauthorized charges, refunds, and access customer payment data. This is a PCI DSS compliance violation.",
                remediation=f"Revoke the Stripe key via dashboard.stripe.com immediately. Remove from '{path}'. Use Stripe's restricted keys or secret managers.",
                evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
                detected_value=f"Stripe key at {path}:{line}",
                expected_value="No Stripe keys in files",
                affected_component=path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.001"],
                tags=["secrets", "stripe", "credentials", "exposure"],
            ))
        return findings


@register_check
class TwilioKeysCheck(AuditCheck):
    id = "SECR-607"
    name = "Twilio Credential Detection"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects exposed Twilio credentials in files"
    depends = ["secrets"]
    tags = ["secrets", "twilio", "credentials", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for match in self._get_data(collectors, "secrets").get("twilio_keys", []):
            path, line = match.get("path", ""), match.get("line", 0)
            findings.append(self.finding(
                finding_id="001",
                title=f"Exposed Twilio credential: {path}:{line}",
                description=f"Twilio credential found in '{path}' at line {line}: '{match.get('match', '')[:80]}'.",
                rationale="Exposed Twilio credentials allow attackers to send SMS, make calls, and access call logs. This can be used for social engineering, phishing, and toll fraud.",
                remediation=f"Revoke the Twilio credential via console.twilio.com. Remove from '{path}'. Use Twilio API keys with restricted permissions.",
                evidence=FileEvidence(path=path, line=line, content=f"Match: {match.get('match', '')[:120]}"),
                detected_value=f"Twilio credential at {path}:{line}",
                expected_value="No Twilio credentials in files",
                affected_component=path,
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.001"],
                tags=["secrets", "twilio", "credentials", "exposure"],
            ))
        return findings


@register_check
class PasswordInCodeCheck(AuditCheck):
    id = "SECR-608"
    name = "Password in Code Detection"
    category = CheckCategory.SECURITY
    severity = Severity.HIGH
    description = "Detects hardcoded passwords in configuration and source files"
    depends = ["secrets"]
    tags = ["secrets", "passwords", "credentials", "exposure"]
    max_findings = 200

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")

        for cat in ("gitlab_tokens", "slack_tokens", "npm_tokens", "azure_devops", "docker_creds", "stripe_keys", "twilio_keys"):
            for match in data.get(cat, []):
                path = match.get("path", "")
                line = match.get("line", 0)
                content = match.get("match", "")
                findings.append(self.finding(
                    finding_id="001",
                    title=f"Hardcoded credential: {path}:{line}",
                    description=f"Hardcoded credential found in '{path}' at line {line}: '{content[:80]}'.",
                    rationale="Hardcoded credentials in code or config files are a common source of data breaches. Automated scanners continuously search for exposed secrets in public and private repositories.",
                    remediation=f"Remove the hardcoded credential from '{path}'. Use environment variables or a secrets manager.",
                    evidence=FileEvidence(path=path, line=line, content=f"Match: {content[:120]}"),
                    detected_value=f"Credential at {path}:{line}",
                    expected_value="No hardcoded credentials",
                    affected_component=path,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1552.001"],
                    tags=["secrets", "passwords", "credentials", "exposure"],
                ))
        return findings
