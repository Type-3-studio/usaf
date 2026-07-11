from __future__ import annotations

from usaf.correlation.engine import CorrelationEngine
from usaf.correlation.rules import (
    DataExfilSurface,
    DefenseEvasionIndicators,
    ExposedVulnerableService,
    SSHBruteForceSurface,
    SuidArmingChain,
    SuspiciousPersistence,
    UnauthorizedService,
)
from usaf.models.evidence import FileEvidence, NetworkEvidence, PackageEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity


class TestSSHBruteForceSurface:
    def test_no_findings_returns_empty(self):
        rule = SSHBruteForceSurface()
        result = rule.evaluate([])
        assert result == []

    def test_no_ssh_findings_returns_empty(self):
        rule = SSHBruteForceSurface()
        findings = [_make_finding("KERN-101-001", "kernel", Severity.MEDIUM)]
        result = rule.evaluate(findings)
        assert result == []

    def test_no_network_exposure_returns_empty(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-101-001", "protocol", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_ssh_and_network_produces_finding(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-101-001", "Protocol version 1 detected", Severity.HIGH),
            _make_finding("SSH-102-001", "Root SSH login is permitted", Severity.HIGH),
            _make_finding_with_port("NET-101-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "CRITICAL" in result[0].severity.value
        assert "brute-force" in result[0].title.lower()

    def test_root_login_triggers_correlation(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-102-001", "Root SSH login is not disabled", Severity.HIGH),
            _make_finding_with_port("NET-101-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_mitre_mapping_present(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-101-001", "Weak protocol version allowed", Severity.HIGH),
            _make_finding_with_port("NET-101-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0
        assert "T1110" in result[0].mitre_attack_ids

    def test_cis_mapping_present(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-101-001", "Protocol version contains security issue", Severity.HIGH),
            _make_finding_with_port("NET-101-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].cis_benchmarks) > 0


class TestSuspiciousPersistence:
    def test_no_user_anomalies_returns_empty(self):
        rule = SuspiciousPersistence()
        result = rule.evaluate([])
        assert result == []

    def test_user_anomaly_and_unknown_service_triggers(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-101-001", "duplicate uid", Severity.CRITICAL),
            _make_finding("PRM-101-001", "unknown_suid", Severity.HIGH),
            _make_finding("PRM-101-002", "another_suid", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "persistence" in result[0].title.lower()

    def test_suid_backdoor_triggers(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-101-001", "duplicate uid", Severity.CRITICAL),
            _make_finding("PRM-101-001", "suid1", Severity.HIGH),
            _make_finding("PRM-101-002", "suid2", Severity.HIGH),
            _make_finding("PRM-101-003", "suid3", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_mitre_mapping_present(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-101-001", "duplicate uid", Severity.CRITICAL),
            _make_finding("PRM-101-001", "suid1", Severity.HIGH),
            _make_finding("PRM-101-002", "suid2", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0

    def test_source_findings_are_tracked(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-201-001", "empty password", Severity.CRITICAL),
            _make_finding("PRM-101-001", "suid1", Severity.HIGH),
            _make_finding("PRM-101-002", "suid2", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].source_findings) >= 2


class TestUnauthorizedService:
    def test_no_unexpected_ports_returns_empty(self):
        rule = UnauthorizedService()
        result = rule.evaluate([])
        assert result == []

    def test_unexpected_port_triggers(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-101-001", "unexpected", Severity.MEDIUM, 4444),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_expected_ports_do_not_trigger(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-101-001", "ssh", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_mitre_mapping_present(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-101-001", "unexpected", Severity.MEDIUM, 9999),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0

    def test_port_detail_in_description(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-101-001", "unexpected", Severity.MEDIUM, 8080),
        ]
        result = rule.evaluate(findings)
        assert "8080" in result[0].description


class TestDataExfilSurface:
    def test_no_promiscuous_returns_empty(self):
        rule = DataExfilSurface()
        result = rule.evaluate([])
        assert result == []

    def test_promiscuous_and_ports_triggers(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-201-001", "promiscuous", Severity.MEDIUM),
            _make_finding_with_port("NET-101-001", "unexpected", Severity.MEDIUM, 4444),
            _make_finding_with_port("NET-101-002", "unexpected", Severity.MEDIUM, 5555),
            _make_finding("PRM-101-001", "suid", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_promiscuous_alone_triggers(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-201-001", "promiscuous", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_mitre_mapping_present(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-201-001", "promiscuous", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0

    def test_sniffing_keyword_in_title(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-201-001", "promiscuous", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert "sniffing" in result[0].title.lower()


class TestSuidArmingChain:
    def test_no_ww_findings_returns_empty(self):
        rule = SuidArmingChain()
        result = rule.evaluate([])
        assert result == []

    def test_no_suid_findings_returns_empty(self):
        rule = SuidArmingChain()
        findings = [
            _make_finding_with_ww_file("PRM-201-001", "ww", Severity.HIGH, "/etc/shadow"),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_both_required_for_correlation(self):
        rule = SuidArmingChain()
        findings = [
            _make_finding_with_ww_file("PRM-201-001", "ww", Severity.HIGH, "/etc/shadow"),
            _make_finding("PRM-101-001", "suid binary", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "privilege escalation" in result[0].title.lower()

    def test_mitre_mapping_present(self):
        rule = SuidArmingChain()
        findings = [
            _make_finding_with_ww_file("PRM-201-001", "ww", Severity.HIGH, "/etc/passwd"),
            _make_finding("PRM-101-001", "suid", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert "T1548.001" in result[0].mitre_attack_ids

    def test_ww_paths_in_description(self):
        rule = SuidArmingChain()
        findings = [
            _make_finding_with_ww_file("PRM-201-001", "ww", Severity.HIGH, "/etc/shadow"),
            _make_finding("PRM-101-001", "suid", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert "/etc/shadow" in result[0].description


class TestDefenseEvasionIndicators:
    def test_no_findings_returns_empty(self):
        rule = DefenseEvasionIndicators()
        result = rule.evaluate([])
        assert result == []

    def test_single_control_does_not_trigger(self):
        rule = DefenseEvasionIndicators()
        findings = [
            _make_finding("FW-101-001", "firewall inactive", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_two_disabled_controls_triggers(self):
        rule = DefenseEvasionIndicators()
        findings = [
            _make_finding("FW-101-001", "firewall inactive", Severity.HIGH),
            _make_finding("FOR-101-001", "auditd disabled", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "defense" in result[0].title.lower() or "security" in result[0].title.lower()

    def test_all_four_disabled_triggers(self):
        rule = DefenseEvasionIndicators()
        findings = [
            _make_finding("FW-101-001", "fw", Severity.HIGH),
            _make_finding("FOR-101-001", "auditd", Severity.MEDIUM),
            _make_finding("SEC-101-001", "apparmor", Severity.HIGH),
            _make_finding("USB-101-001", "usb", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "4/4" in result[0].title

    def test_mitre_mapping_present(self):
        rule = DefenseEvasionIndicators()
        findings = [
            _make_finding("FW-101-001", "fw", Severity.HIGH),
            _make_finding("FOR-101-001", "auditd", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert "T1562.001" in result[0].mitre_attack_ids


class TestExposedVulnerableService:
    def test_no_risky_pkgs_returns_empty(self):
        rule = ExposedVulnerableService()
        result = rule.evaluate([])
        assert result == []

    def test_no_listening_ports_returns_empty(self):
        rule = ExposedVulnerableService()
        findings = [
            _make_finding_with_package("PKG-101-001", "cups", Severity.MEDIUM, "cups"),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_cups_on_port_631_triggers(self):
        rule = ExposedVulnerableService()
        findings = [
            _make_finding_with_package("PKG-101-001", "cups installed", Severity.MEDIUM, "cups"),
            _make_finding_with_port("NET-101-001", "ipp", Severity.MEDIUM, 631),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "cups" in result[0].title.lower()
        assert "631" in result[0].title

    def test_samba_on_port_445_triggers(self):
        rule = ExposedVulnerableService()
        findings = [
            _make_finding_with_package("PKG-101-001", "samba installed", Severity.MEDIUM, "samba"),
            _make_finding_with_port("NET-101-001", "smb", Severity.MEDIUM, 445),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "samba" in result[0].title

    def test_irrelevant_port_does_not_trigger(self):
        rule = ExposedVulnerableService()
        findings = [
            _make_finding_with_package("PKG-101-001", "cups installed", Severity.MEDIUM, "cups"),
            _make_finding_with_port("NET-101-001", "ssh", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_multiple_exposed_services(self):
        rule = ExposedVulnerableService()
        findings = [
            _make_finding_with_package("PKG-101-001", "cups installed", Severity.MEDIUM, "cups"),
            _make_finding_with_package("PKG-101-002", "samba installed", Severity.MEDIUM, "samba"),
            _make_finding_with_port("NET-101-001", "ipp", Severity.MEDIUM, 631),
            _make_finding_with_port("NET-101-002", "smb", Severity.MEDIUM, 445),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "cups" in result[0].title
        assert "samba" in result[0].title

    def test_mitre_mapping_present(self):
        rule = ExposedVulnerableService()
        findings = [
            _make_finding_with_package("PKG-101-001", "cups installed", Severity.MEDIUM, "cups"),
            _make_finding_with_port("NET-101-001", "ipp", Severity.MEDIUM, 631),
        ]
        result = rule.evaluate(findings)
        assert "T1190" in result[0].mitre_attack_ids


class TestCorrelationEngineIntegration:
    def test_full_pipeline_with_all_rules(self):
        engine = CorrelationEngine()
        engine.register(SSHBruteForceSurface())
        engine.register(SuspiciousPersistence())
        engine.register(UnauthorizedService())
        engine.register(DataExfilSurface())

        findings = [
            _make_finding("SSH-101-001", "Protocol version allows weak negotiation", Severity.HIGH),
            _make_finding_with_port("NET-101-001", "ssh port", Severity.MEDIUM, 22),
            _make_finding("USR-201-001", "empty password", Severity.CRITICAL),
            _make_finding_with_port("NET-101-002", "unexpected", Severity.MEDIUM, 9999),
            _make_finding_with_promiscuous("NET-201-001", "promiscuous", Severity.MEDIUM),
        ]

        result = engine.evaluate(findings)
        assert len(result) >= 3  # SSH-brute + data exfil + unauthorized service

    def test_rule_count(self):
        engine = CorrelationEngine()
        assert engine.rule_count == 0
        engine.register(SSHBruteForceSurface())
        assert engine.rule_count == 1
        engine.register(SuspiciousPersistence())
        assert engine.rule_count == 2

    def test_all_rules_have_unique_ids(self):
        rules = [
            SSHBruteForceSurface(),
            SuspiciousPersistence(),
            UnauthorizedService(),
            DataExfilSurface(),
        ]
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {ids}"


def _make_finding(finding_id: str, title: str, severity: Severity) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.SECURITY,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
    )


def _make_finding_with_port(
    finding_id: str, title: str, severity: Severity, port: int
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.NETWORK,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test network finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=NetworkEvidence(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=port,
            state="LISTEN",
        ),
    )


def _make_finding_with_promiscuous(
    finding_id: str, title: str, severity: Severity
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.NETWORK,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test promiscuous finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=FileEvidence(path="/sys/class/net/eth0/flags", content="0x1003"),
    )


def _make_finding_with_ww_file(
    finding_id: str, title: str, severity: Severity, path: str
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.PERMISSIONS,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test world-writable finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=FileEvidence(path=path, permission="0o777"),
    )


def _make_finding_with_package(
    finding_id: str, title: str, severity: Severity, pkg_name: str
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.PACKAGES,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test package finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=PackageEvidence(name=pkg_name, version="1.0"),
    )
