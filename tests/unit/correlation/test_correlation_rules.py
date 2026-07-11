from __future__ import annotations

from usaf.correlation.engine import CorrelationEngine
from usaf.correlation.rules import (
    DataExfilSurface,
    SSHBruteForceSurface,
    SuspiciousPersistence,
    UnauthorizedService,
)
from usaf.models.evidence import FileEvidence, NetworkEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity


class TestSSHBruteForceSurface:
    def test_no_findings_returns_empty(self):
        rule = SSHBruteForceSurface()
        result = rule.evaluate([])
        assert result == []

    def test_no_ssh_findings_returns_empty(self):
        rule = SSHBruteForceSurface()
        findings = [_make_finding("KERN-001-001", "kernel", Severity.MEDIUM)]
        result = rule.evaluate(findings)
        assert result == []

    def test_no_network_exposure_returns_empty(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-001-001", "protocol", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_ssh_and_network_produces_finding(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-001-001", "Protocol version 1 detected", Severity.HIGH),
            _make_finding("SSH-002-001", "Root SSH login is permitted", Severity.HIGH),
            _make_finding_with_port("NET-001-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "CRITICAL" in result[0].severity.value
        assert "brute-force" in result[0].title.lower()

    def test_root_login_triggers_correlation(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-002-001", "Root SSH login is not disabled", Severity.HIGH),
            _make_finding_with_port("NET-001-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_mitre_mapping_present(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-001-001", "Weak protocol version allowed", Severity.HIGH),
            _make_finding_with_port("NET-001-001", "ssh port", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0
        assert "T1110" in result[0].mitre_attack_ids

    def test_cis_mapping_present(self):
        rule = SSHBruteForceSurface()
        findings = [
            _make_finding("SSH-001-001", "Protocol version contains security issue", Severity.HIGH),
            _make_finding_with_port("NET-001-001", "ssh port", Severity.MEDIUM, 22),
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
            _make_finding("USR-001-001", "duplicate uid", Severity.CRITICAL),
            _make_finding("PRM-001-001", "unknown_suid", Severity.HIGH),
            _make_finding("PRM-001-002", "another_suid", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert "persistence" in result[0].title.lower()

    def test_suid_backdoor_triggers(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-001-001", "duplicate uid", Severity.CRITICAL),
            _make_finding("PRM-001-001", "suid1", Severity.HIGH),
            _make_finding("PRM-001-002", "suid2", Severity.HIGH),
            _make_finding("PRM-001-003", "suid3", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_mitre_mapping_present(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-001-001", "duplicate uid", Severity.CRITICAL),
            _make_finding("PRM-001-001", "suid1", Severity.HIGH),
            _make_finding("PRM-001-002", "suid2", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0

    def test_source_findings_are_tracked(self):
        rule = SuspiciousPersistence()
        findings = [
            _make_finding("USR-002-001", "empty password", Severity.CRITICAL),
            _make_finding("PRM-001-001", "suid1", Severity.HIGH),
            _make_finding("PRM-001-002", "suid2", Severity.HIGH),
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
            _make_finding_with_port("NET-001-001", "unexpected", Severity.MEDIUM, 4444),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_expected_ports_do_not_trigger(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-001-001", "ssh", Severity.MEDIUM, 22),
        ]
        result = rule.evaluate(findings)
        assert result == []

    def test_mitre_mapping_present(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-001-001", "unexpected", Severity.MEDIUM, 9999),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0

    def test_port_detail_in_description(self):
        rule = UnauthorizedService()
        findings = [
            _make_finding_with_port("NET-001-001", "unexpected", Severity.MEDIUM, 8080),
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
            _make_finding_with_promiscuous("NET-002-001", "promiscuous", Severity.MEDIUM),
            _make_finding_with_port("NET-001-001", "unexpected", Severity.MEDIUM, 4444),
            _make_finding_with_port("NET-001-002", "unexpected", Severity.MEDIUM, 5555),
            _make_finding("PRM-001-001", "suid", Severity.HIGH),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_promiscuous_alone_triggers(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-002-001", "promiscuous", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1

    def test_mitre_mapping_present(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-002-001", "promiscuous", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result[0].mitre_attack_ids) > 0

    def test_sniffing_keyword_in_title(self):
        rule = DataExfilSurface()
        findings = [
            _make_finding_with_promiscuous("NET-002-001", "promiscuous", Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert "sniffing" in result[0].title.lower()


class TestCorrelationEngineIntegration:
    def test_full_pipeline_with_all_rules(self):
        engine = CorrelationEngine()
        engine.register(SSHBruteForceSurface())
        engine.register(SuspiciousPersistence())
        engine.register(UnauthorizedService())
        engine.register(DataExfilSurface())

        findings = [
            _make_finding("SSH-001-001", "Protocol version allows weak negotiation", Severity.HIGH),
            _make_finding_with_port("NET-001-001", "ssh port", Severity.MEDIUM, 22),
            _make_finding("USR-002-001", "empty password", Severity.CRITICAL),
            _make_finding_with_port("NET-001-002", "unexpected", Severity.MEDIUM, 9999),
            _make_finding_with_promiscuous("NET-002-001", "promiscuous", Severity.MEDIUM),
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
