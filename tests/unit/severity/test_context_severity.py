from __future__ import annotations

from usaf.models.evidence import FileEvidence, NetworkEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity
from usaf.severity.engine import SeverityContextEngine


class TestSeverityContextEngine:
    def test_no_adjustment_for_unmatched_check(self):
        engine = SeverityContextEngine()
        finding = _make_finding("KERN-101-001", "kernel", Severity.MEDIUM)
        result = engine.evaluate(finding, {})
        assert not result.changed
        assert result.original == result.adjusted

    def test_ssh_public_exposure_escalates_to_critical(self):
        engine = SeverityContextEngine()
        finding = _make_finding("SSH-101-001", "ssh protocol", Severity.HIGH)
        collectors = {
            "sockets": {
                "connections": [
                    {
                        "local_port": 22,
                        "local_address": "0.0.0.0",
                        "state": "LISTEN",
                    }
                ]
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.CRITICAL
        assert result.changed

    def test_ssh_localhost_reduces_to_medium(self):
        engine = SeverityContextEngine()
        finding = _make_finding("SSH-101-001", "ssh protocol", Severity.HIGH)
        collectors = {
            "sockets": {
                "connections": [
                    {
                        "local_port": 22,
                        "local_address": "127.0.0.1",
                        "state": "LISTEN",
                    }
                ]
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.MEDIUM
        assert result.changed

    def test_ssh_private_network_keeps_high(self):
        engine = SeverityContextEngine()
        finding = _make_finding("SSH-101-001", "ssh protocol", Severity.HIGH)
        collectors = {
            "sockets": {
                "connections": [
                    {
                        "local_port": 22,
                        "local_address": "10.0.0.5",
                        "state": "LISTEN",
                    }
                ]
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.HIGH

    def test_permission_in_temp_reduces_to_low(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_path(
            "PRM-201-001", "world-writable", Severity.HIGH, "/tmp/test.txt"
        )
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.LOW
        assert "temp" in result.context_reason

    def test_suid_in_opt_escalates_to_critical(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_path(
            "PRM-101-001", "suid binary", Severity.HIGH, "/opt/backdoor"
        )
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.CRITICAL

    def test_suid_in_usr_bin_reduces_to_medium(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_path(
            "PRM-101-001", "suid binary", Severity.HIGH, "/usr/bin/sudo"
        )
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.MEDIUM

    def test_service_account_user_reduces_severity(self):
        engine = SeverityContextEngine()
        finding = _make_finding(
            "USR-201-001", "empty password", Severity.CRITICAL,
            affected_component="daemon",
        )
        collectors = {
            "users": {
                "daemon": {"uid": 1, "gid": 1, "shell": "/usr/sbin/nologin"},
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.MEDIUM
        assert "service account" in result.context_reason

    def test_human_user_escalates_medium_to_high(self):
        engine = SeverityContextEngine()
        finding = _make_finding(
            "USR-102-001", "shadow password", Severity.MEDIUM,
            affected_component="alice",
        )
        collectors = {
            "users": {
                "alice": {"uid": 1001, "gid": 1001, "shell": "/bin/bash", "home": "/home/alice"},
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.HIGH

    def test_root_account_escalates_properly(self):
        engine = SeverityContextEngine()
        finding = _make_finding(
            "USR-201-001", "root issue", Severity.HIGH,
            affected_component="root",
        )
        collectors = {
            "users": {
                "root": {"uid": 0, "gid": 0, "shell": "/bin/bash"},
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.CRITICAL

    def test_network_sensitive_port_exposed(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_network(
            "NET-101-001", "port exposed", Severity.MEDIUM, 3389, "0.0.0.0"
        )
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.CRITICAL

    def test_database_port_exposed(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_network(
            "NET-101-001", "db exposed", Severity.MEDIUM, 5432, "0.0.0.0"
        )
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.HIGH

    def test_apply_all_returns_dict(self):
        engine = SeverityContextEngine()
        findings = [
            _make_finding("SSH-101-001", "ssh", Severity.HIGH),
            _make_finding("KERN-101-001", "kernel", Severity.HIGH),
        ]
        collectors = {
            "sockets": {
                "connections": [
                    {"local_port": 22, "local_address": "0.0.0.0", "state": "LISTEN"},
                ]
            }
        }
        result = engine.apply_all(findings, collectors)
        assert len(result) == 2
        ssh_result = result["SSH-101-001"]
        assert ssh_result.changed

    def test_no_findings_returns_empty(self):
        engine = SeverityContextEngine()
        result = engine.apply_all([], {})
        assert result == {}

    def test_context_aware_severity_repr_changed(self):
        from usaf.severity.engine import ContextAwareSeverity
        cas = ContextAwareSeverity(
            original=Severity.HIGH,
            adjusted=Severity.CRITICAL,
            check_id="SSH-101",
            context_reason="public exposure",
        )
        assert "HIGH→CRITICAL" in repr(cas)

    def test_context_aware_severity_repr_unchanged(self):
        from usaf.severity.engine import ContextAwareSeverity
        cas = ContextAwareSeverity(
            original=Severity.MEDIUM,
            adjusted=Severity.MEDIUM,
            check_id="TEST-001",
            context_reason="no adjustment",
        )
        assert repr(cas) == "MEDIUM"

    def test_ssh_not_listening_no_adjustment(self):
        engine = SeverityContextEngine()
        finding = _make_finding("SSH-101-001", "ssh", Severity.HIGH)
        result = engine.evaluate(finding, {"sockets": {"connections": []}})
        assert not result.changed

    def test_ssh_unspecified_address(self):
        engine = SeverityContextEngine()
        finding = _make_finding("SSH-101-001", "ssh", Severity.HIGH)
        collectors = {
            "sockets": {
                "connections": [
                    {"local_port": 22, "local_address": "192.168.1.1", "state": "LISTEN"},
                ]
            }
        }
        result = engine.evaluate(finding, collectors)
        assert result.adjusted == Severity.HIGH

    def test_permission_no_path_no_adjustment(self):
        engine = SeverityContextEngine()
        finding = _make_finding("PRM-101-001", "perm issue", Severity.HIGH)
        result = engine.evaluate(finding, {})
        assert not result.changed

    def test_permission_var_tmp_reduces_to_low(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_path("PRM-201-001", "world-writable", Severity.HIGH, "/var/tmp/foo")
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.LOW

    def test_permission_bin_reduces_to_medium(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_path("PRM-101-001", "suid binary", Severity.HIGH, "/bin/su")
        result = engine.evaluate(finding, {})
        assert result.adjusted == Severity.MEDIUM

    def test_user_missing_in_collectors(self):
        engine = SeverityContextEngine()
        finding = _make_finding("USR-201-001", "empty password", Severity.CRITICAL)
        result = engine.evaluate(finding, {"users": {}})
        assert not result.changed

    def test_user_non_dict_info(self):
        engine = SeverityContextEngine()
        finding = _make_finding("USR-201-001", "empty password", Severity.CRITICAL,
                                affected_component="nobody")
        result = engine.evaluate(finding, {"users": {"nobody": "not-a-dict"}})
        assert not result.changed

    def test_network_no_evidence(self):
        engine = SeverityContextEngine()
        finding = _make_finding("NET-101-001", "port check", Severity.MEDIUM)
        result = engine.evaluate(finding, {})
        assert not result.changed

    def test_network_non_sensitive_port(self):
        engine = SeverityContextEngine()
        finding = _make_finding_with_network("NET-101-001", "port check", Severity.MEDIUM, 8080, "0.0.0.0")
        result = engine.evaluate(finding, {})
        assert not result.changed


def _make_finding(
    finding_id: str, title: str, severity: Severity,
    affected_component: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.SECURITY,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        affected_component=affected_component,
    )


def _make_finding_with_path(
    finding_id: str, title: str, severity: Severity, path: str
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.PERMISSIONS,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=FileEvidence(path=path, content=""),
    )


def _make_finding_with_network(
    finding_id: str, title: str, severity: Severity, port: int, addr: str
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.NETWORK,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=NetworkEvidence(
            protocol="tcp",
            local_address=addr,
            local_port=port,
            state="LISTEN",
        ),
    )
