from __future__ import annotations

from datetime import datetime

from usaf.models.evidence import (
    CommandEvidence,
    FileEvidence,
    NetworkEvidence,
    ProcessEvidence,
    RegistryEvidence,
    UserEvidence,
)
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Confidence, Severity


class TestFindingModel:
    def test_finding_creation(self):
        f = Finding(
            id="TEST-001-001",
            check_id="TEST-001",
            category=CheckCategory.KERNEL,
            severity=Severity.CRITICAL,
            risk_score=10.0,
            title="Critical issue",
            description="Something is very wrong",
            rationale="Because security",
            remediation="Fix it now",
            source="TestCheck",
        )
        assert f.id == "TEST-001-001"
        assert f.severity == Severity.CRITICAL
        assert f.risk_score == 10.0
        assert f.timestamp is not None
        assert f.false_positive_probability == 0.0
        assert f.confidence == Confidence.HIGH

    def test_finding_with_evidence(self):
        evidence = FileEvidence(
            path="/etc/test",
            permission="0o777",
            owner="root",
            content="dangerous config",
        )
        f = Finding(
            id="TEST-002-001",
            check_id="TEST-002",
            category=CheckCategory.PERMISSIONS,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="World-writable file",
            description="/etc/test is world-writable",
            rationale="Attackers can modify system files",
            remediation="chmod o-w /etc/test",
            evidence=evidence,
            detected_value="0o777",
            expected_value="0o644",
            affected_component="/etc/test",
            mitre_attack_ids=["T1222"],
            cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
            source="PermissionsCheck",
            false_positive_probability=0.0,
        )
        assert f.evidence is not None
        assert isinstance(f.evidence, FileEvidence)
        assert f.evidence.path == "/etc/test"
        assert f.evidence.permission == "0o777"
        assert "T1222" in f.mitre_attack_ids

    def test_finding_without_evidence(self):
        f = Finding(
            id="TEST-003-001",
            check_id="TEST-003",
            category=CheckCategory.GENERAL,
            severity=Severity.INFO,
            risk_score=0.0,
            title="Info only",
            description="Just information",
            rationale="Context",
            remediation="None needed",
            source="InfoCheck",
        )
        assert f.evidence is None

    def test_finding_serialization(self):
        f = Finding(
            id="TEST-004-001",
            check_id="TEST-004",
            category=CheckCategory.NETWORK,
            severity=Severity.MEDIUM,
            risk_score=5.0,
            title="Network issue",
            description="Test",
            rationale="Rationale",
            remediation="Remediation",
            evidence=NetworkEvidence(
                protocol="TCP",
                local_address="0.0.0.0",
                local_port=8080,
                state="LISTEN",
            ),
            source="NetworkCheck",
        )
        data = f.model_dump()
        assert data["id"] == "TEST-004-001"
        assert data["severity"] == "MEDIUM"
        assert data["evidence"]["protocol"] == "TCP"

    def test_finding_timestamp(self):
        f = Finding(
            id="TEST-005-001",
            check_id="TEST-005",
            category=CheckCategory.SYSTEM,
            severity=Severity.LOW,
            risk_score=2.5,
            title="Low issue",
            description="Test",
            rationale="Rationale",
            remediation="Remediation",
            source="TestCheck",
        )
        assert isinstance(f.timestamp, datetime)
        assert f.timestamp.tzinfo is not None


class TestEvidenceModels:
    def test_file_evidence(self):
        ev = FileEvidence(
            path="/etc/passwd",
            line=42,
            content="root:x:0:0:root:/root:/bin/bash",
            permission="0o644",
            owner="root",
        )
        assert ev.path == "/etc/passwd"
        assert ev.line == 42
        assert "root" in (ev.content or "")

    def test_process_evidence(self):
        ev = ProcessEvidence(
            pid=1234,
            name="sshd",
            binary="/usr/sbin/sshd",
            cmdline="/usr/sbin/sshd -D",
            user="root",
            state="S",
        )
        assert ev.pid == 1234
        assert ev.name == "sshd"

    def test_network_evidence(self):
        ev = NetworkEvidence(
            protocol="TCP",
            local_address="0.0.0.0",
            local_port=22,
            state="LISTEN",
            pid=1234,
            process_name="sshd",
        )
        assert ev.local_port == 22

    def test_registry_evidence(self):
        ev = RegistryEvidence(
            key="kernel.randomize_va_space",
            value="0",
            expected="2",
            source="/proc/sys/kernel/randomize_va_space",
        )
        assert ev.key == "kernel.randomize_va_space"
        assert ev.value == "0"
        assert ev.expected == "2"

    def test_command_evidence(self):
        ev = CommandEvidence(
            command="ls -la /tmp",
            stdout="total 8",
            exit_code=0,
        )
        assert ev.exit_code == 0

    def test_user_evidence(self):
        ev = UserEvidence(
            username="bob",
            uid=1000,
            gid=1000,
            home="/home/bob",
            shell="/bin/bash",
        )
        assert ev.username == "bob"
        assert ev.uid == 1000
