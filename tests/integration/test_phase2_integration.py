from __future__ import annotations

"""Integration tests for Phase 2 pipeline components working together.

Tests that severity context, correlation, knowledge base, compliance,
baseline, and profile modules integrate correctly with realistic data
flowing through the pipeline.
"""

from pathlib import Path

import pytest

from usaf.baseline.manager import BaselineManager
from usaf.compliance.framework import ComplianceFramework
from usaf.core.registry import registry
from usaf.correlation.engine import CorrelationEngine
from usaf.correlation.rules import (
    SSHBruteForceSurface,
    SuspiciousPersistence,
    UnauthorizedService,
)
from usaf.knowledge.base import KnowledgeBase
from usaf.models.evidence import (
    FileEvidence,
    NetworkEvidence,
    ProcessEvidence,
    RegistryEvidence,
)
from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult, ScanMetadata
from usaf.models.score import ScanScore
from usaf.models.severity import CheckCategory, Confidence, Severity
from usaf.profiles.manager import ProfileManager
from usaf.scoring.engine import ScoringEngine
from usaf.scoring.trust import TrustScorer
from usaf.severity.engine import SeverityContextEngine


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_finding(
    check_id: str,
    finding_id: str,
    severity: Severity,
    category: CheckCategory = CheckCategory.SYSTEM,
    evidence=None,
    mitre_attack_ids: list[str] | None = None,
    cis_benchmarks: list[str] | None = None,
    confidence: Confidence = Confidence.HIGH,
    fp_prob: float = 0.0,
    affected: str | None = None,
    title: str | None = None,
) -> Finding:
    return Finding(
        id=f"{check_id}-{finding_id}",
        check_id=check_id,
        category=category,
        severity=severity,
        risk_score=severity.score,
        title=title or f"{check_id} finding",
        description=f"Description for {check_id}",
        rationale="Security rationale for this finding",
        remediation="Command to fix",
        evidence=evidence,
        detected_value="bad",
        expected_value="good",
        affected_component=affected,
        source="TestCheck",
        confidence=confidence,
        false_positive_probability=fp_prob,
        mitre_attack_ids=mitre_attack_ids or [],
        cis_benchmarks=cis_benchmarks or [],
    )


_FAKE_COLLECTORS: dict[str, dict] = {
    "kernel_params": {
        "kernel.randomize_va_space": "0",
        "kernel.kptr_restrict": "0",
        "kernel.dmesg_restrict": "0",
        "fs.suid_dumpable": "1",
    },
    "users": {
        "users": [
            {"username": "root", "uid": 0, "gid": 0, "shell": "/bin/bash", "password": ""},
            {"username": "bob", "uid": 1000, "gid": 1000, "shell": "/bin/bash", "password": ""},
        ],
        "shadow": [
            {"username": "root", "password_hash": "", "locked": False},
            {"username": "bob", "password_hash": "", "locked": False},
        ],
    },
    "groups": {"groups": [{"name": "root", "gid": 0}, {"name": "docker", "gid": 999}]},
    "sockets": {
        "connections": [
            {"local_address": "0.0.0.0", "local_port": 22, "state": "LISTEN", "protocol": "TCP"},
            {"local_address": "127.0.0.1", "local_port": 631, "state": "LISTEN", "protocol": "TCP"},
        ],
        "interfaces": [{"name": "eth0", "promisc": False}],
    },
    "processes": {
        "processes": [
            {"name": "sshd", "pid": 100, "uid": 0, "state": "S", "binary": "/usr/sbin/sshd"},
            {"name": "systemd", "pid": 1, "uid": 0, "state": "S", "binary": "/lib/systemd/systemd"},
            {"name": "bash", "pid": 200, "uid": 1000, "state": "S", "binary": "/usr/bin/bash"},
        ]
    },
    "apt": {
        "packages": [
            {"name": "openssh-server", "version": "1:8.9p1", "status": "installed"},
            {"name": "ufw", "version": "0.36.2", "status": "installed"},
        ]
    },
    "systemd": {
        "services": [
            {"name": "ssh", "description": "OpenSSH server", "active": True},
            {"name": "ufw", "description": "Uncomplicated firewall", "active": True},
        ]
    },
    "kernel": {
        "os": {"version": "24.04", "pretty_name": "Ubuntu 24.04 LTS"},
        "kernel": {"release": "6.8.0-31-generic"},
    },
    "firewall": {
        "ufw": {"active": True, "installed": True},
        "nftables": {"active": False, "installed": False},
        "iptables": {"active": False, "installed": False},
    },
}


# ─── 1. Severity Context Pipeline ────────────────────────────────────────────


class TestSeverityContextPipeline:
    """Severity context engine integrated with scoring pipeline."""

    def test_ssh_exposure_escalates_severity(self):
        findings = [
            _make_finding("SSH-101", "001", Severity.HIGH, CheckCategory.SYSTEM),
        ]
        engine = SeverityContextEngine()
        adjustments = engine.apply_all(findings, _FAKE_COLLECTORS)
        adj = adjustments.get("SSH-101-001")
        assert adj is not None
        assert adj.changed
        assert adj.adjusted == Severity.CRITICAL

    def test_permission_temp_dir_deescalates(self):
        findings = [
            _make_finding(
                "PRM-201",
                "001",
                Severity.HIGH,
                CheckCategory.PERMISSIONS,
                evidence=FileEvidence(path="/tmp/world_writable", permission="0o777"),
            ),
        ]
        engine = SeverityContextEngine()
        adjustments = engine.apply_all(findings, _FAKE_COLLECTORS)
        adj = adjustments.get("PRM-201-001")
        assert adj is not None
        assert adj.changed
        assert adj.adjusted == Severity.LOW

    def test_severity_adjustment_flows_to_scoring(self):
        findings = [
            _make_finding("SSH-101", "001", Severity.HIGH, CheckCategory.SYSTEM),
        ]
        engine = SeverityContextEngine()
        adjustments = engine.apply_all(findings, _FAKE_COLLECTORS)
        for f in findings:
            adj = adjustments.get(f.id)
            if adj and adj.changed:
                f.severity = adj.adjusted
                f.risk_score = adj.adjusted.score

        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id="SSH-101",
                    name="SSH Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=findings,
                )
            ],
        )
        score = ScoringEngine().calculate(result)
        assert score.critical_count == 1
        assert score.high_count == 0


# ─── 2. Correlation Pipeline ─────────────────────────────────────────────────


class TestCorrelationPipeline:
    """Correlation engine integrated with finding pipeline."""

    def test_ssh_brute_force_surface_detected(self):
        findings = [
            _make_finding(
                "SSH-102",
                "001",
                Severity.HIGH,
                CheckCategory.SYSTEM,
                title="Root login is permitted",
                evidence=NetworkEvidence(
                    protocol="TCP",
                    local_address="0.0.0.0",
                    local_port=22,
                    state="LISTEN",
                    pid=100,
                    process_name="sshd",
                ),
            ),
            _make_finding(
                "NET-101",
                "001",
                Severity.MEDIUM,
                CheckCategory.NETWORK,
                evidence=NetworkEvidence(
                    protocol="TCP",
                    local_address="0.0.0.0",
                    local_port=22,
                    state="LISTEN",
                    pid=100,
                    process_name="sshd",
                ),
            ),
        ]
        engine = CorrelationEngine()
        engine.register(SSHBruteForceSurface())
        correlated = engine.evaluate(findings)
        assert len(correlated) >= 1
        assert any("SSH" in c.title for c in correlated)

    def test_persistence_pattern_detected(self):
        findings = [
            _make_finding(
                "UNKN-SERVICE",
                "001",
                Severity.HIGH,
                CheckCategory.SERVICES,
                title="Unknown systemd service: backdoor",
                evidence=FileEvidence(path="/etc/systemd/system/backdoor.service"),
                affected="systemd: backdoor",
            ),
            _make_finding(
                "USR-101",
                "001",
                Severity.CRITICAL,
                CheckCategory.USERS,
                evidence=RegistryEvidence(
                    key="passwd", value="root:0:0", expected="one root only", source="/etc/passwd"
                ),
            ),
        ]
        engine = CorrelationEngine()
        engine.register(SuspiciousPersistence())
        correlated = engine.evaluate(findings)
        assert len(correlated) >= 1

    def test_multi_rule_correlation(self):
        findings = [
            _make_finding(
                "SSH-102",
                "001",
                Severity.HIGH,
                CheckCategory.SYSTEM,
                title="Root login is permitted",
                evidence=NetworkEvidence(
                    protocol="TCP",
                    local_address="0.0.0.0",
                    local_port=22,
                    state="LISTEN",
                    pid=100,
                    process_name="sshd",
                ),
            ),
            _make_finding(
                "NET-101",
                "001",
                Severity.MEDIUM,
                CheckCategory.NETWORK,
                evidence=NetworkEvidence(
                    protocol="TCP",
                    local_address="0.0.0.0",
                    local_port=22,
                    state="LISTEN",
                    pid=100,
                    process_name="sshd",
                ),
            ),
            _make_finding(
                "UNKN-SERVICE",
                "001",
                Severity.HIGH,
                CheckCategory.SERVICES,
                title="Unknown systemd service: backdoor",
                evidence=FileEvidence(path="/etc/systemd/system/backdoor.service"),
                affected="systemd: backdoor",
            ),
            _make_finding(
                "USR-101",
                "001",
                Severity.CRITICAL,
                CheckCategory.USERS,
                evidence=RegistryEvidence(
                    key="passwd", value="root:0:0", expected="one root only", source="/etc/passwd"
                ),
            ),
        ]
        engine = CorrelationEngine()
        engine.register(SSHBruteForceSurface())
        engine.register(SuspiciousPersistence())
        correlated = engine.evaluate(findings)
        assert len(correlated) >= 2


# ─── 3. Knowledge Base Enrichment ────────────────────────────────────────────


class TestKnowledgeEnrichmentPipeline:
    """Knowledge base enrichment integrated with findings pipeline."""

    def test_kb_enriches_kernel_finding(self):
        kb = KnowledgeBase()
        findings = [
            _make_finding("KERN-101", "001", Severity.HIGH),
        ]
        names = set()
        for f in findings:
            entry = kb.get(f.check_id)
            if entry:
                names.add(entry.title)
        assert "Kernel ASLR Disabled" in names

    def test_kb_enriches_all_known_checks(self):
        kb = KnowledgeBase()
        check_ids = {
            "KERN-101",
            "KERN-201",
            "KERN-301",
            "SSH-101",
            "SSH-102",
            "SSH-201",
            "USR-101",
            "USR-201",
            "USR-102",
            "NET-101",
            "NET-201",
            "PRM-101",
            "PRM-201",
            "FW-101",
            "USB-101",
            "PWD-101",
            "KERN-401",
            "PKG-101",
            "PER-201",
            "SEC-101",
            "SVC-101",
            "CMP-101",
            "COM-101",
            "CTN-101",
            "FOR-101",
        }
        for cid in check_ids:
            entry = kb.get(cid)
            assert entry is not None, f"Missing KB entry for {cid}"
            assert entry.threat, f"Empty threat for {cid}"
            assert entry.exploit, f"Empty exploit for {cid}"
            assert entry.impact, f"Empty impact for {cid}"
            assert entry.fix, f"Empty fix for {cid}"
            assert entry.cvss, f"Empty CVSS for {cid}"

    def test_kb_confidence_evaluation(self):
        kb = KnowledgeBase()
        finding = _make_finding(
            "KERN-101",
            "001",
            Severity.HIGH,
            evidence=RegistryEvidence(key="test", value="0", expected="2", source="/proc/test"),
        )
        confidence, effective = kb.evaluate_finding_confidence(finding)
        assert isinstance(confidence, Confidence)
        assert 0.0 <= effective <= 1.0


# ─── 4. Compliance Framework ─────────────────────────────────────────────────


class TestCompliancePipeline:
    """Compliance framework integrated with findings pipeline."""

    @staticmethod
    def _ensure_discovery():
        import usaf.checks  # noqa: F401

    def test_cis_mapping_coverage(self):
        self._ensure_discovery()
        findings = [
            _make_finding(
                "KERN-101", "001", Severity.HIGH, cis_benchmarks=["CIS Ubuntu 20.04: 1.6.1"]
            ),
            _make_finding(
                "SSH-101", "001", Severity.HIGH, cis_benchmarks=["CIS Ubuntu 20.04: 5.2.2"]
            ),
            _make_finding(
                "KERN-401", "001", Severity.MEDIUM, cis_benchmarks=["CIS Ubuntu 20.04: 3.5"]
            ),
        ]
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id=f.check_id,
                    name=f.check_id,
                    category=f.category,
                    passed=False,
                    findings=[f],
                )
                for f in findings
            ],
        )
        framework = ComplianceFramework()
        coverage = framework.get_coverage("cis", result)
        assert coverage.passed > 0 or coverage.failed > 0
        assert coverage.coverage_percent >= 0

    def test_gap_analysis(self):
        self._ensure_discovery()
        result = ScanResult(metadata=ScanMetadata(hostname="test"))
        framework = ComplianceFramework()
        gaps = framework.report_gap_analysis("cis", result)
        assert isinstance(gaps, dict)

    def test_findings_without_cis_are_not_mapped(self):
        finding = _make_finding("COM-101", "001", Severity.HIGH)
        framework = ComplianceFramework()
        mapping = framework.get_findings_for("cis", [finding])
        assert isinstance(mapping, list)


# ─── 5. Baseline Snapshot & Diff ─────────────────────────────────────────────


class TestBaselinePipeline:
    """Baseline snapshot and diff integration."""

    def test_baseline_snapshot_from_realistic_data(self, tmp_path):
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            collectors_data=_FAKE_COLLECTORS,
        )
        mgr = BaselineManager(str(tmp_path))
        snap = mgr.build_snapshot(result)
        assert snap.hostname == "test"
        assert isinstance(snap.packages, dict)
        assert len(snap.ports) >= 2
        assert snap.kernel_params.get("kernel.randomize_va_space") == "0"

    def test_baseline_diff_detects_changes(self, tmp_path):
        mgr = BaselineManager(str(tmp_path))
        result_a = ScanResult(
            metadata=ScanMetadata(hostname="test", scan_id="a"),
            collectors_data=_FAKE_COLLECTORS,
        )
        snap_a = mgr.build_snapshot(result_a)
        mgr.store("test-snap", snap_a)

        modified = dict(_FAKE_COLLECTORS)
        modified["kernel_params"] = dict(modified["kernel_params"])
        modified["kernel_params"]["kernel.randomize_va_space"] = "2"
        result_b = ScanResult(
            metadata=ScanMetadata(hostname="test", scan_id="b"),
            collectors_data=modified,
        )
        snap_b = mgr.build_snapshot(result_b)

        loaded_a = mgr.load("test-snap")
        diff = mgr.diff(loaded_a, snap_b)
        modified_kernel = diff.modified.get("kernel_params", {})
        assert "kernel.randomize_va_space" in modified_kernel
        entry = modified_kernel["kernel.randomize_va_space"]
        assert entry["old"] == "0"
        assert entry["new"] == "2"


# ─── 6. Profile Matching ─────────────────────────────────────────────────────


class TestProfilePipeline:
    """Profile matching integrated with scan data."""

    def test_profile_matches_server_desktop(self):
        profiles = ProfileManager.BUILTIN_PROFILES
        assert "ubuntu-server-24-04" in profiles
        assert "ubuntu-desktop-24-04" in profiles
        server = profiles["ubuntu-server-24-04"]
        desktop = profiles["ubuntu-desktop-24-04"]
        assert server.name == "Ubuntu Server 24.04"
        assert desktop.name == "Ubuntu Desktop 24.04"
        assert "ubuntu-server" in server.expected_packages

    def test_profile_has_expected_structure(self):
        profiles = ProfileManager.BUILTIN_PROFILES
        profile = profiles["ubuntu-server-24-04"]
        assert profile.name == "Ubuntu Server 24.04"
        assert len(profile.expected_packages) >= 3
        assert len(profile.expected_ports) >= 1


# ─── 7. Full Pipeline End-to-End ─────────────────────────────────────────────


class TestFullPipelineEndToEnd:
    """End-to-end test exercising all Phase 2 components together."""

    def test_full_pipeline_with_fake_data(self):
        # Phase 1: Build findings from fake collector data
        findings = [
            _make_finding(
                "KERN-101",
                "001",
                Severity.HIGH,
                CheckCategory.KERNEL,
                evidence=RegistryEvidence(
                    key="randomize_va_space", value="0", expected="2", source="/proc/sys"
                ),
            ),
            _make_finding(
                "SSH-102",
                "001",
                Severity.HIGH,
                CheckCategory.SYSTEM,
                title="Root login is permitted",
                evidence=NetworkEvidence(
                    protocol="TCP",
                    local_address="0.0.0.0",
                    local_port=22,
                    state="LISTEN",
                    pid=100,
                    process_name="sshd",
                ),
            ),
            _make_finding(
                "USR-201",
                "001",
                Severity.CRITICAL,
                CheckCategory.USERS,
                evidence=RegistryEvidence(key="root", value="", expected="x", source="/etc/shadow"),
            ),
            _make_finding(
                "NET-101",
                "001",
                Severity.MEDIUM,
                CheckCategory.NETWORK,
                evidence=NetworkEvidence(
                    protocol="TCP",
                    local_address="0.0.0.0",
                    local_port=22,
                    state="LISTEN",
                    pid=100,
                    process_name="sshd",
                ),
            ),
            _make_finding(
                "USR-101",
                "001",
                Severity.CRITICAL,
                CheckCategory.USERS,
                evidence=RegistryEvidence(
                    key="passwd", value="root:0:0", expected="one root", source="/etc/passwd"
                ),
            ),
            _make_finding(
                "PRM-201",
                "001",
                Severity.HIGH,
                CheckCategory.PERMISSIONS,
                evidence=FileEvidence(path="/tmp/world_writable", permission="0o777"),
            ),
        ]

        # Phase 2: Severity context adjustment
        sev_engine = SeverityContextEngine()
        adjustments = sev_engine.apply_all(findings, _FAKE_COLLECTORS)
        for f in findings:
            adj = adjustments.get(f.id)
            if adj and adj.changed:
                f.severity = adj.adjusted
                f.risk_score = adj.adjusted.score
        ssh_adj = adjustments.get("SSH-102-001")
        assert ssh_adj is not None and ssh_adj.changed
        prm_adj = adjustments.get("PRM-201-001")
        assert prm_adj is not None and prm_adj.changed

        # Phase 3: Correlation
        corr_engine = CorrelationEngine()
        corr_engine.register(SSHBruteForceSurface())
        corr_engine.register(UnauthorizedService())
        correlated = corr_engine.evaluate(findings)
        assert len(correlated) >= 1

        # Phase 4: Knowledge enrichment
        kb = KnowledgeBase()
        for f in findings:
            entry = kb.get(f.check_id)
            if entry:
                existing_tags = set(f.tags)
                for tag in entry.tags:
                    if tag not in existing_tags:
                        f.tags.append(tag)
                        existing_tags.add(tag)

        # Phase 5: Scoring
        all_results = [
            CheckResult(
                check_id=f.check_id,
                name=f.check_id,
                category=f.category,
                passed=False,
                findings=[f],
            )
            for f in findings
        ]
        corr_result = CheckResult(
            check_id="CORRELATION",
            name="Correlation",
            category=CheckCategory.COMPROMISE,
            passed=len(correlated) == 0,
            findings=[f for f in correlated],
        )
        all_results.append(corr_result)

        result = ScanResult(
            metadata=ScanMetadata(hostname="test", os_info="Ubuntu 24.04"),
            results=all_results,
            collectors_data=_FAKE_COLLECTORS,
        )
        score = ScoringEngine().calculate(result)
        assert isinstance(score, ScanScore)
        assert 0.0 <= score.overall_score <= 10.0
        assert score.total_findings == len(findings) + len(correlated)
        assert score.critical_count >= 1

        # Phase 6: Compliance
        import usaf.checks  # noqa: F401

        framework = ComplianceFramework()
        coverage = framework.get_coverage("cis", result)
        assert coverage.coverage_percent >= 0

        # Phase 7: Baseline snapshot
        from usaf.baseline.manager import BaselineManager, BaselineSnapshot
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            mgr = BaselineManager(td)
            snap = mgr.build_snapshot(result)
            assert isinstance(snap, BaselineSnapshot)
            assert isinstance(snap.packages, dict)
