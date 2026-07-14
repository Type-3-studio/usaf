from __future__ import annotations

from pathlib import Path

import pytest

from usaf.knowledge.base import KnowledgeBase, KnowledgeEntry
from usaf.models.evidence import FileEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Confidence, Severity


class TestKnowledgeEntry:
    def test_create_from_dict(self):
        entry = KnowledgeEntry({
            "id": "TEST-001",
            "title": "Test Check",
            "threat": "A test threat",
            "exploit": "An exploit scenario",
            "impact": "High impact",
            "cvss": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (7.8)",
        })
        assert entry.id == "TEST-001"
        assert entry.title == "Test Check"
        assert entry.cvss.startswith("CVSS:3.1")

    def test_default_fields(self):
        entry = KnowledgeEntry({"id": "MINIMAL"})
        assert entry.threat == ""
        assert entry.known_exceptions == []
        assert entry.related_findings == []
        assert not entry.has_exceptions

    def test_from_file(self):
        path = Path(__file__).parent.parent.parent.parent / "src" / "usaf" / "knowledge" / "KERN-101.yaml"
        if path.exists():
            entry = KnowledgeEntry.from_file(path)
            assert entry.id == "KERN-101"
            assert entry.title == "Kernel ASLR Disabled"
            assert len(entry.affected_versions) > 0
            assert len(entry.tags) > 0

    def test_from_file_not_found(self):
        from usaf.core.exceptions import PolicyError
        with pytest.raises(PolicyError, match="not found"):
            KnowledgeEntry.from_file("/nonexistent/path.yaml")

    def test_summary(self):
        entry = KnowledgeEntry({
            "id": "T-001",
            "threat": "Bad stuff",
            "impact": "Full compromise",
            "cvss": "CVSS:7.5",
            "known_exceptions": ["Exception A"],
        })
        summary = entry.summary
        assert "Threat:" in summary
        assert "Impact:" in summary
        assert "CVSS:" in summary
        assert "Exceptions" in summary

    def test_summary_minimal(self):
        entry = KnowledgeEntry({"id": "T-001"})
        assert entry.summary == ""

    def test_evaluate_confidence_with_file_evidence(self):
        entry = KnowledgeEntry({
            "id": "T-001",
            "false_positive_rate": 0.1,
        })
        finding = Finding(
            id="T-001-001",
            check_id="T-001",
            category=CheckCategory.SECURITY,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="TestCheck",
            confidence=Confidence.HIGH,
            evidence=FileEvidence(path="/test/file", content="data", permission="0644", owner="root"),
        )
        confidence, effective = entry.evaluate_confidence_from_kb(finding)
        assert effective > 0.5
        assert confidence in (Confidence.HIGH, Confidence.MEDIUM)

    def test_evaluate_confidence_no_evidence(self):
        entry = KnowledgeEntry({
            "id": "T-001",
            "false_positive_rate": 0.0,
        })
        finding = Finding(
            id="T-001-001",
            check_id="T-001",
            category=CheckCategory.SECURITY,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="TestCheck",
            confidence=Confidence.LOW,
        )
        confidence, effective = entry.evaluate_confidence_from_kb(finding)
        assert effective >= 0.0

    def test_attr_fallback(self):
        entry = KnowledgeEntry({"id": "T-001", "custom_field": "hello"})
        assert entry.custom_field == "hello"
        assert entry.nonexistent == ""


class TestKnowledgeBase:
    def test_load_all_from_default_dir(self):
        kb = KnowledgeBase()
        kb.load_all()
        # Should have loaded at least the 13 check YAML files
        assert kb.count >= 13

    def test_get_existing_entry(self):
        kb = KnowledgeBase()
        entry = kb.get("KERN-101")
        assert entry is not None
        assert entry.id == "KERN-101"
        assert entry.title == "Kernel ASLR Disabled"

    def test_get_nonexistent_entry(self):
        kb = KnowledgeBase()
        entry = kb.get("NONEXISTENT-999")
        assert entry is None

    def test_lookup_finding(self):
        kb = KnowledgeBase()
        finding = Finding(
            id="KERN-101-001",
            check_id="KERN-101",
            category=CheckCategory.KERNEL,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="ASLR disabled",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="TestCheck",
        )
        entry = kb.lookup_finding(finding)
        assert entry is not None
        assert entry.id == "KERN-101"

    def test_lookup_finding_no_match(self):
        kb = KnowledgeBase()
        finding = Finding(
            id="UNKNOWN-001",
            check_id="UNKNOWN",
            category=CheckCategory.GENERAL,
            severity=Severity.LOW,
            risk_score=2.5,
            title="Unknown",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="TestCheck",
        )
        entry = kb.lookup_finding(finding)
        assert entry is None

    def test_evaluate_finding_confidence(self):
        kb = KnowledgeBase()
        finding = Finding(
            id="KERN-101-001",
            check_id="KERN-101",
            category=CheckCategory.KERNEL,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="ASLR disabled",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="TestCheck",
            confidence=Confidence.HIGH,
            evidence=FileEvidence(path="/proc/sys/kernel/randomize_va_space", content="0"),
        )
        confidence, effective = kb.evaluate_finding_confidence(finding)
        assert effective > 0.0

    def test_entries_property(self):
        kb = KnowledgeBase()
        entries = kb.entries
        assert len(entries) >= 13
        assert "KERN-101" in entries
        assert "SSH-101" in entries
        assert "USR-101" in entries

    def test_count(self):
        kb = KnowledgeBase()
        assert kb.count >= 13

    def test_all_yaml_files_have_required_fields(self):
        kb = KnowledgeBase()
        for entry in kb.entries.values():
            assert entry.id, f"Entry missing id: {entry}"
            assert entry.title, f"Entry {entry.id} missing title"
            assert entry.threat, f"Entry {entry.id} missing threat"
            assert entry.fix, f"Entry {entry.id} missing fix"
            assert entry.cvss, f"Entry {entry.id} missing cvss"
            assert entry.false_positive_rate >= 0.0, f"Entry {entry.id} invalid false_positive_rate"
            assert len(entry.affected_versions) > 0, f"Entry {entry.id} missing affected_versions"

    def test_all_yaml_files_have_mitre_mappings(self):
        kb = KnowledgeBase()
        for entry in kb.entries.values():
            assert len(entry.mitre_mappings) > 0, f"Entry {entry.id} missing mitre mappings"
