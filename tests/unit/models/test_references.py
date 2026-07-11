from usaf.models.references import CISBenchmark, CVEReference, MITREAttack, OWASPMapping


class TestCVEReference:
    def test_create_basic(self):
        ref = CVEReference(id="CVE-2024-12345")
        assert ref.id == "CVE-2024-12345"
        assert ref.description is None
        assert ref.severity is None
        assert ref.cvss_score is None
        assert ref.url is None

    def test_create_full(self):
        ref = CVEReference(
            id="CVE-2024-12345",
            description="Test vuln",
            severity="HIGH",
            cvss_score=7.5,
            url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345",
        )
        assert ref.cvss_score == 7.5
        assert ref.url is not None

    def test_model_dump_excludes_none(self):
        ref = CVEReference(id="CVE-2024-0001", description="Test")
        data = ref.model_dump()
        assert data == {"id": "CVE-2024-0001", "description": "Test"}

    def test_model_dump_includes_all_when_set(self):
        ref = CVEReference(
            id="CVE-2024-0001",
            description="Test",
            severity="HIGH",
            cvss_score=7.5,
            url="https://example.com",
        )
        data = ref.model_dump()
        assert data["id"] == "CVE-2024-0001"
        assert data["cvss_score"] == 7.5
        assert data["url"] == "https://example.com"


class TestCISBenchmark:
    def test_create_basic(self):
        ref = CISBenchmark(id="CIS Ubuntu 20.04: 5.2.2")
        assert ref.id == "CIS Ubuntu 20.04: 5.2.2"
        assert ref.title is None
        assert ref.level is None

    def test_create_full(self):
        ref = CISBenchmark(
            id="CIS Ubuntu 20.04: 5.2.2",
            title="Ensure SSH Protocol is set to 2",
            description="SSH protocol 1 has known vulnerabilities",
            level="Level 1",
        )
        assert ref.title.startswith("Ensure SSH")
        assert ref.level == "Level 1"

    def test_model_dump_excludes_none(self):
        ref = CISBenchmark(id="CIS:1.1")
        data = ref.model_dump()
        assert data == {"id": "CIS:1.1"}


class TestMITREAttack:
    def test_create_basic(self):
        ref = MITREAttack(technique_id="T1548.001")
        assert ref.technique_id == "T1548.001"
        assert ref.technique_name is None

    def test_create_full(self):
        ref = MITREAttack(
            technique_id="T1548.001",
            technique_name="Setuid and Setgid",
            tactic="Privilege Escalation",
            url="https://attack.mitre.org/techniques/T1548/001/",
        )
        assert ref.technique_name == "Setuid and Setgid"
        assert ref.tactic == "Privilege Escalation"

    def test_model_dump_excludes_none(self):
        ref = MITREAttack(technique_id="T1001")
        data = ref.model_dump()
        assert data == {"technique_id": "T1001"}


class TestOWASPMapping:
    def test_create_basic(self):
        ref = OWASPMapping(id="A1:2017-Injection")
        assert ref.id == "A1:2017-Injection"

    def test_create_full(self):
        ref = OWASPMapping(
            id="A2:2017-Broken Authentication",
            name="Broken Authentication",
            category="Authentication",
        )
        assert ref.name == "Broken Authentication"
        assert ref.category == "Authentication"

    def test_model_dump_excludes_none(self):
        ref = OWASPMapping(id="A3:2017-Sensitive Data Exposure")
        data = ref.model_dump()
        assert data == {"id": "A3:2017-Sensitive Data Exposure"}
