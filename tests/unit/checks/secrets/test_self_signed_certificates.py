from __future__ import annotations

from usaf.checks.secrets.self_signed_certificates import SelfSignedCertificatesCheck


class TestSelfSignedCertificatesCheck:
    def test_no_findings_when_no_certs(self):
        check = SelfSignedCertificatesCheck()
        collectors = {"certificates": {"ca_bundles": [], "system_certs": {"pem_files": []}}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_missing_files(self):
        check = SelfSignedCertificatesCheck()
        collectors = {
            "certificates": {
                "ca_bundles": [{"path": "/nonexistent/cert.pem"}],
                "system_certs": {"pem_files": []},
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_check_id(self):
        assert SelfSignedCertificatesCheck.id == "SECR-502"
