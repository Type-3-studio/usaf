from __future__ import annotations

from usaf.checks.secrets.expired_certificates import ExpiredCertificatesCheck


class TestExpiredCertificatesCheck:
    def test_no_findings_when_no_certs(self):
        check = ExpiredCertificatesCheck()
        collectors = {"certificates": {"ca_bundles": [], "system_certs": {"pem_files": []}}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_missing_files(self):
        check = ExpiredCertificatesCheck()
        collectors = {
            "certificates": {
                "ca_bundles": [{"path": "/nonexistent/cert.pem"}],
                "system_certs": {"pem_files": []},
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_deduplicates(self):
        check = ExpiredCertificatesCheck()
        collectors = {
            "certificates": {
                "ca_bundles": [
                    {"path": "/nonexistent/cert.pem"},
                    {"path": "/nonexistent/cert.pem"},
                ],
                "system_certs": {"pem_files": []},
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_check_id(self):
        assert ExpiredCertificatesCheck.id == "SECR-501"
