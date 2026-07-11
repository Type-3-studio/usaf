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

    def test_skips_system_ca_bundle(self):
        check = SelfSignedCertificatesCheck()
        collectors = {
            "certificates": {
                "ca_bundles": [{"path": "/etc/ssl/certs/ca-certificates.crt"}],
                "system_certs": {"pem_files": [{"path": "/etc/ssl/certs/Some_Root_CA.pem"}]},
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_flags_self_signed_outside_system_store(self, monkeypatch):
        import subprocess
        def mock_run(*args, **kwargs):
            class Result:
                returncode = 0
                stdout = "subject=CN=My Dev Cert\nissuer=CN=My Dev Cert\n"
                stderr = ""
            return Result()
        monkeypatch.setattr(subprocess, "run", mock_run)
        check = SelfSignedCertificatesCheck()
        collectors = {
            "certificates": {
                "ca_bundles": [],
                "system_certs": {"pem_files": [{"path": "/etc/myapp/certs/server.pem"}]},
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_check_id(self):
        assert SelfSignedCertificatesCheck.id == "SECR-502"
