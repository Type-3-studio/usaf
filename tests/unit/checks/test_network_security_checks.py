from __future__ import annotations

import datetime
from unittest.mock import patch

from usaf.checks.network.network_checks import (
    AllMultiInterfacesCheck,
    AvahiMDNSCheck,
    CertStoreIntegrityCheck,
    DNSSearchDomainCheck,
    ExpiringCertificatesCheck,
    ExposedSensitivePortsCheck,
    InterfaceCarrierCheck,
    UntrustedCACheck,
)
from usaf.models.severity import Severity


class TestExposedSensitivePortsCheck:
    def test_passes_when_no_sockets(self):
        check = ExposedSensitivePortsCheck()
        result = check.evaluate({"sockets": {"tcp": [], "tcp6": []}})
        assert result.passed

    def test_passes_when_localhost_only(self):
        check = ExposedSensitivePortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"local_port": 3306, "local_address": "127.0.0.1", "state": "LISTEN", "protocol": "TCP"}],
                "tcp6": [],
            }
        })
        assert result.passed

    def test_fails_when_exposed_on_all(self):
        check = ExposedSensitivePortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"local_port": 3306, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}],
                "tcp6": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_non_sensitive_ports(self):
        check = ExposedSensitivePortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"local_port": 9999, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}],
                "tcp6": [],
            }
        })
        assert result.passed

    def test_has_mitre_mapping(self):
        check = ExposedSensitivePortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"local_port": 5432, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}],
                "tcp6": [],
            }
        })
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestInterfaceCarrierCheck:
    def test_passes_when_all_normal(self):
        check = InterfaceCarrierCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "state": "up", "carrier": True}]}
        })
        assert result.passed

    def test_fails_when_up_no_carrier(self):
        check = InterfaceCarrierCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "state": "up", "carrier": False}]}
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_down_interfaces(self):
        check = InterfaceCarrierCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "state": "down", "carrier": False}]}
        })
        assert result.passed


class TestAllMultiInterfacesCheck:
    def test_passes_when_no_allmulti(self):
        check = AllMultiInterfacesCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "flags": ["UP", "BROADCAST"]}]}
        })
        assert result.passed

    def test_passes_when_promisc_only(self):
        check = AllMultiInterfacesCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "flags": ["UP", "PROMISC"]}]}
        })
        assert result.passed

    def test_fails_when_allmulti_without_promisc(self):
        check = AllMultiInterfacesCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "flags": ["UP", "ALLMULTI"]}]}
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_passes_when_both_allmulti_and_promisc(self):
        check = AllMultiInterfacesCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "flags": ["UP", "ALLMULTI", "PROMISC"]}]}
        })
        assert result.passed


class TestAvahiMDNSCheck:
    def test_passes_when_not_running(self):
        check = AvahiMDNSCheck()
        result = check.evaluate({
            "dns": {"mdns": {"avahi_running": False}}
        })
        assert result.passed

    def test_fails_when_running(self):
        check = AvahiMDNSCheck()
        result = check.evaluate({
            "dns": {"mdns": {"avahi_running": True}}
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_severity_medium(self):
        check = AvahiMDNSCheck()
        result = check.evaluate({
            "dns": {"mdns": {"avahi_running": True}}
        })
        assert result.findings[0].severity == Severity.MEDIUM


class TestDNSSearchDomainCheck:
    def test_passes_when_no_search(self):
        check = DNSSearchDomainCheck()
        result = check.evaluate({
            "dns": {"resolv_conf": {"search_domains": []}, "resolved_status": {}}
        })
        assert result.passed

    def test_passes_with_public_domains(self):
        check = DNSSearchDomainCheck()
        result = check.evaluate({
            "dns": {"resolv_conf": {"search_domains": ["example.com"]}, "resolved_status": {}}
        })
        assert result.passed

    def test_fails_with_internal_domain(self):
        check = DNSSearchDomainCheck()
        result = check.evaluate({
            "dns": {"resolv_conf": {"search_domains": ["corp.internal"]}, "resolved_status": {}}
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_mapping(self):
        check = DNSSearchDomainCheck()
        result = check.evaluate({
            "dns": {"resolv_conf": {"search_domains": ["office.local"]}, "resolved_status": {}}
        })
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestExpiringCertificatesCheck:
    def test_passes_when_no_certs(self):
        check = ExpiringCertificatesCheck()
        result = check.evaluate({"certificates": {"ca_bundles": []}})
        assert result.passed

    @patch("usaf.checks.network.network_checks.ExpiringCertificatesCheck._get_expiry")
    def test_passes_when_cert_valid(self, mock_expiry):
        mock_expiry.return_value = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        check = ExpiringCertificatesCheck()
        result = check.evaluate({
            "certificates": {"ca_bundles": [{"path": "/etc/ssl/certs/valid.pem"}]}
        })
        assert result.passed

    @patch("usaf.checks.network.network_checks.ExpiringCertificatesCheck._get_expiry")
    def test_fails_when_expired(self, mock_expiry):
        mock_expiry.return_value = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        check = ExpiringCertificatesCheck()
        result = check.evaluate({
            "certificates": {"ca_bundles": [{"path": "/etc/ssl/certs/expired.pem"}]}
        })
        assert not result.passed
        assert any("expired" in f.title.lower() for f in result.findings)

    @patch("usaf.checks.network.network_checks.ExpiringCertificatesCheck._get_expiry")
    def test_fails_when_expiring_soon(self, mock_expiry):
        mock_expiry.return_value = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        check = ExpiringCertificatesCheck()
        result = check.evaluate({
            "certificates": {"ca_bundles": [{"path": "/etc/ssl/certs/expiring.pem"}]}
        })
        assert not result.passed
        assert any("expiring" in f.title.lower() for f in result.findings)


class TestCertStoreIntegrityCheck:
    def test_passes_when_clean(self):
        check = CertStoreIntegrityCheck()
        result = check.evaluate({
            "certificates": {
                "system_certs": {"broken_links": []},
                "cert_count": {"total_certs": 100},
            }
        })
        assert result.passed

    def test_fails_when_broken_links(self):
        check = CertStoreIntegrityCheck()
        result = check.evaluate({
            "certificates": {
                "system_certs": {"broken_links": ["/etc/ssl/certs/badlink"]},
                "cert_count": {"total_certs": 100},
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_no_certs(self):
        check = CertStoreIntegrityCheck()
        result = check.evaluate({
            "certificates": {
                "system_certs": {"broken_links": []},
                "cert_count": {"total_certs": 0},
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_both_issues(self):
        check = CertStoreIntegrityCheck()
        result = check.evaluate({
            "certificates": {
                "system_certs": {"broken_links": ["/etc/ssl/certs/bad"]},
                "cert_count": {"total_certs": 0},
            }
        })
        assert not result.passed
        assert len(result.findings) == 2
