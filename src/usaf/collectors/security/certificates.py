from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class CertStoreCollector(BaseCollector):
    name = "certificates"
    description = "System certificate stores, CA bundles, and TLS certificate inventory"

    CA_DIRS = [
        "/etc/ssl/certs",
        "/usr/local/share/ca-certificates",
        "/usr/share/ca-certificates",
        "/etc/ca-certificates",
    ]

    def _do_collect(self) -> dict:
        return {
            "ca_bundles": self._list_ca_bundles(),
            "system_certs": self._inspect_cert_dir(),
            "cert_count": self._count_certs(),
            "update_tool": self._check_update_tool(),
            "pam_opensc": self._check_pam_pkcs11(),
        }

    def _list_ca_bundles(self) -> list[dict]:
        bundles: list[dict] = []
        for d in self.CA_DIRS:
            dp = Path(d)
            if dp.is_dir():
                try:
                    for f in dp.iterdir():
                        if f.is_file() and not f.name.startswith("."):
                            try:
                                st = f.stat()
                                bundles.append({
                                    "path": str(f),
                                    "name": f.name,
                                    "size": st.st_size,
                                    "modified": st.st_mtime,
                                    "is_symlink": f.is_symlink(),
                                })
                            except OSError:
                                continue
                except PermissionError:
                    pass
        return bundles

    def _inspect_cert_dir(self) -> dict:
        result: dict = {
            "hash_links": [],
            "pem_files": [],
            "broken_links": [],
        }
        cert_dir = Path("/etc/ssl/certs")
        if not cert_dir.is_dir():
            return result
        try:
            for f in cert_dir.iterdir():
                try:
                    if f.is_symlink() and not f.exists():
                        result["broken_links"].append(str(f))
                    elif f.name.endswith(".pem") or f.name.endswith(".crt") or f.name.endswith(".der"):
                        result["pem_files"].append({
                            "path": str(f),
                            "name": f.name,
                            "size": f.stat().st_size,
                            "modified": f.stat().st_mtime,
                        })
                    elif "." not in f.name and f.is_symlink():
                        result["hash_links"].append(str(f))
                except OSError:
                    continue
        except PermissionError:
            pass
        return result

    def _count_certs(self) -> dict:
        result: dict = {
            "total_bundles": 0,
            "total_certs": 0,
        }
        bundle = Path("/etc/ssl/certs/ca-certificates.crt")
        if bundle.exists():
            result["total_bundles"] = 1
            try:
                cert_count = 0
                for line in bundle.read_text().splitlines():
                    if line.strip() == "-----BEGIN CERTIFICATE-----":
                        cert_count += 1
                result["total_certs"] = cert_count
            except OSError:
                pass
        return result

    def _check_update_tool(self) -> dict:
        result: dict = {
            "update_ca_certificates": False,
            "update_ca_trust": False,
        }
        try:
            r = subprocess.run(
                ["which", "update-ca-certificates"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["update_ca_certificates"] = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["which", "update-ca-trust"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["update_ca_trust"] = r.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _check_pam_pkcs11(self) -> dict:
        result: dict = {
            "installed": False,
            "configured": False,
        }
        try:
            r = subprocess.run(
                ["dpkg", "-l", "libpam-pkcs11"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["installed"] = "ii" in r.stdout
        except (OSError, subprocess.SubprocessError):
            pass
        pkcs11_conf = Path("/etc/pam_pkcs11/pam_pkcs11.conf")
        if pkcs11_conf.exists():
            result["configured"] = True
        return result
