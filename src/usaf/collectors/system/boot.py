from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class BootCollector(BaseCollector):
    name = "boot"
    description = "Boot firmware, Secure Boot, kernel lockdown, and GRUB state"

    def _do_collect(self) -> dict:
        return {
            "secure_boot": self._get_secure_boot(),
            "kernel_lockdown": self._get_kernel_lockdown(),
            "efi": self._get_efi_state(),
            "grub": self._get_grub_state(),
            "kernel_images": self._get_kernel_images(),
            "bootloader": self._get_bootloader(),
        }

    def _get_secure_boot(self) -> dict:
        result: dict = {"enabled": None, "setup_mode": None}
        if Path("/sys/kernel/security/secureboot").exists():
            try:
                val = Path("/sys/kernel/security/secureboot").read_text().strip()
                result["enabled"] = val == "1"
            except OSError:
                pass
        try:
            r = subprocess.run(
                ["mokutil", "--sb-state"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            out = r.stdout.strip().lower()
            if "enabled" in out:
                result["enabled"] = True
            elif "disabled" in out:
                result["enabled"] = False
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["sbctl", "status"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["sbctl"] = r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _get_kernel_lockdown(self) -> dict:
        result: dict = {"mode": None, "enabled": False}
        try:
            val = Path("/sys/kernel/security/lockdown").read_text().strip()
            result["mode"] = val
            result["enabled"] = "none" not in val.lower()
        except OSError:
            pass
        return result

    def _get_efi_state(self) -> dict:
        result: dict = {"available": False, "efivars": False, "variables": []}
        if Path("/sys/firmware/efi").is_dir():
            result["available"] = True
        if Path("/sys/firmware/efi/efivars").is_dir():
            result["efivars"] = True
        efi_dir = Path("/boot/efi/EFI")
        if efi_dir.is_dir():
            with contextlib.suppress(OSError):
                result["boot_entries"] = [
                    str(p.relative_to(efi_dir))
                    for p in efi_dir.rglob("*.efi")
                ]
        return result

    def _get_grub_state(self) -> dict:
        result: dict = {
            "installed": False,
            "password_protected": None,
            "cfg_path": None,
            "cfg_readable": False,
        }
        grub_cfg = Path("/boot/grub/grub.cfg")
        grub_cfg2 = Path("/boot/grub2/grub.cfg")
        cfg = grub_cfg if grub_cfg.exists() else grub_cfg2 if grub_cfg2.exists() else None
        if cfg:
            result["cfg_path"] = str(cfg)
            result["installed"] = True
            try:
                content = cfg.read_text()
                result["cfg_readable"] = True
                result["password_protected"] = "password" in content.lower() or "superusers" in content.lower()
            except PermissionError:
                result["cfg_readable"] = True
            except OSError:
                pass
        return result

    def _get_kernel_images(self) -> dict:
        result: dict = {"images": []}
        boot = Path("/boot")
        if boot.is_dir():
            try:
                for f in boot.iterdir():
                    if f.name.startswith("vmlinuz-"):
                        result["images"].append({
                            "name": f.name,
                            "path": str(f),
                            "modified": f.stat().st_mtime if f.exists() else None,
                        })
            except OSError:
                pass
        return result

    def _get_bootloader(self) -> dict:
        result: dict = {"type": None, "entries": []}
        loader = Path("/boot/loader/entries")
        if loader.is_dir():
            result["type"] = "systemd-boot"
            with contextlib.suppress(OSError):
                result["entries"] = [str(p) for p in loader.glob("*.conf")]
        return result
