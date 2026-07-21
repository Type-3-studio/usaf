from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from test_lab.harness.provisioner import LibvirtProvisioner


class USAFRunner:
    def __init__(self, provisioner: LibvirtProvisioner) -> None:
        self.provisioner = provisioner

    def install_usaf(self) -> bool:
        steps = [
            ("Update apt cache", "sudo apt-get update -qq"),
            ("Install python3-pip and git", "sudo apt-get install -y -qq python3-pip git"),
            ("Clone USAF repo",
             "rm -rf /tmp/usaf && git clone --depth 1 https://github.com/Type-3-studio/usaf.git /tmp/usaf"),
            ("Install USAF",
             "cd /tmp/usaf && sudo pip3 install --break-system-packages -e ."),
        ]
        for label, cmd in steps:
            out = self.provisioner.ssh_execute(cmd)
            if "Traceback" in out or "error: " in out.lower().split("\n")[0]:
                print(f"  [!] {label} failed")
                for line in out.splitlines()[:5]:
                    print(f"      {line[:150]}")
                return False
        print("  [+] USAF installed on VM")
        return True

    def run_scan(self, checks: list[str] | None = None) -> dict[str, Any]:
        check_filter = " ".join(checks) if checks else ""
        cmd = (
            f"sudo python3 -m usaf.cli.app scan --format json --no-progress {check_filter} 2>&1"
        )
        raw = self.provisioner.ssh_execute(cmd)

        if not raw or raw.isspace():
            print("  [!] Scan returned empty output")
            return {"results": []}

        data = self._try_parse_json(raw)
        if data:
            return data

        print("  [!] Could not parse JSON (first 500 chars):")
        print(f"      {raw[:500]}", file=sys.stderr)
        return {"results": []}

    @staticmethod
    def _try_parse_json(raw: str) -> dict[str, Any] | None:
        json_match = re.search(r'\{.*\}', raw, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _fetch_report(self, report_path: str = "/tmp/usaf-scan-report.json") -> dict[str, Any] | None:
        with tempfile.TemporaryDirectory() as tmp:
            dest_dir = Path(tmp)
            try:
                self.provisioner.scp_to(str(dest_dir) + "/", report_path)
                for f in dest_dir.iterdir():
                    with open(f) as fh:
                        return json.load(fh)
            except Exception:
                pass
        return None

    def get_findings(self, scan_result: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for result in scan_result.get("results", []):
            for finding in result.get("findings", []):
                finding["_check_id"] = result.get("check_id", "UNKNOWN")
                findings.append(finding)
        return findings
