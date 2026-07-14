from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from test_lab.harness.provisioner import VagrantProvisioner


class USAFRunner:
    def __init__(self, provisioner: VagrantProvisioner) -> None:
        self.provisioner = provisioner

    def install_usaf(self) -> bool:
        commands = [
            "sudo apt-get update -qq",
            "sudo apt-get install -y -qq python3-pip git",
            "sudo pip3 install --break-system-packages typer rich pydantic pyyaml requests packaging",
            "cd /tmp && git clone --depth 1 https://github.com/Type-3-studio/usaf.git 2>/dev/null || (cd /tmp/usaf && git pull)",
            "cd /tmp/usaf && sudo pip3 install --break-system-packages -e .",
        ]
        for cmd in commands:
            result = self.provisioner.ssh_execute(cmd)
            if "Error" in result or "error:" in result.lower():
                print(f"  [!] Install step failed: {cmd[:60]}...")
                return False
        print("  [+] USAF installed on VM")
        return True

    def run_scan(self, checks: list[str] | None = None) -> dict[str, Any]:
        check_filter = " ".join(checks) if checks else ""
        cmd = f"usaf scan --format json {check_filter}"
        raw = self.provisioner.ssh_execute(cmd)

        # Parse the JSON report from stdout
        try:
            data = json.loads(raw)
            return data
        except json.JSONDecodeError:
            # The report might be in a file
            result = self._fetch_report()
            if result:
                return result
            print(f"  [!] Failed to parse scan output: {raw[:200]}", file=sys.stderr)
            return {"results": []}

    def _fetch_report(self) -> dict[str, Any] | None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            try:
                self.provisioner.scp_to(
                    str(report_path), "/home/vagrant/reports/*.json"
                )
                if report_path.exists():
                    with open(report_path) as f:
                        return json.load(f)
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
