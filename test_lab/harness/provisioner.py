from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any


class VagrantProvisioner:
    def __init__(self, scenario_dir: Path, scenario_name: str) -> None:
        self.scenario_dir = scenario_dir
        self.scenario_name = scenario_name
        self._check_vagrant()

    @staticmethod
    def _check_vagrant() -> None:
        try:
            subprocess.run(
                ["vagrant", "--version"],
                capture_output=True,
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            print(
                "Error: Vagrant is not installed.\n"
                "Install it with: sudo apt install vagrant virtualbox",
                file=sys.stderr,
            )
            sys.exit(1)

    def _run_vagrant(
        self, *args: str, capture: bool = False
    ) -> subprocess.CompletedProcess:
        cmd = ["vagrant", *args]
        print(f"  [+] vagrant {' '.join(args)}")
        kwargs: dict[str, Any] = {}
        if capture:
            kwargs["capture_output"] = True
        return subprocess.run(
            cmd,
            cwd=self.scenario_dir,
            check=False,
            **kwargs,
        )

    def up(self) -> bool:
        result = self._run_vagrant("up", "--provision")
        return result.returncode == 0

    def provision(self) -> bool:
        result = self._run_vagrant("provision")
        return result.returncode == 0

    def destroy(self) -> bool:
        result = self._run_vagrant("destroy", "-f")
        return result.returncode == 0

    def ssh_config(self) -> dict[str, str]:
        result = self._run_vagrant("ssh-config", capture=True)
        if result.returncode != 0:
            msg = "Failed to get SSH config"
            raise RuntimeError(msg)
        config: dict[str, str] = {}
        for line in result.stdout.decode().splitlines():
            line = line.strip()
            if line.startswith("Host "):
                continue
            if " " in line:
                key, val = line.split(None, 1)
                config[key] = val.strip()
        return config

    def ssh_execute(self, command: str) -> str:
        result = self._run_vagrant("ssh", "-c", command, capture=True)
        return result.stdout.decode().strip()

    def scp_to(self, local_path: str, remote_path: str) -> bool:
        result = self._run_vagrant("scp", local_path, f"default:{remote_path}")
        return result.returncode == 0
