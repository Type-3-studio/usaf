from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

CACHE_DIR = Path.home() / ".cache" / "usaf-lab"
IMAGE_URL = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
IMAGE_NAME = "noble-server-cloudimg-amd64.img"
VM_IMAGE_DIR = Path("/var/lib/libvirt/images")
SSH_KEY_PATH = Path.home() / ".ssh" / "usaf-lab-key"
SSH_USER = "ubuntu"
CLOUD_USER_DATA = """#cloud-config
hostname: {hostname}
users:
  - name: {user}
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - {pubkey}
    lock_passwd: true
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - python3
  - python3-pip
  - git
runcmd:
  - systemctl enable --now qemu-guest-agent
"""

CLOUD_META_DATA = """instance-id: {hostname}
local-hostname: {hostname}
"""


class LibvirtProvisioner:
    def __init__(self, scenario_dir: Path, scenario_name: str, lab_root: Path) -> None:
        self.scenario_dir = scenario_dir
        self.scenario_name = scenario_name
        self.vm_name = f"usaf-{scenario_name}"
        self.lab_root = lab_root
        self._vm_ip: str | None = None
        self._check_deps()

    @staticmethod
    def _check_deps() -> None:
        import shutil

        missing = []
        for cmd in ["virsh", "virt-install", "cloud-localds", "qemu-img"]:
            if shutil.which(cmd) is None:
                missing.append(cmd)
        if missing:
            print(
                f"Error: Missing required tools: {', '.join(missing)}\n"
                "Install them with:\n"
                "  sudo apt install qemu-system-x86 libvirt-daemon-system virt-install cloud-image-utils\n"
                "  sudo adduser $USER libvirt",
                file=sys.stderr,
            )
            sys.exit(1)

    def _run(self, cmd: list[str], capture: bool = False, sudo: bool = False, **kwargs: Any) -> subprocess.CompletedProcess:
        if sudo and cmd[0] not in ("sudo",):
            cmd = ["sudo", *cmd]
        print(f"  [+] {' '.join(str(c) for c in cmd)}")
        kw: dict[str, Any] = {}
        if capture:
            kw["capture_output"] = True
        kw.update(kwargs)
        try:
            return subprocess.run(cmd, check=False, **kw)
        except FileNotFoundError as e:
            print(f"  [!] Command not found: {e}", file=sys.stderr)
            result = subprocess.CompletedProcess(cmd, -1)
            return result

    def _ensure_ssh_key(self) -> Path:
        SSH_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not SSH_KEY_PATH.exists():
            self._run(
                [
                    "ssh-keygen", "-t", "ed25519", "-f", str(SSH_KEY_PATH),
                    "-N", "", "-q",
                ]
            )
        return SSH_KEY_PATH

    def _ensure_cloud_image(self) -> Path:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        image_path = CACHE_DIR / IMAGE_NAME
        if not image_path.exists():
            print("  [+] Downloading Ubuntu cloud image (this may take a while)...")
            self._run(
                ["curl", "-fsSL", "-o", str(image_path), IMAGE_URL],
                timeout=300,
            )
        return image_path

    def _get_vm_ip(self) -> str | None:
        result = self._run(
            ["virsh", "domifaddr", self.vm_name, "--source", "lease"],
            capture=True, sudo=True,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.decode().splitlines():
            if "/" in line:
                ip = line.strip().split()[-1]
                return ip.split("/")[0]
        return None

    def _vm_exists(self) -> bool:
        result = self._run(
            ["virsh", "dominfo", self.vm_name],
            capture=True, sudo=True,
        )
        return result.returncode == 0

    def _vm_running(self) -> bool:
        result = self._run(
            ["virsh", "domstate", self.vm_name],
            capture=True, sudo=True,
        )
        return "running" in result.stdout.decode().lower()

    def _create_seed_iso(self) -> Path:
        seed_dir = VM_IMAGE_DIR / "seeds" / self.scenario_name
        self._run(["mkdir", "-p", str(seed_dir)], sudo=True)
        pubkey_path = Path(str(SSH_KEY_PATH) + ".pub")
        pubkey = pubkey_path.read_text().strip()

        user_data = CLOUD_USER_DATA.format(
            hostname=self.vm_name, user=SSH_USER, pubkey=pubkey
        )
        meta_data = CLOUD_META_DATA.format(hostname=self.vm_name)

        ud_path = seed_dir / "user-data"
        md_path = seed_dir / "meta-data"
        iso_path = seed_dir / "seed.iso"

        # Write user-data/meta-data to temp, then sudo cp so libvirt-qemu can read
        tmp_ud = Path("/tmp") / f"usaf-{self.scenario_name}-user-data"
        tmp_md = Path("/tmp") / f"usaf-{self.scenario_name}-meta-data"
        tmp_ud.write_text(user_data)
        tmp_md.write_text(meta_data)
        self._run(["cp", str(tmp_ud), str(ud_path)], sudo=True)
        self._run(["cp", str(tmp_md), str(md_path)], sudo=True)

        self._run(
            [
                "cloud-localds", "-v",
                str(iso_path), str(ud_path), str(md_path),
            ],
            sudo=True,
        )
        return iso_path

    def up(self) -> bool:
        if self._vm_exists():
            if self._vm_running():
                self._vm_ip = self._get_vm_ip()
                if self._vm_ip:
                    return True
            self.destroy()

        self._ensure_ssh_key()
        base_img = self._ensure_cloud_image()
        seed_iso = self._create_seed_iso()

        # Copy base image to libvirt directory so qemu can access it
        libvirt_base = VM_IMAGE_DIR / "noble-server-cloudimg-amd64.img"
        self._run(["cp", str(base_img), str(libvirt_base)], sudo=True)
        self._run(["chmod", "644", str(libvirt_base)], sudo=True)

        vm_disk = VM_IMAGE_DIR / f"{self.vm_name}.qcow2"

        if vm_disk.exists():
            self._run(["rm", "-f", str(vm_disk)], sudo=True)
        self._run(
            [
                "qemu-img", "create", "-F", "qcow2", "-b", str(libvirt_base),
                "-f", "qcow2", str(vm_disk), "20G",
            ],
            sudo=True,
        )

        result = self._run(
            [
                "virt-install",
                "--name", self.vm_name,
                "--ram", "2048",
                "--vcpus", "2",
                "--disk", f"path={vm_disk},format=qcow2",
                "--disk", f"path={seed_iso},device=cdrom",
                "--network", "default",
                "--os-variant", "ubuntu24.04",
                "--graphics", "none",
                "--console", "pty,target_type=serial",
                "--noautoconsole",
                "--import",
            ],
            timeout=120, sudo=True,
        )
        if result.returncode != 0:
            return False

        if not self._wait_for_ready():
            return False
        return self._wait_for_cloud_init()

    def _wait_for_cloud_init(self, timeout: int = 120) -> bool:
        print(f"  [+] Waiting up to {timeout}s for cloud-init to complete...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                result = self.ssh_execute("cloud-init status 2>/dev/null || echo done")
                if "done" in result or "status: done" in result:
                    print("  [+] cloud-init complete")
                    return True
            except RuntimeError:
                pass
            time.sleep(5)
        print("  [!] Timed out waiting for cloud-init", file=sys.stderr)
        return False

    def _wait_for_ready(self, timeout: int = 180) -> bool:
        print(f"  [+] Waiting up to {timeout}s for VM to boot and get IP...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            ip = self._get_vm_ip()
            if ip:
                self._vm_ip = ip
                print(f"  [+] VM IP: {ip}")
                time.sleep(5)
                return True
            time.sleep(3)
        print("  [!] Timed out waiting for VM IP", file=sys.stderr)
        self._run(["virsh", "domifaddr", self.vm_name, "--source", "lease"], capture=True, sudo=True)
        return False

    def _ssh_cmd_prefix(self) -> list[str]:
        return [
            "ssh", "-i", str(SSH_KEY_PATH),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            f"{SSH_USER}@{self._vm_ip}",
        ]

    def ssh_execute(self, command: str) -> str:
        if not self._vm_ip:
            msg = "VM IP not available. Call up() first."
            raise RuntimeError(msg)
        cmd = [*self._ssh_cmd_prefix(), command]
        result = self._run(cmd, capture=True)
        output = result.stdout.decode().strip()
        if result.returncode != 0:
            stderr = result.stderr.decode().strip()
            if stderr:
                output = f"{output}\n{stderr}" if output else stderr
        return output

    def scp_to(self, local_path: str, remote_path: str) -> bool:
        if not self._vm_ip:
            msg = "VM IP not available. Call up() first."
            raise RuntimeError(msg)
        parent = os.path.dirname(remote_path)
        self._run(
            ["ssh", "-i", str(SSH_KEY_PATH),
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             f"{SSH_USER}@{self._vm_ip}", "sudo", "mkdir", "-p", parent, "&&", "sudo", "chown", f"{SSH_USER}:{SSH_USER}", parent],
        )
        result = self._run(
            [
                "scp", "-i", str(SSH_KEY_PATH),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-r", local_path,
                f"{SSH_USER}@{self._vm_ip}:{remote_path}",
            ]
        )
        return result.returncode == 0

    def provision(self) -> bool:
        vuln_src = self.lab_root / "shared" / "vulnerabilities"
        vm_vuln_dir = "/opt/usaf-lab/vulnerabilities"

        self.ssh_execute("sudo mkdir -p /opt/usaf-lab")
        self.ssh_execute("sudo chown ubuntu:ubuntu /opt/usaf-lab")

        ok = self.scp_to(str(vuln_src) + "/", vm_vuln_dir)
        if not ok:
            print("  [!] Failed to upload vulnerability scripts", file=sys.stderr)
            return False

        ok = self.scp_to(str(self.scenario_dir / "provision.sh"), "/opt/usaf-lab/provision.sh")
        if not ok:
            print("  [!] Failed to upload provision.sh", file=sys.stderr)
            return False

        self.ssh_execute("sudo ln -sf /opt/usaf-lab/vulnerabilities /vagrant/shared/vulnerabilities 2>/dev/null || sudo mkdir -p /vagrant/shared && sudo ln -sf /opt/usaf-lab/vulnerabilities /vagrant/shared/vulnerabilities")
        self.ssh_execute("sudo chmod +x /opt/usaf-lab/provision.sh")

        result = self.ssh_execute("sudo bash /opt/usaf-lab/provision.sh 2>&1")
        success = "complete" in result.lower() or result.count("error") < 3
        if not success:
            print(f"  [!] Provision script output (last 500 chars): {result[-500:]}")
        return success

    def destroy(self) -> bool:
        if not self._vm_exists():
            return True
        self._run(["virsh", "destroy", self.vm_name], sudo=True)
        self._run(["virsh", "undefine", self.vm_name, "--nvram"], sudo=True)
        vm_disk = VM_IMAGE_DIR / f"{self.vm_name}.qcow2"
        if vm_disk.exists():
            self._run(["rm", "-f", str(vm_disk)], sudo=True)
        seed_dir = VM_IMAGE_DIR / "seeds" / self.scenario_name
        if seed_dir.exists():
            self._run(["rm", "-rf", str(seed_dir)], sudo=True)
        return True

    def ssh_config(self) -> dict[str, str]:
        return {
            "HostName": self._vm_ip or "",
            "User": SSH_USER,
            "IdentityFile": str(SSH_KEY_PATH),
            "StrictHostKeyChecking": "no",
        }
