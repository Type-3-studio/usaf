from __future__ import annotations

from pathlib import Path

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings
from test_lab.scenarios.registry import ScenarioRegistry


@ScenarioRegistry.register
class InsecureServer(BaseScenario):
    name = "insecure-server"
    description = "A poorly configured Ubuntu server with weak SSH, no firewall, weak kernel parameters, open ports, and weak user policies"

    @property
    def expected_findings(self) -> ExpectedFindings:
        return ExpectedFindings(
            scenario=self.name,
            description=self.description,
            minimum_detection_rate=0.85,
            expected_findings=[
                # SSH vulnerabilities
                ExpectedFinding(check_id="SSH-101", severity="HIGH"),
                ExpectedFinding(check_id="SSH-102", severity="HIGH"),
                ExpectedFinding(check_id="SSH-103", severity="HIGH"),
                ExpectedFinding(check_id="SSH-104", severity="CRITICAL"),
                ExpectedFinding(check_id="SSH-105", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-107", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-201", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-202", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-501", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-601", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-603", severity="MEDIUM"),
                ExpectedFinding(check_id="SSH-604", severity="HIGH"),
                # Kernel vulnerabilities
                ExpectedFinding(check_id="KERN-101", severity="HIGH"),
                ExpectedFinding(check_id="KERN-201", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-301", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-451", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-511", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-552", severity="MEDIUM"),
                # Firewall vulnerabilities
                ExpectedFinding(check_id="FW-101", severity="HIGH"),
                ExpectedFinding(check_id="FW-201", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-202", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-203", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-205", severity="LOW"),
                # Network vulnerabilities
                ExpectedFinding(check_id="NET-101", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-301", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-302", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-401", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-402", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-201", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-203", severity="MEDIUM"),
                # User vulnerabilities
                ExpectedFinding(check_id="USR-101", severity="CRITICAL"),
                ExpectedFinding(check_id="USR-103", severity="HIGH"),
                ExpectedFinding(check_id="USR-104", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-105", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-201", severity="CRITICAL"),
                ExpectedFinding(check_id="USR-402", severity="HIGH"),
                ExpectedFinding(check_id="USR-403", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-501", severity="MEDIUM"),
                # Password vulnerabilities
                ExpectedFinding(check_id="PWD-101", severity="HIGH"),
                ExpectedFinding(check_id="PWD-202", severity="MEDIUM"),
                ExpectedFinding(check_id="PWD-203", severity="HIGH"),
                ExpectedFinding(check_id="PWD-204", severity="LOW"),
                # Permission vulnerabilities
                ExpectedFinding(check_id="PRM-201", severity="HIGH"),
                ExpectedFinding(check_id="PRM-304", severity="CRITICAL"),
                # Filesystem vulnerabilities
                ExpectedFinding(check_id="FS-601", severity="HIGH"),
                ExpectedFinding(check_id="FS-402", severity="MEDIUM"),
                # Services
                ExpectedFinding(check_id="SVC-201", severity="MEDIUM"),
                # Boot
                ExpectedFinding(check_id="BOOT-607", severity="MEDIUM"),
            ],
            notes="Composite scenario: LAMP-like server with 15+ categories of vulnerabilities",
        )

    def get_vagrantfile_content(self) -> str:
        return """Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "insecure-server"
  config.vm.network "private_network", type: "dhcp"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "usaf-insecure-server"
  end

  config.vm.provision "shell", path: "provision.sh"
end
"""

    def get_provision_commands(self) -> list[str]:
        base_dir = "/vagrant/shared/vulnerabilities"
        return [
            f"bash {base_dir}/ssh_misconfig.sh",
            f"bash {base_dir}/kernel_weak_params.sh",
            f"bash {base_dir}/user_misconfigs.sh",
            f"bash {base_dir}/firewall_off.sh",
            f"bash {base_dir}/network_suspicious.sh",
            f"bash {base_dir}/suid_backdoor.sh",
            f"bash {base_dir}/ld_preload_injection.sh",
            f"bash {base_dir}/cron_persistence.sh",
            f"bash {base_dir}/systemd_trojan.sh",
        ]
