from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings
from test_lab.scenarios.registry import ScenarioRegistry


@ScenarioRegistry.register
class DesktopInsecure(BaseScenario):
    name = "desktop-insecure"
    description = "A desktop workstation with legacy services, weak authentication, world-writable PATH, no firewall, and unsecured X11"

    @property
    def expected_findings(self) -> ExpectedFindings:
        return ExpectedFindings(
            scenario=self.name,
            description=self.description,
            minimum_detection_rate=0.80,
            expected_findings=[
                ExpectedFinding(check_id="CMP-101"),
                ExpectedFinding(check_id="CMP-201"),
                ExpectedFinding(check_id="CMP-202"),
                ExpectedFinding(check_id="CMP-203"),
                ExpectedFinding(check_id="CMP-204"),
                ExpectedFinding(check_id="CMP-206"),
                ExpectedFinding(check_id="CMP-210"),
                ExpectedFinding(check_id="PWD-101"),
                ExpectedFinding(check_id="PWD-203"),
                ExpectedFinding(check_id="FW-101"),
                ExpectedFinding(check_id="FW-201"),
                ExpectedFinding(check_id="PRM-201"),
                ExpectedFinding(check_id="PRM-303"),
                ExpectedFinding(check_id="PRM-304"),
                ExpectedFinding(check_id="FS-402"),
                ExpectedFinding(check_id="SVC-102"),
                ExpectedFinding(check_id="SVC-201"),
                ExpectedFinding(check_id="NET-101"),
                ExpectedFinding(check_id="NET-301"),
                ExpectedFinding(check_id="USR-501"),
            ],
            notes="Desktop workstation scenario targeting CMP and PWD check categories",
        )

    def get_vagrantfile_content(self) -> str:
        return """Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "desktop-insecure"
  config.vm.network "private_network", type: "dhcp"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "usaf-desktop-insecure"
  end
  config.vm.synced_folder "../../shared", "/vagrant/shared"
  config.vm.provision "shell", path: "provision.sh"
end
"""

    def get_provision_commands(self) -> list[str]:
        return [
            "bash /vagrant/shared/vulnerabilities/ssh_misconfig.sh",
            "bash /vagrant/shared/vulnerabilities/user_misconfigs.sh",
            "bash /vagrant/shared/vulnerabilities/firewall_off.sh",
        ]
