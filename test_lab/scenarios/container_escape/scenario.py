from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings
from test_lab.scenarios.registry import ScenarioRegistry


@ScenarioRegistry.register
class ContainerEscape(BaseScenario):
    name = "container-escape"
    description = "A Docker host with exposed socket, privileged containers, host namespace sharing, and old unsigned images"

    @property
    def expected_findings(self) -> ExpectedFindings:
        return ExpectedFindings(
            scenario=self.name,
            description=self.description,
            minimum_detection_rate=0.85,
            expected_findings=[
                ExpectedFinding(check_id="CTN-101"),
                ExpectedFinding(check_id="CTN-102"),
                ExpectedFinding(check_id="CTN-201"),
                ExpectedFinding(check_id="CTN-202"),
                ExpectedFinding(check_id="CTN-203"),
                ExpectedFinding(check_id="CTN-204"),
                ExpectedFinding(check_id="CTN-301"),
                ExpectedFinding(check_id="CTN-303"),
                ExpectedFinding(check_id="CTN-305"),
                ExpectedFinding(check_id="CTN-306"),
                ExpectedFinding(check_id="CTN-401"),
                ExpectedFinding(check_id="CTN-501"),
                ExpectedFinding(check_id="CTN-701"),
                ExpectedFinding(check_id="CTN-703"),
                ExpectedFinding(check_id="CTN-706"),
                ExpectedFinding(check_id="SVC-201"),
                ExpectedFinding(check_id="PRM-201"),
                ExpectedFinding(check_id="FS-601"),
            ],
            notes="Docker container escape scenario covering all CTN checks",
        )

    def get_vagrantfile_content(self) -> str:
        return """Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "container-escape"
  config.vm.network "private_network", type: "dhcp"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
    vb.cpus = 2
    vb.name = "usaf-container-escape"
  end
  config.vm.synced_folder "../../shared", "/vagrant/shared"
  config.vm.provision "shell", path: "provision.sh"
end
"""

    def get_provision_commands(self) -> list[str]:
        return ["bash /vagrant/shared/vulnerabilities/docker_exposure.sh"]
