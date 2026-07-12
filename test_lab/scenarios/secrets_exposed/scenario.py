from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings
from test_lab.scenarios.registry import ScenarioRegistry


@ScenarioRegistry.register
class SecretsExposed(BaseScenario):
    name = "secrets-exposed"
    description = "A host with cloud credentials, API tokens, SSH keys, database credentials, and secrets in source code"

    @property
    def expected_findings(self) -> ExpectedFindings:
        return ExpectedFindings(
            scenario=self.name,
            description=self.description,
            minimum_detection_rate=0.85,
            expected_findings=[
                ExpectedFinding(check_id="SECR-101"),
                ExpectedFinding(check_id="SECR-102"),
                ExpectedFinding(check_id="SECR-201"),
                ExpectedFinding(check_id="SECR-202"),
                ExpectedFinding(check_id="SECR-203"),
                ExpectedFinding(check_id="SECR-301"),
                ExpectedFinding(check_id="SECR-302"),
                ExpectedFinding(check_id="SECR-401"),
                ExpectedFinding(check_id="SECR-601"),
                ExpectedFinding(check_id="SECR-602"),
                ExpectedFinding(check_id="SECR-605"),
                ExpectedFinding(check_id="SECR-608"),
            ],
            notes="Credential exposure scenario covering all SECR check categories",
        )

    def get_vagrantfile_content(self) -> str:
        return """Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "secrets-exposed"
  config.vm.network "private_network", type: "dhcp"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
    vb.cpus = 1
    vb.name = "usaf-secrets-exposed"
  end
  config.vm.synced_folder "../../shared", "/vagrant/shared"
  config.vm.provision "shell", path: "provision.sh"
end
"""

    def get_provision_commands(self) -> list[str]:
        return ["bash /vagrant/shared/vulnerabilities/secret_injection.sh"]
