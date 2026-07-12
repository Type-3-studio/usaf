from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings
from test_lab.scenarios.registry import ScenarioRegistry


@ScenarioRegistry.register
class BackdooredHost(BaseScenario):
    name = "backdoored-host"
    description = "A compromised host with SUID backdoors, cron persistence, LD_PRELOAD injection, rogue systemd services, modified hosts file, and reverse shell process"

    @property
    def expected_findings(self) -> ExpectedFindings:
        return ExpectedFindings(
            scenario=self.name,
            description=self.description,
            minimum_detection_rate=0.85,
            expected_findings=[
                # Permission backdoors
                ExpectedFinding(check_id="PRM-101"),
                ExpectedFinding(check_id="PRM-201"),
                ExpectedFinding(check_id="PRM-301"),
                ExpectedFinding(check_id="PRM-303"),
                ExpectedFinding(check_id="PRM-304"),
                ExpectedFinding(check_id="PRM-308"),
                ExpectedFinding(check_id="PRM-401"),
                # Cron persistence
                ExpectedFinding(check_id="PER-101"),
                ExpectedFinding(check_id="PER-102"),
                # Systemd persistence
                ExpectedFinding(check_id="PER-202"),
                ExpectedFinding(check_id="PER-203"),
                # LD injection
                ExpectedFinding(check_id="PER-401"),
                ExpectedFinding(check_id="PER-402"),
                ExpectedFinding(check_id="PER-403"),
                # Shell init
                ExpectedFinding(check_id="PER-301"),
                ExpectedFinding(check_id="PER-302"),
                # Service checks
                ExpectedFinding(check_id="SVC-101"),
                ExpectedFinding(check_id="SVC-201"),
                ExpectedFinding(check_id="SVC-202"),
                ExpectedFinding(check_id="SVC-301"),
                ExpectedFinding(check_id="SVC-402"),
                ExpectedFinding(check_id="SVC-501"),
                # Filesystem
                ExpectedFinding(check_id="FS-601"),
                ExpectedFinding(check_id="FS-402"),
                # Network
                ExpectedFinding(check_id="NET-302"),
                # Compromise
                ExpectedFinding(check_id="COM-101"),
                ExpectedFinding(check_id="COM-205"),
                ExpectedFinding(check_id="COM-206"),
                ExpectedFinding(check_id="COM-207"),
                ExpectedFinding(check_id="COM-301"),
                ExpectedFinding(check_id="COM-302"),
            ],
            notes="Composite scenario: attacker persistence mechanisms across 12+ check categories",
        )

    def get_vagrantfile_content(self) -> str:
        return """Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"
  config.vm.hostname = "backdoored-host"
  config.vm.network "private_network", type: "dhcp"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "usaf-backdoored-host"
  end

  config.vm.synced_folder "../../shared", "/vagrant/shared"
  config.vm.provision "shell", path: "provision.sh"
end
"""

    def get_provision_commands(self) -> list[str]:
        return [
            "bash /vagrant/shared/vulnerabilities/suid_backdoor.sh",
            "bash /vagrant/shared/vulnerabilities/cron_persistence.sh",
            "bash /vagrant/shared/vulnerabilities/systemd_trojan.sh",
            "bash /vagrant/shared/vulnerabilities/ld_preload_injection.sh",
            "bash /vagrant/shared/vulnerabilities/network_suspicious.sh",
        ]
