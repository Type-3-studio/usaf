from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings


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
                ExpectedFinding(check_id="PRM-101"),
                ExpectedFinding(check_id="PRM-201"),
                ExpectedFinding(check_id="PRM-301"),
                ExpectedFinding(check_id="PRM-303"),
                ExpectedFinding(check_id="PRM-304"),
                ExpectedFinding(check_id="PRM-308"),
                ExpectedFinding(check_id="PRM-401"),
                ExpectedFinding(check_id="PER-101"),
                ExpectedFinding(check_id="PER-102"),
                ExpectedFinding(check_id="PER-202"),
                ExpectedFinding(check_id="PER-203"),
                ExpectedFinding(check_id="PER-401"),
                ExpectedFinding(check_id="PER-402"),
                ExpectedFinding(check_id="PER-403"),
                ExpectedFinding(check_id="PER-301"),
                ExpectedFinding(check_id="PER-302"),
                ExpectedFinding(check_id="SVC-101"),
                ExpectedFinding(check_id="SVC-201"),
                ExpectedFinding(check_id="SVC-202"),
                ExpectedFinding(check_id="SVC-301"),
                ExpectedFinding(check_id="SVC-402"),
                ExpectedFinding(check_id="SVC-501"),
                ExpectedFinding(check_id="FS-601"),
                ExpectedFinding(check_id="FS-402"),
                ExpectedFinding(check_id="NET-302"),
                ExpectedFinding(check_id="COM-101"),
                ExpectedFinding(check_id="COM-205"),
                ExpectedFinding(check_id="COM-206"),
                ExpectedFinding(check_id="COM-207"),
                ExpectedFinding(check_id="COM-301"),
                ExpectedFinding(check_id="COM-302"),
            ],
            notes="Composite scenario: attacker persistence mechanisms across 12+ check categories",
        )
