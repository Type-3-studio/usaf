from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings


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
