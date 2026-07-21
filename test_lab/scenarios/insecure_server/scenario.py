from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings


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
                ExpectedFinding(check_id="KERN-101", severity="HIGH"),
                ExpectedFinding(check_id="KERN-201", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-301", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-451", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-511", severity="MEDIUM"),
                ExpectedFinding(check_id="KERN-552", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-101", severity="HIGH"),
                ExpectedFinding(check_id="FW-201", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-202", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-203", severity="MEDIUM"),
                ExpectedFinding(check_id="FW-205", severity="LOW"),
                ExpectedFinding(check_id="NET-101", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-301", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-302", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-401", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-402", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-201", severity="MEDIUM"),
                ExpectedFinding(check_id="NET-203", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-101", severity="CRITICAL"),
                ExpectedFinding(check_id="USR-103", severity="HIGH"),
                ExpectedFinding(check_id="USR-104", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-105", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-201", severity="CRITICAL"),
                ExpectedFinding(check_id="USR-402", severity="HIGH"),
                ExpectedFinding(check_id="USR-403", severity="MEDIUM"),
                ExpectedFinding(check_id="USR-501", severity="MEDIUM"),
                ExpectedFinding(check_id="PWD-101", severity="HIGH"),
                ExpectedFinding(check_id="PWD-202", severity="MEDIUM"),
                ExpectedFinding(check_id="PWD-203", severity="HIGH"),
                ExpectedFinding(check_id="PWD-204", severity="LOW"),
                ExpectedFinding(check_id="PRM-201", severity="HIGH"),
                ExpectedFinding(check_id="PRM-304", severity="CRITICAL"),
                ExpectedFinding(check_id="FS-601", severity="HIGH"),
                ExpectedFinding(check_id="FS-402", severity="MEDIUM"),
                ExpectedFinding(check_id="SVC-201", severity="MEDIUM"),
                ExpectedFinding(check_id="BOOT-607", severity="MEDIUM"),
            ],
            notes="Composite scenario: LAMP-like server with 15+ categories of vulnerabilities",
        )
