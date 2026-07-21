from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings


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
