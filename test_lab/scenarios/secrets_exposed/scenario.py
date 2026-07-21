from __future__ import annotations

from test_lab.scenarios.base import BaseScenario, ExpectedFinding, ExpectedFindings


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
