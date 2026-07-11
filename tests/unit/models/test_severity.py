from usaf.models.severity import CheckCategory, Confidence, Severity


class TestSeverity:
    def test_score_values(self):
        assert Severity.CRITICAL.score == 10.0
        assert Severity.HIGH.score == 7.5
        assert Severity.MEDIUM.score == 5.0
        assert Severity.LOW.score == 2.5
        assert Severity.INFO.score == 0.0

    def test_level_ordering(self):
        assert Severity.CRITICAL.level > Severity.HIGH.level
        assert Severity.HIGH.level > Severity.MEDIUM.level
        assert Severity.MEDIUM.level > Severity.LOW.level
        assert Severity.LOW.level > Severity.INFO.level

    def test_comparison(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH >= Severity.MEDIUM
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.INFO <= Severity.LOW

    def test_from_score(self):
        assert Severity.from_score(9.5) == Severity.CRITICAL
        assert Severity.from_score(7.0) == Severity.HIGH
        assert Severity.from_score(5.0) == Severity.MEDIUM
        assert Severity.from_score(2.5) == Severity.LOW
        assert Severity.from_score(0.5) == Severity.INFO
        assert Severity.from_score(0.0) == Severity.INFO

    def test_enum_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"


class TestConfidence:
    def test_multiplier(self):
        assert Confidence.HIGH.multiplier == 1.0
        assert Confidence.MEDIUM.multiplier == 0.7
        assert Confidence.LOW.multiplier == 0.4

    def test_level(self):
        assert Confidence.HIGH.level == 3
        assert Confidence.MEDIUM.level == 2
        assert Confidence.LOW.level == 1


class TestCheckCategory:
    def test_values(self):
        assert CheckCategory.SYSTEM.value == "SYSTEM"
        assert CheckCategory.NETWORK.value == "NETWORK"
        assert CheckCategory.USERS.value == "USERS"
        assert CheckCategory.PERMISSIONS.value == "PERMISSIONS"
        assert CheckCategory.COMPROMISE.value == "COMPROMISE"
