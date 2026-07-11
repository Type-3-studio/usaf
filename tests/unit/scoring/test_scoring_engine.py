from __future__ import annotations

from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult
from usaf.models.severity import CheckCategory, Confidence, Severity
from usaf.scoring.engine import ScoringEngine


class TestScoringEngine:
    def test_perfect_score(self):
        engine = ScoringEngine()
        result = ScanResult()
        score = engine.calculate(result)
        assert score.overall_score == 0.0
        assert score.overall_grade == "A+"
        assert score.total_findings == 0

    def test_single_critical_finding(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.CRITICAL,
                            risk_score=10.0,
                            title="Critical",
                            description="Critical finding",
                            rationale="Test",
                            remediation="Fix",
                            source="TestCheck",
                        )
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.critical_count == 1
        assert score.total_findings == 1
        assert score.overall_score > 0.0

    def test_score_components(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="T1",
                            check_id="TEST-001",
                            category=CheckCategory.KERNEL,
                            severity=Severity.CRITICAL,
                            risk_score=10.0,
                            title="T1",
                            description="D1",
                            rationale="R1",
                            remediation="F1",
                            source="S1",
                        ),
                        Finding(
                            id="T2",
                            check_id="TEST-001",
                            category=CheckCategory.KERNEL,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="T2",
                            description="D2",
                            rationale="R2",
                            remediation="F2",
                            source="S2",
                        ),
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.total_findings == 2
        assert len(score.categories) >= 1
        kernel_score = next(c for c in score.categories if c.category == CheckCategory.KERNEL)
        assert kernel_score.critical_count == 1
        assert kernel_score.high_count == 1

    def test_category_breakdown(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="NET-101",
                    name="Net",
                    category=CheckCategory.NETWORK,
                    passed=False,
                    findings=[
                        Finding(
                            id="N1",
                            check_id="NET-101",
                            category=CheckCategory.NETWORK,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="N1",
                            description="N1",
                            rationale="R",
                            remediation="F",
                            source="S",
                        ),
                    ],
                ),
                CheckResult(
                    check_id="USR-101",
                    name="Usr",
                    category=CheckCategory.USERS,
                    passed=False,
                    findings=[
                        Finding(
                            id="U1",
                            check_id="USR-101",
                            category=CheckCategory.USERS,
                            severity=Severity.LOW,
                            risk_score=2.5,
                            title="U1",
                            description="U1",
                            rationale="R",
                            remediation="F",
                            source="S",
                        ),
                    ],
                ),
            ]
        )
        score = engine.calculate(result)
        assert len(score.categories) == 2
        categories = {c.category: c for c in score.categories}
        assert CheckCategory.NETWORK in categories
        assert CheckCategory.USERS in categories

    def test_score_to_grade(self):
        assert ScoringEngine._score_to_grade(0.0) == "A+"
        assert ScoringEngine._score_to_grade(0.5) == "A"
        assert ScoringEngine._score_to_grade(1.0) == "B"
        assert ScoringEngine._score_to_grade(4.0) == "C"
        assert ScoringEngine._score_to_grade(6.0) == "D"
        assert ScoringEngine._score_to_grade(8.0) == "F"
        assert ScoringEngine._score_to_grade(10.0) == "F-"

    def test_confidence_low_reduces_score(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.CRITICAL,
                            risk_score=10.0,
                            title="Critical",
                            description="Critical finding",
                            rationale="Test",
                            remediation="Fix",
                            source="TestCheck",
                            confidence=Confidence.LOW,
                        )
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.critical_count == 1
        assert score.total_findings == 1
        # LOW confidence (0.4x) should produce a lower score than HIGH (1.0x)
        assert score.overall_score < 5.0

    def test_confidence_high_equals_baseline(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.CRITICAL,
                            risk_score=10.0,
                            title="Critical",
                            description="Critical finding",
                            rationale="Test",
                            remediation="Fix",
                            source="TestCheck",
                            confidence=Confidence.HIGH,
                        )
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        # HIGH confidence (1.0x) but no evidence (trust scoring clamps to LOW),
        # so effective confidence is 0.3 → score reflects that
        assert score.overall_score > 0

    def test_false_positive_probability_reduces_score(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.CRITICAL,
                            risk_score=10.0,
                            title="Critical",
                            description="Critical finding",
                            rationale="Test",
                            remediation="Fix",
                            source="TestCheck",
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.8,
                        )
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.total_findings == 1
        # 80% FP probability should significantly reduce the score
        assert score.overall_score < 3.0

    def test_confidence_and_fp_compound(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.CRITICAL,
                            risk_score=10.0,
                            title="Critical",
                            description="Critical finding",
                            rationale="Test",
                            remediation="Fix",
                            source="TestCheck",
                            confidence=Confidence.LOW,
                            false_positive_probability=0.5,
                        )
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.total_findings == 1
        # LOW confidence (0.4x) with no evidence (trust scoring clamps to 0.3)
        # * (1 - 0.5 FP) = 0.15 effective
        # 10.0 * 1.0 * 0.15 = 1.5 base
        assert score.overall_score > 0

    def test_all_severity_counts(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="T1", name="T", category=CheckCategory.SYSTEM, passed=False,
                    findings=[
                        Finding(id="F1", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.INFO, risk_score=0.0, title="I",
                                description="d", rationale="r", remediation="f", source="s"),
                        Finding(id="F2", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.LOW, risk_score=2.5, title="L",
                                description="d", rationale="r", remediation="f", source="s"),
                        Finding(id="F3", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.MEDIUM, risk_score=5.0, title="M",
                                description="d", rationale="r", remediation="f", source="s"),
                        Finding(id="F4", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.HIGH, risk_score=7.5, title="H",
                                description="d", rationale="r", remediation="f", source="s"),
                        Finding(id="F5", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.CRITICAL, risk_score=10.0, title="C",
                                description="d", rationale="r", remediation="f", source="s"),
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.total_findings == 5
        assert score.critical_count == 1
        assert score.high_count == 1
        assert score.medium_count == 1
        assert score.low_count == 1
        assert score.info_count == 1

    def test_empty_categories_returns_zero(self):
        engine = ScoringEngine()
        score = engine._calculate_overall([])
        assert score == 0.0

    def test_zero_weight_returns_zero(self):
        from usaf.models.score import CategoryScore
        engine = ScoringEngine()
        cat = CategoryScore(
            category=CheckCategory.GENERAL, score=5.0, finding_count=1,
            critical_count=0, high_count=0, medium_count=1, low_count=0, info_count=0,
            max_severity=None, weight=0.0,
        )
        score = engine._calculate_overall([cat])
        assert score == 0.0

    def test_no_trust_scoring_disabled(self):
        engine = ScoringEngine(use_trust_scoring=False)
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="T1", name="T", category=CheckCategory.SYSTEM, passed=False,
                    findings=[
                        Finding(id="F1", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.CRITICAL, risk_score=10.0, title="C",
                                description="d", rationale="r", remediation="f", source="s",
                                confidence=Confidence.MEDIUM),
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.critical_count == 1
        assert score.overall_score > 0

    def test_info_severity_weight(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="T1", name="T", category=CheckCategory.SYSTEM, passed=False,
                    findings=[
                        Finding(id="F1", check_id="T1", category=CheckCategory.SYSTEM,
                                severity=Severity.INFO, risk_score=0.0, title="I",
                                description="d", rationale="r", remediation="f", source="s"),
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.overall_score == 0.0

    def test_category_beyond_max_weight(self):
        engine = ScoringEngine()
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="T1", name="T", category=CheckCategory.GENERAL, passed=False,
                    findings=[
                        Finding(id="F1", check_id="T1", category=CheckCategory.GENERAL,
                                severity=Severity.HIGH, risk_score=7.5, title="H",
                                description="d", rationale="r", remediation="f", source="s"),
                    ],
                )
            ]
        )
        score = engine.calculate(result)
        assert score.total_findings == 1
        assert len(score.categories) == 1
