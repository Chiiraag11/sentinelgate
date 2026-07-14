from sentinelgate.models import Finding, ScannerType, Severity
from sentinelgate.scoring import score, should_fail_build


def test_higher_severity_scores_higher():
    low = Finding(file="a.py", line=1, severity=Severity.LOW, rule_id="x")
    crit = Finding(file="a.py", line=1, severity=Severity.CRITICAL, rule_id="x")
    assert score(crit) > score(low)


def test_sqli_gets_exploitability_bump():
    generic = Finding(file="a.py", line=1, severity=Severity.HIGH, rule_id="generic.rule")
    sqli = Finding(file="a.py", line=1, severity=Severity.HIGH, rule_id="python.sql-injection.rule")
    assert score(sqli) > score(generic)


def test_secrets_get_bump_over_equivalent_sast():
    sast = Finding(file="a.py", line=1, severity=Severity.HIGH, rule_id="x", scanner=ScannerType.SAST)
    secret = Finding(file="a.py", line=1, severity=Severity.HIGH, rule_id="x", scanner=ScannerType.SECRETS)
    assert score(secret) > score(sast)


def test_dependency_without_fix_scores_lower():
    with_fix = Finding(file="req.txt", line=0, severity=Severity.HIGH, rule_id="x",
                        scanner=ScannerType.DEPENDENCY, fixed_version="2.0.0")
    without_fix = Finding(file="req.txt", line=0, severity=Severity.HIGH, rule_id="x",
                           scanner=ScannerType.DEPENDENCY, fixed_version=None)
    assert score(with_fix) > score(without_fix)


def test_score_clamped_between_0_and_100():
    f = Finding(file="a.py", line=1, severity=Severity.CRITICAL, rule_id="sql-injection",
                scanner=ScannerType.SECRETS)
    assert 0 <= score(f) <= 100


class TestShouldFailBuild:
    def test_fails_on_new_high_severity(self):
        findings = [Finding(file="a.py", line=1, severity=Severity.HIGH, is_new=True)]
        assert should_fail_build(findings, threshold=Severity.HIGH) is True

    def test_passes_when_only_preexisting_findings(self):
        findings = [Finding(file="a.py", line=1, severity=Severity.CRITICAL, is_new=False)]
        assert should_fail_build(findings, threshold=Severity.HIGH) is False

    def test_passes_when_below_threshold(self):
        findings = [Finding(file="a.py", line=1, severity=Severity.MEDIUM, is_new=True)]
        assert should_fail_build(findings, threshold=Severity.HIGH) is False

    def test_passes_on_empty_findings(self):
        assert should_fail_build([], threshold=Severity.HIGH) is False

    def test_custom_threshold_critical_ignores_high(self):
        findings = [Finding(file="a.py", line=1, severity=Severity.HIGH, is_new=True)]
        assert should_fail_build(findings, threshold=Severity.CRITICAL) is False
