from sentinelgate.models import Finding, ScannerType, Severity
from sentinelgate.normalizer import deduplicate


def test_collapses_same_file_same_category_nearby_lines():
    findings = [
        Finding(file="a.py", line=10, rule_id="semgrep.sqli", owasp_category="A03:2021 - Injection",
                scanner=ScannerType.SAST, severity=Severity.HIGH),
        Finding(file="a.py", line=11, rule_id="other-tool.sql-injection", owasp_category="A03:2021 - Injection",
                scanner=ScannerType.SAST, severity=Severity.MEDIUM),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    # keeps the higher-severity copy
    assert result[0].severity == Severity.HIGH


def test_does_not_collapse_different_files():
    findings = [
        Finding(file="a.py", line=10, owasp_category="A03:2021 - Injection", scanner=ScannerType.SAST),
        Finding(file="b.py", line=10, owasp_category="A03:2021 - Injection", scanner=ScannerType.SAST),
    ]
    assert len(deduplicate(findings)) == 2


def test_does_not_collapse_across_scanner_types():
    findings = [
        Finding(file="a.py", line=10, owasp_category="A02:2021 - Cryptographic Failures", scanner=ScannerType.SAST),
        Finding(file="a.py", line=10, owasp_category="A02:2021 - Cryptographic Failures", scanner=ScannerType.SECRETS),
    ]
    assert len(deduplicate(findings)) == 2


def test_dependency_findings_dedup_by_package_and_rule():
    findings = [
        Finding(file="requirements.txt", line=0, package="requests", rule_id="CVE-1",
                scanner=ScannerType.DEPENDENCY, severity=Severity.HIGH),
        Finding(file="requirements.txt", line=0, package="requests", rule_id="CVE-1",
                scanner=ScannerType.DEPENDENCY, severity=Severity.HIGH, fix_suggestion="upgrade"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1


def test_different_packages_not_deduped():
    findings = [
        Finding(file="requirements.txt", line=0, package="requests", rule_id="CVE-1", scanner=ScannerType.DEPENDENCY),
        Finding(file="requirements.txt", line=0, package="flask", rule_id="CVE-2", scanner=ScannerType.DEPENDENCY),
    ]
    assert len(deduplicate(findings)) == 2


def test_secret_dedup_by_line_and_type():
    findings = [
        Finding(file="a.py", line=5, secret_type="AWS Access Key", scanner=ScannerType.SECRETS),
        Finding(file="a.py", line=5, secret_type="AWS Access Key", scanner=ScannerType.SECRETS),
    ]
    assert len(deduplicate(findings)) == 1


def test_merges_fix_suggestion_into_surviving_duplicate():
    findings = [
        Finding(file="a.py", line=10, owasp_category="A03", scanner=ScannerType.SAST,
                severity=Severity.HIGH, fix_suggestion=""),
        Finding(file="a.py", line=10, owasp_category="A03", scanner=ScannerType.SAST,
                severity=Severity.MEDIUM, fix_suggestion="use parameterized queries"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0].fix_suggestion == "use parameterized queries"
