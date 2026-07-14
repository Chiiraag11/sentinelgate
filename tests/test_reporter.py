from sentinelgate.models import Finding, ScanResult, ScannerType, Severity
from sentinelgate.reporter import MARKER, format_markdown


def test_clean_scan_reports_no_findings():
    result = ScanResult(findings=[], scanners_run=["semgrep", "detect-secrets"])
    md = format_markdown(result)
    assert "No security findings" in md
    assert MARKER in md


def test_blocking_finding_shows_gate_failed():
    result = ScanResult(
        findings=[Finding(file="a.py", line=1, severity=Severity.CRITICAL, is_new=True,
                           owasp_category="A03:2021 - Injection", title="SQL Injection")],
        scanners_run=["semgrep"],
    )
    md = format_markdown(result, fail_on=Severity.HIGH)
    assert "Gate failed" in md
    assert "SQL Injection" in md


def test_only_preexisting_findings_pass_gate():
    result = ScanResult(
        findings=[Finding(file="a.py", line=1, severity=Severity.CRITICAL, is_new=False,
                           owasp_category="A03:2021 - Injection", title="Old issue")],
        scanners_run=["semgrep"],
    )
    md = format_markdown(result, fail_on=Severity.HIGH)
    assert "Gate passed" in md
    assert "pre-existing finding" in md


def test_findings_grouped_by_owasp_category():
    result = ScanResult(
        findings=[
            Finding(file="a.py", line=1, severity=Severity.HIGH, owasp_category="A03:2021 - Injection",
                    title="SQLi", is_new=True),
            Finding(file="b.py", line=2, severity=Severity.HIGH, owasp_category="A02:2021 - Cryptographic Failures",
                    title="Hardcoded key", is_new=True),
        ],
        scanners_run=["semgrep"],
    )
    md = format_markdown(result)
    assert "A03:2021 - Injection" in md
    assert "A02:2021 - Cryptographic Failures" in md


def test_failed_scanners_surfaced_in_report():
    result = ScanResult(findings=[], scanners_run=["semgrep"], scanners_failed=["pip-audit"])
    md = format_markdown(result)
    assert "pip-audit" in md
    assert "failed to run" in md


def test_fix_suggestion_included_when_present():
    result = ScanResult(
        findings=[Finding(file="a.py", line=1, severity=Severity.HIGH, owasp_category="A03:2021 - Injection",
                           title="SQLi", is_new=True, fix_suggestion="Use parameterized queries.")],
        scanners_run=["semgrep"],
    )
    md = format_markdown(result)
    assert "Use parameterized queries." in md
