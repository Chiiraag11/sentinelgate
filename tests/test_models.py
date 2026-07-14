from sentinelgate.models import Finding, ScanResult, ScannerType, Severity


def test_severity_ordering():
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert max(Severity.LOW, Severity.CRITICAL) == Severity.CRITICAL


def test_fingerprint_stable_across_line_number_drift():
    f1 = Finding(file="a.py", line=10, rule_id="sqli", scanner=ScannerType.SAST)
    f2 = Finding(file="a.py", line=13, rule_id="sqli", scanner=ScannerType.SAST)
    assert f1.fingerprint() == f2.fingerprint()


def test_fingerprint_differs_by_file():
    f1 = Finding(file="a.py", line=10, rule_id="sqli", scanner=ScannerType.SAST)
    f2 = Finding(file="b.py", line=10, rule_id="sqli", scanner=ScannerType.SAST)
    assert f1.fingerprint() != f2.fingerprint()


def test_fingerprint_differs_by_scanner_type():
    f1 = Finding(file="a.py", line=10, rule_id="x", scanner=ScannerType.SAST)
    f2 = Finding(file="a.py", line=10, rule_id="x", scanner=ScannerType.SECRETS)
    assert f1.fingerprint() != f2.fingerprint()


def test_scan_result_worst_severity():
    result = ScanResult(findings=[
        Finding(file="a.py", line=1, severity=Severity.LOW),
        Finding(file="b.py", line=2, severity=Severity.CRITICAL),
        Finding(file="c.py", line=3, severity=Severity.MEDIUM),
    ])
    assert result.worst_severity() == Severity.CRITICAL


def test_scan_result_worst_severity_empty():
    assert ScanResult().worst_severity() is None


def test_by_severity_filters_correctly():
    result = ScanResult(findings=[
        Finding(file="a.py", line=1, severity=Severity.HIGH),
        Finding(file="b.py", line=2, severity=Severity.HIGH),
        Finding(file="c.py", line=3, severity=Severity.LOW),
    ])
    assert len(result.by_severity(Severity.HIGH)) == 2


def test_to_dict_includes_fingerprint_and_string_enums():
    f = Finding(file="a.py", line=1, severity=Severity.HIGH, scanner=ScannerType.SAST)
    d = f.to_dict()
    assert d["severity"] == "high"
    assert d["scanner"] == "sast"
    assert "fingerprint" in d
