from sentinelgate.mapper import map_finding


def test_rule_id_hint_takes_precedence_over_cwe():
    # Even if a bogus/conflicting CWE is passed, rule-id substring hints win.
    code, label = map_finding("python.sql-injection.rule", cwe="CWE-798", scanner="sast")
    assert code == "A03"
    assert "Injection" in label


def test_cwe_fallback_when_no_rule_hint():
    code, label = map_finding("some.generic.rule.id", cwe="CWE-89", scanner="sast")
    assert code == "A03"


def test_uncategorized_when_nothing_matches():
    code, label = map_finding("totally.unknown.rule", cwe=None, scanner="sast")
    assert code is None
    assert label == "Uncategorized"


def test_dependency_scanner_always_maps_to_a06():
    code, label = map_finding("GHSA-xxxx-yyyy-zzzz", scanner="dependency")
    assert code == "A06"
    assert "Vulnerable and Outdated Components" in label


def test_secret_rule_maps_to_a02():
    code, label = map_finding("secret-AWS Access Key", scanner="secrets")
    assert code == "A02"


def test_cwe_dash_prefix_normalized():
    code1, _ = map_finding("x", cwe="CWE-89")
    code2, _ = map_finding("x", cwe="89")
    assert code1 == code2 == "A03"
