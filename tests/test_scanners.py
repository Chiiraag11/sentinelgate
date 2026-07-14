import json
import os
from unittest.mock import patch

import pytest

from sentinelgate.models import ScannerType, Severity
from sentinelgate.scanners.base import ScannerError
from sentinelgate.scanners.dependency_scanner import DependencyScanner
from sentinelgate.scanners.secrets_scanner import SecretsScanner
from sentinelgate.scanners.semgrep_scanner import SemgrepScanner

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return f.read()


class TestSemgrepScanner:
    def test_parses_findings_and_maps_owasp(self):
        scanner = SemgrepScanner("/tmp/fake-repo")
        with patch.object(scanner, "_run_subprocess", return_value=_load("semgrep_output.json")):
            findings = scanner.run()

        assert len(findings) == 2
        sqli = next(f for f in findings if "sql-injection" in f.rule_id)
        assert sqli.file == "app/views.py"
        assert sqli.line == 42
        assert sqli.severity == Severity.HIGH
        assert sqli.owasp_category == "A03:2021 - Injection"
        assert sqli.cwe == "CWE-89"
        assert sqli.scanner == ScannerType.SAST

    def test_injection_findings_escalated_to_at_least_high(self):
        # eval-detected comes in as WARNING but maps to A03 (code injection)
        # via rule-id hint, so it should be escalated.
        scanner = SemgrepScanner("/tmp/fake-repo")
        with patch.object(scanner, "_run_subprocess", return_value=_load("semgrep_output.json")):
            findings = scanner.run()
        eval_finding = next(f for f in findings if "eval-detected" in f.rule_id)
        assert eval_finding.severity == Severity.HIGH

    def test_raises_scanner_error_on_bad_json(self):
        scanner = SemgrepScanner("/tmp/fake-repo")
        with patch.object(scanner, "_run_subprocess", return_value="not json"):
            with pytest.raises(ScannerError):
                scanner.run()


class TestSecretsScanner:
    def test_parses_secrets_and_flags_high_confidence_as_critical(self):
        scanner = SecretsScanner("/tmp/fake-repo")
        with patch.object(scanner, "_run_subprocess", return_value=_load("secrets_output.json")):
            findings = scanner.run()

        assert len(findings) == 1
        f = findings[0]
        assert f.file == "config/settings.py"
        assert f.line == 15
        assert f.secret_type == "AWS Access Key"
        assert f.severity == Severity.CRITICAL  # AWS keys are high-confidence
        assert f.scanner == ScannerType.SECRETS
        assert f.owasp_category == "A02:2021 - Cryptographic Failures"


class TestDependencyScanner:
    def test_parses_vulns_and_skips_clean_packages(self):
        scanner = DependencyScanner("/tmp/fake-repo")
        with patch.object(scanner, "_has_python_manifest", return_value=True), \
             patch.object(scanner, "_requirements_path", return_value="requirements.txt"), \
             patch.object(scanner, "_run_subprocess", return_value=_load("pip_audit_output.json")):
            findings = scanner.run()

        # flask has no vulns and should not produce a finding
        assert len(findings) == 1
        f = findings[0]
        assert f.package == "requests"
        assert f.installed_version == "2.25.0"
        assert f.fixed_version == "2.31.0"
        assert f.severity == Severity.HIGH
        assert f.owasp_category == "A06:2021 - Vulnerable and Outdated Components"
        assert "Upgrade requests to 2.31.0" in f.fix_suggestion

    def test_skips_scan_when_no_manifest_present(self):
        scanner = DependencyScanner("/tmp/fake-repo")
        with patch.object(scanner, "_has_python_manifest", return_value=False):
            findings = scanner.run()
        assert findings == []


class TestBaseScanner:
    def test_missing_executable_raises_scanner_error(self):
        scanner = SemgrepScanner("/tmp/fake-repo")
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with pytest.raises(ScannerError):
                scanner.run()
