"""Wraps detect-secrets for secret/credential scanning.

Pluggable by design: gitleaks works just as well and speaks a similar JSON
shape (see GitleaksScanner below) — swap SECRETS_ENGINE in config if you'd
rather ship a Go binary instead of a pip package in your CI image.
"""

from __future__ import annotations

import json

from sentinelgate.mapper import map_finding
from sentinelgate.models import Finding, ScannerType, Severity
from sentinelgate.scanners.base import BaseScanner, ScannerError

# Certain secret types are much worse than others if leaked (private keys,
# cloud credentials) vs. things that are frequently false positives
# (generic high-entropy strings).
_HIGH_CONFIDENCE_TYPES = {
    "AWS Access Key",
    "Private Key",
    "Azure Storage Account access key",
    "Stripe Access Key",
    "GitHub Token",
    "JSON Web Token",
}


class SecretsScanner(BaseScanner):
    name = "detect-secrets"

    def run(self) -> list[Finding]:
        cmd = ["detect-secrets", "scan", "--all-files", "."]
        stdout = self._run_subprocess(cmd)
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"detect-secrets: could not parse JSON output: {e}") from e

        findings: list[Finding] = []
        for file_path, secrets in data.get("results", {}).items():
            for secret in secrets:
                secret_type = secret.get("type", "Secret")
                severity = (
                    Severity.CRITICAL if secret_type in _HIGH_CONFIDENCE_TYPES else Severity.HIGH
                )
                owasp_code, owasp_label = map_finding(
                    f"secret-{secret_type}", scanner="secrets"
                )
                findings.append(
                    Finding(
                        file=file_path,
                        line=secret.get("line_number", 0),
                        title=f"Hardcoded secret: {secret_type}",
                        description=(
                            f"A potential {secret_type} was detected in source. "
                            "Hardcoded credentials in version control are recoverable "
                            "from git history even after deletion."
                        ),
                        rule_id=f"secrets/{secret_type.lower().replace(' ', '-')}",
                        scanner=ScannerType.SECRETS,
                        severity=severity,
                        owasp_category=owasp_label,
                        secret_type=secret_type,
                        fix_suggestion=(
                            "Revoke/rotate this credential immediately, remove it from git "
                            "history, and load it from environment variables or a secrets manager."
                        ),
                    )
                )
        return findings


class GitleaksScanner(BaseScanner):
    """Alternate secrets engine. Same Finding shape as SecretsScanner.

    Requires the `gitleaks` binary on PATH (not pip-installable — Go binary).
    Left implemented so ops can swap engines without touching the rest of
    the pipeline.
    """

    name = "gitleaks"

    def run(self) -> list[Finding]:
        cmd = ["gitleaks", "detect", "--source", ".", "--report-format", "json", "--no-git", "-r", "-"]
        stdout = self._run_subprocess(cmd)
        if not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"gitleaks: could not parse JSON output: {e}") from e

        findings: list[Finding] = []
        for leak in data:
            rule = leak.get("RuleID", "generic-secret")
            owasp_code, owasp_label = map_finding(f"secret-{rule}", scanner="secrets")
            findings.append(
                Finding(
                    file=leak.get("File", "unknown"),
                    line=leak.get("StartLine", 0),
                    title=f"Hardcoded secret: {rule}",
                    description=leak.get("Description", ""),
                    rule_id=f"secrets/{rule}",
                    scanner=ScannerType.SECRETS,
                    severity=Severity.CRITICAL,
                    owasp_category=owasp_label,
                    secret_type=rule,
                    fix_suggestion="Revoke/rotate this credential and remove it from git history.",
                )
            )
        return findings
