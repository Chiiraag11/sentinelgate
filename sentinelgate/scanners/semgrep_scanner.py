"""Wraps Semgrep for SAST findings (SQLi, XSS, IDOR, command injection, etc)."""

from __future__ import annotations

import json
import os

from sentinelgate.mapper import map_finding
from sentinelgate.models import Finding, ScannerType, Severity
from sentinelgate.scanners.base import BaseScanner, ScannerError

# Semgrep's own severities don't line up 1:1 with ours; map explicitly
# rather than assuming string equality.
_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Bundled ruleset shipped with the package, used instead of `--config auto`.
# `auto` requires reaching Semgrep's registry (semgrep.dev) to pull rules,
# which many locked-down CI runners (and this sandbox) block outright.
# Shipping our own curated OWASP-mapped rules means SentinelGate scans work
# fully offline. Point --config at a different path/registry ruleset via the
# `config` argument if you want the larger community ruleset instead.
_BUNDLED_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules")


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    def __init__(self, target_dir: str, config: str | None = None):
        super().__init__(target_dir)
        self.config = config or os.path.normpath(_BUNDLED_RULES_DIR)

    def run(self) -> list[Finding]:
        cmd = [
            "semgrep",
            "scan",
            "--config",
            self.config,
            "--json",
            "--quiet",
            "--metrics=off",
            ".",
        ]
        stdout = self._run_subprocess(cmd)
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"semgrep: could not parse JSON output: {e}") from e

        findings: list[Finding] = []
        for result in data.get("results", []):
            rule_id = result.get("check_id", "")
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            severity_raw = extra.get("severity", "WARNING")
            severity = _SEMGREP_SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)

            # Semgrep sometimes carries its own CWE metadata; prefer that if present.
            cwe_meta = metadata.get("cwe")
            cwe = None
            if isinstance(cwe_meta, list) and cwe_meta:
                cwe = str(cwe_meta[0])
            elif isinstance(cwe_meta, str):
                cwe = cwe_meta
            if cwe:
                # semgrep's metadata.cwe is usually already "CWE-89"; strip
                # any existing prefix so we don't double it up below.
                cwe = cwe.upper().replace("CWE-", "").strip()

            owasp_code, owasp_label = map_finding(rule_id, cwe=cwe, scanner="sast")

            # Escalate injection-family findings tagged HIGH by rule-id hints
            # even if semgrep itself only rated them WARNING — these are the
            # classic "don't let this slip through" categories.
            if owasp_code == "A03" and severity.rank < Severity.HIGH.rank:
                severity = Severity.HIGH

            findings.append(
                Finding(
                    file=result.get("path", "unknown"),
                    line=result.get("start", {}).get("line", 0),
                    end_line=result.get("end", {}).get("line"),
                    title=metadata.get("shortlink", rule_id).split("/")[-1] or rule_id,
                    description=extra.get("message", "").strip(),
                    rule_id=rule_id,
                    scanner=ScannerType.SAST,
                    severity=severity,
                    cwe=f"CWE-{cwe}" if cwe else None,
                    owasp_category=owasp_label,
                    fix_suggestion=metadata.get("fix", "") or _default_fix_hint(owasp_code),
                    code_snippet=_clean_snippet(extra.get("lines", "")),
                )
            )
        return findings


def _clean_snippet(lines: str) -> str:
    # Recent semgrep CLI versions gate the actual code snippet (and
    # `fingerprint`) behind `semgrep login` even for local/OSS scans —
    # unauthenticated runs get the literal string "requires login" instead
    # of the matched lines. Detection, location, severity, and CWE/OWASP
    # mapping are unaffected either way; we just don't want to render that
    # placeholder as if it were real source code in the PR comment.
    text = (lines or "").strip()
    if not text or text.lower() == "requires login":
        return ""
    return text[:300]


def _default_fix_hint(owasp_code: str | None) -> str:
    hints = {
        "A03": "Use parameterized queries / output encoding instead of string concatenation.",
        "A01": "Add an explicit authorization check before this operation.",
        "A02": "Move secrets to environment variables or a secrets manager; use a vetted crypto library.",
        "A08": "Avoid deserializing untrusted input (e.g. pickle/yaml.load); use a safe loader.",
        "A10": "Validate/allowlist the destination before making the outbound request.",
    }
    return hints.get(owasp_code, "Review this finding against secure coding guidelines.")
