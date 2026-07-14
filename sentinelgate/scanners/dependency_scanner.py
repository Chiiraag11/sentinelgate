"""Wraps pip-audit for known-CVE dependency findings.

npm audit follows the same pattern (JSON output, package/version/CVE fields)
— NpmAuditScanner is included for JS repos so orchestrator.py can pick
whichever manifest files are present.
"""

from __future__ import annotations

import json
import os

from sentinelgate.mapper import map_finding
from sentinelgate.models import Finding, ScannerType, Severity
from sentinelgate.scanners.base import BaseScanner, ScannerError

# pip-audit reports CVSS-ish severity inconsistently across advisory
# sources; when a fix_versions list is present at all we treat it as at
# least HIGH, since "there's a known fix, you're not on it" is actionable
# regardless of CVSS wording.
_ALIAS_SEVERITY_KEYWORDS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class DependencyScanner(BaseScanner):
    name = "pip-audit"

    def run(self) -> list[Finding]:
        if not self._has_python_manifest():
            return []

        cmd = ["pip-audit", "-f", "json", "-r", self._requirements_path()] \
            if self._requirements_path() else ["pip-audit", "-f", "json"]
        stdout = self._run_subprocess(cmd)
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"pip-audit: could not parse JSON output: {e}") from e

        # pip-audit's JSON shape varies by version: either a list of
        # dependencies directly, or {"dependencies": [...]}.
        deps = data if isinstance(data, list) else data.get("dependencies", [])

        findings: list[Finding] = []
        for dep in deps:
            name = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "UNKNOWN-CVE")
                fix_versions = vuln.get("fix_versions", [])
                owasp_code, owasp_label = map_finding(vuln_id, scanner="dependency")

                severity = self._infer_severity(vuln)

                findings.append(
                    Finding(
                        file=self._requirements_path() or "pyproject.toml",
                        line=0,
                        title=f"{name}@{version}: {vuln_id}",
                        description=(vuln.get("description") or "")[:400],
                        rule_id=vuln_id,
                        scanner=ScannerType.DEPENDENCY,
                        severity=severity,
                        owasp_category=owasp_label,
                        package=name,
                        installed_version=version,
                        fixed_version=fix_versions[0] if fix_versions else None,
                        fix_suggestion=(
                            f"Upgrade {name} to {fix_versions[0]}"
                            if fix_versions
                            else f"No fixed version published yet for {name} {vuln_id}; consider pinning away or vendoring a patch."
                        ),
                    )
                )
        return findings

    def _infer_severity(self, vuln: dict) -> Severity:
        # Prefer any explicit severity fields present in the advisory data.
        for key in ("severity", "database_specific"):
            val = vuln.get(key)
            if isinstance(val, str):
                for kw, sev in _ALIAS_SEVERITY_KEYWORDS.items():
                    if kw in val.lower():
                        return sev
            if isinstance(val, dict):
                sev_str = str(val.get("severity", "")).lower()
                for kw, sev in _ALIAS_SEVERITY_KEYWORDS.items():
                    if kw in sev_str:
                        return sev
        # No severity info at all but a known CVE with a fix exists: default HIGH.
        return Severity.HIGH if vuln.get("fix_versions") else Severity.MEDIUM

    def _has_python_manifest(self) -> bool:
        return any(
            os.path.exists(os.path.join(self.target_dir, f))
            for f in ("requirements.txt", "pyproject.toml", "setup.py")
        )

    def _requirements_path(self) -> str | None:
        path = os.path.join(self.target_dir, "requirements.txt")
        return "requirements.txt" if os.path.exists(path) else None


class NpmAuditScanner(BaseScanner):
    """Same Finding shape as DependencyScanner, for JS/TS repos with package-lock.json."""

    name = "npm-audit"

    def run(self) -> list[Finding]:
        if not os.path.exists(os.path.join(self.target_dir, "package-lock.json")):
            return []

        stdout = self._run_subprocess(["npm", "audit", "--json"])
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"npm-audit: could not parse JSON output: {e}") from e

        findings: list[Finding] = []
        for name, vuln in data.get("vulnerabilities", {}).items():
            severity_raw = vuln.get("severity", "moderate")
            severity = _ALIAS_SEVERITY_KEYWORDS.get(severity_raw, Severity.MEDIUM)
            via = vuln.get("via", [])
            cve_ids = [v.get("source", name) for v in via if isinstance(v, dict)]
            fix_available = vuln.get("fixAvailable")
            fixed_version = None
            if isinstance(fix_available, dict):
                fixed_version = fix_available.get("version")

            owasp_code, owasp_label = map_finding(str(cve_ids), scanner="dependency")
            findings.append(
                Finding(
                    file="package-lock.json",
                    line=0,
                    title=f"{name}: {severity_raw} severity vulnerability",
                    description=f"npm audit flagged {name} via {', '.join(str(c) for c in cve_ids) or 'transitive dependency'}",
                    rule_id=f"npm-audit/{name}",
                    scanner=ScannerType.DEPENDENCY,
                    severity=severity,
                    owasp_category=owasp_label,
                    package=name,
                    fixed_version=fixed_version,
                    fix_suggestion=(
                        f"Run `npm audit fix` (upgrades to {fixed_version})"
                        if fixed_version
                        else "Run `npm audit fix --force` and review breaking changes, or find an alternative package."
                    ),
                )
            )
        return findings
