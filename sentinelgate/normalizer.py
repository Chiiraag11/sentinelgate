"""Collapses duplicate findings reported by more than one scanner.

The concrete case this handles: Semgrep and a secondary SAST rule pack both
flag the exact same SQL-injection line, or a dependency shows up in both
pip-audit and a lockfile-based scanner. Without dedup, the PR comment would
list the same problem twice with different wording, which is exactly the
"wall of raw tool output" this tool exists to avoid.

Dedup key: same file + same rule family (via OWASP category) + line numbers
within a small window. We don't require an exact rule_id match across tools,
since two different scanners almost never use the same rule slug even when
they've found the same thing.
"""

from __future__ import annotations

from sentinelgate.models import Finding

_LINE_TOLERANCE = 2


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Return findings with duplicates collapsed, keeping the highest-severity copy."""
    kept: list[Finding] = []

    for finding in findings:
        duplicate_of = None
        for existing in kept:
            if _is_duplicate(finding, existing):
                duplicate_of = existing
                break

        if duplicate_of is None:
            kept.append(finding)
        else:
            # Keep whichever copy is more severe; merge fix suggestions if
            # the surviving one doesn't have one.
            if finding.severity.rank > duplicate_of.severity.rank:
                kept.remove(duplicate_of)
                kept.append(finding)
            elif not duplicate_of.fix_suggestion and finding.fix_suggestion:
                duplicate_of.fix_suggestion = finding.fix_suggestion

    return kept


def _is_duplicate(a: Finding, b: Finding) -> bool:
    if a.file != b.file:
        return False
    if a.scanner != b.scanner:
        # Cross-scanner de-dup only applies within the same scanner category
        # (two SAST tools, or two dependency tools) — a secret finding and a
        # SAST finding on the same line are unrelated.
        return False
    if a.package and b.package:
        return a.package == b.package and a.rule_id == b.rule_id
    if a.secret_type and b.secret_type:
        return a.line == b.line and a.secret_type == b.secret_type
    return abs(a.line - b.line) <= _LINE_TOLERANCE and a.owasp_category == b.owasp_category
