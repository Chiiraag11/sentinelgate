"""Risk scoring: severity x exploitability heuristics -> a 0-100 score per finding.

Severity alone (from the scanner) is a coarse signal. This layer adjusts it
with a few cheap exploitability heuristics so the PR comment can sort by
"actually urgent" rather than raw tool severity, which is often noisy.
"""

from __future__ import annotations

from sentinelgate.models import Finding, ScannerType, Severity

_BASE_SCORE = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 5,
}

# Rule/category families that are trivially exploitable once merged (no
# special access needed, remotely triggerable) get a bump.
_HIGH_EXPLOITABILITY_HINTS = (
    "sql-injection",
    "sqli",
    "command-injection",
    "os-command",
    "deserialization",
    "pickle",
    "ssrf",
    "xxe",
)

_LOW_EXPLOITABILITY_HINTS = (
    "info",
    "best-practice",
    "deprecated",
)


def score(finding: Finding) -> int:
    """Return an integer 0-100 risk score for a single finding."""
    base = _BASE_SCORE[finding.severity]
    rule_lower = finding.rule_id.lower()

    adjustment = 0

    if any(hint in rule_lower for hint in _HIGH_EXPLOITABILITY_HINTS):
        adjustment += 15

    if any(hint in rule_lower for hint in _LOW_EXPLOITABILITY_HINTS):
        adjustment -= 15

    # Secrets are worst-case-assume-compromised the moment they're merged to
    # a shared branch (recoverable from git history forever after), so they
    # don't get discounted the way a "maybe exploitable" SAST finding might.
    if finding.scanner == ScannerType.SECRETS:
        adjustment += 10

    # A dependency vuln with no fix available yet is lower urgency to *act*
    # on right now (nothing to upgrade to) even though it's still real risk.
    if finding.scanner == ScannerType.DEPENDENCY and not finding.fixed_version:
        adjustment -= 10

    return max(0, min(100, base + adjustment))


def gate_severity_threshold() -> Severity:
    """The severity at/above which the build should fail.

    Kept as a function (not a bare constant) so cli.py can override via
    --fail-on without every caller needing to know the config plumbing.
    """
    return Severity.HIGH


def should_fail_build(findings: list[Finding], threshold: Severity | None = None) -> bool:
    """True if any *new* finding meets or exceeds the fail threshold.

    Pre-existing findings (is_new=False, from baseline diffing) never fail
    the build on their own — that's the whole point of baseline diffing.
    """
    threshold = threshold or gate_severity_threshold()
    return any(f.is_new and f.severity.rank >= threshold.rank for f in findings)
