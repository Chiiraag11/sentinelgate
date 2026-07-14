"""Formats scan results into one readable, grouped PR comment (not 40 separate ones)
and posts/updates it via the GitHub REST API.
"""

from __future__ import annotations

from sentinelgate.models import Finding, ScanResult, Severity
from sentinelgate.scoring import score

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

MARKER = "<!-- sentinelgate-report -->"


def format_markdown(result: ScanResult, fail_on: Severity = Severity.HIGH) -> str:
    new_findings = [f for f in result.findings if f.is_new]
    preexisting = [f for f in result.findings if not f.is_new]

    lines: list[str] = [MARKER, "## 🛡️ SentinelGate Security Report", ""]

    if not result.findings:
        lines.append("✅ No security findings. Nice work.")
        if result.scanners_failed:
            lines.append("")
            lines.append(
                f"⚠️ These scanners failed to run and were skipped: {', '.join(result.scanners_failed)}"
            )
        return _finish(lines, result)

    blocking = [f for f in new_findings if f.severity.rank >= fail_on.rank]
    if blocking:
        lines.append(
            f"### ❌ Gate failed — {len(blocking)} new finding(s) at or above **{fail_on.value}** severity"
        )
    else:
        lines.append("### ✅ Gate passed — no new blocking findings")

    lines.append("")
    lines.append(_summary_table(new_findings, preexisting))
    lines.append("")

    if new_findings:
        lines.append("### New findings introduced by this PR")
        lines.append("")
        lines.extend(_grouped_findings(new_findings))

    if preexisting:
        lines.append("")
        lines.append(
            f"<details><summary>{len(preexisting)} pre-existing finding(s) "
            "(not introduced by this PR, not blocking)</summary>"
        )
        lines.append("")
        lines.extend(_grouped_findings(preexisting))
        lines.append("</details>")

    if result.scanners_failed:
        lines.append("")
        lines.append(
            f"⚠️ These scanners failed to run and were skipped: {', '.join(result.scanners_failed)}"
        )

    return _finish(lines, result)


def _finish(lines: list[str], result: ScanResult) -> str:
    lines.append("")
    lines.append(f"_Scanners run: {', '.join(result.scanners_run) or 'none'}_")
    return "\n".join(lines)


def _summary_table(new: list[Finding], preexisting: list[Finding]) -> str:
    def count(findings: list[Finding], sev: Severity) -> int:
        return sum(1 for f in findings if f.severity == sev)

    rows = ["| Severity | New | Pre-existing |", "|---|---|---|"]
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n, p = count(new, sev), count(preexisting, sev)
        if n or p:
            rows.append(f"| {_SEVERITY_EMOJI[sev]} {sev.value.title()} | {n} | {p} |")
    return "\n".join(rows)


def _grouped_findings(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.owasp_category or "Uncategorized", []).append(f)

    for category, items in sorted(by_category.items(), key=lambda kv: -max(score(f) for f in kv[1])):
        lines.append(f"**{category}**")
        lines.append("")
        for f in sorted(items, key=lambda x: -score(x)):
            emoji = _SEVERITY_EMOJI[f.severity]
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            lines.append(f"- {emoji} **{f.title}** — {loc} (risk score: {score(f)}/100)")
            if f.description:
                lines.append(f"  - {f.description}")
            if f.fix_suggestion:
                lines.append(f"  - 💡 *Fix:* {f.fix_suggestion}")
        lines.append("")
    return lines


def post_or_update_comment(
    repo_full_name: str,
    pr_number: int,
    body: str,
    token: str,
) -> str:
    """Post a new PR comment, or update the existing SentinelGate comment if one exists.

    Requires PyGithub (`pip install PyGithub`). Returns the comment URL.
    """
    from github import Github  # imported lazily so the rest of the package
    # works without PyGithub installed (e.g. local `sentinelgate scan` mode).

    gh = Github(token)
    repo = gh.get_repo(repo_full_name)
    pr = repo.get_pull(pr_number)

    for comment in pr.get_issue_comments():
        if comment.body.startswith(MARKER):
            comment.edit(body)
            return comment.html_url

    comment = pr.create_issue_comment(body)
    return comment.html_url
