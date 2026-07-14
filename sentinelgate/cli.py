"""sentinelgate CLI — runnable standalone, no GitHub Actions required.

Examples:
    sentinelgate scan .
    sentinelgate scan . --fail-on critical
    sentinelgate baseline-save . --branch main
    sentinelgate scan . --baseline-branch main --post-pr owner/repo#42
"""

from __future__ import annotations

import json
import os
import sys

import click

from sentinelgate.models import Severity
from sentinelgate.orchestrator import run_scan
from sentinelgate.reporter import format_markdown, post_or_update_comment
from sentinelgate.scoring import should_fail_build

_SEVERITY_CHOICES = [s.value for s in Severity]


@click.group()
def main():
    """SentinelGate — a CI/CD security gate."""


@main.command()
@click.argument("target_dir", default=".")
@click.option("--fail-on", type=click.Choice(_SEVERITY_CHOICES), default="high",
              help="Minimum severity of a NEW finding that fails the build.")
@click.option("--baseline-branch", default=None,
              help="Diff results against this branch's saved baseline (skips pre-existing findings).")
@click.option("--baseline-db", default=".sentinelgate/baseline.db")
@click.option("--json-out", default=None, type=click.Path(), help="Write raw findings JSON to this path.")
@click.option("--markdown-out", default=None, type=click.Path(), help="Write the PR-comment markdown to this path.")
@click.option("--post-pr", default=None, metavar="owner/repo#123",
              help="Post/update the report as a PR comment. Requires GITHUB_TOKEN env var.")
def scan(target_dir, fail_on, baseline_branch, baseline_db, json_out, markdown_out, post_pr):
    """Run all scanners against TARGET_DIR and report findings."""
    threshold = Severity(fail_on)

    result = run_scan(
        target_dir,
        baseline_branch=baseline_branch,
        baseline_db=baseline_db,
    )

    markdown = format_markdown(result, fail_on=threshold)
    click.echo(markdown)

    if json_out:
        with open(json_out, "w") as f:
            json.dump([finding.to_dict() for finding in result.findings], f, indent=2)

    if markdown_out:
        with open(markdown_out, "w") as f:
            f.write(markdown)

    if post_pr:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            click.echo("GITHUB_TOKEN env var required for --post-pr", err=True)
            sys.exit(2)
        repo, _, pr_num = post_pr.partition("#")
        url = post_or_update_comment(repo, int(pr_num), markdown, token)
        click.echo(f"Posted comment: {url}", err=True)

    if should_fail_build(result.findings, threshold=threshold):
        click.echo(
            f"\nGate FAILED: new finding(s) at or above '{fail_on}' severity.", err=True
        )
        sys.exit(1)

    click.echo("\nGate PASSED.", err=True)
    sys.exit(0)


@main.command("baseline-save")
@click.argument("target_dir", default=".")
@click.option("--branch", default="main")
@click.option("--baseline-db", default=".sentinelgate/baseline.db")
def baseline_save(target_dir, branch, baseline_db):
    """Scan TARGET_DIR and persist results as the baseline for --branch.

    Run this on your default branch (e.g. in a push-to-main workflow) so PR
    scans have something to diff against.
    """
    from sentinelgate.baseline import BaselineStore

    result = run_scan(target_dir)
    store = BaselineStore(baseline_db)
    count = store.save(result.findings, branch=branch)
    click.echo(f"Saved {count} finding(s) as baseline for branch '{branch}'.")


if __name__ == "__main__":
    main()
