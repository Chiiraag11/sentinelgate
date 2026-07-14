"""Runs all scanners, normalizes, dedups, scores, and baseline-diffs.

This is the single entry point cli.py and the GitHub Action call into. Each
scanner is isolated in its own try/except so that one broken/missing tool
(e.g. semgrep not installed in a stripped-down container) degrades to a
partial scan with a warning, rather than taking down the whole gate.
"""

from __future__ import annotations

import logging

from sentinelgate.baseline import BaselineStore
from sentinelgate.models import Finding, ScanResult
from sentinelgate.normalizer import deduplicate
from sentinelgate.scanners.base import ScannerError
from sentinelgate.scanners.dependency_scanner import DependencyScanner, NpmAuditScanner
from sentinelgate.scanners.secrets_scanner import SecretsScanner
from sentinelgate.scanners.semgrep_scanner import SemgrepScanner

logger = logging.getLogger("sentinelgate")

DEFAULT_SCANNERS = [SemgrepScanner, SecretsScanner, DependencyScanner, NpmAuditScanner]


def run_scan(
    target_dir: str,
    baseline_branch: str | None = None,
    baseline_db: str = ".sentinelgate/baseline.db",
    scanner_classes=None,
) -> ScanResult:
    scanner_classes = scanner_classes or DEFAULT_SCANNERS
    result = ScanResult()
    all_findings: list[Finding] = []

    for scanner_cls in scanner_classes:
        scanner = scanner_cls(target_dir)
        try:
            findings = scanner.run()
            all_findings.extend(findings)
            result.scanners_run.append(scanner.name)
            logger.info("%s: %d finding(s)", scanner.name, len(findings))
        except ScannerError as e:
            result.scanners_failed.append(scanner.name)
            logger.warning("scanner %s failed, continuing without it: %s", scanner.name, e)

    deduped = deduplicate(all_findings)

    if baseline_branch:
        store = BaselineStore(baseline_db)
        deduped = store.diff(deduped, branch=baseline_branch)

    # Sort worst-first so the report and gate logic both see the most
    # important findings up top.
    deduped.sort(key=lambda f: f.severity.rank, reverse=True)

    result.findings = deduped
    return result
