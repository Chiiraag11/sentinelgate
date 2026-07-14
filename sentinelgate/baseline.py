"""Baseline diffing: only flag findings newly introduced by a PR.

Without this, every PR against a repo with existing tech debt would fail the
gate on day one and the tool would get disabled within a week. The baseline
is a snapshot of findings on the main branch, stored in SQLite. A PR scan is
compared against it: anything that matches a stored baseline entry is marked
is_new=False and never blocks the merge; anything left over is new.

Matching is signature + line-tolerant, NOT a bare fingerprint lookup.
Finding.fingerprint() deliberately excludes the line number (to tolerate
minor line drift from unrelated edits above a finding), but that same
property means a plain "is this fingerprint present anywhere in the
baseline" check would silently swallow a second, genuinely new instance of
the same rule in the same file — e.g. a new SQL-injection call added lower
down in a file that already had one. To avoid that, each new finding is
matched against the *closest unclaimed* baseline entry with the same
signature and a line number within tolerance; each baseline entry can only
satisfy one match. Leftover new findings (no baseline entry left to claim)
are genuinely new, even if the same rule already exists elsewhere in the file.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from sentinelgate.models import Finding

_LINE_TOLERANCE = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature TEXT NOT NULL,
    line INTEGER NOT NULL,
    file TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    branch TEXT NOT NULL,
    first_seen REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_baseline_branch_sig ON baseline (branch, signature);
"""


class BaselineStore:
    def __init__(self, db_path: str = ".sentinelgate/baseline.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, findings: list[Finding], branch: str = "main") -> int:
        """Persist the given findings as the baseline for `branch`. Returns count saved.

        Each finding is stored as its own row (not deduplicated by
        signature) so that N pre-existing instances of the same rule in the
        same file are recognized as N known findings, not one.
        """
        now = time.time()
        with self._connect() as conn:
            conn.execute("DELETE FROM baseline WHERE branch = ?", (branch,))
            conn.executemany(
                "INSERT INTO baseline (signature, line, file, rule_id, severity, branch, first_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (f.fingerprint(), f.line, f.file, f.rule_id, f.severity.value, branch, now)
                    for f in findings
                ],
            )
        return len(findings)

    def known_fingerprints(self, branch: str = "main") -> set[str]:
        """Distinct signatures present in the baseline (coarse check, not used by diff())."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT signature FROM baseline WHERE branch = ?", (branch,)
            ).fetchall()
        return {r[0] for r in rows}

    def diff(self, findings: list[Finding], branch: str = "main") -> list[Finding]:
        """Mark each finding's is_new flag in place based on the stored baseline. Returns the same list."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT signature, line FROM baseline WHERE branch = ?", (branch,)
            ).fetchall()

        # signature -> list of available baseline line numbers, each of
        # which can be claimed by at most one PR finding.
        available: dict[str, list[int]] = {}
        for signature, line in rows:
            available.setdefault(signature, []).append(line)

        # Process worst-severity-first so that if a signature has more
        # baseline entries than PR findings claiming it, the most important
        # findings are the ones treated as "known" (arbitrary tie-break, but
        # a deliberate one rather than depending on input order).
        for f in sorted(findings, key=lambda x: -x.severity.rank):
            sig = f.fingerprint()
            candidates = available.get(sig, [])
            if not candidates:
                f.is_new = True
                continue

            closest = min(candidates, key=lambda line: abs(line - f.line))
            if abs(closest - f.line) <= _LINE_TOLERANCE:
                f.is_new = False
                candidates.remove(closest)
            else:
                f.is_new = True

        return findings
