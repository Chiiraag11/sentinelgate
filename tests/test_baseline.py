import tempfile
import os

import pytest

from sentinelgate.baseline import BaselineStore
from sentinelgate.models import Finding, Severity


@pytest.fixture
def db_path():
    with tempfile.TemporaryDirectory() as tmp:
        yield os.path.join(tmp, "baseline.db")


def test_save_and_diff_marks_known_findings_not_new(db_path):
    store = BaselineStore(db_path)
    baseline_findings = [
        Finding(file="a.py", line=10, rule_id="old-issue", severity=Severity.HIGH),
    ]
    store.save(baseline_findings, branch="main")

    pr_findings = [
        Finding(file="a.py", line=10, rule_id="old-issue", severity=Severity.HIGH),  # same fingerprint
        Finding(file="b.py", line=5, rule_id="new-issue", severity=Severity.CRITICAL),  # new
    ]
    diffed = store.diff(pr_findings, branch="main")

    old = next(f for f in diffed if f.rule_id == "old-issue")
    new = next(f for f in diffed if f.rule_id == "new-issue")
    assert old.is_new is False
    assert new.is_new is True


def test_diff_against_empty_baseline_marks_everything_new(db_path):
    store = BaselineStore(db_path)
    findings = [Finding(file="a.py", line=1, rule_id="x")]
    diffed = store.diff(findings, branch="main")
    assert diffed[0].is_new is True


def test_baselines_are_isolated_per_branch(db_path):
    store = BaselineStore(db_path)
    store.save([Finding(file="a.py", line=1, rule_id="issue")], branch="main")

    # same fingerprint, different branch: should NOT be found in baseline
    pr_findings = [Finding(file="a.py", line=1, rule_id="issue")]
    diffed = store.diff(pr_findings, branch="feature-x")
    assert diffed[0].is_new is True


def test_save_overwrites_previous_baseline_for_same_branch(db_path):
    store = BaselineStore(db_path)
    store.save([Finding(file="a.py", line=1, rule_id="old")], branch="main")
    store.save([Finding(file="b.py", line=1, rule_id="new")], branch="main")

    known = store.known_fingerprints("main")
    assert len(known) == 1  # old baseline replaced, not merged


def test_persists_across_store_instances(db_path):
    store1 = BaselineStore(db_path)
    store1.save([Finding(file="a.py", line=1, rule_id="issue")], branch="main")

    store2 = BaselineStore(db_path)  # simulates a fresh CI run
    diffed = store2.diff([Finding(file="a.py", line=1, rule_id="issue")], branch="main")
    assert diffed[0].is_new is False


def test_second_instance_of_same_rule_in_same_file_is_detected_as_new():
    """Regression test: a bare fingerprint-set lookup would treat *any*
    finding matching an existing (file, rule_id) as known, even a distinct
    instance at a totally different line. One baseline entry must not be
    able to silently cover an unlimited number of new findings.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store = BaselineStore(os.path.join(tmp, "baseline.db"))
        store.save(
            [Finding(file="app.py", line=14, rule_id="sqli", severity=Severity.HIGH)],
            branch="main",
        )

        pr_findings = [
            Finding(file="app.py", line=14, rule_id="sqli", severity=Severity.HIGH),  # unchanged
            Finding(file="app.py", line=90, rule_id="sqli", severity=Severity.HIGH),  # genuinely new
        ]
        diffed = store.diff(pr_findings, branch="main")

        at_14 = next(f for f in diffed if f.line == 14)
        at_90 = next(f for f in diffed if f.line == 90)
        assert at_14.is_new is False
        assert at_90.is_new is True


def test_save_does_not_collapse_multiple_identical_rule_findings():
    """Regression test: saving used INSERT OR REPLACE keyed on a fingerprint
    that excludes line number, so N pre-existing instances of the same rule
    in the same file collapsed into 1 stored row.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store = BaselineStore(os.path.join(tmp, "baseline.db"))
        findings = [
            Finding(file="app.py", line=10, rule_id="sqli", severity=Severity.HIGH),
            Finding(file="app.py", line=50, rule_id="sqli", severity=Severity.HIGH),
            Finding(file="app.py", line=90, rule_id="sqli", severity=Severity.HIGH),
        ]
        saved_count = store.save(findings, branch="main")
        assert saved_count == 3

        with store._connect() as conn:
            row_count = conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
        assert row_count == 3


def test_line_drift_within_tolerance_still_matches():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store = BaselineStore(os.path.join(tmp, "baseline.db"))
        store.save([Finding(file="a.py", line=20, rule_id="x", severity=Severity.HIGH)], branch="main")

        # unrelated edits shifted this finding down by 2 lines
        diffed = store.diff(
            [Finding(file="a.py", line=22, rule_id="x", severity=Severity.HIGH)], branch="main"
        )
        assert diffed[0].is_new is False
