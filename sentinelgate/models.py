"""Core data model shared by every scanner wrapper and downstream stage.

Every scanner, regardless of what it natively emits (SARIF, custom JSON,
whatever), gets normalized into a single Finding shape. Everything downstream
of scanners/ only ever deals with Finding objects and never needs to know
which tool produced them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        # Higher = worse. Used for sorting and gate comparisons.
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    # NOTE: Severity mixes in `str`, which brings its own lexicographic
    # comparison methods. Defining only __lt__ isn't enough — str's __gt__
    # takes over for `>`/`max()`, comparing "low" vs "critical" alphabetically
    # instead of by rank. Both __lt__ and __gt__ (plus __le__/__ge__) are
    # overridden explicitly to guard against this str-mixin surprise.
    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


class ScannerType(str, Enum):
    SAST = "sast"
    SECRETS = "secrets"
    DEPENDENCY = "dependency"


@dataclass
class Finding:
    """A single, normalized security finding."""

    # Identity / location
    file: str
    line: int
    end_line: Optional[int] = None

    # What was found
    title: str = ""
    description: str = ""
    rule_id: str = ""
    scanner: ScannerType = ScannerType.SAST
    severity: Severity = Severity.MEDIUM

    # Classification (filled in by the OWASP/CWE mapper)
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None

    # Optional extras
    fix_suggestion: str = ""
    code_snippet: str = ""
    package: Optional[str] = None          # for dependency findings
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    secret_type: Optional[str] = None      # for secret findings

    # Populated by baseline diffing, not by scanners
    is_new: bool = True

    def fingerprint(self) -> str:
        """Stable identity for de-duplication and baseline diffing.

        Deliberately excludes severity/description, since two tools that
        disagree on wording but agree on rule+location are the same finding.
        Line number is intentionally excluded too (within a small tolerance
        handled by the normalizer) since minor line drift between tool runs
        on the same commit shouldn't create a "new" finding.
        """
        key = f"{self.scanner.value}:{self.file}:{self.rule_id}:{self.package or ''}:{self.secret_type or ''}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def location_key(self) -> str:
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["scanner"] = self.scanner.value
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint()
        return d


@dataclass
class ScanResult:
    """Aggregate result across all scanners for a single run."""

    findings: list[Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    scanners_failed: list[str] = field(default_factory=list)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def worst_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)
