"""Maps scanner-specific rule IDs and CWE numbers to OWASP Top 10 (2021) categories.

This is the piece that turns "semgrep says rule
python.django.security.injection.sql.sql-injection-using-extra fired" into
something a reviewer actually understands: "A03:2021 - Injection".

Three lookup layers, tried in order:
  1. Exact rule-id substring match (tool-specific, most precise)
  2. CWE-number match (tool-agnostic, works for any scanner that reports a CWE)
  3. Fallback: "Uncategorized"
"""

from __future__ import annotations

from typing import Optional

OWASP_TOP_10_2021 = {
    "A01": "A01:2021 - Broken Access Control",
    "A02": "A02:2021 - Cryptographic Failures",
    "A03": "A03:2021 - Injection",
    "A04": "A04:2021 - Insecure Design",
    "A05": "A05:2021 - Security Misconfiguration",
    "A06": "A06:2021 - Vulnerable and Outdated Components",
    "A07": "A07:2021 - Identification and Authentication Failures",
    "A08": "A08:2021 - Software and Data Integrity Failures",
    "A09": "A09:2021 - Security Logging and Monitoring Failures",
    "A10": "A10:2021 - Server-Side Request Forgery",
}

# CWE number -> OWASP category. Not exhaustive of all ~900 CWEs, but covers
# the ones that show up constantly in SAST/dependency/secret scanner output.
CWE_TO_OWASP = {
    "22": "A01",   # Path Traversal
    "23": "A01",
    "284": "A01",  # Improper Access Control
    "285": "A01",  # Improper Authorization
    "639": "A01",  # IDOR
    "862": "A01",  # Missing Authorization
    "863": "A01",  # Incorrect Authorization
    "200": "A01",  # Information Exposure (access-control adjacent)
    "798": "A02",  # Hardcoded Credentials -> often cryptographic/secrets
    "259": "A02",  # Hardcoded Password
    "321": "A02",  # Hardcoded Crypto Key
    "327": "A02",  # Broken/Risky Crypto Algorithm
    "328": "A02",  # Weak Hash
    "330": "A02",  # Insufficiently Random Values
    "916": "A02",  # Weak Password Hash
    "89": "A03",   # SQL Injection
    "78": "A03",   # OS Command Injection
    "79": "A03",   # XSS
    "77": "A03",   # Command Injection
    "94": "A03",   # Code Injection
    "643": "A03",  # XPath Injection
    "917": "A03",  # Expression Language Injection
    "611": "A03",  # XXE (classified under Injection in 2021 list)
    "915": "A08",  # Improperly Controlled Modification of Object Attributes
    "502": "A08",  # Deserialization of Untrusted Data
    "829": "A08",  # Inclusion of Functionality from Untrusted Control Sphere
    "347": "A08",  # Improper Verification of Cryptographic Signature
    "corrupt": "A08",
    "raw-node-flags": "A05",
    "16": "A05",   # Configuration
    "260": "A05",  # Password in Config File
    "611-xxe": "A05",
    "1021": "A05",  # Improper Restriction of Rendered UI Layers
    "352": "A01",  # CSRF -> often bucketed under broken access control in practice
    "918": "A10",  # SSRF
    "corrupt2": "A10",
    "287": "A07",  # Improper Authentication
    "306": "A07",  # Missing Authentication for Critical Function
    "384": "A07",  # Session Fixation
    "613": "A07",  # Insufficient Session Expiration
    "798-auth": "A07",
    "1104": "A06",  # Use of Unmaintained Third Party Components
    "937": "A06",   # Using Components with Known Vulnerabilities
    "1035": "A06",
    "778": "A09",  # Insufficient Logging
    "223": "A09",  # Omission of Security-relevant Information
    "532": "A09",  # Insertion of Sensitive Info into Log File
}

# Direct rule-id substring -> OWASP category, for cases where the scanner's
# rule slug is more reliable than whatever CWE it happens to attach (secret
# scanners in particular usually report no CWE at all).
RULE_ID_HINTS = {
    "sql-injection": "A03",
    "sqli": "A03",
    "command-injection": "A03",
    "os-command": "A03",
    "code-injection": "A03",
    "xss": "A03",
    "template-injection": "A03",
    "xxe": "A03",
    "path-traversal": "A01",
    "directory-traversal": "A01",
    "insecure-transport": "A02",
    "weak-cipher": "A02",
    "weak-hash": "A02",
    "insecure-hash": "A02",
    "hardcoded": "A02",
    "secret": "A02",
    "apikey": "A02",
    "api-key": "A02",
    "private-key": "A02",
    "aws-access-key": "A02",
    "password": "A02",
    "token": "A02",
    "deserialization": "A08",
    "pickle": "A08",
    "yaml-load": "A08",
    "insecure-deserialization": "A08",
    "ssrf": "A10",
    "csrf": "A01",
    "auth": "A07",
    "jwt": "A07",
    "session": "A07",
    "logging": "A09",
    "debug": "A05",
    "misconfiguration": "A05",
    "permissive-cors": "A05",
    "wildcard": "A05",
}

# Known-vulnerable-dependency findings (from pip-audit / npm audit) don't map
# via CWE at all in practice — they're just "you're using a version with a
# known CVE" — so those always bucket to A06.
DEPENDENCY_DEFAULT = "A06"


def map_finding(rule_id: str, cwe: Optional[str] = None, scanner: str = "sast") -> tuple[Optional[str], str]:
    """Return (owasp_code, owasp_label) for a given rule id / cwe / scanner.

    Order of precedence: dependency scanner shortcut > rule-id hint > CWE table > uncategorized.
    """
    if scanner == "dependency":
        code = DEPENDENCY_DEFAULT
        return code, OWASP_TOP_10_2021[code]

    rule_lower = (rule_id or "").lower()
    for hint, code in RULE_ID_HINTS.items():
        if hint in rule_lower:
            return code, OWASP_TOP_10_2021[code]

    if cwe:
        cwe_num = cwe.upper().replace("CWE-", "").strip()
        code = CWE_TO_OWASP.get(cwe_num)
        if code:
            return code, OWASP_TOP_10_2021[code]

    return None, "Uncategorized"
