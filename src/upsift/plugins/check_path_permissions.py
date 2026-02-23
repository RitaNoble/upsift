import os
from upsift.checks.base import BaseCheck, Finding

class PathWriteCheck(BaseCheck):
    id = "path_write"
    name = "Writable PATH directories"
    severity = "high"
    description = "Detect user-writable directories in PATH and dangerous entries like '.' that enable PATH hijacking."

    def run(self):
        findings = []
        path = os.environ.get("PATH", "")
        dirs = [p for p in path.split(":") if p]
        writable = []
        for d in dirs:
            try:
                if os.path.isdir(d) and os.access(d, os.W_OK):
                    writable.append(d)
            except Exception:
                continue
        danger = []
        if "." in dirs:
            danger.append(".")
        if writable or danger:
            evidence = []
            if writable:
                evidence.append("Writable: " + ", ".join(writable))
            if danger:
                evidence.append("Dangerous entries: " + ", ".join(danger))
            findings.append(
                Finding(
                    id=self.id,
                    title="PATH is vulnerable to hijacking",
                    severity="high",
                    description=self.description,
                    evidence="; ".join(evidence),
                    remediation="Remove '.' and user-writable directories from PATH. Restrict perms to 755 or less.",
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                )
            )
        return findings
