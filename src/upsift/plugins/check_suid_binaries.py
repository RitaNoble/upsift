import os
import subprocess
from upsift.checks.base import BaseCheck, Finding

class SuidBinariesCheck(BaseCheck):
    id = "suid_binaries"
    name = "SUID/SGID binaries"
    severity = "medium"
    description = "Find world-accessible binaries with SUID/SGID that could allow privilege escalation."

    def run(self):
        findings = []
        # Search for suid/sgid binaries (common technique)
        try:
            # Limit depth and ignore special filesystems for speed
            cmd = ["bash", "-lc", "find / -xdev -perm -4000 -o -perm -2000 2>/dev/null"]
            out = subprocess.check_output(cmd, text=True, timeout=25)
            binaries = [p for p in out.strip().splitlines() if p]
            risky = []
            # Common suspicious ones beyond the typical baseline can be flagged
            baseline = {
                "/usr/bin/passwd",
                "/usr/bin/sudo",
                "/bin/su",
                "/usr/bin/chsh",
                "/usr/bin/chfn",
                "/usr/bin/newgrp",
                "/usr/bin/mount",
                "/usr/bin/umount",
            }
            for b in binaries:
                if b not in baseline:
                    risky.append(b)
            if risky:
                findings.append(
                    Finding(
                        id=self.id,
                        title=f"Found {len(risky)} unusual SUID/SGID binaries",
                        severity="medium",
                        description=self.description,
                        evidence="\n".join(risky[:50]),
                        remediation="Audit and remove SUID/SGID where unnecessary. Example: chmod a-s /path/bin",
                        references=[
                            "https://gtfobins.github.io/",
                            "https://www.kernel.org/doc/Documentation/sysctl/fs.txt",
                        ],
                    )
                )
        except Exception as e:
            findings.append(
                Finding(
                    id=self.id,
                    title="SUID/SGID scan failed",
                    severity="info",
                    description=str(e),
                )
            )
        return findings
