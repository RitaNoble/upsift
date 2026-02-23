import os
import stat
import subprocess
from upsift.checks.base import BaseCheck, Finding

# Directories to skip — these are expected to have world-writable files
SKIP_DIRS = {
    "/tmp", "/var/tmp", "/dev/shm", "/proc", "/sys", "/dev", "/run",
}

# High-value target paths — writable files here are especially dangerous
HIGH_VALUE_PATHS = [
    "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/lib", "/usr/lib",
]


class WorldWritableFilesCheck(BaseCheck):
    id = "world_writable"
    name = "World-writable files"
    severity = "medium"
    description = (
        "Finds files outside /tmp that are writable by any user on the system. "
        "World-writable files in sensitive locations can be used for privilege "
        "escalation, persistence, or tampering with system behaviour."
    )

    def run(self):
        findings = []
        risky = []
        critical_hits = []

        try:
            result = subprocess.check_output(
                ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
                 "-not", "-path", "/proc/*",
                 "-not", "-path", "/sys/*",
                 "-not", "-path", "/dev/*",
                 "-not", "-path", "/tmp/*",
                 "-not", "-path", "/var/tmp/*",
                 "-not", "-path", "/run/*",
                 ],
                text=True,
                timeout=30,
                stderr=subprocess.DEVNULL,
            )

            files = [f for f in result.strip().splitlines() if f]

            for f in files:
                risky.append(f)
                for hp in HIGH_VALUE_PATHS:
                    if f.startswith(hp):
                        critical_hits.append(f)
                        break

        except subprocess.TimeoutExpired:
            findings.append(Finding(
                id=self.id,
                title="World-writable scan timed out",
                severity="info",
                description="The filesystem scan took too long. Try running as root with a narrower scope.",
                remediation="Run manually: find /etc /usr /bin -type f -perm -0002 2>/dev/null",
                references=[],
            ))
            return findings
        except Exception as e:
            findings.append(Finding(
                id=self.id,
                title="World-writable scan failed",
                severity="info",
                description=str(e),
                remediation="Run manually: find / -xdev -type f -perm -0002 2>/dev/null",
                references=[],
            ))
            return findings

        if critical_hits:
            findings.append(Finding(
                id=self.id,
                title=f"Found {len(critical_hits)} world-writable file(s) in sensitive locations",
                severity="high",
                description="World-writable files found in high-value system directories.",
                evidence="\n".join(critical_hits[:30]),
                remediation=(
                    "Remove world-write permission immediately: "
                    "'chmod o-w /path/to/file'. Audit file ownership too: 'ls -la /path/to/file'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1222/",
                    "https://linux-audit.com/linux-file-permissions-security-hardening/",
                ],
            ))

        if risky and not critical_hits:
            findings.append(Finding(
                id=self.id,
                title=f"Found {len(risky)} world-writable file(s) outside /tmp",
                severity="medium",
                description=self.description,
                evidence="\n".join(risky[:30]),
                remediation=(
                    "Review each file and remove world-write permission where unnecessary: "
                    "'chmod o-w /path/to/file'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1222/",
                ],
            ))

        if not risky:
            findings.append(Finding(
                id=self.id,
                title="No world-writable files found outside /tmp",
                severity="info",
                description="System looks clean — no unexpected world-writable files detected.",
                remediation=None,
                references=[],
            ))

        return findings
