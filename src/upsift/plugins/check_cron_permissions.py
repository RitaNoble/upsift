import os, stat, glob
from upsift.checks.base import BaseCheck, Finding

class CronWriteCheck(BaseCheck):
    id = "cron_writable"
    name = "Writable cron jobs"
    severity = "high"
    description = "Writable cron job files or directories can allow privilege escalation or persistence."

    def run(self):
        findings = []
        paths = [
            "/etc/crontab",
            "/etc/cron.d",
            "/var/spool/cron",
            "/var/spool/cron/crontabs",
        ]
        risky = []
        for p in paths:
            if os.path.isdir(p):
                for root, dirs, files in os.walk(p):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            st = os.stat(fp)
                            if st.st_mode & stat.S_IWOTH:
                                risky.append(f"World-writable file: {fp}")
                        except Exception:
                            continue
            elif os.path.isfile(p):
                try:
                    st = os.stat(p)
                    if st.st_mode & stat.S_IWOTH:
                        risky.append(f"World-writable file: {p}")
                except Exception:
                    continue

        if risky:
            findings.append(Finding(
                id=self.id,
                title="Writable cron entries detected",
                severity="high",
                description=self.description,
                evidence="\n".join(risky[:50]),
                remediation="Set correct permissions and ownership on cron files and directories.",
                references=["https://wiki.archlinux.org/title/Cron"],
            ))
        return findings
