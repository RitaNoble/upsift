import os
import re
import pathlib
from upsift.checks.base import BaseCheck, Finding

CRON_FILES = [
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]

# Regex to extract script/command paths from cron lines
CMD_PATTERN = re.compile(r"(/[\w/.\-_]+\.(sh|py|pl|rb|php|bash))")


class CrontabHijackCheck(BaseCheck):
    id = "crontab_hijack"
    name = "Crontab script hijack"
    severity = "high"
    description = (
        "Finds cron jobs that execute scripts which are writable by the current user. "
        "A writable script called by a privileged cron job can be replaced with "
        "malicious code that runs as root."
    )

    def _get_cron_lines(self):
        lines = []
        for path_str in CRON_FILES:
            p = pathlib.Path(path_str)
            if p.is_file():
                try:
                    for line in p.read_text(errors="ignore").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            lines.append(line)
                except Exception:
                    pass
            elif p.is_dir():
                try:
                    for f in p.iterdir():
                        if f.is_file():
                            try:
                                for line in f.read_text(errors="ignore").splitlines():
                                    line = line.strip()
                                    if line and not line.startswith("#"):
                                        lines.append(line)
                            except Exception:
                                pass
                except Exception:
                    pass
        return lines

    def run(self):
        findings = []
        hijackable = []

        cron_lines = self._get_cron_lines()

        for line in cron_lines:
            for match in CMD_PATTERN.finditer(line):
                script_path = match.group(1)
                p = pathlib.Path(script_path)
                if p.exists() and os.access(str(p), os.W_OK):
                    hijackable.append(f"{script_path} (writable) — in cron: {line[:80]}")

        if hijackable:
            findings.append(Finding(
                id=self.id,
                title=f"Found {len(hijackable)} writable script(s) called by cron",
                severity="high",
                description=self.description,
                evidence="\n".join(hijackable),
                remediation=(
                    "Remove write permissions from cron scripts: "
                    "'chmod 755 /path/to/script' and ensure owner is root. "
                    "Audit all cron jobs: 'crontab -l' and 'cat /etc/crontab'."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1053/003/",
                    "https://gtfobins.github.io/",
                ],
            ))
        else:
            findings.append(Finding(
                id=self.id,
                title="No writable cron scripts detected",
                severity="info",
                description="No cron job scripts were found to be writable by the current user.",
                remediation=None,
                references=[],
            ))

        return findings
