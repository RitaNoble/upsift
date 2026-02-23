import os, stat, glob
from upsift.checks.base import BaseCheck, Finding

class SystemdWritableCheck(BaseCheck):
    id = "systemd_writable"
    name = "Writable systemd service files"
    severity = "high"
    description = "Writable unit files allow command hijack to escalate privileges on service restart."

    def run(self):
        findings = []
        dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"]
        risky = []
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    if not f.endswith(".service"):
                        continue
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                        if st.st_mode & stat.S_IWOTH:
                            risky.append(f"World-writable: {fp}")
                    except Exception:
                        continue
        if risky:
            findings.append(Finding(
                id=self.id,
                title="Writable systemd units detected",
                severity="high",
                description=self.description,
                evidence="\n".join(risky[:50]),
                remediation="Set permissions to 0644 and owner root:root for service files.",
                references=["https://www.freedesktop.org/software/systemd/man/systemd.unit.html"],
            ))
        return findings
