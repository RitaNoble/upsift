import os, re, subprocess, getpass, pathlib
from upsift.checks.base import BaseCheck, Finding

class SudoNoPasswdCheck(BaseCheck):
    id = "sudo_nopasswd"
    name = "Sudo NOPASSWD or broad rules"
    severity = "high"
    description = "Detect unsafe sudoers rules that allow command execution without password or with wildcards."

    def run(self):
        findings = []
        user = getpass.getuser()
        # Parse /etc/sudoers and /etc/sudoers.d/*
        sudoers_paths = [pathlib.Path('/etc/sudoers')]
        sudoers_dir = pathlib.Path('/etc/sudoers.d')
        if sudoers_dir.exists():
            sudoers_paths += list(sudoers_dir.glob('*'))
        pattern = re.compile(rf'(^|\s)({user}|%\w+)\s+.*(NOPASSWD|!authenticate|ALL=\(ALL\) ALL|ALL).*', re.IGNORECASE)
        risky_lines = []
        for p in sudoers_paths:
            try:
                text = p.read_text(errors="ignore")
                for line in text.splitlines():
                    if line.strip().startswith("#"):
                        continue
                    if pattern.search(line):
                        risky_lines.append(f"{p}: {line.strip()}")
            except Exception:
                continue
        # Try 'sudo -n -l' to enumerate allowed cmds without prompting
        try:
            out = subprocess.check_output(["sudo", "-n", "-l"], text=True, stderr=subprocess.STDOUT, timeout=5)
            for line in out.splitlines():
                if "may run the following commands" in line.lower():
                    continue
                if "ALL" in line and ("(ALL)" in line or "NOPASSWD" in line):
                    risky_lines.append(f"sudo -l: {line.strip()}")
        except Exception:
            pass

        if risky_lines:
            findings.append(Finding(
                id=self.id,
                title="Unsafe sudo rules detected",
                severity="high",
                description=self.description,
                evidence="\n".join(risky_lines[:50]),
                remediation="Restrict sudo rules; avoid NOPASSWD; scope commands narrowly; use runas and exact paths.",
                references=["https://www.sudo.ws/man/1.8.31/sudoers.man.html"],
            ))
        return findings
