from upsift.checks.base import BaseCheck, Finding

class SSHWeakConfigCheck(BaseCheck):
    id = "ssh_weak_config"
    name = "Weak SSH daemon config"
    severity = "medium"
    description = "Detects risky SSHD options (PermitRootLogin yes, PasswordAuthentication yes)."

    def run(self):
        findings = []
        try:
            with open("/etc/ssh/sshd_config", "r", errors="ignore") as f:
                text = f.read()
            risky = []
            for line in text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if s.lower().startswith("permitrootlogin") and "yes" in s.lower():
                    risky.append(s)
                if s.lower().startswith("passwordauthentication") and "yes" in s.lower():
                    risky.append(s)
            if risky:
                findings.append(Finding(
                    id=self.id,
                    title="Risky SSHD options found",
                    severity="medium",
                    description=self.description,
                    evidence="\n".join(risky),
                    remediation="Set PermitRootLogin no, PasswordAuthentication no (use keys), and restart sshd.",
                    references=["https://www.ssh.com/academy/ssh/sshd_config"],
                ))
        except Exception:
            pass
        return findings
