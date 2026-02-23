import pathlib
from upsift.checks.base import BaseCheck, Finding


class WeakPasswordsCheck(BaseCheck):
    id = "weak_passwords"
    name = "Accounts with no password"
    severity = "critical"
    description = (
        "Detects local user accounts that have no password set. "
        "These accounts can be switched to without any credentials, "
        "making them trivial privilege escalation targets."
    )

    def run(self):
        findings = []
        no_password = []
        shadow_unreadable = False

        # Check /etc/shadow for empty password fields
        shadow = pathlib.Path("/etc/shadow")
        if shadow.exists():
            try:
                for line in shadow.read_text(errors="ignore").splitlines():
                    parts = line.strip().split(":")
                    if len(parts) < 2:
                        continue
                    username = parts[0]
                    pw_field = parts[1]
                    # Empty password field means no password required
                    if pw_field == "" and not username.startswith("#"):
                        no_password.append(username)
            except PermissionError:
                shadow_unreadable = True

        # Fallback: check /etc/passwd for accounts with empty password (older systems)
        passwd = pathlib.Path("/etc/passwd")
        if passwd.exists():
            try:
                for line in passwd.read_text(errors="ignore").splitlines():
                    parts = line.strip().split(":")
                    if len(parts) < 2:
                        continue
                    username = parts[0]
                    pw_field = parts[1]
                    # 'x' means shadow is used, empty means truly no password
                    if pw_field == "" and username not in no_password:
                        no_password.append(username)
            except Exception:
                pass

        if no_password:
            findings.append(Finding(
                id=self.id,
                title=f"Found {len(no_password)} account(s) with no password",
                severity="critical",
                description=self.description,
                evidence="Accounts with no password:\n" + "\n".join(no_password),
                remediation=(
                    "Set a strong password immediately: 'sudo passwd <username>'. "
                    "Or lock unused accounts: 'sudo usermod -L <username>'."
                ),
                references=[
                    "https://linux.die.net/man/5/shadow",
                    "https://attack.mitre.org/techniques/T1078/",
                ],
            ))
        elif shadow_unreadable:
            findings.append(Finding(
                id=self.id,
                title="/etc/shadow not readable — run as root for full check",
                severity="info",
                description="Could not read /etc/shadow to check for empty passwords.",
                remediation="Re-run Upsift with sudo for complete password audit.",
                references=[],
            ))
        else:
            findings.append(Finding(
                id=self.id,
                title="No passwordless accounts detected",
                severity="info",
                description="All accounts appear to have passwords set.",
                remediation=None,
                references=[],
            ))

        return findings
