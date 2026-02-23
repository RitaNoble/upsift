import os
import re
from upsift.checks.base import BaseCheck, Finding

# Patterns that suggest a secret or credential is present
SECRET_PATTERNS = [
    (re.compile(r"(password|passwd|pwd)", re.I),       "Password"),
    (re.compile(r"(api_key|apikey|api-key)", re.I),    "API Key"),
    (re.compile(r"(secret|secret_key)", re.I),         "Secret"),
    (re.compile(r"(token|auth_token|access_token)", re.I), "Token"),
    (re.compile(r"(private_key|privkey)", re.I),       "Private Key"),
    (re.compile(r"(aws_access|aws_secret)", re.I),     "AWS Credential"),
    (re.compile(r"(database_url|db_url|db_pass)", re.I), "Database Credential"),
    (re.compile(r"(stripe|twilio|sendgrid|slack).*key", re.I), "Third-party Service Key"),
]

# Safe known variables to ignore even if they match patterns
SAFE_VARS = {
    "LS_COLORS", "TERM", "COLORTERM", "DBUS_SESSION_BUS_ADDRESS",
}

# Mask the value for display — show only first 4 chars
def _mask(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * min(len(value) - 4, 20)


class EnvVariablesCheck(BaseCheck):
    id = "env_variables"
    name = "Secrets in environment variables"
    severity = "high"
    description = (
        "Scans environment variables for accidentally exposed API keys, passwords, "
        "tokens, and credentials that could be harvested by an attacker."
    )

    def run(self):
        findings = []
        leaked = []

        for key, value in os.environ.items():
            if key in SAFE_VARS or not value.strip():
                continue
            for pattern, label in SECRET_PATTERNS:
                if pattern.search(key):
                    leaked.append(f"{label}: {key}={_mask(value)}")
                    break

        if leaked:
            findings.append(Finding(
                id=self.id,
                title=f"Found {len(leaked)} potential secret(s) in environment",
                severity="high",
                description=self.description,
                evidence="\n".join(leaked),
                remediation=(
                    "Remove secrets from environment variables. Use a secrets manager "
                    "(e.g. HashiCorp Vault, AWS Secrets Manager) or .env files "
                    "that are excluded from version control via .gitignore."
                ),
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                    "https://attack.mitre.org/techniques/T1552/",
                ],
            ))
        else:
            findings.append(Finding(
                id=self.id,
                title="No secrets detected in environment variables",
                severity="info",
                description="No environment variables matched known secret/credential patterns.",
                remediation=None,
                references=[],
            ))

        return findings
