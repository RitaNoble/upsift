import subprocess
from upsift.checks.base import BaseCheck, Finding

SUSPICIOUS_PORTS = {
    4444: "Metasploit default listener",
    5555: "Common backdoor port",
    6666: "Common backdoor port",
    7777: "Common backdoor port",
    8888: "Common backdoor/debug port",
    9999: "Common backdoor port",
    1234: "Common test/backdoor port",
    31337: "Classic elite/backdoor port",
    12345: "NetBus trojan",
    54321: "Back Orifice variant",
}


class OpenPortsCheck(BaseCheck):
    id = "open_ports"
    name = "Suspicious open ports"
    severity = "high"
    description = (
        "Detects unusual or suspicious ports listening on the system that may "
        "indicate backdoors, misconfigured services, or attacker-planted listeners."
    )

    def run(self):
        findings = []
        try:
            out = subprocess.check_output(
                ["ss", "-tlnp"],
                text=True,
                timeout=10,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            try:
                out = subprocess.check_output(
                    ["netstat", "-tlnp"],
                    text=True,
                    timeout=10,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                findings.append(Finding(
                    id=self.id,
                    title="Open ports scan failed",
                    severity="info",
                    description=str(e),
                    remediation="Ensure 'ss' or 'netstat' is available on this system.",
                    references=[],
                ))
                return findings

        flagged = []
        all_listening = []

        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("State") or line.startswith("Proto"):
                continue
            parts = line.split()
            # Extract port from address like 0.0.0.0:4444 or *:4444
            for part in parts:
                if ":" in part:
                    try:
                        port = int(part.rsplit(":", 1)[-1])
                        all_listening.append(port)
                        if port in SUSPICIOUS_PORTS:
                            flagged.append(f"Port {port} — {SUSPICIOUS_PORTS[port]}")
                    except ValueError:
                        continue

        if flagged:
            findings.append(Finding(
                id=self.id,
                title=f"Found {len(flagged)} suspicious listening port(s)",
                severity="high",
                description=self.description,
                evidence="\n".join(flagged),
                remediation=(
                    "Investigate each flagged port. Kill unknown listeners with "
                    "'kill $(lsof -t -i:<port>)' and audit running services."
                ),
                references=[
                    "https://gtfobins.github.io/",
                    "https://attack.mitre.org/techniques/T1049/",
                ],
            ))
        else:
            findings.append(Finding(
                id=self.id,
                title="No suspicious ports detected",
                severity="info",
                description=f"Scanned {len(set(all_listening))} listening port(s). None matched known suspicious ports.",
                remediation=None,
                references=[],
            ))

        return findings
