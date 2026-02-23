import platform
import subprocess
from upsift.checks.base import BaseCheck, Finding

# Known vulnerable kernel version prefixes mapped to CVE info
VULNERABLE_KERNELS = [
    ("5.8",  "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("5.9",  "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("5.10", "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("5.11", "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("5.12", "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("5.13", "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("5.14", "CVE-2021-4034 (PwnKit) affects kernels before 5.15.13"),
    ("4.4",  "CVE-2016-5195 (Dirty COW) — local privilege escalation"),
    ("4.5",  "CVE-2016-5195 (Dirty COW) — local privilege escalation"),
    ("4.6",  "CVE-2016-5195 (Dirty COW) — local privilege escalation"),
    ("4.7",  "CVE-2016-5195 (Dirty COW) — local privilege escalation"),
    ("4.8",  "CVE-2016-5195 (Dirty COW) — local privilege escalation"),
    ("3.",   "End-of-life kernel — no longer receives security patches"),
    ("2.",   "End-of-life kernel — no longer receives security patches"),
]


class KernelVersionCheck(BaseCheck):
    id = "kernel_version"
    name = "Kernel version & known CVEs"
    severity = "high"
    description = (
        "Checks the running kernel version against known vulnerable versions "
        "including Dirty COW (CVE-2016-5195) and PwnKit (CVE-2021-4034)."
    )

    def run(self):
        findings = []
        try:
            kernel = platform.release()
            uname = subprocess.check_output(["uname", "-a"], text=True, timeout=5).strip()

            matched_cves = []
            for prefix, note in VULNERABLE_KERNELS:
                if kernel.startswith(prefix):
                    matched_cves.append(note)

            if matched_cves:
                findings.append(Finding(
                    id=self.id,
                    title=f"Kernel {kernel} may be vulnerable",
                    severity="high",
                    description=self.description,
                    evidence="\n".join([f"Kernel: {kernel}"] + matched_cves),
                    remediation=(
                        "Update your kernel immediately: 'sudo apt update && sudo apt upgrade' "
                        "(Debian/Ubuntu) or 'sudo dnf update kernel' (RHEL/Fedora). "
                        "Reboot after updating."
                    ),
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-4034",
                        "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
                        "https://www.kernel.org/",
                    ],
                ))
            else:
                findings.append(Finding(
                    id=self.id,
                    title=f"Kernel {kernel} — no known critical CVEs matched",
                    severity="info",
                    description=f"Running kernel: {uname}",
                    remediation="Keep your kernel updated regularly as new CVEs are discovered.",
                    references=["https://www.kernel.org/"],
                ))

        except Exception as e:
            findings.append(Finding(
                id=self.id,
                title="Kernel version check failed",
                severity="info",
                description=str(e),
                remediation="Run manually: uname -a",
                references=[],
            ))

        return findings
