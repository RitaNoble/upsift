# ⚡ Upsift

```
 ██╗   ██╗██████╗ ███████╗██╗███████╗████████╗
 ██║   ██║██╔══██╗██╔════╝██║██╔════╝╚══██╔══╝
 ██║   ██║██████╔╝███████╗██║█████╗     ██║
 ██║   ██║██╔═══╝ ╚════██║██║██╔══╝     ██║
 ╚██████╔╝██║     ███████║██║██║        ██║
  ╚═════╝ ╚═╝     ╚══════╝╚═╝╚═╝        ╚═╝
```

**Linux Misconfiguration & Privilege Escalation Detector**

[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-brightgreen?style=flat-square&logo=linux)](https://github.com/RitaNoble/upsift)
[![Author](https://img.shields.io/badge/Built%20by-Rita%20Noble-brightgreen?style=flat-square)](https://github.com/RitaNoble)

---

Upsift is a lightweight, modular open-source security tool that scans Linux systems for common misconfigurations and privilege escalation vectors. It tells you **what's wrong**, **why it matters**, and **how to fix it** — all from your terminal with a clean cyberpunk-styled interface.

> ⚠️ **Ethical use only.** Run only on systems you own or have explicit written permission to test.

---

## ✨ Features

- 🔍 **Modular plugin architecture** — each check is an independent, extensible plugin
- 🎨 **Cyberpunk CLI interface** — neon green ASCII banner, color-coded severity badges, animated progress bar
- 📊 **Severity levels** — `critical`, `high`, `medium`, `low`, `info`
- 📋 **Multiple output formats** — pretty table or JSON
- 💾 **Report saving** — export findings to JSON for documentation or further analysis
- 🔓 **No root required** — finds a lot as a normal user; surfaces more findings when run as root
- 📦 **Minimal dependencies** — only requires Python 3.8+ and `rich`

---

## 🖥️ What It Looks Like

When you run Upsift, you get:

- A **neon green ASCII banner** with version and author info on startup
- An **animated progress bar** showing which check is actively running
- A **color-coded findings table**:
  - 💀 `CRITICAL` — red
  - 🔴 `HIGH` — orange
  - 🟡 `MEDIUM` — yellow
  - 🔵 `LOW` — cyan
  - ⚪ `INFO` — grey
- A **scan summary panel** with counts per severity level
- A **risk verdict** — e.g. `⚠ CRITICAL RISK — Immediate action required!`
- A **footer credit** on every run

---

## 🚀 Installation

### Option 1: pipx (recommended)
```bash
pipx install git+https://github.com/RitaNoble/upsift.git
```

### Option 2: pip
```bash
git clone https://github.com/RitaNoble/upsift.git
cd upsift
pip install -e .
```

### Option 3: Virtual environment
```bash
git clone https://github.com/RitaNoble/upsift.git
cd upsift
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## 🔧 Usage

### Run a full scan
```bash
upsift run
```

### Run with JSON output
```bash
upsift run --format json
```

### Save findings to a report file
```bash
upsift run --save-report report.json
```

### List all available checks
```bash
upsift --list-checks
```

### Run only specific checks
```bash
upsift run --only docker_group,sudo_nopasswd
```

### Skip specific checks
```bash
upsift run --skip suid_binaries
```

### Full help
```bash
upsift --help
upsift run --help
```

---

## 🔍 Security Checks

| ID | Check Name | Severity | Description |
|----|-----------|----------|-------------|
| `docker_group` | User in docker group | 🔴 HIGH | Detects if the current user is in the `docker` group, which can be exploited to gain root access by mounting the host filesystem via containers |
| `path_write` | Writable PATH directories | 🔴 HIGH | Detects user-writable directories in `$PATH` and dangerous entries like `.` that enable PATH hijacking attacks |
| `sudo_nopasswd` | Sudo NOPASSWD or broad rules | 🔴 HIGH | Detects unsafe sudoers rules that allow command execution without a password or with dangerous wildcards |
| `cron_writable` | Writable cron jobs | 🔴 HIGH | Identifies writable cron job files or directories that could allow privilege escalation or persistence |
| `systemd_writable` | Writable systemd service files | 🔴 HIGH | Finds world-writable systemd unit files that allow command hijacking on service restart |
| `ssh_weak_config` | Weak SSH daemon config | 🟡 MEDIUM | Detects risky SSH daemon options such as `PermitRootLogin yes` and `PasswordAuthentication yes` |
| `suid_binaries` | SUID/SGID binaries | 🟡 MEDIUM | Finds world-accessible binaries with SUID/SGID bits set that could allow privilege escalation |

---

## 🧩 Writing Your Own Plugin

Adding a new check is simple. Create a new file in `src/upsift/plugins/your_check.py`:

```python
from upsift.checks.base import BaseCheck, Finding

class MyCheck(BaseCheck):
    id = "my_check"
    name = "My Custom Check"
    severity = "medium"
    description = "Describes what this check looks for."

    def run(self):
        findings = []
        # Your detection logic here
        findings.append(Finding(
            id=self.id,
            title="Something risky was found",
            severity=self.severity,
            description="What it is and why it matters.",
            evidence="/path/to/evidence",
            remediation="How to fix it: chmod 600 /path/to/file",
            references=["https://example.com/best-practice"]
        ))
        return findings
```

Upsift auto-discovers all plugins in the `plugins/` directory — no registration needed. Run `upsift --list-checks` to confirm your new check appears.

---

## 🗺️ Roadmap

- [ ] `check_world_writable_files` — finds world-writable files outside /tmp
- [ ] `check_weak_passwords` — detects accounts with no password set
- [ ] `check_open_ports` — flags unusual listening ports
- [ ] `check_kernel_version` — identifies outdated or known-vulnerable kernels
- [ ] `check_env_variables` — looks for secrets and API keys leaked in environment variables
- [ ] `check_crontab_hijack` — checks for user-writable scripts called by cron
- [ ] HTML report output
- [ ] Container image (Docker/Podman)
- [ ] Deb/RPM packages

---

## 🤝 Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md` before opening a PR.

- Use feature branches and open PRs with tests
- Run `pytest` locally before submitting
- Keep test coverage ≥ 80%
- Follow the existing plugin structure for new checks

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 👑 Author

**Rita Noble**
Security Researcher & Tool Developer
[github.com/RitaNoble](https://github.com/RitaNoble)

---

*Built with 💚 and a hacker mindset. Use responsibly.*
