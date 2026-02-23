# Upsift

**Upsift** is a lightweight, modular Linux misconfiguration and privilege-escalation vector detector.  
It discovers risky settings (e.g., writable service files, SUID binaries, weak sudo rules) and explains **why they matter** plus **how to fix** them.

> Ethical use only. Run on systems you own or have explicit permission to test.

## Features (MVP)
- Modular **plugin** system — each check lives in `upsift/plugins/`
- Clear **severity** levels: `info`, `low`, `medium`, `high`, `critical`
- **CLI** with JSON or pretty table output
- Works without root (finds a lot as a normal user); elevates findings if run as root
- Self-contained Python package; minimal dependencies

## Quickstart

```bash
# 1) Clone your repo after you push this scaffold (instructions below)
# 2) Create a virtual env
python3 -m venv .venv && source .venv/bin/activate

# 3) Install in editable mode
pip install -e .

# 4) Discover available checks
upsift --list-checks

# 5) Run a scan
upsift run --format table

# 6) JSON output
upsift run --format json > report.json
```

## CLI Usage

```bash
upsift --help
upsift run --help
```

Common flags:
- `--format {table,json}`: Output format (default: `table`)
- `--only check_id1,check_id2`: Run only certain checks
- `--skip check_id1,check_id2`: Skip certain checks
- `--save-report path.json`: Save JSON report to a file
- `--list-checks`: List all checks and exit

## Plugin Anatomy

Create a new file in `upsift/plugins/your_check.py`:

```python
from upsift.checks.base import BaseCheck, Finding

class MyCheck(BaseCheck):
    id = "my_check"
    name = "My Useful Check"
    severity = "medium"
    description = "Explains what this check does"

    def run(self):
        findings = []
        # ... your logic ...
        findings.append(Finding(
            id=self.id,
            title="Something risky found",
            severity=self.severity,
            description="What/why",
            evidence="File: /path/to/file",
            remediation="Change perms: chmod 600 /path/to/file",
            references=["https://example.com/best-practice"]
        ))
        return findings
```

Then run: `upsift --list-checks` to see it.

## Roadmap
- Add more checks (kernel configs, package vulns via OS query, NFS/mount options, weak capabilities)
- HTML report output
- Self-update signatures for heuristics
- Container image and Deb/RPM packages

## Contributing
- See `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.
- Use feature branches; open PRs with tests.
- Run `pytest` locally; keep coverage ≥80%.

## License
MIT — see `LICENSE`.
