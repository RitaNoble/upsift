# Contributing to Upsift

Thanks for your interest!

## Dev Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Guidelines
- Write small, composable plugins.
- Each plugin returns actionable remediation.
- Add tests for new code.
- Keep severities consistent.
- Avoid heavy dependencies.

## Commit style
Conventional commits preferred:
- feat:, fix:, docs:, test:, refactor:, chore:
