import argparse

def build_parser():
    parser = argparse.ArgumentParser(
        prog="upsift", description="Linux misconfiguration and priv-esc detector"
    )
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--only", help="Comma-separated check IDs to run", default=None)
    parser.add_argument("--skip", help="Comma-separated check IDs to skip", default=None)
    parser.add_argument("--save-report", help="Save JSON report to path", default=None)
    parser.add_argument("--list-checks", action="store_true", help="List available checks and exit")
    sub = parser.add_subparsers(dest="cmd")
    run = sub.add_parser("run", help="Run all checks (respects --only/--skip)")
    return parser
