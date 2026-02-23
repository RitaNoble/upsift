from .cli import build_parser
from .engine import run_checks, list_checks
from rich.console import Console

def main():
    console = Console()
    parser = build_parser()
    args = parser.parse_args()

    if args.list_checks:
        checks = list_checks()
        for chk in checks:
            console.print(f"[bold]{chk.id}[/bold] - {chk.name} ({chk.severity})")
        return

    results = run_checks(only=args.only, skip=args.skip)
    if args.format == "json":
        import json
        print(json.dumps([f._asdict() for f in results], indent=2))
    else:
        # Pretty table
        from rich.table import Table
        table = Table(title="Upsift Findings")
        table.add_column("ID", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Title")
        table.add_column("Evidence")
        table.add_column("Remediation")
        for f in results:
            table.add_row(f.id, f.severity.upper(), f.title, f.evidence or "-", f.remediation or "-")
        console.print(table)

    if args.save_report:
        import json, pathlib
        path = pathlib.Path(args.save_report)
        path.write_text(json.dumps([f._asdict() for f in results], indent=2))
        console.print(f"[green]Saved report to {path}[/green]")

if __name__ == "__main__":
    main()
