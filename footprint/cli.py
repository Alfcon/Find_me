"""Command-line interface for Find My Footprint."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import webbrowser
from datetime import date, datetime, time
from pathlib import Path
from typing import Any, Iterable

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from . import __version__
from .analyze import classify_domain
from .brokers import category_label, load_catalog
from .config import (
    AppConfig,
    ConfigError,
    build_config,
    config_permission_warning,
    load_config,
    write_config,
)
from .data_points import LABELS, infer_data_points
from .db import BROKER_STATUSES, FINDING_STATUSES, Store
from .demo import run_demo
from .enrich import Enricher
from .models import Finding
from .playbook import build_plan, plan_markdown
from .queries import build_queries
from .report import render_report
from .scan import Scanner, scan_exit_code
from .search import direct_search_url, engine_label
from .util import (
    canonical_url,
    compact,
    domain_of,
    iso_now,
    safe_href,
    unwrap_redirect,
    write_private_text,
)

console = Console()
ERR_CONSOLE = Console(stderr=True)

STATUS_LABELS = {
    "new": "new",
    "confirmed": "confirmed",
    "removal_requested": "removal requested",
    "removed": "removed",
    "reappeared": "reappeared",
    "monitoring": "monitoring",
    "false_positive": "false positive",
    "not_checked": "not checked",
    "no_listing": "no listing",
    "listed": "listed",
    "blocked": "blocked",
}


def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-c", "--config", default=argparse.SUPPRESS, help="Path to profile.yaml")
    parser.add_argument("--db", default=argparse.SUPPRESS, help="Override the SQLite database path")
    parser.add_argument("-v", "--verbose", action="store_true", default=argparse.SUPPRESS, help="Show HTTP requests")
    parser.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS, help="Disable colour")
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="footprint",
        description=(
            "Find your public digital footprint and build a removal plan. "
            "Local-first, self-audit only, no automated opt-out submissions."
        ),
        epilog="Start with: footprint init, then footprint scan",
    )
    parser.add_argument("--version", action="version", version=f"Find My Footprint {__version__}")
    parser.add_argument("-c", "--config", default=None, help="Path to profile.yaml")
    parser.add_argument("--db", default=None, help="Override the SQLite database path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show HTTP requests")
    parser.add_argument("--no-color", action="store_true", help="Disable colour")
    sub = parser.add_subparsers(dest="command", metavar="command")
    common = _common_parser()

    p_init = sub.add_parser("init", help="Create a private profile.yaml")
    p_init.add_argument("--output", "-o", default="profile.yaml", help="Where to write the profile")
    p_init.add_argument("--force", action="store_true", help="Overwrite an existing profile")
    p_init.add_argument("--name", default="", help="Full name")
    p_init.add_argument("--email", action="append", default=[], help="Email address (repeatable)")
    p_init.add_argument("--phone", action="append", default=[], help="Phone number (repeatable)")
    p_init.add_argument("--username", action="append", default=[], help="Username/handle (repeatable)")
    p_init.add_argument("--address", action="append", default=[], help="Address (repeatable)")
    p_init.add_argument("--location", action="append", default=[], help="City/region (repeatable)")
    p_init.add_argument("--website", action="append", default=[], help="Website/domain (repeatable)")
    p_init.add_argument("--country", default="Australia", help="Country for removal guidance")

    p_run = sub.add_parser(
        "run",
        parents=[common],
        help="One command: create/load profile, scan, enrich pages, report, and clear profile",
    )
    p_run.add_argument("--name", default="", help="Full name")
    p_run.add_argument("--email", action="append", default=[], help="Email address (repeatable)")
    p_run.add_argument("--phone", action="append", default=[], help="Phone number (repeatable)")
    p_run.add_argument("--username", action="append", default=[], help="Username/handle (repeatable)")
    p_run.add_argument("--address", action="append", default=[], help="Address (repeatable)")
    p_run.add_argument("--location", action="append", default=[], help="City/region (repeatable)")
    p_run.add_argument("--website", action="append", default=[], help="Website/domain (repeatable)")
    p_run.add_argument("--country", default="Australia", help="Country for ABN/removal guidance")
    p_run.add_argument("--fresh", action="store_true", help="Prompt for/overwrite the profile before running")
    p_run.add_argument("--no-enrich", action="store_true", help="Skip public page fetching")
    p_run.add_argument("--enrich-limit", type=int, default=25, help="Maximum pages to fetch")
    p_run.add_argument("--max-queries", type=int, default=None, help="Cap search queries")
    p_run.add_argument("--offline", action="store_true", help="Use cached HTTP responses only")
    p_run.add_argument("--redact", action="store_true", default=None, help="Mask identifiers in the report")
    p_run.add_argument("--keep-profile", action="store_true", help="Do not clear profile.yaml at the end")
    p_run.add_argument("--open", action="store_true", help="Open the generated report")
    p_run.add_argument("-y", "--yes", action="store_true", help="Skip the network confirmation")

    p_scan = sub.add_parser("scan", parents=[common], help="Search public sources and store findings")
    p_scan.add_argument("--dry-run", action="store_true", help="Show the query plan without network access")
    p_scan.add_argument("--only", choices=["all", "search", "checks"], default="all", help="Limit the scan type")
    p_scan.add_argument("--max-queries", type=int, default=None, help="Cap the number of search queries")
    p_scan.add_argument("--offline", action="store_true", help="Use cached HTTP responses only")
    p_scan.add_argument("--enrich", action="store_true", help="Fetch each active result page for detailed evidence")
    p_scan.add_argument("--enrich-limit", type=int, default=25, help="Maximum pages to fetch during --enrich")
    p_scan.add_argument("--no-report", action="store_true", help="Do not generate the HTML report")
    p_scan.add_argument("--redact", action="store_true", default=None, help="Mask identifiers in the report")
    p_scan.add_argument(
        "--keep-profile", action="store_true", help="Do not clear profile.yaml after this run"
    )
    p_scan.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation before network access")

    p_report = sub.add_parser("report", parents=[common], help="Generate the HTML report")
    p_report.add_argument("--output", "-o", default=None, help="Report path")
    p_report.add_argument("--open", action="store_true", help="Open the report in a browser")
    p_report.add_argument("--redact", action="store_true", default=None, help="Mask identifiers")
    p_report.add_argument("--no-redact", action="store_true", help="Do not mask identifiers")
    p_report.add_argument(
        "--keep-profile", action="store_true", help="Do not clear profile.yaml after this report"
    )

    p_findings = sub.add_parser("findings", parents=[common], help="List stored findings")
    p_findings.add_argument("--status", default="all", help="new, confirmed, removal_requested, removed, reappeared, monitoring, false_positive, active, or all")
    p_findings.add_argument("--severity", default="all", choices=["all", "critical", "high", "medium", "low", "info"])
    p_findings.add_argument("--kind", default="all", help="search, profile, breach, whois, all")
    p_findings.add_argument("--category", default="all", help="Category filter")
    p_findings.add_argument("--limit", type=int, default=100)
    p_findings.add_argument("--json", action="store_true", help="Output JSON")

    p_add_url = sub.add_parser(
        "add-url", parents=[common], help="Add a result you found manually in Google/Bing"
    )
    p_add_url.add_argument("url")
    p_add_url.add_argument("--title", default=None)
    p_add_url.add_argument("--snippet", default=None)
    p_add_url.add_argument("--identifier", default=None)
    p_add_url.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None)
    p_add_url.add_argument("--status", choices=sorted(FINDING_STATUSES), default="new")
    p_add_url.add_argument("--notes", default=None)
    p_add_url.add_argument("--fetch", action="store_true", help="Fetch the page and extract detailed evidence")

    p_annotate = sub.add_parser(
        "annotate", parents=[common], help="Record fields you can see on a site manually"
    )
    p_annotate.add_argument("id", type=int)
    p_annotate.add_argument(
        "--field", action="append", default=[], metavar="KIND=VALUE",
        help="Repeatable, e.g. --field phone=+61412345678 --field employer=Example Labs",
    )
    p_annotate.add_argument("--evidence", default="", help="Where you saw it")
    p_annotate.add_argument("--possible", action="store_true", help="Mark fields as inferred, not confirmed")
    p_annotate.add_argument("--notes", default=None)

    p_enrich = sub.add_parser(
        "enrich", parents=[common], help="Fetch public result pages and extract what each site shows"
    )
    p_enrich.add_argument("ids", nargs="*", type=int, help="Finding IDs (default: all active with --all)")
    p_enrich.add_argument("--all", action="store_true", help="Enrich all active findings")
    p_enrich.add_argument("--limit", type=int, default=50, help="Maximum findings to process")
    p_enrich.add_argument("--force", action="store_true", help="Refetch pages already enriched")
    p_enrich.add_argument("--no-report", action="store_true", help="Do not regenerate the report")
    p_enrich.add_argument(
        "--keep-profile", action="store_true", help="Do not clear profile.yaml after this run"
    )

    p_show = sub.add_parser("show", parents=[common], help="Show one finding in detail")
    p_show.add_argument("id", type=int)
    p_show.add_argument("--json", action="store_true", help="Output the raw JSON record")

    p_update = sub.add_parser("update", parents=[common], help="Update a finding's status or notes")
    p_update.add_argument("id", type=int)
    p_update.add_argument("--status", required=True, choices=sorted(FINDING_STATUSES))
    p_update.add_argument("--notes", default=None, help="Add a note")
    p_update.add_argument("--replace-notes", action="store_true", help="Replace existing notes instead of appending")

    p_brokers = sub.add_parser("brokers", parents=[common], help="List removal directory entries")
    p_brokers.add_argument("--region", default=None, help="AU, US, UK, GLOBAL")
    p_brokers.add_argument("--status", default="all", help="Filter by tracking status")
    p_brokers.add_argument("--json", action="store_true")

    p_broker_update = sub.add_parser("broker-update", parents=[common], help="Track a broker opt-out")
    p_broker_update.add_argument("broker_id")
    p_broker_update.add_argument("--status", required=True, choices=sorted(BROKER_STATUSES))
    p_broker_update.add_argument("--notes", default=None)
    p_broker_update.add_argument("--due", default=None, help="Follow-up date YYYY-MM-DD")

    p_searches = sub.add_parser(
        "searches", parents=[common], help="Print exact Google/Bing/DuckDuckGo search links"
    )
    p_searches.add_argument("--max-queries", type=int, default=None)
    p_searches.add_argument("--json", action="store_true")

    p_plan = sub.add_parser("plan", parents=[common], help="Print the prioritised removal plan")
    p_plan.add_argument("--format", choices=["markdown", "text"], default="text")
    p_plan.add_argument("--limit", type=int, default=None)
    p_plan.add_argument("--output", "-o", default=None, help="Write the plan to a file")

    p_export = sub.add_parser("export", parents=[common], help="Export findings as JSON or CSV")
    p_export.add_argument("--format", choices=["json", "csv"], default="json")
    p_export.add_argument("--output", "-o", default=None, help="Output file (default: stdout)")
    p_export.add_argument("--status", default="all")

    p_demo = sub.add_parser("demo", help="Generate a safe demo report with sample data")
    p_demo.add_argument("--output", "-o", default="reports/demo-report.html")
    p_demo.add_argument("--open", action="store_true")

    p_doctor = sub.add_parser("doctor", parents=[common], help="Check the local setup")
    p_doctor.add_argument("--network", action="store_true", help="Test a search-engine connection")
    return parser


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    console.print(
        Panel(
            "Your profile stays on this machine. It is written with owner-only permissions "
            "and is used only for searches you explicitly run.\n\n"
            "Use identifiers you are authorised to investigate — your own, or someone who has "
            "asked you to help. The more exact the identifiers, the fewer false positives.",
            title="Private by default",
            border_style="green",
        )
    )
    name = args.name
    emails = list(args.email)
    phones = list(args.phone)
    usernames = list(args.username)
    addresses = list(args.address)
    locations = list(args.location)
    websites = list(args.website)
    country = args.country

    if sys.stdin.isatty() and not any([name, emails, phones, usernames, addresses]):
        console.print("\n[bold]Create your profile[/bold] (press Enter to skip optional fields)\n")
        name = input("Full name: ").strip() or name
        emails = _prompt_list("Email addresses (comma separated): ") or emails
        phones = _prompt_list("Phone numbers (comma separated): ") or phones
        usernames = _prompt_list("Usernames / handles (comma separated): ") or usernames
        addresses = _prompt_list("Street addresses (separate multiple with ;): ", split_commas=False) or addresses
        locations = _prompt_list("City / region (separate multiple with ;): ", split_commas=False) or locations
        websites = _prompt_list("Websites or domains (comma separated, optional): ") or websites
        entered_country = input(f"Country [{country}]: ").strip()
        if entered_country:
            country = entered_country

    if not any([name, emails, phones, usernames, addresses]):
        raise ConfigError(
            "No identifiers supplied. Use --name/--email/--username or run from an interactive terminal."
        )
    raw = build_config(
        name=name,
        emails=emails,
        phones=phones,
        usernames=usernames,
        addresses=addresses,
        locations=locations,
        websites=websites,
        country=country,
    )
    output = Path(args.output).expanduser()
    if not output.is_absolute():
        output = (Path.cwd() / output).resolve()
    path = write_config(output, raw, force=args.force)
    # Load it immediately so a bad value fails at creation time, not at scan time.
    loaded = load_config(path)
    console.print(f"\n[green]✓[/green] Profile written to [bold]{escape(str(path))}[/bold]")
    console.print(
        f"  [dim]{len(loaded.profile.emails)} email(s), {len(loaded.profile.phones)} phone(s), "
        f"{len(loaded.profile.usernames)} username(s), {len(loaded.profile.locations)} location(s)[/dim]"
    )
    if not getattr(args, "for_run", False):
        console.print("\nNext: [bold]python -m footprint scan --dry-run[/bold] to preview the queries.")
        console.print("Then: [bold]python -m footprint scan[/bold]")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """One-command workflow used by the quickstart.

    If the profile is absent (or --fresh is used), ask for identifiers and
    write it. Then delegate to the existing scan pipeline, which also performs
    optional page enrichment, writes the named report, and clears the profile
    unless --keep-profile is set.
    """
    config_path = Path(args.config).expanduser() if getattr(args, "config", None) else (Path.cwd() / "profile.yaml")
    if not config_path.is_absolute():
        config_path = (Path.cwd() / config_path).resolve()
    supplied = any(
        [
            args.name,
            args.email,
            args.phone,
            args.username,
            args.address,
            args.location,
            args.website,
        ]
    )
    if args.fresh or not config_path.exists():
        if config_path.exists() and not args.fresh:
            pass
        init_args = argparse.Namespace(
            output=str(config_path),
            force=True,
            name=args.name,
            email=args.email,
            phone=args.phone,
            username=args.username,
            address=args.address,
            location=args.location,
            website=args.website,
            country=args.country,
            for_run=True,
        )
        code = cmd_init(init_args)
        if code != 0:
            return code
    elif supplied:
        console.print(
            "[yellow]A profile already exists.[/yellow] Re-run with [bold]--fresh[/bold] "
            "to replace it, or remove the flags to use the existing profile."
        )
        return 2
    scan_args = argparse.Namespace(
        config=str(config_path),
        db=getattr(args, "db", None),
        verbose=getattr(args, "verbose", False),
        no_color=getattr(args, "no_color", False),
        dry_run=False,
        only="all",
        max_queries=args.max_queries,
        offline=args.offline,
        enrich=not args.no_enrich,
        enrich_limit=args.enrich_limit,
        no_report=False,
        redact=args.redact,
        keep_profile=args.keep_profile,
        yes=args.yes,
    )
    code = cmd_scan(scan_args)
    if code == 0 and args.open:
        report = _latest_report()
        if report:
            _open(report)
    return code


def cmd_scan(args: argparse.Namespace) -> int:
    config = _load(args)
    warning = config_permission_warning(config.path)
    if warning:
        console.print(f"[yellow]Warning:[/yellow] {escape(warning)}")
    store = None if args.dry_run else Store(config.db_path)
    scanner = Scanner(
        config,
        store,
        offline=args.offline,
        logger=(lambda message: console.print(f"[dim]{escape(message)}[/dim]")) if _verbose(args) else None,
        on_event=_scan_event,
    )
    try:
        queries = scanner.plan(args.max_queries)
        if not queries and args.only in {"all", "search"}:
            console.print("[yellow]No search queries can be generated from this profile.[/yellow]")
            if args.only == "search":
                return 2
        _print_scan_plan(config, queries if args.only != "checks" else [], scanner)
        if args.only == "checks":
            console.print("[dim]Checks-only run: no web search queries will be sent.[/dim]")
        if args.dry_run:
            console.print("\n[bold]Dry run:[/bold] no requests were made and no database was created.")
            return 0
        if config.checks.breaches and not config.api_keys.get("hibp") and config.checks.xposedornot:
            console.print(
                "[yellow]Breach source:[/yellow] HIBP_API_KEY is not set, so the free "
                "XposedOrNot index will receive your email for breach checks. "
                "Set `checks.xposedornot: false` to disable it."
            )
        if not args.yes and sys.stdin.isatty():
            console.print(
                "\n[bold yellow]Network note[/bold yellow]: your identifiers will be sent to "
                f"{', '.join(engine_label(engine) for engine in config.search.engines)}. "
                "Use a VPN if your IP address is sensitive."
            )
            if not Confirm.ask("Continue with the scan?", default=True):
                console.print("Cancelled.")
                return 0
        result = scanner.run(only=args.only, max_queries=args.max_queries)
        _print_scan_result(store, result, config, scanner)
        if result.ok and args.enrich:
            console.print("\n[bold]Fetching public result pages for detailed evidence…[/bold]")
            enricher = Enricher(
                config,
                store,
                http=scanner.http,
                on_progress=lambda line: console.print(f"[dim]{escape(line)}[/dim]"),
            )
            try:
                summary = enricher.enrich_many(limit=args.enrich_limit, status="active")
                console.print(
                    f"Enriched [bold]{summary.enriched}[/bold] · skipped {summary.skipped} · "
                    f"failed {summary.failed}"
                )
            finally:
                enricher.close()
        if result.ok and not args.no_report:
            if store is None:
                raise RuntimeError("internal error: no database for report generation")
            output = render_report(store, config, redact=args.redact)
            console.print(f"\n[green]✓[/green] Report written to [bold]{escape(str(output))}[/bold]")
            console.print(f"  Open it with: [dim]python -m footprint report --open[/dim]")
            _clear_profile(config, args.keep_profile)
        elif result.ok:
            _clear_profile(config, args.keep_profile)
        return scan_exit_code(result)
    finally:
        scanner.close()
        if store is not None:
            store.close()


def cmd_report(args: argparse.Namespace) -> int:
    try:
        config = _load(args)
    except ConfigError:
        if args.open:
            existing = _latest_report()
            if existing:
                console.print(f"[green]✓[/green] Opening existing report [bold]{escape(str(existing))}[/bold]")
                _open(existing)
                return 0
        raise
    store = Store(config.db_path)
    try:
        redact = True if args.redact else (False if args.no_redact else None)
        output = render_report(store, config, output_path=args.output, redact=redact)
    finally:
        store.close()
    console.print(f"[green]✓[/green] Report written to [bold]{escape(str(output))}[/bold]")
    console.print(f"  {output.stat().st_size // 1024} KB · owner-only permissions where supported")
    if args.open:
        _open(output)
    _clear_profile(config, args.keep_profile)
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    config = _load(args)
    store = Store(config.db_path)
    try:
        findings = store.list_findings(
            status=args.status,
            severity=args.severity,
            kind=args.kind,
            category=args.category,
            limit=args.limit,
        )
        if args.json:
            console.print_json(data=findings)
            return 0
        if not findings:
            console.print("[dim]No findings match those filters.[/dim]")
            return 0
        table = Table(title=f"Stored findings ({len(findings)})", show_lines=False)
        table.add_column("ID", justify="right", style="dim", no_wrap=True)
        table.add_column("Risk", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Finding", overflow="fold")
        table.add_column("Source", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        for finding in findings:
            table.add_row(
                str(finding["id"]),
                _severity_text(finding["severity"]),
                escape(category_label(finding["category"])),
                escape(compact(finding["title"], 90)),
                escape(finding["source"]),
                escape(STATUS_LABELS.get(finding["status"], finding["status"])),
            )
        console.print(table)
        return 0
    finally:
        store.close()


def cmd_add_url(args: argparse.Namespace) -> int:
    config = _load(args)
    raw_url = args.url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raise ConfigError("URL must start with http:// or https://")
    url = safe_href(unwrap_redirect(raw_url))
    if not url:
        raise ConfigError("URL is not a safe public http(s) URL")
    store = Store(config.db_path)
    try:
        existing = store.find_by_url(url)
        if existing:
            console.print(
                f"[yellow]Already tracked:[/yellow] finding #{existing['id']} — "
                f"{escape(existing['title'])}"
            )
            return 0
        title = args.title
        snippet = args.snippet or ""
        host = domain_of(url)
        catalog = load_catalog()
        category, broker_id = classify_domain(host, catalog)
        if not title:
            title = f"{host}{url.split(host, 1)[-1] if host in url else ''}"
        if not args.identifier:
            identifier = config.profile.display_name
            identifier_type = "name"
            if not identifier and config.profile.emails:
                identifier = config.profile.emails[0]
                identifier_type = "email"
        else:
            identifier = args.identifier
            identifier_type = "manual"
        severity = args.severity
        if not severity:
            severity = {
                "data_broker": "high",
                "public_record": "medium",
                "social": "low",
                "code": "low",
                "professional": "low",
                "news": "medium",
                "forum": "low",
            }.get(category, "medium")
        finding = Finding(
            kind="manual",
            category=category,
            source="Manual URL",
            title=title or host,
            url=url,
            snippet=snippet,
            identifier=identifier or "",
            identifier_type=identifier_type,
            severity=severity,
            confidence=1.0,
            matched="manually added",
            details={
                "provider": "manual",
                "domain": host,
                "broker_id": broker_id,
                "reason": "Added manually after a browser search; verify identity and context",
                "reasons": ["Manually added from a URL you supplied"],
            },
        )
        finding_id, _is_new, _reappeared = store.upsert_finding(finding, None)
        if args.status != "new" or args.notes:
            store.update_finding(finding_id, status=args.status, notes=args.notes)
        console.print(
            f"[green]✓[/green] Added finding #{finding_id}: {escape(finding.title)} "
            f"[dim]({category_label(category)})[/dim]"
        )
        if args.fetch:
            enricher = Enricher(config, store, on_progress=lambda line: console.print(f"[dim]{escape(line)}[/dim]"))
            try:
                result = enricher.enrich_finding(finding_id, force=True)
                if result.ok:
                    console.print(
                        f"  Extracted {len(result.points)} data point(s) and {len(result.excerpts)} excerpt(s) "
                        "from the public page."
                    )
                else:
                    console.print(f"  [yellow]Page enrichment:[/yellow] {escape(result.error)}")
            finally:
                enricher.close()
        if broker_id:
            broker = catalog.get(broker_id)
            if broker:
                console.print(f"  Opt-out guide: {escape(broker.optout_url)}")
        console.print("  Regenerate the report with: [bold]footprint report --open[/bold]")
        return 0
    finally:
        store.close()


def cmd_annotate(args: argparse.Namespace) -> int:
    config = _load(args)
    fields: list[tuple[str, str]] = []
    for raw in args.field:
        kind, separator, value = raw.partition("=")
        kind = kind.strip().casefold()
        if not separator or not kind or not value.strip():
            raise ConfigError("--field must be KIND=VALUE, e.g. --field phone=+61412345678")
        if kind not in LABELS:
            raise ConfigError(
                f"Unknown field kind '{kind}'. Use one of: {', '.join(sorted(LABELS))}"
            )
        fields.append((kind, value.strip()))
    if not fields and not args.notes:
        raise ConfigError("Add at least one --field or --notes")
    store = Store(config.db_path)
    try:
        finding = store.get_finding(args.id)
        if not finding:
            raise ConfigError(f"No finding with id {args.id}")
        details = finding.get("details") or {}
        existing = details.get("data_points")
        if not isinstance(existing, list):
            existing = []
        merged = {
            (str(item.get("kind")), str(item.get("value") or "").casefold()): item
            for item in existing
            if isinstance(item, dict)
        }
        for kind, value in fields:
            merged[(kind, value.casefold())] = {
                "kind": kind,
                "label": LABELS[kind],
                "value": value,
                "evidence": args.evidence or "Manually recorded from the site",
                "confidence": 0.6 if args.possible else 0.95,
                "source": "manual annotation",
                "observed": not args.possible,
            }
        details["data_points"] = list(merged.values())[:40]
        details["manual_notes"] = args.evidence or details.get("manual_notes", "")
        store.update_finding_details(args.id, details)
        if args.notes:
            store.update_finding(args.id, notes=args.notes)
        console.print(
            f"[green]✓[/green] Recorded {len(fields)} field(s) on finding #{args.id}. "
            "Regenerate the report with [bold]footprint report --open[/bold]."
        )
        return 0
    finally:
        store.close()


def cmd_enrich(args: argparse.Namespace) -> int:
    config = _load(args)
    if not args.ids and not args.all:
        raise ConfigError("Specify one or more finding IDs, or use --all")
    store = Store(config.db_path)
    enricher = Enricher(
        config,
        store,
        on_progress=lambda line: console.print(f"[dim]{escape(line)}[/dim]"),
    )
    try:
        summary = enricher.enrich_many(
            finding_ids=args.ids or None,
            limit=args.limit,
            force=args.force,
            status="active",
        )
        table = Table(title="Page enrichment")
        table.add_column("ID", justify="right", style="dim")
        table.add_column("Status")
        table.add_column("Page")
        table.add_column("Data points", justify="right")
        table.add_column("Note", overflow="fold")
        for result in summary.results:
            table.add_row(
                str(result.finding_id),
                result.status,
                escape(compact(result.title or result.url, 70)),
                str(len(result.points)),
                escape(compact(result.error, 120)),
            )
        console.print(table)
        console.print(
            f"Enriched [bold]{summary.enriched}[/bold] · skipped {summary.skipped} · failed {summary.failed}"
        )
        if not args.no_report:
            output = render_report(store, config)
            console.print(f"[green]✓[/green] Report updated: {escape(str(output))}")
            _clear_profile(config, args.keep_profile)
        return 0
    finally:
        enricher.close()
        store.close()


def cmd_show(args: argparse.Namespace) -> int:
    config = _load(args)
    store = Store(config.db_path)
    try:
        finding = store.get_finding(args.id)
        if not finding:
            raise ConfigError(f"No finding with id {args.id}")
        if args.json:
            console.print_json(data=finding)
            return 0
        _print_finding_detail(finding, config)
        return 0
    finally:
        store.close()


def _print_finding_detail(finding: dict[str, Any], config: AppConfig) -> None:
    details = finding.get("details") or {}
    console.print(
        Panel(
            f"[bold]{escape(finding.get('title') or 'Untitled')}[/bold]\n"
            f"{_severity_text(finding.get('severity', 'medium'))} · "
            f"{escape(category_label(finding.get('category', '')))} · "
            f"{escape(str(finding.get('status') or ''))}\n"
            f"[dim]{escape(finding.get('url') or '')}[/dim]",
            border_style="green",
        )
    )
    points = infer_data_points(finding, config.profile)
    if points:
        table = Table(title="What this source appears to show")
        table.add_column("Data type")
        table.add_column("Value", overflow="fold")
        table.add_column("Observed")
        table.add_column("Confidence", justify="right")
        for point in points:
            table.add_row(
                escape(point.label),
                escape(point.value or "—"),
                "yes" if point.observed else "possible",
                f"{int(point.confidence * 100)}%",
            )
        console.print(table)
    breaches = details.get("breaches")
    if isinstance(breaches, list) and breaches:
        table = Table(title="Breach detail")
        table.add_column("Breach")
        table.add_column("Date")
        table.add_column("Records", justify="right")
        table.add_column("Data exposed", overflow="fold")
        for breach in breaches[:20]:
            if isinstance(breach, dict):
                table.add_row(
                    escape(str(breach.get("breach") or breach.get("name") or "—")),
                    escape(str(breach.get("date") or "—")),
                    escape(str(breach.get("records") or "—")),
                    escape(", ".join(map(str, breach.get("data") or []))),
                )
        console.print(table)
    enrichment = details.get("enrichment")
    if isinstance(enrichment, dict):
        if enrichment.get("status") == "ok":
            console.print(
                f"[green]Public page read:[/green] {escape(str(enrichment.get('fetched_at') or ''))}"
            )
            fields = enrichment.get("fields") or {}
            if fields:
                table = Table(title="Fields extracted from the page")
                table.add_column("Field")
                table.add_column("Value", overflow="fold")
                for key, value in list(fields.items())[:15]:
                    table.add_row(escape(str(key)), escape(str(value)))
                console.print(table)
            for excerpt in (enrichment.get("excerpts") or [])[:4]:
                console.print(f"[dim]“{escape(str(excerpt))}”[/dim]")
        else:
            console.print(
                f"[yellow]Page enrichment:[/yellow] "
                f"{escape(str(enrichment.get('http_error') or enrichment.get('status') or ''))}"
            )
    if details.get("exposed_fields"):
        console.print(f"[bold]Exposed WHOIS fields[/bold]: {escape(str(details['exposed_fields']))}")
    if details.get("reasons"):
        console.print("[bold]Why it was flagged[/bold]")
        for reason in details["reasons"][:10]:
            console.print(f"  • {escape(str(reason))}")
    if finding.get("notes"):
        console.print(f"[bold]Notes[/bold]\n{escape(finding['notes'])}")


def cmd_update(args: argparse.Namespace) -> int:
    config = _load(args)
    store = Store(config.db_path)
    try:
        updated = store.update_finding(
            args.id,
            status=args.status,
            notes=args.notes,
            append_note=not args.replace_notes,
        )
        if not updated:
            raise ConfigError(f"No finding with id {args.id}")
        console.print(
            f"[green]✓[/green] Finding {args.id}: {STATUS_LABELS.get(updated['status'], updated['status'])}"
        )
        if updated.get("notes"):
            console.print(f"[dim]{escape(updated['notes'])}[/dim]")
        return 0
    finally:
        store.close()


def cmd_brokers(args: argparse.Namespace) -> int:
    config = _load(args)
    store = Store(config.db_path)
    try:
        catalog = load_catalog()
        statuses = store.get_broker_statuses()
        brokers = catalog.filter_regions(config.brokers.regions)
        if args.region:
            wanted = args.region.upper()
            brokers = [broker for broker in brokers if wanted in broker.regions]
        rows = []
        for broker in brokers:
            status = statuses.get(broker.id, {}).get("status", "not_checked")
            if args.status != "all" and status != args.status:
                continue
            rows.append(
                {
                    "id": broker.id,
                    "name": broker.name,
                    "regions": broker.regions,
                    "category": broker.category,
                    "status": status,
                    "method": broker.method,
                    "minutes": broker.minutes,
                    "optout_url": broker.optout_url,
                    "notes": broker.notes,
                }
            )
        if args.json:
            console.print_json(data=rows)
            return 0
        table = Table(title="Removal directory")
        table.add_column("ID", no_wrap=True, style="dim")
        table.add_column("Service", overflow="fold")
        table.add_column("Region", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Process", overflow="fold")
        for row in rows:
            table.add_row(
                escape(row["id"]),
                escape(row["name"]),
                escape(", ".join(row["regions"])),
                escape(STATUS_LABELS.get(row["status"], row["status"])),
                escape(f"{row['method']} · ~{row['minutes']} min"),
            )
        console.print(table)
        console.print("[dim]Track one with: python -m footprint broker-update <id> --status listed[/dim]")
        return 0
    finally:
        store.close()


def cmd_broker_update(args: argparse.Namespace) -> int:
    config = _load(args)
    catalog = load_catalog()
    broker = catalog.get(args.broker_id)
    if not broker:
        raise ConfigError(f"Unknown broker id: {args.broker_id}. Run `python -m footprint brokers`.")
    due = _parse_due(args.due)
    store = Store(config.db_path)
    try:
        row = store.update_broker(args.broker_id, args.status, notes=args.notes, due_at=due)
        console.print(
            f"[green]✓[/green] {escape(broker.name)}: {escape(STATUS_LABELS.get(row['status'], row['status']))}"
        )
        return 0
    finally:
        store.close()


def cmd_searches(args: argparse.Namespace) -> int:
    config = _load(args)
    query_limit = args.max_queries or config.search.max_queries
    queries = build_queries(
        config.profile,
        config.search,
        load_catalog().filter_regions(config.brokers.regions),
    )[: max(0, query_limit)]
    rows = []
    for query in queries:
        rows.append(
            {
                "label": query.label,
                "query": query.text,
                "purpose": query.purpose,
                "google": direct_search_url("google", query.text, config.search.region),
                "bing": direct_search_url("bing", query.text, config.search.region),
                "duckduckgo": direct_search_url("duckduckgo", query.text, config.search.region),
            }
        )
    if args.json:
        sys.stdout.write(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
        return 0
    if not rows:
        console.print("[dim]No search queries can be generated from this profile.[/dim]")
        return 0
    table = Table(title="Manual searches — open these in your browser")
    table.add_column("#", justify="right", style="dim", no_wrap=True)
    table.add_column("Query", overflow="fold")
    table.add_column("Open in", overflow="fold")
    for index, row in enumerate(rows, 1):
        links = "\n".join(
            f"{label}: {url}"
            for label, url in [
                ("Google", row["google"]),
                ("Bing", row["bing"]),
                ("DDG", row["duckduckgo"]),
            ]
        )
        table.add_row(str(index), escape(row["query"]), escape(links))
    console.print(table)
    console.print(
        "[dim]These are ordinary search URLs, not API calls. Open them in a private "
        "window, then add worthwhile results to your removal plan manually.[/dim]"
    )
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    config = _load(args)
    store = Store(config.db_path)
    try:
        plan = build_plan(store, config, load_catalog())
        markdown = plan_markdown(plan, limit=args.limit)
        if args.output:
            output = Path(args.output).expanduser()
            if not output.is_absolute():
                output = (Path.cwd() / output).resolve()
            write_private_text(output, markdown)
            console.print(f"[green]✓[/green] Plan written to [bold]{escape(str(output))}[/bold]")
            return 0
        if args.format == "markdown":
            console.print(markdown, markup=False)
            return 0
        _print_plan_rich(plan)
        return 0
    finally:
        store.close()


def cmd_export(args: argparse.Namespace) -> int:
    config = _load(args)
    store = Store(config.db_path)
    try:
        findings = store.list_findings(status=args.status, limit=100000)
        plan = build_plan(store, config, load_catalog())
        stats = store.stats()
        if args.format == "json":
            payload = {
                "generated_at": iso_now(),
                "tool": f"Find My Footprint {__version__}",
                "profile": config.public_summary(redact=False),
                "stats": stats,
                "findings": findings,
                "plan": plan.as_dict(),
            }
            content = json.dumps(payload, ensure_ascii=False, indent=2)
        else:
            content = _findings_csv(findings, config.profile)
        if args.output:
            output = Path(args.output).expanduser()
            if not output.is_absolute():
                output = (Path.cwd() / output).resolve()
            write_private_text(output, content)
            console.print(f"[green]✓[/green] Exported to [bold]{escape(str(output))}[/bold]")
        else:
            sys.stdout.write(content)
            if not content.endswith("\n"):
                sys.stdout.write("\n")
        return 0
    finally:
        store.close()


def cmd_demo(args: argparse.Namespace) -> int:
    output = Path(args.output).expanduser()
    if not output.is_absolute():
        output = (Path.cwd() / output).resolve()
    path = run_demo(Path.cwd(), output)
    console.print(f"[green]✓[/green] Demo report written to [bold]{escape(str(path))}[/bold]")
    console.print("[dim]The demo uses reserved example.com data. It does not touch your profile or database.[/dim]")
    if args.open:
        _open(path)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    rows: list[tuple[str, str, str]] = []
    rows.append(("Python", "OK", f"{sys.version.split()[0]}"))
    for module in ("requests", "bs4", "yaml", "rich"):
        try:
            __import__(module)
            rows.append((f"dependency: {module}", "OK", "installed"))
        except ImportError:
            rows.append((f"dependency: {module}", "MISSING", "pip install -r requirements.txt"))
    try:
        config = _load(args)
        rows.append(("profile", "OK", str(config.path)))
        warning = config_permission_warning(config.path)
        rows.append(("profile permissions", "WARN" if warning else "OK", warning or "owner-only"))
        derived = config.profile.derived_usernames
        rows.append(
            (
                "identifiers",
                "OK",
                f"{len(config.profile.emails)} email, {len(config.profile.phones)} phone, "
                f"{len(config.profile.usernames)} username"
                + (f" (+{len(derived)} derived from email)" if derived else ""),
            )
        )
        if not config.profile.locations:
            rows.append(
                (
                    "location",
                    "WARN",
                    "No city/region set; name-only matches will be low-confidence. "
                    "Add `locations` to profile.yaml for better results.",
                )
            )
        keys = config.api_keys
        rows.append(("HIBP key", "OK" if keys["hibp"] else "OPTIONAL", "set HIBP_API_KEY to check breaches"))
        rows.append(("GitHub token", "OK" if keys["github"] else "OPTIONAL", "set GITHUB_TOKEN for a higher rate limit"))
        rows.append(("Brave API", "OK" if keys["brave"] else "OPTIONAL", "set BRAVE_SEARCH_API_KEY"))
        rows.append(
            (
                "Google CSE",
                "OK" if keys["google_cse_key"] and keys["google_cse_id"] else "OPTIONAL",
                "set GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID",
            )
        )
        rows.append(("SerpAPI", "OK" if keys["serpapi"] else "OPTIONAL", "set SERPAPI_API_KEY"))
        rows.append(("Serper", "OK" if keys["serper"] else "OPTIONAL", "set SERPER_API_KEY (free tier available)"))
        rows.append(("database", "OK", str(config.db_path) if config.db_path.exists() else "created on first scan"))
        if args.network:
            from .http import HttpClient

            client = HttpClient(config.cache_dir, min_interval=1)
            try:
                response = client.get(
                    "https://html.duckduckgo.com/html/",
                    params={"q": "privacy"},
                    ttl=0,
                )
                status = "OK" if response.status == 200 and "result" in response.text else "WARN"
                rows.append(("network: DuckDuckGo", status, f"HTTP {response.status}"))
            except Exception as exc:
                rows.append(("network: DuckDuckGo", "FAIL", type(exc).__name__))
            finally:
                client.close()
    except ConfigError as exc:
        rows.append(("profile", "MISSING", str(exc).splitlines()[0]))
    table = Table(title="Find My Footprint setup")
    table.add_column("Check")
    table.add_column("State")
    table.add_column("Detail", overflow="fold")
    for check, state, detail in rows:
        style = {"OK": "green", "OPTIONAL": "dim", "WARN": "yellow", "FAIL": "red", "MISSING": "red"}.get(state, "")
        table.add_row(escape(check), Text(state, style=style), escape(detail))
    console.print(table)
    return 0


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _clear_profile(config: AppConfig, keep: bool = False) -> None:
    if keep:
        console.print("[dim]Profile kept because --keep-profile was used.[/dim]")
        return
    path = config.path
    if not path.exists():
        return
    try:
        path.unlink()
        console.print(
            f"[dim]Profile cleared: {escape(str(path))}. "
            "The local database and generated report remain. Re-run "
            "`footprint init` before another scan.[/dim]"
        )
    except OSError as exc:
        console.print(f"[yellow]Could not clear profile:[/yellow] {escape(str(exc))}")


def _latest_report() -> Path | None:
    roots = [Path.cwd() / "reports", Path.cwd()]
    candidates = []
    for root in roots:
        if root.exists():
            candidates.extend(root.glob("*footprint-report.html"))
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _load(args: argparse.Namespace) -> AppConfig:
    return load_config(getattr(args, "config", None), getattr(args, "db", None))


def _verbose(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "verbose", False))


def _prompt_list(prompt: str, split_commas: bool = True) -> list[str]:
    raw = input(prompt).strip()
    if not raw:
        return []
    if split_commas:
        parts = raw.replace(";", ",").split(",")
    else:
        parts = raw.replace(";", "\n").splitlines()
    return [part.strip() for part in parts if part.strip()]


def _severity_text(severity: str) -> Text:
    style = {
        "critical": "bold red",
        "high": "bold dark_orange",
        "medium": "yellow",
        "low": "green",
        "info": "dim",
    }.get(severity, "")
    return Text(severity.upper(), style=style)


def _scan_event(event: dict[str, Any]) -> None:
    stage = event.get("stage")
    if stage == "search":
        current = event.get("current")
        total = event.get("total")
        if current and total:
            console.print(f"[dim]\\[{current}/{total}][/dim] {escape(event.get('message', ''))}")
    elif stage == "checks":
        console.print(f"[dim]{escape(event.get('message', ''))}[/dim]")


def _print_scan_plan(config: AppConfig, queries, scanner: Scanner) -> None:
    console.print(
        Panel(
            f"[bold]{escape(config.profile.display_name or 'Unnamed profile')}[/bold]\n"
            f"{len(config.profile.emails)} email(s) · {len(config.profile.phones)} phone(s) · "
            f"{len(config.profile.usernames)} username(s) · {len(config.profile.addresses)} address(es)\n"
            f"[dim]Search: {', '.join(engine_label(engine) for engine in config.search.engines)} · "
            f"{len(queries)} queries · {config.search.delay_seconds}s delay · region {config.search.region}"
            + (
                f" · fallback {engine_label(scanner.search.fallback_engine)}"
                if scanner.search.fallback_engine
                else ""
            )
            + "[/dim]",
            title="Scan plan",
            border_style="green",
        )
    )
    if not config.profile.locations:
        console.print(
            "[yellow]No city/region configured.[/yellow] Name-only matches will be "
            "low-confidence. Add `locations` to profile.yaml to improve matching."
        )
    if queries:
        table = Table(show_header=True, header_style="dim")
        table.add_column("#", justify="right", no_wrap=True)
        table.add_column("Identifier", no_wrap=True)
        table.add_column("Search query", overflow="fold")
        table.add_column("Purpose", no_wrap=True, style="dim")
        for index, query in enumerate(queries, 1):
            table.add_row(
                str(index),
                escape(query.identifier_type),
                escape(query.text),
                escape(query.purpose),
            )
        console.print(table)
    else:
        console.print("[dim]No web search queries (checks-only or no search identifiers).[/dim]")
    for engine, ok, reason in scanner.search.availability():
        style = "green" if ok else "yellow"
        console.print(f"  [{style}]{escape(engine_label(engine))}[/{style}] {escape(reason)}")


def _print_scan_result(store: Store, result, config: AppConfig, scanner: Scanner) -> None:
    stats = result.stats
    stats_table = Table(title="Scan summary", show_header=False)
    stats_table.add_column("Metric", style="dim")
    stats_table.add_column("Value", justify="right")
    stats_table.add_row("Queries run", str(stats.queries_run))
    stats_table.add_row("Results matched", str(stats.results_matched))
    stats_table.add_row("New findings", str(stats.new_findings))
    stats_table.add_row("Updated findings", str(stats.updated_findings))
    stats_table.add_row("Requests", str(stats.requests))
    stats_table.add_row("Errors", str(stats.errors))
    console.print(stats_table)

    current = store.stats()
    console.print(
        f"\n[bold]Exposure score: {current['score']}/100 ({escape(current['band'])})[/bold] · "
        f"{current['active']} active · {current['by_severity'].get('critical', 0)} critical · "
        f"{current['by_severity'].get('high', 0)} high"
    )
    warnings = [note for note in stats.notes if note.level in {"warning", "error"}]
    for note in warnings[:8]:
        colour = "red" if note.level == "error" else "yellow"
        console.print(f"  [{colour}]{escape(note.kind)}:[/{colour}] {escape(note.message)}")
    if len(warnings) > 8:
        console.print(f"  [dim]…and {len(warnings) - 8} more notes in the database run log.[/dim]")


def _print_plan_rich(plan) -> None:
    console.print(
        Panel(
            f"{plan.summary.get('total', 0)} actions · "
            f"{plan.summary.get('p0', 0)} act now · {plan.summary.get('p1', 0)} this week · "
            f"{plan.summary.get('p2', 0)} this month",
            title="Removal plan",
            border_style="green",
        )
    )
    for action in plan.actions:
        console.print(f"\n[bold]{escape(action.priority)} · {escape(action.title)}[/bold]")
        console.print(f"[dim]Due {escape(action.due_label)}[/dim]")
        console.print(escape(action.detail))
        for index, step in enumerate(action.steps, 1):
            console.print(f"  {index}. {escape(step)}")
        if action.url:
            console.print(f"  {escape(action.url)}")
        if action.command:
            console.print(f"  [dim]{escape(action.command)}[/dim]")


def _parse_due(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ConfigError("--due must be YYYY-MM-DD") from exc
    local = datetime.combine(parsed, time(23, 59, 59)).astimezone()
    return local.isoformat(timespec="seconds")


def _open(path: Path) -> None:
    try:
        webbrowser.open(path.resolve().as_uri())
    except Exception:
        console.print(f"[yellow]Could not open a browser. Open {escape(str(path))} manually.[/yellow]")


def _findings_csv(findings: Iterable[dict[str, Any]], profile) -> str:
    import io

    buffer = io.StringIO()
    fields = [
        "id",
        "first_seen",
        "last_seen",
        "status",
        "severity",
        "category",
        "kind",
        "source",
        "title",
        "url",
        "identifier",
        "identifier_type",
        "confidence",
        "matched",
        "snippet",
        "data_points",
        "page_enrichment",
        "notes",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        row = dict(finding)
        row["category"] = category_label(str(row.get("category") or ""))
        points = infer_data_points(finding, profile)
        row["data_points"] = "; ".join(
            f"{point.label}: {point.value}" if point.value else point.label
            for point in points[:20]
        )
        enrichment = (row.get("details") or {}).get("enrichment") or {}
        row["page_enrichment"] = enrichment.get("status", "")
        row["details"] = ""
        writer.writerow(row)
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if getattr(args, "no_color", False):
        console.no_color = True
        ERR_CONSOLE.no_color = True
    try:
        handlers = {
            "init": cmd_init,
            "run": cmd_run,
            "scan": cmd_scan,
            "report": cmd_report,
            "findings": cmd_findings,
            "add-url": cmd_add_url,
            "annotate": cmd_annotate,
            "enrich": cmd_enrich,
            "show": cmd_show,
            "update": cmd_update,
            "brokers": cmd_brokers,
            "broker-update": cmd_broker_update,
            "searches": cmd_searches,
            "plan": cmd_plan,
            "export": cmd_export,
            "demo": cmd_demo,
            "doctor": cmd_doctor,
        }
        return handlers[args.command](args)
    except ConfigError as exc:
        ERR_CONSOLE.print(f"[red]Error:[/red] {escape(str(exc))}")
        return 2
    except KeyboardInterrupt:
        ERR_CONSOLE.print("\n[yellow]Interrupted.[/yellow]")
        return 130
    except BrokenPipeError:
        return 0
    except Exception as exc:
        if getattr(args, "verbose", False):
            ERR_CONSOLE.print_exception()
        ERR_CONSOLE.print(f"[red]Unexpected error:[/red] {escape(type(exc).__name__)}: {escape(str(exc))}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
