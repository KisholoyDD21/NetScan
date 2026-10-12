"""Typer CLI for authorized scans, report generation, and result diffing."""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from netscan.auth import (
    ScopeAuthorizer,
    add_targets_to_scope,
    detect_local_ips,
    normalize_target,
    parse_targets,
)
from netscan.cache import ScanCache
from netscan.concurrency import run_bounded
from netscan.config import load_settings
from netscan.cve import enrich_cve_candidates
from netscan.diff import compare_scans
from netscan.exceptions import (
    AuthorizationError,
    ConfigurationError,
    NetScanError,
    NmapNotFoundError,
    TargetValidationError,
)
from netscan.logging_config import configure_logging
from netscan.models import Host, ScanMetadata, ScanResult
from netscan.native_scanner import NativeScanner
from netscan.reports.csv_report import write_csv
from netscan.reports.html import write_html
from netscan.reports.json_report import write_json
from netscan.reports.markdown import write_markdown
from netscan.reports.pdf import write_pdf
from netscan.scanner import PROFILES, NmapScanner, find_nmap_executable, validate_custom_flags

app = typer.Typer(name="netscan", help="Authorized network scanning and multi-format reporting.", no_args_is_help=True)
scope_app = typer.Typer(name="scope", help="Manage authorized scanning scopes and targets.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")
console = Console()
LOGGER = logging.getLogger(__name__)

LEGAL = ("Use only against systems you own or are explicitly authorized to assess. "
         "You are responsible for obtaining written permission and respecting applicable law. "
         "NetScan requires an authorization flag and a scope file; it is not an authorization substitute.")


@app.command()
def scan(
    targets: Annotated[str | None, typer.Option("--targets", help="IP, CIDR, hostname, or comma-separated list.")] = None,
    targets_file: Annotated[Path | None, typer.Option("--targets-file", exists=True, dir_okay=False)] = None,
    scope_file: Annotated[Path | None, typer.Option("--scope-file", help="YAML scope with authorized targets.")] = None,
    authorized: Annotated[bool, typer.Option("--authorized", help="Confirm explicit authorization to scan these targets.")] = False,
    profile: Annotated[str | None, typer.Option(help="Scan profile; defaults to config.")] = None,
    report: Annotated[list[str], typer.Option("--report", help="Repeat for each format: html,json,csv,md,pdf.")] = ["html", "json"],
    output_dir: Annotated[Path | None, typer.Option("--output-dir")] = None,
    config: Annotated[Path | None, typer.Option("--config", help="YAML config path.")] = None,
    custom_flags: Annotated[str | None, typer.Option("--custom-flags", help="Flags for custom profile, e.g. '-sV --top-ports 20'.")] = None,
    engine: Annotated[str, typer.Option("--engine", help="Scan engine: auto, native (pure Python), wrapper, or subprocess.")] = "auto",
    allow_vuln_scripts: Annotated[bool, typer.Option("--allow-vuln-scripts", help="Acknowledge that NSE vuln scripts are intrusive/noisy.")] = False,
    cve_enrichment: Annotated[bool, typer.Option("--cve-enrichment", help="Opt in to NVD keyword lookups; sends product/version strings externally.")] = False,
    workers: Annotated[int | None, typer.Option(min=1, max=32)] = None,
    timeout: Annotated[int | None, typer.Option("--timeout", min=10, max=86400)] = None,
    rate_delay: Annotated[float | None, typer.Option("--rate-delay", min=0.0, max=10.0)] = None,
    sequential: Annotated[bool, typer.Option("--sequential", help="Run one target at a time.")] = False,
    cache_ttl: Annotated[int, typer.Option("--cache-ttl", min=0, help="Skip cached hosts younger than N seconds; 0 disables cache.")] = 0,
    acknowledge_large: Annotated[bool, typer.Option("--i-know-this-is-big", help="Acknowledge large CIDR expansion (hard safety cap still applies). ")] = False,
    compare_with: Annotated[Path | None, typer.Option("--compare-with", exists=True, dir_okay=False)] = None,
    fail_on_risk: Annotated[int | None, typer.Option("--fail-on-risk", min=0, max=100, help="Exit 5 if any host score meets/exceeds threshold.")] = None,
    open_report: Annotated[bool, typer.Option("--open", help="Open generated HTML report in default browser.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
    quiet: Annotated[bool, typer.Option("--quiet")] = False,
    debug: Annotated[bool, typer.Option("--debug")] = False,
) -> None:
    """Run an authorized scan and write selected report formats."""
    console.print(f"[bold yellow]LEGAL / ETHICAL USE[/bold yellow] {LEGAL}")
    if not authorized or scope_file is None:
        console.print("[red]Authorization required:[/red] provide --authorized and --scope-file.")
        raise typer.Exit(code=3)
    try:
        config_path = config or (Path("netscan.yaml") if Path("netscan.yaml").exists() else None)
        settings = load_settings(config_path)
        configure_logging(settings.log_dir, logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING, quiet)
        selected_profile = profile or settings.default_profile
        if engine not in {"auto", "native", "wrapper", "subprocess"}:
            console.print("[red]--engine must be auto, native, wrapper, or subprocess.[/red]")
            raise typer.Exit(code=2)
        if selected_profile not in PROFILES:
            console.print(f"[red]Unknown profile '{selected_profile}'.[/red] Available: {', '.join(PROFILES)}")
            raise typer.Exit(code=2)
        if selected_profile == "discovery":
            console.print("[dim]Note: 'discovery' profile checks host reachability only (-sn). Use --profile quick for port scanning.[/dim]")
        if selected_profile == "vuln" and not allow_vuln_scripts:
            console.print("[red]The vuln profile requires --allow-vuln-scripts; NSE vuln scripts can be intrusive.[/red]")
            raise typer.Exit(code=2)
        if selected_profile == "vuln":
            console.print("[bold red]WARNING: NSE vuln scripts may be intrusive or disruptive. Proceed only with explicit written authorization and an approved test window.[/bold red]")
        selected_formats = [item.strip().lower() for token in report for item in token.split(",") if item.strip()]
        formats = {"html": write_html, "json": write_json, "csv": write_csv, "md": write_markdown, "pdf": write_pdf}
        invalid_formats = set(selected_formats) - set(formats)
        if invalid_formats or not selected_formats:
            console.print(f"[red]Unsupported or empty report format selection:[/red] {', '.join(sorted(invalid_formats)) or '(empty)'}")
            raise typer.Exit(code=2)
        safe_custom_flags: list[str] | None = None
        if selected_profile == "custom":
            try:
                safe_custom_flags = validate_custom_flags(shlex.split(custom_flags) if custom_flags else [])
            except NetScanError as exc:
                console.print(f"[red]Invalid custom flags:[/red] {exc}")
                raise typer.Exit(code=2) from exc
        targets_list = parse_targets(targets, targets_file, settings.max_targets, acknowledge_large)
        authorizer = ScopeAuthorizer(scope_file)
        authorizer.authorize(authorized, targets_list)
        excluded = {item.lower() for item in settings.exclude_hosts}
        targets_list = [target for target in targets_list if target.lower() not in excluded]
        if not targets_list:
            raise TargetValidationError("All targets were excluded by configuration.")
        if acknowledge_large and len(targets_list) > settings.max_targets:
            console.print(f"[yellow]Large-scope acknowledgment accepted for {len(targets_list):,} normalized targets.[/yellow]")
        output = output_dir or settings.output_dir
        output.mkdir(parents=True, exist_ok=True)
        scanner: NmapScanner | NativeScanner
        if engine == "native":
            scanner = NativeScanner(timeout or settings.timeout_seconds)
        elif engine == "auto":
            if find_nmap_executable() is not None:
                scanner = NmapScanner(timeout or settings.timeout_seconds)
            else:
                console.print(
                    "[yellow]Notice:[/yellow] Nmap executable not detected. Using native pure-Python scanner engine."
                )
                scanner = NativeScanner(timeout or settings.timeout_seconds)
        else:
            scanner = NmapScanner(timeout or settings.timeout_seconds)
    except AuthorizationError as exc:
        console.print(f"[red]Authorization denied:[/red] {exc}")
        raise typer.Exit(code=3) from exc
    except NmapNotFoundError as exc:
        console.print(f"[red]Nmap not found:[/red] {exc}")
        raise typer.Exit(code=4) from exc
    except TargetValidationError as exc:
        console.print(f"[red]Invalid target input:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except OSError as exc:
        console.print(f"[red]Filesystem error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except (ConfigurationError, NetScanError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    cache = ScanCache(settings.cache_dir)
    cached: dict[str, Host] = {}
    pending: list[str] = []
    for target in targets_list:
        hit = cache.get(target, selected_profile, cache_ttl)
        if hit is None:
            pending.append(target)
        else:
            cached[target] = hit
            LOGGER.info("Cache hit target=%s profile=%s", target, selected_profile)
    results: list[ScanResult] = []
    completed_by_target: dict[str, ScanResult | Exception] = {}
    callback: Callable[[str, ScanResult | Exception], None] | None = None
    if pending:
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(), console=console) as progress:
            task_id = progress.add_task("Scanning authorized targets", total=len(pending))
            live_ports = Table(title="Open ports discovered (updated when each host completes)")
            for column in ("Host", "Protocol", "Port", "Service", "Product / version"):
                live_ports.add_column(column)
            def complete(target: str, outcome: ScanResult | Exception) -> None:
                """Update progress and present the newly completed host's open ports."""
                completed_by_target[target] = outcome
                progress.advance(task_id)
                if isinstance(outcome, ScanResult):
                    for warning in outcome.metadata.warnings:
                        console.print(f"[yellow]Warning for {target}:[/yellow] {warning}")
                    open_count = 0
                    is_down = bool(outcome.hosts) and all(h.status == "down" for h in outcome.hosts)
                    for host in outcome.hosts:
                        for port in host.ports:
                            if port.state == "open":
                                open_count += 1
                                live_ports.add_row(host.address, port.protocol, str(port.number), port.service.name, port.service.banner or "—")
                    if is_down:
                        console.log(f"[yellow]Completed[/yellow] {target}: host unreachable / down (0 open ports)")
                    else:
                        console.log(f"[green]Completed[/green] {target}: {open_count} open ports")
                    if open_count > 0:
                        console.print(live_ports)
                else:
                    console.log(f"[red]Failed[/red] {target}: {outcome}")
            callback = complete
            async def execute() -> list[ScanResult | Exception]:
                """Run target scans concurrently within the configured worker limit."""
                return await run_bounded(pending, lambda target: scanner.scan(target, selected_profile,
                    custom_flags=safe_custom_flags if selected_profile == "custom" else None, allow_vuln=allow_vuln_scripts, engine=engine),
                    1 if sequential else (workers or settings.max_workers),
                    settings.rate_delay_seconds if rate_delay is None else rate_delay, callback)
            outcomes: list[ScanResult | Exception | None] = []
            try:
                outcomes.extend(asyncio.run(execute()))
            except KeyboardInterrupt:
                console.print("[yellow]Interrupted. Writing reports from completed results collected so far.[/yellow]")
                outcomes = [completed_by_target.get(target) for target in pending]
            for target, outcome in zip(pending, outcomes):
                if outcome is None:
                    continue
                if isinstance(outcome, Exception):
                    LOGGER.error("Target %s failed: %s", target, outcome)
                else:
                    results.append(outcome)
                    for host in outcome.hosts:
                        cache.put(target, selected_profile, host)
    hosts = [host for result in results for host in result.hosts]
    hosts.extend(cached.values())
    metadata = ScanMetadata(profile=selected_profile, nmap_version=scanner.nmap_version,
        command=results[0].metadata.command if results else [],
        started_at=min((r.metadata.started_at for r in results if r.metadata.started_at), default=datetime.now(UTC).isoformat()),
        finished_at=datetime.now(UTC).isoformat(),
        duration_seconds=round(sum(r.metadata.duration_seconds for r in results), 3),
        warnings=[warning for r in results for warning in r.metadata.warnings])
    combined = ScanResult(metadata=metadata, hosts=hosts)
    if cve_enrichment:
        console.print("[yellow]Optional CVE enrichment enabled: service/version strings will be sent to NVD keyword search. Results are leads, not confirmation.[/yellow]")
        for warning in enrich_cve_candidates(combined):
            console.print(f"[yellow]CVE enrichment warning:[/yellow] {warning}")
    if compare_with:
        try:
            old = ScanResult.from_dict(json.loads(compare_with.read_text(encoding="utf-8")))
            combined.changes_since_previous = compare_scans(old, combined)
        except (OSError, json.JSONDecodeError, TypeError, KeyError, ValueError) as exc:
            console.print(f"[red]Could not compare prior result:[/red] {exc}")
    stem = f"netscan-{selected_profile}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    successful = 0
    failed_reports = 0
    written_reports: list[Path] = []
    for fmt in dict.fromkeys(selected_formats):
        try:
            path = formats[fmt](combined, output / f"{stem}.{fmt}")
            console.print(f"[green]Report written:[/green] {path}")
            written_reports.append(path)
            successful += 1
        except (NetScanError, OSError, ValueError) as exc:
            failed_reports += 1
            console.print(f"[red]{fmt.upper()} report failed:[/red] {exc}")
    _show_summary(combined)
    if open_report:
        html_reports = [p for p in written_reports if p.suffix.lower() == ".html"]
        if html_reports:
            import webbrowser

            console.print(f"[cyan]Opening report in browser:[/cyan] {html_reports[0]}")
            webbrowser.open(html_reports[0].resolve().as_uri())
    if not successful or failed_reports:
        raise typer.Exit(code=1)
    if fail_on_risk is not None and any(host.risk_score >= fail_on_risk for host in hosts):
        raise typer.Exit(code=5)
    if pending and not results and not cached:
        raise typer.Exit(code=1)


@app.command("diff")
def diff_command(old_json: Path, new_json: Path) -> None:
    """Compare two saved JSON results; this command does not scan."""
    try:
        old = ScanResult.from_dict(json.loads(old_json.read_text(encoding="utf-8")))
        new = ScanResult.from_dict(json.loads(new_json.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError, KeyError, ValueError) as exc:
        console.print(f"[red]Unable to load scan JSON:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    changes = compare_scans(old, new)
    table = Table(title="Changes since previous scan")
    table.add_column("Change")
    table.add_column("Count", justify="right")
    for key, value in changes.items():
        table.add_row(key.replace("_", " ").title(), str(len(value)))
    console.print(table)
    console.print_json(data=changes)


@app.command()
def profiles() -> None:
    """List built-in scan profiles."""
    table = Table(title="Built-in scan profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Nmap flags")
    for name, flags in PROFILES.items():
        table.add_row(name, " ".join(flags))
    console.print(table)


@scope_app.command("list")
def scope_list(
    scope_file: Annotated[Path, typer.Option("--scope-file", help="YAML scope file path.")] = Path("scope.yaml"),
) -> None:
    """List targets and details in the authorized scope file."""
    if not scope_file.exists():
        console.print(f"[yellow]Scope file '{scope_file}' does not exist.[/yellow]")
        return
    try:
        authorizer = ScopeAuthorizer(scope_file)
    except AuthorizationError as exc:
        console.print(f"[red]Error reading scope file:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title=f"Authorized Scope: {scope_file.name}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Owner", authorizer.owner)
    table.add_row("Expires At", str(authorizer.expires_at) if authorizer.expires_at else "No expiration")
    table.add_row("Target Count", str(len(authorizer.targets)))
    console.print(table)

    target_table = Table(title="Authorized Targets")
    target_table.add_column("#", style="dim")
    target_table.add_column("Target", style="bold green")
    for i, t in enumerate(authorizer.targets, 1):
        target_table.add_row(str(i), t)
    console.print(target_table)


@scope_app.command("add")
def scope_add(
    target: Annotated[str, typer.Argument(help="IP, CIDR, or hostname to add to authorized scope.")],
    scope_file: Annotated[Path, typer.Option("--scope-file", help="YAML scope file path.")] = Path("scope.yaml"),
) -> None:
    """Add an IP, CIDR, or hostname to the scope file."""
    targets_to_add = [item.strip() for item in target.split(",") if item.strip()]
    try:
        for t in targets_to_add:
            normalize_target(t)
    except TargetValidationError as exc:
        console.print(f"[red]Invalid target:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    added = add_targets_to_scope(scope_file, targets_to_add)
    if added:
        console.print(f"[green]Successfully added to {scope_file}:[/green] {', '.join(added)}")
    else:
        console.print(f"[yellow]Target(s) already present in {scope_file}.[/yellow]")


@scope_app.command("local")
def scope_local(
    scope_file: Annotated[Path, typer.Option("--scope-file", help="YAML scope file path.")] = Path("scope.yaml"),
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Automatically add detected interfaces without prompting.")] = False,
) -> None:
    """Detect local host network interfaces and add them to the authorized scope."""
    detected = detect_local_ips()
    console.print("[bold cyan]Discovered local machine interfaces:[/bold cyan]")
    table = Table(title="Detected Local Host Interfaces")
    table.add_column("Interface IP", style="green")
    for ip in detected:
        table.add_row(ip)
    console.print(table)

    if not yes:
        proceed = typer.confirm(f"Add these {len(detected)} address(es) to {scope_file}?", default=True)
        if not proceed:
            console.print("[yellow]Cancelled.[/yellow]")
            return

    added = add_targets_to_scope(scope_file, detected)
    if added:
        console.print(f"[green]Added {len(added)} address(es) to {scope_file}:[/green] {', '.join(added)}")
    else:
        console.print(f"[yellow]All detected interfaces are already present in {scope_file}.[/yellow]")


def _show_summary(result: ScanResult) -> None:
    """Render a host summary table in the terminal."""
    table = Table(title="NetScan summary")
    for column in ("Host", "Hostname", "Status", "Open ports", "Risk"):
        table.add_column(column)
    for host in result.hosts:
        count = sum(port.state == "open" for port in host.ports)
        table.add_row(host.address, host.hostname or "—", host.status, str(count), f"{host.risk_level} ({host.risk_score})")
    console.print(table)


if __name__ == "__main__":
    app()
