#!/usr/bin/env python3
"""
GANDIV v2.0.0 — Multi-source OSINT Reconnaissance Tool
CLI + Interactive Menu entry point.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Optional

# Windows UTF-8 console fix — must come AFTER __future__ import.
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

# Silence asyncio "Event loop is closed" cleanup noise on Windows + Python 3.8
if sys.platform == "win32":
    try:
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from gandiv.config import load_config
from gandiv.logger import setup_logger
from gandiv.orchestrator import resume_scan, run_scan
from gandiv.reporters import html_reporter, json_reporter, markdown_reporter
from gandiv.utils.validators import sanitize_filename

app = typer.Typer(
    name="gandiv",
    help="GANDIV — Never Miss Target Intelligence. Multi-source OSINT reconnaissance.",
    add_completion=False,
)
console = Console()

REPORTERS = {
    "json": json_reporter,
    "html": html_reporter,
    "markdown": markdown_reporter,
}

VERSION = "2.0.0"


def _banner() -> None:
    console.print(Panel.fit(
        f"[bold cyan]GANDIV[/bold cyan] [dim]v{VERSION}[/dim]\n"
        "[dim]Multi-source OSINT Reconnaissance — Never Miss Target Intelligence[/dim]",
        border_style="cyan",
    ))


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Target"),
    type: Optional[str] = typer.Option(None, "--type", help="Force target type"),
    full: bool = typer.Option(False, "--full"),
    threads: int = typer.Option(10, "--threads"),
    report: str = typer.Option("json,html", "--report"),
    output_dir: Optional[str] = typer.Option(None, "--output-dir"),
    parallel: bool = typer.Option(True, "--parallel/--sequential"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
):
    """Run a full OSINT scan against a single target."""
    config = load_config()
    if output_dir:
        config.output_dir = Path(output_dir)
        config.ensure_dirs()

    setup_logger(config.log_dir, debug=config.debug)

    if not quiet:
        _banner()
        console.print(f"[bold]Target:[/bold] {target}" + (f"  [dim](forced type: {type})[/dim]" if type else ""))
        console.print(f"[bold]Mode:[/bold] {'full' if full else 'quick'}  [bold]Threads:[/bold] {threads}\n")

    safe_name = sanitize_filename(target)
    checkpoint_path = config.checkpoint_dir / f"gandiv_{safe_name}_checkpoint.json"

    with console.status("[cyan]Running reconnaissance modules...", spinner="dots"):
        result = run_scan(
            raw_target=target, config=config, forced_type=type, full=full,
            threads=threads, parallel=parallel, checkpoint_path=checkpoint_path,
        )

    _print_summary(result)

    formats = [f.strip().lower() for f in report.split(",") if f.strip()]
    written = []
    for fmt in formats:
        reporter = REPORTERS.get(fmt)
        if not reporter:
            console.print(f"[yellow]Unknown report format '{fmt}', skipping.[/yellow]")
            continue
        ext = {"json": "json", "html": "html", "markdown": "md"}[fmt]
        out_path = config.output_dir / f"{safe_name}__gandiv_{result.scan_id}.{ext}"
        reporter.generate(result, out_path)
        written.append(out_path)

    console.print("\n[bold green]Reports written:[/bold green]")
    for p in written:
        console.print(f"  • {p}")


@app.command()
def resume(
    checkpoint: str = typer.Option(..., "--checkpoint", "-c"),
    report: str = typer.Option("json,html", "--report"),
):
    """Resume an interrupted scan from a checkpoint file."""
    config = load_config()
    setup_logger(config.log_dir, debug=config.debug)
    _banner()

    checkpoint_path = Path(checkpoint)
    if not checkpoint_path.exists():
        console.print(f"[red]Checkpoint file not found: {checkpoint_path}[/red]")
        raise typer.Exit(code=1)

    with console.status("[cyan]Resuming scan...", spinner="dots"):
        result = resume_scan(checkpoint_path, config)

    _print_summary(result)

    safe_name = sanitize_filename(result.target.normalized)
    formats = [f.strip().lower() for f in report.split(",") if f.strip()]
    for fmt in formats:
        reporter = REPORTERS.get(fmt)
        if not reporter:
            continue
        ext = {"json": "json", "html": "html", "markdown": "md"}[fmt]
        out_path = config.output_dir / f"{safe_name}__gandiv_{result.scan_id}_resumed.{ext}"
        reporter.generate(result, out_path)
        console.print(f"  • {out_path}")


@app.command()
def check():
    """Verify GANDIV's environment: dependencies and configured API keys."""
    _banner()
    config = load_config()

    table = Table(title="Dependency Check")
    table.add_column("Package")
    table.add_column("Status")
    for pkg in ["requests", "aiohttp", "dns.resolver", "whois", "typer", "rich"]:
        try:
            __import__(pkg)
            table.add_row(pkg, "[green]OK[/green]")
        except ImportError:
            table.add_row(pkg, "[red]MISSING[/red]")
    console.print(table)

    table2 = Table(title="API Keys Configured")
    table2.add_column("Service")
    table2.add_column("Status")
    keys = {
        "VirusTotal": config.api_keys.virustotal,
        "Shodan": config.api_keys.shodan,
        "Censys": config.api_keys.censys_id and config.api_keys.censys_secret,
        "HaveIBeenPwned": config.api_keys.hibp,
        "DeHashed": config.api_keys.dehashed_key,
        "GitHub": config.api_keys.github,
    }
    for name, val in keys.items():
        table2.add_row(name, "[green]configured[/green]" if val else "[yellow]not set (optional)[/yellow]")
    console.print(table2)

    console.print(f"\n[dim]Output directory:[/dim] {config.output_dir}")
    console.print(f"[dim]Log directory:[/dim] {config.log_dir}")


@app.command("config-wizard")
def config_wizard():
    """Interactively write a .env file with your API keys."""
    _banner()
    console.print("[bold]GANDIV Configuration Wizard[/bold]")
    console.print("[dim]Leave blank to skip any key.[/dim]\n")

    fields = [
        ("VT_API_KEY", "VirusTotal API key"),
        ("SHODAN_API_KEY", "Shodan API key"),
        ("CENSYS_API_ID", "Censys API ID"),
        ("CENSYS_API_SECRET", "Censys API secret"),
        ("HIBP_API_KEY", "Have I Been Pwned API key"),
        ("DEHASHED_EMAIL", "DeHashed account email"),
        ("DEHASHED_API_KEY", "DeHashed API key"),
        ("GITHUB_TOKEN", "GitHub personal access token"),
    ]

    lines = []
    for env_key, label in fields:
        val = typer.prompt(label, default="", show_default=False)
        if val:
            lines.append(f"{env_key}={val}")

    env_path = Path(".env")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"\n[green]Wrote {len(lines)} key(s) to {env_path.resolve()}[/green]")


def _print_summary(result) -> None:
    stats = result.stats or result.compute_stats() or result.stats
    table = Table(title=f"Scan Summary — {result.target.normalized}")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Scan ID", result.scan_id)
    table.add_row("Total Findings", str(stats.get("total_findings", 0)))
    table.add_row("Modules Succeeded", f"{stats.get('modules_succeeded', 0)}/{stats.get('modules_run', 0)}")
    for risk, count in stats.get("by_risk", {}).items():
        table.add_row(f"Risk: {risk}", str(count))
    console.print(table)


def _run_from_menu() -> None:
    """Launch GANDIV via interactive menu, then dispatch to scan()."""
    from gandiv.menu import run_interactive

    result = run_interactive()
    if result is None:
        return

    action = result.get("action")
    target = result.get("target")
    target_type = result.get("type")

    if not target:
        console.print("[red]No target provided.[/red]")
        return

    if action == "people":
        forced_type = f"people-{target_type}"
        scan(
            target=target, type=forced_type, full=True, threads=10,
            report="json,html,markdown", output_dir=None, parallel=True, quiet=False,
        )
    elif action in ("domain", "web", "infra", "breach", "username", "image", "full", "custom"):
        scan(
            target=target, type=action, full=(action == "full"), threads=10,
            report="json,html,markdown", output_dir=None, parallel=True, quiet=False,
        )
    else:
        console.print(f"[red]Unknown action: {action}[/red]")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        try:
            _run_from_menu()
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Exiting.[/yellow]")
            sys.exit(0)
    else:
        app()