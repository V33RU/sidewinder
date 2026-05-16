#!/usr/bin/env python3
"""
SiDEWiNDER - SSID Injection Detection & Wireless INjection Defense EngineeR

Scans IoT firmware, source code, and binaries for WiFi SSID injection
vulnerabilities across 14 vulnerability classes identified in the
CommandInWiFi-Zeroclick research.

Usage:
    python cli.py scan <target>           Scan source code directory
    python cli.py binary <target>         Analyze ELF binaries
    python cli.py firmware <firmware.bin> Extract and scan firmware image
    python cli.py deps <target>           Check for vulnerable dependencies
    python cli.py full <target>           Run all scanners
    python cli.py info                    Show vulnerability classes and CVEs
"""

import json
import sys
from pathlib import Path

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Resolve project paths
PROJECT_ROOT = Path(__file__).parent
RULES_DIR = PROJECT_ROOT / "config" / "rules"
CVE_DB_PATH = PROJECT_ROOT / "config" / "cve_database.json"

from core.source_scanner import SourceScanner
from core.binary_analyzer import BinaryAnalyzer
from core.firmware_extractor import FirmwareExtractor
from core.dependency_checker import DependencyChecker


CLASS_DESCRIPTIONS = {
    "wifi_cmd":      "Shell command injection via SSID in system()/popen()/exec()",
    "wifi_overflow": "Buffer overflow from SSID copy without length validation",
    "wifi_fmt":      "Format string: SSID used as format argument in printf/syslog",
    "wifi_xss":      "Cross-site scripting via unescaped SSID in web interfaces",
    "wifi_serial":   "Serialization/config injection: SSID in JSON/XML/SQL/YAML",
    "wifi_crlf":     "CRLF injection via SSID reflected in HTTP headers",
    "wifi_jndi":     "JNDI/expression language injection via SSID in Log4j",
    "wifi_path":     "Path traversal via SSID used in filesystem path construction",
    "wifi_nosql":    "NoSQL/LDAP injection via SSID in database queries",
    "wifi_esc":      "Terminal escape injection via SSID in serial/log output",
    "wifi_enc":      "Encoding normalization bypass: validation before normalization",
    "wifi_heap":     "Heap metadata corruption via SSID overflow into allocator structures",
    "wifi_chain":    "Multi-SSID chain: split payloads across concatenated scan results",
    "wifi_probe":    "Malformed SSID probes targeting WiFi stack parsing logic",
}


def get_console():
    if HAS_RICH:
        return Console()
    return None


def run_source_scan(scanner, target, console):
    """Run source scanner with progress bar."""
    files = scanner.collect_files(target)
    total = len(files)

    if not total:
        if console:
            console.print("[yellow]  No source files found to scan.[/yellow]")
        return

    if console and HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total} files"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Source scan", total=total)

            def callback(fpath, done, tot):
                progress.update(task, completed=done,
                                description=f"Source scan ({len(scanner.findings)} findings)")

            scanner.scan_directory(target, progress_callback=callback)
    else:
        def callback(fpath, done, tot):
            if done % 100 == 0 or done == tot:
                print(f"  [{done}/{tot}] {len(scanner.findings)} findings so far...")

        scanner.scan_directory(target, progress_callback=callback)


def run_binary_scan(analyzer, target, console):
    """Run binary analyzer with progress bar."""
    elf_files = analyzer.collect_elf_files(target)
    total = len(elf_files)

    if not total:
        if console:
            console.print("[yellow]  No ELF binaries found.[/yellow]")
        return

    if console and HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total} binaries"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Binary analysis", total=total)

            def callback(fpath, done, tot):
                progress.update(task, completed=done,
                                description=f"Binary analysis ({len(analyzer.findings)} findings)")

            analyzer.analyze_directory(target, progress_callback=callback)
    else:
        def callback(fpath, done, tot):
            if done % 50 == 0 or done == tot:
                print(f"  [{done}/{tot}] {len(analyzer.findings)} findings so far...")

        analyzer.analyze_directory(target, progress_callback=callback)


def run_dep_check(checker, target, console):
    """Run dependency checker with progress bar."""
    if console and HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Dependency check", total=1)
            started = [False]

            def callback(fpath, done, tot):
                if not started[0]:
                    progress.update(task, total=tot)
                    started[0] = True
                progress.update(task, completed=done,
                                description=f"Dependency check ({len(checker.findings)} findings)")

            checker.check_directory(target, progress_callback=callback)
    else:
        def callback(fpath, done, tot):
            if done % 200 == 0 or done == tot:
                print(f"  [{done}/{tot}] checking dependencies...")

        checker.check_directory(target, progress_callback=callback)


def print_banner():
    banner = r"""
  _____ _ ____  _______        ___ _   _ ____  _____ ____
 / ____(_)  _ \| ____\ \      / (_) \ | |  _ \| ____|  _ \
 \___ \| | | | |  _|  \ \ /\ / /| |  \| | | | |  _| | |_) |
  ___) | | |_| | |___  \ V  V / | | |\  | |_| | |___|  _ <
 |____/|_|____/|_____|  \_/\_/  |_|_| \_|____/|_____|_| \_\

  SSID Injection Detection & Wireless INjection Defense EngineeR
  v1.0.0 | 14 Vuln Classes | 17 CVEs | CommandInWiFi-Zeroclick
  Author: Veerababu Penugonda
"""
    print(banner)


def print_findings_table(console, findings, title):
    """Print findings as a rich table."""
    if not HAS_RICH or not findings:
        return

    table = Table(title=title, show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=10, no_wrap=True)
    table.add_column("Class", width=14, no_wrap=True)
    table.add_column("File Path", overflow="fold", min_width=30)
    table.add_column("Details", overflow="fold", min_width=20)

    severity_colors = {
        "critical": "red",
        "high": "dark_orange",
        "medium": "yellow",
        "low": "green",
    }

    for f in findings[:50]:  # Limit display to 50
        sev = f.get("severity", "unknown")
        color = severity_colors.get(sev, "white")
        cls = f.get("class", f.get("vuln_class", "?"))
        file_info = f.get("file", "?")
        if "line" in f and f["line"]:
            file_info = f"{file_info}:{f['line']}"

        detail = f.get("content", f.get("details", f.get("context", "")))

        table.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            cls,
            file_info,
            detail,
        )

    console.print(table)
    if len(findings) > 50:
        console.print(
            f"  [yellow]Showing 50/{len(findings)} findings.[/yellow] "
            f"Use --json <path> to write the full result set."
        )


def _write_json(path: str, payload: dict, console=None) -> None:
    """Write a scanner summary (or merged summary) to ``path`` as JSON.

    The payload is whatever a scanner's ``get_summary()`` returns (or a dict
    that combines several summaries). Writing is best-effort: failures emit
    a warning to the console but do not raise.
    """
    try:
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        if console:
            console.print(f"[green]Wrote JSON results to {path}[/green]")
    except OSError as e:
        if console:
            console.print(f"[red]Failed to write {path}: {e}[/red]")
        else:
            print(f"Failed to write {path}: {e}", file=sys.stderr)


def _merge_summaries(*summaries):
    """Merge multiple scanner summaries into one for display."""
    total = 0
    severity = {}
    files = 0
    for s in summaries:
        if not s:
            continue
        total += s.get("total_findings", 0)
        files += s.get("files_scanned", 0)
        for sev, count in s.get("by_severity", {}).items():
            severity[sev] = severity.get(sev, 0) + count
    return {"total_findings": total, "severity": severity, "files_scanned": files}


def print_summary(console, summary):
    """Print scan summary."""
    if HAS_RICH and console:
        console.print()
        console.print(Panel(
            f"[bold]Total Findings:[/bold] {summary['total_findings']}  |  "
            f"[red]Critical: {summary['severity'].get('critical', 0)}[/red]  |  "
            f"[dark_orange]High: {summary['severity'].get('high', 0)}[/dark_orange]  |  "
            f"[yellow]Medium: {summary['severity'].get('medium', 0)}[/yellow]  |  "
            f"[green]Low: {summary['severity'].get('low', 0)}[/green]  |  "
            f"Files: {summary['files_scanned']}",
            title="Scan Summary",
        ))
    else:
        print("\n--- Scan Summary ---")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Critical: {summary['severity'].get('critical', 0)}")
        print(f"High: {summary['severity'].get('high', 0)}")
        print(f"Medium: {summary['severity'].get('medium', 0)}")
        print(f"Low: {summary['severity'].get('low', 0)}")
        print(f"Files Scanned: {summary['files_scanned']}")


@click.group()
def cli():
    """SiDEWiNDER - SSID Injection Vulnerability Scanner for IoT Firmware"""
    pass


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--json", "json_path", type=click.Path(), default=None,
              help="Write full results (all findings + summary) to this JSON file.")
def scan(target, json_path):
    """Scan source code for SSID injection vulnerabilities."""
    print_banner()
    console = get_console()

    scanner = SourceScanner(str(RULES_DIR), str(CVE_DB_PATH))

    if console:
        console.print(f"[bold blue]Scanning source code:[/bold blue] {target}")

    run_source_scan(scanner, target, console)
    summary = scanner.get_summary()

    if console:
        print_findings_table(console, summary["findings"], "Source Code Findings")

    print_summary(console, _merge_summaries(summary))

    if json_path:
        _write_json(json_path, {"command": "scan", "target": target, "source": summary}, console)


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--json", "json_path", type=click.Path(), default=None,
              help="Write full results (all findings + summary) to this JSON file.")
def binary(target, json_path):
    """Analyze ELF binaries for SSID vulnerability indicators."""
    print_banner()
    console = get_console()

    analyzer = BinaryAnalyzer(str(RULES_DIR), str(CVE_DB_PATH))

    if console:
        console.print(f"[bold blue]Analyzing binaries:[/bold blue] {target}")

    run_binary_scan(analyzer, target, console)
    summary = analyzer.get_summary()

    if console:
        print_findings_table(console, summary["findings"], "Binary Analysis Findings")

    print_summary(console, _merge_summaries(summary))

    if json_path:
        _write_json(json_path, {"command": "binary", "target": target, "binary": summary}, console)


@cli.command()
@click.argument("firmware_path", type=click.Path(exists=True))
@click.option("--extract-dir", "-e", default=None, help="Custom extraction directory")
@click.option("--keep", is_flag=True, help="Keep extracted files after scanning")
@click.option("--json", "json_path", type=click.Path(), default=None,
              help="Write full results (all phases) to this JSON file.")
def firmware(firmware_path, extract_dir, keep, json_path):
    """Extract and scan firmware image (requires unblob)."""
    print_banner()
    console = get_console()

    if console:
        console.print(f"[bold blue]Extracting firmware:[/bold blue] {firmware_path}")

    # Step 1: Extract firmware
    extractor = FirmwareExtractor()
    result = extractor.extract(firmware_path, extract_dir)

    if not result.success:
        print(f"Extraction failed: {result.error}")
        sys.exit(1)

    if console:
        console.print(f"  Extracted {result.file_count} files to {result.output_dir}")
        console.print(f"  ELF binaries: {len(result.elf_binaries)}")
        console.print(f"  Source files: {len(result.source_files)}")
        console.print(f"  Config files: {len(result.config_files)}")

    # Step 2: Source scan
    if console:
        console.print("\n[bold]Phase 1/3: Source Code Analysis[/bold]")
    src_scanner = SourceScanner(str(RULES_DIR), str(CVE_DB_PATH))
    run_source_scan(src_scanner, result.output_dir, console)
    src_summary = src_scanner.get_summary()

    # Step 3: Binary analysis
    if console:
        console.print("\n[bold]Phase 2/3: Binary Analysis[/bold]")
    bin_analyzer = BinaryAnalyzer(str(RULES_DIR), str(CVE_DB_PATH))
    run_binary_scan(bin_analyzer, result.output_dir, console)
    bin_summary = bin_analyzer.get_summary()

    # Step 4: Dependency check
    if console:
        console.print("\n[bold]Phase 3/3: Dependency Check[/bold]")
    dep_checker = DependencyChecker()
    run_dep_check(dep_checker, result.output_dir, console)
    dep_summary = dep_checker.get_summary()

    if console:
        print_findings_table(console, src_summary["findings"], "Source Code Findings")
        print_findings_table(console, bin_summary["findings"], "Binary Analysis Findings")
        print_findings_table(console, dep_summary["findings"], "Vulnerable Dependencies")

    print_summary(console, _merge_summaries(src_summary, bin_summary, dep_summary))

    if json_path:
        _write_json(
            json_path,
            {
                "command": "firmware",
                "firmware": firmware_path,
                "extraction": result.to_dict(),
                "source": src_summary,
                "binary": bin_summary,
                "dependencies": dep_summary,
            },
            console,
        )

    # Cleanup
    if not keep:
        extractor.cleanup(result.output_dir)
        print("Extracted files cleaned up. Use --keep to preserve.")


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--json", "json_path", type=click.Path(), default=None,
              help="Write full results (all findings + summary) to this JSON file.")
def deps(target, json_path):
    """Check for vulnerable dependencies (libraries, packages)."""
    print_banner()
    console = get_console()

    checker = DependencyChecker()

    if console:
        console.print(f"[bold blue]Checking dependencies:[/bold blue] {target}")

    run_dep_check(checker, target, console)
    summary = checker.get_summary()

    if console:
        print_findings_table(console, summary["findings"], "Vulnerable Dependencies")

    print_summary(console, _merge_summaries(summary))

    if json_path:
        _write_json(json_path, {"command": "deps", "target": target, "dependencies": summary}, console)


@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--json", "json_path", type=click.Path(), default=None,
              help="Write full results (all 3 phases) to this JSON file.")
def full(target, json_path):
    """Run all scanners on a target directory."""
    print_banner()
    console = get_console()

    if console:
        console.print(f"[bold blue]Full scan:[/bold blue] {target}")

    # Source scan
    if console:
        console.print("\n[bold]Phase 1/3: Source Code Analysis[/bold]")
    src_scanner = SourceScanner(str(RULES_DIR), str(CVE_DB_PATH))
    run_source_scan(src_scanner, target, console)
    src_summary = src_scanner.get_summary()

    # Binary analysis
    if console:
        console.print("\n[bold]Phase 2/3: Binary Analysis[/bold]")
    bin_analyzer = BinaryAnalyzer(str(RULES_DIR), str(CVE_DB_PATH))
    run_binary_scan(bin_analyzer, target, console)
    bin_summary = bin_analyzer.get_summary()

    # Dependency check
    if console:
        console.print("\n[bold]Phase 3/3: Dependency Check[/bold]")
    dep_checker = DependencyChecker()
    run_dep_check(dep_checker, target, console)
    dep_summary = dep_checker.get_summary()

    if console:
        print_findings_table(console, src_summary["findings"], "Source Code Findings")
        print_findings_table(console, bin_summary["findings"], "Binary Analysis Findings")
        print_findings_table(console, dep_summary["findings"], "Vulnerable Dependencies")

    print_summary(console, _merge_summaries(src_summary, bin_summary, dep_summary))

    if json_path:
        _write_json(
            json_path,
            {
                "command": "full",
                "target": target,
                "source": src_summary,
                "binary": bin_summary,
                "dependencies": dep_summary,
            },
            console,
        )


@cli.command()
def info():
    """Show supported vulnerability classes and CVE database."""
    print_banner()
    console = get_console()

    if HAS_RICH and console:
        table = Table(title="14 SSID Vulnerability Classes", show_lines=True)
        table.add_column("Class", style="cyan", width=16)
        table.add_column("Description", width=60)

        for cls, desc in CLASS_DESCRIPTIONS.items():
            table.add_row(cls, desc)
        console.print(table)

        try:
            with open(CVE_DB_PATH) as f:
                cves = json.load(f).get("cves", [])
        except (FileNotFoundError, json.JSONDecodeError):
            cves = []

        if cves:
            cve_table = Table(title="CVE Database", show_lines=True)
            cve_table.add_column("CVE", width=18)
            cve_table.add_column("Component", width=30)
            cve_table.add_column("Class", width=16)
            cve_table.add_column("Zero-Click", width=10)

            for cve in cves:
                zc = "[green]Yes[/green]" if cve.get("zero_click") else "[red]No[/red]"
                cve_table.add_row(
                    cve["id"],
                    cve["component"],
                    cve["vuln_class"],
                    zc,
                )
            console.print(cve_table)
    else:
        print("\nVulnerability Classes:")
        for cls, desc in CLASS_DESCRIPTIONS.items():
            print(f"  {cls:16s} {desc}")


if __name__ == "__main__":
    cli()
