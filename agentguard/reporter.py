"""Report generation — human-readable and JSON output."""

from __future__ import annotations

import json
import sys

from agentguard.models import ScanResult, Severity
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def print_report(result: ScanResult, console: Console | None = None) -> None:
    """Print a rich, human-readable scan report."""
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(Panel.fit(
        f"[bold cyan]AgentGuard[/bold cyan] — AI Agent Security Scan\n"
        f"Target: [white]{result.target}[/white]\n"
        f"Files scanned: [white]{result.files_scanned}[/white]\n"
        f"Duration: [white]{result.scan_duration_ms}ms[/white]",
        border_style="cyan",
    ))

    # Summary
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_row(
        f"🔴 Critical: {result.critical_count}",
        f"🟠 High: {result.high_count}",
        f"🟡 Medium: {result.medium_count}",
        f"🔵 Low: {result.low_count}",
    )
    console.print(summary)
    console.print()

    if result.clean:
        console.print("[bold green]✓ No vulnerabilities found.[/bold green]")
        console.print()
        return

    # Findings table
    table = Table(
        show_header=True,
        header_style="bold",
        border_style="dim",
        title="Findings",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("OWASP", width=8)
    table.add_column("Rule", width=25)
    table.add_column("File:Line", width=30)
    table.add_column("Description")

    for i, f in enumerate(result.findings, 1):
        sev_str = f"{SEVERITY_ICONS[f.severity]} {f.severity.value}"
        color = SEVERITY_COLORS[f.severity]

        file_line = f"{f.file}:{f.line}"
        if len(file_line) > 28:
            # Truncate path
            parts = file_line.split("/")
            if len(parts) > 2:
                file_line = ".../" + "/".join(parts[-2:])

        table.add_row(
            str(i),
            Text(sev_str, style=color),
            f.owasp.value if f.owasp else "—",
            f.rule_name,
            file_line,
            f.description,
        )

    console.print(table)
    console.print()

    # Recommendations
    console.print("[bold]Recommendations:[/bold]")
    seen = set()
    for f in result.findings:
        key = f.rule_id
        if key not in seen:
            seen.add(key)
            console.print(f"  • [{SEVERITY_COLORS[f.severity]}]{f.rule_name}[/{SEVERITY_COLORS[f.severity]}]: {f.recommendation}")
    console.print()


def json_report(result: ScanResult) -> str:
    """Generate JSON report."""
    return json.dumps(result.model_dump(), indent=2, default=str)


def sarif_report(result: ScanResult) -> str:
    """Generate SARIF report for CI/CD integration."""
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentGuard",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/dockfixlabs/agentguard",
                }
            },
            "results": [
                {
                    "ruleId": f.rule_id,
                    "level": _sarif_level(f.severity),
                    "message": {"text": f.description},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line},
                        }
                    }],
                    "properties": {
                        "owasp": f.owasp.value if f.owasp else None,
                        "confidence": f.confidence,
                        "recommendation": f.recommendation,
                        "snippet": f.snippet,
                    },
                }
                for f in result.findings
            ],
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }.get(severity, "warning")
