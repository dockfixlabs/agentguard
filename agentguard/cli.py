"""CLI entry point for AgentGuard."""

from __future__ import annotations

import sys

import click

from agentguard.scanner import scan_directory
from agentguard.reporter import print_report, json_report, sarif_report, _make_console


@click.command()
@click.argument("target", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--exit-code/--no-exit-code",
    default=True,
    help="Exit with non-zero code if findings found (default: True)",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    default="INFO",
    help="Minimum severity to report (default: INFO = all)",
)
@click.option(
    "--include-tests",
    is_flag=True,
    default=False,
    help="Include test files and directories in scan (default: skip tests)",
)
def main(target: str, output_format: str, exit_code: bool, min_severity: str,
         include_tests: bool) -> None:
    """AgentGuard -- Scan AI agent code for security vulnerabilities.

    TARGET: Directory or file to scan (default: current directory)

    Examples:

        agentguard .                        # Scan current directory
        agentguard src/ --format json       # JSON output
        agentguard . --format sarif         # SARIF for CI/CD
        agentguard . --min-severity HIGH    # Only HIGH+ findings
        agentguard . --include-tests        # Include test files
    """
    console = _make_console()
    result = scan_directory(target, include_tests=include_tests)

    # Filter by severity
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = severity_order.index(min_severity.upper())
    allowed = severity_order[:min_idx + 1]
    result.findings = [f for f in result.findings if f.severity.value in allowed]

    if output_format.lower() == "json":
        print(json_report(result))
    elif output_format.lower() == "sarif":
        print(sarif_report(result))
    else:
        print_report(result, console)

    if exit_code and not result.clean:
        sys.exit(1)


if __name__ == "__main__":
    main()
