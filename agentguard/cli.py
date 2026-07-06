"""CLI entry point for AgentGuard."""

from __future__ import annotations

import sys

import click

from agentguard.scanner import scan_directory
from agentguard.reporter import print_report, json_report, sarif_report, _make_console


@click.group(invoke_without_command=True)
@click.version_option(version="0.7.0", prog_name="agentguard")
@click.argument("target", default=".", type=click.Path(exists=True), required=False)
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
@click.pass_context
def main_group(ctx: click.Context, target: str, output_format: str, exit_code: bool,
              min_severity: str, include_tests: bool) -> None:
    """AgentGuard -- Autonomous security scanner for AI agent code.

    Scan AI agent code for OWASP ASI Top 10 vulnerabilities and novel attack vectors.

    Examples:

        agentguard .                        # Scan current directory
        agentguard src/ --format json       # JSON output
        agentguard . --format sarif         # SARIF for CI/CD
        agentguard . --min-severity HIGH    # Only HIGH+ findings
        agentguard . --include-tests        # Include test files

    Security Specification: https://github.com/dockfixlabs/agentguard/blob/main/specification.md
    """
    if ctx.invoked_subcommand is not None:
        return

    console = _make_console()
    result = scan_directory(target, include_tests=include_tests)

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


@main_group.command()
@click.option(
    "--pre-commit",
    "install_precommit",
    is_flag=True,
    default=False,
    help="Install AgentGuard as a pre-commit hook",
)
@click.option(
    "--in",
    "target_dir",
    type=click.Path(exists=True),
    default=".",
    help="Target project directory",
)
def install(install_precommit: bool, target_dir: str) -> None:
    """Install AgentGuard integrations.

    agentguard install --pre-commit       # Add to .pre-commit-config.yaml
    agentguard install --pre-commit --in /path/to/project
    """
    if install_precommit:
        from agentguard.precommit import install_precommit_hook
        success = install_precommit_hook(target_dir)
        if not success:
            sys.exit(1)
    else:
        print("Usage: agentguard install --pre-commit")
        print()
        print("Install AgentGuard as a git pre-commit hook to block")
        print("insecure AI agent code from being committed.")


@main_group.command()
@click.option(
    "--pre-commit",
    "uninstall_precommit",
    is_flag=True,
    default=False,
    help="Remove AgentGuard from pre-commit hooks",
)
@click.option(
    "--in",
    "target_dir",
    type=click.Path(exists=True),
    default=".",
    help="Target project directory",
)
def uninstall(uninstall_precommit: bool, target_dir: str) -> None:
    """Remove AgentGuard integrations."""
    if uninstall_precommit:
        from agentguard.precommit import uninstall_precommit_hook
        uninstall_precommit_hook(target_dir)
    else:
        print("Usage: agentguard uninstall --pre-commit")


main = main_group
