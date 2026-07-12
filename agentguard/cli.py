"""CLI entry point for AgentGuard."""

from __future__ import annotations

import sys

import click

from agentguard.scanner import scan_directory
from agentguard.reporter import print_report, json_report, sarif_report, _make_console
from agentguard.false_positive_filter import describe_filters
from agentguard.classifier import describe_classification
from agentguard.auto_reporter import (
    compute_stats,
    generate_markdown_report,
    generate_json_summary,
    generate_ci_summary,
)


@click.group(invoke_without_command=True)
@click.version_option(version="0.8.0", prog_name="agentguard")
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
@click.option(
    "--no-fp-filter",
    is_flag=True,
    default=False,
    help="Disable automatic false positive filtering",
)
@click.option(
    "--no-classify",
    is_flag=True,
    default=False,
    help="Disable automatic finding classification",
)
@click.option(
    "--auto-report",
    "auto_report_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Generate auto Markdown report to PATH",
)
@click.option(
    "--ci",
    is_flag=True,
    default=False,
    help="CI/CD mode: concise one-line output",
)
@click.pass_context
def main_group(ctx: click.Context, target: str, output_format: str, exit_code: bool,
              min_severity: str, include_tests: bool, no_fp_filter: bool,
              no_classify: bool, auto_report_path: str | None, ci: bool) -> None:
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
    result = scan_directory(
        target,
        include_tests=include_tests,
        enable_fp_filter=not no_fp_filter,
        enable_classifier=not no_classify,
    )

    # Extract pipeline metadata
    fp_result = result.__dict__.get("_fp_result")
    classifier_result = result.__dict__.get("_classifier_result")

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    min_idx = severity_order.index(min_severity.upper())
    allowed = severity_order[:min_idx + 1]
    result.findings = [f for f in result.findings if f.severity.value in allowed]

    # ── CI mode: concise output ──
    if ci:
        stats = compute_stats(
            result,
            fp_removed=fp_result.removed_count if fp_result else 0,
            fp_downgraded=fp_result.downgraded_count if fp_result else 0,
            confirmed=classifier_result.confirmed if classifier_result else 0,
            investigate=classifier_result.investigate if classifier_result else 0,
            best_practice=classifier_result.best_practice if classifier_result else 0,
            likely_fp=classifier_result.likely_fp if classifier_result else 0,
        )
        print(generate_ci_summary(stats))
        if exit_code and not result.clean:
            sys.exit(1)
        return

    # ── Auto report generation ──
    if auto_report_path:
        fp_removed = fp_result.removed_count if fp_result else 0
        fp_downgraded = fp_result.downgraded_count if fp_result else 0
        confirmed = classifier_result.confirmed if classifier_result else 0
        investigate = classifier_result.investigate if classifier_result else 0
        best_practice = classifier_result.best_practice if classifier_result else 0
        likely_fp = classifier_result.likely_fp if classifier_result else 0

        stats = compute_stats(
            result,
            fp_removed=fp_removed,
            fp_downgraded=fp_downgraded,
            confirmed=confirmed,
            investigate=investigate,
            best_practice=best_practice,
            likely_fp=likely_fp,
        )

        fp_summary = describe_filters(fp_result) if fp_result else ""
        cls_summary = describe_classification(classifier_result) if classifier_result else ""

        report_md = generate_markdown_report(result, stats, cls_summary, fp_summary)
        with open(auto_report_path, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"Auto-report saved to: {auto_report_path}", file=sys.stderr)

    # ── Standard output ──
    if output_format.lower() == "json":
        print(json_report(result))
    elif output_format.lower() == "sarif":
        print(sarif_report(result))
    else:
        print_report(result, console)
        # Print pipeline summaries after report
        if not no_fp_filter and fp_result:
            console.print()
            console.print("[dim]" + describe_filters(fp_result) + "[/dim]")
            console.print()
        if not no_classify and classifier_result:
            console.print()
            console.print("[dim]" + describe_classification(classifier_result) + "[/dim]")
            console.print()

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
