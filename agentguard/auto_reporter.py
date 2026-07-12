"""Auto Reporter — automatic structured report generation.

Generates comprehensive audit reports in multiple formats:
- Markdown: Executive summary, severity breakdown, top findings, recommendations
- JSON: Machine-readable aggregated statistics
- CI Summary: Concise one-liner for CI/CD pipelines

Runs after FP filtering and classification to produce final,
human-readable output that does not require LLM interpretation.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from agentguard.models import Finding, Severity, ScanResult, OWASP_ASI

try:
    from agentguard import __version__
except ImportError:
    __version__ = "unknown"


# ── Severity weights for risk scoring ────────────────────────────────
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class ReportStats:
    """Aggregated statistics for auto-reporting."""
    target: str
    files_scanned: int
    scan_duration_ms: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    risk_score: int  # Weighted sum
    confirmed: int
    investigate: int
    best_practice: int
    likely_fp: int
    fp_removed: int
    fp_downgraded: int
    top_rules: list[tuple[str, int, Severity]]  # (rule_name, count, severity)
    top_files: list[tuple[str, int]]  # (file, count)
    owasp_breakdown: dict[str, int] = field(default_factory=dict)
    framework_health: str = ""  # "HEALTHY", "NEEDS REVIEW", "CRITICAL"


def compute_stats(
    result: ScanResult,
    fp_removed: int = 0,
    fp_downgraded: int = 0,
    confirmed: int = 0,
    investigate: int = 0,
    best_practice: int = 0,
    likely_fp: int = 0,
) -> ReportStats:
    """Compute aggregated statistics from a scan result."""
    risk_score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in result.findings)

    # Top rules by count
    rule_counter: Counter = Counter()
    for f in result.findings:
        rule_counter[f.rule_name] += 1

    # Get severity per rule
    rule_severity: dict[str, Severity] = {}
    for f in result.findings:
        if f.rule_name not in rule_severity:
            rule_severity[f.rule_name] = f.severity

    top_rules = [
        (name, count, rule_severity.get(name, Severity.INFO))
        for name, count in rule_counter.most_common(10)
    ]

    # Top files by finding count
    file_counter: Counter = Counter(f.file for f in result.findings)
    top_files = file_counter.most_common(10)

    # OWASP breakdown
    owasp_counter: Counter = Counter()
    for f in result.findings:
        if f.owasp:
            owasp_counter[f.owasp.value] += 1

    # Framework health assessment
    if result.critical_count == 0 and result.high_count == 0:
        health = "HEALTHY — No critical or high findings"
    elif result.critical_count <= 5:
        health = "NEEDS REVIEW — Few critical findings"
    elif result.critical_count <= 20:
        health = "WARNING — Significant critical findings"
    else:
        health = "CRITICAL — Large number of critical findings requiring immediate attention"

    # Detect if classification tags are present in descriptions
    if confirmed == 0 and investigate == 0:
        # Classification not applied yet — estimate from raw counts
        total = len(result.findings)
        if total > 0:
            cr = result.critical_count
            hr = result.high_count
            confirmed = cr  # Critical findings are almost certainly confirmed
            investigate = hr
            best_practice = result.medium_count + result.low_count
            likely_fp = result.info_count

    return ReportStats(
        target=result.target,
        files_scanned=result.files_scanned,
        scan_duration_ms=result.scan_duration_ms,
        total_findings=len(result.findings),
        critical=result.critical_count,
        high=result.high_count,
        medium=result.medium_count,
        low=result.low_count,
        info=result.info_count,
        risk_score=risk_score,
        confirmed=confirmed,
        investigate=investigate,
        best_practice=best_practice,
        likely_fp=likely_fp,
        fp_removed=fp_removed,
        fp_downgraded=fp_downgraded,
        top_rules=top_rules,
        top_files=top_files,
        owasp_breakdown=dict(owasp_counter),
        framework_health=health,
    )


def generate_markdown_report(
    result: ScanResult,
    stats: ReportStats,
    classification_summary: str = "",
    fp_summary: str = "",
) -> str:
    """Generate a comprehensive Markdown audit report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []

    # ── Header ──
    lines.append(f"# AgentGuard Security Audit Report")
    lines.append(f"")
    lines.append(f"**Tool:** AgentGuard v{__version__} | **Date:** {now}")
    lines.append(f"**Target:** `{stats.target}` | **Files scanned:** {stats.files_scanned}")
    lines.append(f"**Scan duration:** {stats.scan_duration_ms}ms")
    lines.append(f"")

    # ── Executive Summary ──
    lines.append(f"## Executive Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total findings | {stats.total_findings} |")
    lines.append(f"| CRITICAL | {stats.critical} |")
    lines.append(f"| HIGH | {stats.high} |")
    lines.append(f"| MEDIUM | {stats.medium} |")
    lines.append(f"| LOW | {stats.low} |")
    lines.append(f"| INFO | {stats.info} |")
    lines.append(f"| Risk Score | {stats.risk_score} |")
    lines.append(f"| Health | **{stats.framework_health}** |")
    lines.append(f"")

    # ── Classification Summary ──
    if stats.confirmed > 0 or stats.investigate > 0:
        lines.append(f"## Classification")
        lines.append(f"")
        lines.append(f"| Category | Count | Description |")
        lines.append(f"|----------|-------|-------------|")
        lines.append(f"| CONFIRMED | {stats.confirmed} | Actionable, high-confidence vulnerabilities |")
        lines.append(f"| INVESTIGATE | {stats.investigate} | Needs human review |")
        lines.append(f"| BEST_PRACTICE | {stats.best_practice} | Security pattern, not exploitable |")
        lines.append(f"| LIKELY_FP | {stats.likely_fp} | Probable false positive |")
        if stats.fp_removed > 0 or stats.fp_downgraded > 0:
            lines.append(f"| FP Removed | {stats.fp_removed} | Auto-filtered false positives |")
            lines.append(f"| FP Downgraded | {stats.fp_downgraded} | Severity reduced |")
        lines.append(f"")

    # ── Top Vulnerabilities by Rule ──
    lines.append(f"## Top Detection Rules")
    lines.append(f"")
    lines.append(f"| Rule | Count | Severity |")
    lines.append(f"|------|-------|----------|")
    for rule_name, count, sev in stats.top_rules:
        lines.append(f"| {rule_name} | {count} | {sev.value} |")
    lines.append(f"")

    # ── Top Affected Files ──
    lines.append(f"## Most Affected Files")
    lines.append(f"")
    lines.append(f"| File | Findings |")
    lines.append(f"|------|----------|")
    for filepath, count in stats.top_files:
        short_path = _shorten_path(filepath)
        lines.append(f"| {short_path} | {count} |")
    lines.append(f"")

    # ── OWASP ASI Coverage ──
    if stats.owasp_breakdown:
        lines.append(f"## OWASP ASI Coverage")
        lines.append(f"")
        lines.append(f"| Category | Findings |")
        lines.append(f"|----------|----------|")
        for cat, count in sorted(stats.owasp_breakdown.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")
        lines.append(f"")

    # ── Critical/High Findings Detail ──
    critical_high = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical_high:
        lines.append(f"## Critical & High Findings")
        lines.append(f"")
        for f in critical_high[:30]:  # Cap at 30 for readability
            sev_marker = "[!]" if f.severity == Severity.CRITICAL else "[H]"
            short_path = _shorten_path(f.file)
            lines.append(f"### {sev_marker} {f.rule_name} — `{short_path}:{f.line}`")
            lines.append(f"")
            lines.append(f"**Confidence:** {f.confidence:.0%} | **OWASP:** {f.owasp.value if f.owasp else 'N/A'}")
            lines.append(f"")
            lines.append(f"> {f.description}")
            lines.append(f"")
            lines.append(f"**Snippet:**")
            lines.append(f"```")
            lines.append(f"{f.snippet}")
            lines.append(f"```")
            lines.append(f"")
            lines.append(f"**Recommendation:** {f.recommendation}")
            lines.append(f"")
        if len(critical_high) > 30:
            lines.append(f"*... and {len(critical_high) - 30} more critical/high findings*")
            lines.append(f"")

    # ── Filtering Summary ──
    if fp_summary:
        lines.append(f"## False Positive Filtering")
        lines.append(f"")
        lines.append(f"```")
        lines.append(fp_summary)
        lines.append(f"```")
        lines.append(f"")

    # ── Recommendations ──
    lines.append(f"## Top Recommendations")
    lines.append(f"")
    seen_rules: set[str] = set()
    for f in result.findings:
        if f.rule_name not in seen_rules:
            seen_rules.add(f.rule_name)
            lines.append(f"- **{f.rule_name}:** {f.recommendation}")
    lines.append(f"")

    # ── Footer ──
    lines.append(f"---")
    lines.append(f"*Report generated by [AgentGuard](https://github.com/dockfixlabs/agentguard) v{__version__} — AI Agent Security Scanner*")
    lines.append(f"*OWASP ASI Top 10 coverage | 22+ detection rules | Static analysis for AI agent codebases*")

    return "\n".join(lines)


def generate_json_summary(
    result: ScanResult,
    stats: ReportStats,
) -> str:
    """Generate a JSON summary for programmatic consumption."""
    summary = {
        "tool": "AgentGuard",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": stats.target,
        "files_scanned": stats.files_scanned,
        "scan_duration_ms": stats.scan_duration_ms,
        "summary": {
            "total": stats.total_findings,
            "critical": stats.critical,
            "high": stats.high,
            "medium": stats.medium,
            "low": stats.low,
            "info": stats.info,
            "risk_score": stats.risk_score,
            "framework_health": stats.framework_health,
        },
        "classification": {
            "confirmed": stats.confirmed,
            "investigate": stats.investigate,
            "best_practice": stats.best_practice,
            "likely_fp": stats.likely_fp,
            "fp_removed": stats.fp_removed,
            "fp_downgraded": stats.fp_downgraded,
        },
        "top_rules": [
            {"rule": name, "count": count, "severity": sev.value}
            for name, count, sev in stats.top_rules
        ],
        "top_files": [
            {"file": filepath, "count": count}
            for filepath, count in stats.top_files
        ],
        "owasp_coverage": stats.owasp_breakdown,
        "critical_findings": [
            {
                "rule": f.rule_name,
                "rule_id": f.rule_id,
                "file": f.file,
                "line": f.line,
                "confidence": f.confidence,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in result.findings
            if f.severity == Severity.CRITICAL
        ],
    }
    return json.dumps(summary, indent=2)


def generate_ci_summary(stats: ReportStats) -> str:
    """Generate a concise one-line summary for CI/CD pipelines."""
    parts = []
    parts.append(f"AgentGuard: {stats.files_scanned} files")
    parts.append(f"{stats.critical}C/{stats.high}H/{stats.medium}M")
    parts.append(f"score={stats.risk_score}")
    parts.append(f"[{stats.framework_health.split(' — ')[0]}]")
    return " | ".join(parts)


def _shorten_path(path: str, max_len: int = 50) -> str:
    """Shorten a file path for display."""
    if len(path) <= max_len:
        return path
    parts = path.replace("\\", "/").split("/")
    if len(parts) <= 2:
        return path[-max_len:]
    return ".../" + "/".join(parts[-2:])
