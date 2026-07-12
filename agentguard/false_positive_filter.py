"""False Positive Filter — automatic FP detection and confidence adjustment.

Post-scan filtering layer that identifies likely false positives using:
1. Rule-specific exclusion patterns (known FP regexes per rule)
2. File-level heuristics (__init__.py, setup.py, conftest, etc.)
3. Content-level heuristics (comments, docs, test code patterns)
4. Density-based anomaly detection (single rule flooding one file)

This runs AFTER all rules have fired and adjusts confidence/severity
or removes findings that match known FP patterns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections import Counter

from agentguard.models import Finding, Severity


# ── Rule-specific FP exclusion patterns ──────────────────────────────
# Each key is a rule_id prefix. Each value is a list of (regex, reason) tuples.
# When a finding's snippet matches one of these, its confidence is zeroed.

RULE_FP_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "ASI-AGENT-COLLUSION": [
        # Detecting agent collusion IN code ABOUT agent collusion detection
        (re.compile(r'\bdetect\b.*\bcollusion\b|\bcollusion\b.*\bdetect\b|\bagent_collusion\b', re.I),
         "Security research code — detecting collusion, not enabling it"),
        # Config/registry files
        (re.compile(r'__all__|__version__|package_name|entry_point|console_scripts', re.I),
         "Package metadata — not agent code"),
        # Standalone "Team" or "Group" class names (not agent teams)
        (re.compile(r'class\s+(Team|Group|Swarm|Crew)\b', re.I),
         "Class definition name — not necessarily agent team"),
    ],
    "ASI09-AGENT-LOOP": [
        # while True in event loops / servers / main
        (re.compile(r'(?:event[_ ]?loop|main[_ ]?loop|run[_ ]?server|start[_ ]?server|serve[_ ]?forever|poll[_ ]?loop)', re.I),
         "Event loop / server main loop — legitimate infinite loop"),
        # while True in CLI entry points
        (re.compile(r'if\s+__name__\s*==\s*["\']__main__["\']', re.I),
         "CLI entry point — not agent loop"),
        # Test fixtures with while True
        (re.compile(r'\btest_|def test_|class Test', re.I),
         "Test code — intentional infinite loops for testing"),
    ],
    "ASI01-PROMPT-INJECTION": [
        # Documentation about prompt injection
        (re.compile(r'\bprompt[_ ]?injection\b.*\b(?:detect|prevent|mitigate|fix|protect|guard|sanitize)\b', re.I),
         "Security documentation — describing mitigation, not vulnerable code"),
        (re.compile(r'\b(?:ignore|disregard|forget)\b.*\bprevious\b.*\b(?:instruction|prompt)\b.*#.*(?:test|demo|example|sample)', re.I),
         "Test/demo payload — not production injection vector"),
        # JSON/TOML/YAML config files with prompt template fields
        (re.compile(r'\.(?:json|toml|yaml|yml):', re.I),
         "Config file — not executable code"),
        # Sanitization calls — defense, not vulnerability
        (re.compile(r'_sanitize\b|sanitize_\w+\(|deepcopy\(', re.I),
         "Input sanitization or defensive copy — not injection"),
        # Variable assignment from event data (not user input)
        (re.compile(r'\bag_ui_messages\b|\bev\.\w+_data\b', re.I),
         "UI event data assignment — not direct user input"),
    ],
    "ASI-MOUNT-EXPOSURE": [
        # Class definitions matching Docker executor name
        (re.compile(r'^\s*class\s+', re.I),
         "Class definition — not instantiation"),
        # Deprecation warning strings
        (re.compile(r'\bdeprecated\b', re.I),
         "Deprecation warning — not active mount exposure"),
    ],
    "ASI10-TRUST-BOUNDARY": [
        # def _update_prompts, def update(self, ...) — method definitions, not self-modification
        (re.compile(r'^\s*def\s+(?:update|_update)\w*\s*\(', re.I),
         "Method definition — update method, not runtime self-modification"),
    ],
    "ASI06-UNSAFE-EVAL": [
        # PyTorch model.eval()
        (re.compile(r'\.eval\(\)', re.I),
         "PyTorch model.eval() — not Python eval()"),
        # eval/exec in prompt strings (not executable)
        (re.compile(r'^\s*["\']', re.I),
         "String literal — not executable code"),
    ],
    "ASI04-EXCESSIVE-AGENCY": [
        # chmod setting restrictive permissions (0o700, 0o600) — securing, not escalating
        (re.compile(r'chmod\s*\(.*0o[0-7]00', re.I),
         "Setting restrictive permissions — securing, not escalating"),
        # Documentation/docstring about os.chmod — broader detection
        (re.compile(r'(?:^\s*["\']|whereas|explicit|chmod.*not\.)', re.I),
         "Docstring or string literal — not executable code"),
    ],
    "ASI01-TAINT-TRACK": [
        # Bare array/message declarations — match messages = [ or messages =\n
        (re.compile(r'^\s*(?:messages|prompt|user_prompt)\s*=\s*\[', re.I),
         "Array declaration — too generic for taint"),
        # I18N/translation lookup
        (re.compile(r'I18N|i18n|translation|locale|gettext', re.I),
         "Internationalization lookup — not user input"),
        # Type casting
        (re.compile(r'cast\(str,', re.I),
         "Type casting — not user input assignment"),
    ],
    "ASI03-DATA-EXFIL": [
        # Normal API headers (not exfiltration)
        (re.compile(r'["\']x-api-key["\']\s*:', re.I),
         "Standard API authentication header — not data exfiltration"),
        # Redacted snippets can't be verified
        (re.compile(r'\*\*\*REDACTED\*\*\*', re.I),
         "Redacted snippet — cannot verify exfiltration"),
    ],
    "ASI05-SUPPLY-CHAIN": [
        # Fetching from built-in/local source
        (re.compile(r'builtin|built_in|buildin|local|internal', re.I),
         "Built-in/local fetch — not remote code execution"),
    ],
    "ASI02-TOOL-ABUSE": [
        # Sandboxed exec in test harnesses
        (re.compile(r'\btest_|def test_|class Test|conftest|fixture', re.I),
         "Test harness — controlled execution environment"),
        # eval in type checking / safe contexts
        (re.compile(r'ast\.literal_eval|json\.loads|safe_eval|restricted_eval', re.I),
         "Safe eval variant — not arbitrary code execution"),
    ],
    "ASI07-CREDENTIAL-LEAK": [
        # Example/test credentials — broader pattern including YOUR_ prefix and *** mask
        (re.compile(r'(?:example|test|demo|sample|placeholder|changeme|xxx|replace|\*\*\*|YOUR_|your-\w+-\w+-|your-?key\b|your-?token\b|your-?secret\b)', re.I),
         "Example/test credential placeholder"),
        # Documentation about credential handling
        (re.compile(r'\b(?:never|don\'?t|do\s+not)\b.*\b(?:hardcode|store|embed|commit)\b.*\b(?:key|token|secret|password|credential)\b', re.I),
         "Security documentation — warning against hardcoding, not hardcoding"),
    ],
}

# ── File-level exclusion patterns ────────────────────────────────────
# Files that are extremely unlikely to contain agent vulnerabilities.
# Findings in these files get confidence set to 0.

FP_FILE_PATTERNS = [
    re.compile(p, re.I) for p in [
        r'__init__\.py$',
        r'setup\.py$',
        r'conftest\.py$',
        r'\.pre-commit.*\.yaml$',
        r'\.pre-commit.*\.yml$',
        r'Makefile$',
        r'Dockerfile$',
        r'\.gitignore$',
        r'\.dockerignore$',
        r'requirements.*\.txt$',
        r'pyproject\.toml$',
        r'\.editorconfig$',
        r'LICENSE$',
        r'NOTICE$',
        r'CODE_OF_CONDUCT\.md$',
        r'CONTRIBUTING\.md$',
        r'SECURITY\.md$',
        r'package-lock\.json$',
        r'package\.json$',
        r'yarn\.lock$',
        r'pnpm-lock\.yaml$',
        r'poetry\.lock$',
        r'Pipfile\.lock$',
    ]
]

# ── Content-level heuristics ─────────────────────────────────────────
# Lines that indicate documentation/commentary, not vulnerability.

FP_CONTENT_PATTERNS = [
    # Commented-out code
    re.compile(r'^\s*#.*$'),
    re.compile(r'^\s*//.*$'),
    # Docstrings
    re.compile(r'^\s*"""'),
    re.compile(r"^\s*'''"),
    re.compile(r'^\s*""".*"""$'),
    # Security documentation
    re.compile(r'\b(?:security|vulnerability|advisory|CVE|GHSA|disclosure|responsible|report)\b', re.I),
    # Type stubs
    re.compile(r'^\s*(?:->|\.\.\.)\s*(?:None|str|int|bool|float|dict|list|tuple|Any|Optional|Union)\s*$'),
]

# ── Density thresholds ───────────────────────────────────────────────
# If a single rule produces more than this many findings in one file,
# flag all of them as suspicious (likely FP pattern flooding).

DENSITY_THRESHOLD = 50  # findings per file per rule
DENSITY_DROP_CONFIDENCE = 0.3  # Multiply confidence by this for density-flagged findings


@dataclass
class FilterResult:
    """Result of applying FP filters to a scan result."""
    original_count: int
    filtered_count: int
    removed_count: int
    downgraded_count: int
    flagged_count: int  # density-flagged but kept
    downgrades: list[dict] = field(default_factory=list)  # {rule_id, file, line, old_sev, new_sev, reason}


def apply_fp_filters(findings: list[Finding]) -> tuple[list[Finding], FilterResult]:
    """Apply all FP filters to a list of findings.

    Returns (filtered_findings, filter_result).
    """
    original_count = len(findings)
    removed_count = 0
    downgraded_count = 0
    flagged_count = 0
    downgrades: list[dict] = []

    # Step 1: Count density per (file, rule_id)
    density_counter: Counter = Counter()
    for f in findings:
        density_counter[(f.file, f.rule_id)] += 1

    density_flagged: set[tuple[str, str]] = set()
    for (file, rule_id), count in density_counter.items():
        if count >= DENSITY_THRESHOLD:
            density_flagged.add((file, rule_id))

    # Step 2: Apply filters to each finding
    filtered: list[Finding] = []
    for f in findings:
        should_remove = False
        confidence = f.confidence

        # 2a: File-level FP check
        if _is_fp_file(f.file):
            should_remove = True
            downgrades.append({
                "rule_id": f.rule_id, "file": f.file, "line": f.line,
                "old_sev": f.severity.value, "new_sev": "REMOVED",
                "reason": "FP: metadata/config file"
            })

        # 2b: Rule-specific FP patterns
        if not should_remove:
            # Build search text from snippet, description AND file path
            search_text = f.snippet + ' ' + f.description
            for rule_prefix, patterns in RULE_FP_PATTERNS.items():
                if f.rule_id.startswith(rule_prefix):
                    for pattern, reason in patterns:
                        if pattern.search(search_text) or pattern.search(f.file):
                            should_remove = True
                            downgrades.append({
                                "rule_id": f.rule_id, "file": f.file, "line": f.line,
                                "old_sev": f.severity.value, "new_sev": "REMOVED",
                                "reason": f"FP: {reason}"
                            })
                            break
                    break  # Only check matching rule prefix

        # 2c: Content-level FP check
        if not should_remove:
            for pattern in FP_CONTENT_PATTERNS:
                if pattern.search(f.snippet):
                    should_remove = True
                    downgrades.append({
                        "rule_id": f.rule_id, "file": f.file, "line": f.line,
                        "old_sev": f.severity.value, "new_sev": "REMOVED",
                        "reason": "FP: documentation/comment line"
                    })
                    break

        # 2d: Ultra-low confidence
        if not should_remove and f.confidence < 0.4:
            should_remove = True
            downgrades.append({
                "rule_id": f.rule_id, "file": f.file, "line": f.line,
                "old_sev": f.severity.value, "new_sev": "REMOVED",
                "reason": f"FP: very low confidence ({f.confidence:.2f})"
            })

        if should_remove:
            removed_count += 1
            continue

        # Step 3: Density-based confidence adjustment (keep but flag)
        if (f.file, f.rule_id) in density_flagged:
            confidence = f.confidence * DENSITY_DROP_CONFIDENCE
            flagged_count += 1

        # Step 4: Severity downgrade for specific patterns
        severity = f.severity
        new_sev = _maybe_downgrade_severity(f)

        if new_sev != severity:
            downgraded_count += 1
            downgrades.append({
                "rule_id": f.rule_id, "file": f.file, "line": f.line,
                "old_sev": severity.value, "new_sev": new_sev.value,
                "reason": "Auto-downgraded: pattern context suggests lower risk"
            })

        # Rebuild finding with adjusted confidence/severity
        filtered.append(Finding(
            rule_id=f.rule_id,
            rule_name=f.rule_name,
            severity=new_sev,
            owasp=f.owasp,
            file=f.file,
            line=f.line,
            column=f.column,
            snippet=f.snippet,
            description=f.description,
            recommendation=f.recommendation,
            confidence=round(confidence, 2),
        ))

    result = FilterResult(
        original_count=original_count,
        filtered_count=len(filtered),
        removed_count=removed_count,
        downgraded_count=downgraded_count,
        flagged_count=flagged_count,
        downgrades=downgrades,
    )

    return filtered, result


def _is_fp_file(filepath: str) -> bool:
    """Check if a file path matches known FP file patterns."""
    import os
    filename = os.path.basename(filepath)
    for pattern in FP_FILE_PATTERNS:
        if pattern.search(filename):
            return True
    return False


def _maybe_downgrade_severity(finding: Finding) -> Severity:
    """Downgrade severity for patterns that are often noisy.

    Returns potentially lower severity, or original if no downgrade needed.
    """
    # ASI-AGENT-COLLUSION: shared state without inter-agent comm is MEDIUM at most
    if finding.rule_id == "ASI-AGENT-COLLUSION" and finding.confidence < 0.7:
        return Severity.LOW

    # ASI09: MEDIUM findings with low confidence -> INFO
    if finding.rule_id == "ASI09-AGENT-LOOP" and finding.severity == Severity.MEDIUM:
        if finding.confidence < 0.6:
            return Severity.INFO

    # ASI01: findings matching "ignore previous instructions" pattern in potential doc
    if finding.rule_id == "ASI01-PROMPT-INJECTION" and finding.confidence < 0.5:
        return Severity.INFO

    return finding.severity


def describe_filters(result: FilterResult) -> str:
    """Human-readable summary of applied FP filters."""
    lines = []
    lines.append(f"FP Filter: {result.original_count} findings -> {result.filtered_count} after filtering")
    lines.append(f"  Removed: {result.removed_count} (certain false positives)")
    lines.append(f"  Downgraded: {result.downgraded_count} (severity reduced)")
    lines.append(f"  Density-flagged: {result.flagged_count} (confidence reduced due to pattern flooding)")

    if result.downgrades:
        # Group by reason
        by_reason: dict[str, int] = {}
        for d in result.downgrades:
            reason = d["reason"]
            by_reason[reason] = by_reason.get(reason, 0) + 1

        lines.append("\n  Breakdown by reason:")
        for reason, count in sorted(by_reason.items(), key=lambda x: -x[1]):
            lines.append(f"    {reason}: {count} findings")

    return "\n".join(lines)
