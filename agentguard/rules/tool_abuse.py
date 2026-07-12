"""ASI02: Tool Abuse — detects agents with unrestricted or dangerous tool access."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Dangerous tool patterns — require actual call syntax, not just name mentions
# Excludes: string literals, variable name assignments, prompt text
DANGEROUS_TOOLS = re.compile(
    r'(?:os\.system\s*\(|os\.popen\s*\(|os\.exec\w*\s*\(|os\.spawn\w*\s*\(|'
    r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(|'
    r'subprocess\.\w+.*shell\s*=\s*True)',
    re.I
)

# Unrestricted tool registration — must be actual function call, not name definition
UNRESTRICTED_TOOL = re.compile(
    r'(?:register_tool|add_tool|define_tool)\s*\(\s*.*(?:all|any|\*|wildcard|unlimited)',
    re.I
)

# No rate limiting on tool calls
NO_RATE_LIMIT = re.compile(
    r'(?:max_calls|rate_limit|max_iterations|timeout)\s*[:=]\s*(?:None|null|0|float\([\'"]inf|math\.inf|-1)',
    re.I
)

# FP FILTERS for this rule
# Matches that are definitely not tool abuse
FP_PATTERNS = [
    # Name constant definitions: THING_NAME = "thing"
    re.compile(r'^\s*[A-Z_]+_NAME\s*=\s*["\']'),
    # String literals at start of line (prompt text, documentation)
    re.compile(r'^\s*["\']'),
    # Tool retrieval/iteration (not execution): get_function_name, filter, next()
    re.compile(r'(?:get_function_name|get_tool|list_tools|filter\(|next\()'),
    # Comments
    re.compile(r'^\s*#'),
    # Deprecation warnings
    re.compile(r'deprecated', re.I),
]


def _is_false_positive(stripped: str) -> bool:
    """Check if a matched line is a known false positive pattern."""
    for pattern in FP_PATTERNS:
        if pattern.search(stripped):
            return True
    return False


class ToolAbuseRule(Rule):
    rule_id = "ASI02-TOOL-ABUSE"
    rule_name = "Unrestricted Tool Access"
    severity = Severity.HIGH
    owasp = OWASP_ASI.ASI02

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()

        # Skip known FP patterns
        if _is_false_positive(stripped):
            return findings

        if DANGEROUS_TOOLS.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Dangerous system-level tool accessible to agent — code execution capability",
                recommendation="Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations.",
                confidence=0.9,
            ))

        if UNRESTRICTED_TOOL.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Tool registered with wildcard/unlimited scope — agent can invoke any tool",
                recommendation="Explicitly whitelist allowed tools per agent role.",
                confidence=0.8,
            ))

        if NO_RATE_LIMIT.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="No rate limit or timeout on tool calls — resource exhaustion risk",
                recommendation="Set explicit max_iterations, rate_limit, and timeout for all tool calls.",
                confidence=0.75,
            ))

        return findings
