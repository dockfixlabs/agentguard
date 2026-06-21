"""ASI02: Tool Abuse — detects agents with unrestricted or dangerous tool access."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Dangerous tool patterns
DANGEROUS_TOOLS = re.compile(
    r'(?:exec|eval|subprocess|os\.system|os\.popen|os\.exec|os\.spawn|'
    r'child_process|run_command|shell_exec|popen|pty\.spawn|commands\.)',
    re.I
)

# Unrestricted tool registration
UNRESTRICTED_TOOL = re.compile(
    r'(?:register_tool|add_tool|define_tool|tool_manager\.\w+)\s*\(\s*.*(?:all|any|\*|wildcard|unlimited)',
    re.I
)

# No rate limiting on tool calls
NO_RATE_LIMIT = re.compile(
    r'(?:max_calls|rate_limit|max_iterations|timeout)\s*[:=]\s*(?:None|null|0|float\([\'"]inf|math\.inf|-1)',
    re.I
)

# Shell/code execution tools exposed to agent
SHELL_TOOL = re.compile(
    r'(?:tool_name|name|function)\s*[:=]\s*["\'](?:shell|bash|exec|eval|run_command|terminal|cmd|powershell)["\']',
    re.I
)

# Arbitrary file access
FILE_ACCESS = re.compile(
    r'(?:tool_name|name|function)\s*[:=]\s*["\'](?:read_file|write_file|delete_file|file_operations|filesystem)["\'].*(?:\*|any|all|root|/)',
    re.I
)

# Network access without restrictions
NETWORK_TOOL = re.compile(
    r'(?:tool_name|name|function)\s*[:=]\s*["\'](?:http_request|fetch|curl|wget|web_search|browse)["\'].*(?:\*|any|all|unlimited)',
    re.I
)


class ToolAbuseRule(Rule):
    rule_id = "ASI02-TOOL-ABUSE"
    rule_name = "Unrestricted Tool Access"
    severity = Severity.HIGH
    owasp = OWASP_ASI.ASI02

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()

        if DANGEROUS_TOOLS.search(stripped) and not stripped.startswith("#"):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Dangerous system-level tool accessible to agent — code execution capability",
                recommendation="Remove shell/exec access from agents. Use sandboxed, whitelisted tool implementations. Never expose raw subprocess to LLM-controlled code.",
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
                recommendation="Explicitly whitelist allowed tools per agent role. Implement tool-level RBAC.",
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

        if SHELL_TOOL.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Shell/terminal tool exposed to agent — arbitrary code execution",
                recommendation="Never expose shell access to AI agents. Use restricted, purpose-built tools instead.",
                confidence=0.95,
            ))

        return findings
