"""ASI08: Context Window Manipulation — detects context overflow attack vectors."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# No max token limit on inputs
NO_TOKEN_LIMIT = re.compile(
    r'(?:max_tokens|token_limit|max_length|max_chars|max_input)\s*[:=]\s*(?:None|null|0|float\([\'"]inf|math\.inf|999999|1000000)',
    re.I
)

# Unbounded context accumulation
UNBOUNDED_CONTEXT = re.compile(
    r'(?:context|history|messages|memory|buffer)\s*(?:\.\s*append|\s*\+=|\.\s*extend)\s*',
    re.I
)

# No truncation before LLM call
NO_TRUNCATION = re.compile(
    r'(?:messages|context|history)\s*\]\s*\n\s*(?:completion|chat|generate|invoke|call)',
    re.I
)

# Large file read into context
FILE_TO_CONTEXT = re.compile(
    r'(?:read|load|open)\s*\(.*\)\s*\.\s*(?:read|text|content)\s*(?:\+?=|\bformat\b)',
    re.I
)


class ContextManipulationRule(Rule):
    rule_id = "ASI08-CONTEXT-MANIPULATION"
    rule_name = "Context Window Manipulation"
    severity = Severity.MEDIUM
    owasp = OWASP_ASI.ASI08

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        if NO_TOKEN_LIMIT.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.MEDIUM,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="No token/length limit set — context window overflow risk",
                recommendation="Set explicit max_tokens and max_input_length. Truncate or summarize long inputs before sending to LLM.",
                confidence=0.7,
            ))

        if FILE_TO_CONTEXT.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.MEDIUM,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="File content loaded directly into LLM context — overflow injection risk",
                recommendation="Limit file size before loading into context. Use chunking and summarization for large files.",
                confidence=0.6,
            ))

        return findings
