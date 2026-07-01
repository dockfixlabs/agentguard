"""ASI01: Prompt Injection -- detects untrusted input flowing into LLM prompts."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Patterns that indicate untrusted data reaching prompt construction
PATTERNS = [
    # Direct user input in prompt strings -- use word boundaries, exclude string literals
    (re.compile(r'(?:prompt|system_prompt|messages)\s*(?:\+?=|\bformat\b|\bf\b)\s*.*(?:\buser_input\b|\buser_request\b|request\.\w+\b|\buser_query\b|\buser_message\b|\buser_msg\b|\buser_content\b|\binput_data\b)', re.I),
     "Untrusted input concatenated into prompt -- prompt injection vector",
     Severity.CRITICAL, 0.9),
    # f-string prompt construction with user data -- use word boundaries
    (re.compile(r'f["\'].*(?:system|assistant|user|prompt).*\{.*(?:\buser_input\b|\buser_msg\b|\buser_message\b|\brequest\b|\buser_query\b|\binput_data\b).*\}', re.I),
     "f-string prompt with user-controlled variable -- prompt injection via format string",
     Severity.CRITICAL, 0.85),
    # .format() on prompt templates with user data
    (re.compile(r'\.format\s*\(\s*.*(?:input|user|request|query|message|content|q=|msg)', re.I),
     "Prompt template formatted with user data -- injection via .format()",
     Severity.HIGH, 0.75),
    # Unescaped HTML/markdown in agent context
    (re.compile(r'(?:innerHTML|dangerouslySetInnerHTML|eval\(.*prompt)', re.I),
     "Prompt output rendered as HTML -- XSS via prompt injection",
     Severity.HIGH, 0.7),
    # System prompt override attempts
    (re.compile(r'(?:ignore|disregard|forget).*(?:previous|prior|above|system).*(?:instruction|prompt|rule)', re.I),
     "Potential prompt injection payload in code -- system prompt override pattern",
     Severity.MEDIUM, 0.5),
    # User input assigned to message content variable
    (re.compile(r'(?:content|message|msg)\s*[:=]\s*(?:user_msg|user_input|user_message|request|query)', re.I),
     "Untrusted input assigned to message content -- prompt injection via messages array",
     Severity.HIGH, 0.8),
    # User input in messages array/dict construction
    (re.compile(r'["\'](?:role|content)["\']\s*:\s*(?:user_msg|user_input|user_message|request\.\w+)', re.I),
     "User-controlled variable in messages array -- prompt injection via LLM messages",
     Severity.CRITICAL, 0.85),
]


class PromptInjectionRule(Rule):
    rule_id = "ASI01-PROMPT-INJECTION"
    rule_name = "Prompt Injection"
    severity = Severity.CRITICAL
    owasp = OWASP_ASI.ASI01

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        for pattern, desc, sev, confidence in PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=sev,
                    owasp=self.owasp,
                    file=file,
                    line=line_num,
                    snippet=stripped[:200],
                    description=desc,
                    recommendation="Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters. Consider prompt shielding and input/output filtering.",
                    confidence=confidence,
                ))
        return findings
