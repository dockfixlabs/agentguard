"""Prompt Template Injection Detection (ASI-PROMPT-TEMPLATE)

Detects when user data is interpolated into prompt TEMPLATES
rather than prompt CONTENT -- a structural attack where the
attacker controls the prompt format, not just its text.

This is more dangerous than content injection because it can:
- Change the system/user role boundaries
- Inject fake conversation history
- Restructure the entire prompt format
- Bypass content-based sanitizers by attacking the template
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class PromptTemplateRule(Rule):
    """Detects template injection in LLM prompts.

    When user data controls the STRUCTURE of a prompt (not just its text),
    attackers can manipulate system/user role boundaries, inject fake
    conversation turns, or restructure the entire prompt format.
    """

    rule_id = "ASI-PROMPT-TEMPLATE"
    rule_name = "Prompt Template Injection"
    severity = Severity.CRITICAL

    # User data in system prompt template position
    SYSTEM_TEMPLATE_INJECT = re.compile(
        rb'"system"\s*:\s*\{[^}]*"content"\s*:\s*[^}]*\}',
        re.IGNORECASE
    )

    # Jinja2 template with user variables in prompt context
    JINJA2_IN_PROMPT = re.compile(
        rb"jinja2|Template\s*\(|\.render\s*\(\s*.*user|"
        rb"\.from_string\s*\(|Environment\s*\(\s*\)",
        re.IGNORECASE
    )

    # f-string template that builds message structure
    FSTRING_MESSAGE_STRUCTURE = re.compile(
        rb'f["\']\s*\{\s*"role"\s*:|f["\'].*"role"\s*:|'
        rb'f["\'].*"messages"\s*:|'
        rb'f["\']\s*\[.*\{.*role.*\}.*\].*["\']',
        re.IGNORECASE
    )

    # Variable controlling conversation structure
    CONVERSATION_STRUCTURE = re.compile(
        rb'\.extend\s*\(\s*.+input|\.append\s*\(\s*\{.*"role"|'
        rb'messages\s*\+=\s*\[|messages\.(extend|append)\s*\(',
        re.IGNORECASE
    )

    # Taint sources in template contexts
    TEMPLATE_TAINT = re.compile(
        rb"user[_]?input|user[_]?message|user[_]?query|"
        rb"request\.(body|data|json|form|args)|request[_]data|"
        rb"user[_]?provided|attacker[_]?controlled|"
        rb"external[_]?input|untrusted[_]?(data|input|content|source)",
        re.IGNORECASE
    )

    def scan_line(self, line, line_num, file):
        return []

    def scan_content(self, content, file):
        ext = file.rsplit(".", 1)[-1] if "." in file else ""
        if ext not in ("py", "js", "ts", "jsx", "tsx"):
            return []

        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            encoded = line.encode("utf-8", errors="ignore")

            # Detect Jinja2 template injection in prompts
            if self.JINJA2_IN_PROMPT.search(encoded):
                ctx = " ".join(lines[max(0, i-3):min(len(lines), i+3)])
                if self.TEMPLATE_TAINT.search(ctx.encode("utf-8", errors="ignore")):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.CRITICAL,
                        file=file,
                        line=i,
                        snippet=line.strip()[:120],
                        description="Jinja2 template rendering with user-controlled data -- template injection enables structural prompt manipulation",
                        recommendation="Never pass user data directly to template.render(). Use whitelist-based template variables. Escape all user inputs before template rendering.",
                        confidence=0.9,
                    ))
                    continue

            # Detect f-string building message structure
            if self.FSTRING_MESSAGE_STRUCTURE.search(encoded):
                ctx = " ".join(lines[max(0, i-2):min(len(lines), i+2)])
                if self.TEMPLATE_TAINT.search(ctx.encode("utf-8", errors="ignore")):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        file=file,
                        line=i,
                        snippet=line.strip()[:120],
                        description="Message structure built from f-string with user data -- attacker can inject fake conversation turns",
                        recommendation="Build message structures from validated templates. Never use f-strings to construct message role/content objects with user data.",
                        confidence=0.85,
                    ))
                    continue

            # Detect conversation structure manipulation
            if self.CONVERSATION_STRUCTURE.search(encoded):
                ctx = " ".join(lines[max(0, i-2):min(len(lines), i+2)])
                if self.TEMPLATE_TAINT.search(ctx.encode("utf-8", errors="ignore")):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        file=file,
                        line=i,
                        snippet=line.strip()[:120],
                        description="Conversation structure manipulation with user data -- attacker can inject fake messages into history",
                        recommendation="Validate message structure before appending to conversation. Sanitize role fields. Use typed message objects.",
                        confidence=0.8,
                    ))
                    continue

        return findings
