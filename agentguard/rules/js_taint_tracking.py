"""AST-based taint tracking for JavaScript/TypeScript agent code.

Tracks data flow from untrusted sources to LLM sinks in JS/TS files.
Uses regex-based structural analysis (no JS parser dependency).
"""

from __future__ import annotations

import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# JS/TS source patterns: variables/params that indicate untrusted input
JS_SOURCES = {
    "userInput", "userMessage", "userMsg", "userQuery", "userInput",
    "request", "req", "inputData", "query", "message",
    "promptInput", "chatInput", "msg",
    "result", "toolResult", "toolOutput", "responseText",
    "searchResult", "webResult", "apiResponse",
    "ctx", "context", "interaction", "event",
}

# JS/TS source attribute patterns
JS_SOURCE_ATTR = re.compile(
    r'(?:request|req|ctx|interaction|event)\s*(?:\.\w+)*\s*[\(\[]\s*["\']?\w+["\']?\s*[\)\]]',
    re.I
)

# JS/TS sink function patterns
JS_SINK_FUNCS = re.compile(
    r'(?:openai|anthropic|client|llm|model|ai)\s*\.\s*(?:chat|completions|messages|generate|complete|invoke)\b',
    re.I
)

# JS/TS sink variable names
JS_SINK_VARS = {
    "prompt", "systemPrompt", "messages", "instruction",
    "systemMessage", "userPrompt", "chatPrompt",
    "system_prompt", "user_message",
}

# Sanitizer functions in JS/TS
JS_SANITIZERS = {
    "String", "Number", "Boolean", "parseInt", "parseFloat",
    "encodeURIComponent", "escape", "sanitize", "validate", "filter",
    "DOMPurify.sanitize", "encodeURI",
}


class JSTaintTrackingRule(Rule):
    """AST-based taint tracking for JavaScript/TypeScript.

    Since we cannot parse JS AST without a dependency, this uses
    structural regex analysis to approximate taint flow.
    """
    rule_id = "ASI01-JS-TAINT"
    rule_name = "JS Taint Tracking"
    severity = Severity.CRITICAL
    owasp = OWASP_ASI.ASI01

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings: list[Finding] = []
        
        # Only scan JS/TS files
        if not any(file.endswith(ext) for ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
            return findings
        
        lines = content.splitlines()

        tainted_vars: dict[str, int] = {}  # var_name -> line where tainted

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Track function parameters with taint-suggesting names
            param_match = re.match(
                r'(?:async\s+)?function\s+\w+\s*\(([^)]+)\)|'
                r'(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\(([^)]+)\)\s*=>',
                stripped
            )
            if param_match:
                params = (param_match.group(1) or param_match.group(2) or "")
                for p in params.split(","):
                    p = p.strip().split("=")[0].strip().split(":")[0].strip()
                    if p and p in JS_SOURCES:
                        tainted_vars[p] = i

            # Detect source assignment: const/let/var x = <source>
            assign_match = re.match(
                r'(?:const|let|var)\s+(\w+)\s*=\s*(.+)',
                stripped
            )
            if assign_match:
                var_name = assign_match.group(1)
                rhs = assign_match.group(2)

                if self._is_js_source(rhs) or self._is_tainted_var(rhs, tainted_vars):
                    if not self._is_sanitized(rhs):
                        tainted_vars[var_name] = i
                        # Check if assigning to a sink variable
                        if var_name in JS_SINK_VARS:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=Severity.CRITICAL,
                                owasp=self.owasp,
                                file=file,
                                line=i,
                                snippet=stripped[:200],
                                description=f"Untrusted data assigned to LLM sink variable '{var_name}' in JS/TS",
                                recommendation="Sanitize and validate all user input before including in prompts. Use structured prompts with clear delimiters.",
                                confidence=0.85,
                            ))
                else:
                    # Variable reassigned to safe value -- remove taint
                    tainted_vars.pop(var_name, None)

            # Detect reassignment (no const/let/var): x = <expr>
            reassign_match = re.match(r'(\w+)\s*=\s*(.+)', stripped)
            if reassign_match and not assign_match:
                var_name = reassign_match.group(1)
                rhs = reassign_match.group(2)
                if self._is_js_source(rhs) or self._is_tainted_var(rhs, tainted_vars):
                    if not self._is_sanitized(rhs):
                        tainted_vars[var_name] = i
                        if var_name in JS_SINK_VARS:
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=Severity.CRITICAL,
                                owasp=self.owasp,
                                file=file,
                                line=i,
                                snippet=stripped[:200],
                                description=f"Untrusted data reassigned to LLM sink variable '{var_name}' in JS/TS",
                                recommendation="Sanitize and validate all user input before including in prompts.",
                                confidence=0.85,
                            ))
                else:
                    tainted_vars.pop(var_name, None)

            # Detect LLM sink function calls with tainted args
            if JS_SINK_FUNCS.search(stripped):
                # Check this line and next few lines (multi-line calls)
                call_block = stripped
                for j in range(i, min(i + 5, len(lines) + 1)):
                    if j < len(lines):
                        call_block += " " + lines[j].strip()
                for var_name in tainted_vars:
                    if re.search(r'\b' + re.escape(var_name) + r'\b', call_block):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.CRITICAL,
                            owasp=self.owasp,
                            file=file,
                            line=i,
                            snippet=stripped[:200],
                            description=f"Tainted variable '{var_name}' passed to LLM API call in JS/TS",
                            recommendation="Sanitize input before passing to LLM APIs. Use structured prompts with delimiters.",
                            confidence=0.8,
                        ))
                        break

            # Detect template literal with tainted var in prompt context
            if re.search(r'(?:prompt|messages|systemPrompt|instruction)', stripped, re.I):
                if '`' in stripped or '${' in stripped:
                    for var_name in tainted_vars:
                        if re.search(r'\$\{' + re.escape(var_name) + r'\}', stripped) or re.search(r'\b' + re.escape(var_name) + r'\b', stripped):
                            findings.append(Finding(
                                rule_id=self.rule_id,
                                rule_name=self.rule_name,
                                severity=Severity.HIGH,
                                owasp=self.owasp,
                                file=file,
                                line=i,
                                snippet=stripped[:200],
                                description=f"Tainted variable '{var_name}' in prompt template literal in JS/TS",
                                recommendation="Sanitize input before interpolating into prompts. Use structured prompts.",
                                confidence=0.75,
                            ))
                            break

        return findings

    def _is_js_source(self, expr: str) -> bool:
        """Check if a JS expression is a taint source."""
        # Check for source variable names
        for src in JS_SOURCES:
            if re.search(r'\b' + re.escape(src) + r'\b', expr):
                return True
        # Check for attribute access patterns
        if JS_SOURCE_ATTR.search(expr):
            return True
        # Check for req.query, req.body, req.params
        if re.search(r'req\s*\.\s*(?:query|body|params|headers|cookies)', expr, re.I):
            return True
        # Check for request.args equivalent
        if re.search(r'request\s*\.\s*(?:query|body|params|headers|cookies|args|json|form)', expr, re.I):
            return True
        # Check for ctx.message, interaction.options
        if re.search(r'(?:ctx|context|interaction|event)\s*\.\s*(?:message|options|args|input|content|text|query)', expr, re.I):
            return True
        # Check for process.argv
        if 'process.argv' in expr:
            return True
        return False

    def _is_tainted_var(self, expr: str, tainted_vars: dict[str, int]) -> bool:
        """Check if expression references a tainted variable."""
        for var_name in tainted_vars:
            if re.search(r'\b' + re.escape(var_name) + r'\b', expr):
                return True
        return False

    def _is_sanitized(self, expr: str) -> bool:
        """Check if expression is wrapped in a sanitizer."""
        for sanitizer in JS_SANITIZERS:
            if sanitizer + '(' in expr:
                return True
        return False

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []
