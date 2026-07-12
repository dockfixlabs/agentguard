"""AST-based taint tracking for Python agent code.

Tracks data flow from untrusted sources to LLM sinks.
This is the semantic analysis layer that goes beyond regex patterns.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Source patterns: variables/params that indicate untrusted input
SOURCE_PATTERNS = {
    "user_input", "user_msg", "user_message", "user_query",
    "request", "req", "input_data", "query", "message",
    "prompt_input", "chat_input", "msg",
    "result", "tool_result", "tool_output", "response_text",
    "search_result", "web_result", "api_response",
}

# Source attribute access patterns (e.g., request.args.get("q"))
SOURCE_ATTR_PATTERNS = {
    "request", "req", "flask.request",
}

# Sink patterns: functions/variables that send data to LLMs
LLM_SINK_FUNCS = {
    "openai.chat.completions.create",
    "openai.completions.create",
    "anthropic.Anthropic.messages.create",
    "client.chat.completions.create",
    "llm.generate", "llm.chat", "llm.complete",
    "model.generate", "model.chat",
    "client.messages.create",
}

# Variable names that are LLM sinks (prompt, messages, system_prompt)
LLM_SINK_VARS = {
    "prompt", "system_prompt", "messages", "instruction",
    "system_message", "user_prompt", "chat_prompt",
}

# Sanitization functions that make input safe
SANITIZERS = {
    "str", "int", "float", "bool", "len",
    "escape", "html_escape", "bleach.clean",
    "sanitize", "validate", "filter",
}


class TaintTracker:
    """Tracks taint flow through a single function/module."""

    def __init__(self, file: str):
        self.file = file
        self.tainted_vars: dict[str, int] = {}  # var_name -> line where tainted
        self.findings: list[Finding] = []
        self._source_lines: list[str] = []
        try:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                self._source_lines = f.readlines()
        except:
            pass

    def _get_line(self, lineno: int) -> str:
        """Get source line text, 1-indexed."""
        if 0 < lineno <= len(self._source_lines):
            return self._source_lines[lineno - 1].strip()[:200]
        return ""

    def _is_source(self, node: ast.AST) -> bool:
        """Check if an AST node represents a taint source."""
        # Variable name match
        if isinstance(node, ast.Name) and node.id in SOURCE_PATTERNS:
            return True
        # request.args.get("q"), request.json["key"], etc.
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                # request.args.get, request.json.get, request.get
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in SOURCE_ATTR_PATTERNS:
                        return True
        # request.json["key"], request.args["key"]
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute):
                if isinstance(node.value.value, ast.Name):
                    if node.value.value.id in SOURCE_ATTR_PATTERNS:
                        return True
            if isinstance(node.value, ast.Name) and node.value.id in SOURCE_ATTR_PATTERNS:
                return True
        # input() function
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "input":
                return True
        return False

    def _is_sanitized(self, node: ast.AST) -> bool:
        """Check if a node wraps input in a sanitizer."""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in SANITIZERS:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in SANITIZERS:
                return True
        return False

    def _is_llm_sink(self, node: ast.AST) -> tuple[bool, str]:
        """Check if an AST node is an LLM sink. Returns (is_sink, description)."""
        # Assignment to prompt/messages/system_prompt variable
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in LLM_SINK_VARS:
                    return True, f"User input assigned to LLM sink variable '{target.id}'"
        # Function call to LLM API
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            return self._check_llm_call(node.value)
        if isinstance(node, ast.Call):
            return self._check_llm_call(node)
        return False, ""

    def _check_llm_call(self, call: ast.Call) -> tuple[bool, str]:
        """Check if a function call is an LLM API call with tainted data."""
        func = call.func
        # Build the dotted name (e.g., openai.chat.completions.create)
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        dotted = ".".join(reversed(parts))

        if dotted in LLM_SINK_FUNCS or any(dotted.endswith(s) for s in LLM_SINK_FUNCS):
            # Check if any argument is tainted
            for kw in call.keywords:
                if kw.arg in ("messages", "prompt", "content", "input"):
                    if self._expr_is_tainted(kw.value):
                        return True, f"Tainted data passed to LLM via '{dotted}' parameter '{kw.arg}'"
            for arg in call.args:
                if self._expr_is_tainted(arg):
                    return True, f"Tainted data passed to LLM via '{dotted}'"
        return False, ""

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        """Check if an expression contains tainted data."""
        if self._is_source(node):
            return True
        if self._is_sanitized(node):
            return False
        # Variable reference
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return True
        # F-string with tainted variable
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if self._expr_is_tainted(val.value):
                        return True
        # Binary op (string concatenation)
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        # .format() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                for arg in node.args:
                    if self._expr_is_tainted(arg):
                        return True
                for kw in node.keywords:
                    if self._expr_is_tainted(kw.value):
                        return True
            # Method calls on tainted variables: tainted.strip(), tainted.upper(), etc.
            # These propagate taint (the result is still tainted)
            if isinstance(node.func, ast.Attribute):
                # Check if the object being called on is tainted
                if self._expr_is_tainted(node.func.value):
                    return True
                # Check if any arguments are tainted
                for arg in node.args:
                    if self._expr_is_tainted(arg):
                        return True
            # Function call with tainted argument
            for arg in node.args:
                if self._expr_is_tainted(arg):
                    return True
        # List/dict construction
        if isinstance(node, ast.List):
            return any(self._expr_is_tainted(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(v) for v in node.values if v)
        return False

    def visit_assignment(self, node: ast.Assign) -> None:
        """Process an assignment: if RHS is tainted, LHS becomes tainted."""
        tainted = self._expr_is_tainted(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted_vars[target.id] = node.lineno
                    # Check if assigning to a sink variable
                    if target.id in LLM_SINK_VARS:
                        self.findings.append(Finding(
                            rule_id="ASI01-TAINT-TRACK",
                            rule_name="Prompt Injection (Taint Tracked)",
                            severity=Severity.CRITICAL,
                            owasp=OWASP_ASI.ASI01,
                            file=self.file,
                            line=node.lineno,
                            snippet=self._get_line(node.lineno) or f"{target.id} = <tainted expression>",
                            description=f"Untrusted input flows into LLM sink variable '{target.id}' without sanitization",
                            recommendation="Sanitize user input before including in prompts. Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.",
                            confidence=0.92,
                        ))
                else:
                    # Untaint the variable
                    self.tainted_vars.pop(target.id, None)

    def visit_call(self, node: ast.Call, lineno: int) -> None:
        """Check if a function call passes tainted data to an LLM sink."""
        is_sink, desc = self._check_llm_call(node)
        if is_sink:
            self.findings.append(Finding(
                rule_id="ASI01-TAINT-TRACK",
                rule_name="Prompt Injection (Taint Tracked)",
                severity=Severity.CRITICAL,
                owasp=OWASP_ASI.ASI01,
                file=self.file,
                line=lineno,
                snippet=desc,
                description=desc,
                recommendation="Sanitize user input before passing to LLM APIs. Use structured message arrays. Validate and filter all user-controlled data.",
                confidence=0.9,
            ))


class TaintTrackingRule(Rule):
    """AST-based taint tracking rule for prompt injection detection."""

    rule_id = "ASI01-TAINT-TRACK"
    rule_name = "Prompt Injection (Taint Tracked)"
    severity = Severity.CRITICAL
    owasp = OWASP_ASI.ASI01

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings: list[Finding] = []

        try:
            tree = ast.parse(content, filename=file)
        except SyntaxError:
            return findings

        tracker = TaintTracker(file)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                tracker.visit_assignment(node)
            elif isinstance(node, ast.Call):
                tracker.visit_call(node, node.lineno)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                tracker.visit_call(node.value, node.lineno)

        return tracker.findings

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []
