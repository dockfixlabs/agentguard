"""Interprocedural taint analysis -- tracks taint across function boundaries."""

from __future__ import annotations
import ast
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

SOURCE_WORDS = {
    "user_input", "user_msg", "user_message", "user_query",
    "request", "req", "input_data", "query", "message",
    "prompt_input", "chat_input", "msg",
    "result", "tool_result", "tool_output", "response_text",
    "search_result", "web_result", "api_response",
    "input", "data", "content", "text",
}

LLM_SINK_SIGS = {
    "chat.completions", "completions.create", "messages.create",
    "llm.generate", "llm.chat", "llm.complete", "model.generate",
    "client.chat", "client.completions", "client.messages",
}


class InterproceduralRule(Rule):
    """Tracks taint across function calls within Python files.

    Detects when tainted data is passed as an argument to a function
    that internally calls an LLM API, or when a function parameter
    with a taint-suggesting name reaches an LLM sink.
    """
    rule_id = "ASI01-INTERPROCEDURAL"
    rule_name = "Cross-Function Taint Flow"
    severity = Severity.CRITICAL
    owasp = OWASP_ASI.ASI01

    def scan_line(self, line, line_num, file):
        return []

    def scan_content(self, content, file):
        if not file.endswith(".py"):
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        findings = []
        funcs = self._collect_funcs(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                findings.extend(self._check_func(node, funcs, file))
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, funcs, file))

        return findings

    def _collect_funcs(self, tree):
        funcs = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                params = [p.arg for p in node.args.args]
                params = [p for p in params if p not in ("self", "cls")]
                has_sink = False
                sink_line = 0
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if self._is_llm_call(child):
                            has_sink = True
                            sink_line = child.lineno
                            break
                funcs[node.name] = (params, has_sink, sink_line, node.lineno)
        return funcs

    def _is_llm_call(self, call):
        func = call.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        dotted = ".".join(reversed(parts))
        return any(sig in dotted for sig in LLM_SINK_SIGS)

    def _is_source(self, node):
        if isinstance(node, ast.Name):
            return (node.id in SOURCE_WORDS or
                    any(kw in node.id.lower()
                        for kw in ("_input", "_msg", "_query", "_message", "_data", "_content")))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    return node.func.value.id in ("request", "req")
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return node.value.id in ("request", "req")
        return False

    def _check_call(self, call, funcs, file):
        findings = []
        callee = None
        if isinstance(call.func, ast.Name):
            callee = call.func.id
        elif isinstance(call.func, ast.Attribute):
            callee = call.func.attr

        if callee and callee in funcs:
            _, has_sink, sink_line, _ = funcs[callee]
            if has_sink:
                for arg in call.args:
                    if self._is_source(arg):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.CRITICAL,
                            owasp=self.owasp,
                            file=file,
                            line=call.lineno,
                            snippet="%s(...)" % callee,
                            description="Tainted data passed to function '%s' which calls an LLM API at line %d -- cross-function prompt injection" % (callee, sink_line),
                            recommendation="Sanitize data before passing to LLM-interacting functions.",
                            confidence=0.8,
                        ))
                        break
        return findings

    def _check_func(self, node, funcs, file):
        findings = []
        name = node.name
        if name in funcs:
            params, has_sink, sink_line, _ = funcs[name]
            if has_sink:
                for p in params:
                    if any(kw in p.lower()
                           for kw in ("user", "input", "query", "message",
                                      "prompt", "request", "data", "content",
                                      "result", "tool", "msg")):
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            severity=Severity.HIGH,
                            owasp=self.owasp,
                            file=file,
                            line=node.lineno,
                            snippet="def %s(%s, ...)" % (name, p),
                            description="Parameter '%s' in function '%s' may carry tainted data to LLM sink at line %d" % (p, name, sink_line),
                            recommendation="Validate parameters at function boundary before LLM calls.",
                            confidence=0.7,
                        ))
                        break
        return findings
