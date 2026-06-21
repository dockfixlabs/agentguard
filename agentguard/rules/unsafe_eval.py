"""ASI06: Unsafe Eval — detects dynamic code execution in agent code."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

PATTERNS = [
    (re.compile(r'\beval\s*\('), "eval() — arbitrary code execution from string", Severity.CRITICAL, 0.95),
    (re.compile(r'\bexec\s*\('), "exec() — arbitrary code execution", Severity.CRITICAL, 0.95),
    (re.compile(r'__import__\s*\('), "Dynamic __import__() — module loading from variable", Severity.HIGH, 0.8),
    (re.compile(r'compile\s*\(.*(?:input|user|request|query|message)', re.I), "compile() with user input — code compilation from untrusted data", Severity.CRITICAL, 0.85),
    (re.compile(r'getattr\s*\(.*(?:input|user|request|query|message)', re.I), "getattr() with user input — attribute access from untrusted data", Severity.HIGH, 0.7),
    (re.compile(r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True', re.I), "subprocess with shell=True — command injection risk", Severity.CRITICAL, 0.9),
    (re.compile(r'os\.system\s*\('), "os.system() — shell command execution", Severity.HIGH, 0.85),
    (re.compile(r'os\.popen\s*\('), "os.popen() — shell command execution", Severity.HIGH, 0.85),
    (re.compile(r'pickle\.loads?\s*\('), "pickle.load() — deserialization of untrusted data", Severity.HIGH, 0.8),
    (re.compile(r'yaml\.load\s*\('), "yaml.load() without SafeLoader — deserialization risk", Severity.HIGH, 0.75),
    (re.compile(r'marshal\.loads?\s*\('), "marshal.load() — unsafe deserialization", Severity.HIGH, 0.8),
]


class UnsafeEvalRule(Rule):
    rule_id = "ASI06-UNSAFE-EVAL"
    rule_name = "Unsafe Code Execution"
    severity = Severity.CRITICAL
    owasp = OWASP_ASI.ASI06

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        for pattern, desc, sev, confidence in PATTERNS:
            if pattern.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=sev,
                    owasp=self.owasp,
                    file=file,
                    line=line_num,
                    snippet=stripped[:200],
                    description=desc,
                    recommendation="Avoid dynamic code execution. Use safe alternatives: ast.literal_eval for literals, yaml.safe_load for YAML, subprocess with shell=False and argument lists.",
                    confidence=confidence,
                ))
        return findings
