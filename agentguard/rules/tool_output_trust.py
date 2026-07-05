"""Tool Output Trust Attack (ASI-TOOL-TRUST)

Detects agents blindly trusting tool outputs without validation.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class ToolOutputTrustRule(Rule):
    """Detects unvalidated trust in tool API outputs."""

    rule_id = "ASI-TOOL-TRUST"
    rule_name = "Tool Output Trust"
    severity = Severity.CRITICAL

    # Lines that assign tool output to a variable
    OUTPUT_ASSIGN = re.compile(
        rb"(tool_output|tool_result|tool_response|"
        rb"api_result|api_response|api_data|"
        rb"function_result|function_output|agent_output|agent_result|"
        rb"execution_result|webhook|callback_data|"
        rb"external_response|third_party_result)\s*=",
        re.IGNORECASE
    )

    # Dangerous operations on variables
    DANGEROUS_OP = re.compile(
        rb"os\.system\s*\(|os\.popen\s*\(|subprocess\.(call|run|Popen)\s*\(|"
        rb"eval\s*\(|exec\s*\(|pickle\.loads?\s*\(|yaml\.load\s*\(|"
        rb"open\s*\(\s*[_a-zA-Z]|open\s*\(\s*f[\"']|"
        rb"shutil\.(copy|move|rmtree)\s*\(|os\.(remove|unlink|rmdir)\s*\(|"
        rb"\.execute\s*\(|\.run\s*\(\s*[_a-zA-Z]|\.invoke\s*\(\s*[_a-zA-Z]|"
        rb"\.create\s*\(\s*[_a-zA-Z]",
        re.IGNORECASE
    )

    # Lines using tool output variables
    OUTPUT_USE_RE = re.compile(
        rb"\b(tool_output|tool_result|tool_response|"
        rb"api_result|api_response|api_data|"
        rb"function_result|function_output|agent_output|agent_result|"
        rb"execution_result)\.|"
        rb"\b(tool_output|tool_result|tool_response|"
        rb"api_result|api_response|api_data|"
        rb"function_result|function_output|agent_output|agent_result|"
        rb"execution_result)\b",
        re.IGNORECASE
    )

    SAFE_PATTERNS = re.compile(
        rb"\.validate\s*\(|\.verify\s*\(|assert\s+|isinstance\s*\(|"
        rb"pydantic|BaseModel|Schema|dataclass|@validate|json\.schema|"
        rb"jsonschema|marshmallow|cerberus|attrs\.define|"
        rb"\.model_validate|\.schema_validate|ContentFilter|InputValidator|"
        rb"bleach\.clean|html\.escape|sanitize|validated",
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

        # Phase 1: Find lines where tool output is ASSIGNED
        tool_output_lines = set()
        for i, line in enumerate(lines, 1):
            encoded = line.encode("utf-8", errors="ignore")
            if self.OUTPUT_ASSIGN.search(encoded):
                tool_output_lines.add(i)

        if not tool_output_lines:
            return findings

        # Phase 2: Find dangerous operations near tool output assignments
        for i, line in enumerate(lines, 1):
            encoded = line.encode("utf-8", errors="ignore")

            # Check if this line uses tool output AND has dangerous op
            if not self.OUTPUT_USE_RE.search(encoded):
                continue
            if not self.DANGEROUS_OP.search(encoded):
                continue

            # Check nearby context for validation
            ctx_start = max(0, i - 3)
            ctx_end = min(len(lines), i + 3)
            context = " ".join(lines[ctx_start:ctx_end])
            if self.SAFE_PATTERNS.search(context.encode("utf-8", errors="ignore")):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                file=file,
                line=i,
                snippet=line.strip()[:120],
                description="Tool output used without validation in dangerous operation -- agent blindly trusts untrusted external data",
                recommendation="Validate all tool outputs before use. Apply Pydantic models, JSON Schema, type checking, and content filtering. Never treat tool results as executable commands or file paths.",
                confidence=0.9,
            ))

        return findings
