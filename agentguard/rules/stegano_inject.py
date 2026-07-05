"""Steganographic Command Injection Detection (ASI-STEGANO-INJECT)

Detects patterns where commands are hidden in encoded data
(base64, hex, rot13, unicode escapes) that AI agents decode
before execution -- bypassing content-based sanitizers.

This is the most sophisticated injection vector: the payload
looks like innocent encoded text until the agent decodes it.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class SteganoInjectRule(Rule):
    """Detects encoded command injection in AI agent code.

    Attackers hide malicious commands in base64, hex, or other
    encoded formats. The agent decodes them and executes the
    decoded content -- bypassing all content-based filters.
    """

    rule_id = "ASI-STEGANO-INJECT"
    rule_name = "Steganographic Command Injection"
    severity = Severity.CRITICAL

    # Decode-to-execute patterns
    DECODE_EXECUTE = re.compile(
        rb"(base64|b64|hex|rot13|unicode|utf-?16|url)\s*(?:\.|_)?\s*decode",
        re.IGNORECASE
    )

    # Dangerous operations on decoded data (multi-line check)
    DANGEROUS_AFTER_DECODE = re.compile(
        rb"(os\.system|subprocess\.(call|run|Popen)|eval|exec|\.execute|\.run)\s*\(",
        re.IGNORECASE
    )

    # Source of encoded data
    ENCODED_SOURCE = re.compile(
        rb"user[_]?input|user[_]?message|request\.(body|data|json|form|args)|"
        rb"request[_]data|webhook|api[_]?callback|external[_]?data|tool[_]?output|"
        rb"untrusted|raw[_]?input",
        re.IGNORECASE
    )

    # Decode + exec on same/adjacent lines
    DECODE_THEN_EXEC = re.compile(
        rb"(base64|b64decode|hexlify|unhexlify|"
        rb"codecs\.decode|\.fromhex|\.decode\s*\(\s*['\"]base64|"
        rb"atob|btoa|Buffer\.from.*base64)",
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
            
            # Find decode operations
            if not self.DECODE_THEN_EXEC.search(encoded):
                continue

            # Check nearby context for tainted source
            ctx_start = max(0, i - 8)
            ctx_end = min(len(lines), i + 5)
            context = " ".join(lines[ctx_start:ctx_end])
            ctx_encoded = context.encode("utf-8", errors="ignore")

            if not self.ENCODED_SOURCE.search(ctx_encoded):
                continue

            # Check if decoded data ends up in dangerous operation
            nearby = " ".join(lines[max(0, i-2):min(len(lines), i+3)])
            nearby_enc = nearby.encode("utf-8", errors="ignore")
            if not self.DANGEROUS_AFTER_DECODE.search(ctx_encoded):
                continue

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                file=file,
                line=i,
                snippet=line.strip()[:120],
                description="Encoded data decoded and executed -- steganographic command injection bypasses content filters",
                recommendation="Never execute decoded data. Validate decoded content against allowlists. Use type-safe structured formats (JSON Schema, Pydantic) instead of raw decode+execute.",
                confidence=0.9,
            ))

        return findings
