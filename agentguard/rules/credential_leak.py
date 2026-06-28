"""ASI07: Credential Leak — detects hardcoded secrets and credential exposure."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Hardcoded API keys (common patterns)
API_KEY_PATTERNS = [
    re.compile(r'(?:api_key|apikey|api-key)\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', re.I),
    re.compile(r'(?:sk-|pk-|rk-|ghp_|gho_|ghs_|ghr_|ghu_)[a-zA-Z0-9]{20,}', re.I),
    re.compile(r'AKIA[0-9A-Z]{16}', re.I),  # AWS
    re.compile(r'(?:Bearer|Token)\s+[a-zA-Z0-9._-]{20,}', re.I),
]

# Private keys
PRIVATE_KEY = re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----', re.I)

# Connection strings with credentials
CONN_STRING = re.compile(r'(?:mongodb|postgres|postgresql|mysql|redis|amqp)://[^:]+:[^@]+@', re.I)

# Hardcoded passwords
PASSWORD = re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', re.I)

# Wallet private keys (crypto)
WALLET_KEY = re.compile(r'(?:private_key|priv_key|seed|mnemonic)\s*[:=]\s*["\'][a-zA-Z0-9]{32,}["\']', re.I)

# .env in code (not in .env file)
ENV_IN_CODE = re.compile(r'\.env\s*(?:\[|\.get|\.getenv|\[)', re.I)


class CredentialLeakRule(Rule):
    rule_id = "ASI07-CREDENTIAL-LEAK"
    rule_name = "Credential Exposure"
    severity = Severity.CRITICAL
    owasp = OWASP_ASI.ASI07

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            findings.extend(self._scan_line(line, i, file))

        return findings

    def _scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        for pattern in API_KEY_PATTERNS:
            if pattern.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=line_num,
                    snippet=redact(stripped),
                    description="Hardcoded API key detected — credential in source code",
                    recommendation="Use environment variables or a secret manager. Never commit credentials. Rotate any exposed keys immediately.",
                    confidence=0.95,
                ))
                break

        if PRIVATE_KEY.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet="***REDACTED PRIVATE KEY***",
                description="Private key in source code — immediate credential compromise",
                recommendation="Remove immediately. Rotate the key. Use secret manager or HSM for private keys.",
                confidence=0.99,
            ))

        if CONN_STRING.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=redact(stripped),
                description="Connection string with embedded credentials — password in URL",
                recommendation="Use separate host, user, and password parameters from environment variables. Never embed credentials in connection URLs.",
                confidence=0.9,
            ))

        if WALLET_KEY.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet="***REDACTED WALLET KEY***",
                description="Crypto wallet private key or seed phrase in code — fund theft risk",
                recommendation="Remove immediately. Move funds to a new wallet. Never store private keys in code.",
                confidence=0.99,
            ))

        return findings


def redact(text: str) -> str:
    """Redact potential secrets from display text."""
    text = re.sub(r'(sk-|pk-|ghp_|gho_)[a-zA-Z0-9]+', r'\1****REDACTED****', text)
    text = re.sub(r'(["\'])[a-zA-Z0-9_-]{20,}(["\'])', r'\1****REDACTED****\2', text)
    text = re.sub(r':[a-zA-Z0-9_-]{8,}@', ':****REDACTED****@', text)
    return text
