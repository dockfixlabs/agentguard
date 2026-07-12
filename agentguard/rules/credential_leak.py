"""ASI07: Credential Leak -- detects hardcoded secrets and credential exposure."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Hardcoded API keys (common patterns) — requires actual key format, not placeholders
API_KEY_PATTERNS = [
    re.compile(r'(?:sk-|pk-|rk-|ghp_|gho_|ghs_|ghr_|ghu_)[a-zA-Z0-9_-]{20,}', re.I),
    re.compile(r'AKIA[0-9A-Z]{16}', re.I),  # AWS access key
    re.compile(r'(?:Bearer|Token)\s+[a-zA-Z0-9._-]{20,}', re.I),
    re.compile(r'xox[baprs]-[a-zA-Z0-9-]{10,}', re.I),  # Slack tokens
    re.compile(r'AIza[0-9A-Za-z_-]{35}', re.I),  # Google API key
    # Generic api_key assignment — but require actual value, not placeholder
    re.compile(r'(?:api_key|apikey|api-key)\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', re.I),
]

# Private keys — require actual key content, not truncated "..."
PRIVATE_KEY = re.compile(r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----', re.I)
PRIVATE_KEY_TRUNCATED = re.compile(r'-----BEGIN.*PRIVATE\s+KEY-----.*\.\.\.', re.I)

# Connection strings with credentials
CONN_STRING = re.compile(r'(?:mongodb|postgres|postgresql|mysql|redis|amqp)://[^:]+:[^@]+@', re.I)

# Hardcoded passwords — exclude placeholders
PASSWORD = re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I)

# Wallet private keys (crypto)
WALLET_KEY = re.compile(r'(?:private_key|priv_key|seed|mnemonic)\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']', re.I)

# Generic secret variable assignment (high-entropy strings)
GENERIC_SECRET = re.compile(
    r'(?:secret|token|credential|auth_key|access_key)\s*[:=]\s*["\']([a-zA-Z0-9_-]{32,})["\']',
    re.I
)

# PLACEHOLDER PATTERNS — values that are definitely NOT real credentials
# But NOT when they're just a prefix mask (e.g., "***" followed by real UUID)
PLACEHOLDER_VALUES = re.compile(
    r'^(?:your[-_]|example|test|demo|sample|placeholder|changeme|xxx|replace[-_]me|'
    r'todo|fill[-_]in|<your)$',
    re.I
)

# Masked but likely real: e.g., "***a0f8a6ba-c32f-4407-af0c" has a real UUID after mask
MASKED_REAL_KEY = re.compile(r'\*{2,}\s*["\']?\s*(?:sk-|pk-|[a-zA-Z0-9_-]{20,})')


def _is_placeholder(value: str) -> bool:
    """Check if a matched value is a known placeholder, not a real credential.
    Returns False for masked-but-real keys like \"***a0f8a6ba-c32f-4407-af0c\"."""
    if MASKED_REAL_KEY.search(value):
        return False
    return bool(PLACEHOLDER_VALUES.search(value))


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

        # Check API key patterns
        for pattern in API_KEY_PATTERNS:
            m = pattern.search(stripped)
            if m:
                groups = m.groups()
                if groups and _is_placeholder(groups[0]):
                    continue
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=line_num,
                    snippet=redact(stripped),
                    description="Hardcoded API key detected — credential in source code",
                    recommendation="Use environment variables or a secret manager. Rotate any exposed keys immediately.",
                    confidence=0.95,
                ))
                break

        # Check private key (skip truncated "...")
        if PRIVATE_KEY.search(stripped) and not PRIVATE_KEY_TRUNCATED.search(stripped):
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

        # Check connection strings
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
                recommendation="Use separate host, user, and password parameters from environment variables.",
                confidence=0.9,
            ))

        # Check wallet keys
        m = WALLET_KEY.search(stripped)
        if m and not _is_placeholder(m.group(1)):
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

        # Check hardcoded passwords — skip placeholders
        m = PASSWORD.search(stripped)
        if m and not _is_placeholder(m.group(1)):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=redact(stripped),
                description="Hardcoded password in source code",
                recommendation="Use environment variables or a secret manager. Never commit passwords.",
                confidence=0.85,
            ))

        # Check generic secret assignments — skip placeholders
        m = GENERIC_SECRET.search(stripped)
        if m and not _is_placeholder(m.group(1)):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=redact(stripped),
                description="Hardcoded secret or token in source code",
                recommendation="Use environment variables or a secret manager. Never commit secrets.",
                confidence=0.8,
            ))

        return findings


def redact(text: str) -> str:
    """Redact potential secrets from display text."""
    text = re.sub(r'(sk-|pk-|ghp_|gho_)[a-zA-Z0-9_-]+', r'\1****REDACTED****', text)
    text = re.sub(r'(["\'])[a-zA-Z0-9_-]{20,}(["\'])', r'\1****REDACTED****\2', text)
    text = re.sub(r':[a-zA-Z0-9_-]{8,}@', ':****REDACTED****@', text)
    return text
