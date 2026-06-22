"""ASI03: Data Exfiltration — detects data leakage channels in agent code."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Sending data to external URLs
EXFIL_URL = re.compile(
    r'(?:requests\.(?:post|put|get)|fetch|axios|http\.request|urllib)\s*\(\s*[f"\']https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
    re.I
)

# Environment variable / secret access then transmission
SECRET_ACCESS = re.compile(
    r'(?:os\.environ|process\.env|getenv|config\.\w+|settings\.\w+|SECRET|API_KEY|TOKEN|PASSWORD|PRIVATE_KEY)',
    re.I
)

# Webhook / callback patterns
WEBHOOK = re.compile(
    r'(?:webhook|callback_url|notify_url|report_url|postback)\s*[:=]',
    re.I
)

# Logging sensitive data
LOG_SECRETS = re.compile(
    r'(?:print|log|logger|console)\w*\s*\(\s*(?:f["\'].*|.*format.*)?(?:api_key|token|password|secret|private_key|credential)',
    re.I
)

# File upload to external service
UPLOAD = re.compile(
    r'(?:upload|send_file|transfer)\w*\s*\(.*(?:s3|bucket|cloud|external|remote)',
    re.I
)

# DNS exfiltration patterns
DNS_EXFIL = re.compile(
    r'(?:socket\.gethostbyname|dns\.resolve|resolver\.query)\s*\(.*(?:format|encode|base64|hex)',
    re.I
)


class DataExfiltrationRule(Rule):
    rule_id = "ASI03-DATA-EXFIL"
    rule_name = "Data Exfiltration Risk"
    severity = Severity.HIGH
    owasp = OWASP_ASI.ASI03

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if EXFIL_URL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Agent sends data to external URL — potential exfiltration channel",
                    recommendation="Whitelist allowed domains. Proxy all external requests through a filtering layer. Log and alert on unexpected outbound traffic.",
                    confidence=0.7,
                ))

            if LOG_SECRETS.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet="***REDACTED***",
                    description="Secret/credential value being logged — credential exposure in logs",
                    recommendation="Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.",
                    confidence=0.85,
                ))

            if WEBHOOK.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Webhook/callback URL configured — verify it's not exfiltrating data",
                    recommendation="Validate webhook URLs against an allowlist. Ensure webhook payloads don't contain sensitive data.",
                    confidence=0.5,
                ))

            if DNS_EXFIL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="DNS resolution with encoded data — DNS exfiltration pattern",
                    recommendation="Block DNS-based data channels. Monitor for high-entropy DNS queries.",
                    confidence=0.8,
                ))

        # Check for secret access + network call on adjacent lines (correlation)
        for i in range(len(lines) - 1):
            if SECRET_ACCESS.search(lines[i]) and EXFIL_URL.search(lines[i + 1]):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i + 1,
                    snippet="***REDACTED***",
                    description="Secret accessed then sent to external URL — active exfiltration",
                    recommendation="Isolate secret access from network code. Use secret managers that don't expose values to agent context.",
                    confidence=0.9,
                ))

        return findings

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []
