"""ASI03: Data Exfiltration -- detects data leakage channels in agent code."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Sending data to external URLs (inline string)
EXFIL_URL = re.compile(
    r'(?:requests|httpx|aiohttp|urllib)\.\s*(?:post|put|get|patch|delete|request)\s*\(\s*(?:f["\']|["\'])https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
    re.I
)

# Fetch API (JavaScript/TypeScript)
FETCH_EXFIL = re.compile(
    r'fetch\s*\(\s*(?:f["\']|["\'])https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
    re.I
)

# Axios (JavaScript/TypeScript)
AXIOS_EXFIL = re.compile(
    r'axios\s*\.\s*(?:post|put|get|patch|delete)\s*\(\s*(?:f["\']|["\'])https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
    re.I
)

# URL variable assignment to external host (excluding known API providers)
URL_VAR_ASSIGN = re.compile(
    r'(?:url|endpoint|host|server|webhook_url|callback_url|api_url|base_url)\s*[:=]\s*(?:f["\']|["\'])https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.together\.xyz|api\.mistral\.ai|api\.cohere\.ai|api\.deepseek\.com|api\.xai\.com)',
    re.I
)

# Network call with variable (correlation: URL was assigned earlier)
NET_CALL_VAR = re.compile(
    r'(?:requests|httpx|aiohttp|urllib)\.\s*(?:post|put|get|patch|delete|request)\s*\(\s*(?:url|endpoint|host|server|webhook_url|callback_url|api_url|base_url)\b',
    re.I
)

# Secret access patterns
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

# Subprocess with external URL
SUBPROCESS_EXFIL = re.compile(
    r'(?:subprocess|os\.system|os\.popen)[.\w]*\s*\(.*(?:curl|wget).*https?://',
    re.I
)

# WebSocket exfiltration
WEBSOCKET_EXFIL = re.compile(
    r'(?:websocket|ws)\.\s*(?:create_connection|send|connect)\s*\(\s*(?:f["\']|["\'])wss?://',
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

        # First pass: find URL variable assignments
        url_assigned = False
        url_line = 0
        url_var_names = set()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            m = URL_VAR_ASSIGN.search(stripped)
            if m:
                url_assigned = True
                url_line = i
                # Extract variable name
                var_match = re.match(r'(\w+)\s*[:=]', stripped)
                if var_match:
                    url_var_names.add(var_match.group(1))

        # Second pass: scan each line
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Inline URL in network call
            if EXFIL_URL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Agent sends data to external URL -- potential exfiltration channel",
                    recommendation="Whitelist allowed domains. Proxy all external requests through a filtering layer. Log and alert on unexpected outbound traffic.",
                    confidence=0.7,
                ))

            # Fetch API exfil (JS/TS)
            if FETCH_EXFIL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Fetch call to external URL -- potential exfiltration channel",
                    recommendation="Whitelist allowed domains. Use a Content Security Policy. Log and alert on unexpected outbound traffic.",
                    confidence=0.7,
                ))

            # Axios exfil (JS/TS)
            if AXIOS_EXFIL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Axios call to external URL -- potential exfiltration channel",
                    recommendation="Whitelist allowed domains. Proxy all external requests. Log and alert on unexpected outbound traffic.",
                    confidence=0.7,
                ))

            # URL variable assignment
            if URL_VAR_ASSIGN.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="External URL assigned to variable -- review destination",
                    recommendation="Validate all external URLs against an allowlist. Ensure URLs are not constructed from user input.",
                    confidence=0.5,
                ))

            # Network call with previously-assigned URL variable
            if url_assigned and i > url_line and NET_CALL_VAR.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Network call using external URL variable -- potential exfiltration",
                    recommendation="Whitelist allowed domains. Proxy all external requests through a filtering layer.",
                    confidence=0.65,
                ))

            # Logging secrets
            if LOG_SECRETS.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet="***REDACTED***",
                    description="Secret/credential value being logged -- credential exposure in logs",
                    recommendation="Never log secrets. Use structured logging with field redaction. Mask API keys, tokens, and passwords in all output.",
                    confidence=0.85,
                ))

            # Webhook configuration
            if WEBHOOK.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Webhook/callback URL configured -- verify it is not exfiltrating data",
                    recommendation="Validate webhook URLs against an allowlist. Ensure webhook payloads do not contain sensitive data.",
                    confidence=0.5,
                ))

            # DNS exfiltration
            if DNS_EXFIL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="DNS resolution with encoded data -- DNS exfiltration pattern",
                    recommendation="Block DNS-based data channels. Monitor for high-entropy DNS queries.",
                    confidence=0.8,
                ))

            # Subprocess exfiltration (curl/wget)
            if SUBPROCESS_EXFIL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Subprocess calling curl/wget to external URL -- exfiltration via shell",
                    recommendation="Never pass user-controlled data to subprocess calls. Use safe HTTP libraries with URL validation.",
                    confidence=0.85,
                ))

            # WebSocket exfiltration
            if WEBSOCKET_EXFIL.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="WebSocket connection to external server -- potential exfiltration channel",
                    recommendation="Whitelist allowed WebSocket endpoints. Monitor WebSocket traffic for data exfiltration.",
                    confidence=0.75,
                ))

        # Cross-line correlation: secret access + network call on adjacent lines
        for i in range(len(lines) - 1):
            line_i = lines[i].strip()
            line_next = lines[i + 1].strip()
            if (line_i.startswith("#") or line_i.startswith("//")):
                continue
            if SECRET_ACCESS.search(line_i) and (EXFIL_URL.search(line_next) or NET_CALL_VAR.search(line_next)):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i + 1,
                    snippet="***REDACTED***",
                    description="Secret accessed then sent to external URL -- active exfiltration",
                    recommendation="Isolate secret access from network code. Use secret managers that do not expose values to agent context.",
                    confidence=0.9,
                ))

        return findings

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []
