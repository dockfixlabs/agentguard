"""ASI10: Trust Boundary Violation — detects missing isolation between agent and system."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Agent running with system/admin privileges
PRIVILEGED = re.compile(
    r'(?:run_as|user|uid|gid|euid)\s*[:=]\s*(?:root|0|admin|administrator|system)',
    re.I
)

# No sandbox/docker isolation
NO_SANDBOX = re.compile(
    r'(?:docker|container|sandbox|isolate|namespace)\s*[:=]\s*(?:None|null|false|disabled|off|no)',
    re.I
)

# Agent has access to host filesystem
HOST_FS = re.compile(
    r'(?:mount|volume|path|directory|root)\s*[:=]\s*["\']/(?:etc|var|root|home|proc|sys|dev)',
    re.I
)

# Shared state between agent and host
SHARED_STATE = re.compile(
    r'(?:shared|global|host)\s*(?:state|memory|variable|context)\s*[:=]',
    re.I
)

# Agent can modify its own code
SELF_MODIFY = re.compile(
    r'(?:write|modify|patch|edit|update)\w*\s*\(.*(?:__file__|self|this|agent|own)',
    re.I
)

# Direct database access from agent
DB_ACCESS = re.compile(
    r'(?:cursor|query|execute|db|database|sql)\s*\.\s*(?:execute|raw|query|run)\s*\(.*(?:input|user|request|message)',
    re.I
)


class TrustBoundaryRule(Rule):
    rule_id = "ASI10-TRUST-BOUNDARY"
    rule_name = "Trust Boundary Violation"
    severity = Severity.HIGH
    owasp = OWASP_ASI.ASI10

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        if PRIVILEGED.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent running with privileged access — trust boundary bypass",
                recommendation="Run agents as unprivileged users. Use containers or sandboxing. Never run agents as root.",
                confidence=0.9,
            ))

        if HOST_FS.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent has access to host system directories — filesystem trust boundary violation",
                recommendation="Isolate agent filesystem access. Mount only necessary directories as read-only.",
                confidence=0.85,
            ))

        if SELF_MODIFY.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent can modify its own code — self-modification attack vector",
                recommendation="Make agent code immutable at runtime. Use code signing and integrity checks.",
                confidence=0.85,
            ))

        if DB_ACCESS.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent has direct database access with user input — SQL injection via agent",
                recommendation="Use parameterized queries. Add a data access layer between agent and database. Never let agents construct raw SQL.",
                confidence=0.75,
            ))

        return findings
