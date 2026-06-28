"""ASI10: Trust Boundary Violation -- detects missing isolation between agent and system."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Agent running with system/admin privileges
PRIVILEGED = re.compile(
    r'(?:run_as|user|uid|gid|euid)\s*[:=]\s*(?:root|0|admin|administrator|system)',
    re.I
)

# No sandbox/docker isolation (variable assignment to None/false/disabled)
NO_SANDBOX = re.compile(
    r'(?:sandbox|isolation|container|sandbox_enabled)\s*[:=]\s*(?:None|null|False|false|disabled|off|no|0)',
    re.I
)

# Agent has access to host filesystem via mount/volume
HOST_FS = re.compile(
    r'["\']/(?:etc|var|root|home|proc|sys|dev)(?:/|"|\'])',
    re.I
)

# Volume mount with host path
VOLUME_MOUNT = re.compile(
    r'(?:volumes|mounts|binds)\s*[:=]',
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

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        # Check for volume mounts with host paths (multi-line context)
        has_volumes = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if VOLUME_MOUNT.search(stripped):
                has_volumes = True

            if has_volumes and HOST_FS.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.CRITICAL,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Agent mounts host system directories -- filesystem trust boundary violation",
                    recommendation="Isolate agent filesystem access. Mount only necessary directories as read-only. Never mount /etc, /root, or /proc.",
                    confidence=0.85,
                ))
                has_volumes = False  # avoid duplicate

            findings.extend(self._scan_line(stripped, i, file))

        return findings

    def _scan_line(self, stripped: str, line_num: int, file: str) -> list[Finding]:
        findings = []

        if PRIVILEGED.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent running with privileged access -- trust boundary bypass",
                recommendation="Run agents as unprivileged users. Use containers or sandboxing. Never run agents as root.",
                confidence=0.9,
            ))

        if NO_SANDBOX.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.MEDIUM,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Sandbox/isolation disabled -- agent runs without containment",
                recommendation="Enable sandboxing for all agent execution. Use containers, namespaces, or seccomp profiles.",
                confidence=0.7,
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
                description="Agent can modify its own code -- self-modification attack vector",
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
                description="Agent has direct database access with user input -- SQL injection via agent",
                recommendation="Use parameterized queries. Add a data access layer between agent and database. Never let agents construct raw SQL.",
                confidence=0.75,
            ))

        return findings

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return self._scan_line(line.strip(), line_num, file)
