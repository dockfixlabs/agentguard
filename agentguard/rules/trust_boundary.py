"""ASI10: Trust Boundary Violation -- detects missing isolation between agent and system."""

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
    r'(?:sandbox|isolation|container|sandbox_enabled)\s*[:=]\s*(?:None|null|False|false|disabled|off|no|0)',
    re.I
)

# Host filesystem paths
HOST_FS = re.compile(
    r'["\']/(?:etc|var|root|home|proc|sys|dev)(?:/|"|\')',
    re.I
)

# Volume mount
VOLUME_MOUNT = re.compile(
    r'(?:volumes|mounts|binds)\s*[:=]',
    re.I
)

# Real self-modification: requires actual code manipulation patterns
SELF_MODIFY = re.compile(
    r'(?:setattr\s*\(\s*self|'
    r'importlib|import_module|__import__|compile\s*\(|'
    r'monkey_patch|monkeypatch|hot.?patch|'
    r'__file__\s*.*write|write\s*\(.*__file__|'
    r'\.__code__|\.__class__\s*=)',
    re.I
)

# Direct database access from agent
DB_ACCESS = re.compile(
    r'(?:cursor|query|execute|db|database|sql)\s*\.\s*(?:execute|raw|query|run)\s*\(.*(?:input|user|request|message)',
    re.I
)

# FP exclusion: skip class defs, I/O writes, event handlers — but NOT when the line
# contains actual self-modification keywords (monkey_patch, setattr, __code__, etc.)
FP_EXCLUDE = re.compile(
    r'^\s*(?:class\s+|#'
    r'|f\.write|f\.read|file\.write|file\.read'
    r'|log_|on_|handle_|_callback|_handler|_event'
    r'|\.json|\.md|\.txt|\.csv)',
    re.I
)

# def exclusion — only when the function name does NOT contain self-modification keywords
DEF_EXCLUDE = re.compile(
    r'^\s*def\s+(?!\w*(?:monkey_patch|monkeypatch|hot_patch|hotpatch|setattr|importlib|__code__|__class__))',
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
                    file=file, line=i, snippet=stripped[:200],
                    description="Agent mounts host system directories -- trust boundary violation",
                    recommendation="Isolate agent filesystem. Mount only necessary directories as read-only.",
                    confidence=0.85,
                ))
                has_volumes = False

            findings.extend(self._scan_line(stripped, i, file))

        return findings

    def _scan_line(self, stripped: str, line_num: int, file: str) -> list[Finding]:
        findings = []

        if PRIVILEGED.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id, rule_name=self.rule_name,
                severity=Severity.CRITICAL, owasp=self.owasp,
                file=file, line=line_num, snippet=stripped[:200],
                description="Agent running with privileged access -- trust boundary bypass",
                recommendation="Run agents as unprivileged users. Use containers or sandboxing.",
                confidence=0.9,
            ))

        if NO_SANDBOX.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id, rule_name=self.rule_name,
                severity=Severity.MEDIUM, owasp=self.owasp,
                file=file, line=line_num, snippet=stripped[:200],
                description="Sandbox/isolation disabled -- agent runs without containment",
                recommendation="Enable sandboxing for all agent execution.",
                confidence=0.7,
            ))

        if SELF_MODIFY.search(stripped) and not FP_EXCLUDE.search(stripped) and not DEF_EXCLUDE.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id, rule_name=self.rule_name,
                severity=Severity.CRITICAL, owasp=self.owasp,
                file=file, line=line_num, snippet=stripped[:200],
                description="Agent can modify its own code -- self-modification attack vector",
                recommendation="Make agent code immutable at runtime. Use code signing and integrity checks.",
                confidence=0.85,
            ))

        if DB_ACCESS.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id, rule_name=self.rule_name,
                severity=Severity.HIGH, owasp=self.owasp,
                file=file, line=line_num, snippet=stripped[:200],
                description="Agent has direct database access with user input -- SQL injection via agent",
                recommendation="Use parameterized queries. Add data access layer between agent and database.",
                confidence=0.75,
            ))

        return findings

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return self._scan_line(line.strip(), line_num, file)
