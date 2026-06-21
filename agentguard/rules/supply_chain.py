"""ASI05: Supply Chain — detects untrusted dependencies in agent code."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# pip install from git/non-PyPI
UNTRUSTED_INSTALL = re.compile(
    r'pip\s+install\s+(?:git\+|https?://|file://|--index-url\s+\w+://)',
    re.I
)

# npm install from non-registry
NPM_UNTRUSTED = re.compile(
    r'npm\s+install\s+(?:git\+|https?://|file:)',
    re.I
)

# No version pinning
NO_VERSION_PIN = re.compile(
    r'(?:pip\s+install|requires)\s+[a-zA-Z0-9_-]+(?!\s*[=<>])',
    re.I
)

# Unpinned Docker image
UNPINNED_DOCKER = re.compile(
    r'(?:FROM|image)\s+([a-z0-9]+(?:/[a-z0-9]+)+(?::latest)?(?!\s*:\d))',
    re.I
)

# eval/exec of downloaded code
REMOTE_CODE_EXEC = re.compile(
    r'(?:exec|eval|compile)\s*\(.*(?:requests\.get|urllib|fetch|download|curl|wget)',
    re.I
)

# Dynamic import from URL
DYNAMIC_IMPORT_URL = re.compile(
    r'__import__\s*\(\s*(?:requests\.get|urllib|fetch|download)',
    re.I
)

# Unverified pickle/marshal from network
UNVERIFIED_DESERIALIZE = re.compile(
    r'(?:pickle|marshal|yaml)\.loads?\s*\(.*(?:requests|urllib|fetch|response|download)',
    re.I
)

# requirements.txt with no hashes
NO_HASHES = re.compile(
    r'--no-deps|--no-cache-dir',
    re.I
)


class SupplyChainRule(Rule):
    rule_id = "ASI05-SUPPLY-CHAIN"
    rule_name = "Supply Chain Risk"
    severity = Severity.MEDIUM
    owasp = OWASP_ASI.ASI05

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        if UNTRUSTED_INSTALL.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Installing packages from non-registry source — supply chain attack risk",
                recommendation="Only install from PyPI/npm registry. Pin versions. Use hash verification (--require-hashes).",
                confidence=0.8,
            ))

        if REMOTE_CODE_EXEC.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Executing code downloaded from network — remote code execution",
                recommendation="Never execute downloaded code. Verify integrity with hashes. Use signed packages only.",
                confidence=0.95,
            ))

        if UNVERIFIED_DESERIALIZE.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Deserializing untrusted data from network — RCE via pickle/marshal",
                recommendation="Never pickle/marshal data from untrusted sources. Use JSON with schema validation.",
                confidence=0.9,
            ))

        if UNPINNED_DOCKER.search(stripped) and ":latest" in stripped.lower():
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.MEDIUM,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Docker image uses :latest tag — non-reproducible, supply chain risk",
                recommendation="Pin Docker images to specific version tags or SHA256 digests.",
                confidence=0.6,
            ))

        return findings
