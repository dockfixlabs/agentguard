"""Core data models for AgentGuard findings and scan results."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASP_ASI(str, Enum):
    """OWASP Agentic Security Initiative Top 10 (2026)."""
    ASI01 = "ASI01"  # Prompt Injection
    ASI02 = "ASI02"  # Tool Abuse / Unintended Tool Use
    ASI03 = "ASI03"  # Data Exfiltration / Sensitive Data Leakage
    ASI04 = "ASI04"  # Unauthorized Actions / Excessive Agency
    ASI05 = "ASI05"  # Supply Chain / Untrusted Components
    ASI06 = "ASI06"  # Insecure Output Handling
    ASI07 = "ASI07"  # Credential / Secret Exposure
    ASI08 = "ASI08"  # Context Window Manipulation
    ASI09 = "ASI09"  # Agent Loop Exploitation
    ASI10 = "ASI10"  # Trust Boundary Violation


class Finding(BaseModel):
    """A single security finding from a scan."""
    rule_id: str
    rule_name: str
    severity: Severity
    owasp: Optional[OWASP_ASI] = None
    file: str
    line: int
    column: int = 0
    snippet: str = ""
    description: str
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 confidence score")


class ScanResult(BaseModel):
    """Complete scan result for a project."""
    target: str
    files_scanned: int
    findings: list[Finding] = Field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


class Rule:
    """Base class for detection rules."""
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.MEDIUM
    owasp: Optional[OWASP_ASI] = None

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        raise NotImplementedError

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings: list[Finding] = []
        for i, line in enumerate(content.splitlines(), 1):
            findings.extend(self.scan_line(line, i, file))
        return findings
