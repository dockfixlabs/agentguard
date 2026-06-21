"""ASI04: Excessive Agency — detects agents with permissions beyond their intended scope."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# Agent with write/delete capabilities when it should only read
EXCESSIVE_WRITE = re.compile(
    r'(?:agent|bot|assistant)\w*\s*(?:can|has|with|granted|allow)\s*(?:write|delete|modify|update|create|remove|drop|alter)',
    re.I
)

# No permission scope defined
NO_SCOPE = re.compile(
    r'(?:tool|function|capability|permission)\s*(?:list|registry|config)\s*(?:\.\s*append|\s*\+=|\.\s*extend)\s*["\'](?:\*|all|any|everything|unlimited)["\']',
    re.I
)

# Agent can escalate privileges
PRIV_ESCALATION = re.compile(
    r'(?:sudo|chmod|chown|setuid|setgid|admin_panel|escalate|elevate)\s*\(',
    re.I
)

# No action validation/confirmation
NO_CONFIRMATION = re.compile(
    r'(?:auto_confirm|skip_confirmation|require_confirmation|confirm)\s*[:=]\s*(?:True|true|yes|1)',
    re.I
)

# Agent has access to other agents' resources
CROSS_AGENT = re.compile(
    r'(?:other_agent|peer_agent|all_agents|agent_pool|shared_workspace)\s*[:=]',
    re.I
)

# Unrestricted API access
UNRESTRICTED_API = re.compile(
    r'(?:api_access|endpoints|routes|permissions)\s*[:=]\s*(?:\*|["\']all["\']|["\']any["\']|["\']unlimited["\'])',
    re.I
)


class ExcessiveAgencyRule(Rule):
    rule_id = "ASI04-EXCESSIVE-AGENCY"
    rule_name = "Excessive Agency"
    severity = Severity.HIGH
    owasp = OWASP_ASI.ASI04

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        findings = []
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        if EXCESSIVE_WRITE.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent granted write/delete/modify permissions — excessive agency",
                recommendation="Apply least-privilege principle. Agents should only have permissions strictly needed for their task. Separate read and write capabilities.",
                confidence=0.75,
            ))

        if PRIV_ESCALATION.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.CRITICAL,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent can escalate privileges — sudo/chmod/setuid access",
                recommendation="Never allow agents to escalate privileges. Run in restricted sandbox with no sudo access.",
                confidence=0.9,
            ))

        if NO_CONFIRMATION.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Destructive actions set to auto-confirm — no human-in-the-loop",
                recommendation="Require human confirmation for destructive actions (delete, write, send). Use auto_confirm=False for all irreversible operations.",
                confidence=0.8,
            ))

        if CROSS_AGENT.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent has access to other agents' resources — cross-agent trust violation",
                recommendation="Isolate agent resources. Each agent should only access its own state and workspace.",
                confidence=0.7,
            ))

        if UNRESTRICTED_API.search(stripped):
            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH,
                owasp=self.owasp,
                file=file,
                line=line_num,
                snippet=stripped[:200],
                description="Agent has unrestricted API access — no endpoint scoping",
                recommendation="Whitelist specific API endpoints per agent role. Implement API gateway with per-agent rate limits.",
                confidence=0.75,
            ))

        return findings
