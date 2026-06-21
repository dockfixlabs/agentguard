"""ASI09: Agent Loop Exploitation — detects infinite loop and resource exhaustion vectors."""

from __future__ import annotations
import re
from agentguard.models import Finding, OWASP_ASI, Rule, Severity

# While True with agent calls
INFINITE_LOOP = re.compile(
    r'while\s+(?:True|1|not\s+(?:False|0|None))\s*:',
    re.I
)

# No max iterations on agent loop
NO_MAX_ITER = re.compile(
    r'(?:max_iterations|max_steps|max_rounds|max_loops|iteration_limit)\s*[:=]\s*(?:None|null|0|float\([\'"]inf|math\.inf|-1|999999)',
    re.I
)

# Recursive agent calls without depth limit
UNBOUNDED_RECURSION = re.compile(
    r'def\s+(\w+)\s*\(.*\).*:\s*\n.*\1\s*\(',
    re.I | re.DOTALL
)

# Self-invoking agent
SELF_INVOKE = re.compile(
    r'(?:self|this)\.(?:run|execute|call|invoke|step|loop|process)\s*\(',
    re.I
)

# No cost/budget limit
NO_BUDGET = re.compile(
    r'(?:budget|max_cost|max_spend|max_tokens|max_api_calls|spending_limit)\s*[:=]\s*(?:None|null|0|float\([\'"]inf|math\.inf)',
    re.I
)

# Sleep in agent loop (resource waste)
SLEEP_LOOP = re.compile(
    r'(?:time\.sleep|asyncio\.sleep|await\s+sleep)\s*\(\s*(?:0|0\.0|0\.001|0\.01)\s*\)',
    re.I
)


class AgentLoopRule(Rule):
    rule_id = "ASI09-AGENT-LOOP"
    rule_name = "Agent Loop Exploitation"
    severity = Severity.MEDIUM
    owasp = OWASP_ASI.ASI09

    def scan_content(self, content: str, file: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            if INFINITE_LOOP.search(stripped):
                # Check if there's a break/exit within reasonable distance
                has_break = False
                for j in range(i, min(i + 20, len(lines))):
                    if re.search(r'\bbreak\b|\breturn\b|\braise\b|\bexit\b', lines[j - 1]):
                        has_break = True
                        break
                if not has_break:
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=Severity.HIGH,
                        owasp=self.owasp,
                        file=file,
                        line=i,
                        snippet=stripped[:200],
                        description="Infinite loop without clear exit — agent loop exploitation risk",
                        recommendation="Always set max_iterations. Use for-loops with explicit bounds instead of while True.",
                        confidence=0.7,
                    ))

            if NO_MAX_ITER.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.HIGH,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="No iteration limit set — unbounded agent loop risk",
                    recommendation="Set explicit max_iterations (recommend 10-50 for most agents). Track and enforce iteration count.",
                    confidence=0.75,
                ))

            if NO_BUDGET.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="No cost/budget limit — financial resource exhaustion",
                    recommendation="Set spending limits (max_tokens, max_cost). Monitor API usage. Alert on budget threshold.",
                    confidence=0.7,
                ))

            if SELF_INVOKE.search(stripped):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=Severity.MEDIUM,
                    owasp=self.owasp,
                    file=file,
                    line=i,
                    snippet=stripped[:200],
                    description="Agent self-invokes — potential infinite recursion",
                    recommendation="Add recursion depth limit. Use iteration instead of recursion for agent loops.",
                    confidence=0.6,
                ))

        return findings

    def scan_line(self, line: str, line_num: int, file: str) -> list[Finding]:
        return []
