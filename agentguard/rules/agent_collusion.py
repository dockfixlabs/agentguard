"""Multi-Agent Collusion Detection (ASI-AGENT-COLLUSION)

Detects patterns where multiple AI agents can collude through
shared state, unvalidated inter-agent communication, or
common memory without audit trails or trust verification.

This is the most sophisticated attack vector in multi-agent systems:
two or more compromised agents conspiring through covert channels
that no single-agent scanner can detect.
"""
from __future__ import annotations
import re
from agentguard.models import Finding, Rule, Severity


class AgentCollusionRule(Rule):
    """Detects multi-agent collusion patterns.

    When multiple AI agents share state, memory, or communicate
    directly without trust verification, they can conspire to:
    - Bypass individual agent safeguards
    - Escalate privileges through agent chains
    - Hide malicious actions across agent boundaries
    - Coordinate resource exhaustion attacks
    """

    rule_id = "ASI-AGENT-COLLUSION"
    rule_name = "Multi-Agent Collusion"
    severity = Severity.CRITICAL

    # Inter-agent communication patterns
    INTER_AGENT_COMM = re.compile(
        rb"\.send_message\s*\(|\.broadcast\s*\(|\.publish\s*\(|"
        rb"\.notify\s*\(|\.emit\s*\(|\.dispatch\s*\(|"
        rb"\.forward_to\s*\(|\.relay\s*\(|\.proxy\s*\(|"
        rb"\.handoff\s*\(|\.transfer_to\s*\(|\.delegate_to\s*\(|"
        rb"\.route\s*\(|\.publish_event\s*\(|\.trigger\s*\(",
        re.IGNORECASE
    )

    # Shared state between agents
    SHARED_STATE = re.compile(
        rb"shared[_]?(memory|context|state|knowledge|store|db|queue|cache)|"
        rb"global[_]?(memory|context|state|knowledge|store|queue|cache)|"
        rb"common[_]?(memory|context|state|knowledge|store|queue|cache)|"
        rb"multi[_]?agent[_]?(memory|context|state|knowledge|store|queue|cache)|"
        rb"agent[_]?pool|agent[_]?group|agent[_]?team|agent[_]?swarm|"
        rb"group[_]?chat|team[_]?chat|round[_]?robin|"
        rb"ConversableAgent|GroupChat|RoundRobinGroupChat|Team|"
        rb"SwarmAgent|CrewAgent|Orchestrator",
        re.IGNORECASE
    )

    # Agent output -> agent input patterns
    AGENT_CHAIN = re.compile(
        rb"agent\d+[_\.]?(output|result|response)\s*[=,].*agent\d+|"
        rb"agent\d+\.process\s*\(.*agent\d+_",
        re.IGNORECASE
    )

    # Trust verification patterns (absence indicates risk)
    TRUST_VERIFICATION = re.compile(
        rb"verify[_]?(output|result|response|identity|source|origin)|"
        rb"validate[_]?(output|result|response|identity|source|origin)|"
        rb"trust[_]?(score|level|check|verify|validate|model)|"
        rb"reputation[_]?(score|check|system|tracker|model)|"
        rb"agent[_]?(audit|log|trace|monitor|guard)|"
        rb"inter[_]?agent[_]?(audit|log|trace|monitor|guard|verify|validate)|"
        rb"message[_]?(sign|verify|validate|authenticate|check)|"
        rb"sender[_]?(verify|validate|authenticate|check|identity)|"
        rb"nonce|challenge[_]?response|proof[_]?of[_]?(work|stake|identity)",
        re.IGNORECASE
    )

    def scan_line(self, line, line_num, file):
        return []

    def scan_content(self, content, file):
        ext = file.rsplit(".", 1)[-1] if "." in file else ""
        if ext not in ("py", "js", "ts", "jsx", "tsx"):
            return []

        findings = []
        lines = content.splitlines()
        file_has_trust_verify = False

        # First pass: check if file has ANY trust verification
        full_text = "\n".join(lines)
        if self.TRUST_VERIFICATION.search(full_text.encode("utf-8", errors="ignore")):
            file_has_trust_verify = True

        for i, line in enumerate(lines, 1):
            encoded = line.encode("utf-8", errors="ignore")

            # Check for inter-agent communication
            comm_match = self.INTER_AGENT_COMM.search(encoded)
            state_match = self.SHARED_STATE.search(encoded)
            chain_match = self.AGENT_CHAIN.search(encoded)

            if not (comm_match or state_match or chain_match):
                continue

            # Determine what was detected
            if comm_match:
                pattern = comm_match.group(0).decode("utf-8", errors="ignore")
                desc = "Inter-agent communication (%s) without trust verification -- agents can collude through unvalidated messages" % pattern
            elif chain_match:
                pattern = chain_match.group(0).decode("utf-8", errors="ignore")
                desc = "Agent output chaining (%s) without validation -- agent output flows into another agent as unverified input" % pattern
            else:
                pattern = state_match.group(0).decode("utf-8", errors="ignore")
                desc = "Shared agent state (%s) without access controls -- multiple agents share mutable memory enabling collusion" % pattern

            # If trust verification exists anywhere in file, lower confidence
            confidence = 0.75 if file_has_trust_verify else 0.9

            findings.append(Finding(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=Severity.HIGH if file_has_trust_verify else Severity.CRITICAL,
                file=file,
                line=i,
                snippet=line.strip()[:120],
                description=desc,
                recommendation="Implement inter-agent trust verification: message signing, sender identity checks, nonce/challenge-response, audit trails, and output validation gates between agents.",
                confidence=confidence,
            ))

        return findings
