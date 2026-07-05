"""Tests for ASI-AGENT-COLLUSION rule."""
import tempfile, os
from agentguard.scanner import scan_file

def _tmp(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_agent_broadcast_no_trust():
    """Agent broadcasts without trust verification."""
    code = """
class AgentSystem:
    def process(self):
        result = self.agent1.run()
        self.broadcast(result)

    def broadcast(self, msg):
        for agent in self.pool:
            agent.receive(msg)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) >= 1
        assert coll[0].severity.name == "CRITICAL"
    finally:
        os.unlink(p)


def test_shared_memory_collusion():
    """Multiple agents share mutable memory."""
    code = """
class MultiAgentOrchestrator:
    def __init__(self):
        self.shared_memory = {}
        self.shared_context = []

    def run(self):
        for agent in self.agent_pool:
            output = agent.execute(self.shared_context)
            self.shared_memory[agent.name] = output
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) >= 1
    finally:
        os.unlink(p)


def test_agent_chain_no_validation():
    """Agent output flows directly to another agent."""
    code = """
class Pipeline:
    def execute(self):
        agent1_output = self.agent1.process(input_data)
        return self.agent2.process(agent1_output)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) >= 1
    finally:
        os.unlink(p)


def test_group_chat_pattern():
    """AutoGen-style GroupChat without trust checks."""
    code = """
from autogen_agentchat.teams import RoundRobinGroupChat

team = RoundRobinGroupChat(participants=[agent1, agent2, agent3])

async def run():
    result = await team.run(task="Do something")
    return result
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) >= 1
    finally:
        os.unlink(p)


def test_publish_event_no_verify():
    """Agent publishes events without verification."""
    code = """
class EventSystem:
    def handle(self, agent_result):
        event = {"source": "agent1", "data": agent_result}
        self.publish_event(event)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) >= 1
    finally:
        os.unlink(p)


def test_with_trust_verification():
    """Has trust verification -- should flag at HIGH not CRITICAL."""
    code = """
class SecureOrchestrator:
    def __init__(self):
        self.trust_scores = {}
        self.agent_audit_log = []

    def verify_output(self, result):
        return self.trust_model.validate(result)

    def process(self):
        for agent in self.agent_pool:
            output = agent.run()
            if self.verify_output(output):
                self.broadcast(output)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) >= 1
        assert coll[0].severity.name == "HIGH"
    finally:
        os.unlink(p)


def test_safe_single_agent():
    """Single agent with no inter-agent patterns -- should NOT flag."""
    code = """
class SimpleAgent:
    def run(self, user_input):
        return process(user_input)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        coll = [f for f in findings if f.rule_id == "ASI-AGENT-COLLUSION"]
        assert len(coll) == 0
    finally:
        os.unlink(p)
