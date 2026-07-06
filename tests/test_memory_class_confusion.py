"""Tests for ASI-MEMORY-CLASS-CONFUSION rule (v0.7.0)."""

import pytest
from pathlib import Path
from agentguard.scanner import scan_file
from agentguard.rules.memory_class_confusion import MemoryClassConfusionRule


@pytest.fixture
def rule():
    return MemoryClassConfusionRule()


# --- self.tools modification tests ---

def test_self_tools_append_without_auth(tmp_path, rule):
    """Should detect self.tools.append() without auth check."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.tools = ["read_file"]

    def add_tool(self, tool_name):
        self.tools.append(tool_name)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) > 0, "Should detect self.tools.append()"
    # Should be HIGH since no auth check
    assert any(f.severity.value == "HIGH" for f in findings)


def test_self_tools_init_not_high(tmp_path, rule):
    """self.tools assignment in __init__ should be MEDIUM or not flagged."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.tools = ["read_file", "search"]
        self.config = {"max_tokens": 1000}
''')
    findings = rule.scan_content(f.read_text(), str(f))
    # __init__ self.tools assignment — may still flag but at MEDIUM
    for f in findings:
        if "self.tools" in f.snippet.lower():
            assert f.severity.value == "MEDIUM", f"__init__ self.tools should be MEDIUM, got {f.severity.value}"


# --- self.permissions modification tests ---

def test_self_permissions_modification(tmp_path, rule):
    """Should detect self.permissions modification."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.permissions = ["read"]

    def escalate(self):
        self.permissions.append("write")
        self.permissions.append("delete")
''')
    findings = rule.scan_content(f.read_text(), str(f))
    perm_findings = [f for f in findings if "permission" in f.description.lower()]
    assert len(perm_findings) > 0, "Should detect self.permissions modification"
    assert any(f.severity.value == "CRITICAL" for f in perm_findings)


def test_self_permissions_with_auth(tmp_path, rule):
    """self.permissions with auth check should have lower severity."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.permissions = ["read"]

    def escalate(self):
        if not check_permission("admin"):
            raise PermissionError
        self.permissions.append("write")
''')
    findings = rule.scan_content(f.read_text(), str(f))
    perm_findings = [f for f in findings if "permission" in f.description.lower()]
    if perm_findings:
        # With auth check, should be HIGH or lower
        assert all(f.severity.value != "CRITICAL" for f in perm_findings), \
            "With auth check, should not be CRITICAL"


# --- System prompt / instructions mutation ---

def test_system_prompt_mutation(tmp_path, rule):
    """Should detect self.system_prompt mutation."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.system_prompt = "You are helpful."

    def update_prompt(self, new_prompt):
        self.system_prompt = new_prompt
''')
    findings = rule.scan_content(f.read_text(), str(f))
    prompt_findings = [f for f in findings if "system_prompt" in f.description.lower()
                       or "system_prompt" in f.snippet.lower()]
    assert len(prompt_findings) > 0, "Should detect system_prompt mutation"


def test_instructions_mutation(tmp_path, rule):
    """Should detect self.instructions mutation."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.instructions = "Default"

    def override(self, text):
        self.instructions = text
''')
    findings = rule.scan_content(f.read_text(), str(f))
    inst_findings = [f for f in findings if "instruction" in f.description.lower()
                     or "instruction" in f.snippet.lower()]
    assert len(inst_findings) > 0, "Should detect instructions mutation"


# --- Config mutation ---

def test_self_config_mutation(tmp_path, rule):
    """Should detect self.config modification."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.config = {"max_tokens": 1000}

    def update_config(self, key, value):
        self.config[key] = value
''')
    findings = rule.scan_content(f.read_text(), str(f))
    config_findings = [f for f in findings if "config" in f.description.lower()]
    assert len(config_findings) > 0, "Should detect self.config modification"


# --- Memory update without checks ---

def test_memory_update_without_auth(tmp_path, rule):
    """Should detect update_context without auth check."""
    f = tmp_path / "agent.py"
    f.write_text('''
class MemoryStore:
    def write(self, key, value):
        self.update_context(key, value)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    mem_findings = [f for f in findings if "memory" in f.description.lower()
                    or "context" in f.description.lower()]
    assert len(mem_findings) > 0, "Should detect memory update without auth"


def test_memory_update_thread_context(tmp_path, rule):
    """Memory update in thread context should be CRITICAL."""
    f = tmp_path / "agent.py"
    f.write_text('''
import threading

class Agent:
    def __init__(self):
        self.memory = MemoryStore()

    def background(self):
        def mutate():
            self.memory.update_context("key", "malicious_value")
        t = threading.Thread(target=mutate)
        t.start()
''')
    findings = rule.scan_content(f.read_text(), str(f))
    mem_findings = [f for f in findings if "memory" in f.description.lower()
                    or "context" in f.description.lower()]
    if mem_findings:
        # In thread context, should be CRITICAL
        assert any(f.severity.value == "CRITICAL" for f in mem_findings), \
            "Thread-context memory update should be CRITICAL"


# --- Capability modification ---

def test_self_capabilities_modification(tmp_path, rule):
    """Should detect self.capabilities modification."""
    f = tmp_path / "agent.py"
    f.write_text('''
class Agent:
    def __init__(self):
        self.capabilities = ["text"]

    def add_capability(self, cap):
        self.capabilities.append(cap)
''')
    findings = rule.scan_content(f.read_text(), str(f))
    cap_findings = [f for f in findings if "capabilit" in f.description.lower()]
    assert len(cap_findings) > 0, "Should detect capabilities modification"


# --- Benchmark sample tests ---

def test_benchmark_memory_01():
    """Benchmark 03: Agent self-modification vulnerabilities."""
    sample = Path(__file__).parent / "samples" / "benchmark_memory_01.py"
    if not sample.exists():
        pytest.skip("Benchmark sample not found")
    findings = scan_file(sample)
    mem_findings = [f for f in findings if "MEMORY-CLASS-CONFUSION" in f.rule_id]
    assert len(mem_findings) >= 5, f"Should find >=5 class confusion issues, got {len(mem_findings)}"


def test_benchmark_memory_02():
    """Benchmark 04: Shared state mutation vulnerabilities."""
    sample = Path(__file__).parent / "samples" / "benchmark_memory_02.py"
    if not sample.exists():
        pytest.skip("Benchmark sample not found")
    findings = scan_file(sample)
    mem_findings = [f for f in findings if "MEMORY-CLASS-CONFUSION" in f.rule_id]
    assert len(mem_findings) >= 3, f"Should find >=3 class confusion issues, got {len(mem_findings)}"


# --- Safe patterns ---

def test_commented_code_not_flagged(tmp_path, rule):
    """Comments should not be flagged."""
    f = tmp_path / "agent.py"
    f.write_text('# self.tools.append("dangerous_tool")')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not flag comments"


def test_safe_agent_not_flagged(tmp_path, rule):
    """Safe agent code should not be flagged."""
    f = tmp_path / "agent.py"
    f.write_text('''
class SafeAgent:
    def __init__(self):
        self.tools = frozenset(["read"])

    def process(self, query):
        return "Hello"
''')
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not flag safe agent code"


def test_non_code_file_not_scanned(tmp_path, rule):
    """Non-code files should return empty."""
    f = tmp_path / "README.md"
    f.write_text("self.tools.append('evil')")
    findings = rule.scan_content(f.read_text(), str(f))
    assert len(findings) == 0, "Should not scan .md files"
