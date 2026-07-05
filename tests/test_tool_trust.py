"""Tests for ASI-TOOL-TRUST rule."""
import tempfile, os
from agentguard.scanner import scan_file

def _tmp(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_tool_output_subprocess():
    """tool_output used directly in subprocess.run."""
    code = """
import subprocess
def handle_tool():
    tool_output = fetch_tool_result()
    subprocess.run(tool_output, shell=True)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)


def test_tool_result_eval():
    """tool_result fed into eval."""
    code = """
def parse():
    tool_result = get_data()
    return eval(tool_result)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)


def test_agent_output_os_system():
    """agent_output in os.system."""
    code = """
import os
def run():
    agent_output = get_agent_response()
    os.system(agent_output)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)


def test_api_response_exec():
    """api_response used in exec()."""
    code = """
def run_code():
    api_response = call_api()
    exec(api_response)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)


def test_execution_result_open():
    """execution_result as file path."""
    code = """
def save():
    execution_result = run_script()
    open(execution_result, "w").write("ok")
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)


def test_agent_output_create():
    """agent_output used in factory create()."""
    code = """
def chain():
    agent_output = get_response()
    Step.create(agent_output)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)


def test_safe_validated():
    """Validated with pydantic -- should NOT flag."""
    code = """
from pydantic import BaseModel
class Step(BaseModel):
    action: str
def safe():
    api_response = call_api()
    validated = Step.model_validate(api_response)
    execute(validated.action)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) == 0
    finally:
        os.unlink(p)


def test_safe_constant():
    """No tool output -- should NOT flag."""
    code = """
def write():
    path = "config.json"
    open(path, "w").write("{}")
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) == 0
    finally:
        os.unlink(p)


def test_js_tool_output_exec():
    """JavaScript: toolOutput -> exec()."""
    code = """
async function handleTool() {
    tool_output = await fetchResult();
    exec(tool_output);
}
"""
    p = _tmp(code, ".js")
    try:
        findings = scan_file(p)
        trust = [f for f in findings if f.rule_id == "ASI-TOOL-TRUST"]
        assert len(trust) >= 1
    finally:
        os.unlink(p)
