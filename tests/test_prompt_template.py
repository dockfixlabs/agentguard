"""Tests for ASI-PROMPT-TEMPLATE rule."""
import tempfile, os
from agentguard.scanner import scan_file

def _tmp(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_jinja2_template_user_input():
    """Jinja2 template renders user input."""
    code = """
from jinja2 import Template
def build_prompt(user_input):
    tmpl = Template("System: {{ user_data }}")
    return tmpl.render(user_data=user_input)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        tmpl = [f for f in findings if f.rule_id == "ASI-PROMPT-TEMPLATE"]
        assert len(tmpl) >= 1
    finally:
        os.unlink(p)


def test_fstring_message_structure():
    """f-string builds message role/content structure."""
    code = """
def build_messages(user_input):
    return f'[{{"role": "user", "content": "{user_input}"}}]'
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        tmpl = [f for f in findings if f.rule_id == "ASI-PROMPT-TEMPLATE"]
        assert len(tmpl) >= 1
    finally:
        os.unlink(p)


def test_messages_append_user_data():
    """messages.append() with user data -- conversation poisoning."""
    code = """
def add_to_history(user_input, messages):
    messages.append({"role": "user", "content": user_input})
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        tmpl = [f for f in findings if f.rule_id == "ASI-PROMPT-TEMPLATE"]
        assert len(tmpl) >= 1
    finally:
        os.unlink(p)


def test_messages_extend_user_data():
    """messages.extend() with user-controlled messages."""
    code = """
def merge_history(request_data):
    messages.extend(request_data.get("history", []))
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        tmpl = [f for f in findings if f.rule_id == "ASI-PROMPT-TEMPLATE"]
        assert len(tmpl) >= 1
    finally:
        os.unlink(p)


def test_safe_hardcoded_template():
    """Template without user input -- should NOT flag."""
    code = """
from jinja2 import Template
def build():
    tmpl = Template("System: You are helpful")
    return tmpl.render()
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        tmpl = [f for f in findings if f.rule_id == "ASI-PROMPT-TEMPLATE"]
        assert len(tmpl) == 0
    finally:
        os.unlink(p)


def test_safe_messages_constant():
    """messages.append with constant -- should NOT flag."""
    code = """
def setup_messages():
    messages = []
    messages.append({"role": "system", "content": "You are helpful"})
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        tmpl = [f for f in findings if f.rule_id == "ASI-PROMPT-TEMPLATE"]
        assert len(tmpl) == 0
    finally:
        os.unlink(p)
