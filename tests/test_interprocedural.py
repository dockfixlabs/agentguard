"""Tests for interprocedural taint analysis -- cross-function taint flow."""
import tempfile, os
from agentguard.scanner import scan_file


def _tmp(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_direct_cross_func_taint():
    code = """
import openai

def call_llm(prompt):
    return openai.chat.completions.create(model="gpt-4", messages=[{"role":"user","content":prompt}])

def handle_request(user_input):
    response = call_llm(user_input)
    return response
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        rids = [f.rule_id for f in findings]
        assert "ASI01-INTERPROCEDURAL" in rids
    finally:
        os.unlink(p)


def test_indirect_chain_taint():
    code = """
import openai

def call_llm(text):
    return openai.chat.completions.create(model="gpt-4", messages=[{"role":"user","content":text}])

def process_data(data):
    return call_llm(data)

def main(user_input):
    return process_data(user_input)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        rids = [f.rule_id for f in findings]
        assert "ASI01-INTERPROCEDURAL" in rids
    finally:
        os.unlink(p)


def test_tainted_param_sink():
    code = """
import openai

def generate_answer(user_query):
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role":"user","content":user_query}]
    )
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        rids = [f.rule_id for f in findings]
        assert "ASI01-INTERPROCEDURAL" in rids
    finally:
        os.unlink(p)


def test_clean_function_no_alert():
    code = """
def sanitize(user_input):
    return user_input.strip().lower()

def process(input_str):
    return sanitize(input_str)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        rids = [f.rule_id for f in findings]
        assert "ASI01-INTERPROCEDURAL" not in rids
        assert len(findings) == 0
    finally:
        os.unlink(p)


def test_multi_arg_taint():
    code = """
import openai

def ask_ai(system_msg, user_content, temperature=0.7):
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role":"system","content":system_msg},
            {"role":"user","content":user_content}
        ]
    )

def handle(user_input):
    return ask_ai("You are helpful", user_input)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        rids = [f.rule_id for f in findings]
        assert "ASI01-INTERPROCEDURAL" in rids
    finally:
        os.unlink(p)


def test_js_file_skipped():
    code = """
function callLLM(prompt) {
    return fetch("https://api.openai.com/v1/chat/completions")
}
function handle(userInput) {
    return callLLM(userInput)
}
"""
    p = _tmp(code, ".js")
    try:
        findings = scan_file(p)
        ip = [f for f in findings if f.rule_id == "ASI01-INTERPROCEDURAL"]
        assert len(ip) == 0
    finally:
        os.unlink(p)
