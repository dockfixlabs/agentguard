"""Tests for cross-file interprocedural taint analysis -- Phase 2."""
import tempfile, os
from agentguard.scanner import scan_file


def test_cross_file_imported_sink():
    """Tainted data flows from main.py into imported utils.py function."""
    tmpdir = tempfile.mkdtemp()

    # Create utils.py with LLM sink
    utils_path = os.path.join(tmpdir, "utils.py")
    with open(utils_path, "w", encoding="utf-8") as f:
        f.write("""
import openai

def call_llm(prompt):
    return openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
""")

    # Create main.py that imports and calls utils.call_llm with tainted data
    main_path = os.path.join(tmpdir, "main.py")
    with open(main_path, "w", encoding="utf-8") as f:
        f.write("""
from utils import call_llm

def handle_request(user_input):
    return call_llm(user_input)
""")

    try:
        findings = scan_file(main_path)
        cross_file = [f for f in findings if f.rule_id == "ASI01-CROSS-FILE"]
        assert len(cross_file) >= 1
        assert "call_llm" in cross_file[0].description
    finally:
        os.unlink(utils_path)
        os.unlink(main_path)
        os.rmdir(tmpdir)


def test_cross_file_clean_import():
    """Importing a function without LLM sink should not flag."""
    tmpdir = tempfile.mkdtemp()

    with open(os.path.join(tmpdir, "formatters.py"), "w", encoding="utf-8") as f:
        f.write("""
def clean(text):
    return text.strip().title()
""")

    main_path = os.path.join(tmpdir, "main.py")
    with open(main_path, "w", encoding="utf-8") as f:
        f.write("""
from formatters import clean

def handle(user_input):
    return clean(user_input)
""")

    try:
        findings = scan_file(main_path)
        cross_file = [f for f in findings if f.rule_id == "ASI01-CROSS-FILE"]
        assert len(cross_file) == 0
    finally:
        os.unlink(os.path.join(tmpdir, "formatters.py"))
        os.unlink(main_path)
        os.rmdir(tmpdir)


def test_cross_file_client_pattern():
    """Imported function using client.chat.completions pattern."""
    tmpdir = tempfile.mkdtemp()

    with open(os.path.join(tmpdir, "ai.py"), "w", encoding="utf-8") as f:
        f.write("""
from openai import OpenAI
client = OpenAI()

def ask_ai(prompt):
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
""")

    main_path = os.path.join(tmpdir, "main.py")
    with open(main_path, "w", encoding="utf-8") as f:
        f.write("""
from ai import ask_ai

def chat(user_message):
    return ask_ai(user_message)
""")

    try:
        findings = scan_file(main_path)
        cross_file = [f for f in findings if f.rule_id == "ASI01-CROSS-FILE"]
        assert len(cross_file) >= 1
    finally:
        os.unlink(os.path.join(tmpdir, "ai.py"))
        os.unlink(main_path)
        os.rmdir(tmpdir)
