"""Tests for ASI-STEGANO-INJECT rule."""
import tempfile, os
from agentguard.scanner import scan_file

def _tmp(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_base64_decode_exec():
    """base64 decode then exec."""
    code = """
import base64, os
def handle(user_input):
    decoded = base64.b64decode(user_input)
    os.system(decoded)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        steg = [f for f in findings if f.rule_id == "ASI-STEGANO-INJECT"]
        assert len(steg) >= 1
    finally:
        os.unlink(p)


def test_hex_decode_eval():
    """hex decode then eval."""
    code = """
def process(request_data):
    decoded = bytes.fromhex(request_data)
    return eval(decoded)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        steg = [f for f in findings if f.rule_id == "ASI-STEGANO-INJECT"]
        assert len(steg) >= 1
    finally:
        os.unlink(p)


def test_rot13_decode_subprocess():
    """rot13 decode then subprocess."""
    code = """
import codecs, subprocess
def run(user_input):
    decoded = codecs.decode(user_input, "rot13")
    subprocess.run(decoded, shell=True)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        steg = [f for f in findings if f.rule_id == "ASI-STEGANO-INJECT"]
        assert len(steg) >= 1
    finally:
        os.unlink(p)


def test_js_atob_exec():
    """JavaScript atob decode then dangerous op."""
    code = """
async function handle(userInput) {
    const decoded = atob(userInput);
    exec(decoded);
}
"""
    p = _tmp(code, ".js")
    try:
        findings = scan_file(p)
        steg = [f for f in findings if f.rule_id == "ASI-STEGANO-INJECT"]
        assert len(steg) >= 1
    finally:
        os.unlink(p)


def test_safe_decode_no_exec():
    """Decode without dangerous operation -- should NOT flag."""
    code = """
import base64
def decode_only(user_input):
    decoded = base64.b64decode(user_input)
    return decoded.upper()
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        steg = [f for f in findings if f.rule_id == "ASI-STEGANO-INJECT"]
        assert len(steg) == 0
    finally:
        os.unlink(p)


def test_safe_no_decode():
    """No decode at all -- should NOT flag."""
    code = """
def process(user_input):
    return user_input.strip()
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        steg = [f for f in findings if f.rule_id == "ASI-STEGANO-INJECT"]
        assert len(steg) == 0
    finally:
        os.unlink(p)
