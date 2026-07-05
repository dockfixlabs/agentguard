"""Tests for ASI-CHAIN-AMPLIFY rule."""
import tempfile, os
from agentguard.scanner import scan_file

def _tmp(content, ext=".py"):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


def test_for_loop_delete_batch():
    """Delete in for loop without rate limit."""
    code = """
def cleanup_files(tool_output):
    files = tool_output.get("files")
    for f in files:
        os.remove(f)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) >= 1
    finally:
        os.unlink(p)


def test_while_true_send():
    """Send in while True loop."""
    code = """
def broadcast(api_response):
    while True:
        msg = api_response.get("next")
        channel.send(msg)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) >= 1
    finally:
        os.unlink(p)


def test_map_lambda_delete():
    """map(lambda) with destructive operation."""
    code = """
def bulk_delete(user_input):
    ids = fetch_all(user_input)
    list(map(lambda x: db.delete(x), ids))
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) >= 1
    finally:
        os.unlink(p)


def test_thread_pool_destroy():
    """ThreadPoolExecutor with destroy operations."""
    code = """
from concurrent.futures import ThreadPoolExecutor
def destroy_all(tool_result):
    targets = tool_result.get("targets")
    with ThreadPoolExecutor() as executor:
        executor.map(lambda x: db.delete(x), targets)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) >= 1
    finally:
        os.unlink(p)


def test_safe_rate_limited():
    """Rate-limited batch -- should NOT flag."""
    code = """
def safe_cleanup(tool_output):
    files = tool_output.get("files")
    batch_size = 10
    processed = 0
    for f in files:
        if processed >= max_batch:
            break
        os.remove(f)
        time.sleep(1)
        processed += 1
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) == 0
    finally:
        os.unlink(p)


def test_safe_no_destructive():
    """Loop with safe operation -- should NOT flag."""
    code = """
def process_items(tool_output):
    items = tool_output.get("items")
    for item in items:
        log.info(item)
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) == 0
    finally:
        os.unlink(p)


def test_agent_result_loop():
    """agent_result in destructive for loop."""
    code = """
def cascade_delete(agent_result):
    resources = agent_result.get("resources", [])
    for r in resources:
        cloud.delete(r["id"])
"""
    p = _tmp(code)
    try:
        findings = scan_file(p)
        chain = [f for f in findings if f.rule_id == "ASI-CHAIN-AMPLIFY"]
        assert len(chain) >= 1
    finally:
        os.unlink(p)
