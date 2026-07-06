## v0.5.1 - Adversarial Hardening

### Critical Fix: scan_file() Path Handling

`scan_file()` now converts `str` arguments to `Path` internally. Previously, passing a string path would silently fail (no findings returned). This was a critical bug that caused the scanner to miss vulnerabilities when called from external tools.

### Adversarial Hardening: 8 New Detection Patterns

Based on adversarial testing with 10 real-world attack patterns, the following gaps were identified and fixed:

**ASI01 Prompt Injection:**
- Added tool result variables (`result`, `tool_result`, `tool_output`, `api_response`, etc.) to taint tracking sources. Agents that pipe tool output into prompts are now detected.
- Tightened prompt injection regex to avoid false positives on `SYSTEM_PROMPT` constants (no longer matches `content` or `message` generically)

**ASI02 Tool Abuse:**
- Rewrote `DANGEROUS_TOOLS` regex: `subprocess` alone no longer triggers -- only `subprocess.*shell=True` or `os.system`/`os.popen` patterns fire
- Eliminates false positive on safe `subprocess.run(["ls"], capture_output=True)`

**ASI03 Data Exfiltration:**
- Added WebSocket exfiltration detection (`websocket.create_connection("wss://...")`)
- Catches `wss://` and `ws://` protocols

**Scanner:**
- `scan_file()` accepts `Path | str` (was `Path` only, causing silent failures)

### Test Results

- **Unit tests**: 46/46 PASS (up from 38)
- **Adversarial tests**: 10/10 attacks detected, 2/2 safe patterns passed
- **Benchmark**: 32 samples covering all detection rules

### PyPI Metadata Fixes

- Description: Replaced em dash with period for compatibility
- Development Status: Alpha -> Beta
- mcp-scanner: Added full classifiers, project URLs, Beta status
