## v0.5.0 - AST-Based Taint Tracking

### Headline

**AgentGuard now traces data flow from user input to LLM sinks using AST analysis.** This is the transition from regex-only to semantic understanding.

### New: AST Taint Tracking (ASI01-TAINT-TRACK)

The new `TaintTrackingRule` parses Python AST and tracks how untrusted data flows through variable assignments, string formatting, and function calls to reach LLM sinks.

**What it catches that regex cannot:**

```python
# Regex cannot track this -- multi-hop flow
user_input = request.args.get("message")
processed = user_input.strip()       # taint propagates
prompt = f"You are helpful. {processed}"  # tainted var in f-string
```

```python
# Regex cannot track this -- .format() with named args
query = request.json.get("query")
template = "Answer: {q}"
prompt = template.format(q=query)    # taint via .format()
```

**How it works:**

1. **Sources**: Identifies `request.args.get()`, `request.json.get()`, `input()`, and known source variable names
2. **Propagation**: Tracks taint through variable assignments, method calls (`.strip()`, `.upper()`), f-strings, `.format()`, string concatenation, list/dict construction
3. **Sinks**: Detects when tainted data reaches LLM sink variables (`prompt`, `messages`, `system_prompt`) or LLM API calls (`openai.chat.completions.create`)
4. **Sanitizers**: `str()`, `int()`, `len()` and similar are treated as sanitizers that remove taint

**6 taint tracking tests:** direct flow, indirect (.format), multi-hop, sanitized (negative), safe prompt (negative), messages array.

### Test Results

- **Unit tests**: 38/38 PASS (up from 32)
- **Benchmark**: 32 samples, 100% detection, 0% FP
- **Taint tracking**: 6/6 test cases correct (4 detected, 2 correctly skipped)

### Install

```bash
pip install --upgrade dfx-agentguard
agentguard . --format text
```
