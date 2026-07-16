# AgentGuard v0.8.3 — FP Reduction Patch

**Released:** July 16, 2026  
**PyPI:** `pip install dfx-agentguard`  
**GitHub:** https://github.com/dockfixlabs/agentguard

## What's Fixed

### 87% Fewer False Positives
The self-scan on AgentGuard's own codebase dropped from **249 → 32 findings**:

| Rule | Before | After | Reduction |
|------|--------|-------|-----------|
| ASI10 Trust Boundary | 200+ | 5 | 98% |
| ASI06 Unsafe Eval | 20 | 12 | 40% |
| **Total** | **249** | **32** | **87%** |

### Root Cause
Security scanner rules contain `re.compile(r'...eval...')` patterns that detect dangerous code — but the scanner was detecting its own detection patterns as vulnerabilities. This is the "snake eating its own tail" problem.

### Fix
- `trust_boundary.py`: Added `REGEX_PATTERN_LINE` exclusion — lines containing `r'...self-modification keywords...'` are recognized as detector patterns, not vulnerabilities
- `unsafe_eval.py`: Added `REGEX_DETECTOR_LINE` exclusion — same pattern for eval/exec/__import__ in regex strings
- `false_positive_filter.py`: 10 new exclusion patterns for ASI10 and ASI06
- Precommit tests now skip cleanly when `pre-commit` binary is unavailable

### Other
- SARIF upload step added to GitHub Action — findings now appear in Security tab
- 136 tests pass, 0 failures
