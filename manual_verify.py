"""Manual verification of top 50 CONFIRMED findings.
Reads each source file at reported line, shows context, records TP/FP judgment.
"""
import json, os, sys
sys.path.insert(0, '.')

with open('test_output/manual_review_candidates.json', 'r', encoding='utf-8') as f:
    candidates = json.load(f)

print(f"VERIFYING {len(candidates)} FINDINGS")
print("=" * 80)
print("Reviewer: AutoClaw | Date: 2026-07-09")
print("Judgment: TRUE_POSITIVE (real vuln) or FALSE_POSITIVE (pattern match, not exploitable)")
print("=" * 80)

results = []
tp_count = 0
fp_count = 0

for idx, c in enumerate(candidates):
    filepath = c['file']
    line_num = c['line']
    
    # Resolve relative path from agentguard dir
    if filepath.startswith('..'):
        abs_path = os.path.normpath(os.path.join(os.getcwd(), filepath))
    else:
        abs_path = filepath
    
    if not os.path.exists(abs_path):
        # Try alternative path resolution
        alt = filepath.split('\\')
        for part in alt:
            if os.path.exists(os.path.join(os.getcwd(), '..', part)):
                abs_path = os.path.join(os.getcwd(), '..', part)
                break
    
    context_lines = []
    try:
        with open(abs_path, 'r', encoding='utf-8', errors='ignore') as src:
            all_lines = src.readlines()
            start = max(0, line_num - 4)
            end = min(len(all_lines), line_num + 3)
            context_lines = [f"  {start+i+1}: {all_lines[start+i].rstrip()}" for i in range(end-start)]
    except Exception as e:
        context_lines = [f"  ERROR reading file: {e}"]
    
    print(f"\n{'='*80}")
    print(f"[{idx+1}/{len(candidates)}] {c['framework'].upper()} | {c['rule_id']} | conf={c['confidence']:.0%}")
    print(f"File: {filepath}:{line_num}")
    print(f"Description: {c['description']}")
    print(f"Source context:")
    for line in context_lines:
        print(line)
    print(f"\n{'-'*40}")
    
    # Present context for judgment
    judgment = yield (idx, c, context_lines, abs_path)

# After all reviews, compute results
# (This will be called after the generator completes)
