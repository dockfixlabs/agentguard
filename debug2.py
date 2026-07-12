import json, os, sys
sys.path.insert(0, '.')

with open('test_output/manual_review_candidates.json', 'r') as f:
    cands = json.load(f)

from agentguard.scanner import scan_file
from agentguard.false_positive_filter import apply_fp_filters

nums = [42, 46, 47, 48, 49, 50]
for num in nums:
    c = cands[num-1]
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))

    if not os.path.exists(fpath):
        print(f'#{num}: FILE NOT FOUND')
        continue

    raw = scan_file(fpath)
    filtered, _ = apply_fp_filters(raw)

    matches_raw = [f for f in raw if f.rule_id == c['rule_id'] and f.line == c['line']]
    matches_filt = [f for f in filtered if f.rule_id == c['rule_id'] and f.line == c['line']]

    print(f'#{num} {c["rule_id"]} (verdict={c.get("verdict","?")}):')
    print(f'  raw={len(matches_raw)} filt={len(matches_filt)}')
    for m in matches_raw:
        print(f'  RAW: {m.snippet[:120]}')
    for m in matches_filt:
        print(f'  FILT: {m.snippet[:120]}')
    # Also show what's AT that line vs nearby
    for f in raw:
        if abs(f.line - c['line']) <= 2 and f.rule_id == c['rule_id']:
            print(f'  NEARBY L{f.line}: {f.snippet[:100]}')
    print()
