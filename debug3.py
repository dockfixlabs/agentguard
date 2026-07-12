import json, os, sys
sys.path.insert(0, '.')

with open('test_output/manual_review_candidates.json', 'r') as f:
    cands = json.load(f)

from agentguard.scanner import scan_file
from agentguard.false_positive_filter import apply_fp_filters

for num in [42, 46, 49, 50]:
    c = cands[num-1]
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))

    raw = scan_file(fpath)
    filtered, _ = apply_fp_filters(raw)

    matches_raw = [f for f in raw if f.rule_id == c['rule_id'] and f.line == c['line']]
    matches_filt = [f for f in filtered if f.rule_id == c['rule_id'] and f.line == c['line']]

    print(f'#{num} {c["rule_id"]}:')
    print(f'  raw={len(matches_raw)} filt={len(matches_filt)}')
    for m in matches_raw:
        print(f'  RAW snippet: {m.snippet[:120]}')
        print(f'  RAW desc: {m.description[:120]}')
    for m in matches_filt:
        print(f'  FILT snippet: {m.snippet[:120]}')
        print(f'  FILT desc: {m.description[:120]}')
    print()
