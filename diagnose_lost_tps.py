"""Diagnose lost TPs by comparing raw vs filtered findings."""
import json, os, sys
sys.path.insert(0, '.')

with open('test_output/independent_sample.json', 'r') as f:
    cands = json.load(f)

with open('test_output/independent_verdicts.json', 'r') as f:
    heuristic_verdicts = json.load(f)

from agentguard.scanner import scan_file
from agentguard.false_positive_filter import apply_fp_filters

lost_tps = []
for idx, c in enumerate(cands):
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    raw = scan_file(fpath)
    filtered, removed_result = apply_fp_filters(raw)
    
    hv = heuristic_verdicts[idx]
    if hv['verdict'] != 'TP':
        continue
    
    survived = any(f.rule_id == c['rule_id'] and f.line == c['line'] for f in filtered)
    if survived:
        continue
    
    # Find the raw finding that was removed
    raw_finding = None
    for f in raw:
        if f.rule_id == c['rule_id'] and f.line == c['line']:
            raw_finding = f
            break
    
    lost_tps.append({
        'num': idx + 1,
        'framework': c['framework'],
        'rule_id': c['rule_id'],
        'file': c['file'],
        'line': c['line'],
        'snippet': raw_finding.snippet[:150] if raw_finding else 'NOT FOUND IN RAW',
        'description': raw_finding.description[:150] if raw_finding else '',
        'heuristic_reason': hv['reason'],
    })

print(f'LOST TPs: {len(lost_tps)}')
print()
for lt in lost_tps:
    print(f'#{lt["num"]:>2d} {lt["rule_id"]:<28s} {lt["framework"]}')
    print(f'    File: {lt["file"]}:{lt["line"]}')
    print(f'    Snippet: {lt["snippet"]}')
    print(f'    Desc: {lt["description"]}')
    print(f'    Heuristic: {lt["heuristic_reason"]}')
    print()

# Group by rule
by_rule = {}
for lt in lost_tps:
    rid = lt['rule_id']
    if rid not in by_rule:
        by_rule[rid] = []
    by_rule[rid].append(lt)

print('BY RULE:')
for rid, items in sorted(by_rule.items()):
    print(f'  {rid}: {len(items)} lost TPs')
    for item in items:
        print(f'    -> {item["snippet"][:80]}')
