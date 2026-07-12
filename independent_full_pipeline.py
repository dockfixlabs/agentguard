"""Re-run independent validation with FULL pipeline (rules + FP filter)."""
import json, os, sys
sys.path.insert(0, '.')

with open('test_output/independent_sample.json', 'r') as f:
    cands = json.load(f)

from agentguard.scanner import scan_file
from agentguard.false_positive_filter import apply_fp_filters

# Also load the heuristic verdicts from the first independent run
with open('test_output/independent_verdicts.json', 'r') as f:
    heuristic_verdicts = json.load(f)

results = []
for idx, c in enumerate(cands):
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    raw = scan_file(fpath)
    filtered, _ = apply_fp_filters(raw)
    
    # Check if finding survived the full pipeline
    survived = any(f.rule_id == c['rule_id'] and f.line == c['line'] for f in filtered)
    
    # Use the heuristic verdict from the independent validation
    hv = heuristic_verdicts[idx]
    verdict = hv['verdict']
    
    improvement = ('FIXED' if verdict == 'FP' and not survived else
                   'GOOD' if verdict == 'TP' and survived else
                   'BAD' if verdict == 'FP' and survived else
                   'REGRESSION' if verdict == 'TP' and not survived else '?')
    
    results.append({
        'num': idx + 1,
        'framework': c['framework'],
        'rule_id': c['rule_id'],
        'verdict': verdict,
        'survived': survived,
        'improvement': improvement,
        'reason': hv['reason'],
    })

# Compute
tp_total = sum(1 for r in results if r['verdict'] == 'TP')
fp_total = sum(1 for r in results if r['verdict'] == 'FP')
tp_detected = sum(1 for r in results if r['verdict'] == 'TP' and r['survived'])
fp_detected = sum(1 for r in results if r['verdict'] == 'FP' and r['survived'])
fp_fixed = fp_total - fp_detected
tp_lost = sum(1 for r in results if r['verdict'] == 'TP' and not r['survived'])

total_detected = tp_detected + fp_detected
precision = tp_detected / total_detected * 100 if total_detected > 0 else 0

print(f'{"="*65}')
print(f'INDEPENDENT VALIDATION — FULL PIPELINE (rules + FP filter)')
print(f'50 findings NOT used in any fix')
print(f'{"="*65}')
print(f'Heuristic verdicts:  {tp_total}TP / {fp_total}FP = {tp_total/(tp_total+fp_total)*100:.0f}% precision')
print(f'After full pipeline: {tp_detected}TP / {fp_detected}FP = {tp_detected}/{total_detected} ({precision:.0f}% precision)')
print(f'FP eliminated by filter: {fp_fixed}')
print(f'TP lost (regression): {tp_lost}')
print()

# By rule
by_rule = {}
for r in results:
    rid = r['rule_id']
    if rid not in by_rule:
        by_rule[rid] = {'tp_h': 0, 'fp_h': 0, 'tp_f': 0, 'fp_f': 0}
    if r['verdict'] == 'TP':
        by_rule[rid]['tp_h'] += 1
        if r['survived']: by_rule[rid]['tp_f'] += 1
    else:
        by_rule[rid]['fp_h'] += 1
        if r['survived']: by_rule[rid]['fp_f'] += 1

print('BY RULE:')
print(f'{"Rule":<30s} {"Heuristic":>10s} {"Pipeline":>10s} {"Change":>7s}')
print('-'*60)
for rid, c in sorted(by_rule.items()):
    th = c['tp_h']; fh = c['fp_h']; tf = c['tp_f']; ff = c['fp_f']
    ph = th/(th+fh)*100 if th+fh > 0 else 0
    pf = tf/(tf+ff)*100 if tf+ff > 0 else 100
    arrow = '+' if pf-ph > 0 else ''
    print(f'{rid:<30s} {ph:>8.0f}% -> {pf:>7.0f}%  {arrow}{pf-ph:>+5.0f}%')

# Problems
problems = [r for r in results if r['improvement'] in ('BAD', 'REGRESSION')]
if problems:
    print(f'\nREMAINING ISSUES ({len(problems)}):')
    for r in problems:
        flag = '!' if r['improvement'] == 'BAD' else 'X'
        print(f'  {flag} #{r["num"]:>2d} {r["rule_id"]:<28s} {r["verdict"]} survived={r["survived"]} — {r["reason"]}')

if precision >= 90:
    print(f'\n*** EXCELLENT: {precision:.0f}% precision on independent sample ***')
elif precision >= 80:
    print(f'\n*** GOOD: {precision:.0f}% precision on independent sample ***')
elif precision >= 60:
    print(f'\n*** ACCEPTABLE: {precision:.0f}% precision — above 60% target ***')
else:
    print(f'\n*** BELOW TARGET: {precision:.0f}% — needs more work ***')
