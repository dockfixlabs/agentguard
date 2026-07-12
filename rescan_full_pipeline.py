"""Re-scan using FULL pipeline: rules + FP filter + classifier."""
import json, os, sys
sys.path.insert(0, '.')

from agentguard.scanner import scan_directory
from agentguard.false_positive_filter import apply_fp_filters

# Load the 50 candidates
with open('test_output/manual_review_candidates.json', 'r', encoding='utf-8') as f:
    cands = json.load(f)

# Load manual verdicts
with open('test_output/manual_verdicts_final.json', 'r', encoding='utf-8') as f:
    verdicts = json.load(f)

# Scan each file via full pipeline: scan_file -> FP filter
from agentguard.scanner import scan_file

results = []
for idx, c in enumerate(cands):
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    # Raw scan
    raw_findings = scan_file(fpath)
    # Apply FP filter
    filtered, fp_result = apply_fp_filters(raw_findings)
    
    # Check if our specific finding survived
    manual = verdicts[idx]
    match = None
    for f in filtered:
        if f.line == c['line'] and f.rule_id == c['rule_id']:
            match = f
            break
    
    verdict_label = manual['verdict']
    still_there = match is not None
    improvement = ('FIXED' if verdict_label == 'FP' and not still_there else
                   'GOOD' if verdict_label == 'TP' and still_there else
                   'BAD' if verdict_label == 'FP' and still_there else
                   'REGRESSION' if verdict_label == 'TP' and not still_there else '?')
    
    results.append({
        'num': idx + 1,
        'framework': c['framework'],
        'rule_id': c['rule_id'],
        'verdict': verdict_label,
        'still_detected': still_there,
        'improvement': improvement,
    })

# Compute
tp_manual = sum(1 for r in results if r['verdict'] == 'TP')
fp_manual = sum(1 for r in results if r['verdict'] == 'FP')
new_tp = sum(1 for r in results if r['verdict'] == 'TP' and r['still_detected'])
new_fp = sum(1 for r in results if r['verdict'] == 'FP' and r['still_detected'])
fp_fixed = fp_manual - new_fp
tp_lost = sum(1 for r in results if r['verdict'] == 'TP' and not r['still_detected'])

total_new = new_tp + new_fp
precision = new_tp / total_new * 100 if total_new > 0 else 0

print(f'{"="*60}')
print(f'FULL PIPELINE RE-SCAN (rules + FP filter)')
print(f'{"="*60}')
print(f'Before: {tp_manual}TP / {fp_manual}FP = {tp_manual/(tp_manual+fp_manual)*100:.0f}% precision')
print(f'After:  {new_tp}TP / {new_fp}FP = {new_tp}/{total_new} ({precision:.0f}% precision)')
print(f'FP eliminated: {fp_fixed}')
print(f'TP lost: {tp_lost}')
print()

# By rule
by_rule = {}
for r in results:
    rid = r['rule_id']
    if rid not in by_rule:
        by_rule[rid] = {'tp_m': 0, 'fp_m': 0, 'tp_n': 0, 'fp_n': 0}
    if r['verdict'] == 'TP':
        by_rule[rid]['tp_m'] += 1
        if r['still_detected']: by_rule[rid]['tp_n'] += 1
    else:
        by_rule[rid]['fp_m'] += 1
        if r['still_detected']: by_rule[rid]['fp_n'] += 1

print('BY RULE:')
print(f'{"Rule":<30s} {"Before":>7s} {"After":>7s} {"Change":>7s}')
print('-'*55)
for rid, cnt in sorted(by_rule.items()):
    tm = cnt['tp_m']; fm = cnt['fp_m']; tn = cnt['tp_n']; fn = cnt['fp_n']
    b = tm/(tm+fm)*100 if tm+fm>0 else 0
    a = tn/(tn+fn)*100 if tn+fn>0 else 100
    arrow = '+' if a-b > 0 else ''
    print(f'{rid:<30s} {b:>5.0f}% -> {a:>5.0f}%  {arrow}{a-b:>+5.0f}%')

# Print remaining problems
problems = [r for r in results if r['improvement'] in ('BAD', 'REGRESSION')]
if problems:
    print(f'\nREMAINING PROBLEMS ({len(problems)}):')
    for r in problems:
        flag = '!' if r['improvement']=='BAD' else 'X'
        print(f'  {flag} [{r["num"]:>2d}] {r["rule_id"]:<28s} {r["verdict"]} still detected')

if precision >= 60:
    print(f'\n*** TARGET REACHED: {precision:.0f}% >= 60% ***')
else:
    gap = 60 - precision
    print(f'\nGap to 60%: {gap:.0f}% — {int(gap/100*50)} more FPs to fix')
