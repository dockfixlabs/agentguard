"""Re-scan the same 50 findings with fixed rules to measure improvement."""
import json, os, re, sys
sys.path.insert(0, '.')

from agentguard.scanner import scan_file

# Reload the 50 review candidates
with open('test_output/manual_review_candidates.json', 'r', encoding='utf-8') as f:
    cands = json.load(f)

# Re-scan each file
by_candidate = {}
for c in cands:
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    if fpath not in by_candidate:
        findings = scan_file(fpath)
        by_candidate[fpath] = findings
        # No findings from this file
        if not findings:
            by_candidate[fpath] = []

# Now check if each original finding is still detected
results = []
for c in cands:
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    findings = by_candidate.get(fpath, [])
    matched = False
    for f in findings:
        if f.line == c['line'] and f.rule_id == c['rule_id']:
            matched = True
            break
    
    # Load our manual verdict
    with open('test_output/manual_verdicts_final.json', 'r', encoding='utf-8') as vf:
        verdicts = json.load(vf)
    manual_verdict = next((v['verdict'] for v in verdicts if v['num'] == len(results) + 1), 'UNKNOWN')
    
    results.append({
        'num': len(results) + 1,
        'framework': c['framework'],
        'rule_id': c['rule_id'],
        'manual_verdict': manual_verdict,
        'still_detected': matched,
        'improvement': 'FIXED' if manual_verdict == 'FP' and not matched else
                       'GOOD' if manual_verdict == 'TP' and matched else
                       'BAD' if manual_verdict == 'FP' and matched else
                       'REGRESSION' if manual_verdict == 'TP' and not matched else 'UNKNOWN'
    })

# Compute new precision
tp_manual = sum(1 for r in results if r['manual_verdict'] == 'TP')
fp_manual = sum(1 for r in results if r['manual_verdict'] == 'FP')

# New detection: TP = still_detected AND manual_verdict=TP, FP = still_detected AND manual_verdict=FP
new_tp = sum(1 for r in results if r['manual_verdict'] == 'TP' and r['still_detected'])
new_fp = sum(1 for r in results if r['manual_verdict'] == 'FP' and r['still_detected'])
fp_fixed = fp_manual - new_fp
tp_lost = sum(1 for r in results if r['manual_verdict'] == 'TP' and not r['still_detected'])

print(f'{"="*60}')
print(f'RE-SCAN RESULTS (with fixed rules)')
print(f'{"="*60}')
print(f'Original: {tp_manual}TP / {fp_manual}FP = {tp_manual}/{tp_manual+fp_manual} ({tp_manual/(tp_manual+fp_manual)*100:.0f}% precision)'  if (tp_manual+fp_manual) > 0 else '')
total_new = new_tp + new_fp
print(f'New:      {new_tp}TP / {new_fp}FP = {new_tp}/{total_new} ({new_tp/total_new*100:.0f}% precision)' if total_new > 0 else '')
print(f'FP fixed: {fp_fixed} — False positives eliminated')
print(f'TP lost:  {tp_lost} — True positives lost (regression)')
print()

# By rule
by_rule = {}
for r in results:
    rid = r['rule_id']
    if rid not in by_rule:
        by_rule[rid] = {'tp_manual': 0, 'fp_manual': 0, 'new_tp': 0, 'new_fp': 0}
    if r['manual_verdict'] == 'TP':
        by_rule[rid]['tp_manual'] += 1
        if r['still_detected']:
            by_rule[rid]['new_tp'] += 1
    else:
        by_rule[rid]['fp_manual'] += 1
        if r['still_detected']:
            by_rule[rid]['new_fp'] += 1

print('BY RULE (precision: before -> after):')
print(f'{"Rule":<30s} {"Before":>8s} {"After":>8s} {"Change":>8s}')
print('-'*60)
for rid, counts in sorted(by_rule.items()):
    total_m = counts['tp_manual'] + counts['fp_manual']
    total_n = counts['new_tp'] + counts['new_fp']
    before = counts['tp_manual']/total_m*100 if total_m > 0 else 0
    after = counts['new_tp']/total_n*100 if total_n > 0 else 0
    change = after - before
    arrow = '+' if change > 0 else ''
    print(f'{rid:<30s} {before:>6.0f}% -> {after:>5.0f}% {arrow}{change:>+6.0f}%')

print()
print('DETAIL:')
for r in results:
    if r['improvement'] != 'GOOD':
        flag = {'FIXED': '+', 'BAD': '!', 'REGRESSION': 'X', 'UNKNOWN': '?'}.get(r['improvement'], '?')
        print(f'  {flag} [{r["num"]:>2d}] {r["rule_id"]:<28s} {r["manual_verdict"]:>2s} -> {"DETECTED" if r["still_detected"] else "GONE":>8s}  {r["improvement"]}')
