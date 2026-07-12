"""Automated heuristic verdict on 50 findings, then manual override for ambiguous cases."""
import json, os, re

cands_path = r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_review_candidates.json'
base = r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard'

with open(cands_path, 'r') as f:
    cands = json.load(f)

verdicts = []
for c in cands:
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(base, fpath))
    
    line_text = ''
    context_before = ''
    context_after = ''
    filename = ''
    
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as src:
            lines = src.readlines()
            filename = os.path.basename(fpath)
            idx = c['line'] - 1
            line_text = lines[idx].strip() if 0 <= idx < len(lines) else ''
            # Get context
            ctx_start = max(0, idx - 2)
            ctx_end = min(len(lines), idx + 3)
            context_before = '\n'.join(lines[ctx_start:idx]).strip()
            context_after = '\n'.join(lines[idx+1:ctx_end]).strip()
    except:
        pass
    
    rule = c['rule_id']
    desc = c['description']
    fw = c['framework']
    
    verdict = 'TP'  # default
    reason = ''
    
    # ── HEURISTIC RULES ──
    
    # H1: String literal containing matched keyword = FP
    if re.match(r'^\s*[\"\'"]', line_text) and not re.search(r'\bf\s*["\']', line_text):
        # Check if it's just a string assignment or string in a list/dict
        if any(line_text.startswith(x) for x in ['"', "'", '"""', "'''"]):
            verdict = 'FP'
            reason = 'STRING_LITERAL: matched keyword inside a string, not executable code'
    
    # H2: Constant/variable assignment matching rule name = FP
    if re.match(r'^\s*[A-Z_]+_NAME\s*=\s*["\']', line_text):
        verdict = 'FP'
        reason = 'NAME_CONSTANT: variable name definition, not tool exposure'
    
    # H3: Class definition matching rule = FP (matches class name, not usage)
    if re.match(r'^\s*class\s+', line_text):
        verdict = 'FP'
        reason = 'CLASS_DEF: class definition, not instantiation without safety'
    
    # H4: PyTorch .eval() = FP
    if '.eval()' in line_text and ('model' in context_before.lower() or 'from_pretrained' in context_before or 'transformers' in line_text.lower()):
        verdict = 'FP'
        reason = 'PYTORCH_EVAL: model.eval() not Python eval()'
    
    # H5: Comment/docstring line = FP
    if re.match(r'^\s*#', line_text) or re.match(r'^\s*["\']{3}', line_text):
        verdict = 'FP'
        reason = 'COMMENT: finding on comment/docstring line'
    
    # H6: Deprecation warning string = FP
    if 'deprecated' in line_text.lower() or 'DeprecationWarning' in line_text:
        verdict = 'FP'
        reason = 'DEPRECATION: finding on deprecation warning text'
    
    # H7: exec()/eval() of untrusted data in non-test code = TP (confirmed)
    if rule == 'ASI06-UNSAFE-EVAL' and ('exec(' in line_text or 'eval(' in line_text):
        if '.eval()' not in line_text:  # not PyTorch
            # Check if it's benchmark/test code
            if any(x in c['file'].lower() for x in ['benchmark', 'test_', '_test.', 'conftest', 'fixture', 'metric']):
                verdict = 'TP'
                reason = 'REAL_EVAL_BENCHMARK: actual eval()/exec() in benchmark code'
            elif any(x in c['file'].lower() for x in ['example', 'demo', 'sample']):
                verdict = 'TP'
                reason = 'REAL_EVAL_EXAMPLE: actual eval()/exec() in example code'
            else:
                verdict = 'TP'
                reason = 'REAL_EVAL: actual eval()/exec() of potentially untrusted input'
    
    # H8: ASI02 - actual dangerous tool instantiation = TP
    if rule == 'ASI02-TOOL-ABUSE' and ('subprocess' in line_text.lower() or 'os.system' in line_text.lower() or 'shell=True' in line_text.lower() or 'popen' in line_text.lower()):
        verdict = 'TP'
        reason = 'REAL_DANGEROUS_TOOL: actual system-level execution exposed'
    
    # H9: ASI10 - trust boundary violations on actual self-modification = TP
    if rule == 'ASI10-TRUST-BOUNDARY':
        if 'self.' in line_text and ('run' in line_text or 'execute' in line_text or 'eval' in line_text):
            verdict = 'TP'
            reason = 'REAL_SELF_MODIFY: agent self-modification/code execution pattern'
        elif re.match(r'^\s*[\"\'"]', line_text):
            verdict = 'FP'
            reason = 'STRING_LITERAL: trust boundary match in string literal'
    
    # H10: ASI04 - Excessive agency = check if actual dangerous permission
    if rule == 'ASI04-EXCESSIVE-AGENCY' and re.match(r'^\s*[\"\'"]', line_text):
        verdict = 'FP'
        reason = 'STRING_LITERAL: excessive agency match in string'
    
    # H11: ASI01 - Prompt injection in prompt text = ambiguous
    if rule == 'ASI01-PROMPT-INJECTION':
        if re.match(r'^\s*["\']', line_text) and 'f"' not in line_text and "f'" not in line_text:
            verdict = 'FP'
            reason = 'STRING_LITERAL: matched in static string, not dynamic prompt construction'
    
    # H12: ASI07 - check if real credential vs placeholder
    if rule == 'ASI07-CREDENTIAL-LEAK':
        if any(x in line_text.lower() for x in ['example', 'test', 'your-', 'placeholder', 'replace', 'xxx', 'changeme']):
            verdict = 'FP'
            reason = 'PLACEHOLDER: example/test credential, not real secret'
    
    # H13: ASI01-TAINT-TRACK - check if real taint path
    if rule == 'ASI01-TAINT-TRACK':
        if re.match(r'^\s*[\"\'"]', line_text):
            verdict = 'FP'
            reason = 'STRING_LITERAL: taint match in string literal'
    
    # H14: Text in prompt/instruction strings about security tools = FP
    if any(x in line_text.lower() for x in ['use the terminal', 'use terminal', 'execute commands']):
        if re.match(r'^\s*["\']', line_text):
            verdict = 'FP'
            reason = 'PROMPT_TEXT: instruction text about tools, not tool exposure'
    
    # H15: ASI-MOUNT-EXPOSURE on class definition or unrelated line = FP
    if rule == 'ASI-MOUNT-EXPOSURE':
        if re.match(r'^\s*class\s+', line_text):
            verdict = 'FP'
            reason = 'CLASS_DEF: mount exposure matched on class definition'
        elif 'deprecated' in line_text.lower():
            verdict = 'FP'
            reason = 'DEPRECATION: deprecated usage warning'
    
    # H16: ASI05 supply chain - check if real
    if rule == 'ASI05-SUPPLY-CHAIN':
        if re.match(r'^\s*[\"\'"]', line_text) or re.match(r'^\s*#', line_text):
            verdict = 'FP'
            reason = 'STRING_LITERAL_OR_COMMENT: supply chain match in non-code'
    
    # H17: ASI03 data exfil - check context
    if rule == 'ASI03-DATA-EXFIL':
        if re.match(r'^\s*[\"\'"]', line_text) and 'f"' not in line_text:
            verdict = 'FP'
            reason = 'STRING_LITERAL: data exfil match in static string'
    
    if not reason:
        reason = 'AUTO_HEURISTIC: default classification'
    
    verdicts.append({
        'num': len(verdicts) + 1,
        'framework': c['framework'],
        'rule_id': c['rule_id'],
        'confidence': c['confidence'],
        'description': c['description'],
        'file': c['file'],
        'line': c['line'],
        'verdict': verdict,
        'reason': reason,
        'line_text': line_text[:120],
        'filename': filename,
    })

# Print summary
tp = [v for v in verdicts if v['verdict'] == 'TP']
fp = [v for v in verdicts if v['verdict'] == 'FP']
print(f'TOTAL: {len(verdicts)}')
print(f'TRUE POSITIVES: {len(tp)} ({len(tp)/len(verdicts)*100:.0f}%)')
print(f'FALSE POSITIVES: {len(fp)} ({len(fp)/len(verdicts)*100:.0f}%)')
print()

# Print FP breakdown by reason
from collections import Counter
fp_reasons = Counter(v['reason'] for v in fp)
print('FP REASONS:')
for reason, count in fp_reasons.most_common():
    print(f'  {reason}: {count}')

print()
print('TP BREAKDOWN:')
tp_reasons = Counter(v['reason'] for v in tp)
for reason, count in tp_reasons.most_common():
    print(f'  {reason}: {count}')

print()
# By rule
print('BY RULE:')
rule_counts = {}
for v in verdicts:
    rule = v['rule_id']
    if rule not in rule_counts:
        rule_counts[rule] = {'TP': 0, 'FP': 0}
    rule_counts[rule][v['verdict']] += 1

for rule, counts in sorted(rule_counts.items()):
    total = counts['TP'] + counts['FP']
    prec = counts['TP'] / total * 100 if total > 0 else 0
    print(f'  {rule}: {counts["TP"]}TP/{counts["FP"]}FP = {prec:.0f}% precision')

# Save detailed report
with open(r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_verdicts.json', 'w') as f:
    json.dump(verdicts, f, indent=2, ensure_ascii=False)

# Print all FPs for review
print(f'\n{"="*60}')
print('ALL FALSE POSITIVES (for manual spot-check):')
print(f'{"="*60}')
for v in fp:
    print(f"\n{v['num']}. [{v['framework']}] {v['rule_id']} | {v['filename']}:{v['line']}")
    print(f"   Line: {v['line_text'][:100]}")
    print(f"   Desc: {v['description'][:120]}")
    print(f"   Why FP: {v['reason']}")

print(f'\n{"="*60}')
print('ALL TRUE POSITIVES:')
print(f'{"="*60}')
for v in tp:
    print(f"\n{v['num']}. [{v['framework']}] {v['rule_id']} | {v['filename']}:{v['line']}")
    print(f"   Line: {v['line_text'][:100]}")
    print(f"   Desc: {v['description'][:120]}")
    print(f"   Why TP: {v['reason']}")
