"""Final verdict: manually review each of 50 findings and record TP/FP."""
import json, os

cands_path = r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_review_candidates.json'
base_dir = r'C:\Users\PC\.openclaw-autoclaw\workspace'

with open(cands_path, 'r') as f:
    cands = json.load(f)

# Read full context for each finding (wider window)
full_contexts = []
for c in cands:
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(
            r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard', fpath))
    
    ctx = []
    filename = ''
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as src:
            lines = src.readlines()
            filename = os.path.basename(fpath)
            start = max(0, c['line'] - 5)
            end = min(len(lines), c['line'] + 5)
            for j in range(start, end):
                ctx.append((j + 1, j + 1 == c['line'], lines[j].rstrip()))
    except:
        ctx = [(0, True, f'FILE NOT READABLE: {fpath}')]
    
    full_contexts.append({
        'num': len(full_contexts) + 1,
        'framework': c['framework'],
        'rule': c['rule_id'],
        'conf': c['confidence'],
        'desc': c['description'],
        'file_line': f'{filename}:{c["line"]}',
        'full_path': c['file'],
        'ctx': ctx
    })

# Now print ALL 50 with wider context, ready for verdict
for fc in full_contexts:
    print(f"\n{'='*70}")
    print(f"[{fc['num']}/50] {fc['framework'].upper()} | {fc['rule']} | conf={fc['conf']:.0%}")
    print(f"File: {fc['file_line']}")
    print(f"Desc: {fc['desc'][:160]}")
    print(f"---")
    for line_num, is_target, text in fc['ctx']:
        marker = '>>>' if is_target else '   '
        print(f"{marker} {line_num:>4d}: {text[:150]}")
    print(f"{'='*70}")
    print(f"VERDICT: ________")
