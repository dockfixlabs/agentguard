"""Manual verification: read source files at reported lines, output for judgment."""
import json, os

cands_path = r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_review_candidates.json'
base_dir = r'C:\Users\PC\.openclaw-autoclaw\workspace'

with open(cands_path, 'r') as f:
    cands = json.load(f)

output = []
for idx, c in enumerate(cands):
    entry = {
        'num': idx + 1,
        'framework': c['framework'],
        'rule_id': c['rule_id'],
        'confidence': c['confidence'],
        'description': c['description'],
        'file': c['file'],
        'line': c['line'],
    }
    
    # Resolve path
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(
            r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard', fpath))
    
    if os.path.exists(fpath):
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as src:
                lines = src.readlines()
                start = max(0, c['line'] - 3)
                end = min(len(lines), c['line'] + 2)
                entry['context'] = []
                for j in range(start, end):
                    entry['context'].append({
                        'num': j + 1,
                        'is_target': j + 1 == c['line'],
                        'text': lines[j].rstrip()
                    })
                entry['file_found'] = True
                entry['file_basename'] = os.path.basename(fpath)
        except Exception as e:
            entry['file_found'] = False
            entry['error'] = str(e)
    else:
        entry['file_found'] = False
        entry['error'] = f'File not found: {fpath}'
    
    output.append(entry)

# Write structured review file
review_path = r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_review_data.json'
with open(review_path, 'w', encoding='utf-8') as f:
    json.dump(output, f, indent=2, ensure_ascii=False)

print(f'Wrote {len(output)} entries to manual_review_data.json')

# Also print first 15 for immediate review
for entry in output[:15]:
    print(f"\n{'='*70}")
    print(f"[{entry['num']}/50] {entry['framework'].upper()} | {entry['rule_id']} | conf={entry['confidence']:.0%}")
    print(f"File: {entry.get('file_basename', entry['file'])}:{entry['line']}")
    print(f"Desc: {entry['description'][:150]}")
    if entry['file_found'] and 'context' in entry:
        for ctx in entry['context']:
            marker = '>>>' if ctx['is_target'] else '   '
            print(f"{marker} {ctx['num']}: {ctx['text'][:120]}")
    else:
        print(f"ERROR: {entry.get('error', 'unknown')}")
    print(f"VERDICT: ________ (TP=real vuln / FP=false positive)")
