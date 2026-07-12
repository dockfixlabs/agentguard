"""Extract 50 NEW findings for independent validation — completely disjoint from first sample."""
import json, os, sys
sys.path.insert(0, '.')

reports_dir = 'test_output/reports'
frameworks = ['camel', 'qwen-agent', 'langchain', 'crewai', 'autogen', 'llamaindex', 'dify']

# Load first sample to exclude
with open('test_output/manual_review_candidates.json', 'r') as f:
    first_sample = json.load(f)
first_sample_keys = set()
for c in first_sample:
    first_sample_keys.add((c['file'], c['line'], c['rule_id']))

# Collect all CONFIRMED findings from all frameworks
all_confirmed = []
for fw in frameworks:
    path = os.path.join(reports_dir, f'{fw}_summary.json')
    if not os.path.exists(path):
        continue
    d = json.load(open(path, 'r', encoding='utf-8'))
    for f in d.get('critical_findings', []):
        if '[CONFIRMED]' in f.get('description', ''):
            key = (f['file'], f['line'], f['rule_id'])
            if key not in first_sample_keys:
                all_confirmed.append({
                    'framework': fw,
                    'rule': f['rule'],
                    'rule_id': f['rule_id'],
                    'file': f['file'],
                    'line': f['line'],
                    'confidence': f['confidence'],
                    'description': f['description'].replace('[CONFIRMED] ', ''),
                    'recommendation': f.get('recommendation', ''),
                })

print(f"Total CONFIRMED findings excluding first sample: {len(all_confirmed)}")

# Diversify: max 8 per framework, max 6 per rule
from collections import Counter
fw_counts = Counter()
rule_counts = Counter()
selected = []

# Shuffle for randomness — use hash of file+line for deterministic but varied selection
import hashlib
def sort_key(c):
    h = hashlib.md5(f"{c['file']}{c['line']}".encode()).hexdigest()
    # Sort by rule diversity first (pick from rules we haven't filled), then hash
    rule_count = rule_counts.get(c['rule_id'], 0)
    return (rule_count, h)

all_confirmed.sort(key=sort_key)

for c in all_confirmed:
    fw = c['framework']
    rule = c['rule_id']
    
    if fw_counts.get(fw, 0) >= 8:
        continue
    if rule_counts.get(rule, 0) >= 6:
        continue
    
    selected.append(c)
    fw_counts[fw] += 1
    rule_counts[rule] += 1
    
    if len(selected) >= 50:
        break

# Save
with open('test_output/independent_sample.json', 'w', encoding='utf-8') as f:
    json.dump(selected, f, indent=2)

print(f"\nSelected {len(selected)} NEW findings for independent validation")
print(f"\nFramework distribution:")
for fw, cnt in sorted(fw_counts.items()):
    print(f"  {fw}: {cnt}")
print(f"\nRule distribution:")
for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
    print(f"  {rule}: {cnt}")

# Verify NO overlap with first sample
overlap = 0
for s in selected:
    key = (s['file'], s['line'], s['rule_id'])
    if key in first_sample_keys:
        overlap += 1
print(f"\nOverlap with first sample: {overlap} (must be 0)")
