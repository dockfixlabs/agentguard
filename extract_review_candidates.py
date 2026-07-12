"""Extract top 50 CONFIRMED findings from all 7 frameworks for manual review."""
import json, os, sys
sys.path.insert(0, '.')

reports_dir = 'test_output/reports'
frameworks = ['camel', 'qwen-agent', 'langchain', 'crewai', 'autogen', 'llamaindex', 'dify']

# RULE NOISE: lower = more precise, pick more from these
LOW_NOISE_RULES = {
    'ASI02-TOOL-ABUSE': 0.35,
    'ASI06-UNSAFE-EVAL': 0.3,
    'ASI10-TRUST-BOUNDARY': 0.35,
    'ASI04-EXCESSIVE-AGENCY': 0.35,
    'ASI01-PROMPT-INJECTION': 0.45,
    'ASI07-CREDENTIAL-LEAK': 0.5,
    'ASI-STEGANO-INJECT': 0.15,
    'ASI-MOUNT-EXPOSURE': 0.2,
}

candidates = []

for fw in frameworks:
    path = os.path.join(reports_dir, f'{fw}_summary.json')
    if not os.path.exists(path):
        continue
    
    d = json.load(open(path, 'r', encoding='utf-8'))
    
    # Find all CONFIRMED findings
    for f in d.get('critical_findings', []):
        if '[CONFIRMED]' in f.get('description', ''):
            candidates.append({
                'framework': fw,
                'rule': f['rule'],
                'rule_id': f['rule_id'],
                'file': f['file'],
                'line': f['line'],
                'confidence': f['confidence'],
                'description': f['description'].replace('[CONFIRMED] ', ''),
                'recommendation': f.get('recommendation', ''),
            })

# Sort by: (low noise rule first, then high confidence)
def sort_key(c):
    rule = c['rule_id']
    noise = 1.0
    for prefix, n in LOW_NOISE_RULES.items():
        if rule.startswith(prefix):
            noise = n
            break
    return (noise, -c['confidence'])

candidates.sort(key=sort_key)

# Select top 50, ensuring diversity across frameworks and rules
selected = []
fw_counts = {}
rule_counts = {}

for c in candidates:
    fw = c['framework']
    rule = c['rule_id']
    
    # Max 10 per framework, max 8 per rule
    if fw_counts.get(fw, 0) >= 8:
        continue
    if rule_counts.get(rule, 0) >= 6:
        continue
    
    selected.append(c)
    fw_counts[fw] = fw_counts.get(fw, 0) + 1
    rule_counts[rule] = rule_counts.get(rule, 0) + 1
    
    if len(selected) >= 50:
        break

# Save to JSON for review
os.makedirs('test_output', exist_ok=True)
with open('test_output/manual_review_candidates.json', 'w', encoding='utf-8') as f:
    json.dump(selected, f, indent=2)

print(f"Selected {len(selected)} findings for manual review")
print(f"\nFramework distribution:")
for fw, cnt in sorted(fw_counts.items()):
    print(f"  {fw}: {cnt}")

print(f"\nRule distribution:")
for rule, cnt in sorted(rule_counts.items(), key=lambda x: -x[1]):
    print(f"  {rule}: {cnt}")

# Print the first 10 for quick inspection
print("\n=== FIRST 10 CANDIDATES ===")
for i, c in enumerate(selected[:10]):
    print(f"\n{i+1}. [{c['framework']}] {c['rule_id']} (conf={c['confidence']:.0%})")
    print(f"   File: {c['file']}:{c['line']}")
    print(f"   Desc: {c['description'][:120]}")
