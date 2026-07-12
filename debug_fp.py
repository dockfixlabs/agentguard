import json, os, re, sys
sys.path.insert(0, '.')

with open('test_output/manual_review_candidates.json', 'r') as f:
    cands = json.load(f)

print("=== Checking remaining FPs (#38-41 ASI07, #46-49 ASI01-TAINT, #50 ASI03, #19 ASI04) ===\n")

for num in [19, 38, 39, 40, 41, 46, 47, 48, 49, 50]:
    c = cands[num-1]
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            line = lines[c['line']-1].strip() if 0 <= c['line']-1 < len(lines) else 'N/A'
    except:
        line = 'FILE NOT FOUND'
    
    print(f"#{num} [{c['framework']}] {c['rule_id']}")
    print(f"  Line: {line[:150]}")
    
    # Check against FP filter patterns
    from agentguard.false_positive_filter import RULE_FP_PATTERNS
    patterns = RULE_FP_PATTERNS.get(c['rule_id'], [])
    matched = False
    for pat, reason in patterns:
        if pat.search(line) or pat.search(c['file']):
            print(f"  FP FILTER MATCH: {reason}")
            matched = True
    if not matched:
        print(f"  NO FP FILTER MATCH — pattern gap detected")
    
    # For ASI07 specifically
    if c['rule_id'] == 'ASI07-CREDENTIAL-LEAK':
        m = re.search(r'["\']([^"\']+)["\']\s*$', line)
        if m:
            val = m.group(1)
            print(f"  Extracted value: '{val}'")
            # Check placeholder
            ph = re.compile(r'^(?:your[-_]|example|test|demo|sample|placeholder|changeme|xxx|replace[-_]me|todo|fill[-_]in|<your)', re.I)
            if ph.search(val):
                print(f"  IS PLACEHOLDER — should be filtered!")
            # Check masked real
            mr = re.compile(r'\*{2,}\s*["\']?\s*(?:sk-|pk-|[a-zA-Z0-9_-]{20,})')
            if mr.search(val) or mr.search(line):
                print(f"  IS MASKED REAL — should pass through")
    
    print()

print("Now checking what the actual FP filter does on these snippets:\n")
from agentguard.false_positive_filter import apply_fp_filters, describe_filters
from agentguard.models import Finding, Severity

for num in [19, 38, 39, 40, 41, 46, 47, 48, 49, 50]:
    c = cands[num-1]
    fpath = c['file']
    if fpath.startswith('..'):
        fpath = os.path.normpath(os.path.join(os.getcwd(), fpath))
    
    try:
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            snippet = lines[c['line']-1].strip()[:200] if 0 <= c['line']-1 < len(lines) else ''
    except:
        snippet = ''
    
    finding = Finding(
        rule_id=c['rule_id'],
        rule_name='Test',
        severity=Severity.CRITICAL,
        file=c['file'],
        line=c['line'],
        snippet=snippet,
        description='Test',
        recommendation='Test',
        confidence=c['confidence'],
    )
    
    filtered, result = apply_fp_filters([finding])
    survived = len(filtered) > 0
    print(f"#{num} {c['rule_id']}: snippet='{snippet[:60]}...' -> {'STAYS' if survived else 'FILTERED'}")
    if not survived:
        print(f"  (this FP should be gone — but rescan says it's detected)")
