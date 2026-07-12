"""FINAL CORRECTED VERDICTS after manual review of all 50 findings.
Each verdict with specific reason based on actual source code inspection.
"""
import json, os

# Manual corrected verdicts for ALL 50 findings
# Format: (finding_num, corrected_verdict, reason)
CORRECTIONS = {
    # AUTO-HEURISTIC TPs that are actually FP:
    7: ('FP', 'PROMPT_STRING: "Your code will be executed using eval()" is text in a system prompt, not executable eval'),
    8: ('FP', 'PYTORCH_EVAL: .eval() is PyTorch model evaluation method, not Python eval()'),
    17: ('FP', 'TOOL_RETRIEVAL: getting tool named "shell_exec" from list — not executing shell'),
    18: ('FP', 'TOOL_RETRIEVAL: generator expression filtering tools by name — not executing'),
    19: ('FP', 'DOCSTRING: "whereas the explicit os.chmod() used here is not" is documentation text'),
    23: ('FP', 'SECURING: directory.chmod(0o700) sets restrictive permissions — securing, not escalating'),
    24: ('FP', 'SECURING: os.chmod(tmp, 0o600) sets restrictive temp file permissions'),
    25: ('FP', 'FUNC_DEF: def create_writer_agent() is function definition, not self-modification'),
    26: ('FP', 'EVENT_HANDLER: def log_task_updated() is event callback, not self-modification'),
    27: ('FP', 'FILE_WRITE: f.write(markdown) is generic file output, not agent self-modification'),
    29: ('FP', 'AGENT_INSTANTIATION: writing_agent = WriteFromScratch() is creating an agent, not modifying one'),
    31: ('FP', 'SANITIZATION: _sanitize_messages() is actually sanitizing input — defense, not vulnerability'),
    32: ('FP', 'DEEPCOPY: deepcopy(list(request.messages)) is creating a copy for editing, not injection'),
    35: ('FP', 'VAR_ASSIGN: ag_ui_messages = ev.input_data.messages is variable assignment from event data'),
    37: ('FP', 'TRUNCATED: private_key_pem="-----BEGIN PRIVATE KEY-----..." has ... indicating truncated placeholder'),
    40: ('FP', 'PLACEHOLDER: aoai_api_key = "YOUR_AZURE_OPENAI_API_KEY" is clearly placeholder text'),
    41: ('FP', 'PLACEHOLDER: aoai_api_key = "YOUR_AZURE_OPENAI_API_KEY" is placeholder'),
    43: ('FP', 'BUILTIN_FETCH: fetch_recommended_apps_from_builtin() fetches from built-in not network'),
    46: ('FP', 'ARRAY_DECL: messages = [ is array declaration, too generic for taint tracking'),
    47: ('FP', 'I18N: I18N_DEFAULT.retrieve() is translation lookup not user input'),
    48: ('FP', 'TYPE_CAST: cast(str, content) is type annotation, not prompt construction'),
    49: ('FP', 'ARRAY_DECL: messages = [ is array declaration'),
    50: ('FP', 'NORMAL_API: headers = {"x-api-key": api_key} is standard API header, not exfiltration'),
    
    # Keep as TP (confirmed):
    2: ('TP', 'REAL_MOUNT: DockerCommandLineCodeExecutor(work_dir=os.getcwd()) — host mount without read_only (same vuln as AutoGen#7917)'),
    3: ('TP', 'REAL_MOUNT: DockerCommandLineCodeExecutor() — no read_only or safety flags'),
    4: ('TP', 'REAL_MOUNT: DockerCommandLineCodeExecutor() — duplicate pattern'),
    5: ('TP', 'REAL_MOUNT: DockerCommandLineCodeExecutor(work_dir="coding") — work_dir exposed without read_only'),
    9: ('TP', 'REAL_EVAL: eval(last_digit) on benchmark answer — though low impact in test context'),
    10: ('TP', 'REAL_EXEC: exec(code_piece, vars) — agent code executor with LLM-generated code'),
    11: ('TP', 'REAL_EXEC: exec(text, locals()) — code execution in benchmark harness'),
    12: ('TP', 'REAL_EVAL: eval(expr, vars) — agent eval with LLM expressions'),
    20: ('TP', 'CHMOD: dir_path.chmod() on tool-accessible directory'),
    21: ('TP', 'CHMOD: full_path.chmod() on tool-accessible file'),
    22: ('TP', 'CHMOD: os.chmod(path, mode) in agent tool code'),
    30: ('TP', 'MONKEY_PATCH: def monkey_patch_mcp_create_platform_compatible_process — real runtime self-modification'),
    33: ('TP', 'PROMPT_CONCAT: [system_message] + chat_history + [user_message] — user msg in prompt without sanitization'),
    34: ('TP', 'PROMPT_CONCAT: same pattern as #33'),
    36: ('TP', 'PROMPT_FUNC: _prompt_messages_from_query(user_query) — user query becomes prompt'),
    42: ('TP', 'REAL_KEY: api_key="a0f8a6ba-c32f-4407-af0c-169f1915490c" — looks like real UUID API key'),
    44: ('TP', 'FSTRING_PROMPT: prompt = f""" — f-string prompt construction with variables'),
    45: ('TP', 'BUILD_MESSAGES: messages = self._build_observation_messages() — observation data into LLM messages'),
}

# Apply corrections
final_tp = 0
final_fp = 0
by_rule = {}

for num in range(1, 51):
    if num in CORRECTIONS:
        verdict, reason = CORRECTIONS[num]
        if verdict == 'TP':
            final_tp += 1
        else:
            final_fp += 1
    else:
        # From original auto-verdict (already correct FPs: 1,6,13,14,15,16,28,38,39)
        # These were correctly identified as FP by the heuristic
        final_fp += 1

# But wait - we also have 9 auto-detected FPs from the first run
# Let me be more careful. Let me use the original verdicts and apply corrections.
import json as j

with open(r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_verdicts.json') as f:
    orig = j.load(f)

# Apply all corrections
for v in orig:
    num = v['num']
    if num in CORRECTIONS:
        v['verdict'], v['reason'] = CORRECTIONS[num]
    # Also fix the ASI06 eval() cases that were already handled
    
    rule = v['rule_id']
    if rule not in by_rule:
        by_rule[rule] = {'TP':0, 'FP':0, 'total':0}
    by_rule[rule][v['verdict']] += 1
    by_rule[rule]['total'] += 1

tp_count = sum(1 for v in orig if v['verdict'] == 'TP')
fp_count = sum(1 for v in orig if v['verdict'] == 'FP')

print(f'{"="*60}')
print(f'FINAL MANUAL VERIFICATION RESULTS')
print(f'{"="*60}')
print(f'Total reviewed: {len(orig)}')
print(f'TRUE POSITIVES: {tp_count} ({tp_count/len(orig)*100:.0f}%)')
print(f'FALSE POSITIVES: {fp_count} ({fp_count/len(orig)*100:.0f}%)')
print()

print('BY RULE (precision):')
print(f'{"Rule":<30s} {"TP":>3s} {"FP":>3s} {"Precision":>9s}')
print('-'*50)
for rule, counts in sorted(by_rule.items()):
    prec = counts['TP']/counts['total']*100 if counts['total'] > 0 else 0
    bar = '#'*int(prec/10) + '.'*(10-int(prec/10))
    print(f'{rule:<30s} {counts["TP"]:>3d} {counts["FP"]:>3d} {prec:>6.0f}% {bar}')

# Save corrected
with open(r'C:\Users\PC\.openclaw-autoclaw\workspace\agentguard\test_output\manual_verdicts_final.json', 'w') as f:
    j.dump(orig, f, indent=2, ensure_ascii=False)

print()
print('FP BREAKDOWN by reason:')
from collections import Counter
reasons = Counter(v['reason'] for v in orig if v['verdict'] == 'FP')
for reason, cnt in reasons.most_common(15):
    short = reason[:80]
    print(f'  {cnt:>2d}x {short}')
