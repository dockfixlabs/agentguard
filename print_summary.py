"""Print complete CI and classification summary."""
import json, os

reports_dir = 'test_output/reports'
frameworks = ['camel', 'qwen-agent', 'langchain', 'crewai', 'autogen', 'llamaindex', 'dify']

print('CI SUMMARY (All 7 Frameworks):')
print('=' * 80)
for fw in frameworks:
    path = os.path.join(reports_dir, f'{fw}_summary.json')
    if os.path.exists(path):
        d = json.load(open(path, 'r', encoding='utf-8'))
        s = d['summary']
        print(fw.ljust(15), '| AgentGuard:', d['files_scanned'], 'files |',
              str(s['critical'])+'C/'+str(s['high'])+'H/'+str(s['medium'])+'M |',
              'score='+str(s['risk_score']),
              '| ['+s['framework_health'][:8]+']')

print()
print('CLASSIFICATION SUMMARY:')
print('=' * 80)
total_conf = 0
total_inv = 0
total_bp = 0
total_lfp = 0
total_fp = 0
for fw in frameworks:
    path = os.path.join(reports_dir, f'{fw}_summary.json')
    if os.path.exists(path):
        d = json.load(open(path, 'r', encoding='utf-8'))
        c = d['classification']
        line = (fw.ljust(15), 'CONFIRMED='+str(c['confirmed']).rjust(4),
                'INVESTIGATE='+str(c['investigate']).rjust(4),
                'BEST_PRACTICE='+str(c['best_practice']).rjust(3),
                'LIKELY_FP='+str(c['likely_fp']).rjust(4),
                'FP-removed='+str(c['fp_removed']).rjust(3))
        print(' '.join(line))
        total_conf += c['confirmed']
        total_inv += c['investigate']
        total_bp += c['best_practice']
        total_lfp += c['likely_fp']
        total_fp += c['fp_removed']

line = ('TOTAL'.ljust(15), 'CONFIRMED='+str(total_conf).rjust(4),
        'INVESTIGATE='+str(total_inv).rjust(4),
        'BEST_PRACTICE='+str(total_bp).rjust(3),
        'LIKELY_FP='+str(total_lfp).rjust(4),
        'FP-removed='+str(total_fp).rjust(3))
print(' '.join(line))

print()
total_actionable = total_conf + total_inv
total_findings = total_conf + total_inv + total_bp + total_lfp
print('Actionable: '+str(total_actionable)+'/'+str(total_findings)+' ('+str(round(total_actionable/total_findings*100, 1))+'%)')
print('Auto FP removed: '+str(total_fp))
print('Noise eliminated: '+str(total_lfp + total_fp)+' (LIKELY_FP + FP-removed)')
