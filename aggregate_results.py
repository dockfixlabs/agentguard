"""Aggregate results from all framework reports."""
import json, os

reports_dir = 'test_output/reports'
frameworks = ['camel', 'qwen-agent', 'langchain', 'crewai', 'autogen', 'llamaindex', 'dify']

print(f"{'Framework':<15s} {'Files':>5s} {'Raw':>6s} {'Post':>6s} {'C':>5s} {'H':>5s} {'M':>5s} {'FP-Rem':>6s} {'Conf':>5s} {'Inv':>5s} {'BP':>5s} {'LFP':>5s}  {'Score':>6s}  Health")
print("-" * 140)

totals = {'files': 0, 'raw': 0, 'post': 0, 'C': 0, 'H': 0, 'M': 0,
          'fp_rem': 0, 'conf': 0, 'inv': 0, 'bp': 0, 'lfp': 0, 'score': 0}

for fw in frameworks:
    path = os.path.join(reports_dir, f'{fw}_summary.json')
    if not os.path.exists(path):
        print(f"{fw:<15s} not found")
        continue

    d = json.load(open(path, 'r', encoding='utf-8'))
    s = d['summary']
    c = d['classification']

    files = d['files_scanned']
    post = s['total']
    raw = post + c['fp_removed']
    crit = s['critical']
    high = s['high']
    med = s['medium']
    fp_rem = c['fp_removed']
    conf = c['confirmed']
    inv = c['investigate']
    bp = c['best_practice']
    lfp = c['likely_fp']
    score = s['risk_score']
    health = s['framework_health']

    totals['files'] += files
    totals['raw'] += raw
    totals['post'] += post
    totals['C'] += crit
    totals['H'] += high
    totals['M'] += med
    totals['fp_rem'] += fp_rem
    totals['conf'] += conf
    totals['inv'] += inv
    totals['bp'] += bp
    totals['lfp'] += lfp
    totals['score'] += score

    print(f"{fw:<15s} {files:>5d} {raw:>6d} {post:>6d} {crit:>5d} {high:>5d} {med:>5d} {fp_rem:>6d} {conf:>5d} {inv:>5d} {bp:>5d} {lfp:>5d}  {score:>6d}  {health}")

print("-" * 140)
t = totals
print(f"{'TOTAL':<15s} {t['files']:>5d} {t['raw']:>6d} {t['post']:>6d} {t['C']:>5d} {t['H']:>5d} {t['M']:>5d} {t['fp_rem']:>6d} {t['conf']:>5d} {t['inv']:>5d} {t['bp']:>5d} {t['lfp']:>5d}  {t['score']:>6d}")

print(f"\nFP Filtering: {t['fp_rem']} false positives auto-removed ({t['fp_rem']/max(t['raw'],1)*100:.1f}% of raw)")
print(f"Actionable: {t['conf']} confirmed + {t['inv']} investigate = {t['conf']+t['inv']} ({ (t['conf']+t['inv'])/max(t['post'],1)*100:.1f}% of post-FP)")
print(f"Noise reduction: {t['lfp']} likely FP + {t['fp_rem']} removed = {t['lfp']+t['fp_rem']} noise eliminated")
