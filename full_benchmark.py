"""Full pipeline scan: all 7 frameworks -> auto reports."""
import sys, os, time, json
sys.path.insert(0, '.')

from agentguard.scanner import scan_directory
from agentguard.auto_reporter import compute_stats, generate_markdown_report, generate_json_summary, generate_ci_summary

frameworks = [
    ('camel', '../camel'),
    ('qwen-agent', '../qwen-agent'),
    ('langchain', '../langchain-audit'),
    ('crewai', '../crewai-audit'),
    ('autogen', '../autogen-audit'),
    ('llamaindex', '../llama-index-audit'),
    ('dify', '../dify-audit'),
]

os.makedirs('test_output', exist_ok=True)
os.makedirs('test_output/reports', exist_ok=True)

summary_rows = []

for name, target in frameworks:
    if not os.path.exists(target):
        print(f"{name}: SKIP (not found)")
        continue

    t0 = time.time()
    result = scan_directory(target, enable_fp_filter=True, enable_classifier=True)
    elapsed = time.time() - t0

    fp = result.__dict__.get('_fp_result')
    cl = result.__dict__.get('_classifier_result')
    fp_removed = fp.removed_count if fp else 0
    fp_downgraded = fp.downgraded_count if fp else 0
    confirmed = cl.confirmed if cl else 0
    investigate = cl.investigate if cl else 0
    best_practice = cl.best_practice if cl else 0
    likely_fp = cl.likely_fp if cl else 0

    raw = len(result.findings) + fp_removed
    post = len(result.findings)

    stats = compute_stats(result,
        fp_removed=fp_removed,
        fp_downgraded=fp_downgraded,
        confirmed=confirmed,
        investigate=investigate,
        best_practice=best_practice,
        likely_fp=likely_fp)

    # Generate reports
    report = generate_markdown_report(result, stats)
    with open(f'test_output/reports/{name}_report.md', 'w', encoding='utf-8') as f:
        f.write(report)

    summary = generate_json_summary(result, stats)
    with open(f'test_output/reports/{name}_summary.json', 'w', encoding='utf-8') as f:
        f.write(summary)

    ci = generate_ci_summary(stats)

    summary_rows.append({
        'framework': name,
        'files': result.files_scanned,
        'raw': raw,
        'post_fp': post,
        'critical': result.critical_count,
        'high': result.high_count,
        'medium': result.medium_count,
        'fp_removed': fp_removed,
        'confirmed': confirmed,
        'investigate': investigate,
        'best_practice': best_practice,
        'likely_fp': likely_fp,
        'risk_score': stats.risk_score,
        'time': round(elapsed, 1),
        'ci': ci,
    })

    print(f"{name:<15s} files={result.files_scanned:>5d} raw={raw:>5d} post={post:>5d} "
          f"C={result.critical_count:>3d} H={result.high_count:>3d} M={result.medium_count:>3d} "
          f"FP-rem={fp_removed:>3d} conf={confirmed:>3d} inv={investigate:>3d} "
          f"score={stats.risk_score:>5d} t={elapsed:.1f}s")

# Write aggregate summary
with open('test_output/reports/_all_summary.json', 'w', encoding='utf-8') as f:
    json.dump(summary_rows, f, indent=2)

print(f"\nAll reports in test_output/reports/")
print(f"Frameworks scanned: {len(summary_rows)}")
total_raw = sum(r['raw'] for r in summary_rows)
total_post = sum(r['post_fp'] for r in summary_rows)
total_fp = sum(r['fp_removed'] for r in summary_rows)
total_conf = sum(r['confirmed'] for r in summary_rows)
total_inv = sum(r['investigate'] for r in summary_rows)
print(f"Total raw findings: {total_raw}")
print(f"Total post-FP: {total_post} ({total_fp} FP removed)")
print(f"Total confirmed: {total_conf}")
print(f"Total investigate: {total_inv}")
print(f"Actionable: {total_conf + total_inv} ({(total_conf+total_inv)/max(total_post,1)*100:.0f}%)")
