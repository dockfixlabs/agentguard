"""Quick benchmark: 3 frameworks with full pipeline."""
import sys, os, time
sys.path.insert(0, '.')

from agentguard.scanner import scan_directory

frameworks = ['camel', 'qwen-agent', 'crewai-audit']

print(f"{'Framework':<22s} {'Files':>5s} {'Raw':>5s} {'Post-FP':>7s} {'C':>4s} {'H':>4s} {'M':>4s} {'FP-Rem':>6s} {'Conf':>5s} {'Invest':>6s}  Time")
print("-" * 100)

for fw in frameworks:
    target = f'../{fw}'
    if not os.path.exists(target):
        print(f"{fw:<22s} NOT FOUND")
        continue

    t0 = time.time()
    result = scan_directory(target, enable_fp_filter=True, enable_classifier=True)
    elapsed = time.time() - t0

    fp = result.__dict__.get('_fp_result')
    cl = result.__dict__.get('_classifier_result')
    fp_removed = fp.removed_count if fp else 0
    confirmed = cl.confirmed if cl else 0
    investigate = cl.investigate if cl else 0
    raw = len(result.findings) + fp_removed
    post = len(result.findings)

    print(f"{fw:<22s} {result.files_scanned:>5d} {raw:>5d} {post:>7d} {result.critical_count:>4d} {result.high_count:>4d} {result.medium_count:>4d} {fp_removed:>6d} {confirmed:>5d} {investigate:>6d}  {elapsed:.1f}s")

print("\nDone.")
