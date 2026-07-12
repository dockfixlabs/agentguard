"""Test CLI integration with new flags."""
import sys
sys.path.insert(0, '.')
from agentguard.scanner import scan_directory
from agentguard.reporter import print_report, _make_console
from agentguard.false_positive_filter import describe_filters
from agentguard.classifier import describe_classification
from agentguard.auto_reporter import compute_stats, generate_markdown_report, generate_ci_summary

# Test 1: CI mode
print("=" * 60)
print("TEST 1: CI mode (concise one-liner)")
print("=" * 60)
result = scan_directory('../camel', enable_fp_filter=True, enable_classifier=True)
fp = result.__dict__.get('_fp_result')
cl = result.__dict__.get('_classifier_result')
stats = compute_stats(result,
    fp_removed=fp.removed_count if fp else 0,
    fp_downgraded=fp.downgraded_count if fp else 0,
    confirmed=cl.confirmed if cl else 0,
    investigate=cl.investigate if cl else 0,
    best_practice=cl.best_practice if cl else 0,
    likely_fp=cl.likely_fp if cl else 0)
print(generate_ci_summary(stats))

# Test 2: Auto report generation
print()
print("=" * 60)
print("TEST 2: Auto Markdown report")
print("=" * 60)
report = generate_markdown_report(result, stats)
with open('test_output/camel_auto_report.md', 'w', encoding='utf-8') as f:
    f.write(report)
import os
size = os.path.getsize('test_output/camel_auto_report.md')
print(f"Report size: {size} bytes")

# Test 3: Full pipeline with no FP filter
print()
print("=" * 60)
print("TEST 3: Raw scan (no FP filter, no classifier)")
print("=" * 60)
result_raw = scan_directory('../qwen-agent', enable_fp_filter=False, enable_classifier=False)
print(f"Raw findings: {len(result_raw.findings)} (C:{result_raw.critical_count} H:{result_raw.high_count} M:{result_raw.medium_count})")
result_filtered = scan_directory('../qwen-agent', enable_fp_filter=True, enable_classifier=True)
print(f"Filtered: {len(result_filtered.findings)} ({len(result_raw.findings) - len(result_filtered.findings)} removed)")

# Test 4: Auto report with explicit path
print()
print("=" * 60)
print("TEST 4: Generate report to explicit path")
print("=" * 60)
result_qw = scan_directory('../qwen-agent', enable_fp_filter=True, enable_classifier=True)
fp_qw = result_qw.__dict__.get('_fp_result')
cl_qw = result_qw.__dict__.get('_classifier_result')
stats_qw = compute_stats(result_qw,
    fp_removed=fp_qw.removed_count if fp_qw else 0,
    fp_downgraded=fp_qw.downgraded_count if fp_qw else 0,
    confirmed=cl_qw.confirmed if cl_qw else 0,
    investigate=cl_qw.investigate if cl_qw else 0,
    best_practice=cl_qw.best_practice if cl_qw else 0,
    likely_fp=cl_qw.likely_fp if cl_qw else 0)
report = generate_markdown_report(result_qw, stats_qw)
os.makedirs('test_output', exist_ok=True)
with open('test_output/report_qwen_agent.md', 'w', encoding='utf-8') as f:
    f.write(report)
print(f"Report: test_output/report_qwen_agent.md ({os.path.getsize('test_output/report_qwen_agent.md')} bytes)")

# JSON summary
import json
from agentguard.auto_reporter import generate_json_summary
summary = generate_json_summary(result_qw, stats_qw)
with open('test_output/qwen_agent_summary.json', 'w', encoding='utf-8') as f:
    f.write(summary)
print(f"JSON: test_output/qwen_agent_summary.json ({os.path.getsize('test_output/qwen_agent_summary.json')} bytes)")

print()
print("=" * 60)
print("ALL TESTS PASSED")
print("=" * 60)
