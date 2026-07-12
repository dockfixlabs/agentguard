"""Core scanner engine -- orchestrates rules across files."""

from __future__ import annotations

import time
from pathlib import Path

from agentguard.models import ScanResult, Finding
from agentguard.rules import ALL_RULES
from agentguard.false_positive_filter import apply_fp_filters, FilterResult
from agentguard.classifier import classify_findings, ClassifierResult

# File extensions to scan
SCANABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".rb", ".go", ".rs", ".java", ".kt", ".swift",
    ".yaml", ".yml", ".json", ".toml",
    ".sh", ".bash", ".zsh",
}

# Special filenames to scan (files without standard extensions)
SCANABLE_FILENAMES = {
    "dockerfile",  # Dockerfile, dockerfile
}

# Directories to always skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    ".tox", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", "vendor", ".cargo", "target",
}

# Files to always skip (lock files, binary, generated)
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "Gemfile.lock",
    "Cargo.lock", "composer.lock", "mix.lock",
    ".DS_Store", "Thumbs.db",
}

# Directories that contain intentional test vulnerabilities
# Skipped by default, can be included with --include-tests
TEST_DIRS = {
    "tests", "test", "__tests__", "spec", "specs",
    "samples", "benchmarks", "fixtures",
}

# File prefixes for test/fixture files
TEST_PREFIXES = ("test_", "conftest", "fixture", "mock_", "sample_")


def should_scan(path: Path, include_tests: bool = False) -> bool:
    """Check if a file should be scanned."""
    suffix = path.suffix.lower()
    name = path.name.lower()

    # Skip known lock/generated files
    if name in SKIP_FILES:
        return False

    # Check standard extensions
    if suffix not in SCANABLE_EXTENSIONS:
        # Check special filenames (Dockerfile, etc.)
        if name not in SCANABLE_FILENAMES and not name.startswith("dockerfile."):
            return False

    parts_lower = [p.lower() for p in path.parts]

    # Always skip these directories
    for skip_dir in SKIP_DIRS:
        if skip_dir in parts_lower:
            return False

    # Skip test directories unless include_tests is True
    if not include_tests:
        for test_dir in TEST_DIRS:
            if test_dir in parts_lower:
                return False
        # Skip test files by name prefix
        if path.name.lower().startswith(TEST_PREFIXES):
            return False

    return True


def scan_file(file_path: Path | str) -> list[Finding]:
    """Scan a single file with all rules."""
    findings: list[Finding] = []

    file_path = Path(file_path)

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    file_str = str(file_path)

    for rule in ALL_RULES:
        try:
            findings.extend(rule.scan_content(content, file_str))
        except Exception:
            continue

    return findings


def scan_directory(
    target: str | Path,
    include_tests: bool = False,
    enable_fp_filter: bool = True,
    enable_classifier: bool = True,
) -> ScanResult:
    """Scan an entire directory for AI agent security vulnerabilities.

    Args:
        target: Directory or file to scan.
        include_tests: If True, include test files and directories.
                       Defaults to False (test files skipped).
        enable_fp_filter: If True, apply automatic false positive filtering.
                          Defaults to True.
        enable_classifier: If True, classify findings into CONFIRMED/INVESTIGATE/etc.
                           Defaults to True.
    """
    target_path = Path(target)
    start_time = time.time()

    if not target_path.exists():
        return ScanResult(
            target=str(target),
            files_scanned=0,
            findings=[],
            scan_duration_ms=0,
        )

    files_to_scan: list[Path] = []

    if target_path.is_file():
        # Single file: always scan regardless of test status
        suffix = target_path.suffix.lower()
        name = target_path.name.lower()
        if suffix in SCANABLE_EXTENSIONS or name in SCANABLE_FILENAMES or name.startswith("dockerfile."):
            files_to_scan = [target_path]
    else:
        for path in target_path.rglob("*"):
            if path.is_file() and should_scan(path, include_tests=include_tests):
                files_to_scan.append(path)

    all_findings: list[Finding] = []
    for f in files_to_scan:
        all_findings.extend(scan_file(f))

    # ── False Positive Filtering ──
    fp_result: FilterResult | None = None
    if enable_fp_filter and all_findings:
        all_findings, fp_result = apply_fp_filters(all_findings)

    # ── Classification ──
    classifier_result: ClassifierResult | None = None
    if enable_classifier and all_findings:
        all_findings, classifier_result = classify_findings(all_findings)

    duration_ms = int((time.time() - start_time) * 1000)

    result = ScanResult(
        target=str(target),
        files_scanned=len(files_to_scan),
        findings=sorted(all_findings, key=lambda x: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity.value),
            x.line,
        )),
        scan_duration_ms=duration_ms,
    )

    # Attach pipeline metadata for reporters
    if fp_result:
        result.__dict__["_fp_result"] = fp_result
    if classifier_result:
        result.__dict__["_classifier_result"] = classifier_result

    return result
