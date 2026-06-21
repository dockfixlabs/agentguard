"""Core scanner engine — orchestrates rules across files."""

from __future__ import annotations

import time
from pathlib import Path

from agentguard.models import ScanResult, Finding
from agentguard.rules import ALL_RULES

# File extensions to scan
SCANABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".rb", ".go", ".rs", ".java", ".kt", ".swift",
    ".yaml", ".yml", ".json", ".toml",
    ".sh", ".bash", ".zsh",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    ".tox", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", "vendor", ".cargo", "target",
}


def should_scan(path: Path) -> bool:
    """Check if a file should be scanned."""
    if path.suffix.lower() not in SCANABLE_EXTENSIONS:
        return False
    # Check if any skip dir is in the path
    for part in path.parts:
        if part in SKIP_DIRS:
            return False
    return True


def scan_file(file_path: Path) -> list[Finding]:
    """Scan a single file with all rules."""
    findings: list[Finding] = []

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


def scan_directory(target: str | Path) -> ScanResult:
    """Scan an entire directory for AI agent security vulnerabilities."""
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
        if should_scan(target_path):
            files_to_scan = [target_path]
    else:
        for path in target_path.rglob("*"):
            if path.is_file() and should_scan(path):
                files_to_scan.append(path)

    all_findings: list[Finding] = []
    for f in files_to_scan:
        all_findings.extend(scan_file(f))

    duration_ms = int((time.time() - start_time) * 1000)

    return ScanResult(
        target=str(target),
        files_scanned=len(files_to_scan),
        findings=sorted(all_findings, key=lambda x: (
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity.value),
            x.line,
        )),
        scan_duration_ms=duration_ms,
    )
