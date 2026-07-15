# Changelog

All notable changes to AgentGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-07-12

### Fixed
- All 6 remaining false positives fixed (single pattern: `def _update_prompts` flagged as ASI10 self-modification)
- CLI version now reads from `__version__` instead of hardcoded string

### Changed
- License: MIT → LGPL v3 (protects core from cloud vendor appropriation; apps/extensions remain MIT-compatible)
- README precision claim: "scheduled for fix" → confirmed fixed; added license row to precision table

## [0.8.0] - 2026-07-08

### Added
- **Automatic False Positive Filtering** (`false_positive_filter.py`): Post-scan FP detection using:
  - Rule-specific exclusion patterns (known FP regexes per rule)
  - File-level heuristics (metadata files, lock files, configs)
  - Content-level heuristics (comments, documentation, security docs)
  - Density-based anomaly detection (single rule flooding >50 findings/file)
  - Severity auto-downgrade for noisy rule patterns
- **Automatic Finding Classification** (`classifier.py`): 4-tier classification:
  - `CONFIRMED`: High-confidence actionable vulnerabilities
  - `INVESTIGATE`: Needs human review
  - `BEST_PRACTICE`: Security pattern, not exploitable
  - `LIKELY_FP`: Probable false positive
- **Auto Report Generation** (`auto_reporter.py`):
  - Structured Markdown audit reports with executive summary, OWASP coverage, top findings
  - JSON summary for programmatic consumption
  - CI-mode concise one-liner (`--ci` flag)
  - Risk scoring (weighted by severity)
  - Framework health assessment (HEALTHY / NEEDS REVIEW / CRITICAL)
- New CLI flags: `--no-fp-filter`, `--no-classify`, `--auto-report PATH`, `--ci`
- Scanner now skips lock files (`package-lock.json`, `yarn.lock`, `poetry.lock`, etc.)

### Changed
- `scan_directory()` now accepts `enable_fp_filter` and `enable_classifier` flags
- Scan pipeline: raw findings -> FP filter -> classifier -> sorted output
- FP filter enabled by default; classifier enabled by default

### Fixed
- Lock files no longer scanned (eliminates noise from `package-lock.json`)
- Unicode arrow characters replaced with ASCII equivalents for Windows cp1256 compatibility

## [0.2.1] - 2026-06-28

### Fixed
- Critical: CredentialLeakRule had scan_line instead of scan_content — rule was never invoked
- Critical: EXFIL_URL regex now matches f-strings (was missing in v0.2.0 PyPI release)
- Reporter: replaced emoji with ASCII labels to fix Windows cp1256 crash
- SARIF report version now uses __version__ instead of hardcoded 0.1.0

## [0.2.0] - 2026-06-21

### Added
- Complete OWASP ASI Top 10 coverage (10/10 categories)
- ASI04: Excessive Agency detection
- ASI05: Supply Chain risk detection
- ASI09: Agent Loop Exploitation detection
- MCP server mode (scan from Claude Code / Cursor)
- 3 MCP tools: scan_agent_code, list_rules, get_finding_details
- SARIF output format for CI/CD integration
- Confidence scoring on all findings

### Changed
- Improved regex patterns for data exfiltration (f-string support)
- Credential leak detection now redacts sensitive output

### Fixed
- pyproject.toml build-backend corrected to setuptools.build_meta
- PEP 639 license classifier removal
- setup.py README.md case sensitivity on Linux CI
- CredentialLeakRule restored in rules registry
- EXFIL_URL regex now matches f-strings

## [0.1.0] - 2026-06-21

### Added
- 7 detection rules covering OWASP ASI Top 10
- CLI with text/json/sarif output
- Programmatic Python API
- CI/CD integration ready
- 10 test cases
