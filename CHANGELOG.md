# Changelog

All notable changes to AgentGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
## [0.2.1] - 2026-06-28

### Fixed
- Critical: CredentialLeakRule had scan_line instead of scan_content — rule was never invoked
- Critical: EXFIL_URL regex now matches f-strings (was missing in v0.2.0 PyPI release)
- Reporter: replaced emoji with ASCII labels to fix Windows cp1256 crash
- SARIF report version now uses __version__ instead of hardcoded 0.1.0
