## v0.2.1 - Critical Bug Fixes

### Fixed

- **ASI07 Credential Exposure**: Fixed detection of modern OpenAI keys (sk-proj-* format). The regex now allows hyphens in key bodies.
- **ASI07 Credential Exposure**: Added missing PASSWORD, GENERIC_SECRET, ENV_IN_CODE, Slack token, and Google API key detection patterns.
- **ASI03 Data Exfiltration**: Added detection for variable-based URL exfiltration (url = ...; requests.post(url)).
- **ASI03 Data Exfiltration**: Added fetch(), axios, httpx, aiohttp, and subprocess curl/wget patterns.
- **Windows CLI crash**: Fixed UnicodeEncodeError on Windows cp1256 encoding. CLI now uses _make_console() with UTF-8 reconfiguration.
- **Benchmark**: Removed emoji from output (caused Windows crash). Corrected sample counts (28, not 100+).

### Added

- **.pre-commit-hooks.yaml**: Pre-commit hook integration for automated scanning.
- **action.yml**: GitHub Action for CI/CD integration.
- **Dockerfile** (agentguard-app): Containerized deployment with non-root user and health check.
- **16 new tests**: 26 total (up from 10). Coverage includes modern key formats, variable URLs, correlation detection, and edge cases.

### Test Results

```
26 passed in 0.29s
```

### Install

```bash
pip install --upgrade dfx-agentguard
agentguard . --format text
```
