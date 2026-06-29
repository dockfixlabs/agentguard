# Roadmap

## v0.3.x (Current -- June 2026)
- [x] Complete OWASP ASI Top 10 coverage (10/10)
- [x] MCP server mode
- [x] SARIF output for CI/CD
- [x] CLI (text/json/sarif)
- [x] PyPI package (dfx-agentguard) -- Trusted Publishing (OIDC)
- [x] VS Code extension
- [x] GitHub App for PR reviews
- [x] Benchmark suite (28 samples)
- [x] Pre-commit hook (.pre-commit-hooks.yaml)
- [x] GitHub Action (action.yml)
- [x] Dockerfile for agentguard-app
- [x] 100% detection rate, 0% false positives on benchmark
- [x] Test suite: 26 tests covering all OWASP ASI categories
- [x] Dev.to publication (3 articles)

## v0.4.0 (Q3 2026)
- [ ] AST-based taint tracking for Python (beyond regex)
- [ ] AST-based taint tracking for JavaScript/TypeScript
- [ ] Rust language support
- [ ] Go language support
- [ ] Java language support
- [ ] Custom rules engine (user-defined YAML rules)
- [ ] GitHub Code Scanning integration (native SARIF upload)
- [ ] Semgrep rule export (for users who already use Semgrep)
- [ ] 100+ benchmark samples (community-contributed)

## v0.5.0 (Q4 2026)
- [ ] Web dashboard (SaaS)
- [ ] REST API (Scan-as-a-Service)
- [ ] Trend analysis and security posture tracking
- [ ] Integration: Slack, Discord, Microsoft Teams
- [ ] Integration: Jira, Linear
- [ ] Diff-aware scanning (only scan changed files in PRs)

## v1.0.0 (2027)
- [ ] Enterprise SSO/SAML
- [ ] Audit log and compliance reports (SOC2, ISO27001)
- [ ] Multi-tenant architecture
- [ ] On-premise deployment option
- [ ] 200+ detection rules
- [ ] 500+ benchmark samples
- [ ] Real-time IDE feedback (deep VS Code integration)

## Community
- [Feature requests](https://github.com/dockfixlabs/agentguard/discussions/categories/ideas)
- [Bug reports](https://github.com/dockfixlabs/agentguard/issues)
- [Contributing](CONTRIBUTING.md)
