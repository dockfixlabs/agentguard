# Contributing

Thanks for your interest in contributing to AgentGuard!

## Quick Start

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature`
3. Commit with clear messages: `feat: add X`, `fix: resolve Y`
4. Open a Pull Request

## Guidelines

- **Tests:** Add tests for new rules and features
- **Docs:** Update README and rule documentation if behavior changes
- **Scope:** One feature/fix per PR
- **Style:** Follow existing code conventions (ruff for linting)

## Adding a New Detection Rule

1. Create `agentguard/rules/your_rule.py`
2. Inherit from `Rule` base class
3. Set `rule_id`, `rule_name`, `severity`, `owasp`
4. Implement `scan_line()` or `scan_content()`
5. Return `Finding` objects
6. Register in `agentguard/rules/__init__.py`
7. Add tests in `tests/test_scanner.py`

## Issue Reports

Include:
- OS and version
- Steps to reproduce
- Expected vs actual behavior
- Logs (redact sensitive info)

## Code of Conduct

Be respectful. Be constructive. No harassment.

---

Built by [Dockfix Labs](https://github.com/dockfixlabs).
