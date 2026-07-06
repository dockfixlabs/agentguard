# Comparative SAST Analysis: AgentGuard vs Semgrep vs Bandit

**Date:** 2026-07-06 | **Scanner:** AgentGuard v0.7.1 | **Methodology:** Identical codebases, full-project scans

---

## Executive Summary

We scanned identical codebases of LangChain and AutoGen with three static analysis tools. Semgrep and Bandit — the two most popular Python SAST tools — detected **zero** agent-specific security vulnerabilities across all codebases. AgentGuard detected **681**.

The "agent-related" findings from Semgrep and Bandit were:
- **Semgrep**: GitHub Actions CI/CD issues (script injection in workflow YAML) — not AI agent security
- **Bandit**: Generic Python issues (assert usage, subprocess calls without shell=False) — not AI agent security

---

## LangChain — 1,784 files

| Tool | Total Findings | Agent-Specific | Agent-Specific Types |
|------|---------------|----------------|---------------------|
| **AgentGuard** | **452** | **452** | Prompt injection, tool abuse, unsafe eval, credential leak, trust boundary, memory poison, agent collusion, chain amplify |
| Semgrep | 52 | **0** | GitHub Actions YAML, uv dependency cooldown, non-literal imports |
| Bandit | 14,445 | **0** | assert usage (14,264), hardcoded passwords (72), yaml.load (41), subprocess (6) |

## AutoGen — 549 files

| Tool | Total Findings | Agent-Specific | Agent-Specific Types |
|------|---------------|----------------|---------------------|
| **AgentGuard** | **229** | **229** | Tool abuse, unsafe eval, trust boundary, agent collusion, memory class confusion, chain amplify |
| Semgrep | 150 | **0** | GitHub Actions mutable tag (122), non-literal imports, shell injection in CI |
| Bandit | 4,975 | **0** | assert usage (4,897), subprocess (15), partial path (11) |

---

## What Semgrep and Bandit Actually Found

### Semgrep Top Detections
| Rule | Category | Count |
|------|----------|-------|
| github-actions-mutable-action-tag | CI/CD config | 122 |
| uv-missing-dependency-cooldown | Package manager | 21 |
| non-literal-import | Generic Python | 15 |
| github-script-injection | CI/CD config | 5 |
| secrets-inherit | CI/CD config | 5 |

**Zero prompt injection. Zero agent collusion. Zero tool abuse. Zero memory poison.**

### Bandit Top Detections
| Rule | Category | Count |
|------|----------|-------|
| B101 (assert) | Debug code | 19,161 |
| B603 (subprocess) | Generic Python | 21 |
| B105 (hardcoded_password_string) | Generic Python | 72 |
| B607 (partial path) | Generic Python | 11 |

**Zero prompt injection. Zero agent collusion. Zero tool abuse. Zero memory poison.**

---

## Why This Matters

AI agent code introduces entirely new attack surfaces that traditional SAST tools were never designed to detect:

1. **Prompt injection** — User input flows into LLM prompts through chains, tools, and memory
2. **Agent collusion** — Multiple agents sharing mutable state without access controls
3. **Memory poisoning** — Vector DB writes from untrusted sources
4. **Tool output trust** — Agents consuming unvalidated tool results
5. **Chain amplification** — Destructive ops in unbounded loops
6. **Mount exposure** — Docker executors exposing host filesystems

Semgrep and Bandit have **no rules** for any of these patterns. Their rule sets target web applications, general Python security, and CI/CD configurations. They are completely blind to AI agent-specific attack vectors.

---

## Conclusion

**AgentGuard is not competing with Semgrep and Bandit — it operates in a security domain they don't address.** Organizations building AI agents need BOTH: traditional SAST for standard code issues AND AgentGuard for AI agent-specific vulnerabilities.

This is not a weakness of Semgrep/Bandit. It's a category difference. The AI agent attack surface is new, and the tooling hasn't caught up — until now.

---

*Analysis performed by Dockfix Labs using AgentGuard v0.7.1. Full scan data and methodology in [PAPER_6173_FINDINGS.md](https://github.com/dockfixlabs/agentguard/blob/main/PAPER_6173_FINDINGS.md).*
