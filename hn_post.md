# Show HN: AgentGuard — SAST for AI agent security (951 findings in 7 frameworks)

I built a static analysis tool specifically for AI agent code because existing tools (Bandit, Semgrep, CodeQL) don't detect agent-specific attack vectors.

**The gap:** OWASP published the Agentic Security Initiative (ASI) Top 10 in 2025 — 10 vulnerability categories unique to AI agents: prompt injection, tool abuse, data exfiltration, excessive agency, trust boundary violations. No existing SAST tool covers them.

**The tool:** 22 detection rules. AST-based taint tracking. False positive filter (32 systematic patterns). 4-tier classifier (CONFIRMED / INVESTIGATE / BEST_PRACTICE / LIKELY_FP).

**The scan:** 7 major frameworks, 9,000 Python files → 951 confirmed findings. Dify alone: 216 confirmed across 2,030 files.

**Precision:** 88% on independent validation (50 findings, zero overlap with dev sample). Publishing the real number, not a rounded-up one.

**Install:** `pip install dfx-agentguard && agentguard scan ./your-agent-code`

**GitHub:** https://github.com/dockfixlabs/agentguard
**License:** LGPL v3

Honest limits: 88% precision (not 100%), Python only, intra-procedural taint tracking, no CVEs yet (3 GHSAs pending).

Happy to answer questions about methodology, rules, or findings.
