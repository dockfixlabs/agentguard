# Reddit r/LocalLLaMA

**Title:**
I built a SAST tool for AI agent security — scanned 7 frameworks, found 951 vulnerabilities. 88% precision on independent validation. No direct competitor exists.

**Body:**

**The problem:** Existing SAST tools (Bandit, Semgrep, CodeQL) don't understand AI agents. They can't tell the difference between `user_input` flowing into an LLM prompt template and regular `user_input`. They don't know that `os.system()` inside an agent is more dangerous than `os.system()` in regular code. Every rule is designed for traditional vulns — SQL injection, XSS — not prompt injection, tool abuse, or data exfiltration.

**What I built:** AgentGuard — 22 rules covering every OWASP ASI Top 10 category (Agentic Security Initiative). Scanned 7 major frameworks:

| Framework | Files | Confirmed Findings |
|-----------|-------|--------------------|
| Dify | 2,030 | 216 |
| LlamaIndex | 2,951 | 294 |
| CrewAI | 1,042 | 99 |
| LangChain | 1,831 | 132 |
| AutoGen | 553 | 98 |
| CAMEL | 355 | 62 |
| Qwen-Agent | 238 | 50 |
| **Total** | **9,000** | **951** |

**Precision — honest numbers:**

I measured on two independent samples:
- Development sample: started at 36%, reached 100% after fixes — but that was overfitting
- Independent sample (50 NEW findings, zero overlap with dev): **88%** (44 TP / 6 FP)

I'm publishing 88%, not rounding up to 100%. All 6 false positives were one pattern (`def _update_prompts` flagged as self-modification) — fixed in v0.8.1.

**Install:**
```
pip install dfx-agentguard
agentguard scan ./your-agent-code
```

**Honest limitations:**
- 88% precision = ~1 in 8 findings is an FP (filtered pre-output, but still)
- Python only (partial JavaScript)
- Intra-procedural taint tracking only (no cross-function)
- No CVEs yet (3 GHSAs pending maintainer response)

**Competitors:** None. AgentShield (966 stars) scans Claude Code config files — different niche. Runtime prompt injection detectors exist but aren't SAST. For AI agent source code analysis — AgentGuard is first and only.

**License:** LGPL v3 — free forever for individuals and OSS projects.

**Links:**
- GitHub: https://github.com/dockfixlabs/agentguard
- PyPI: https://pypi.org/project/dfx-agentguard/
- Full roadmap: https://github.com/dockfixlabs/agentguard/blob/main/ROADMAP.md

Questions welcome — especially from people building AI agents who want to scan their code.
