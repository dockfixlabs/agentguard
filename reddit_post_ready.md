# Reddit Post — READY FOR MANUAL POSTING

## Subreddit: r/LocalLLaMA

## Title
AgentGuard — SAST tool for AI agent security. Scanned 7 frameworks (LangChain, AutoGen, CrewAI, LlamaIndex, Dify, CAMEL, Qwen-Agent): 951 confirmed findings with 88% precision on independent validation.

## Body

We built a static analysis tool specifically for AI agent security. Existing SAST tools (Bandit, Semgrep, CodeQL) don't detect agent-specific attack vectors — prompt injection flowing into LLM templates, agents with unrestricted `os.system()` access, data exfiltration to external endpoints, runtime self-modification, etc.

**What it does:** 22 rules covering all 10 OWASP ASI (Agentic Security Initiative) categories. AST-based taint tracking, false positive filtering, auto-classification.

**What we scanned:** 7 major AI agent frameworks, 9,000 Python files total:

| Framework | Files | Confirmed Findings |
|-----------|-------|--------------------|
| Dify | 2,030 | 216 |
| LlamaIndex | 2,951 | 294 |
| CrewAI | 1,042 | 99 |
| LangChain | 1,831 | 132 |
| AutoGen | 553 | 98 |
| CAMEL | 355 | 62 |
| Qwen-Agent | 238 | 50 |

**Precision validation (honest):**

- Development sample (50 findings): started at 36%, reached 100% after fixes — but that was overfitting
- Independent sample (50 NEW findings, zero overlap): **88%** (44 true positives, 6 false positives)
- Publishing 88%, not 100%, because that's the real number

**The 6 remaining FPs** were all one pattern: `def _update_prompts(self, ...)` flagged as self-modification. Fixed in v0.8.1.

**Install:**

```
pip install dfx-agentguard
agentguard scan ./your-agent-code
```

Outputs Markdown, JSON, or SARIF for GitHub Code Scanning.

**Honest limitations:**
- 88% precision = ~1 in 8 findings is FP
- Python only (JS partial)
- Intra-procedural taint tracking (no cross-function data flow yet)
- 951 findings on 9,000 files = 10.6% density (some frameworks are noisy)

**Links:**
- GitHub: https://github.com/dockfixlabs/agentguard
- PyPI: https://pypi.org/project/dfx-agentguard/

We have 3 GitHub Security Advisories open (including a CVSS 10.0 on LangChain) — waiting on maintainer responses. No CVEs yet.

Happy to answer questions about the tool, the rules, or the findings.

---

**POSTING INSTRUCTIONS FOR OWNER:**
1. Go to https://www.reddit.com/r/LocalLLaMA/submit
2. Select "Link" post type
3. Copy title and body above
4. Post manually (no bot per user preference)
5. After posting, monitor for comments and engage

**Alternative subreddits (post separately, customize title):**
- r/cybersecurity — focus on the security research angle
- r/MachineLearning — focus on the framework audit results
- r/programming — focus on the SAST tool itself
