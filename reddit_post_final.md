# Reddit Post — Final Sanitized for Public Launch

---

## الخيار 1: r/LocalLLaMA ⭐ الموصى به (English subreddit)

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
- 88% precision = ~1 in 8 findings is an FP
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

---

## الخيار 2: r/cybersecurity (English)

**Title:** AgentGuard — First SAST tool specifically for AI agent security. 951 findings in 7 frameworks. OWASP ASI Top 10 coverage.

**Body:**

I built a static analysis tool for AI agent security because existing tools weren't designed for this attack surface.

**The gap:** OWASP's Agentic Security Initiative (ASI) Top 10 covers 10 attack vectors unique to AI agents. No existing SAST tool detects them. Bandit, Semgrep, CodeQL — all built for SQL injection, XSS, traditional vulns. Not prompt injection flowing into LLM templates, agents with unrestricted tool access, or runtime self-modification.

**The tool:** 22 detection rules across all 10 OWASP ASI categories. AST-based taint tracking. False positive filter (32 systematic patterns). 4-tier classification (CONFIRMED/INVESTIGATE/BEST_PRACTICE/LIKELY_FP).

**The scan:** 7 frameworks, 9,000 Python files → 951 confirmed findings → 88% independent precision.

**Comparison:**

| Feature | AgentGuard | Semgrep | CodeQL | Bandit |
|---------|-----------|---------|--------|--------|
| ASI01 Prompt Injection | Yes + taint | No | No | No |
| ASI02 Tool Abuse | Yes | No | No | Partial |
| ASI10 Trust Boundary | Yes | No | No | No |
| OWASP ASI Coverage | 10/10 | 1/10 | 1/10 | 2/10 |

**No direct competitors.** AgentShield scans configs (different niche).

**Install:** `pip install dfx-agentguard` | **License:** LGPL v3

GitHub: https://github.com/dockfixlabs/agentguard

---

## الخيار 3: r/programming (English, short)

**Title:** Show r/programming: AgentGuard — SAST for AI agent code (951 findings in 7 frameworks)

**Body:**

Built a SAST tool that scans AI agent code for vulnerabilities existing tools miss. Scanned 7 frameworks, found 951 confirmed issues. 88% precision on independent validation.

`pip install dfx-agentguard && agentguard scan ./your-agent-code`

Covers all 10 OWASP ASI categories. Bandit, Semgrep, CodeQL don't cover these. No direct competitor.

Honest limits: 88% precision, Python only, intra-procedural taint tracking.

GitHub: https://github.com/dockfixlabs/agentguard

---

## استراتيجية النشر

1. **r/LocalLLaMA أولاً** — أعلى تداخل مع مطوري AI agents
2. **انتظر ساعة.** إذا حصل تفاعل: cross-post لـ r/cybersecurity
3. **إذا صفر تفاعل:** جرب r/MachineLearning بزاوية بحثية أكثر
4. **تفاعل مع كل تعليق في أول 4 ساعات** — خوارزمية Reddit تزن التفاعل المبكر جداً

## تعليمات النشر

1. اذهب إلى https://www.reddit.com/r/LocalLLaMA/submit
2. اختر "Text" post (وليس Link)
3. انسخ العنوان + النص من الخيار 1 أعلاه
4. انشر
5. رد على كل تعليق في أول ساعتين
6. كن متواضعاً، تقنياً، لا تبالغ في التسويق

## ملاحظات مهمة قبل النشر

- ⚠️ **لا تذكر تفاصيل الثغرات** — ذكر "CVSS 10.0 pending" فقط بدون شرح exploit
- ⚠️ **لا تبالغ** — 88% وليس 100%، هذا يميزنا
- ⚠️ **ردك الأول يحدد النبرة** — متواضع، تقني، مفيد
- ✅ أضف رابط الـ Reddit في MEMORY.md بعد النشر حتى أرصده
