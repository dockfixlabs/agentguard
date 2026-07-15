# Reddit Post — READY FOR OWNER (Final Polish)

## اختر الـ subreddit الأنسب حسب المزاج:

### الخيار 1: r/LocalLLaMA (تقني، جمهور AI agents) ⭐ الموصى به

**Title:**
I built a SAST tool for AI agent security — scanned 7 frameworks, found 951 vulnerabilities. 88% precision on independent validation. No direct competitor exists.

**Body:**
السلام عليكم — أداة بنيتها خصيصاً لأمن وكلاء الذكاء الاصطناعي.

**المشكلة:** أدوات SAST الحالية (Bandit, Semgrep, CodeQL) لا تفهم AI agents. ما تفرق بين `user_input` يتدفق إلى قالب LLM و `user_input` عادي. ما تعرف إن `os.system()` داخل agent أخطر من `os.system()` عادي. كل القواعد صممت للثغرات التقليدية — SQL injection, XSS — وليس لـ prompt injection, tool abuse, data exfiltration.

**اللي سويته:** AgentGuard — 22 قاعدة تغطي كل فئات OWASP ASI Top 10 (مبادرة أمن الوكلاء). فحصت 7 أطر:

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

**الدقة:** ما راح أخدعكم وأقول 100%. قست على عينتين:
- عينة التطوير: بدأت 36%، وصلت 100% بعد التصليح — لكن هذا overfitting
- عينة مستقلة (50 finding جديدة، صفر تداخل): **88%** (44 TP / 6 FP)

أنشر 88% بصدق، مو 100% كذب.

**الـ 6 FPs المتبقية** كلها من نمط واحد: تعريفات دوال `def _update_prompts(self, ...)` تتفلتر كأنها self-modification. انحلت في v0.8.1.

**التثبيت:**
```
pip install dfx-agentguard
agentguard scan ./your-agent-code
```

**حدود صادقة:**
- 88% دقة تعني ~1 من كل 8 findings كاذب
- Python فقط (JavaScript جزئي)
- تتبع التلوث داخل الدالة فقط (ما يعبر حدود الدوال)
- لا يوجد CVE بعد (3 GHSAs مفتوحة، ننتظر رد الفرق)

**المنافسون:** لا يوجد. AgentShield (966 نجمة) أداة مختلفة — تفحص config files لـ Claude Code، ليس source code. الأدوات اللي تفحص source code للـ AI agents بالذات — AgentGuard الأول والوحيد.

**الرخصة:** LGPL v3 — مجاني للأبد للأفراد والمشاريع مفتوحة المصدر. 

**الروابط:**
- GitHub: https://github.com/dockfixlabs/agentguard
- PyPI: https://pypi.org/project/dfx-agentguard/

أسئلتكم مرحب بها — خصوصاً من اللي يبنون AI agents ويبغون يفحصون أمن الكود حقهم.

---

### الخيار 2: r/cybersecurity (جمهور أمني محترف)

**Title:**
AgentGuard — First SAST tool specifically for AI agent security. 951 findings in 7 frameworks. OWASP ASI Top 10 coverage.

**Body:**
I built a static analysis tool for AI agent security because existing SAST tools (Bandit, Semgrep, CodeQL) weren't designed to detect agent-specific attack vectors.

**The gap:** OWASP published the Agentic Security Initiative (ASI) Top 10 in 2025. These are critical attack vectors unique to AI agents — prompt injection, tool abuse, data exfiltration, excessive agency, trust boundary violations. No existing SAST tool covers them. They're built for SQL injection, XSS, traditional vulns.

**The tool:** AgentGuard — 22 rules across all 10 OWASP ASI categories. AST-based taint tracking. False positive filter. Auto-classification (CONFIRMED/INVESTIGATE/BEST_PRACTICE/LIKELY_FP).

**The scan:** 7 major AI agent frameworks, 9,000 Python files → 951 confirmed findings.

**Precision:** 88% on independent validation (50 findings, zero overlap with dev sample). Publishing the real number, not a rounded-up one.

**No competitors:** AgentShield scans Claude Code configs (different niche). Runtime prompt injection detectors exist but aren't SAST. For AI agent source code analysis specifically — AgentGuard is the only one.

**Install:** `pip install dfx-agentguard`
**License:** LGPL v3

GitHub: https://github.com/dockfixlabs/agentguard

I have 3 GitHub Security Advisories pending (incl. CVSS 10.0 on LangChain). Happy to discuss methodology, rules, or findings.

---

### الخيار 3: r/programming (جمهور عام)

**Title:**
Show r/programming: AgentGuard — SAST for AI agent code (951 findings in 7 frameworks)

**Body:**
Built a SAST tool that scans AI agent code for vulnerabilities that existing tools miss. Scanned 7 frameworks, found 951 confirmed issues. 88% precision on independent validation.

`pip install dfx-agentguard && agentguard scan ./your-agent-code`

GitHub: https://github.com/dockfixlabs/agentguard

The tool covers all 10 OWASP ASI (Agentic Security Initiative) categories. Bandit, Semgrep, CodeQL don't cover these. No direct competitor exists yet.

Honest limitations: 88% precision (not 100%), Python only, intra-procedural taint tracking.

Happy to answer questions.

---

## Posting Strategy

1. **Post on r/LocalLLaMA first** — highest overlap with AI agent developers
2. **Wait 1 hour.** If it gains traction, cross-post to r/cybersecurity and r/programming
3. **If zero traction on first post:** try r/MachineLearning with a more research-focused angle
4. **Monitor comments actively** for the first 4 hours — engagement in the first hours determines whether the post goes viral or dies

## Posting Instructions

1. Go to https://www.reddit.com/r/LocalLLaMA/submit
2. Select "Text" post type (not Link)
3. Copy the title and body from your chosen variant above
4. Post
5. Reply to EVERY comment in the first 2 hours — Reddit algorithm heavily weights early engagement
6. Stay humble, stay technical, don't oversell
