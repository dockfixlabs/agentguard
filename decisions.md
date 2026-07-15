# AgentGuard Strategic Decisions Log

## Format: [DATE] Decision — Reason

### 2026-07-12 — Independent precision validation before any public claim
**Decision:** Validate precision on independent sample before publishing any number.
**Reason:** First sample (36%→100%) was overfitting. Independent sample proved real precision is 88%. Prevented publishing false 100% claim.
**Status:** Executed. 88% published in README.

### 2026-07-12 — Focus solely on AgentGuard product until first CVE
**Decision:** Stop pursuing bug bounty platforms (HackenProof, Huntr, etc.) and side projects. All effort on AgentGuard.
**Reason:** Product is the durable asset. CVE is the proof. Bug bounty is distraction until product is proven.
**Status:** Active.

### 2026-07-12 — Do not contact potential clients until precision ≥85% verified independently
**Decision:** Gate client outreach on independent precision validation.
**Reason:** Going to clients with unmeasured precision = risk of being exposed as noise generator. 88% verified independently is sufficient. Below 85% would not be.
**Status:** Met. 88% > 85% threshold. Outreach now permitted.

### 2026-07-12 — Self-review system: every intensive work session
**Decision:** Conduct self-review at end of every intensive session or every ~4 hours of work.
**Reason:** Catches overfitting, optimistic assumptions, and scope creep before they compound.
**Status:** Active. First review conducted 2026-07-12.

### 2026-07-12 — Publish 88% precision and create PR for v0.8.1
**Decision:** Publish 88% in README, push v0.8.1 branch, create PR #18.
**Reason:** Precision is independently verified. 88% is honest and defensible. Publishing builds credibility.
**Status:** PR #18 open, awaiting merge.

### 2026-07-12 — Do not chase the 7 lost TPs from rule behavior changes
**Decision:** Accept 7 TP loss from rewritten rules (not over-filtering). Focus on new users, not recovering old findings.
**Reason:** The rules were rewritten to be more precise. Some old findings no longer match because the patterns changed. This is expected behavior, not a bug.
**Status:** Active.

### 2026-07-12 — PyPI upload blocked: no credentials in environment
**Decision:** Defer PyPI upload. Owner needs to provide PyPI token or upload manually.
**Reason:** v0.8.1 is on GitHub main but not on PyPI. Users who `pip install` get v0.8.0.
**Status:** DONE — Owner provided token on 2026-07-15, v0.8.1 uploaded to PyPI.

### 2026-07-12 — Blog post draft: remove vulnerability details before publishing
**Decision:** Blog post draft contains specific exploit details (LangChain CVSS 10.0, AutoGen Docker mount). Must be sanitized before any public posting.
**Reason:** Responsible disclosure — 90-day window not expired. Publishing exploit details before CVE or fix = irresponsible.
**Status:** DONE — v2 sanitized, no exploit details. Ready for Reddit.

### 2026-07-12 — GitHub topics added for discoverability
**Decision:** Added 10 topics: ai-security, sast, owasp, agent-security, static-analysis, prompt-injection, llm-security, code-scanner, python, security-audit.
**Reason:** Repo had no topics. Topics improve GitHub search discoverability.
**Status:** Applied.

### 2026-07-15 — Owner grants full autonomy
**Decision:** Owner granted full decision authority for all reversible actions.
**Reason:** Trust established through consistent self-review and honest reporting.
**Status:** Active. External irreversible actions (public posts, client emails) still drafted first.

### 2026-07-15 — LangChain GHSA follow-up blocked
**Decision:** Cannot post follow-up comments on external GHSA — 403 permission denied.
**Reason:** GitHub Security Advisories only allow comments from repo collaborators.
**Status:** Blocked — must wait. 10 days, 0 response.

### 2026-07-15 — Submit to awesome-gpt-security
**Decision:** Forked and submitted PR #57 to cckuailong/awesome-gpt-security.
**Reason:** 662 stars, target audience is GPT security researchers.
**Status:** PR #57 open, awaiting maintainer review.

### 2026-07-15 — Reddit post prepared for manual owner posting
**Decision:** Prepared Reddit post content in REDDIT_POST_READY.md. Owner posts manually.
**Reason:** User prefers manual Reddit posting. Content ready for r/LocalLLaMA, r/cybersecurity, r/MachineLearning.
**Status:** Content ready, awaiting owner to post.
