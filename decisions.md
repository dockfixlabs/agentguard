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

### 2026-07-12 — External action gate: draft + present before any external send
**Decision:** Any action reaching an external party (GHSA, CVE request, client email, public post) must be drafted and presented before sending.
**Reason:** External actions are irreversible. Internal decisions are reversible.
**Status:** Active.
