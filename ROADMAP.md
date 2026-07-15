# AgentGuard Roadmap 2026–2027

> Public roadmap. Updated 2026-07-15. Built on evidence from studying Snyk, Semgrep, Bandit, Sidekiq, and Tailwind growth patterns.

## Phase 1: Prove Technical Value ✅ (June–July 2026)

- [x] 22 rules covering all 10 OWASP ASI categories
- [x] AST-based taint tracking for prompt injection
- [x] False positive filter (32 systematic patterns eliminated)
- [x] 4-tier classification (CONFIRMED / INVESTIGATE / BEST_PRACTICE / LIKELY_FP)
- [x] Auto-reporter (Markdown, JSON, SARIF)
- [x] Independent precision validation: **88%** (44 TP / 6 FP)
- [x] Published on PyPI (v0.8.1) and GitHub
- [x] 3 GitHub Security Advisories submitted (incl. CVSS 10.0)
- [x] License changed to LGPL v3 (protects against cloud vendor appropriation)

## Phase 2: Build Audience (August–October 2026)

**Goal:** 50+ GitHub stars, 5+ external issues, 200+ PyPI downloads/day

- [ ] Launch Week — 5 days, 5 feature releases (Supabase model)
- [ ] Multi-language support: JavaScript/TypeScript rules
- [ ] AgentGuard Playground — in-browser rule editor (Semgrep model)
- [ ] Community rule registry — shareable YAML rules
- [ ] OWASP ASI compliance badge for projects
- [ ] Technical blog series: "AI Agent Attack Patterns"
- [ ] Conference proposals: OWASP Global, AI Engineer Summit, Black Hat Arsenal
- [ ] Discord community (launch at 100+ stars)

## Phase 3: First Paid Users (November–January 2027)

**Goal:** First $1K MRR, 3 pilot customers

- [ ] AgentGuard Pro:
  - Private rules engine (proprietary rules not in community registry)
  - Team dashboard with historical trends
  - SSO (SAML/OIDC)
  - Priority support SLA
- [ ] Pricing: $99/seat/month for teams, free for individuals and OSS projects
- [ ] Pilot program: 3 AI agent platform companies
- [ ] GitHub App integration (scan PRs automatically)

## Phase 4: Product-Market Fit (February–April 2027)

**Goal:** $5K MRR, 500+ GitHub stars

- [ ] Full JavaScript/TypeScript rule parity with Python
- [ ] AgentGuard Cloud — managed scanning platform
- [ ] Enterprise tier: on-premise deployment, dedicated rules, CVE early warning
- [ ] Integration marketplace: CI/CD plugins (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- [ ] First CVE (if LangChain GHSA resolves) or new vulnerability discovery

## Phase 5: Scale (May–July 2027)

**Goal:** $10K MRR, 1,000+ GitHub stars

- [ ] AgentGuard Academy — paid courses on AI agent security
- [ ] Annual "State of AI Agent Security" report (marketing + thought leadership)
- [ ] Dedicated security research team
- [ ] Expand to Go, Rust, and Java
- [ ] First hire (customer success engineer)

## North Star (2028+)

AgentGuard becomes the standard security tool for AI agent development — what Bandit is for Python, what Semgrep is for multi-language SAST, but specifically for the agent attack surface.

## Why This Roadmap

This isn't guesswork. It's built on documented patterns from companies that faced the same situation:

- **Semgrep** proved the "community rule registry + open core + enterprise tier" model works for SAST ($93M raised, 15K+ stars)
- **Sidekiq** proved LGPL + solo founder + $10M+ ARR is achievable without VC
- **Bandit** proved that Apache 2.0 + no owner = $0 forever (27M downloads, zero revenue)
- **Snyk** proved dev-first security can reach $220M ARR (but at the cost of $1.2B raised and 14% layoffs)

We're taking the Semgrep + Sidekiq path: open source core (LGPL), lean team, revenue before funding.

## What We Won't Do

- ❌ Raise VC before $10K MRR
- ❌ Hire before revenue
- ❌ Change the name (AgentGuard is the name)
- ❌ Sell to enterprise before 1,000 free users
- ❌ Publish vulnerability details before responsible disclosure window
- ❌ Build features users haven't asked for
