# AgentGuard — Show HN

**Title:** AgentGuard — Open-source security scanner for AI agents (OWASP ASI Top 10)

**Body:**

Hi HN,

We built AgentGuard because AI agents are being deployed everywhere — in coding tools, trading bots, customer support — but nobody is scanning their code for agent-specific security vulnerabilities.

Traditional SAST tools (Bandit, Semgrep, CodeQL) look for traditional bugs. AgentGuard looks for attack vectors unique to AI agents:

- **Prompt Injection** — untrusted user input concatenated into LLM prompts via f-strings
- **Tool Abuse** — agents with unrestricted `exec()`, `subprocess`, or shell access
- **Data Exfiltration** — agents sending data to external URLs, DNS exfiltration
- **Credential Exposure** — hardcoded API keys, private keys, wallet seeds in agent code
- **Trust Boundary Violations** — agents running as root, accessing host filesystem

It maps to the OWASP Agentic Security Initiative (ASI) Top 10 (2026), covering 7 of 10 categories.

**Output formats:** text (human-readable), JSON, SARIF (for GitHub Code Scanning).

```bash
pip install agentguard
agentguard .
```

**Repo:** https://github.com/dockfixlabs/agentguard

Built with Python, pydantic, click, and rich. MIT licensed.

We're actively developing the remaining 3 OWASP ASI categories and an MCP server mode so you can scan agent code directly from Claude Code or Cursor.

Feedback welcome!
