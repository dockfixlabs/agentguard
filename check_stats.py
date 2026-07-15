import urllib.request, json
url = 'https://pypistats.org/api/packages/dfx-agentguard/recent'
with urllib.request.urlopen(url) as r:
    data = json.loads(r.read())
    print(f"Last day:  {data['data']['last_day']}")
    print(f"Last week: {data['data']['last_week']}")
    print(f"Last month: {data['data']['last_month']}")

# Also check GitHub stats
url2 = 'https://api.github.com/repos/dockfixlabs/agentguard'
req = urllib.request.Request(url2, headers={'User-Agent': 'AgentGuard'})
with urllib.request.urlopen(req) as r:
    gh = json.loads(r.read())
    print(f"\nGitHub stars: {gh['stargazers_count']}")
    print(f"GitHub forks: {gh['forks_count']}")
    print(f"Open issues: {gh['open_issues_count']}")
