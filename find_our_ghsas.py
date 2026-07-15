"""Find our GHSAs in Dify and Haystack."""
import urllib.request, json

repos = [
    ("langgenius/dify", "GHSA-4whw-g9j9-v77x"),
    ("langgenius/dify", "GHSA-9c9q-5rj5-mjj2"),
    ("langgenius/dify", "GHSA-fj5w-7rc8-3f3f"),
    ("deepset-ai/haystack", "GHSA-xr34-83qq-82wc"),
    ("deepset-ai/haystack", "GHSA-hx9v-6r9f-w677"),
]

for repo, ghsa in repos:
    url = f"https://api.github.com/repos/{repo}/security-advisories/{ghsa}"
    req = urllib.request.Request(url, headers={"User-Agent": "AgentGuard", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req) as r:
            data = json.loads(r.read())
            credits = data.get("credits", [])
            credit_names = [c.get("login", "") for c in credits] if credits else []
            print(f"{repo}/{ghsa}: state={data['state']} summary={data['summary'][:80]} credits={credit_names}")
    except Exception as e:
        print(f"{repo}/{ghsa}: ERROR {e}")

# Also check all Dify advisories for our credit
url = "https://api.github.com/repos/langgenius/dify/security-advisories"
req = urllib.request.Request(url, headers={"User-Agent": "AgentGuard", "Accept": "application/vnd.github+json"})
with urllib.request.urlopen(req) as r:
    advisories = json.loads(r.read())
    for adv in advisories:
        credits = adv.get("credits", [])
        credit_logins = [c.get("login", "") for c in credits] if credits else []
        if any("dockfix" in str(c).lower() for c in credit_logins):
            print(f"OURS: {adv['ghsa_id']} state={adv['state']} summary={adv['summary'][:80]}")

# Haystack
url2 = "https://api.github.com/repos/deepset-ai/haystack/security-advisories"
req2 = urllib.request.Request(url2, headers={"User-Agent": "AgentGuard", "Accept": "application/vnd.github+json"})
with urllib.request.urlopen(req2) as r:
    advisories = json.loads(r.read())
    for adv in advisories:
        credits = adv.get("credits", [])
        credit_logins = [c.get("login", "") for c in credits] if credits else []
        if any("dockfix" in str(c).lower() for c in credit_logins):
            print(f"OURS: {adv['ghsa_id']} state={adv['state']} summary={adv['summary'][:80]}")
