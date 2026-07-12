"""Fetch AgentShield README for competitive analysis."""
import urllib.request, json, base64

url = 'https://api.github.com/repos/affaan-m/agentshield/readme'
req = urllib.request.Request(url, headers={'User-Agent': 'AgentGuard'})
with urllib.request.urlopen(req) as r:
    data = json.loads(r.read())
    content = base64.b64decode(data['content']).decode('utf-8', errors='replace')
    # Print first 4000 chars
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    print(content[:4000])
