"""Check PyPI download sources for dfx-agentguard."""
import urllib.request, json

# Recent downloads
url = 'https://pypistats.org/api/packages/dfx-agentguard/recent'
with urllib.request.urlopen(url) as r:
    data = json.loads(r.read())
    print("Recent downloads:")
    print(f"  Last day:  {data['data']['last_day']}")
    print(f"  Last week: {data['data']['last_week']}")
    print(f"  Last month: {data['data']['last_month']}")
    print()

# Overall by category
url2 = 'https://pypistats.org/api/packages/dfx-agentguard/overall?mirrors=false'
with urllib.request.urlopen(url2) as r:
    data2 = json.loads(r.read())
    rows = data2.get('data', [])
    print(f"Overall (no mirrors): {len(rows)} rows")
    total = 0
    for row in rows:
        cat = row['category']
        dl = row['downloads']
        total += dl
        print(f"  {cat:<30s} {dl:>6d}")
    print(f"  {'TOTAL':<30s} {total:>6d}")
    print()

# Python minor version distribution
try:
    url3 = 'https://pypistats.org/api/packages/dfx-agentguard/python_minor'
    with urllib.request.urlopen(url3) as r:
        data3 = json.loads(r.read())
        rows3 = data3.get('data', [])
        print("Python minor versions:")
        for row in rows3[:10]:
            print(f"  {row['category']:<20s} {row['downloads']:>6d}")
except Exception as e:
    print(f"Python minor: {e}")
