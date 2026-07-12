import re
# Check if 'tes' in 'sk-tes' matches placeholder pattern 'test'
PLACEHOLDER = re.compile(r'^(?:your[-_]|example|test|demo|sample|placeholder|changeme|xxx|replace[-_]me)', re.I)
print(f'test match: {bool(PLACEHOLDER.search("test"))}')
print(f'tes match: {bool(PLACEHOLDER.search("tes"))}')

# The REAL issue: check if credential_leak PLACEHOLDER_VALUES matches 'sk-proj-7H9...'
import sys; sys.path.insert(0, '.')
from agentguard.rules.credential_leak import PLACEHOLDER_VALUES, _is_placeholder, API_KEY_PATTERNS, PASSWORD

test_val = "sk-proj-7H9Xk2mLp4Qr8VuW3Yb6nTf5Cs1Da0Eg9Hi2Jk4Lm6No8Pq3Rt5Su8Vw0Xy2Zb4"
print(f'\nTest value: {test_val[:20]}...')
print(f'API_KEY_PATTERNS match: {any(p.search(test_val) for p in API_KEY_PATTERNS)}')
print(f'PLACEHOLDER match: {bool(PLACEHOLDER_VALUES.search(test_val))}')
print(f'is_placeholder: {_is_placeholder(test_val)}')

# Also check password
pwd = 'dxT9$kPz2#mN4vQ!7wR'
print(f'\nPassword: {pwd}')
print(f'PASSWORD match: {bool(PASSWORD.search(pwd))}')
print(f'is_placeholder pwd: {_is_placeholder(pwd)}')

# Check token
token = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
print(f'\nToken: {token[:30]}...')
print(f'API_KEY_PATTERNS match: {any(p.search(token) for p in API_KEY_PATTERNS)}')
print(f'is_placeholder token: {_is_placeholder(token)}')
