import re
PASSWORD = re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I)
line = 'password = "dxT9$kPz2#mN4vQ!7wR"'
print(f'Line: {line}')
print(f'Match: {bool(PASSWORD.search(line))}')
m = PASSWORD.search(line)
if m:
    print(f'Group 1: {m.group(1)}')

# Also check with the actual line from the fixture
line2 = 'password = "dxT9$kPz2#mN4vQ!7wR"'
print(f'\nLine2: {line2}')
print(f'Match2: {bool(PASSWORD.search(line2))}')
