import sys

path = sys.argv[1]
raw = open(path, encoding='utf-8', newline='').read()
BACKSLASH = chr(92)
out = []
i = 0
in_str = False
while i < len(raw):
    ch = raw[i]
    if ch == '"':
        n = 0
        j = i - 1
        while j >= 0 and raw[j] == BACKSLASH:
            n += 1
            j -= 1
        if n % 2 == 0:
            in_str = not in_str
        out.append(ch)
        i += 1
        continue
    if in_str and ch in '\r\n':
        if ch == '\r' and i + 1 < len(raw) and raw[i + 1] == '\n':
            i += 2
        else:
            i += 1
        out.append(BACKSLASH + 'r' + BACKSLASH + 'n')
        continue
    out.append(ch)
    i += 1
open(path, 'w', encoding='utf-8', newline='').write(''.join(out))
print('escaped')
