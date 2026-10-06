with open("dump_head.bin", "rb") as f:
    data = f.read()

import re

# Search for URLs, endpoints, JSON keys
patterns = [
    rb"http[s]?://[^\x00\r\n\s]+",
    rb"/api/[^\x00\r\n\s]+",
    rb"{\"status\":[^\x00\r\n]+",
    rb"\"[a-zA-Z0-9_-]+\":\s*\"[^\x00\r\n]+\"",
    rb"\.php[^\x00\r\n\s]*",
    rb"\.json[^\x00\r\n\s]*",
]

for pat in patterns:
    matches = list(re.finditer(pat, data))
    print(f"Pattern {pat}: {len(matches)} matches")
    for m in matches[:10]:
        print(f"  0x{0x140000000+m.start():x}: {m.group(0)}")
