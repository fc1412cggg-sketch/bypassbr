import re

with open("dump_head.bin", "rb") as f:
    d = f.read()

terms = [
    b"Madium", b"madium", b"Medium", b"medium", b"Key", b"key", b"KEY",
    b"License", b"license", b"Auth", b"auth", b"Login", b"login",
    b"Expire", b"expire", b"Success", b"success", b"Invalid", b"invalid",
    b"HWID", b"hwid", b"Paste", b"paste", b"Submit", b"submit",
    b"Enter", b"enter", b"Check", b"check", b"Valid", b"valid"
]

for t in terms:
    matches = [m.start() for m in re.finditer(re.escape(t), d)]
    print(f"Term '{t.decode()}': {len(matches)} matches")
    for pos in matches[:5]:
        # print surrounding text/bytes
        start = max(0, pos - 30)
        end = min(len(d), pos + 50)
        chunk = d[start:end]
        # try ascii / utf-16
        printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
        print(f"  @ {hex(pos)} (VA: {hex(0x140000000 + pos)}): {printable}")
