import re
import pefile

with open("deef.exe", "rb") as f:
    d = f.read()

print("File size:", len(d))

# Search for common frameworks/signatures
keywords = [
    b"PyInstaller", b"_MEIPASS", b"python", b"nuitka", b"electron", b"app.asar", 
    b"V8", b"Unity", b"Unreal", b"Godot", b"Flutter", b"Go build", b"rust_eh",
    b"C:\\", b"/home/", b"ghidra", b"key", b"license", b"auth", b"login", b"KeyAuth",
    b"Madium", b"madium", b"Medium", b"medium"
]

for kw in keywords:
    count = d.count(kw)
    if count > 0:
        print(f"Found {kw}: {count} occurrences")

# Find URLs
urls = list(set(re.findall(rb"https?://[a-zA-Z0-9\.\-\/\_\?\=\&\%]+", d)))
print(f"Found {len(urls)} URLs. Sample:")
for u in urls[:25]:
    print("  ", u.decode(errors="ignore"))

# UTF-16 strings
utf16_matches = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", d)
print(f"Found {len(utf16_matches)} UTF-16 ASCII strings")
for m in utf16_matches[:10]:
    print("  UTF-16:", m.decode("utf-16le", errors="ignore"))
