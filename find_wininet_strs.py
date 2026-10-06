# Let's inspect WinINet calls in deef.exe using a memory scanner or API monitor
# Let's find where wininet functions are imported in dump_head.bin
with open("dump_head.bin", "rb") as f:
    data = f.read()

import re

for fn in [b"InternetOpenA", b"InternetOpenW", b"InternetConnectA", b"InternetConnectW", 
           b"HttpOpenRequestA", b"HttpOpenRequestW", b"HttpSendRequestA", b"HttpSendRequestW", 
           b"InternetReadFile", b"InternetCloseHandle", b"Software\\BypassEmulator"]:
    pos = 0
    while True:
        idx = data.find(fn, pos)
        if idx == -1:
            break
        print(f"Found {fn.decode('latin-1')} at RVA {hex(idx)} (VA: {hex(0x140000000+idx)})")
        pos = idx + len(fn)
