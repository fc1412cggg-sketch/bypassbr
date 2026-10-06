import capstone
import struct

with open("dump_head.bin", "rb") as f:
    raw = f.read()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Find all occurrences of "Software\BypassEmulator" or "select_screen" or "Dev:"
for name, s in [
    ("reg", b"Software\\BypassEmulator"),
    ("dev", b"@naitik.dll"),
    ("anim", b"select_screen_anim"),
    ("switch", b"switch_screen"),
    ("fail", b"Invalid key or expired license"),
    ("succ", b"LOGGED IN - OPENING..."),
    ("ready", b"READY"),
    ("v2", b"Building V2 Module"),
]:
    pos = raw.find(s)
    print(f"{name}: RVA {hex(pos)}")
    if pos != -1:
        # Search xrefs in .text
        for i in range(0x1000, 0x21c000):
            # 7 byte
            d7 = struct.unpack("<i", raw[i+3:i+7])[0]
            if (i + 7 + d7) == pos:
                print(f"  xref 7-byte from 0x{0x140000000+i:x}: {raw[i:i+7].hex()}")
            # 6 byte
            d6 = struct.unpack("<i", raw[i+2:i+6])[0]
            if (i + 6 + d6) == pos:
                print(f"  xref 6-byte from 0x{0x140000000+i:x}: {raw[i:i+6].hex()}")
