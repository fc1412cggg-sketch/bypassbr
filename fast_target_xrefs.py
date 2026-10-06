import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

# Build set of target offsets
targets = {}
for s in [b"##login_btn", b"##login_btn_disabled", b"login_btn_anim", b"Failed to load core DLL", 
          b"Invalid key or expired license.", b"Software\\BypassEmulator", b"Username",
          b"Dev: @naitik.dll", b"switch_screen", b"select_screen_anim", b"input##key",
          b"##exec_bypass_btn", b"FREE FIRE MAX", b"FREE FIRE"]:
    pos = 0
    while True:
        pos = data.find(s, pos)
        if pos == -1:
            break
        targets[pos] = s.decode(errors='ignore')
        pos += 1

print(f"Target RVAs: { {hex(k): v for k, v in targets.items()} }")

# Target RVA = rip + disp32
# If instruction ends at `end_pos` (4 to 8 bytes), disp32 = target - end_pos
# That means bytes at (end_pos - 4 : end_pos) must equal struct.pack("<i", target - end_pos)
# We can search for the exact 4-byte sequence for each target!

for target, name in targets.items():
    print(f"\nScanning xrefs for '{name}' (RVA {hex(target)}):")
    # For every possible instruction ending pos in .text (0x1000 .. 0x21c000):
    # disp = target - end_pos
    # Let's check common instruction prefixes:
    # 48 8d 05 (7 byte, end_pos = i+7, disp at i+3) -> target - (i+7)
    # 48 8d 0d (7 byte)
    # 48 8d 15 (7 byte)
    # 4c 8d 05 (7 byte)
    # 4c 8d 0d (7 byte)
    # etc.
    for i in range(0x1000, 0x21c000):
        # 7-byte instruction
        disp = target - (i + 7)
        if -0x80000000 <= disp <= 0x7fffffff:
            b = struct.pack("<i", disp)
            if data[i+3:i+7] == b:
                print(f"  7-byte ref from 0x{0x140000000+i:x} (bytes: {data[i:i+7].hex()})")
        # 6-byte instruction (e.g. 8d 05 xx xx xx xx)
        disp6 = target - (i + 6)
        if -0x80000000 <= disp6 <= 0x7fffffff:
            b6 = struct.pack("<i", disp6)
            if data[i+2:i+6] == b6:
                print(f"  6-byte ref from 0x{0x140000000+i:x} (bytes: {data[i:i+6].hex()})")
