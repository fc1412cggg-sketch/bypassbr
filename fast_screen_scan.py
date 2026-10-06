import array

with open("dump_head.bin", "rb") as f:
    raw_data = f.read()

terms = [
    b"Software\\BypassEmulator",
    b"Dev: ",
    b"@naitik.dll",
    b"select_screen_anim",
    b"switch_screen",
    b"Invalid key or expired license",
    b"LOGGED IN - OPENING...",
    b"READY",
    b"Building V2 Module",
    b"FF MAX BYPASS COMPLETE",
    b"FREE FIRE BYPASS COMPLETE",
    b"EXECUTE INJECTION PROTOCOL",
    b"Locating ADB",
    b"##get_key_btn",
    b"https://discord.gg/B8dG35r2qx"
]

targets = {}
for t in terms:
    pos = 0
    while True:
        pos = raw_data.find(t, pos)
        if pos == -1:
            break
        targets[pos] = t.decode(errors='ignore')
        pos += 1

print(f"Found {len(targets)} targets:")
for p, name in targets.items():
    print(f"  {hex(p)}: {name}")

for align in range(4):
    buf = raw_data[align : 0x21c000 - ((0x21c000 - align) % 4)]
    arr = array.array('i')
    arr.frombytes(buf)
    
    for k, disp in enumerate(arr):
        disp_pos = align + k * 4
        # 7-byte instruction
        i7 = disp_pos - 3
        if 0x1000 <= i7 < 0x21c000:
            target7 = (i7 + 7) + disp
            if target7 in targets:
                op = raw_data[i7:i7+3]
                print(f"0x{0x140000000+i7:x} (7-byte, op={op.hex()}) -> {targets[target7]} (RVA {hex(target7)})")
        
        # 6-byte instruction
        i6 = disp_pos - 2
        if 0x1000 <= i6 < 0x21c000:
            target6 = (i6 + 6) + disp
            if target6 in targets:
                op = raw_data[i6:i6+2]
                print(f"0x{0x140000000+i6:x} (6-byte, op={op.hex()}) -> {targets[target6]} (RVA {hex(target6)})")
