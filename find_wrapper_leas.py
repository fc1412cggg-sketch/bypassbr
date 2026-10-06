import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

targets = {
    0x21a0b0: "Login wrapper",
    0x21a0f0: "Main wrapper",
    0x214370: "Login UI",
    0x2194b0: "Main UI",
}

for t_rva, name in targets.items():
    print(f"\nSearching LEA/MOV RIP-relative to {name} (0x{0x140000000+t_rva:x}):")
    for i in range(0x1000, 0x21c000):
        # 7-byte RIP relative
        disp = t_rva - (i + 7)
        if -0x80000000 <= disp <= 0x7fffffff:
            if data[i+3:i+7] == struct.pack("<i", disp):
                print(f"  7-byte ref from 0x{0x140000000+i:x} (op: {data[i:i+7].hex()})")
        # 6-byte RIP relative
        disp6 = t_rva - (i + 6)
        if -0x80000000 <= disp6 <= 0x7fffffff:
            if data[i+2:i+6] == struct.pack("<i", disp6):
                print(f"  6-byte ref from 0x{0x140000000+i:x} (op: {data[i:i+6].hex()})")
