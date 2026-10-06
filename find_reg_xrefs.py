import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

targets = [0x22e020, 0x22e658, 0x22e648]

for t in targets:
    print(f"\nSearching xrefs to RVA {hex(t)}:")
    for i in range(0x1000, 0x21c000):
        # 7-byte RIP relative
        disp = t - (i + 7)
        if -0x80000000 <= disp <= 0x7fffffff:
            if data[i+3:i+7] == struct.pack("<i", disp):
                print(f"  7-byte ref from 0x{0x140000000+i:x}")
        # 6-byte RIP relative
        disp6 = t - (i + 6)
        if -0x80000000 <= disp6 <= 0x7fffffff:
            if data[i+2:i+6] == struct.pack("<i", disp6):
                print(f"  6-byte ref from 0x{0x140000000+i:x}")
