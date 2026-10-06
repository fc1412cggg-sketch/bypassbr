import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

t1 = 0x21a0b0
t2 = 0x21a0f0

print("Scanning full 8MB for ptrs and calls...")
for i in range(0, len(data) - 8):
    val = struct.unpack("<Q", data[i:i+8])[0]
    if val == (0x140000000 + t1):
        print(f"Absolute 64-bit ptr to t1 at RVA {hex(i)} (VA: {hex(0x140000000+i)})")
    if val == (0x140000000 + t2):
        print(f"Absolute 64-bit ptr to t2 at RVA {hex(i)} (VA: {hex(0x140000000+i)})")

    # 32-bit offset (RVA)
    val32 = struct.unpack("<I", data[i:i+4])[0]
    if val32 == t1:
        print(f"RVA32 to t1 at RVA {hex(i)}")
    if val32 == t2:
        print(f"RVA32 to t2 at RVA {hex(i)}")
