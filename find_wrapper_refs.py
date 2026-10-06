import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

# Let's search for references to 0x14021a0b0 (Login screen wrapper) and 0x14021a0f0 (Main bypass screen wrapper)
t1 = 0x21a0b0
t2 = 0x21a0f0

print("Searching references to screen wrappers...")
for i in range(0x1000, 0x21c000):
    # Absolute 8-byte pointer (e.g. function pointer table / vtable):
    if i <= len(data) - 8:
        val = struct.unpack("<Q", data[i:i+8])[0]
        if val == (0x140000000 + t1):
            print(f"Absolute 64-bit ptr to t1 (0x{0x140000000+t1:x}) at RVA {hex(i)}")
        if val == (0x140000000 + t2):
            print(f"Absolute 64-bit ptr to t2 (0x{0x140000000+t2:x}) at RVA {hex(i)}")

    # 4-byte call / jump
    if data[i] in (0xe8, 0xe9):
        rel = struct.unpack("<i", data[i+1:i+5])[0]
        target = (i + 5) + rel
        if target == t1:
            print(f"Call/Jmp to t1 (0x{0x140000000+t1:x}) from RVA {hex(i)}")
        if target == t2:
            print(f"Call/Jmp to t2 (0x{0x140000000+t2:x}) from RVA {hex(i)}")
