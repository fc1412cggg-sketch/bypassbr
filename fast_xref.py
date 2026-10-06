import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

# Exact string offsets
target_strings = {
    b"input##key": None,
    b"Invalid key or expired license": None,
    b"LOG IN": None,
    b"Authenticating...": None,
    b"VERIFYING": None,
    b"LOGGED IN - OPENING...": None,
    b"Authentication failed.": None,
    b"Software\\BypassEmulator": None,
}

for s in target_strings:
    pos = data.find(s)
    target_strings[s] = pos
    print(f"String '{s.decode()}' at RVA {hex(pos)}")

# Check for references
# Target RVA = instr_end + disp32 => disp32 = target_rva - instr_end
# instr_end = file_off + 7 (e.g. 48 8d ?? xx xx xx xx or 4c 8d ?? xx xx xx xx)
print("\nSearching LEA references...")
for s, rva in target_strings.items():
    if rva is None or rva == -1:
        continue
    # Let's test standard LEA opcodes:
    # 48 8d 05 (rax), 48 8d 0d (rcx), 48 8d 15 (rdx), 48 8d 1d (rbx), 48 8d 2d (rbp), 48 8d 35 (rsi), 48 8d 3d (rdi)
    # 4c 8d 05 (r8), 4c 8d 0d (r9), 4c 8d 15 (r10), etc.
    for reg in range(16):
        # 7-byte LEA: [48/4c] 8d [modrm] disp32
        # Let's just scan all 7-byte windows where data[i:i+2] in [b'\x48\x8d', b'\x4c\x8d']
        pass

for i in range(0x1000, 0x21c000):
    if data[i:i+2] in (b'\x48\x8d', b'\x4c\x8d', b'\x48\x8b', b'\x4c\x8b'):
        disp = struct.unpack("<i", data[i+3:i+7])[0]
        target = (i + 7) + disp
        for s, rva in target_strings.items():
            if target == rva:
                print(f"Found ref to '{s.decode()}' at .text {hex(i)} (VA: {hex(0x140000000 + i)}) -> instr: {data[i:i+7].hex()}")
