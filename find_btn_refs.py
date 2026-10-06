import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

# Let's search for string locations
strings = [
    b"##login_btn",
    b"##login_btn_disabled",
    b"login_btn_anim",
    b"Failed to load core DLL",
    b"Invalid key or expired license.",
    b"Software\\BypassEmulator",
    b"Username",
    b"https://",
    b"http://",
]

str_positions = {}
for s in strings:
    pos = 0
    while True:
        pos = data.find(s, pos)
        if pos == -1:
            break
        print(f"String '{s.decode(errors='ignore')}' found at RVA {hex(pos)}")
        str_positions.setdefault(s, []).append(pos)
        pos += 1

print("\nSearching code xrefs...")
for i in range(0x1000, 0x21c000):
    # check 7-byte RIP relative instructions: LEA, MOV, CMP, etc.
    # [REX] opcode [modrm] disp32
    for prefix_len in [2, 3]:
        disp = struct.unpack("<i", data[i+prefix_len:i+prefix_len+4])[0]
        target = (i + prefix_len + 4) + disp
        for s, positions in str_positions.items():
            for p in positions:
                if target == p:
                    print(f"Ref to '{s.decode(errors='ignore')}' from 0x{0x140000000+i:x} (opcode: {data[i:i+prefix_len+4].hex()})")
