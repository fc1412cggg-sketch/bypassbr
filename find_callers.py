import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

funcs = {
    0x214370: "Login screen UI",
    0x214db9: "214db9",
    0x2194b0: "Main bypass menu UI",
    0x21a0b0: "Login wrapper",
    0x21a0f0: "Main wrapper",
    0x20f950: "Key Input text box"
}

for rva, name in funcs.items():
    print(f"\nCallers of {name} (0x{0x140000000+rva:x}):")
    for i in range(0x1000, 0x21c000):
        if data[i] in (0xe8, 0xe9):
            rel = struct.unpack("<i", data[i+1:i+5])[0]
            target = (i + 5) + rel
            if target == rva:
                print(f"  from 0x{0x140000000+i:x} (type {'CALL' if data[i]==0xe8 else 'JMP'})")
