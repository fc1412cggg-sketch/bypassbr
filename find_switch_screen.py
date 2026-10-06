with open("dump_head.bin", "rb") as f:
    data = f.read()

target = data.find(b"switch_screen")
print(f"switch_screen at RVA {hex(target)}")

# Search for any references to switch_screen
import struct
for i in range(0, len(data) - 4):
    val = struct.unpack("<I", data[i:i+4])[0]
    if val == (0x140000000 + target) or val == target:
        print(f"Match at {hex(i)}")
    disp = target - (i + 4)
    if struct.unpack("<i", data[i:i+4])[0] == disp:
        print(f"RIP relative disp match at {hex(i)}")
