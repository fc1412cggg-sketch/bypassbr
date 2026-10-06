with open("dump_head.bin", "rb") as f:
    data = f.read()

target = data.find(b"Software\\BypassEmulator")
print(f"Software\\BypassEmulator at RVA: {hex(target)}")

# Search for any references to target or nearby bytes (0x22e658) in the whole dump_head.bin
import struct
for i in range(0, len(data) - 4):
    val = struct.unpack("<I", data[i:i+4])[0]
    # VA reference: 0x14022e658
    if val == (0x140000000 + target):
        print(f"Absolute VA ref at {hex(i)}")
    # RIP relative ref
    disp = target - (i + 4) # or i+7 etc
    # check 7-byte instruction
    if i >= 3:
        disp7 = target - (i + 4)
        if struct.unpack("<i", data[i:i+4])[0] == disp7:
            print(f"RIP disp7 ref at instr {hex(i-3)} (VA: {hex(0x140000000+i-3)})")
