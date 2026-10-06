import numpy as np

with open("dump_head.bin", "rb") as f:
    raw_data = f.read()

# Targets in .rdata
targets = {
    0x22e210: "input##key",
    0x22e260: "Failed to load core DLL",
    0x22e277: "Invalid key or expired license.",
    0x22e35b: "##login_btn",
    0x22e36b: "##login_btn_disabled",
    0x22e380: "login_btn_anim",
    0x22e388: "LOG IN",
    0x22e390: "Authenticating...",
    0x22e3a8: "VERIFYING",
    0x22e3b8: "LOGGED IN - OPENING...",
    0x22e430: "SELECT MODULE VERSION",
    0x22e4ec: "##exec_bypass_btn",
    0x22e5b8: "READY",
    0x22e658: "Software\\BypassEmulator",
}

# Scan .text: 0x1000 to 0x21c000
text = raw_data[0x1000:0x21c000]
# Use numpy int32 view
arr = np.frombuffer(raw_data[:0x220000], dtype=np.int32)

# For 7-byte instruction starting at i:
# disp32 is at raw_data[i+3 : i+7]
# rip = (i + 7)
# target = rip + disp32 => disp32 = target - (i + 7)

# Let's check offsets i in 0x1000..0x21b000
for instr_len in [6, 7]:
    for disp_off in [instr_len - 4]:
        # byte slice
        # we can unpack int32 directly
        pass

# Fast python single loop
import struct
disp_map = {}
for t_rva, name in targets.items():
    disp_map[t_rva] = name

results = []
for i in range(0x1000, 0x21b800):
    # check 7 byte (disp at i+3)
    b3 = raw_data[i+3:i+7]
    disp7 = int.from_bytes(b3, byteorder='little', signed=True)
    t7 = i + 7 + disp7
    if t7 in disp_map:
        results.append((i, 7, disp_map[t7], raw_data[i:i+7].hex()))

    # check 6 byte (disp at i+2)
    b2 = raw_data[i+2:i+6]
    disp6 = int.from_bytes(b2, byteorder='little', signed=True)
    t6 = i + 6 + disp6
    if t6 in disp_map:
        results.append((i, 6, disp_map[t6], raw_data[i:i+6].hex()))

print(f"Found {len(results)} xrefs:")
for rva, length, name, hx in results:
    print(f"0x{0x140000000+rva:x} (+{length}) -> {name} | bytes: {hx}")
