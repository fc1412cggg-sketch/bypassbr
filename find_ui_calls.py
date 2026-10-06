import capstone
import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Look for calls to ImGui::NewFrame, ImGui::Render, or calls to 0x14020f... and 0x140214...
# Let's search in .text (0x1000 - 0x21c000) for calls (E8 rel32) to 0x140214... (Login UI) or 0x140219...
targets = [0x214000, 0x214700, 0x214800, 0x214a50, 0x218f00, 0x219000, 0x216d00]

print("Searching for calls to screen renderers...")
for i in range(0x1000, 0x21c000):
    if data[i] == 0xe8:
        rel = struct.unpack("<i", data[i+1:i+5])[0]
        target_rva = (i + 5) + rel
        if 0x213000 <= target_rva <= 0x21a000:
            print(f"Call from 0x{0x140000000+i:x} to 0x{0x140000000+target_rva:x}")
