import capstone
import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Look at 0x140218f00 to 0x140219400 (select_screen_anim)
# Let's print every instruction in select_screen_anim from 0x218f00 to 0x219430
start_rva = 0x218f00
end_rva = 0x219430

offset = start_rva
while offset < end_rva:
    insns = list(md.disasm(data[offset:offset+15], 0x140000000 + offset, count=1))
    if insns:
        i = insns[0]
        # Look for global variables RIP relative
        line = f"0x{i.address:08x}:  {i.bytes.hex():18s}  {i.mnemonic:8s} {i.op_str}"
        print(line)
        offset += i.size
    else:
        offset += 1
