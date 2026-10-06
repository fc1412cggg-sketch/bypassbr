# Find cross references to strings in dump_head.bin
# In x64 PE, strings in .rdata (VA ~ 0x14022e000) are typically referenced via RIP-relative addressing: LEA reg, [RIP + disp32]

with open("dump_head.bin", "rb") as f:
    data = f.read()

image_base = 0x140000000

# String offsets:
# 0x22e268: "Failed to load core DLL." or "Invalid key or expired license."
# 0x22e2a0: "Authorize through your license key..."
# 0x22e378: "LOG IN"
# 0x22e390: "Authenticating..."
# 0x22e3b0: "LOGGED IN - OPENING..."

targets = {
    0x22e22e: "input##key",
    0x22e268: "Invalid key",
    0x22e378: "LOG IN",
    0x22e390: "Authenticating...",
    0x22e3b0: "LOGGED IN - OPENING...",
    0x22e5b8: "READY"
}

# Scan .text (0x1000 to 0x21c000) for RIP-relative LEA / MOV / etc.
print("Searching for RIP-relative references in .text section...")

for file_off in range(0x1000, 0x21c000 - 7):
    # RIP relative instruction is typically opcode (1-3 bytes) + 4-byte disp
    # Instruction end is file_off + instr_len
    # Target VA = image_base + instr_end + disp32
    # So disp32 = target_rva - instr_end_rva
    # We can check common instruction lengths (e.g. 7 bytes: 48 8d 05 xx xx xx xx or 48 8d 15 xx xx xx xx)
    for instr_len in [5, 6, 7, 8]:
        disp_bytes = data[file_off + instr_len - 4 : file_off + instr_len]
        import struct
        disp = struct.unpack("<i", disp_bytes)[0]
        next_rip = file_off + instr_len
        target_rva = next_rip + disp
        
        for t_rva, label in targets.items():
            if abs(target_rva - t_rva) < 32: # close match to target string
                print(f"Found ref to {label} (rva {hex(target_rva)}) at .text offset {hex(file_off)} (VA: {hex(image_base + file_off)}): {data[file_off:file_off+instr_len].hex()}")
