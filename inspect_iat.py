import struct

with open("dump_head.bin", "rb") as f:
    data = f.read()

# Let's find wininet functions in IAT
# In PE header, let's find the Import Directory RVA and IAT RVA
# In 64-bit PE:
opt_hdr_offset = 0x3c
pe_offset = struct.unpack("<I", data[opt_hdr_offset:opt_hdr_offset+4])[0]
import_rva = struct.unpack("<I", data[pe_offset+0x90:pe_offset+0x94])[0]
import_size = struct.unpack("<I", data[pe_offset+0x94:pe_offset+0x98])[0]
iat_rva = struct.unpack("<I", data[pe_offset+0xd0:pe_offset+0xd4])[0]
iat_size = struct.unpack("<I", data[pe_offset+0xd4:pe_offset+0xd8])[0]

print(f"Import RVA: {hex(import_rva)}, IAT RVA: {hex(iat_rva)}")

# Scan imports
pos = import_rva
wininet_iat_thunks = {}
while pos < len(data):
    ilt_rva, time_date, forwarder, name_rva, ft_rva = struct.unpack("<IIIII", data[pos:pos+20])
    if ilt_rva == 0 and name_rva == 0:
        break
    dll_name = data[name_rva:data.find(b"\x00", name_rva)].decode("latin-1", errors="ignore")
    print(f"DLL: {dll_name}, FirstThunk (IAT): {hex(ft_rva)}")
    
    # Read thunks
    thunk_pos = ft_rva
    while True:
        val = struct.unpack("<Q", data[thunk_pos:thunk_pos+8])[0]
        if val == 0:
            break
        # If ordinal or hint/name:
        if val < len(data) - 2 and (val & 0x8000000000000000) == 0:
            func_name = data[val+2:data.find(b"\x00", val+2)].decode("latin-1", errors="ignore")
            print(f"  IAT RVA {hex(thunk_pos)} (VA: {hex(0x140000000+thunk_pos)}): {func_name}")
            if "wininet" in dll_name.lower():
                wininet_iat_thunks[thunk_pos] = func_name
        thunk_pos += 8
    pos += 20
