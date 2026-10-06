import struct

with open("deef.exe", "rb") as f:
    data = f.read()

opt_hdr_offset = 0x3c
pe_offset = struct.unpack("<I", data[opt_hdr_offset:opt_hdr_offset+4])[0]
num_sections = struct.unpack("<H", data[pe_offset+6:pe_offset+8])[0]
opt_hdr_size = struct.unpack("<H", data[pe_offset+20:pe_offset+22])[0]
sec_hdr_offset = pe_offset + 24 + opt_hdr_size

print(f"Num sections: {num_sections}")
sections = []
for i in range(num_sections):
    sh = data[sec_hdr_offset + i*40 : sec_hdr_offset + (i+1)*40]
    name = sh[:8].rstrip(b"\x00").decode("latin-1", errors="ignore")
    vsize, rva, raw_size, raw_offset = struct.unpack("<IIII", sh[8:24])
    sections.append((name, rva, vsize, raw_offset, raw_size))
    print(f"Section {name}: RVA {hex(rva)}, VSize {hex(vsize)}, RawOffset {hex(raw_offset)}, RawSize {hex(raw_size)}")

import_rva = struct.unpack("<I", data[pe_offset+0x90:pe_offset+0x94])[0]
print(f"Import RVA: {hex(import_rva)}")

def rva_to_offset(rva):
    for name, s_rva, vsize, raw_offset, raw_size in sections:
        if s_rva <= rva < s_rva + vsize:
            return raw_offset + (rva - s_rva)
    return None

import_offset = rva_to_offset(import_rva)
print(f"Import Offset: {hex(import_offset) if import_offset else 'None'}")

if import_offset:
    pos = import_offset
    while pos < len(data):
        ilt_rva, time_date, forwarder, name_rva, ft_rva = struct.unpack("<IIIII", data[pos:pos+20])
        if ilt_rva == 0 and name_rva == 0:
            break
        name_off = rva_to_offset(name_rva)
        dll_name = data[name_off:data.find(b"\x00", name_off)].decode("latin-1", errors="ignore")
        print(f"DLL: {dll_name}, FirstThunk (IAT): {hex(ft_rva)}")
        
        # Read thunks
        thunk_rva = ilt_rva if ilt_rva else ft_rva
        thunk_off = rva_to_offset(thunk_rva)
        while thunk_off and thunk_off < len(data) - 8:
            val = struct.unpack("<Q", data[thunk_off:thunk_off+8])[0]
            if val == 0:
                break
            if (val & 0x8000000000000000) == 0:
                fn_off = rva_to_offset(val)
                if fn_off:
                    func_name = data[fn_off+2:data.find(b"\x00", fn_off+2)].decode("latin-1", errors="ignore")
                    print(f"  {func_name}")
            thunk_off += 8
        pos += 20
