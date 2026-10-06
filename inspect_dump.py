with open("dump_head.bin", "rb") as f:
    data = f.read(1024)
    print("dump_head magic:", data[:16])

try:
    import pefile
    pe = pefile.PE("dump_head.bin")
    print("dump_head is PE!")
    print("Entry point:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    for s in pe.sections:
        name = s.Name.decode(errors='ignore').strip('\x00')
        print(f"Section {name}: VirtualAddress={hex(s.VirtualAddress)} SizeOfRawData={hex(s.SizeOfRawData)}")
except Exception as e:
    print("dump_head pefile error:", e)
