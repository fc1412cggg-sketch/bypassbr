import pefile

pe = pefile.PE("deef.exe")

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode(errors='ignore').lower()
    for imp in entry.imports:
        name = imp.name.decode(errors='ignore') if imp.name else str(imp.ordinal)
        if any(k in dll_name for k in ['wininet', 'advapi']) or any(k in name.lower() for k in ['reg', 'crypt', 'http', 'url', 'thread', 'createfile']):
            print(f"{dll_name:20s} {name:30s} IAT RVA: {hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)}")
