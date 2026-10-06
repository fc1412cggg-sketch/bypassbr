import pefile

pe = pefile.PE("dump_head.bin")

wininet_imports = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode(errors='ignore').lower()
    if 'wininet' in dll_name:
        for imp in entry.imports:
            print(f"Wininet func: {imp.name.decode(errors='ignore')} at IAT RVA: {hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)}")
            wininet_imports[imp.address - pe.OPTIONAL_HEADER.ImageBase] = imp.name.decode(errors='ignore')
    if 'advapi32' in dll_name or 'kernel32' in dll_name:
        for imp in entry.imports:
            name = imp.name.decode(errors='ignore') if imp.name else ""
            if any(k in name.lower() for k in ['reg', 'crypt', 'http', 'url', 'thread', 'createfile']):
                print(f"{dll_name} func: {name} at IAT RVA: {hex(imp.address - pe.OPTIONAL_HEADER.ImageBase)}")
