import pefile

pe = pefile.PE("deef.exe")
print(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
print(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
print(f"NumberOfSections: {pe.FILE_HEADER.NumberOfSections}")

for s in pe.sections:
    name = s.Name.decode(errors='ignore').strip('\x00')
    print(f"Section {name:8s}: VirtualAddress={hex(s.VirtualAddress):10s} Misc_VirtualSize={hex(s.Misc_VirtualSize):10s} SizeOfRawData={hex(s.SizeOfRawData):10s} PointerToRawData={hex(s.PointerToRawData):10s} Characteristics={hex(s.Characteristics)}")

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    print("\nImports:")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  DLL: {entry.dll.decode(errors='ignore')}")
        for imp in entry.imports[:5]:
            print(f"    {imp.name.decode(errors='ignore') if imp.name else imp.ordinal}")
        if len(entry.imports) > 5:
            print(f"    ... ({len(entry.imports)} total)")
