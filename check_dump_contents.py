with open("dump_head.bin", "rb") as f:
    data = f.read()

# Check .text at offset 0x1000
text_slice = data[0x1000:0x1000+64]
print("data at 0x1000 (hex):", text_slice.hex())

# Check .rdata at offset 0x21d000
rdata_slice = data[0x21d000:0x21d000+100]
print("data at 0x21d000 (hex):", rdata_slice.hex())

# Extract ASCII and UTF-16 strings from dump_head.bin
import re
ascii_strs = [s.decode(errors='ignore') for s in re.findall(rb'[\x20-\x7e]{4,}', data)]
print(f"Total ASCII strings in dump_head: {len(ascii_strs)}")
print("First 30 strings:")
for s in ascii_strs[:30]:
    print(" ", s)

utf16_strs = [s.decode('utf-16le', errors='ignore') for s in re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)]
print(f"\nTotal UTF-16 strings in dump_head: {len(utf16_strs)}")
for s in utf16_strs[:30]:
    print(" ", s)
