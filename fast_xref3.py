import array

with open("dump_head.bin", "rb") as f:
    raw_data = f.read()

targets = {
    0x22e210: "input##key",
    0x22e260: "Failed to load core DLL",
    0x22e277: "Invalid key or expired license.",
    0x22e35b: "##login_btn",
    0x22e36b: "##login_btn_disabled",
    0x22e380: "login_btn_anim",
    0x22e388: "LOG IN",
    0x22e390: "Authenticating...",
    0x22e3a8: "VERIFYING",
    0x22e3b8: "LOGGED IN - OPENING...",
    0x22e430: "SELECT MODULE VERSION",
    0x22e4ec: "##exec_bypass_btn",
    0x22e5b8: "READY",
    0x22e658: "Software\\BypassEmulator",
}

# Scan with array.array for maximum speed
# int32 array aligned at byte offset 0, 1, 2, 3
for align in range(4):
    buf = raw_data[align : 0x21c000 - ((0x21c000 - align) % 4)]
    arr = array.array('i')
    arr.frombytes(buf)
    
    # arr[k] corresponds to int32 at byte offset (align + k*4)
    # If 7-byte instruction starts at i, disp is at i+3:
    # so align + k*4 = i + 3 => i = align + k*4 - 3
    # target = (i + 7) + disp = (align + k*4 + 4) + disp
    # If 6-byte instruction starts at i, disp is at i+2:
    # so align + k*4 = i + 2 => i = align + k*4 - 2
    # target = (i + 6) + disp = (align + k*4 + 4) + disp
    for k, disp in enumerate(arr):
        disp_pos = align + k * 4
        # Case 7-byte instruction:
        i7 = disp_pos - 3
        if 0x1000 <= i7 < 0x21c000:
            target7 = (i7 + 7) + disp
            if target7 in targets:
                op = raw_data[i7:i7+3]
                print(f"0x{0x140000000+i7:x} (7-byte, op={op.hex()}) -> {targets[target7]} (RVA {hex(target7)})")
        
        # Case 6-byte instruction:
        i6 = disp_pos - 2
        if 0x1000 <= i6 < 0x21c000:
            target6 = (i6 + 6) + disp
            if target6 in targets:
                op = raw_data[i6:i6+2]
                print(f"0x{0x140000000+i6:x} (6-byte, op={op.hex()}) -> {targets[target6]} (RVA {hex(target6)})")
