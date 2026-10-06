import ctypes
from ctypes import wintypes
import struct

PROCESS_ALL_ACCESS = 0x1F0FFF

kernel32 = ctypes.windll.kernel32

# Find deef.exe PID
import subprocess

out = subprocess.check_output('tasklist /FI "IMAGENAME eq deef.exe" /FO CSV', shell=True).decode()
print("Tasklist output:")
print(out)

pids = []
for line in out.strip().splitlines()[1:]:
    parts = [p.strip('"') for p in line.split('","')]
    if len(parts) >= 2 and parts[0].lower() == "deef.exe":
        pids.append(int(parts[1]))

print("Found PIDs:", pids)

for pid in pids:
    hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    print(f"\nPID {pid} Handle: {hProc}")
    if not hProc:
        continue
    
    # Check memory at 0x140000000
    base = 0x140000000
    buf = ctypes.create_string_buffer(0x1000)
    bytesRead = wintypes.ULONG()
    
    res = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(base), buf, 0x1000, ctypes.byref(bytesRead))
    print(f"Read Base 0x140000000: Res={res}, Read={bytesRead.value}")
    if res and bytesRead.value >= 2:
        print(f"Magic: {buf.raw[:2]}")
        
    # Check memory at 0x1402170fa
    auth_call_addr = 0x1402170fa
    buf64 = ctypes.create_string_buffer(32)
    res = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(auth_call_addr), buf64, 32, ctypes.byref(bytesRead))
    if res:
        print(f"Memory at 0x1402170fa: {buf64.raw[:bytesRead.value].hex()}")
    else:
        print(f"Failed to read 0x1402170fa (err: {kernel32.GetLastError()})")
        
    kernel32.CloseHandle(hProc)
