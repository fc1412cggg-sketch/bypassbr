import ctypes
from ctypes import wintypes
import psutil

# Find deef.exe process
pids = [p.info['pid'] for p in psutil.process_iter(['pid', 'name']) if p.info['name'] and 'deef' in p.info['name'].lower()]
print("deef PIDs:", pids)

if not pids:
    print("No deef process found")
    exit(0)

pid = pids[0]

PROCESS_ALL_ACCESS = 0x1F0FFF
kernel32 = ctypes.windll.kernel32

hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
print("hProcess:", hProcess)

# Get base address of deef.exe
# We can use EnumProcessModules
psapi = ctypes.windll.psapi
hMods = (wintypes.HMODULE * 1024)()
cbNeeded = wintypes.DWORD()
if psapi.EnumProcessModules(hProcess, ctypes.byref(hMods), ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
    count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
    print(f"Modules count: {count}")
    for i in range(min(5, count)):
        mod_name = ctypes.create_unicode_buffer(512)
        psapi.GetModuleBaseNameW(hProcess, hMods[i], mod_name, 512)
        print(f"  Module {mod_name.value} at {hex(hMods[i])}")
        
    main_base = hMods[0]
    print(f"Main module base: {hex(main_base)}")
    
    # Read first 0x1000 bytes at base
    buf = ctypes.create_string_buffer(0x1000)
    bytesRead = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(hProcess, ctypes.c_void_p(main_base), buf, 0x1000, ctypes.byref(bytesRead)):
        print(f"Read {bytesRead.value} bytes from main base. Magic: {buf.raw[:4]}")
    else:
        print("ReadProcessMemory failed:", kernel32.GetLastError())

kernel32.CloseHandle(hProcess)
