import ctypes
from ctypes import wintypes
import struct

psapi = ctypes.windll.psapi
kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF

psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.restype = wintypes.BOOL
psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

pid = 8136
hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

hMods = (wintypes.HMODULE * 1024)()
cbNeeded = wintypes.DWORD()
base = 0

if psapi.EnumProcessModules(hProc, hMods, ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
    count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
    for i in range(count):
        mod = hMods[i]
        mod_name = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(hProc, mod, mod_name, 260)
        if mod_name.value.lower() == "deef.exe":
            base = mod
            break

print(f"Base: {hex(base)}")
target_login_wrapper = base + 0x21a0b0
target_login_ui = base + 0x214370
target_main_wrapper = base + 0x21a0f0
target_main_ui = base + 0x2194b0

print(f"target_login_wrapper: {hex(target_login_wrapper)}")
print(f"target_login_ui: {hex(target_login_ui)}")
print(f"target_main_wrapper: {hex(target_main_wrapper)}")
print(f"target_main_ui: {hex(target_main_ui)}")

# Scan all committed readable/writable memory in deef.exe
mbi = MEMORY_BASIC_INFORMATION()
addr = 0
found_login_wrapper = []
found_login_ui = []

while kernel32.VirtualQueryEx(hProc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
    if mbi.State == 0x1000 and (mbi.Protect & 0xEE) != 0: # MEM_COMMIT and readable
        # Read region
        size = mbi.RegionSize
        if size > 0:
            # Read in chunks of 1MB
            chunk_size = min(size, 1024*1024*64)
            buf = ctypes.create_string_buffer(chunk_size)
            bytesRead = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(addr), buf, chunk_size, ctypes.byref(bytesRead)):
                raw = buf.raw[:bytesRead.value]
                # search for 8-byte pointer to target_login_wrapper
                p_bytes = struct.pack("<Q", target_login_wrapper)
                pos = 0
                while True:
                    idx = raw.find(p_bytes, pos)
                    if idx == -1:
                        break
                    match_addr = addr + idx
                    found_login_wrapper.append(match_addr)
                    print(f"Found ptr to Login Wrapper at {hex(match_addr)}")
                    pos = idx + 8
                    
                # search for 8-byte pointer to target_login_ui
                p_bytes_ui = struct.pack("<Q", target_login_ui)
                pos = 0
                while True:
                    idx = raw.find(p_bytes_ui, pos)
                    if idx == -1:
                        break
                    match_addr = addr + idx
                    found_login_ui.append(match_addr)
                    print(f"Found ptr to Login UI at {hex(match_addr)}")
                    pos = idx + 8
    addr += mbi.RegionSize
    if addr >= 0x7ffffffeffff:
        break

print(f"Total Login Wrapper refs: {len(found_login_wrapper)}")
print(f"Total Login UI refs: {len(found_login_ui)}")
