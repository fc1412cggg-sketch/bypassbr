import ctypes
from ctypes import wintypes

psapi = ctypes.windll.psapi
kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF

psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.restype = wintypes.BOOL

psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

pid = 8136
hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
print("hProc:", hProc)

hMods = (wintypes.HMODULE * 1024)()
cbNeeded = wintypes.DWORD()

if psapi.EnumProcessModules(hProc, hMods, ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
    count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
    print(f"Module count: {count}")
    for i in range(count):
        mod = hMods[i]
        mod_name = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(hProc, mod, mod_name, 260)
        if mod_name.value.lower() == "deef.exe":
            base = mod
            print(f"Target Module: {mod_name.value} at Base: {hex(base)}")
            buf = ctypes.create_string_buffer(0x1000)
            bytesRead = ctypes.c_size_t()
            res = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(base), buf, 0x1000, ctypes.byref(bytesRead))
            print(f"Read Base {hex(base)}: Res={res}, Read={bytesRead.value}, Magic={buf.raw[:2]}")
            
            # Read 0x2170fa from base
            auth_call_addr = base + 0x2170fa
            buf64 = ctypes.create_string_buffer(32)
            res = kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(auth_call_addr), buf64, 32, ctypes.byref(bytesRead))
            if res:
                print(f"Memory at Base+0x2170fa ({hex(auth_call_addr)}): {buf64.raw[:bytesRead.value].hex()}")
            else:
                print(f"Failed to read auth call addr (err: {kernel32.GetLastError()})")
