import ctypes
from ctypes import wintypes
import capstone

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
target_addr = base + 0x8b3be4
buf = ctypes.create_string_buffer(64)
bytesRead = ctypes.c_size_t()
kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(target_addr), buf, 64, ctypes.byref(bytesRead))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for insn in md.disasm(buf.raw[:bytesRead.value], target_addr):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
