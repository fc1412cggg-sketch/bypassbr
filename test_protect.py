import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x40

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualProtectEx.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

pid = 8136
base = 0x7ff6a98b0000
target_addr = base + 0x2170fa

hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
oldProtect = wintypes.DWORD()

res_vp = kernel32.VirtualProtectEx(hProc, ctypes.c_void_p(target_addr), 32, PAGE_EXECUTE_READWRITE, ctypes.byref(oldProtect))
print(f"VirtualProtectEx: {res_vp}, OldProtect: {hex(oldProtect.value)}")

# Read original 16 bytes
buf = ctypes.create_string_buffer(16)
bytesRead = ctypes.c_size_t()
kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(target_addr), buf, 16, ctypes.byref(bytesRead))
print("Original bytes:", buf.raw.hex())

kernel32.CloseHandle(hProc)
