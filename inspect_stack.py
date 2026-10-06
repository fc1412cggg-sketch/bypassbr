import ctypes
from ctypes import wintypes
import struct

kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD
kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

pid = 8136
tid = 5036
base = 0x7ff6a98b0000

hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
hThread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)

kernel32.SuspendThread(hThread)

# Read stack around 0x14fcd8
buf = ctypes.create_string_buffer(0x1000)
bytesRead = ctypes.c_size_t()
kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(0x14f000), buf, 0x1000, ctypes.byref(bytesRead))

kernel32.ResumeThread(hThread)

print("Stack pointers:")
for offset in range(0, bytesRead.value - 8, 8):
    val = struct.unpack("<Q", buf.raw[offset:offset+8])[0]
    stack_addr = 0x14f000 + offset
    if base <= val <= base + 0x6000000:
        rva = val - base
        print(f"Stack 0x{stack_addr:x} -> Value: 0x{val:x} (Base + 0x{rva:x})")
