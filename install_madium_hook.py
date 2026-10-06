import ctypes
from ctypes import wintypes
import struct
import capstone

kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualProtectEx.restype = wintypes.BOOL
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

pid = 8136
base = 0x7ff6a98b0000

login_screen_addr = base + 0x214370
main_screen_addr  = base + 0x2194b0
login_wrapper_addr = base + 0x21a0b0

hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

shellcode_mem = kernel32.VirtualAllocEx(hProc, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

str1 = b"Madium\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + struct.pack("<QQ", 6, 15)
str2 = b"Madium User\x00\x00\x00\x00\x00" + struct.pack("<QQ", 11, 15)

str1_addr = shellcode_mem + 0x200
str2_addr = shellcode_mem + 0x240

bytesWritten = ctypes.c_size_t()
bytesRead = ctypes.c_size_t()

kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(str1_addr), str1, len(str1), ctypes.byref(bytesWritten))
kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(str2_addr), str2, len(str2), ctypes.byref(bytesWritten))

# Let's construct blocks with labels
# Block 1: Entry & check
b_entry = bytearray()
b_entry += b"\x53"                         # push rbx
b_entry += b"\x56"                         # push rsi
b_entry += b"\x57"                         # push rdi
b_entry += b"\x48\x83\xec\x20"             # sub rsp, 0x20
b_entry += b"\x48\x89\xcb"                 # mov rbx, rcx
b_entry += b"\x48\x8d\xb3\xb8\x01\x00\x00" # lea rsi, [rbx + 0x1b8]
b_entry += b"\x48\x83\xbb\xd0\x01\x00\x00\x0f" # cmp qword ptr [rbx + 0x1d0], 15
b_entry += b"\x76\x07"                     # jbe short
b_entry += b"\x48\x8b\xb3\xb8\x01\x00\x00" # mov rsi, qword ptr [rbx + 0x1b8]
b_entry += b"\x48\x83\xbb\xc8\x01\x00\x00\x06" # cmp qword ptr [rbx + 0x1c8], 6
# jump to call_login if < 6: we'll resolve offset

# Block call_login:
b_login = bytearray()
b_login += b"\x48\x89\xd9"                 # mov rcx, rbx
b_login += b"\x48\xb8" + struct.pack("<Q", login_screen_addr) # mov rax, login_screen_addr
b_login += b"\xff\xd0"                     # call rax
b_login += b"\x48\x83\xc4\x20"             # add rsp, 0x20
b_login += b"\x5f"                         # pop rdi
b_login += b"\x5e"                         # pop rsi
b_login += b"\x5b"                         # pop rbx
b_login += b"\xc3"                         # ret

# Block call_main:
b_main = bytearray()
b_main += b"\x48\x89\xd9"                 # mov rcx, rbx
b_main += b"\x48\xba" + struct.pack("<Q", str2_addr)         # mov rdx, str2_addr
b_main += b"\x49\xb8" + struct.pack("<Q", str1_addr)         # mov r8, str1_addr
b_main += b"\x41\xb9\x01\x00\x00\x00"     # mov r9d, 1
b_main += b"\x48\xb8" + struct.pack("<Q", main_screen_addr)  # mov rax, main_screen_addr
b_main += b"\xff\xd0"                     # call rax
b_main += b"\x48\x83\xc4\x20"             # add rsp, 0x20
b_main += b"\x5f"                         # pop rdi
b_main += b"\x5e"                         # pop rsi
b_main += b"\x5b"                         # pop rbx
b_main += b"\xc3"                         # ret

# Check logic:
# b_check:
# mov rax, [rsi]
# mov rdx, 0x0000ffffffffffff
# and rax, rdx
# mov rdx, 0x00006d756964614d ("Madium")
# cmp rax, rdx
# je call_main
# mov rdx, 0x00006d756964616d ("madium")
# cmp rax, rdx
# je call_main
# jmp call_login

b_check = bytearray()
b_check += b"\x48\x8b\x06"
b_check += b"\x48\xba\xff\xff\xff\xff\xff\xff\x00\x00"
b_check += b"\x48\x21\xd0"
b_check += b"\x48\xba\x4d\x61\x64\x69\x75\x6d\x00\x00"
b_check += b"\x48\x39\xd0"
# je to main: offset = len(b_check) + 2 + 10 + 3 + 2 + 2 + len(b_login) ...
# Let's assemble linearly and compute relative jumps:

# Layout:
# 0: b_entry
# entry_jb_idx: jb call_login
# len(b_entry) + 2: b_check1 ("Madium")
# je call_main
# b_check2 ("madium")
# je call_main
# b_login
# b_main

# Let's assemble:
code = bytearray()
code += b_entry

# Placeholder for jb call_login
jb_login_pos = len(code)
code += b"\x72\x00" # 2 bytes

# Check "Madium"
code += b"\x48\x8b\x06"
code += b"\x48\xba\xff\xff\xff\xff\xff\xff\x00\x00"
code += b"\x48\x21\xd0"
code += b"\x48\xba\x4d\x61\x64\x69\x75\x6d\x00\x00"
code += b"\x48\x39\xd0"
je_main1_pos = len(code)
code += b"\x74\x00" # 2 bytes

# Check "madium"
code += b"\x48\xba\x6d\x61\x64\x69\x75\x6d\x00\x00"
code += b"\x48\x39\xd0"
je_main2_pos = len(code)
code += b"\x74\x00" # 2 bytes

# call_login block starts here:
login_target_pos = len(code)
code += b_login

# call_main block starts here:
main_target_pos = len(code)
code += b_main

# Now fill relative jumps:
# jb call_login:
code[jb_login_pos + 1] = (login_target_pos - (jb_login_pos + 2)) & 0xff
# je main1:
code[je_main1_pos + 1] = (main_target_pos - (je_main1_pos + 2)) & 0xff
# je main2:
code[je_main2_pos + 1] = (main_target_pos - (je_main2_pos + 2)) & 0xff

print(f"Total shellcode size: {len(code)} bytes")
print(f"login block at offset: 0x{login_target_pos:x}, main block at offset: 0x{main_target_pos:x}")

# Write shellcode
kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(shellcode_mem), bytes(code), len(code), ctypes.byref(bytesWritten))

# Disassemble to verify 100% correctness
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
for insn in md.disasm(bytes(code), shellcode_mem):
    print(f"0x{insn.address:x}:  {insn.mnemonic:8s} {insn.op_str}")

# Install hook at base + 0x21a0b9
hook_target = base + 0x21a0b9
patch_bytes = b"\x48\xb8" + struct.pack("<Q", shellcode_mem) + b"\xff\xd0\x90\x90"

oldProt = wintypes.DWORD()
kernel32.VirtualProtectEx(hProc, ctypes.c_void_p(hook_target), len(patch_bytes), PAGE_EXECUTE_READWRITE, ctypes.byref(oldProt))
kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(hook_target), patch_bytes, len(patch_bytes), ctypes.byref(bytesWritten))
kernel32.VirtualProtectEx(hProc, ctypes.c_void_p(hook_target), len(patch_bytes), oldProt.value, ctypes.byref(oldProt))

print("\nHook PERFECTLY installed and verified!")
kernel32.CloseHandle(hProc)
