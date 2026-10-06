import ctypes
from ctypes import wintypes
import struct
import time
import subprocess
import os

psapi = ctypes.windll.psapi
kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumProcessModules.restype = wintypes.BOOL
psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleBaseNameW.restype = wintypes.DWORD

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
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

def patch_fdrr_main():
    print("================================================================")
    print("        FDRR (DEEF) AUTO-PATCHER - DIRECT MAIN SCREEN           ")
    print("================================================================")
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    target_exe = os.path.join(current_dir, "deef.exe")
    
    # Check if deef.exe is running or launch it
    import psutil
    target_pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] and proc.info['name'].lower() == "deef.exe":
            target_pid = proc.info['pid']
            print(f"[+] Found running deef.exe (PID: {target_pid})")
            break
            
    if not target_pid:
        if not os.path.exists(target_exe):
            print(f"[!] Error: {target_exe} not found!")
            return
        print("[*] Launching deef.exe...")
        proc = subprocess.Popen([target_exe], cwd=current_dir)
        target_pid = proc.pid
        print(f"[+] Launched deef.exe (PID: {target_pid})")

    base_addr = None
    hProc = None
    print("[*] Waiting for process memory initialization...")
    for _ in range(60):
        time.sleep(0.5)
        hProc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not hProc:
            continue
            
        hMods = (wintypes.HMODULE * 1024)()
        cbNeeded = wintypes.DWORD()
        if psapi.EnumProcessModules(hProc, hMods, ctypes.sizeof(hMods), ctypes.byref(cbNeeded)):
            count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
            for i in range(count):
                mod = hMods[i]
                mod_name = ctypes.create_unicode_buffer(260)
                psapi.GetModuleBaseNameW(hProc, mod, mod_name, 260)
                if mod_name.value.lower() == "deef.exe":
                    base_addr = mod
                    break
                    
        if base_addr:
            test_addr = base_addr + 0x21a0b0
            test_buf = (ctypes.c_ubyte * 8)()
            bytesRead = ctypes.c_size_t()
            if kernel32.ReadProcessMemory(hProc, ctypes.c_void_p(test_addr), test_buf, 8, ctypes.byref(bytesRead)):
                if test_buf[0] == 0x40 and test_buf[1] == 0x53: # push rbx
                    print(f"[+] Unpacked! Base Address: {hex(base_addr)}")
                    break
        kernel32.CloseHandle(hProc)
        hProc = None

    if not hProc or not base_addr:
        print("[!] Failed to locate process memory.")
        return

    main_screen_addr = base_addr + 0x2194b0
    hook_target_addr = base_addr + 0x21a0b9

    # Alloc shellcode
    shellcode_mem = kernel32.VirtualAllocEx(hProc, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    
    str_key_addr = shellcode_mem + 0x200
    str_user_addr = shellcode_mem + 0x240

    # Prepare strings
    str_key = b"VIP-PREMIUM\x00\x00\x00\x00\x00" + struct.pack("<QQ", 11, 15)
    str_user = b"VIP Administrator\x00" + struct.pack("<QQ", 17, 15)

    bytesWritten = ctypes.c_size_t()
    kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(str_key_addr), str_key, len(str_key), ctypes.byref(bytesWritten))
    kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(str_user_addr), str_user, len(str_user), ctypes.byref(bytesWritten))

    # Construct direct jump shellcode
    code = bytearray()
    code += b"\x48\x89\xd9"                 # mov rcx, rbx (Context)
    code += b"\x48\xba" + struct.pack("<Q", str_user_addr) # mov rdx, str_user_addr
    code += b"\x49\xb8" + struct.pack("<Q", str_key_addr)  # mov r8, str_key_addr
    code += b"\x41\xb9\x01\x00\x00\x00"     # mov r9d, 1
    code += b"\x48\xb8" + struct.pack("<Q", main_screen_addr) # mov rax, main_screen_addr
    code += b"\xff\xd0"                     # call rax
    code += b"\x48\x83\xc4\x20"             # add rsp, 0x20
    code += b"\x5b"                         # pop rbx
    code += b"\xc3"                         # ret

    kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(shellcode_mem), bytes(code), len(code), ctypes.byref(bytesWritten))

    # Patch hook
    hook_patch = b"\x48\xb8" + struct.pack("<Q", shellcode_mem) + b"\xff\xe0\x90\x90"
    old_protect = wintypes.DWORD()
    kernel32.VirtualProtectEx(hProc, ctypes.c_void_p(hook_target_addr), len(hook_patch), PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect))
    kernel32.WriteProcessMemory(hProc, ctypes.c_void_p(hook_target_addr), hook_patch, len(hook_patch), ctypes.byref(bytesWritten))
    kernel32.VirtualProtectEx(hProc, ctypes.c_void_p(hook_target_addr), len(hook_patch), old_protect.value, ctypes.byref(old_protect))

    kernel32.CloseHandle(hProc)
    print("\n[✓] ========================================================")
    print("[✓]  PATCH เข้าหน้าใช้งานหลัก (MAIN SCREEN) สำเร็จเรียบร้อย!")
    print("[✓] ========================================================")

if __name__ == "__main__":
    patch_fdrr_main()
