"""Login Key Patcher (Python mirror of LoginKeyPatcher.cs) — deef.exe bypass.

Usage:
    python login_key_patch.py [any|auto|custom] [key] [username]

    any     : กรอก key อะไรก็ได้ (ยาว > 0) -> เข้าหน้าหลักทันที [default]
    auto    : ข้ามหน้า login ไปหน้าหลักเลย
    custom  : ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนพิมพ์เล็ก/ใหญ่)

    python login_key_patch.py --restore   : คืนค่า hook เดิม

Requires: Windows 64-bit Python, no third-party packages.
"""
import ctypes
from ctypes import wintypes
import struct
import sys
import time
import subprocess
import os

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
TH32CS_SNAPPROCESS = 0x2

RVA_LOGIN_SCREEN = 0x214370
RVA_MAIN_SCREEN = 0x2194B0
RVA_WRAPPER = 0x21A0B0
RVA_HOOK = 0x21A0B9
HOOK_LEN = 14

LAYOUT_USER_STR = 0x300
LAYOUT_KEY_STR = 0x320
LAYOUT_EXPECT = 0x340
LAYOUT_USER_LONG = 0x3C0
LAYOUT_KEY_LONG = 0x400

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
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
kernel32.Process32NextW.restype = wintypes.BOOL


def find_pid(name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value:
        return None
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
        while True:
            if pe.szExeFile.lower() == name.lower():
                pid = pe.th32ProcessID
                break
            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                break
    kernel32.CloseHandle(snap)
    return pid


def rpm(h, addr, size):
    buf = (ctypes.c_ubyte * size)()
    done = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(done)):
        return None
    return bytes(buf[:done.value])


def wpm(h, addr, data):
    done = ctypes.c_size_t()
    return bool(kernel32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(done)))


def get_base(h, mod_name):
    mods = (wintypes.HMODULE * 1024)()
    need = wintypes.DWORD()
    if psapi.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(need)):
        for i in range(need.value // ctypes.sizeof(wintypes.HMODULE)):
            name = ctypes.create_unicode_buffer(260)
            psapi.GetModuleBaseNameW(h, mods[i], name, 260)
            if name.value.lower() == mod_name.lower():
                return mods[i]
    return None


# ---------------- shellcode builders ----------------

def prologue():
    c = bytearray()
    c += b"\x53"                                     # push rbx
    c += b"\x56"                                     # push rsi
    c += b"\x57"                                     # push rdi
    c += b"\x48\x83\xec\x20"                         # sub rsp, 0x20
    c += b"\x48\x89\xcb"                             # mov rbx, rcx
    c += b"\x48\x8d\xb3\xb8\x01\x00\x00"             # lea rsi, [rbx+0x1B8]
    c += b"\x48\x83\xbb\xd0\x01\x00\x00\x0f"         # cmp [rbx+0x1D0], 15
    c += b"\x76\x07"                                 # jbe +7
    c += b"\x48\x8b\xb3\xb8\x01\x00\x00"             # mov rsi, [rbx+0x1B8]
    return c


def epilogue(c):
    c += b"\x48\x83\xc4\x20"                         # add rsp, 0x20
    c += b"\x5f\x5e\x5b\xc3"                         # pop rdi/rsi/rbx; ret


def call_login(c, login_screen):
    c += b"\x48\x89\xd9"                             # mov rcx, rbx
    c += b"\x48\xb8" + struct.pack("<Q", login_screen)
    c += b"\xff\xd0"                                 # call rax
    epilogue(c)


def call_main_pass(c, fake_user, main_screen):
    c += b"\x48\x89\xd9"                             # mov rcx, rbx
    c += b"\x48\xba" + struct.pack("<Q", fake_user)  # mov rdx, fakeUser
    c += b"\x4c\x8d\x83\xb8\x01\x00\x00"             # lea r8, [rbx+0x1B8] (typed key)
    c += b"\x41\xb9\x01\x00\x00\x00"                 # mov r9d, 1
    c += b"\x48\xb8" + struct.pack("<Q", main_screen)
    c += b"\xff\xd0"                                 # call rax
    epilogue(c)


def call_main_fake(c, fake_user, fake_key, main_screen):
    c += b"\x48\x89\xd9"
    c += b"\x48\xba" + struct.pack("<Q", fake_user)
    c += b"\x49\xb8" + struct.pack("<Q", fake_key)   # mov r8, fakeKey
    c += b"\x41\xb9\x01\x00\x00\x00"
    c += b"\x48\xb8" + struct.pack("<Q", main_screen)
    c += b"\xff\xd0"
    epilogue(c)


def tolower_al(c):
    c += b"\x3c\x41\x72\x06\x3c\x5a\x77\x02\x0c\x20"


def tolower_dl(c):
    c += b"\x80\xfa\x41\x72\x06\x80\xfa\x5a\x77\x02\x80\xca\x20"


def build_any(login_screen, main_screen, fake_user):
    c = prologue()
    c += b"\x48\x8b\xbb\xc8\x01\x00\x00"             # mov rdi, [rbx+0x1C8]
    c += b"\x48\x85\xff"                             # test rdi, rdi
    jz = len(c); c += b"\x74\x00"
    jmpm = len(c); c += b"\xeb\x00"
    login_pos = len(c)
    call_login(c, login_screen)
    main_pos = len(c)
    call_main_pass(c, fake_user, main_screen)
    c[jz + 1] = (login_pos - (jz + 2)) & 0xFF
    c[jmpm + 1] = (main_pos - (jmpm + 2)) & 0xFF
    return bytes(c)


def build_auto(main_screen, fake_user, fake_key):
    c = prologue()
    call_main_fake(c, fake_user, fake_key, main_screen)
    return bytes(c)


def build_custom(login_screen, main_screen, fake_user, expect_addr, expect_len):
    c = prologue()
    c += b"\x4c\x8b\x93\xc8\x01\x00\x00"             # mov r10, [rbx+0x1C8]
    c += b"\x49\xbb" + struct.pack("<Q", expect_addr)
    c += b"\x49\x81\xfa" + struct.pack("<I", expect_len)
    jne1 = len(c); c += b"\x0f\x85\x00\x00\x00\x00"
    c += b"\x31\xc9"                                 # xor ecx, ecx
    loop = len(c)
    c += b"\x8a\x04\x0e"                             # mov al, [rsi+rcx]
    tolower_al(c)
    c += b"\x41\x8a\x14\x0b"                         # mov dl, [r11+rcx]
    tolower_dl(c)
    c += b"\x38\xc2"                                 # cmp dl, al
    jne2 = len(c); c += b"\x0f\x85\x00\x00\x00\x00"
    c += b"\xff\xc1"                                 # inc ecx
    c += b"\x44\x39\xd1"                             # cmp ecx, r10d
    jb = len(c); c += b"\x72\x00"
    jmpm = len(c); c += b"\xeb\x00"
    login_pos = len(c)
    call_login(c, login_screen)
    main_pos = len(c)
    call_main_pass(c, fake_user, main_screen)
    struct.pack_into("<i", c, jne1 + 2, login_pos - (jne1 + 6))
    struct.pack_into("<i", c, jne2 + 2, login_pos - (jne2 + 6))
    c[jb + 1] = (loop - (jb + 2)) & 0xFF
    c[jmpm + 1] = (main_pos - (jmpm + 2)) & 0xFF
    return bytes(c)


def std_string(text):
    raw = text.encode("ascii", errors="replace")
    if len(raw) <= 15:
        return raw + b"\x00" * (16 - len(raw)) + struct.pack("<QQ", len(raw), 15), None
    return struct.pack("<Q", 0) + b"\x00" * 8 + struct.pack("<QQ", len(raw), len(raw)), raw + b"\x00"


# ---------------- main ----------------

def main():
    print("=================================================")
    print("        LOGIN KEY PATCHER  (deef bypass)         ")
    print("=================================================")

    args = sys.argv[1:]
    if args and args[0] in ("--help", "-h", "/?"):
        print(__doc__)
        return
    mode = args[0].lower() if args else "any"
    if mode == "--restore":
        return do_restore()
    if mode not in ("any", "auto", "custom"):
        print("[!] mode ไม่ถูกต้อง"); print(__doc__); return
    key = args[1] if len(args) > 1 else ""
    username = args[2] if len(args) > 2 else "VIP User"
    if mode == "custom" and not key:
        print("[!] custom mode ต้องระบุ key"); return
    if len(key) > 128 or len(username) > 64:
        print("[!] key/username ยาวเกินไป"); return
    if mode == "auto" and not key:
        key = "VIP-PREMIUM"

    print(f"[*] Mode: {mode.upper()}  user=\"{username}\"" + (f"  key=\"{key}\"" if mode == "custom" else ""))

    cur = os.path.dirname(os.path.abspath(__file__))
    target_exe = os.path.join(cur, "deef.exe")

    pid = find_pid("deef.exe")
    if pid:
        print(f"[+] พบ deef.exe ที่รันอยู่ (PID: {pid})")
    else:
        if not os.path.exists(target_exe):
            print(f"[!] ไม่พบไฟล์ {target_exe}"); return
        print("[*] กำลังเปิด deef.exe...")
        p = subprocess.Popen([target_exe], cwd=cur)
        pid = p.pid
        print(f"[+] เปิด deef.exe สำเร็จ (PID: {pid})")

    h = None
    base = None
    print("[*] รอโปรแกรมโหลด/Unpack ใน memory...")
    for _ in range(60):
        time.sleep(0.5)
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h:
            continue
        base = get_base(h, "deef.exe")
        if base:
            t = rpm(h, base + RVA_WRAPPER, 8)
            if t and len(t) == 8 and t[0] == 0x40 and t[1] == 0x53:
                print(f"[+] Unpack เสร็จ! Base: {hex(base)}")
                break
        kernel32.CloseHandle(h)
        h = None
    if not h or not base:
        print("[!] หา Base Address ไม่เจอ (รัน Python แบบ Admin แล้วหรือยัง?)")
        return

    login_screen = base + RVA_LOGIN_SCREEN
    main_screen = base + RVA_MAIN_SCREEN
    hook_target = base + RVA_HOOK

    orig = rpm(h, hook_target, HOOK_LEN)
    if not orig or len(orig) != HOOK_LEN:
        print("[!] อ่าน memory ตรงจุด hook ไม่ได้")
        kernel32.CloseHandle(h)
        return
    print("[*] Original hook bytes: " + orig.hex("-"))
    if not (orig[0] == 0x48 and orig[1] == 0xB8):
        with open(os.path.join(cur, "hook_backup.bin"), "wb") as f:
            f.write(orig)
    else:
        print("[!] ดูเหมือนเคย patch จุดนี้แล้ว — จะ patch ทับ")

    mem = kernel32.VirtualAllocEx(h, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not mem:
        print("[!] VirtualAllocEx ล้มเหลว"); kernel32.CloseHandle(h); return

    user_struct, user_long = std_string(username)
    key_struct, key_long = std_string(key)
    if user_long:
        wpm(h, mem + LAYOUT_USER_LONG, user_long)
        user_struct = struct.pack("<Q", mem + LAYOUT_USER_LONG) + user_struct[8:]
    if key_long:
        wpm(h, mem + LAYOUT_KEY_LONG, key_long)
        key_struct = struct.pack("<Q", mem + LAYOUT_KEY_LONG) + key_struct[8:]
    wpm(h, mem + LAYOUT_USER_STR, user_struct)
    wpm(h, mem + LAYOUT_KEY_STR, key_struct)

    if mode == "auto":
        code = build_auto(main_screen, mem + LAYOUT_USER_STR, mem + LAYOUT_KEY_STR)
    elif mode == "custom":
        raw = key.lower().encode("ascii", errors="replace")
        wpm(h, mem + LAYOUT_EXPECT, raw)
        code = build_custom(login_screen, main_screen, mem + LAYOUT_USER_STR, mem + LAYOUT_EXPECT, len(raw))
    else:
        code = build_any(login_screen, main_screen, mem + LAYOUT_USER_STR)

    print(f"[*] Shellcode size: {len(code)} bytes @ {hex(mem)}")
    wpm(h, mem, code)

    patch = b"\x48\xb8" + struct.pack("<Q", mem) + b"\xff\xd0\x90\x90"
    old = wintypes.DWORD()
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(hook_target), len(patch), PAGE_EXECUTE_READWRITE, ctypes.byref(old))
    wpm(h, hook_target, patch)
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(hook_target), len(patch), old.value, ctypes.byref(old))

    back = rpm(h, hook_target, HOOK_LEN)
    kernel32.CloseHandle(h)
    if back != patch:
        print("[!] Verify hook ล้มเหลว!")
        return

    print()
    print("[OK] PATCH LOGIN KEY สำเร็จ!")
    if mode == "any":
        print("[OK] กรอก key อะไรก็ได้ (ห้ามว่าง) -> เข้าหน้าหลักทันที")
    elif mode == "auto":
        print("[OK] ข้ามหน้า login เข้าหน้าหลักอัตโนมัติ")
    else:
        print(f"[OK] ใช้ key \"{key}\" (ไม่สนพิมพ์เล็ก/ใหญ่) เพื่อเข้าใช้งาน")
    print()
    print("patch ค้างอยู่ใน deef จนปิดโปรแกรม (ไม่ต้องเปิด loader ค้างไว้ก็ได้)")


def do_restore():
    cur = os.path.dirname(os.path.abspath(__file__))
    bp = os.path.join(cur, "hook_backup.bin")
    if not os.path.exists(bp):
        print("[!] ไม่พบไฟล์ hook_backup.bin"); return
    orig = open(bp, "rb").read()
    if len(orig) != HOOK_LEN:
        print("[!] ไฟล์ backup ไม่ถูกต้อง"); return
    pid = find_pid("deef.exe")
    if not pid:
        print("[!] deef.exe ไม่ได้รันอยู่"); return
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    base = get_base(h, "deef.exe")
    if not base:
        print("[!] หา base ไม่เจอ"); kernel32.CloseHandle(h); return
    hook_target = base + RVA_HOOK
    old = wintypes.DWORD()
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(hook_target), HOOK_LEN, PAGE_EXECUTE_READWRITE, ctypes.byref(old))
    wpm(h, hook_target, orig)
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(hook_target), HOOK_LEN, old.value, ctypes.byref(old))
    kernel32.CloseHandle(h)
    print("[OK] คืนค่า hook เดิมเรียบร้อย")


if __name__ == "__main__":
    main()
