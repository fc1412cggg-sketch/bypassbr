import ctypes
from ctypes import wintypes

TH32CS_SNAPPROCESS = 0x00000002
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260)
    ]

kernel32 = ctypes.windll.kernel32
snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
pe32 = PROCESSENTRY32()
pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

pids = []
if kernel32.Process32First(snap, ctypes.byref(pe32)):
    while True:
        exe_name = pe32.szExeFile.decode(errors='ignore').lower()
        if 'deef' in exe_name:
            pids.append(pe32.th32ProcessID)
        if not kernel32.Process32Next(snap, ctypes.byref(pe32)):
            break
kernel32.CloseHandle(snap)

print("deef PIDs:", pids)
if not pids:
    exit(0)

pid = pids[0]
PROCESS_ALL_ACCESS = 0x1F0FFF
hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

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

kernel32.CloseHandle(hProcess)
