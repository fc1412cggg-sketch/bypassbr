import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32

hwnds = []
def enum_windows_proc(hwnd, lParam):
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    length = user32.GetWindowTextLengthW(hwnd)
    buff = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buff, length + 1)
    
    cls_buff = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, cls_buff, 256)
    
    visible = user32.IsWindowVisible(hwnd)
    print(f"PID: {pid.value:5d} HWND: {hex(hwnd):10s} Visible: {visible} Class: '{cls_buff.value}' Title: '{buff.value}'")
    return True

EnumWindowsProcType = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
user32.EnumWindows(EnumWindowsProcType(enum_windows_proc), 0)
