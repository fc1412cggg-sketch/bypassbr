import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32

WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

def callback(hwnd, lparam):
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    
    cls_buff = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, cls_buff, 256)
    
    length = user32.GetWindowTextLengthW(hwnd)
    buff = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buff, length + 1)
    
    visible = bool(user32.IsWindowVisible(hwnd))
    if visible or buff.value:
        print(f"PID: {pid.value} HWND: {hex(hwnd)} Visible: {visible} Class: '{cls_buff.value}' Title: '{buff.value}'")
    return True

cb = WNDENUMPROC(callback)
user32.EnumWindows(cb, 0)
