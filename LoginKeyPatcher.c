/* LoginKeyPatcher — native Windows x64 single-file patcher for deef.exe.
 *
 * Build (cross-compile on Linux with zig):
 *   python -m ziglang cc -target x86_64-windows-gnu -O2 -o LoginKeyPatcher.exe LoginKeyPatcher.c -lpsapi
 *
 * Usage:
 *   LoginKeyPatcher.exe [any|auto|custom] [key] [username]
 *   LoginKeyPatcher.exe --restore
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "sc_build.h"

#define RVA_LOGIN_SCREEN 0x214370ull
#define RVA_MAIN_SCREEN  0x2194B0ull
#define RVA_WRAPPER      0x21A0B0ull
#define RVA_HOOK         0x21A0B9ull
#define HOOK_LEN 14

#define LAYOUT_USER_STR  0x300
#define LAYOUT_KEY_STR   0x320
#define LAYOUT_EXPECT    0x340
#define LAYOUT_USER_LONG 0x3C0
#define LAYOUT_KEY_LONG  0x400

static void usage(void) {
    printf("Usage:\n");
    printf("  LoginKeyPatcher.exe [mode] [key] [username]\n\n");
    printf("  mode:\n");
    printf("    any     = กรอก key อะไรก็ได้ (ยาว > 0) เข้าหน้าหลักทันที [default]\n");
    printf("    auto    = ข้ามหน้า login ไปหน้าหลักเลย ไม่ต้องกรอกอะไร\n");
    printf("    custom  = ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนตัวพิมพ์เล็ก/ใหญ่)\n\n");
    printf("  Examples:\n");
    printf("    LoginKeyPatcher.exe any\n");
    printf("    LoginKeyPatcher.exe auto\n");
    printf("    LoginKeyPatcher.exe custom MySecret123 \"VIP User\"\n");
    printf("    LoginKeyPatcher.exe --restore   (คืนค่า hook เดิม)\n\n");
}

static DWORD find_pid(const char *name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    wchar_t wname[260];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 260);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, wname) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static uint64_t get_module_base(HANDLE h, const char *name) {
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(h, mods, sizeof(mods), &needed)) return 0;
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;
    for (DWORD i = 0; i < count; i++) {
        char buf[260];
        if (GetModuleBaseNameA(h, mods[i], buf, sizeof(buf)) && _stricmp(buf, name) == 0)
            return (uint64_t)(uintptr_t)mods[i];
    }
    return 0;
}

static int rpm(HANDLE h, uint64_t addr, void *buf, SIZE_T size) {
    SIZE_T done = 0;
    return ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, buf, size, &done) && done == size;
}

static int wpm(HANDLE h, uint64_t addr, const void *buf, SIZE_T size) {
    SIZE_T done = 0;
    return WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, buf, size, &done) && done == size;
}

static void strtolower_ascii(char *d, const char *s, size_t max) {
    size_t i;
    for (i = 0; i + 1 < max && s[i]; i++) {
        char c = s[i];
        d[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    d[i] = 0;
}

static int do_restore(void) {
    uint8_t orig[HOOK_LEN];
    FILE *f = fopen("hook_backup.bin", "rb");
    if (!f) { printf("[!] ไม่พบไฟล์ hook_backup.bin\n"); return 1; }
    size_t n = fread(orig, 1, HOOK_LEN, f);
    fclose(f);
    if (n != HOOK_LEN) { printf("[!] ไฟล์ backup ไม่ถูกต้อง\n"); return 1; }

    DWORD pid = find_pid("deef.exe");
    if (!pid) { printf("[!] deef.exe ไม่ได้รันอยู่\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) { printf("[!] OpenProcess ล้มเหลว err=%lu\n", GetLastError()); return 1; }
    uint64_t base = get_module_base(h, "deef.exe");
    if (!base) { printf("[!] หา base ไม่เจอ\n"); CloseHandle(h); return 1; }

    uint64_t hook = base + RVA_HOOK;
    DWORD old = 0;
    VirtualProtectEx(h, (LPVOID)(uintptr_t)hook, HOOK_LEN, PAGE_EXECUTE_READWRITE, &old);
    wpm(h, hook, orig, HOOK_LEN);
    VirtualProtectEx(h, (LPVOID)(uintptr_t)hook, HOOK_LEN, old, &old);
    CloseHandle(h);
    printf("[OK] คืนค่า hook เดิมเรียบร้อย\n");
    return 0;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(65001); /* UTF-8 for Thai text */
    SetConsoleTitleA("Login Key Patcher - deef bypass");

    printf("=================================================\n");
    printf("        LOGIN KEY PATCHER  (deef bypass)         \n");
    printf("=================================================\n");

    const char *mode = "any";
    char key[129] = {0};
    char username[65] = "VIP User";

    if (argc > 1) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "/?") == 0) {
            usage(); return 0;
        }
        if (strcmp(argv[1], "--restore") == 0) return do_restore();
        if (strcmp(argv[1], "any") == 0 || strcmp(argv[1], "auto") == 0 || strcmp(argv[1], "custom") == 0) {
            mode = argv[1];
        } else {
            printf("[!] mode ไม่ถูกต้อง\n"); usage(); return 1;
        }
    }
    if (argc > 2) { strncpy(key, argv[2], sizeof(key) - 1); }
    if (argc > 3) { strncpy(username, argv[3], sizeof(username) - 1); username[sizeof(username)-1] = 0; }

    if (strcmp(mode, "custom") == 0 && key[0] == 0) {
        printf("[!] custom mode ต้องระบุ key ด้วย\n"); usage(); return 1;
    }
    if (strcmp(mode, "auto") == 0 && key[0] == 0) strcpy(key, "VIP-PREMIUM");

    printf("[*] Mode: %s  user=\"%s\"%s%s%s\n", mode, username,
           strcmp(mode, "custom") == 0 ? "  key=\"" : "",
           strcmp(mode, "custom") == 0 ? key : "",
           strcmp(mode, "custom") == 0 ? "\"" : "");

    /* ---- find or launch deef.exe ---- */
    char exe_dir[512] = {0};
    GetModuleFileNameA(NULL, exe_dir, sizeof(exe_dir));
    char *slash = strrchr(exe_dir, '\\');
    if (slash) *slash = 0; else strcpy(exe_dir, ".");
    char target_exe[600];
    _snprintf(target_exe, sizeof(target_exe), "%s\\deef.exe", exe_dir);

    DWORD pid = find_pid("deef.exe");
    if (pid) {
        printf("[+] พบ deef.exe ที่รันอยู่ (PID: %lu)\n", (unsigned long)pid);
    } else {
        DWORD attr = GetFileAttributesA(target_exe);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            printf("[!] ไม่พบไฟล์ deef.exe ใน %s\n", exe_dir);
            printf("กด Enter เพื่อออก..."); getchar();
            return 1;
        }
        printf("[*] กำลังเปิด deef.exe...\n");
        STARTUPINFOA si; PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        char cmd[620];
        _snprintf(cmd, sizeof(cmd), "\"%s\"", target_exe);
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, exe_dir, &si, &pi)) {
            printf("[!] เปิด deef.exe ไม่ได้ err=%lu\n", GetLastError());
            return 1;
        }
        pid = pi.dwProcessId;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        printf("[+] เปิด deef.exe สำเร็จ (PID: %lu)\n", (unsigned long)pid);
    }

    /* ---- wait for unpack + get base ---- */
    HANDLE h = NULL;
    uint64_t base = 0;
    printf("[*] รอโปรแกรมโหลด/Unpack ใน memory...\n");
    for (int retry = 0; retry < 60; retry++) {
        Sleep(500);
        if (!find_pid("deef.exe")) { printf("[!] โปรแกรมเป้าหมายถูกปิด\n"); return 1; }
        h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) continue;
        base = get_module_base(h, "deef.exe");
        if (base) {
            uint8_t t[8];
            if (rpm(h, base + RVA_WRAPPER, t, 8) && t[0] == 0x40 && t[1] == 0x53) {
                printf("[+] Unpack เสร็จ! Base: 0x%llX\n", (unsigned long long)base);
                break;
            }
        }
        CloseHandle(h);
        h = NULL;
    }
    if (!h || !base) {
        printf("[!] หา Base Address ของ deef.exe ไม่เจอ (รันแบบ Admin แล้วหรือยัง?)\n");
        printf("กด Enter เพื่อออก..."); getchar();
        return 1;
    }

    uint64_t login_screen = base + RVA_LOGIN_SCREEN;
    uint64_t main_screen  = base + RVA_MAIN_SCREEN;
    uint64_t hook_target  = base + RVA_HOOK;

    /* ---- backup original hook bytes ---- */
    uint8_t orig[HOOK_LEN];
    if (!rpm(h, hook_target, orig, HOOK_LEN)) {
        printf("[!] อ่าน memory ตรงจุด hook ไม่ได้\n");
        CloseHandle(h);
        return 1;
    }
    printf("[*] Original hook bytes: ");
    for (int i = 0; i < HOOK_LEN; i++) printf("%02X%s", orig[i], i + 1 < HOOK_LEN ? "-" : "\n");
    if (orig[0] == 0x48 && orig[1] == 0xB8) {
        printf("[!] ดูเหมือนเคย patch จุดนี้แล้ว — จะ patch ทับ\n");
    } else {
        FILE *bf = fopen("hook_backup.bin", "wb");
        if (bf) { fwrite(orig, 1, HOOK_LEN, bf); fclose(bf); }
    }

    /* ---- allocate RWX ---- */
    uint64_t mem = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[!] VirtualAllocEx ล้มเหลว err=%lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }
    uint64_t user_str = mem + LAYOUT_USER_STR;
    uint64_t key_str  = mem + LAYOUT_KEY_STR;
    uint64_t expect   = mem + LAYOUT_EXPECT;
    uint64_t user_lng = mem + LAYOUT_USER_LONG;
    uint64_t key_lng  = mem + LAYOUT_KEY_LONG;

    uint8_t st[32], longbuf[256];
    sc_std_string(st, username, user_lng, longbuf);
    if (strlen(username) > 15) wpm(h, user_lng, longbuf, strlen(username) + 1);
    wpm(h, user_str, st, 32);

    sc_std_string(st, key, key_lng, longbuf);
    if (strlen(key) > 15) wpm(h, key_lng, longbuf, strlen(key) + 1);
    wpm(h, key_str, st, 32);

    /* ---- build shellcode ---- */
    uint8_t code[512];
    int code_len = 0;
    if (strcmp(mode, "auto") == 0) {
        code_len = sc_build_auto(code, main_screen, user_str, key_str);
    } else if (strcmp(mode, "custom") == 0) {
        char klower[129];
        strtolower_ascii(klower, key, sizeof(klower));
        size_t klen = strlen(klower);
        wpm(h, expect, klower, klen);
        code_len = sc_build_custom(code, login_screen, main_screen, user_str, expect, (uint32_t)klen);
    } else {
        code_len = sc_build_any(code, login_screen, main_screen, user_str);
    }
    printf("[*] Shellcode size: %d bytes @ 0x%llX\n", code_len, (unsigned long long)mem);
    wpm(h, mem, code, code_len);

    /* ---- install hook: mov rax, shellcode; call rax; nop; nop ---- */
    uint8_t patch[HOOK_LEN];
    patch[0] = 0x48; patch[1] = 0xB8;
    memcpy(patch + 2, &mem, 8);
    patch[10] = 0xFF; patch[11] = 0xD0;
    patch[12] = 0x90; patch[13] = 0x90;

    DWORD old = 0;
    VirtualProtectEx(h, (LPVOID)(uintptr_t)hook_target, HOOK_LEN, PAGE_EXECUTE_READWRITE, &old);
    wpm(h, hook_target, patch, HOOK_LEN);
    VirtualProtectEx(h, (LPVOID)(uintptr_t)hook_target, HOOK_LEN, old, &old);

    /* ---- verify ---- */
    uint8_t back[HOOK_LEN];
    int ok = rpm(h, hook_target, back, HOOK_LEN) && memcmp(back, patch, HOOK_LEN) == 0;

    printf("\n");
    if (ok) {
        printf("[OK] PATCH LOGIN KEY สำเร็จ!\n");
        if (strcmp(mode, "any") == 0) printf("[OK] กรอก key อะไรก็ได้ (ห้ามว่าง) -> เข้าหน้าหลักทันที\n");
        else if (strcmp(mode, "auto") == 0) printf("[OK] ข้ามหน้า login เข้าหน้าหลักอัตโนมัติ\n");
        else printf("[OK] ใช้ key \"%s\" (ไม่สนพิมพ์เล็ก/ใหญ่) เพื่อเข้าใช้งาน\n", key);
    } else {
        printf("[!] Verify hook ล้มเหลว!\n");
        CloseHandle(h);
        return 1;
    }
    printf("\nLoader จะค้างเบื้องหลัง (กด Ctrl+C เพื่อปิด — patch ยังอยู่ใน deef จนปิดโปรแกรม)\n");

    /* keep-alive while target lives */
    for (;;) {
        Sleep(1000);
        DWORD ec = 0;
        if (!GetExitCodeProcess(h, &ec) || ec != STILL_ACTIVE) break;
    }
    CloseHandle(h);
    return 0;
}
