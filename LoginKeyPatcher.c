/* LoginKeyPatcher v2 — STEALTH (VEH + hardware breakpoint) for deef.exe.
 *
 * v1 patched 14 bytes of code in-memory, which trips Enigma Protector's
 * integrity check ("File corrupted! ... manipulated ... cracked").
 * v2 modifies ZERO bytes of the target image:
 *   - shellcode + VEH handler live in our own RX block (foreign allocation)
 *   - a hardware execution breakpoint (Dr0-Dr3) is set on the hook address
 *   - our VEH redirects to the shellcode, which jumps back to hook+14
 *   - VEH is installed via thread hijack (no new thread, no debugger attach,
 *     PEB untouched) with CreateRemoteThread as fallback
 *
 * Build (cross-compile on Linux with zig):
 *   python -m ziglang cc -target x86_64-windows-gnu -O2 -o LoginKeyPatcher.exe LoginKeyPatcher.c -lpsapi
 *
 * Usage:
 *   LoginKeyPatcher.exe [any|auto|custom] [key] [username]   (stealth, default)
 *   LoginKeyPatcher.exe --direct [mode...]                   (old in-place patch)
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
#include <stddef.h>
#include <wchar.h>
#include <stdarg.h>
#include "sc_build.h"

/* ---- ABI offsets used by the VEH stub (verified at compile time) ---- */
_Static_assert(offsetof(CONTEXT, Rip) == 0xF8, "CONTEXT.Rip");
_Static_assert(offsetof(CONTEXT, Rsp) == 0x98, "CONTEXT.Rsp");
_Static_assert(offsetof(CONTEXT, Rax) == 0x78, "CONTEXT.Rax");
_Static_assert(offsetof(CONTEXT, Rcx) == 0x80, "CONTEXT.Rcx");
_Static_assert(offsetof(CONTEXT, Rdx) == 0x88, "CONTEXT.Rdx");
_Static_assert(offsetof(CONTEXT, Dr0) == 0x48, "CONTEXT.Dr0");
_Static_assert(offsetof(CONTEXT, Dr1) == 0x50, "CONTEXT.Dr1");
_Static_assert(offsetof(CONTEXT, Dr2) == 0x58, "CONTEXT.Dr2");
_Static_assert(offsetof(CONTEXT, Dr3) == 0x60, "CONTEXT.Dr3");
_Static_assert(offsetof(CONTEXT, Dr6) == 0x68, "CONTEXT.Dr6");
_Static_assert(offsetof(CONTEXT, Dr7) == 0x70, "CONTEXT.Dr7");
_Static_assert(offsetof(EXCEPTION_RECORD, ExceptionCode) == 0, "ER.Code");
_Static_assert(offsetof(EXCEPTION_RECORD, ExceptionAddress) == 0x10, "ER.Addr");
_Static_assert(offsetof(EXCEPTION_POINTERS, ExceptionRecord) == 0, "EP.ER");
_Static_assert(offsetof(EXCEPTION_POINTERS, ContextRecord) == 8, "EP.CR");

#define RVA_LOGIN_SCREEN 0x214370ull
#define RVA_MAIN_SCREEN  0x2194B0ull
#define RVA_WRAPPER      0x21A0B0ull
#define RVA_HOOK         0x21A0B9ull
#define HOOK_LEN 14

/* layout inside our RX code block */
#define L_VEH        0x000
#define L_DONE       0x080  /* EB FE (hijack completion marker) */
#define L_RTSTUB     0x0A0  /* CreateRemoteThread fallback stub */
#define L_CODE       0x100
#define L_USER_STR   0x300
#define L_KEY_STR    0x320
#define L_EXPECT     0x340
#define L_USER_LONG  0x3C0
#define L_KEY_LONG   0x400

/* ---------------- console output (Unicode-safe) + log file ---------------- */
static HANDLE g_out;
static FILE *g_log = NULL;

static void wprint(const wchar_t *fmt, ...) {
    wchar_t buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap);
    va_end(ap);
    buf[2047] = 0;
    DWORD w = 0;
    if (!WriteConsoleW(g_out, buf, (DWORD)wcslen(buf), &w, NULL))
        wprintf(L"%s", buf);
    if (g_log) {
        fwprintf(g_log, L"%s", buf);
        fflush(g_log);
    }
}

static void towide(const char *s, wchar_t *d, int n) {
    MultiByteToWideChar(CP_ACP, 0, s, -1, d, n);
    d[n - 1] = 0;
}

/* ---------------- helpers ---------------- */
static void usage(void) {
    wprint(L"Usage:\n");
    wprint(L"  LoginKeyPatcher.exe [mode] [key] [username]   (stealth, default)\n\n");
    wprint(L"  mode:\n");
    wprint(L"    any     = กรอก key อะไรก็ได้ (ยาว > 0) เข้าหน้าหลักทันที [default]\n");
    wprint(L"    auto    = ข้ามหน้า login ไปหน้าหลักเลย ไม่ต้องกรอกอะไร\n");
    wprint(L"    custom  = ใช้ได้เฉพาะ key ที่กำหนด (ไม่สนตัวพิมพ์เล็ก/ใหญ่)\n\n");
    wprint(L"  Examples:\n");
    wprint(L"    LoginKeyPatcher.exe any\n");
    wprint(L"    LoginKeyPatcher.exe auto\n");
    wprint(L"    LoginKeyPatcher.exe custom MySecret123 \"VIP User\"\n");
    wprint(L"    LoginKeyPatcher.exe --direct any   (วิธีเก่า: แก้โค้ดตรงๆ — Enigma จับได้)\n");
    wprint(L"    LoginKeyPatcher.exe --restore      (คืนค่า hook เดิม)\n\n");
}

static DWORD find_pid(const char *name) {
    DWORD pid = 0;
    wchar_t wname[260];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 260);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
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

static int target_alive(HANDLE h) {
    DWORD ec = 0;
    return GetExitCodeProcess(h, &ec) && ec == STILL_ACTIVE;
}

/* identify the exact target build (file size + PE TimeDateStamp) */
static void print_target_identity(const char *path) {
    FILE *f = fopen(path, "rb");
    uint8_t hdr[512];
    size_t n;
    long sz;
    uint32_t ts = 0;
    if (!f) return;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    n = fread(hdr, 1, sizeof(hdr), f);
    fclose(f);
    if (n >= 0x40 && hdr[0] == 'M' && hdr[1] == 'Z') {
        uint32_t peo;
        memcpy(&peo, hdr + 0x3C, 4);
        if (peo + 8 < n) memcpy(&ts, hdr + peo + 8, 4);
    }
    wprint(L"[*] deef.exe size=%ld bytes TimeDateStamp=0x%08X\n", sz, ts);
}

static void print_hex(const wchar_t *label, uint8_t *b, int n) {
    int i;
    wprint(L"%s", label);
    for (i = 0; i < n; i++) wprint(L"%02X%s", b[i], i + 1 < n ? L" " : L"\n");
}

/* ---------------- hardware breakpoints ---------------- */
static HANDLE open_thread_full(DWORD tid) {
    return OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                      THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
}

/* returns slot 0-3 on success, -2 if no free slot, -1 on error */
static int arm_hwbp_on_thread(HANDLE ht, uint64_t addr) {
    if (SuspendThread(ht) == (DWORD)-1) return -1;
    int ret = -1;
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(ht, &ctx)) {
        uint64_t *dr[4] = { &ctx.Dr0, &ctx.Dr1, &ctx.Dr2, &ctx.Dr3 };
        int slot = -2, i;
        for (i = 0; i < 4; i++) { /* already ours? */
            int enabled = (int)((ctx.Dr7 >> (2 * i)) & 3);
            if (*dr[i] == addr && enabled) { slot = i; break; }
        }
        if (slot == -2) {
            for (i = 0; i < 4; i++) { /* first free slot (leave foreign ones alone) */
                int enabled = (int)((ctx.Dr7 >> (2 * i)) & 3);
                if (!enabled) { slot = i; break; }
            }
        }
        if (slot >= 0) {
            *dr[slot] = addr;
            ctx.Dr7 |= (1ULL << (2 * slot));         /* L0..L3 */
            ctx.Dr7 &= ~(0xFULL << (16 + 4 * slot)); /* RW=00 exec, LEN=00 */
            ctx.Dr6 &= ~(1ULL << slot);
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (SetThreadContext(ht, &ctx)) ret = slot;
        } else {
            ret = -2;
        }
    }
    ResumeThread(ht);
    return ret;
}

#define MAX_THREADS 1024
static DWORD g_seen[MAX_THREADS];
static int g_nseen = 0;

static int seen_before(DWORD tid) {
    int i;
    for (i = 0; i < g_nseen; i++)
        if (g_seen[i] == tid) return 1;
    return 0;
}

static void mark_seen(DWORD tid) {
    if (g_nseen < MAX_THREADS) g_seen[g_nseen++] = tid;
}

/* arm all threads; only_new=1 skips already-seen TIDs */
static int arm_threads(DWORD pid, uint64_t addr, int only_new) {
    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (only_new && seen_before(te.th32ThreadID)) continue;
            HANDLE ht = open_thread_full(te.th32ThreadID);
            if (!ht) continue;
            if (arm_hwbp_on_thread(ht, addr) >= 0) n++;
            CloseHandle(ht);
            mark_seen(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

/* read-only check: how many threads currently have our HWBP armed */
static int count_armed(DWORD pid, uint64_t addr) {
    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE ht;
            CONTEXT ctx;
            int s;
            if (te.th32OwnerProcessID != pid) continue;
            ht = open_thread_full(te.th32ThreadID);
            if (!ht) continue;
            if (SuspendThread(ht) != (DWORD)-1) {
                uint64_t dr[4];
                memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(ht, &ctx)) {
                    dr[0] = ctx.Dr0; dr[1] = ctx.Dr1; dr[2] = ctx.Dr2; dr[3] = ctx.Dr3;
                    for (s = 0; s < 4; s++) {
                        if (dr[s] == addr && ((ctx.Dr7 >> (2 * s)) & 3)) { n++; break; }
                    }
                }
                ResumeThread(ht);
            }
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

/* ---------------- VEH installation ----------------
 * System DLLs share one base address across all processes per boot, so the
 * local GetProcAddress result is valid inside the target too. */

/* Call AddVectoredExceptionHandler(handler, 1) by hijacking existing threads.
 * Returns the VEH handle, or 0 on failure. Restores every thread exactly. */
static uint64_t remote_add_veh_hijack(HANDLE hProc, DWORD pid, uint64_t handler, uint64_t done_stub) {
    FARPROC addveh = GetProcAddress(GetModuleHandleA("kernel32.dll"), "AddVectoredExceptionHandler");
    if (!addveh) return 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int tried = 0;
    uint64_t handle = 0;
    if (Thread32First(snap, &te)) {
        do {
            int i, done = 0;
            HANDLE ht;
            CONTEXT ctx, saved, c2;
            uint64_t newsp;
            SIZE_T wr = 0;
            if (te.th32OwnerProcessID != pid) continue;
            if (tried >= 4) break;
            tried++;
            ht = open_thread_full(te.th32ThreadID);
            if (!ht) continue;
            if (SuspendThread(ht) == (DWORD)-1) { CloseHandle(ht); continue; }
            memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_ALL;
            if (!GetThreadContext(ht, &ctx)) { ResumeThread(ht); CloseHandle(ht); continue; }
            saved = ctx;
            /* borrow the thread's own stack (shadow space + ret addr), keep Rsp%16==8 */
            newsp = (ctx.Rsp - 256) & ~15ULL;
            newsp -= 8;
            if (!WriteProcessMemory(hProc, (LPVOID)(uintptr_t)newsp, &done_stub, 8, &wr) || wr != 8) {
                ResumeThread(ht); CloseHandle(ht); continue;
            }
            ctx.Rip = (DWORD64)(uintptr_t)addveh;
            ctx.Rcx = (DWORD64)handler;
            ctx.Rdx = 1; /* FirstHandler */
            ctx.Rsp = (DWORD64)newsp;
            ctx.ContextFlags = CONTEXT_ALL;
            if (!SetThreadContext(ht, &ctx)) {
                SetThreadContext(ht, &saved);
                ResumeThread(ht); CloseHandle(ht); continue;
            }
            ResumeThread(ht);
            for (i = 0; i < 50; i++) {
                Sleep(100);
                if (SuspendThread(ht) == (DWORD)-1) break;
                memset(&c2, 0, sizeof(c2));
                c2.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                if (GetThreadContext(ht, &c2) && c2.Rip == done_stub) {
                    handle = (uint64_t)c2.Rax;
                    done = 1;
                    ResumeThread(ht);
                    break;
                }
                ResumeThread(ht);
            }
            SuspendThread(ht);
            saved.ContextFlags = CONTEXT_ALL;
            SetThreadContext(ht, &saved);
            ResumeThread(ht);
            CloseHandle(ht);
            if (done && handle) break;
            handle = 0;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return handle;
}

/* Fallback: CreateRemoteThread on a small stub that calls AddVEH and stores
 * the full 64-bit result where we can read it. */
static uint64_t remote_add_veh_remote_thread(HANDLE hProc, uint64_t stub, uint64_t result) {
    (void)result;
    HANDLE rt = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)(uintptr_t)stub,
                                   NULL, 0, NULL);
    uint64_t handle = 0;
    DWORD ec = 0;
    if (!rt) return 0;
    if (WaitForSingleObject(rt, 8000) == WAIT_OBJECT_0 && GetExitCodeThread(rt, &ec)) {
        uint64_t v = 0;
        if (rpm(hProc, result, &v, 8)) handle = v;
    }
    CloseHandle(rt);
    return handle;
}

/* stub: sub rsp,0x28; mov rcx,handler; mov edx,1; mov rax,AddVEH; call rax;
 *       add rsp,0x28; mov [result],rax; ret */
static int build_rtstub(uint8_t *out, uint64_t handler, uint64_t addveh, uint64_t result) {
    uint8_t *p = out;
    static const uint8_t a[] = { 0x48, 0x83, 0xEC, 0x28 };
    static const uint8_t b[] = { 0x48, 0xB9 };
    static const uint8_t c[] = { 0xBA, 0x01, 0x00, 0x00, 0x00 };
    static const uint8_t d[] = { 0x48, 0xB8 };
    static const uint8_t e[] = { 0xFF, 0xD0 };
    static const uint8_t f[] = { 0x48, 0x83, 0xC4, 0x28 };
    static const uint8_t g[] = { 0x48, 0xA3 };
    memcpy(p, a, sizeof(a)); p += sizeof(a);
    memcpy(p, b, sizeof(b)); p += sizeof(b);
    memcpy(p, &handler, 8); p += 8;
    memcpy(p, c, sizeof(c)); p += sizeof(c);
    memcpy(p, d, sizeof(d)); p += sizeof(d);
    memcpy(p, &addveh, 8); p += 8;
    memcpy(p, e, sizeof(e)); p += sizeof(e);
    memcpy(p, f, sizeof(f)); p += sizeof(f);
    memcpy(p, g, sizeof(g)); p += sizeof(g);
    memcpy(p, &result, 8); p += 8;
    *p++ = 0xC3;
    return (int)(p - out);
}

/* ---------------- restore (direct mode leftovers) ---------------- */
static int do_restore(void) {
    uint8_t orig[HOOK_LEN];
    FILE *f = fopen("hook_backup.bin", "rb");
    if (!f) { wprint(L"[!] ไม่พบไฟล์ hook_backup.bin\n"); return 1; }
    if (fread(orig, 1, HOOK_LEN, f) != HOOK_LEN) { fclose(f); wprint(L"[!] ไฟล์ backup ไม่ถูกต้อง\n"); return 1; }
    fclose(f);

    DWORD pid = find_pid("deef.exe");
    if (!pid) { wprint(L"[!] deef.exe ไม่ได้รันอยู่\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) { wprint(L"[!] OpenProcess ล้มเหลว err=%lu\n", GetLastError()); return 1; }
    {
        uint64_t base = get_module_base(h, "deef.exe");
        if (!base) { wprint(L"[!] หา base ไม่เจอ\n"); CloseHandle(h); return 1; }
        {
            uint64_t hook = base + RVA_HOOK;
            DWORD old = 0;
            VirtualProtectEx(h, (LPVOID)(uintptr_t)hook, HOOK_LEN, PAGE_EXECUTE_READWRITE, &old);
            wpm(h, hook, orig, HOOK_LEN);
            VirtualProtectEx(h, (LPVOID)(uintptr_t)hook, HOOK_LEN, old, &old);
        }
    }
    CloseHandle(h);
    wprint(L"[OK] คืนค่า hook เดิมเรียบร้อย\n");
    return 0;
}

/* ---------------- stealth install ---------------- */
static int do_stealth(HANDLE h, DWORD pid, uint64_t base,
                      const char *mode, const char *key, const char *username) {
    uint64_t hook = base + RVA_HOOK;
    uint64_t cont = hook + HOOK_LEN;
    uint64_t login_screen = base + RVA_LOGIN_SCREEN;
    uint64_t main_screen = base + RVA_MAIN_SCREEN;
    uint8_t orig[HOOK_LEN];
    int i;
    uint64_t mem, datab, counter;
    uint64_t veh_addr, done_addr, stub_addr, code_addr;
    uint64_t user_str, key_str, expect, user_lng, key_lng;
    uint8_t code[512], veh[128], stub[64], st[32], longbuf[256];
    int code_len = 0, veh_len = 0, stub_len = 0;
    SIZE_T wr = 0;
    DWORD old = 0;
    uint64_t veh_handle;
    int armed;

    wprint(L"[*] โหมด STEALTH — ไม่แก้โค้ดใน memory เลย (Enigma-safe)\n");

    /* read (only) + backup original bytes for analysis */
    if (!rpm(h, hook, orig, HOOK_LEN)) {
        wprint(L"[!] อ่าน memory ตรงจุด hook ไม่ได้\n");
        return 1;
    }
    wprint(L"[*] Hook bytes (ไม่แตะ): ");
    for (i = 0; i < HOOK_LEN; i++) wprint(L"%02X%s", orig[i], i + 1 < HOOK_LEN ? L"-" : L"\n");
    {
        FILE *bf = fopen("hook_backup.bin", "wb");
        if (bf) { fwrite(orig, 1, HOOK_LEN, bf); fclose(bf); }
    }

    /* allocate our own blocks (foreign to the image: unchecked by Enigma) */
    mem = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    datab = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem || !datab) {
        wprint(L"[!] VirtualAllocEx ล้มเหลว err=%lu\n", GetLastError());
        return 1;
    }
    counter = datab + 0x100;
    veh_addr = mem + L_VEH; done_addr = mem + L_DONE; stub_addr = mem + L_RTSTUB;
    code_addr = mem + L_CODE;
    user_str = mem + L_USER_STR; key_str = mem + L_KEY_STR; expect = mem + L_EXPECT;
    user_lng = mem + L_USER_LONG; key_lng = mem + L_KEY_LONG;

    /* build everything locally first */
    veh_len = sc_veh_handler(veh, hook, code_addr, counter);
    {
        FARPROC addveh = GetProcAddress(GetModuleHandleA("kernel32.dll"), "AddVectoredExceptionHandler");
        stub_len = build_rtstub(stub, veh_addr, (uint64_t)(uintptr_t)addveh, datab);
    }
    if (strcmp(mode, "auto") == 0) {
        code_len = sc_build_auto(code, main_screen, user_str, key_str, cont);
    } else if (strcmp(mode, "custom") == 0) {
        char klower[129];
        strtolower_ascii(klower, key, sizeof(klower));
        wpm(h, expect, klower, strlen(klower));
        code_len = sc_build_custom(code, login_screen, main_screen, user_str, expect,
                                   (uint32_t)strlen(klower), cont);
    } else {
        code_len = sc_build_any(code, login_screen, main_screen, user_str, cont);
    }

    sc_std_string(st, username, user_lng, longbuf);
    if (strlen(username) > 15) wpm(h, user_lng, longbuf, strlen(username) + 1);
    wpm(h, user_str, st, 32);
    sc_std_string(st, key, key_lng, longbuf);
    if (strlen(key) > 15) wpm(h, key_lng, longbuf, strlen(key) + 1);
    wpm(h, key_str, st, 32);

    wpm(h, veh_addr, veh, veh_len);
    {
        uint8_t doneb[2] = { 0xEB, 0xFE };
        wpm(h, done_addr, doneb, 2);
    }
    wpm(h, stub_addr, stub, stub_len);
    wpm(h, code_addr, code, code_len);
    wprint(L"[*] VEH=%d shellcode=%d bytes @ 0x%llX\n", veh_len, code_len, (unsigned long long)mem);

    /* drop write permission: pure RX code block */
    VirtualProtectEx(h, (LPVOID)(uintptr_t)mem, 4096, PAGE_EXECUTE_READ, &old);

    /* install VEH (hijack first, remote thread as fallback) */
    wprint(L"[*] ติดตั้ง VEH...\n");
    veh_handle = remote_add_veh_hijack(h, pid, veh_addr, done_addr);
    if (veh_handle) {
        wprint(L"[+] ติดตั้ง VEH สำเร็จ (hijack) handle=0x%llX\n", (unsigned long long)veh_handle);
    } else {
        wprint(L"[*] hijack ไม่สำเร็จ ลอง CreateRemoteThread...\n");
        veh_handle = remote_add_veh_remote_thread(h, stub_addr, datab);
        if (veh_handle)
            wprint(L"[+] ติดตั้ง VEH สำเร็จ (remote thread) handle=0x%llX\n", (unsigned long long)veh_handle);
    }
    if (!veh_handle) {
        wprint(L"[!] ติดตั้ง VEH ไม่สำเร็จ\n");
        return 1;
    }

    /* arm hardware breakpoints */
    g_nseen = 0;
    armed = arm_threads(pid, hook, 0);
    if (armed == 0) {
        wprint(L"[!] ใส่ hardware breakpoint ไม่ได้เลย\n");
        return 1;
    }
    wprint(L"[+] ใส่ hardware breakpoint แล้ว %d threads (slot ว่าง, ไม่ทับของเดิม)\n", armed);
    wprint(L"[*] hook=0x%llX cont=0x%llX\n", (unsigned long long)hook, (unsigned long long)cont);
    /* verify: read back debug regs from one thread + dump memory context */
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (snap != INVALID_HANDLE_VALUE && Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                {
                    HANDLE ht = open_thread_full(te.th32ThreadID);
                    if (ht && SuspendThread(ht) != (DWORD)-1) {
                        CONTEXT ctx;
                        memset(&ctx, 0, sizeof(ctx));
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (GetThreadContext(ht, &ctx)) {
                            wprint(L"[*] DR verify: Dr0=%llX Dr1=%llX Dr2=%llX Dr3=%llX Dr7=%llX\n",
                                   (unsigned long long)ctx.Dr0, (unsigned long long)ctx.Dr1,
                                   (unsigned long long)ctx.Dr2, (unsigned long long)ctx.Dr3,
                                   (unsigned long long)ctx.Dr7);
                        }
                        ResumeThread(ht);
                    }
                    if (ht) CloseHandle(ht);
                }
                break;
            } while (Thread32Next(snap, &te));
        }
        if (snap != INVALID_HANDLE_VALUE) CloseHandle(snap);
    }
    {
        uint8_t dump[32];
        if (rpm(h, base + RVA_WRAPPER, dump, 32)) print_hex(L"[*] wrapper @0x21A0B0: ", dump, 32);
        if (rpm(h, hook, dump, 32)) print_hex(L"[*] hook @0x21A0B9 (+32): ", dump, 32);
    }

    wprint(L"\n[OK] STEALTH PATCH สำเร็จ! (ไม่ได้แก้โค้ด deef.exe เลย)\n");
    if (strcmp(mode, "any") == 0) wprint(L"[OK] กรอก key อะไรก็ได้ (ห้ามว่าง) -> เข้าหน้าหลักทันที\n");
    else if (strcmp(mode, "auto") == 0) wprint(L"[OK] ข้ามหน้า login เข้าหน้าหลักอัตโนมัติ\n");
    else {
        wchar_t wk[160];
        towide(key, wk, 160);
        wprint(L"[OK] ใช้ key \"%s\" (ไม่สนพิมพ์เล็ก/ใหญ่) เพื่อเข้าใช้งาน\n", wk);
    }
    wprint(L"[*] ห้ามปิดหน้าต่างนี้ — loader ต้องค้างไว้เลี้ยง breakpoint (กด Ctrl+C เพื่อปิด)\n");

    /* watchdog (500ms): poll hit counter, arm new threads, re-arm + wipe check */
    {
        int tick = 0, last_armed = armed;
        uint64_t last_hits = 0, shown_hits = 0;
        for (;;) {
            uint64_t hits = 0;
            Sleep(500);
            if (!target_alive(h)) break;
            rpm(h, counter, &hits, 8);
            if (hits != shown_hits && (hits <= 20 || tick % 4 == 0)) {
                wprint(L"[HIT] hook แตกแล้ว! รวม %llu ครั้ง\n", (unsigned long long)hits);
                shown_hits = hits;
            }
            last_hits = hits;
            arm_threads(pid, hook, 1);
            if (++tick % 4 == 0) {
                int cur = count_armed(pid, hook);
                if (cur == 0 && last_armed > 0)
                    wprint(L"[!] breakpoint โดนล้าง (Enigma?) — ใส่ใหม่...\n");
                arm_threads(pid, hook, 0);
                last_armed = count_armed(pid, hook);
            }
        }
        if (last_hits == 0)
            wprint(L"[!] hook ไม่แตกเลยสักครั้ง (hits=0) — จุด hook อาจผิดสำหรับ deef เวอร์ชันนี้\n");
        else
            wprint(L"[*] hook แตกทั้งหมด %llu ครั้ง\n", (unsigned long long)last_hits);
        wprint(L"[*] deef ปิดแล้ว — ปิด loader ได้\n");
    }
    (void)wr;
    return 0;
}

/* ---------------- direct install (legacy, trips Enigma) ---------------- */
static int do_direct(HANDLE h, uint64_t base,
                     const char *mode, const char *key, const char *username) {
    uint64_t hook = base + RVA_HOOK;
    uint64_t login_screen = base + RVA_LOGIN_SCREEN;
    uint64_t main_screen = base + RVA_MAIN_SCREEN;
    uint8_t orig[HOOK_LEN];
    int i;
    uint64_t mem, user_str, key_str, expect, user_lng, key_lng;
    uint8_t code[512], st[32], longbuf[256];
    int code_len = 0;
    uint8_t patch[HOOK_LEN], back[HOOK_LEN];
    DWORD old = 0;
    SIZE_T wr = 0;

    wprint(L"[*] โหมด DIRECT (แก้โค้ดตรงๆ — Enigma จับได้ ปกติไม่ต้องใช้)\n");
    if (!rpm(h, hook, orig, HOOK_LEN)) {
        wprint(L"[!] อ่าน memory ตรงจุด hook ไม่ได้\n");
        return 1;
    }
    wprint(L"[*] Original hook bytes: ");
    for (i = 0; i < HOOK_LEN; i++) wprint(L"%02X%s", orig[i], i + 1 < HOOK_LEN ? L"-" : L"\n");
    if (!(orig[0] == 0x48 && orig[1] == 0xB8)) {
        FILE *bf = fopen("hook_backup.bin", "wb");
        if (bf) { fwrite(orig, 1, HOOK_LEN, bf); fclose(bf); }
    } else {
        wprint(L"[!] ดูเหมือนเคย patch จุดนี้แล้ว — จะ patch ทับ\n");
    }

    mem = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        wprint(L"[!] VirtualAllocEx ล้มเหลว err=%lu\n", GetLastError());
        return 1;
    }
    user_str = mem + L_USER_STR; key_str = mem + L_KEY_STR; expect = mem + L_EXPECT;
    user_lng = mem + L_USER_LONG; key_lng = mem + L_KEY_LONG;

    sc_std_string(st, username, user_lng, longbuf);
    if (strlen(username) > 15) wpm(h, user_lng, longbuf, strlen(username) + 1);
    wpm(h, user_str, st, 32);
    sc_std_string(st, key, key_lng, longbuf);
    if (strlen(key) > 15) wpm(h, key_lng, longbuf, strlen(key) + 1);
    wpm(h, key_str, st, 32);

    if (strcmp(mode, "auto") == 0) {
        code_len = sc_build_auto(code, main_screen, user_str, key_str, 0);
    } else if (strcmp(mode, "custom") == 0) {
        char klower[129];
        strtolower_ascii(klower, key, sizeof(klower));
        wpm(h, expect, klower, strlen(klower));
        code_len = sc_build_custom(code, login_screen, main_screen, user_str, expect,
                                   (uint32_t)strlen(klower), 0);
    } else {
        code_len = sc_build_any(code, login_screen, main_screen, user_str, 0);
    }
    wprint(L"[*] Shellcode size: %d bytes @ 0x%llX\n", code_len, (unsigned long long)mem);
    wpm(h, mem, code, code_len);

    patch[0] = 0x48; patch[1] = 0xB8;
    memcpy(patch + 2, &mem, 8);
    patch[10] = 0xFF; patch[11] = 0xD0;
    patch[12] = 0x90; patch[13] = 0x90;

    VirtualProtectEx(h, (LPVOID)(uintptr_t)hook, HOOK_LEN, PAGE_EXECUTE_READWRITE, &old);
    wpm(h, hook, patch, HOOK_LEN);
    VirtualProtectEx(h, (LPVOID)(uintptr_t)hook, HOOK_LEN, old, &old);

    if (!rpm(h, hook, back, HOOK_LEN) || memcmp(back, patch, HOOK_LEN) != 0) {
        wprint(L"[!] Verify hook ล้มเหลว!\n");
        return 1;
    }
    wprint(L"\n[OK] DIRECT PATCH สำเร็จ!\n");
    (void)wr;
    return 0;
}

/* ---------------- main ---------------- */
int main(int argc, char **argv) {
    const char *mode = "any";
    char key[129] = { 0 };
    char username[65] = "VIP User";
    int direct = 0;
    int argi = 1;
    wchar_t wmode[16], wuser[80];
    char exe_dir[512] = { 0 };
    char target_exe[600], cmd[620];
    char *slash;
    DWORD attr;
    DWORD pid;
    HANDLE h = NULL;
    uint64_t base = 0;
    int retry, rc;

    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_log = _wfopen(L"patcher_log.txt", L"w, ccs=UTF-8");
    SetConsoleOutputCP(65001);
    SetConsoleTitleA("Login Key Patcher - deef bypass (stealth)");
    /* force a TrueType font so Thai text renders (fixes ???? on raster fonts) */
    {
        CONSOLE_FONT_INFOEX fi;
        memset(&fi, 0, sizeof(fi));
        fi.cbSize = sizeof(fi);
        fi.dwFontSize.Y = 16;
        wcscpy(fi.FaceName, L"Consolas");
        SetCurrentConsoleFontEx(g_out, FALSE, &fi);
    }

    wprint(L"=================================================\n");
    wprint(L"     LOGIN KEY PATCHER v2.1 (STEALTH deef bypass) \n");
    wprint(L"=================================================\n");

    if (argi < argc && strcmp(argv[argi], "--direct") == 0) { direct = 1; argi++; }
    if (argi < argc) {
        if (strcmp(argv[argi], "--help") == 0 || strcmp(argv[argi], "-h") == 0 ||
            strcmp(argv[argi], "/?") == 0) { usage(); return 0; }
        if (strcmp(argv[argi], "--restore") == 0) return do_restore();
        if (strcmp(argv[argi], "any") == 0 || strcmp(argv[argi], "auto") == 0 ||
            strcmp(argv[argi], "custom") == 0) {
            mode = argv[argi++];
        } else {
            wprint(L"[!] mode ไม่ถูกต้อง\n"); usage(); return 1;
        }
    }
    if (argi < argc) { strncpy(key, argv[argi++], sizeof(key) - 1); }
    if (argi < argc) { strncpy(username, argv[argi++], sizeof(username) - 1); username[sizeof(username) - 1] = 0; }

    if (strcmp(mode, "custom") == 0 && key[0] == 0) {
        wprint(L"[!] custom mode ต้องระบุ key ด้วย\n"); usage(); return 1;
    }
    if (strcmp(mode, "auto") == 0 && key[0] == 0) strcpy(key, "VIP-PREMIUM");

    towide(mode, wmode, 16);
    towide(username, wuser, 80);
    if (strcmp(mode, "custom") == 0) {
        wchar_t wk[160];
        towide(key, wk, 160);
        wprint(L"[*] Mode: %s%s  user=\"%s\"  key=\"%s\"\n", direct ? L"DIRECT " : L"STEALTH ",
               wmode, wuser, wk);
    } else {
        wprint(L"[*] Mode: %s%s  user=\"%s\"\n", direct ? L"DIRECT " : L"STEALTH ", wmode, wuser);
    }

    /* ---- find or launch deef.exe ---- */
    GetModuleFileNameA(NULL, exe_dir, sizeof(exe_dir));
    slash = strrchr(exe_dir, '\\');
    if (slash) *slash = 0;
    else strcpy(exe_dir, ".");
    _snprintf(target_exe, sizeof(target_exe), "%s\\deef.exe", exe_dir);
    print_target_identity(target_exe);

    pid = find_pid("deef.exe");
    if (pid) {
        wprint(L"[+] พบ deef.exe ที่รันอยู่ (PID: %lu)\n", (unsigned long)pid);
    } else {
        attr = GetFileAttributesA(target_exe);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            wchar_t wdir[512];
            towide(exe_dir, wdir, 512);
            wprint(L"[!] ไม่พบไฟล์ deef.exe ใน %s\n", wdir);
            wprint(L"กด Enter เพื่อออก...");
            getchar();
            return 1;
        }
        wprint(L"[*] กำลังเปิด deef.exe...\n");
        {
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            _snprintf(cmd, sizeof(cmd), "\"%s\"", target_exe);
            if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, exe_dir, &si, &pi)) {
                wprint(L"[!] เปิด deef.exe ไม่ได้ err=%lu\n", GetLastError());
                return 1;
            }
            pid = pi.dwProcessId;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            wprint(L"[+] เปิด deef.exe สำเร็จ (PID: %lu)\n", (unsigned long)pid);
        }
    }

    /* ---- wait for unpack + get base (reading memory is safe) ---- */
    wprint(L"[*] รอโปรแกรมโหลด/Unpack ใน memory...\n");
    for (retry = 0; retry < 60; retry++) {
        uint8_t t[8];
        Sleep(500);
        if (!find_pid("deef.exe")) { wprint(L"[!] โปรแกรมเป้าหมายถูกปิด\n"); return 1; }
        h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) continue;
        base = get_module_base(h, "deef.exe");
        if (base && rpm(h, base + RVA_WRAPPER, t, 8) && t[0] == 0x40 && t[1] == 0x53) {
            wprint(L"[+] Unpack เสร็จ! Base: 0x%llX\n", (unsigned long long)base);
            break;
        }
        CloseHandle(h);
        h = NULL;
    }
    if (!h || !base) {
        wprint(L"[!] หา Base Address ไม่เจอ (รันแบบ Admin แล้วหรือยัง?)\n");
        wprint(L"กด Enter เพื่อออก...");
        getchar();
        return 1;
    }

    if (direct) {
        rc = do_direct(h, base, mode, key, username);
        if (rc == 0) {
            wprint(L"\nLoader จะค้างเบื้องหลัง (กด Ctrl+C เพื่อปิด)\n");
            while (target_alive(h)) Sleep(1000);
        }
        CloseHandle(h);
        return rc;
    }

    rc = do_stealth(h, pid, base, mode, key, username);
    CloseHandle(h);
    if (g_log) fclose(g_log);
    if (rc != 0) {
        wprint(L"\nกด Enter เพื่อออก...");
        getchar();
    }
    return rc;
}
