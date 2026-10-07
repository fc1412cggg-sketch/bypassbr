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
#include <stdlib.h>
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
    wprint(L"  v2.4: ดักที่ตัว login เอง — จอ login + ตรวจ key + เรียก API เก่าไม่รันเลย\n");
    wprint(L"        เข้าหน้าหลักตรง ไม่ต้องกรอกอะไร (key/username = ชื่อที่โชว์ในจอหลัก)\n\n");
    wprint(L"  mode:\n");
    wprint(L"    any     = เข้าหน้าหลักตรง (ค่า default) [default]\n");
    wprint(L"    auto    = เหมือน any\n");
    wprint(L"    custom  = เหมือน any แต่กำหนด key/username ที่โชว์เอง\n\n");
    wprint(L"  Examples:\n");
    wprint(L"    LoginKeyPatcher.exe any\n");
    wprint(L"    LoginKeyPatcher.exe auto\n");
    wprint(L"    LoginKeyPatcher.exe custom MySecret123 \"VIP User\"\n");
    wprint(L"    LoginKeyPatcher.exe --direct any   (วิธีเก่า: แก้โค้ดตรงๆ — Enigma จับได้)\n");
    wprint(L"    LoginKeyPatcher.exe --restore      (คืนค่า hook เดิม)\n\n");
    wprint(L"  RE tools (หาจุด hook จริง — ไม่อ่านอย่างเดียว, ไม่แก้โค้ด):\n");
    wprint(L"    --diag                  ชุดสำรวจครบ (scan calls + หาข้อความ) รันครั้งเดียว\n");
    wprint(L"    --scan-calls <RVA>      หา CALL/JMP ที่เรียก address นั้น (hex)\n");
    wprint(L"    --findstr <text>        หาข้อความใน memory (ASCII + UTF-16)\n");
    wprint(L"    --scan-ref <addr>       หาโค้ดที่อ้างถึง address นั้น (hex, runtime addr)\n");
    wprint(L"    --trace <RVA..>         นับว่าโค้ดวิ่งผ่านจุดนั้นกี่ครั้ง (1-4 จุด)\n");
    wprint(L"    --probe                 หาว่าขั้นไหนทำ deef ตาย (เปิดใหม่ 4 รอบ, ~2 นาที)\n\n");
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

/* print deef's exit code after death: distinguishes clean self-exit
 * (anti-debug / normal quit) from a crash (our bug). */
static void report_exit(HANDLE h) {
    DWORD ec = 0;
    const wchar_t *why = L"";
    if (!GetExitCodeProcess(h, &ec)) {
        wprint(L"[*] exit code: ถามไม่ได้ err=%lu\n", GetLastError());
        return;
    }
    if (ec == STILL_ACTIVE) { wprint(L"[*] exit code: ยังรันอยู่\n"); return; }
    if (ec == 0) why = L" (ออกเองแบบสะอาด — ไม่ใช่ crash)";
    else if (ec == 0xC0000005) why = L" (CRASH: access violation!)";
    else if (ec == 0xC0000409) why = L" (CRASH: fail-fast!)";
    else if (ec == 0xC0000374) why = L" (CRASH: heap corruption!)";
    wprint(L"[*] exit code: %lu (0x%08lX)%s\n", (unsigned long)ec, (unsigned long)ec, why);
}

/* make sure no leftover deef is running (fresh slate for probe stages) */
static void kill_deef(void) {
    DWORD pid = find_pid("deef.exe");
    if (!pid) return;
    {
        HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 0);
            WaitForSingleObject(h, 5000);
            CloseHandle(h);
        }
    }
    Sleep(500);
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

/* remove our HWBP (slots whose address == hook) from all threads */
static int disarm_all(DWORD pid, uint64_t addr) {
    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE ht;
            CONTEXT ctx;
            int s, touched = 0;
            uint64_t *dr[4];
            if (te.th32OwnerProcessID != pid) continue;
            ht = open_thread_full(te.th32ThreadID);
            if (!ht) continue;
            if (SuspendThread(ht) == (DWORD)-1) { CloseHandle(ht); continue; }
            memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(ht, &ctx)) {
                dr[0] = &ctx.Dr0; dr[1] = &ctx.Dr1; dr[2] = &ctx.Dr2; dr[3] = &ctx.Dr3;
                for (s = 0; s < 4; s++) {
                    if (*dr[s] == addr && ((ctx.Dr7 >> (2 * s)) & 3)) {
                        ctx.Dr7 &= ~(1ULL << (2 * s));
                        touched = 1;
                    }
                }
                if (touched) {
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    SetThreadContext(ht, &ctx);
                    n++;
                }
            }
            ResumeThread(ht);
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
            ctx.Rcx = 1; /* FirstHandler (ULONG) — ต้องเป็นตัวแรก! */
            ctx.Rdx = (DWORD64)handler;
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

/* stub: sub rsp,0x28; rcx=a1; rdx=a2; r8=a3; r9=a4; call func;
 *       add rsp,0x28; mov [result],rax; ret
 * ระวัง: AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
 *        -> a1 = 1/0, a2 = handler (ลำดับนี้ผิดมาตลอดคือบั๊กที่ทำให้ deef พัง) */
static int build_rtstub(uint8_t *out, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                        uint64_t func, uint64_t result) {
    uint8_t *p = out;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;
    *p++ = 0x48; *p++ = 0xB9; memcpy(p, &a1, 8); p += 8;   /* mov rcx, a1 */
    *p++ = 0x48; *p++ = 0xBA; memcpy(p, &a2, 8); p += 8;   /* mov rdx, a2 */
    *p++ = 0x49; *p++ = 0xB8; memcpy(p, &a3, 8); p += 8;   /* mov r8,  a3 */
    *p++ = 0x49; *p++ = 0xB9; memcpy(p, &a4, 8); p += 8;   /* mov r9,  a4 */
    *p++ = 0x48; *p++ = 0xB8; memcpy(p, &func, 8); p += 8; /* mov rax, func */
    *p++ = 0xFF; *p++ = 0xD0;                              /* call rax */
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xC4; *p++ = 0x28;
    *p++ = 0x48; *p++ = 0xA3; memcpy(p, &result, 8); p += 8; /* mov [result], rax */
    *p++ = 0xC3;
    return (int)(p - out);
}

/* helper: address of an exported function INSIDE the target process */
static uint64_t remote_proc(HANDLE h, const char *mod, const char *name) {
    HMODULE m = GetModuleHandleA(mod);
    FARPROC f = m ? GetProcAddress(m, name) : NULL;
    uint64_t base = get_module_base(h, mod);
    if (!f || !base) return 0;
    return base + ((uint64_t)(uintptr_t)f - (uint64_t)(uintptr_t)m);
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
    /* v2.4: hook the login function ENTRY itself (the old wrapper point is dead:
     * it never executes). Login validation + auth API never run at all. */
    uint64_t hook = base + RVA_LOGIN_SCREEN;
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
        stub_len = build_rtstub(stub, 1, veh_addr, 0, 0,
                             remote_proc(h, "kernel32.dll", "AddVectoredExceptionHandler"), datab);
    }
    /* entry-redirect: show main UI instead of login, return success to caller.
     * key/username only set the displayed identity (login UI never appears). */
    (void)expect;
    (void)mode;
    code_len = sc_build_entry(code, main_screen, user_str, key_str);

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
    wprint(L"[*] hook=login entry 0x%llX (จอ login จะไม่โผล่เลย — ข้ามเข้าหน้าหลักตรง)\n",
           (unsigned long long)hook);
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
        if (rpm(h, hook, dump, 32)) print_hex(L"[*] login entry @0x214370 (+32): ", dump, 32);
    }

    {
        wchar_t wk[160], wu[80];
        towide(key, wk, 160);
        towide(username, wu, 80);
        wprint(L"\n[OK] STEALTH PATCH สำเร็จ! (ไม่ได้แก้โค้ด deef.exe เลย)\n");
        wprint(L"[OK] จอ login เก่า + ระบบตรวจ key + เรียก API จะไม่รันเลย — เข้าหน้าหลักตรง\n");
        wprint(L"[OK] identity ที่โชว์: user=\"%s\" key=\"%s\"\n", wu, wk);
    }
    wprint(L"[*] ห้ามปิดหน้าต่างนี้ — loader ต้องค้างไว้เลี้ยง breakpoint (กด Ctrl+C เพื่อปิด)\n");

    /* watchdog (500ms): poll hit counter, arm new threads, re-arm + wipe check */
    {
        int tick = 0, last_armed = armed, tripped = 0;
        uint64_t last_hits = 0, shown_hits = 0, prev = 0;
        for (;;) {
            uint64_t hits = 0;
            Sleep(500);
            if (!target_alive(h)) break;
            rpm(h, counter, &hits, 8);
            /* rate guard: login entry should fire ~once; a flood means wrong spot */
            if (tick <= 10 && !tripped && hits - prev > 40) {
                int d = disarm_all(pid, hook);
                wprint(L"[!] จุด hook ถูกเรียกถี่ผิดปกติ (%llu ครั้ง/0.5วิ) — ไม่ใช่ login! ปลด breakpoint แล้ว %d threads\n",
                       (unsigned long long)(hits - prev), d);
                wprint(L"[!] ปิด deef แล้วส่ง patcher_log.txt มา — จะหาจุดใหม่ให้\n");
                tripped = 1;
            }
            prev = hits;
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
            wprint(L"[!] hook ไม่แตกเลยสักครั้ง (hits=0) — ส่ง log นี้มา จะหาจุดใหม่ให้\n");
        else
            wprint(L"[*] hook แตกทั้งหมด %llu ครั้ง\n", (unsigned long long)last_hits);
        wprint(L"[*] deef ปิดแล้ว — ปิด loader ได้\n");
        report_exit(h);
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

/* ================= RE toolkit (scan + trace, zero image writes) ================= */

static uint64_t get_module_size(HANDLE h, uint64_t base) {
    MODULEINFO mi;
    memset(&mi, 0, sizeof(mi));
    if (GetModuleInformation(h, (HMODULE)(uintptr_t)base, &mi, sizeof(mi)))
        return mi.SizeOfImage;
    return 0;
}

typedef void (*chunk_cb)(uint64_t chunk_rva, uint8_t *buf, SIZE_T len, void *ctx);

/* walk committed regions of the module, read in <=1MB chunks */
static void walk_image(HANDLE h, uint64_t base, uint64_t size, int exec_only, chunk_cb cb, void *ctx) {
    uint64_t addr = base, end = base + size;
    uint8_t *buf = (uint8_t *)malloc(1024 * 1024);
    if (!buf) return;
    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        uint64_t rbase, rend, p;
        if (VirtualQueryEx(h, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.RegionSize == 0) break;
        rbase = (uint64_t)(uintptr_t)mbi.BaseAddress;
        rend = rbase + mbi.RegionSize;
        if (rbase < base) rbase = base;
        if (rend > end) rend = end;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            int is_exec = (mbi.Protect & 0xF0) != 0;
            if (!exec_only || is_exec) {
                for (p = rbase; p < rend; p += 1024 * 1024) {
                    SIZE_T n = rend - p, done = 0;
                    if (n > 1024 * 1024) n = 1024 * 1024;
                    if (ReadProcessMemory(h, (LPCVOID)(uintptr_t)p, buf, n, &done) && done > 0)
                        cb(p - base, buf, done, ctx);
                }
            }
        }
        addr = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    free(buf);
}

/* ---- shared target open: find/launch + wait unpack ---- */

/* Single-exe bundle support: if deef.exe is missing next to us, look for it
 * appended to our own file (payload + 16-byte footer: [u64 size][8B magic]).
 * Returns 1 if deef.exe is present afterwards, 0 otherwise. */
static int extract_bundled_deef(const char *target_exe) {
    char self[512];
    HANDLE hf, out;
    LARGE_INTEGER fsz, off;
    uint8_t foot[16];
    uint64_t dsize, left, doff;
    DWORD rd;
    uint8_t *buf;
    if (!GetModuleFileNameA(NULL, self, sizeof(self))) return 0;
    hf = CreateFileA(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(hf, &fsz) || fsz.QuadPart < 64) { CloseHandle(hf); return 0; }
    off.QuadPart = fsz.QuadPart - 16;
    if (!SetFilePointerEx(hf, off, NULL, FILE_BEGIN)) { CloseHandle(hf); return 0; }
    if (!ReadFile(hf, foot, 16, &rd, NULL) || rd != 16) { CloseHandle(hf); return 0; }
    if (memcmp(foot + 8, "LKPBNDL1", 8) != 0) { CloseHandle(hf); return 0; } /* not a bundle */
    memcpy(&dsize, foot, 8);
    if (dsize < 1000000ULL || dsize + 16 >= (uint64_t)fsz.QuadPart) { CloseHandle(hf); return 0; }
    { /* skip extraction if the file already matches */
        HANDLE ex = CreateFileA(target_exe, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
        if (ex != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER esz;
            if (GetFileSizeEx(ex, &esz) && (uint64_t)esz.QuadPart == dsize) {
                CloseHandle(ex);
                CloseHandle(hf);
                wprint(L"[*] deef.exe มีอยู่แล้ว (ขนาดตรง) — ข้ามการแตกไฟล์\n");
                return 1;
            }
            CloseHandle(ex);
        }
    }
    wprint(L"[*] แตกไฟล์ deef.exe จาก bundle (%llu MB)...\n",
           (unsigned long long)(dsize / 1048576));
    doff = (uint64_t)fsz.QuadPart - 16 - dsize;
    off.QuadPart = (LONGLONG)doff;
    if (!SetFilePointerEx(hf, off, NULL, FILE_BEGIN)) { CloseHandle(hf); return 0; }
    out = CreateFileA(target_exe, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) { CloseHandle(hf); return 0; }
    buf = (uint8_t *)malloc(1024 * 1024);
    if (!buf) { CloseHandle(out); CloseHandle(hf); return 0; }
    left = dsize;
    while (left > 0) {
        DWORD chunk = (left > 1048576) ? 1048576 : (DWORD)left;
        DWORD got = 0, wrote = 0;
        if (!ReadFile(hf, buf, chunk, &got, NULL) || got == 0) break;
        WriteFile(out, buf, got, &wrote, NULL);
        if (wrote != got) break;
        left -= got;
    }
    free(buf);
    CloseHandle(out);
    CloseHandle(hf);
    if (left != 0) { DeleteFileA(target_exe); return 0; }
    wprint(L"[+] แตกไฟล์เสร็จ\n");
    return 1;
}

static int open_target(const char *target_exe, const char *exe_dir,
                       DWORD *out_pid, HANDLE *out_h, uint64_t *out_base) {
    DWORD pid = find_pid("deef.exe");
    HANDLE h = NULL;
    uint64_t base = 0;
    int retry;
    if (pid) {
        wprint(L"[+] พบ deef.exe ที่รันอยู่ (PID: %lu)\n", (unsigned long)pid);
    } else {
        DWORD attr = GetFileAttributesA(target_exe);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (!extract_bundled_deef(target_exe)) {
                wchar_t wdir[512];
                towide(exe_dir, wdir, 512);
                wprint(L"[!] ไม่พบไฟล์ deef.exe ใน %s\n", wdir);
                return 0;
            }
            attr = GetFileAttributesA(target_exe);
            if (attr == INVALID_FILE_ATTRIBUTES) return 0;
        }
        wprint(L"[*] กำลังเปิด deef.exe...\n");
        {
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            char cmd[620];
            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            _snprintf(cmd, sizeof(cmd), "\"%s\"", target_exe);
            if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, exe_dir, &si, &pi)) {
                wprint(L"[!] เปิด deef.exe ไม่ได้ err=%lu\n", GetLastError());
                return 0;
            }
            pid = pi.dwProcessId;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            wprint(L"[+] เปิด deef.exe สำเร็จ (PID: %lu)\n", (unsigned long)pid);
        }
    }
    wprint(L"[*] รอโปรแกรมโหลด/Unpack ใน memory...\n");
    for (retry = 0; retry < 60; retry++) {
        uint8_t t[8];
        Sleep(500);
        if (!find_pid("deef.exe")) { wprint(L"[!] โปรแกรมเป้าหมายถูกปิด\n"); return 0; }
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
        return 0;
    }
    *out_pid = pid;
    *out_h = h;
    *out_base = base;
    return 1;
}

/* ---- --scan-calls <rva>: find CALL/JMP rel32 targeting base+rva ---- */
typedef struct { HANDLE h; uint64_t base; uint64_t want; int found; int cap; } ScanCallsCtx;

static void scan_calls_cb(uint64_t chunk_rva, uint8_t *buf, SIZE_T len, void *vctx) {
    ScanCallsCtx *c = (ScanCallsCtx *)vctx;
    SIZE_T i;
    for (i = 0; i + 5 <= len && c->found < c->cap; i++) {
        if (buf[i] != 0xE8 && buf[i] != 0xE9) continue;
        {
            int32_t rel;
            uint64_t tgt;
            memcpy(&rel, buf + i + 1, 4);
            tgt = c->base + chunk_rva + i + 5 + (int64_t)rel;
            if (tgt == c->want) {
                int s = (i >= 8) ? (int)i - 8 : 0;
                int e = (int)i + 16;
                if (e > (int)len) e = (int)len;
                wprint(L"  %s @RVA 0x%llX\n", buf[i] == 0xE8 ? L"CALL" : L"JMP ",
                       (unsigned long long)(chunk_rva + i));
                print_hex(L"    bytes: ", buf + s, e - s);
                c->found++;
            }
        }
    }
}

static void tool_scan_calls(HANDLE h, uint64_t base, uint64_t size, uint64_t want_rva) {
    ScanCallsCtx ctx;
    ctx.h = h; ctx.base = base; ctx.want = base + want_rva; ctx.found = 0; ctx.cap = 300;
    wprint(L"[*] scan CALL/JMP -> RVA 0x%llX (abs 0x%llX)...\n",
           (unsigned long long)want_rva, (unsigned long long)ctx.want);
    walk_image(h, base, size, 1, scan_calls_cb, &ctx);
    wprint(L"[*] พบ %d จุด\n", ctx.found);
}

/* ---- --findstr <text>: find ASCII + UTF-16LE strings in module memory ---- */
typedef struct {
    uint8_t pa[256]; int la;
    uint8_t pw[512]; int lw;
    uint64_t base; int found; int cap;
} FindStrCtx;

static SIZE_T find_bytes(uint8_t *buf, SIZE_T len, uint8_t *pat, int plen, SIZE_T start) {
    SIZE_T i;
    if (plen <= 0 || (SIZE_T)plen > len) return (SIZE_T)-1;
    for (i = start; i + (SIZE_T)plen <= len; i++)
        if (memcmp(buf + i, pat, plen) == 0) return i;
    return (SIZE_T)-1;
}

static void print_asc_ctx(uint8_t *buf, SIZE_T pos, SIZE_T len) {
    SIZE_T s = (pos >= 16) ? pos - 16 : 0;
    SIZE_T e = pos + 48;
    SIZE_T i;
    char tmp[80];
    int o = 0;
    if (e > len) e = len;
    for (i = s; i < e && o < 70; i++) {
        uint8_t c = buf[i];
        tmp[o++] = (c >= 32 && c < 127) ? (char)c : '.';
    }
    tmp[o] = 0;
    {
        wchar_t w[80];
        int k;
        for (k = 0; k <= o; k++) w[k] = (wchar_t)(uint8_t)tmp[k];
        wprint(L"    ...%s...\n", w);
    }
}

static void findstr_cb(uint64_t chunk_rva, uint8_t *buf, SIZE_T len, void *vctx) {
    FindStrCtx *c = (FindStrCtx *)vctx;
    SIZE_T p = 0;
    while (c->found < c->cap) {
        p = find_bytes(buf, len, c->pa, c->la, p);
        if (p == (SIZE_T)-1) break;
        wprint(L"  [A] @ 0x%llX (RVA 0x%llX)\n",
               (unsigned long long)(c->base + chunk_rva + p),
               (unsigned long long)(chunk_rva + p));
        print_asc_ctx(buf, p, len);
        c->found++;
        p++;
    }
    p = 0;
    while (c->found < c->cap) {
        p = find_bytes(buf, len, c->pw, c->lw, p);
        if (p == (SIZE_T)-1) break;
        wprint(L"  [W] @ 0x%llX (RVA 0x%llX)\n",
               (unsigned long long)(c->base + chunk_rva + p),
               (unsigned long long)(chunk_rva + p));
        print_asc_ctx(buf, p, len);
        c->found++;
        p++;
    }
}

static void tool_findstr(HANDLE h, uint64_t base, uint64_t size, const char *text) {
    FindStrCtx ctx;
    size_t n = strlen(text), i;
    wchar_t w[300];
    if (n == 0 || n > 120) { wprint(L"[!] ข้อความค้นหายาวเกินไป\n"); return; }
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.pa, text, n);
    ctx.la = (int)n;
    for (i = 0; i < n; i++) { ctx.pw[2 * i] = (uint8_t)text[i]; ctx.pw[2 * i + 1] = 0; }
    ctx.lw = (int)(n * 2);
    ctx.base = base; ctx.found = 0; ctx.cap = 50;
    towide(text, w, 300);
    wprint(L"[*] findstr \"%s\" (ASCII + UTF-16)...\n", w);
    walk_image(h, base, size, 0, findstr_cb, &ctx);
    wprint(L"[*] พบ %d จุด\n", ctx.found);
}

/* ---- --scan-ref <addr>: find LEA reg,[rip+rel] referencing runtime addr ---- */
typedef struct { uint64_t base; uint64_t want; int found; int cap; } ScanRefCtx;

static void scan_ref_cb(uint64_t chunk_rva, uint8_t *buf, SIZE_T len, void *vctx) {
    ScanRefCtx *c = (ScanRefCtx *)vctx;
    SIZE_T i;
    for (i = 0; i + 8 <= len && c->found < c->cap; i++) {
        SIZE_T j = i;
        int32_t rel;
        uint64_t tgt;
        if (buf[j] >= 0x40 && buf[j] <= 0x4F) j++;
        if (j + 6 > len) break;
        if (buf[j] != 0x8D) continue;
        if ((buf[j + 1] & 0xC7) != 0x05) continue; /* mod=00 rm=101 (rip-rel) */
        memcpy(&rel, buf + j + 2, 4);
        tgt = c->base + chunk_rva + j + 6 + (int64_t)rel;
        if (tgt == c->want) {
            int e = (int)i + 12;
            if (e > (int)len) e = (int)len;
            wprint(L"  LEA @RVA 0x%llX\n", (unsigned long long)(chunk_rva + i));
            print_hex(L"    bytes: ", buf + i, e - (int)i);
            c->found++;
        }
    }
}

static void tool_scan_ref(HANDLE h, uint64_t base, uint64_t size, uint64_t want) {
    ScanRefCtx ctx;
    ctx.base = base; ctx.want = want; ctx.found = 0; ctx.cap = 300;
    wprint(L"[*] scan LEA-ref -> 0x%llX...\n", (unsigned long long)want);
    walk_image(h, base, size, 1, scan_ref_cb, &ctx);
    wprint(L"[*] พบ %d จุด\n", ctx.found);
}

/* ---- --trace rva...: HWBP hit counters (single-shot + periodic re-arm) ---- */
static int force_arm_thread(HANDLE ht, uint64_t *addrs, int n) {
    CONTEXT ctx;
    uint64_t *dr[4];
    int i;
    if (SuspendThread(ht) == (DWORD)-1) return 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(ht, &ctx)) { ResumeThread(ht); return 0; }
    dr[0] = &ctx.Dr0; dr[1] = &ctx.Dr1; dr[2] = &ctx.Dr2; dr[3] = &ctx.Dr3;
    for (i = 0; i < n; i++) {
        int enabled = (int)((ctx.Dr7 >> (2 * i)) & 3);
        if (enabled && *dr[i] != addrs[i]) { ResumeThread(ht); return 0; } /* foreign occupant */
    }
    for (i = 0; i < n; i++) {
        *dr[i] = addrs[i];
        ctx.Dr7 |= (1ULL << (2 * i));
        ctx.Dr7 &= ~(0xFULL << (16 + 4 * i));
        ctx.Dr6 &= ~(1ULL << i);
    }
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SetThreadContext(ht, &ctx);
    ResumeThread(ht);
    return 1;
}

static int force_arm_all(DWORD pid, uint64_t *addrs, int n) {
    int ok = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            HANDLE ht;
            if (te.th32OwnerProcessID != pid) continue;
            ht = open_thread_full(te.th32ThreadID);
            if (!ht) continue;
            if (force_arm_thread(ht, addrs, n)) ok++;
            CloseHandle(ht);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ok;
}

static int tool_trace(HANDLE h, DWORD pid, uint64_t base, uint64_t *rvas, int n) {
    uint64_t mem, datab;
    uint64_t veh_addr, done_addr, stub_addr;
    uint8_t veh[128], stub[64];
    int veh_len, stub_len, i;
    uint64_t addrs[4];
    uint64_t veh_handle;
    DWORD old = 0;
    for (i = 0; i < n && i < 4; i++) addrs[i] = base + rvas[i];

    mem = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    datab = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem || !datab) {
        wprint(L"[!] VirtualAllocEx ล้มเหลว err=%lu\n", GetLastError());
        return 1;
    }
    veh_addr = mem + L_VEH; done_addr = mem + L_DONE; stub_addr = mem + L_RTSTUB;
    veh_len = sc_trace_veh(veh, datab, datab + 0x40);
    wpm(h, datab + 0x40, addrs, (SIZE_T)(n * 8)); /* slot->address verify table */
    {
        stub_len = build_rtstub(stub, 1, veh_addr, 0, 0,
                             remote_proc(h, "kernel32.dll", "AddVectoredExceptionHandler"), datab + 0x80);
    }
    wpm(h, veh_addr, veh, veh_len);
    {
        uint8_t doneb[2] = { 0xEB, 0xFE };
        wpm(h, done_addr, doneb, 2);
    }
    wpm(h, stub_addr, stub, stub_len);
    VirtualProtectEx(h, (LPVOID)(uintptr_t)mem, 4096, PAGE_EXECUTE_READ, &old);

    veh_handle = remote_add_veh_hijack(h, pid, veh_addr, done_addr);
    if (veh_handle) {
        wprint(L"[*] VEH via hijack (ไม่สร้าง thread ใหม่)\n");
    } else {
        veh_handle = remote_add_veh_remote_thread(h, stub_addr, datab + 0x80);
        if (veh_handle) wprint(L"[*] VEH via CreateRemoteThread (fallback)\n");
    }
    if (!veh_handle) {
        wprint(L"[!] ติดตั้ง VEH ไม่สำเร็จ\n");
        return 1;
    }
    wprint(L"[+] VEH handle=0x%llX — tracing %d address(es):\n", (unsigned long long)veh_handle, n);
    for (i = 0; i < n; i++)
        wprint(L"    slot%d: RVA 0x%llX (0x%llX)\n", i,
               (unsigned long long)rvas[i], (unsigned long long)addrs[i]);
    force_arm_all(pid, addrs, n);
    wprint(L"[*] ไปกดใช้งานใน deef ได้เลย — ตัวนับจะขึ้นเมื่อโค้ดวิ่งผ่านจุดนั้น (ปิด deef เพื่อจบ)\n");
    {
        uint64_t last[4] = { 0, 0, 0, 0 };
        int tick = 0;
        for (;;) {
            uint64_t cur[4] = { 0, 0, 0, 0 };
            int changed = 0;
            Sleep(500);
            if (!target_alive(h)) break;
            for (i = 0; i < n; i++) {
                rpm(h, datab + 8 * i, &cur[i], 8);
                if (cur[i] != last[i]) changed = 1;
                last[i] = cur[i];
            }
            if (changed) {
                wprint(L"[TRACE]");
                for (i = 0; i < n; i++)
                    wprint(L"  0x%llX=%llu", (unsigned long long)rvas[i], (unsigned long long)cur[i]);
                wprint(L"\n");
            }
            if (++tick % 4 == 0) force_arm_all(pid, addrs, n); /* re-arm single-shots */
        }
        wprint(L"[*] สรุป:");
        for (i = 0; i < n; i++)
            wprint(L"  0x%llX=%llu", (unsigned long long)rvas[i], (unsigned long long)last[i]);
        wprint(L"\n[*] deef ปิดแล้ว — ปิด tracer ได้\n");
        report_exit(h);
    }
    return 0;
}

/* ---- --diag: one-shot discovery batch ---- */
static void tool_diag(HANDLE h, uint64_t base, uint64_t size) {
    wprint(L"===== DIAG BATCH =====\n");
    tool_scan_calls(h, base, size, RVA_LOGIN_SCREEN);
    tool_scan_calls(h, base, size, RVA_MAIN_SCREEN);
    tool_findstr(h, base, size, "Authentication failed.");
    wprint(L"===== END DIAG =====\n");
}

/* ---- --probe v2.13: ทางผ่านเดียวที่เหลือ = PAGE_GUARD ----
 * v2.12 สรุป:  VEH ทำงานแล้ว (เห็น exception 12 ครั้ง — Enigma ใช้ #DB เองด้วย)
 *              hardware breakpoint → Enigma จับได้ → exit 0xDEADC0DE (8.8วิ)
 *              int3 (แก้โค้ด 1 ไบต์) → Enigma จับได้ → exit 0xDEADC0DE (10.3วิ)
 *              PAGE_GUARD → Enigma **ไม่**จับ (ตายเพราะ exception เราไม่รับเอง 6.6วิ)
 * ก็เลยใช้ PAGE_GUARD เป็นตัวสะดุดแทน:
 *   G0 = PAGE_GUARD + handler ครบชุด (รับทุกการเข้าถึงในเพจ + ตั้ง TF + ตั้ง guard ใหม่ผ่าน syscall ตรง)
 *   G1 = PAGE_GUARD แบบยิงครั้งเดียว (ไม่มี TF/syscall — ตัวสำรอง) */

typedef struct { uint64_t code; uint64_t addr; } ExcEnt;

/* ดูเลข syscall จากโค้ดสะอาดของเรา: 4C 8B D1 | B8 <num> */
static uint32_t get_syscall_no(const char *name) {
    FARPROC f = GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
    uint8_t *b = (uint8_t *)f;
    uint32_t n = 0;
    if (!f) return 0x50;
    if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8) {
        memcpy(&n, b + 4, 4);
        return n;
    }
    return 0x50;
}

static uint64_t probe_alloc2(HANDLE h, uint64_t *out_mem, uint64_t *out_datab) {
    uint64_t mem = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    uint64_t datab = (uint64_t)(uintptr_t)VirtualAllocEx(h, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem || !datab) {
        wprint(L"[!] VirtualAllocEx ล้มเหลว err=%lu\n", GetLastError());
        return 0;
    }
    *out_mem = mem;
    *out_datab = datab;
    return 1;
}

static uint64_t install_veh(HANDLE h, uint64_t handler, uint64_t mem, uint64_t datab) {
    uint8_t stub[128];
    uint8_t doneb[2] = { 0xEB, 0xFE };
    uint64_t addveh = remote_proc(h, "ntdll.dll", "RtlAddVectoredExceptionHandler");
    uint64_t vh = 0;
    int n;
    DWORD old = 0;
    HANDLE rt;
    if (!addveh) { wprint(L"[!]   หา RtlAddVectoredExceptionHandler ไม่เจอ\n"); return 0; }
    n = build_rtstub(stub, 1, handler, 0, 0, addveh, datab + 0x80);
    wpm(h, mem + L_RTSTUB, stub, (SIZE_T)n);
    wpm(h, mem + L_DONE, doneb, 2);
    VirtualProtectEx(h, (LPVOID)(uintptr_t)mem, 4096, PAGE_EXECUTE_READ, &old);
    rt = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)(uintptr_t)(mem + L_RTSTUB), NULL, 0, NULL);
    if (rt) { WaitForSingleObject(rt, 5000); CloseHandle(rt); }
    rpm(h, datab + 0x80, &vh, 8);
    if (vh) wprint(L"[*]   ลง VEH ได้ handle=0x%llX handler=0x%llX\n",
                   (unsigned long long)vh, (unsigned long long)handler);
    else wprint(L"[!]   ลง VEH ไม่สำเร็จ\n");
    return vh;
}

struct WinFind { DWORD pid; HWND hwnd; char title[256]; };
static BOOL CALLBACK enum_win_cb(HWND hw, LPARAM lp) {
    struct WinFind *w = (struct WinFind *)lp;
    DWORD pid = 0;
    char title[256];
    if (!IsWindowVisible(hw)) return TRUE;
    GetWindowThreadProcessId(hw, &pid);
    if (pid != w->pid) return TRUE;
    title[0] = 0;
    GetWindowTextA(hw, title, sizeof(title));
    if (!title[0]) return TRUE;
    w->hwnd = hw;
    strcpy(w->title, title);
    return FALSE;
}

static void dump_log(uint64_t total, ExcEnt *ring, uint64_t base) {
    int k, newest;
    if (!total) return;
    newest = (int)((total - 1) & 31);
    for (k = 2; k >= 0; k--) {
        int idx = (newest - k + 32) & 31;
        if (total < (uint64_t)(k + 1)) continue;
        wprint(L"        #%llu code=0x%08X addr=0x%llX",
               (unsigned long long)(total - k),
               (unsigned)(ring[idx].code & 0xFFFFFFFFu),
               (unsigned long long)ring[idx].addr);
        if (base && ring[idx].addr >= base && ring[idx].addr < base + 0x10000000)
            wprint(L" (deef+0x%llX)", (unsigned long long)(ring[idx].addr - base));
        wprint(L"\n");
    }
}

static int watch_run(HANDLE h, DWORD pid, int secs, uint64_t counter, const wchar_t *tag,
                     uint64_t page, DWORD orig_prot, uint64_t log_total, uint64_t log_ring,
                     uint64_t base) {
    int i;
    uint64_t hits = 0, shown = 0;
    ExcEnt ring[32], tmp[32];
    uint64_t ltot = 0, lshown = 0;
    memset(ring, 0, sizeof(ring));
    for (i = 0; i < secs * 10; i++) {
        Sleep(100);
        if (log_total) {
            uint64_t t = 0;
            if (rpm(h, log_total, &t, 8)) ltot = t;
            if (rpm(h, log_ring, tmp, sizeof(tmp))) memcpy(ring, tmp, sizeof(ring));
        }
        if (!target_alive(h)) {
            wprint(L"[DIED] %s: ตายหลัง ~%.1f วินาที! ", tag, (i + 1) * 0.1);
            report_exit(h);
            wprint(L"[*]   exception ที่ handler เห็น: %llu ครั้ง\n", (unsigned long long)ltot);
            dump_log(ltot, ring, base);
            return 0;
        }
        if (log_total && ltot != lshown && (ltot - lshown >= 3 || i % 5 == 4)) {
            wprint(L"[EXC] เห็น exception แล้ว %llu ครั้ง\n", (unsigned long long)ltot);
            dump_log(ltot, ring, base);
            lshown = ltot;
        }
        if (counter) {
            rpm(h, counter, &hits, 8);
            if (hits != shown) {
                wprint(L"[HIT] จุด login สะดุดแล้ว! รวม %llu ครั้ง\n", (unsigned long long)hits);
                shown = hits;
            }
            if (hits && page) {   /* ผ่านแล้ว — เอาสิทธิ์เพจคืนให้เหมือนเดิม */
                DWORD oldp = 0;
                VirtualProtectEx(h, (LPVOID)(uintptr_t)page, 0x1000, orig_prot, &oldp);
                wprint(L"[*]   คืนสิทธิ์เพจเป็นปกติแล้ว (กันความช้า)\n");
                page = 0;
            }
        }
        if (i % 20 == 19) {
            struct WinFind w;
            wchar_t wt[256];
            w.pid = pid; w.hwnd = NULL; w.title[0] = 0;
            EnumWindows(enum_win_cb, (LPARAM)&w);
            towide(w.title, wt, 256);
            wprint(L"[*]   t=%.1fวิ หน้าต่าง: \"%s\" hits=%llu\n",
                   (i + 1) * 0.1, wt[0] ? wt : L"(ไม่มี)", (unsigned long long)hits);
        }
    }
    wprint(L"[LIVE] %s: รอดครบ %d วินาที (hits=%llu)\n", tag, secs, (unsigned long long)hits);
    return 1;
}

static int tool_probe(const char *target_exe, const char *exe_dir) {
    int live[2] = { 0, 0 };
    int opened[2] = { 0, 0 };
    int s;
    static const wchar_t *tags[2] = {
        L"G0  PAGE_GUARD + ตั้ง guard ใหม่ผ่าน syscall ตรง",
        L"G1  PAGE_GUARD ยิงครั้งเดียว (ตัวสำรอง)"
    };
    wprint(L"[*] probe v2.13: ใช้ PAGE_GUARD เป็นตัวสะดุด (ไม่แตะโค้ด ไม่แตะ Dr)\n");
    for (s = 0; s < 2; s++) {
        DWORD pid = 0;
        HANDLE h = NULL;
        uint64_t base = 0, hook, mem = 0, datab = 0;
        uint64_t page, main_screen, code_addr, user_str, key_str, user_lng, key_lng;
        uint64_t counter, scratch, handler, log_total, log_ring;
        uint8_t veh[512], code[512], st[32], longbuf[256];
        int n;
        DWORD oldp = 0;
        uint32_t sysno = get_syscall_no("NtProtectVirtualMemory");
        kill_deef();
        wprint(L"\n===== PROBE %d/2 =====\n", s);
        if (!open_target(target_exe, exe_dir, &pid, &h, &base)) {
            wprint(L"[DIED] ขั้น %d: เปิด/wait ไม่ผ่านตั้งแต่ต้น\n", s);
            continue;
        }
        opened[s] = 1;
        hook = base + RVA_LOGIN_SCREEN;
        page = hook & ~0xFFFULL;
        if (!probe_alloc2(h, &mem, &datab)) { CloseHandle(h); continue; }
        main_screen = base + RVA_MAIN_SCREEN;
        code_addr = mem + L_CODE; user_str = mem + L_USER_STR; key_str = mem + L_KEY_STR;
        user_lng = mem + L_USER_LONG; key_lng = mem + L_KEY_LONG;
        counter = datab + 0x100; scratch = datab + 0x300; handler = mem + 0x500;
        log_total = datab + 0x108; log_ring = datab + 0x200;

        n = sc_guard_veh(veh, page, page + 0x1000, hook, code_addr, counter,
                         scratch, log_total, log_ring, sysno, s == 0 ? 1 : 0);
        wpm(h, handler, veh, (SIZE_T)n);
        n = sc_build_entry(code, main_screen, user_str, key_str);
        wpm(h, code_addr, code, (SIZE_T)n);
        sc_std_string(st, "VIP User", user_lng, longbuf);
        wpm(h, user_str, st, 32);
        sc_std_string(st, "ARENA-2026-FREE", key_lng, longbuf);
        wpm(h, key_str, st, 32);
        wprint(L"[*]   handler %d ไบต์ @0x%llX (syscall NtProtectVirtualMemory=#0x%lX)\n",
               n, (unsigned long long)handler, (unsigned long)sysno);
        /* ตั้ง PAGE_GUARD บนเพจของจุด login (ไม่แตะโค้ดเลย) */
        if (!VirtualProtectEx(h, (LPVOID)(uintptr_t)page, 0x1000,
                              PAGE_EXECUTE_READ | PAGE_GUARD, &oldp)) {
            wprint(L"[!]   ตั้ง PAGE_GUARD ไม่ได้ err=%lu\n", GetLastError());
            CloseHandle(h);
            continue;
        }
        wprint(L"[*]   ตั้ง PAGE_GUARD บนเพจ 0x%llX แล้ว (สิทธิ์เดิม=0x%lX)\n",
               (unsigned long long)page, (unsigned long)oldp);
        if (!install_veh(h, handler, mem, datab)) { CloseHandle(h); continue; }
        live[s] = watch_run(h, pid, 22, counter, tags[s], page, oldp,
                            log_total, log_ring, base);
        CloseHandle(h);
    }
    kill_deef();
    wprint(L"\n===== PROBE SUMMARY =====\n");
    for (s = 0; s < 2; s++)
        wprint(L"  G%d: %s\n", s, !opened[s] ? L"เปิดไม่ติด" : live[s] ? L"รอด" : L"ตาย");
    wprint(L"[*] ถ้ามี [HIT] + รอด = ข้าม login สำเร็จ → รัน LoginKeyPatcher.exe any ใช้งานจริงได้เลย\n");
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
    char target_exe[600];
    char *slash;
    DWORD pid;
    HANDLE h = NULL;
    uint64_t base = 0;
    int rc;

    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    g_log = _wfopen(L"patcher_log.txt", L"a, ccs=UTF-8");
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
    wprint(L"     LOGIN KEY PATCHER v2.14 (GUARD+LOG)          \n");
    wprint(L"=================================================\n");

    GetModuleFileNameA(NULL, exe_dir, sizeof(exe_dir));
    slash = strrchr(exe_dir, '\\');
    if (slash) *slash = 0;
    else strcpy(exe_dir, ".");
    _snprintf(target_exe, sizeof(target_exe), "%s\\deef.exe", exe_dir);

    /* ---- RE tool modes ---- */
    if (argi < argc && strncmp(argv[argi], "--", 2) == 0) {
        if (strcmp(argv[argi], "--probe") == 0) {
            int trc;
            print_target_identity(target_exe);
            trc = tool_probe(target_exe, exe_dir);
            if (g_log) fclose(g_log);
            return trc;
        }
        if (strcmp(argv[argi], "--scan-calls") == 0 || strcmp(argv[argi], "--findstr") == 0 ||
            strcmp(argv[argi], "--scan-ref") == 0 || strcmp(argv[argi], "--trace") == 0 ||
            strcmp(argv[argi], "--diag") == 0) {
            DWORD tpid;
            HANDLE th = NULL;
            uint64_t tbase = 0, tsize = 0;
            int trc = 1;
            print_target_identity(target_exe);
            if (open_target(target_exe, exe_dir, &tpid, &th, &tbase)) {
                tsize = get_module_size(th, tbase);
                wprint(L"[*] module size=0x%llX\n", (unsigned long long)tsize);
                if (tsize) {
                    if (strcmp(argv[argi], "--scan-calls") == 0) {
                        if (argi + 1 >= argc) { wprint(L"[!] ระบุ RVA เช่น --scan-calls 214370\n"); }
                        else { tool_scan_calls(th, tbase, tsize, strtoull(argv[argi + 1], NULL, 16)); trc = 0; }
                    } else if (strcmp(argv[argi], "--findstr") == 0) {
                        if (argi + 1 >= argc) { wprint(L"[!] ระบุข้อความ เช่น --findstr \"Authentication failed.\"\n"); }
                        else { tool_findstr(th, tbase, tsize, argv[argi + 1]); trc = 0; }
                    } else if (strcmp(argv[argi], "--scan-ref") == 0) {
                        if (argi + 1 >= argc) { wprint(L"[!] ระบุ address เช่น --scan-ref 7FF6A9ACA0B9\n"); }
                        else { tool_scan_ref(th, tbase, tsize, strtoull(argv[argi + 1], NULL, 16)); trc = 0; }
                    } else if (strcmp(argv[argi], "--trace") == 0) {
                        uint64_t rvas[4];
                        int n = 0;
                        while (argi + 1 + n < argc && n < 4) {
                            rvas[n] = strtoull(argv[argi + 1 + n], NULL, 16);
                            n++;
                        }
                        if (n == 0) { wprint(L"[!] ระบุ RVA เช่น --trace 214370 2194B0\n"); }
                        else { trc = tool_trace(th, tpid, tbase, rvas, n); }
                    } else if (strcmp(argv[argi], "--diag") == 0) {
                        tool_diag(th, tbase, tsize);
                        trc = 0;
                    }
                }
                CloseHandle(th);
            }
            if (g_log) fclose(g_log);
            return trc;
        }
    }

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
    if (key[0] == 0) strcpy(key, "VIP-PREMIUM");

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

    print_target_identity(target_exe);

    if (!open_target(target_exe, exe_dir, &pid, &h, &base)) {
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
