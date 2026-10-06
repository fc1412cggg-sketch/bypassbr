/* Shellcode builders for LoginKeyPatcher — pure C, no platform deps.
 * Included by LoginKeyPatcher.c (Windows) and the Linux test harness.
 * All x64 encodings verified with capstone.
 *
 * cont (continuation): 0 = end blocks with ret (DIRECT in-place hook style),
 *   nonzero = end blocks with jmp cont (STEALTH VEH+HWBP style: HW breakpoint
 *   fires before executing the hooked instruction, VEH redirects here, and we
 *   jump back to hook+LEN afterwards — zero bytes modified in target image).
 */
#ifndef SC_BUILD_H
#define SC_BUILD_H

#include <stdint.h>
#include <string.h>

typedef struct { uint8_t *buf; int pos; } ScBuf;

static void sc_put(ScBuf *s, const void *data, int n) { memcpy(s->buf + s->pos, data, n); s->pos += n; }
static void sc_u8(ScBuf *s, uint8_t v) { s->buf[s->pos++] = v; }
static void sc_u32(ScBuf *s, uint32_t v) { memcpy(s->buf + s->pos, &v, 4); s->pos += 4; }
static void sc_u64(ScBuf *s, uint64_t v) { memcpy(s->buf + s->pos, &v, 8); s->pos += 8; }

/* Prologue: save regs, align stack (ABI-safe inner calls), rbx = AppContext,
 * rsi = typed key chars (SSO-aware). r12 preserves the entry Rsp. */
static const uint8_t B_PROLOGUE[] = {
    0x53,                         /* push rbx */
    0x56,                         /* push rsi */
    0x57,                         /* push rdi */
    0x41, 0x54,                   /* push r12 */
    0x49, 0x89, 0xE4,             /* mov r12, rsp */
    0x48, 0x83, 0xE4, 0xF0,       /* and rsp, -16 */
    0x48, 0x83, 0xEC, 0x20,       /* sub rsp, 0x20 (shadow space) */
    0x48, 0x89, 0xCB,             /* mov rbx, rcx */
    0x48, 0x8D, 0xB3, 0xB8, 0x01, 0x00, 0x00, /* lea rsi, [rbx+0x1B8] */
    0x48, 0x83, 0xBB, 0xD0, 0x01, 0x00, 0x00, 0x0F, /* cmp [rbx+0x1D0], 15 */
    0x76, 0x07,                   /* jbe +7 */
    0x48, 0x8B, 0xB3, 0xB8, 0x01, 0x00, 0x00  /* mov rsi, [rbx+0x1B8] */
};
static const uint8_t B_EPILOGUE_PRE[] = {
    0x4C, 0x89, 0xE4,             /* mov rsp, r12 (restore exact entry Rsp) */
    0x41, 0x5C,                   /* pop r12 */
    0x5F, 0x5E, 0x5B              /* pop rdi/rsi/rbx */
};
static const uint8_t B_MOV_RDI_LEN[]  = { 0x48, 0x8B, 0xBB, 0xC8, 0x01, 0x00, 0x00 };
static const uint8_t B_TEST_RDI[]     = { 0x48, 0x85, 0xFF };
static const uint8_t B_MOV_R10_LEN[]  = { 0x4C, 0x8B, 0x93, 0xC8, 0x01, 0x00, 0x00 };
static const uint8_t B_MOV_R11[]      = { 0x49, 0xBB };
static const uint8_t B_JMP_R11[]      = { 0x41, 0xFF, 0xE3 };
static const uint8_t B_CMP_R10[]      = { 0x49, 0x81, 0xFA };
static const uint8_t B_JNE32[]        = { 0x0F, 0x85 };
static const uint8_t B_XOR_ECX[]      = { 0x31, 0xC9 };
static const uint8_t B_MOV_AL[]       = { 0x8A, 0x04, 0x0E };
static const uint8_t B_TOLOWER_AL[]   = { 0x3C, 0x41, 0x72, 0x06, 0x3C, 0x5A, 0x77, 0x02, 0x0C, 0x20 };
static const uint8_t B_MOV_DL[]       = { 0x41, 0x8A, 0x14, 0x0B };
static const uint8_t B_TOLOWER_DL[]   = { 0x80, 0xFA, 0x41, 0x72, 0x06, 0x80, 0xFA, 0x5A, 0x77, 0x02, 0x80, 0xCA, 0x20 };
static const uint8_t B_CMP_DL_AL[]    = { 0x38, 0xC2 };
static const uint8_t B_INC_ECX[]      = { 0xFF, 0xC1 };
static const uint8_t B_CMP_ECX_R10D[] = { 0x44, 0x39, 0xD1 };
static const uint8_t B_MOV_RCX_RBX[]  = { 0x48, 0x89, 0xD9 };
static const uint8_t B_MOV_RAX[]      = { 0x48, 0xB8 };
static const uint8_t B_CALL_RAX[]     = { 0xFF, 0xD0 };
static const uint8_t B_MOV_RDX[]      = { 0x48, 0xBA };
static const uint8_t B_LEA_R8[]       = { 0x4C, 0x8D, 0x83, 0xB8, 0x01, 0x00, 0x00 }; /* lea r8,[rbx+0x1B8] */
static const uint8_t B_MOV_R8[]       = { 0x49, 0xB8 };
static const uint8_t B_MOV_R9D1[]     = { 0x41, 0xB9, 0x01, 0x00, 0x00, 0x00 };

#define SC_PUT(s, blob) sc_put(s, blob, (int)sizeof(blob))

static void sc_epilogue(ScBuf *s, uint64_t cont) {
    SC_PUT(s, B_EPILOGUE_PRE);
    if (cont) {
        SC_PUT(s, B_MOV_R11); sc_u64(s, cont);
        SC_PUT(s, B_JMP_R11);
    } else {
        sc_u8(s, 0xC3); /* ret */
    }
}

static void sc_call_login(ScBuf *s, uint64_t login_screen, uint64_t cont) {
    SC_PUT(s, B_MOV_RCX_RBX);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, login_screen);
    SC_PUT(s, B_CALL_RAX);
    sc_epilogue(s, cont);
}

static void sc_call_main_pass(ScBuf *s, uint64_t fake_user, uint64_t main_screen, uint64_t cont) {
    SC_PUT(s, B_MOV_RCX_RBX);
    SC_PUT(s, B_MOV_RDX); sc_u64(s, fake_user);
    SC_PUT(s, B_LEA_R8); /* r8 = &typed key string (pass-through) */
    SC_PUT(s, B_MOV_R9D1);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, main_screen);
    SC_PUT(s, B_CALL_RAX);
    sc_epilogue(s, cont);
}

static void sc_call_main_fake(ScBuf *s, uint64_t fake_user, uint64_t fake_key, uint64_t main_screen, uint64_t cont) {
    SC_PUT(s, B_MOV_RCX_RBX);
    SC_PUT(s, B_MOV_RDX); sc_u64(s, fake_user);
    SC_PUT(s, B_MOV_R8); sc_u64(s, fake_key);
    SC_PUT(s, B_MOV_R9D1);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, main_screen);
    SC_PUT(s, B_CALL_RAX);
    sc_epilogue(s, cont);
}

/* any: typed_len > 0 -> main, else login */
static int sc_build_any(uint8_t *out, uint64_t login_screen, uint64_t main_screen, uint64_t fake_user, uint64_t cont) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    SC_PUT(s, B_PROLOGUE);
    SC_PUT(s, B_MOV_RDI_LEN);
    SC_PUT(s, B_TEST_RDI);
    int jz = s->pos;    sc_u8(s, 0x74); sc_u8(s, 0x00);
    int jmpm = s->pos;  sc_u8(s, 0xEB); sc_u8(s, 0x00);
    int login_pos = s->pos;
    sc_call_login(s, login_screen, cont);
    int main_pos = s->pos;
    sc_call_main_pass(s, fake_user, main_screen, cont);
    out[jz + 1] = (uint8_t)(login_pos - (jz + 2));
    out[jmpm + 1] = (uint8_t)(main_pos - (jmpm + 2));
    return s->pos;
}

/* auto: straight to main with fake key+user */
static int sc_build_auto(uint8_t *out, uint64_t main_screen, uint64_t fake_user, uint64_t fake_key, uint64_t cont) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    SC_PUT(s, B_PROLOGUE);
    sc_call_main_fake(s, fake_user, fake_key, main_screen, cont);
    return s->pos;
}

/* custom: case-insensitive compare against expected bytes */
static int sc_build_custom(uint8_t *out, uint64_t login_screen, uint64_t main_screen,
                           uint64_t fake_user, uint64_t expect_addr, uint32_t expect_len, uint64_t cont) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    SC_PUT(s, B_PROLOGUE);
    SC_PUT(s, B_MOV_R10_LEN);
    SC_PUT(s, B_MOV_R11); sc_u64(s, expect_addr);
    SC_PUT(s, B_CMP_R10); sc_u32(s, expect_len);
    int jne1 = s->pos; SC_PUT(s, B_JNE32); sc_u32(s, 0);
    SC_PUT(s, B_XOR_ECX);
    int loop = s->pos;
    SC_PUT(s, B_MOV_AL);
    SC_PUT(s, B_TOLOWER_AL);
    SC_PUT(s, B_MOV_DL);
    SC_PUT(s, B_TOLOWER_DL);
    SC_PUT(s, B_CMP_DL_AL);
    int jne2 = s->pos; SC_PUT(s, B_JNE32); sc_u32(s, 0);
    SC_PUT(s, B_INC_ECX);
    SC_PUT(s, B_CMP_ECX_R10D);
    int jb = s->pos;   sc_u8(s, 0x72); sc_u8(s, 0x00);
    int jmpm = s->pos; sc_u8(s, 0xEB); sc_u8(s, 0x00);
    int login_pos = s->pos;
    sc_call_login(s, login_screen, cont);
    int main_pos = s->pos;
    sc_call_main_pass(s, fake_user, main_screen, cont);
    { int32_t r1 = (int32_t)(login_pos - (jne1 + 6)); memcpy(out + jne1 + 2, &r1, 4); }
    { int32_t r2 = (int32_t)(login_pos - (jne2 + 6)); memcpy(out + jne2 + 2, &r2, 4); }
    out[jb + 1] = (uint8_t)(loop - (jb + 2));
    out[jmpm + 1] = (uint8_t)(main_pos - (jmpm + 2));
    return s->pos;
}

/* ENTRY-REDIRECT shellcode: runs INSTEAD of loginScreen (HWBP at its entry).
 * rcx (login's arg1, AppContext) is forwarded untouched to mainScreen.
 * Old login (validation, auth API, "Authentication failed." path) never executes.
 * Ends with ret -> returns to loginScreen's caller with RAX=1 (success). */
static int sc_build_entry(uint8_t *out, uint64_t main_screen, uint64_t fake_user, uint64_t fake_key) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    static const uint8_t pro[] = {
        0x53,                         /* push rbx */
        0x56,                         /* push rsi */
        0x57,                         /* push rdi */
        0x41, 0x54,                   /* push r12 */
        0x49, 0x89, 0xE4,             /* mov r12, rsp */
        0x48, 0x83, 0xE4, 0xF0,       /* and rsp, -16 */
        0x48, 0x83, 0xEC, 0x20        /* sub rsp, 0x20 */
    };
    SC_PUT(s, pro);
    SC_PUT(s, B_MOV_RDX); sc_u64(s, fake_user);
    SC_PUT(s, B_MOV_R8); sc_u64(s, fake_key);
    SC_PUT(s, B_MOV_R9D1);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, main_screen);
    SC_PUT(s, B_CALL_RAX);
    { static const uint8_t m[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; SC_PUT(s, m); } /* mov eax, 1 */
    sc_epilogue(s, 0); /* restore regs + ret to login's caller */
    return s->pos;
}

/* VEH handler stub: LONG Handler(EXCEPTION_POINTERS *p).
 * if (p->ExceptionRecord->ExceptionCode == SINGLE_STEP &&
 *     p->ExceptionRecord->ExceptionAddress == hook_addr) {
 *     p->ContextRecord->Dr6 = 0;
 *     p->ContextRecord->Rip = shell_addr;
 *     (*counter_addr)++;   // diagnostics: loader polls this (RW data block)
 *     return EXCEPTION_CONTINUE_EXECUTION; // 0
 * }
 * return EXCEPTION_CONTINUE_SEARCH; // 1
 * Uses only volatile regs (rax, rdx, r10, r11). Offsets (x64 ABI):
 *   EXCEPTION_RECORD: Code@0x00, Address@0x10
 *   EXCEPTION_POINTERS: Record@0x00, Context@0x08
 *   CONTEXT: Dr6@0x68, Rip@0xF8
 */
static int sc_veh_handler(uint8_t *out, uint64_t hook_addr, uint64_t shell_addr, uint64_t counter_addr) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    static const uint8_t m1[] = { 0x48, 0x8B, 0x01 };                 /* mov rax, [rcx] */
    static const uint8_t m2[] = { 0x81, 0x38, 0x04, 0x00, 0x00, 0x80 }; /* cmp dword [rax], 0x80000004 */
    static const uint8_t m3[] = { 0x48, 0x8B, 0x51, 0x08 };           /* mov rdx, [rcx+8] */
    static const uint8_t m4[] = { 0x4C, 0x8B, 0x50, 0x10 };           /* mov r10, [rax+0x10] */
    static const uint8_t m5[] = { 0x4D, 0x39, 0xDA };                 /* cmp r10, r11 */
    static const uint8_t m6[] = { 0x48, 0xC7, 0x42, 0x68, 0x00, 0x00, 0x00, 0x00 }; /* mov qword [rdx+0x68], 0 */
    static const uint8_t m7[] = { 0x4C, 0x89, 0x9A, 0xF8, 0x00, 0x00, 0x00 };       /* mov [rdx+0xF8], r11 */
    SC_PUT(s, m1);
    SC_PUT(s, m2);
    int jne1 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    SC_PUT(s, m3);
    SC_PUT(s, m4);
    SC_PUT(s, B_MOV_R11); sc_u64(s, hook_addr);
    SC_PUT(s, m5);
    int jne2 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    SC_PUT(s, m6);
    SC_PUT(s, B_MOV_R11); sc_u64(s, shell_addr);
    SC_PUT(s, m7);
    { static const uint8_t m9[] = { 0x48, 0xB8 }; SC_PUT(s, m9); } /* mov rax, counter */
    sc_u64(s, counter_addr);
    { static const uint8_t m10[] = { 0x48, 0xFF, 0x00 }; SC_PUT(s, m10); } /* inc qword [rax] */
    sc_u8(s, 0x31); sc_u8(s, 0xC0); /* xor eax, eax (CONTINUE_EXECUTION) */
    sc_u8(s, 0xC3);                /* ret */
    int search = s->pos;
    { static const uint8_t m8[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; SC_PUT(s, m8); } /* mov eax, 1 */
    sc_u8(s, 0xC3);                /* ret */
    out[jne1 + 1] = (uint8_t)(search - (jne1 + 2));
    out[jne2 + 1] = (uint8_t)(search - (jne2 + 2));
    return s->pos;
}

/* TRACE VEH stub (diagnostics): single-shot per-thread hit counters.
 * On EXCEPTION_SINGLE_STEP with a Dr0-Dr3 status bit set:
 *   slot = bsf(Dr6 & 0xF); counters[slot]++; clear that slot's L-bit (single-shot);
 *   Dr6 = 0; return CONTINUE_EXECUTION (re-executes the hooked instruction
 *   normally since the breakpoint is now off). The loader re-arms periodically.
 * Foreign single-steps (Dr6&0xF == 0) return CONTINUE_SEARCH.
 * Uses only volatile regs (rax, rdx, r10, r11).
 */
static int sc_trace_veh(uint8_t *out, uint64_t counters_base) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    static const uint8_t m1[] = { 0x48, 0x8B, 0x01 };                 /* mov rax, [rcx] */
    static const uint8_t m2[] = { 0x81, 0x38, 0x04, 0x00, 0x00, 0x80 }; /* cmp dword [rax], 0x80000004 */
    static const uint8_t m3[] = { 0x48, 0x8B, 0x51, 0x08 };           /* mov rdx, [rcx+8] */
    static const uint8_t m4[] = { 0x4C, 0x8B, 0x52, 0x68 };           /* mov r10, [rdx+0x68] (Dr6) */
    static const uint8_t m5[] = { 0x41, 0xF6, 0xC2, 0x0F };           /* test r10b, 0x0F */
    static const uint8_t m6[] = { 0x41, 0x83, 0xE2, 0x0F };           /* and r10d, 0x0F */
    static const uint8_t m7[] = { 0x41, 0x0F, 0xBC, 0xC2 };           /* bsf eax, r10d */
    static const uint8_t m8[] = { 0x4D, 0x8D, 0x1C, 0xC3 };           /* lea r11, [r11+rax*8] */
    static const uint8_t m9[] = { 0x49, 0xFF, 0x03 };                 /* inc qword [r11] */
    static const uint8_t m10[] = { 0xD1, 0xE0 };                      /* shl eax, 1 */
    static const uint8_t m11[] = { 0x48, 0x0F, 0xB3, 0x42, 0x70 };    /* btr [rdx+0x70], rax */
    static const uint8_t m12[] = { 0x48, 0xC7, 0x42, 0x68, 0x00, 0x00, 0x00, 0x00 }; /* mov qword [rdx+0x68], 0 */
    SC_PUT(s, m1);
    SC_PUT(s, m2);
    int jne1 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    SC_PUT(s, m3);
    SC_PUT(s, m4);
    SC_PUT(s, m5);
    int jz1 = s->pos; sc_u8(s, 0x74); sc_u8(s, 0x00);
    SC_PUT(s, m6);
    SC_PUT(s, m7);
    SC_PUT(s, B_MOV_R11); sc_u64(s, counters_base);
    SC_PUT(s, m8);
    SC_PUT(s, m9);
    SC_PUT(s, m10);
    SC_PUT(s, m11);
    SC_PUT(s, m12);
    sc_u8(s, 0x31); sc_u8(s, 0xC0); /* xor eax, eax (CONTINUE_EXECUTION) */
    sc_u8(s, 0xC3);                /* ret */
    int search = s->pos;
    { static const uint8_t m13[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; SC_PUT(s, m13); } /* mov eax, 1 */
    sc_u8(s, 0xC3);                /* ret */
    out[jne1 + 1] = (uint8_t)(search - (jne1 + 2));
    out[jz1 + 1] = (uint8_t)(search - (jz1 + 2));
    return s->pos;
}

/* MSVC std::string (32 bytes). If text > 15 chars, chars (+NUL) go to longbuf
 * and the struct points at longaddr. longbuf must fit strlen(text)+1. */
static void sc_std_string(uint8_t st[32], const char *text, uint64_t longaddr, uint8_t *longbuf) {
    size_t n = strlen(text);
    memset(st, 0, 32);
    if (n <= 15) {
        memcpy(st, text, n);
        uint64_t sz = (uint64_t)n, cap = 15;
        memcpy(st + 16, &sz, 8);
        memcpy(st + 24, &cap, 8);
    } else {
        memcpy(longbuf, text, n + 1);
        uint64_t sz = (uint64_t)n;
        memcpy(st, &longaddr, 8);
        memcpy(st + 16, &sz, 8);
        memcpy(st + 24, &sz, 8);
    }
}

#endif /* SC_BUILD_H */
