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
static const uint8_t B_MOV_R10[]      = { 0x49, 0xBA };
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

/* TRACE VEH stub v2 (Enigma-safe diagnostics): single-shot per-thread counters.
 * On EXCEPTION_SINGLE_STEP:
 *   - Dr6&0xF == 0 (TF step / foreign) -> CONTINUE_SEARCH, touch nothing.
 *   - slot = bsf(Dr6 & 0xF); if ExceptionAddress != table[slot] -> SEARCH
 *     (someone else's breakpoint: Enigma coexistence, never disturb it).
 *   - else: counters[slot]++, clear ONLY our Dr6 bit + L-bit (single-shot),
 *     return CONTINUE_EXECUTION (instruction re-runs normally, bp now off).
 * The loader re-arms periodically. Uses only volatile regs (rax, rdx, r10, r11).
 */
static int sc_trace_veh(uint8_t *out, uint64_t counters_base, uint64_t table_base) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    static const uint8_t m1[] = { 0x48, 0x8B, 0x01 };                 /* mov rax, [rcx] */
    static const uint8_t m2[] = { 0x81, 0x38, 0x04, 0x00, 0x00, 0x80 }; /* cmp dword [rax], 0x80000004 */
    static const uint8_t m3[] = { 0x48, 0x8B, 0x51, 0x08 };           /* mov rdx, [rcx+8] */
    static const uint8_t m4[] = { 0x4C, 0x8B, 0x52, 0x68 };           /* mov r10, [rdx+0x68] (Dr6) */
    static const uint8_t m5[] = { 0x4C, 0x8B, 0x58, 0x10 };           /* mov r11, [rax+0x10] (ExcAddr) */
    static const uint8_t m6[] = { 0x41, 0xF6, 0xC2, 0x0F };           /* test r10b, 0x0F */
    static const uint8_t m7[] = { 0x41, 0x83, 0xE2, 0x0F };           /* and r10d, 0x0F */
    static const uint8_t m8[] = { 0x41, 0x0F, 0xBC, 0xC2 };           /* bsf eax, r10d */
    static const uint8_t m9[] = { 0x4D, 0x8B, 0x14, 0xC2 };           /* mov r10, [r10+rax*8] */
    static const uint8_t m10[] = { 0x4D, 0x39, 0xD3 };                /* cmp r11, r10 */
    static const uint8_t m11[] = { 0x4D, 0x8D, 0x14, 0xC2 };          /* lea r10, [r10+rax*8] */
    static const uint8_t m12[] = { 0x49, 0xFF, 0x02 };                /* inc qword [r10] */
    static const uint8_t m13[] = { 0x0F, 0xB3, 0x42, 0x68 };          /* btr dword [rdx+0x68], eax */
    static const uint8_t m14[] = { 0xD1, 0xE0 };                      /* shl eax, 1 */
    static const uint8_t m15[] = { 0x48, 0x0F, 0xB3, 0x42, 0x70 };    /* btr [rdx+0x70], rax */
    SC_PUT(s, m1);
    SC_PUT(s, m2);
    int jne1 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    SC_PUT(s, m3);
    SC_PUT(s, m4);
    SC_PUT(s, m5);
    SC_PUT(s, m6);
    int jz1 = s->pos; sc_u8(s, 0x74); sc_u8(s, 0x00);
    SC_PUT(s, m7);
    SC_PUT(s, m8);
    SC_PUT(s, B_MOV_R10); sc_u64(s, table_base); /* mov r10, table */
    SC_PUT(s, m9);                               /* mov r10, [r10+rax*8] */
    SC_PUT(s, m10);                              /* cmp r11, r10 */
    int jne2 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    SC_PUT(s, B_MOV_R10); sc_u64(s, counters_base); /* mov r10, counters */
    SC_PUT(s, m11);                              /* lea r10, [r10+rax*8] */
    SC_PUT(s, m12);                              /* inc qword [r10] */
    SC_PUT(s, m13);                              /* btr dword [rdx+0x68], eax */
    SC_PUT(s, m14);                              /* shl eax, 1 */
    SC_PUT(s, m15);                              /* btr [rdx+0x70], rax */
    sc_u8(s, 0x31); sc_u8(s, 0xC0); /* xor eax, eax (CONTINUE_EXECUTION) */
    sc_u8(s, 0xC3);                /* ret */
    int search = s->pos;
    { static const uint8_t m16[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; SC_PUT(s, m16); } /* mov eax, 1 */
    sc_u8(s, 0xC3);                /* ret */
    out[jne1 + 1] = (uint8_t)(search - (jne1 + 2));
    out[jz1 + 1] = (uint8_t)(search - (jz1 + 2));
    out[jne2 + 1] = (uint8_t)(search - (jne2 + 2));
    return s->pos;
}

/* OBSERVER VEH (v2.7 diagnostic): log EVERY exception into a 32-entry ring,
 * touch nothing else, always return EXCEPTION_CONTINUE_SEARCH (1).
 *   datab+0x100 : u64 total seen
 *   datab+0x200 : 32 x { u32 code, u32 pad, u64 addr } (16 bytes each)
 * Volatile regs only (rax/rdx/r8/r9) — safe to run in front of Enigma. */
static int sc_log_veh(uint8_t *out, uint64_t datab) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    static const uint8_t m1[]  = { 0x48, 0x8B, 0x01 };                     /* mov rax,[rcx]        ; ExceptionRecord */
    static const uint8_t m2[]  = { 0x44, 0x8B, 0x00 };                     /* mov r8d,[rax]        ; ExceptionCode */
    static const uint8_t m3[]  = { 0x4C, 0x8B, 0x48, 0x10 };               /* mov r9,[rax+0x10]    ; ExceptionAddress */
    static const uint8_t m5[]  = { 0x8B, 0x90, 0x00, 0x01, 0x00, 0x00 };   /* mov edx,[rax+0x100]  ; total */
    static const uint8_t m6[]  = { 0x83, 0xE2, 0x1F };                     /* and edx,31 */
    static const uint8_t m7[]  = { 0xC1, 0xE2, 0x04 };                     /* shl edx,4 */
    static const uint8_t m8[]  = { 0x48, 0x8D, 0x94, 0x10,
                                   0x00, 0x02, 0x00, 0x00 };               /* lea rdx,[rax+rdx+0x200] */
    static const uint8_t m9[]  = { 0x44, 0x89, 0x02 };                     /* mov [rdx],r8d */
    static const uint8_t m10[] = { 0x4C, 0x89, 0x4A, 0x08 };               /* mov [rdx+8],r9 */
    static const uint8_t m11[] = { 0x48, 0xFF, 0x80,
                                   0x00, 0x01, 0x00, 0x00 };               /* inc qword [rax+0x100] */
    static const uint8_t m12[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 };         /* mov eax,1 (SEARCH) */
    SC_PUT(s, m1);
    SC_PUT(s, m2);
    SC_PUT(s, m3);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, datab);
    SC_PUT(s, m5);
    SC_PUT(s, m6);
    SC_PUT(s, m7);
    SC_PUT(s, m8);
    SC_PUT(s, m9);
    SC_PUT(s, m10);
    SC_PUT(s, m11);
    SC_PUT(s, m12);
    sc_u8(s, 0xC3);
    return s->pos;
}

/* SELF-TEST VEH: เหมือน sc_log_veh ทุกประการ แต่ถ้า ExceptionCode == 0xDEADBEEF
 * (exception ที่เรายิงเองเพื่อทดสอบ) จะคืน EXCEPTION_CONTINUE_EXECUTION (0)
 * เพื่อให้ thread ทดสอบรอดกลับมาได้ — พิสูจน์ว่า handler ถูกติดตั้งจริงและทำงานจริง */
static int sc_test_veh(uint8_t *out, uint64_t datab) {
    int n = sc_log_veh(out, datab);
    uint8_t *p = out + n - 6; /* แทรกก่อน mov eax,1 ; ret */
    static const uint8_t cmp[] = { 0x41, 0x81, 0xF8, 0xEF, 0xBE, 0xAD, 0xDE }; /* cmp r8d,0xDEADBEEF */
    static const uint8_t jm[]  = { 0x75, 0x03 };                               /* jne +3 */
    static const uint8_t z[]   = { 0x31, 0xC0, 0xC3 };                         /* xor eax,eax; ret */
    memcpy(p, cmp, sizeof(cmp)); p += sizeof(cmp);
    memcpy(p, jm, sizeof(jm)); p += sizeof(jm);
    memcpy(p, z, sizeof(z)); p += sizeof(z);
    return (int)(p - out);
}

/* SELF-TEST VEH v2: บันทึก exception ทุกตัว แล้ว
 *   ถ้า ExceptionAddress == fault_addr (จุดที่เราจงใจทำให้พัง)
 *     -> แก้ Context->Rip = fault_addr+2 (ข้ามคำสั่งที่พัง) แล้วคืน CONTINUE_EXECUTION
 *   อื่น ๆ -> คืน CONTINUE_SEARCH
 * ถ้า thread ทดสอบรอดกลับมาได้ = handler เราถูกเรียกจริงและทำงานได้จริง */
static int sc_test_veh2(uint8_t *out, uint64_t datab, uint64_t fault_addr) {
    int n = sc_log_veh(out, datab);
    uint8_t *p = out + n - 6;
    *p++ = 0x48; *p++ = 0xB8; { uint64_t a = fault_addr;        memcpy(p, &a, 8); p += 8; }
    *p++ = 0x49; *p++ = 0x39; *p++ = 0xC1;                       /* cmp r9, rax */
    *p++ = 0x75; *p++ = 0x18;                                    /* jne -> search */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0x51; *p++ = 0x08;           /* mov rdx,[rcx+8] (Context) */
    *p++ = 0x48; *p++ = 0xB8; { uint64_t a = fault_addr + 2;     memcpy(p, &a, 8); p += 8; }
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x82;
    *p++ = 0xF8; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;           /* mov [rdx+0xF8], rax (Rip) */
    *p++ = 0x31; *p++ = 0xC0;                                    /* xor eax,eax */
    *p++ = 0xC3;                                                 /* ret */
    *p++ = 0xB8; *p++ = 0x01; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; /* mov eax,1 */
    *p++ = 0xC3;
    return (int)(p - out);
}

/* TRIGGER-AGNOSTIC redirect handler: รับเหตุการณ์ได้ 3 แบบ
 *   EXCEPTION_SINGLE_STEP (0x80000004) = hardware breakpoint
 *   EXCEPTION_BREAKPOINT  (0x80000003) = int3 (0xCC) ที่เราเขียน
 *   EXCEPTION_GUARD_PAGE  (0x80000001) = หน้าเพจที่ตั้ง PAGE_GUARD
 * ถ้า ExceptionAddress == trigger_addr -> ข้ามไปทำ shellcode แทน (login เก่าไม่รัน)
 * นอกนั้นคืน CONTINUE_SEARCH (ไม่ยุ่งกับของ Enigma เลย) */
static int sc_any_veh(uint8_t *out, uint64_t trigger_addr, uint64_t shell_addr,
                      uint64_t counter_addr) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    static const uint8_t m1[] = { 0x48, 0x8B, 0x01 };                 /* mov rax,[rcx] (ExcRecord) */
    static const uint8_t m2[] = { 0x48, 0x8B, 0x51, 0x08 };           /* mov rdx,[rcx+8] (Context) */
    static const uint8_t m3[] = { 0x44, 0x8B, 0x00 };                 /* mov r8d,[rax] (code) */
    static const uint8_t m4[] = { 0x4C, 0x8B, 0x48, 0x10 };           /* mov r9,[rax+0x10] (addr) */
    static const uint8_t cm[] = { 0x41, 0x81, 0xF8 };                 /* cmp r8d, imm32 */
    static const uint8_t c1[] = { 0x04, 0x00, 0x00, 0x80 };           /* SINGLE_STEP */
    static const uint8_t c2[] = { 0x03, 0x00, 0x00, 0x80 };           /* BREAKPOINT */
    static const uint8_t c3[] = { 0x01, 0x00, 0x00, 0x80 };           /* GUARD_PAGE */
    static const uint8_t m5[] = { 0x49, 0x39, 0xC1 };                 /* cmp r9, rax */
    static const uint8_t m6[] = { 0x48, 0x89, 0x82,
                                  0xF8, 0x00, 0x00, 0x00 };           /* mov [rdx+0xF8], rax */
    static const uint8_t m7[] = { 0x48, 0xFF, 0x00 };                 /* inc qword [rax] */
    SC_PUT(s, m1);
    SC_PUT(s, m2);
    SC_PUT(s, m3);
    SC_PUT(s, m4);
    SC_PUT(s, cm); SC_PUT(s, c1);
    int je1 = s->pos; sc_u8(s, 0x74); sc_u8(s, 0x00);
    SC_PUT(s, cm); SC_PUT(s, c2);
    int je2 = s->pos; sc_u8(s, 0x74); sc_u8(s, 0x00);
    SC_PUT(s, cm); SC_PUT(s, c3);
    int jne3 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    int ok = s->pos;
    SC_PUT(s, B_MOV_RAX); sc_u64(s, trigger_addr);
    SC_PUT(s, m5);
    int jne4 = s->pos; sc_u8(s, 0x75); sc_u8(s, 0x00);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, shell_addr);
    SC_PUT(s, m6);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, counter_addr);
    SC_PUT(s, m7);
    sc_u8(s, 0x31); sc_u8(s, 0xC0);
    sc_u8(s, 0xC3);
    int search = s->pos;
    { static const uint8_t z[] = { 0xB8, 0x01, 0x00, 0x00, 0x00 }; SC_PUT(s, z); }
    sc_u8(s, 0xC3);
    out[je1 + 1]  = (uint8_t)(ok - (je1 + 2));
    out[je2 + 1]  = (uint8_t)(ok - (je2 + 2));
    out[jne3 + 1] = (uint8_t)(search - (jne3 + 2));
    out[jne4 + 1] = (uint8_t)(search - (jne4 + 2));
    return s->pos;
}

/* GUARD-PAGE redirect handler v2 (Enigma-safe: ไม่แตะโค้ด ไม่แตะ Dr register)
 *  + บันทึก exception ทุกตัวลง ring (log_total/log_ring) เพื่อดูว่ามันเห็นอะไรบ้าง
 *  ตั้ง PAGE_GUARD บนเพจที่มีจุด login → การเข้าถึงเพจนั้นจะทำให้เกิด
 *  EXCEPTION_GUARD_PAGE (0x80000001) ซึ่ง VEH เราได้ก่อน
 *   - ถ้าเป็นจุด login เป๊ะ -> กระโดดไปทำ shellcode ข้าม login เลย (นับ hits)
 *   - ถ้าเป็นจุดอื่นในเพจเดียวกัน -> ปล่อยผ่าน แล้วเปิด TF ให้สะดุดหลังคำสั่งนั้น
 *     แล้วค่อยตั้ง PAGE_GUARD กลับผ่าน **syscall ตรง** (ข้าม hook ของ Enigma)
 *  scratch: +0x00 Context, +0x08 ExceptionAddress, +0x10 old protect
 *  mode 0 = ยิงครั้งเดียว (ไม่ตั้ง TF ไม่ตั้ง guard ใหม่) */
static int sc_guard_veh(uint8_t *out, uint64_t page, uint64_t page_end,
                        uint64_t trigger, uint64_t shell, uint64_t counter,
                        uint64_t scratch, uint64_t log_total, uint64_t log_ring,
                        uint32_t syscall_no, int mode) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    int p_je_step = -1, p_je_guard = -1, p_jmp_search = -1;
    int p_jb1 = -1, p_jae1 = -1, p_je_hit = -1, p_jz_step = -1;
    int guard_at, hit_at, step_at, search_at, i;
    int fixups[8][2]; int nfix = 0;

    sc_u8(s, 0x48); sc_u8(s, 0x8B); sc_u8(s, 0x01);       /* mov rax,[rcx] */
    sc_u8(s, 0x48); sc_u8(s, 0x8B); sc_u8(s, 0x51); sc_u8(s, 0x08); /* mov rdx,[rcx+8] */
    sc_u8(s, 0x44); sc_u8(s, 0x8B); sc_u8(s, 0x00);       /* mov r8d,[rax] */
    sc_u8(s, 0x4C); sc_u8(s, 0x8B); sc_u8(s, 0x48); sc_u8(s, 0x10); /* mov r9,[rax+0x10] */
    /* --- log: ring[(total&31)] = {code, addr}; total++ (ใช้ r10/r11) --- */
    sc_u8(s, 0x49); sc_u8(s, 0xBA); sc_u64(s, log_total); /* mov r10, log_total */
    sc_u8(s, 0x45); sc_u8(s, 0x8B); sc_u8(s, 0x1A);       /* mov r11d,[r10] */
    sc_u8(s, 0x41); sc_u8(s, 0x83); sc_u8(s, 0xE3); sc_u8(s, 0x1F); /* and r11d,31 */
    sc_u8(s, 0x41); sc_u8(s, 0xC1); sc_u8(s, 0xE3); sc_u8(s, 0x04); /* shl r11d,4 */
    sc_u8(s, 0x49); sc_u8(s, 0xBA); sc_u64(s, log_ring);  /* mov r10, log_ring */
    sc_u8(s, 0x4F); sc_u8(s, 0x8D); sc_u8(s, 0x1C); sc_u8(s, 0x1A); /* lea r11,[r10+r11] */
    sc_u8(s, 0x45); sc_u8(s, 0x89); sc_u8(s, 0x03);       /* mov [r11],r8d */
    sc_u8(s, 0x4D); sc_u8(s, 0x89); sc_u8(s, 0x4B); sc_u8(s, 0x08); /* mov [r11+8],r9 */
    sc_u8(s, 0x49); sc_u8(s, 0xBA); sc_u64(s, log_total); /* mov r10, log_total */
    sc_u8(s, 0x49); sc_u8(s, 0xFF); sc_u8(s, 0x02);       /* inc qword [r10] */
    /* --- save context/addr for the syscall path --- */
    sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, scratch);   /* mov rax, scratch */
    sc_u8(s, 0x48); sc_u8(s, 0x89); sc_u8(s, 0x50); sc_u8(s, 0x00); /* mov [rax],rdx */
    sc_u8(s, 0x4C); sc_u8(s, 0x89); sc_u8(s, 0x48); sc_u8(s, 0x08); /* mov [rax+8],r9 */
    sc_u8(s, 0x41); sc_u8(s, 0x81); sc_u8(s, 0xF8); sc_u32(s, 0x80000004u);
    sc_u8(s, 0x0F); sc_u8(s, 0x84); p_je_step = s->pos; sc_u32(s, 0);
    sc_u8(s, 0x41); sc_u8(s, 0x81); sc_u8(s, 0xF8); sc_u32(s, 0x80000001u);
    sc_u8(s, 0x0F); sc_u8(s, 0x84); p_je_guard = s->pos; sc_u32(s, 0);
    sc_u8(s, 0xE9); p_jmp_search = s->pos; sc_u32(s, 0);

    guard_at = s->pos;
    sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, page);
    sc_u8(s, 0x49); sc_u8(s, 0x39); sc_u8(s, 0xC1);
    sc_u8(s, 0x0F); sc_u8(s, 0x82); p_jb1 = s->pos; sc_u32(s, 0);
    sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, page_end);
    sc_u8(s, 0x49); sc_u8(s, 0x39); sc_u8(s, 0xC1);
    sc_u8(s, 0x0F); sc_u8(s, 0x83); p_jae1 = s->pos; sc_u32(s, 0);
    sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, trigger);
    sc_u8(s, 0x49); sc_u8(s, 0x39); sc_u8(s, 0xC1);
    sc_u8(s, 0x0F); sc_u8(s, 0x84); p_je_hit = s->pos; sc_u32(s, 0);
    if (mode) {
        sc_u8(s, 0x81); sc_u8(s, 0x4A); sc_u8(s, 0x44);
        sc_u8(s, 0x00); sc_u8(s, 0x01); sc_u8(s, 0x00); sc_u8(s, 0x00);
    }
    sc_u8(s, 0x31); sc_u8(s, 0xC0); sc_u8(s, 0xC3);

    hit_at = s->pos;
    sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, shell);
    sc_u8(s, 0x48); sc_u8(s, 0x89); sc_u8(s, 0x82);
    sc_u8(s, 0xF8); sc_u8(s, 0x00); sc_u8(s, 0x00); sc_u8(s, 0x00);
    sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, counter);
    sc_u8(s, 0x48); sc_u8(s, 0xFF); sc_u8(s, 0x00);
    sc_u8(s, 0x31); sc_u8(s, 0xC0); sc_u8(s, 0xC3);

    step_at = s->pos;
    if (!mode) {
        sc_u8(s, 0xE9); p_jz_step = s->pos; sc_u32(s, 0);
    } else {
        sc_u8(s, 0xF7); sc_u8(s, 0x42); sc_u8(s, 0x68);
        sc_u8(s, 0x00); sc_u8(s, 0x40); sc_u8(s, 0x00); sc_u8(s, 0x00);
        sc_u8(s, 0x0F); sc_u8(s, 0x84); p_jz_step = s->pos; sc_u32(s, 0);
        sc_u8(s, 0x48); sc_u8(s, 0xB9); sc_u64(s, page);
        sc_u8(s, 0x48); sc_u8(s, 0xBA); sc_u64(s, page_end - page);
        sc_u8(s, 0x49); sc_u8(s, 0xB8); sc_u64(s, 0x120);
        sc_u8(s, 0x49); sc_u8(s, 0xB9); sc_u64(s, scratch + 0x10);
        sc_u8(s, 0x4C); sc_u8(s, 0x8B); sc_u8(s, 0xD1);
        sc_u8(s, 0xB8); sc_u32(s, syscall_no);
        sc_u8(s, 0x0F); sc_u8(s, 0x05);
        sc_u8(s, 0x48); sc_u8(s, 0xB8); sc_u64(s, scratch);
        sc_u8(s, 0x48); sc_u8(s, 0x8B); sc_u8(s, 0x10);
        sc_u8(s, 0x81); sc_u8(s, 0x62); sc_u8(s, 0x44);
        sc_u8(s, 0xFF); sc_u8(s, 0xFE); sc_u8(s, 0xFF); sc_u8(s, 0xFF);
        sc_u8(s, 0x81); sc_u8(s, 0x62); sc_u8(s, 0x68);
        sc_u8(s, 0xFF); sc_u8(s, 0xBF); sc_u8(s, 0xFF); sc_u8(s, 0xFF);
        sc_u8(s, 0x31); sc_u8(s, 0xC0); sc_u8(s, 0xC3);
    }

    search_at = s->pos;
    sc_u8(s, 0xB8); sc_u32(s, 1);
    sc_u8(s, 0xC3);

    fixups[nfix][0] = p_je_step;  fixups[nfix++][1] = step_at;
    fixups[nfix][0] = p_je_guard; fixups[nfix++][1] = guard_at;
    fixups[nfix][0] = p_jmp_search; fixups[nfix++][1] = search_at;
    fixups[nfix][0] = p_jb1;      fixups[nfix++][1] = search_at;
    fixups[nfix][0] = p_jae1;     fixups[nfix++][1] = search_at;
    fixups[nfix][0] = p_je_hit;   fixups[nfix++][1] = hit_at;
    fixups[nfix][0] = p_jz_step;  fixups[nfix++][1] = search_at;
    for (i = 0; i < nfix; i++) {
        int at = fixups[i][0];
        if (at < 0) continue;
        uint32_t rel = (uint32_t)(fixups[i][1] - (at + 4));
        memcpy(out + at, &rel, 4);
    }
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
