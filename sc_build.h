/* Shellcode builders for LoginKeyPatcher — pure C, no platform deps.
 * Included by LoginKeyPatcher.c (Windows) and the Linux test harness.
 * All x64 encodings verified with capstone (see repo history).
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

static const uint8_t B_PROLOGUE[] = {
    0x53,                                     /* push rbx */
    0x56,                                     /* push rsi */
    0x57,                                     /* push rdi */
    0x48, 0x83, 0xEC, 0x20,                   /* sub rsp, 0x20 */
    0x48, 0x89, 0xCB,                         /* mov rbx, rcx */
    0x48, 0x8D, 0xB3, 0xB8, 0x01, 0x00, 0x00, /* lea rsi, [rbx+0x1B8] */
    0x48, 0x83, 0xBB, 0xD0, 0x01, 0x00, 0x00, 0x0F, /* cmp [rbx+0x1D0], 15 */
    0x76, 0x07,                               /* jbe +7 */
    0x48, 0x8B, 0xB3, 0xB8, 0x01, 0x00, 0x00  /* mov rsi, [rbx+0x1B8] */
};
static const uint8_t B_EPILOGUE[] = {
    0x48, 0x83, 0xC4, 0x20, 0x5F, 0x5E, 0x5B, 0xC3 /* add rsp,0x20; pop rdi/rsi/rbx; ret */
};
static const uint8_t B_MOV_RDI_LEN[]  = { 0x48, 0x8B, 0xBB, 0xC8, 0x01, 0x00, 0x00 };
static const uint8_t B_TEST_RDI[]     = { 0x48, 0x85, 0xFF };
static const uint8_t B_MOV_R10_LEN[]  = { 0x4C, 0x8B, 0x93, 0xC8, 0x01, 0x00, 0x00 };
static const uint8_t B_MOV_R11[]      = { 0x49, 0xBB };
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

static void sc_call_login(ScBuf *s, uint64_t login_screen) {
    SC_PUT(s, B_MOV_RCX_RBX);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, login_screen);
    SC_PUT(s, B_CALL_RAX);
    SC_PUT(s, B_EPILOGUE);
}

static void sc_call_main_pass(ScBuf *s, uint64_t fake_user, uint64_t main_screen) {
    SC_PUT(s, B_MOV_RCX_RBX);
    SC_PUT(s, B_MOV_RDX); sc_u64(s, fake_user);
    SC_PUT(s, B_LEA_R8); /* r8 = &typed key string (pass-through) */
    SC_PUT(s, B_MOV_R9D1);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, main_screen);
    SC_PUT(s, B_CALL_RAX);
    SC_PUT(s, B_EPILOGUE);
}

static void sc_call_main_fake(ScBuf *s, uint64_t fake_user, uint64_t fake_key, uint64_t main_screen) {
    SC_PUT(s, B_MOV_RCX_RBX);
    SC_PUT(s, B_MOV_RDX); sc_u64(s, fake_user);
    SC_PUT(s, B_MOV_R8); sc_u64(s, fake_key);
    SC_PUT(s, B_MOV_R9D1);
    SC_PUT(s, B_MOV_RAX); sc_u64(s, main_screen);
    SC_PUT(s, B_CALL_RAX);
    SC_PUT(s, B_EPILOGUE);
}

/* any: typed_len > 0 -> main, else login */
static int sc_build_any(uint8_t *out, uint64_t login_screen, uint64_t main_screen, uint64_t fake_user) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    SC_PUT(s, B_PROLOGUE);
    SC_PUT(s, B_MOV_RDI_LEN);
    SC_PUT(s, B_TEST_RDI);
    int jz = s->pos;    sc_u8(s, 0x74); sc_u8(s, 0x00);
    int jmpm = s->pos;  sc_u8(s, 0xEB); sc_u8(s, 0x00);
    int login_pos = s->pos;
    sc_call_login(s, login_screen);
    int main_pos = s->pos;
    sc_call_main_pass(s, fake_user, main_screen);
    out[jz + 1] = (uint8_t)(login_pos - (jz + 2));
    out[jmpm + 1] = (uint8_t)(main_pos - (jmpm + 2));
    return s->pos;
}

/* auto: straight to main with fake key+user */
static int sc_build_auto(uint8_t *out, uint64_t main_screen, uint64_t fake_user, uint64_t fake_key) {
    ScBuf b = { out, 0 }; ScBuf *s = &b;
    SC_PUT(s, B_PROLOGUE);
    sc_call_main_fake(s, fake_user, fake_key, main_screen);
    return s->pos;
}

/* custom: case-insensitive compare against expected bytes */
static int sc_build_custom(uint8_t *out, uint64_t login_screen, uint64_t main_screen,
                           uint64_t fake_user, uint64_t expect_addr, uint32_t expect_len) {
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
    sc_call_login(s, login_screen);
    int main_pos = s->pos;
    sc_call_main_pass(s, fake_user, main_screen);
    { int32_t r1 = (int32_t)(login_pos - (jne1 + 6)); memcpy(out + jne1 + 2, &r1, 4); }
    { int32_t r2 = (int32_t)(login_pos - (jne2 + 6)); memcpy(out + jne2 + 2, &r2, 4); }
    out[jb + 1] = (uint8_t)(loop - (jb + 2));
    out[jmpm + 1] = (uint8_t)(main_pos - (jmpm + 2));
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
