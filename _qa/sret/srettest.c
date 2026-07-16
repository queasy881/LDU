/* Ground-truth fixture for the x64 hidden-return-pointer (sret) ABI.
 *
 * MSVC x64 returns a struct in RAX only when sizeof is exactly 1/2/4/8 AND it is
 * trivially copyable. Every other size returns through a CALLER-allocated buffer
 * whose address arrives in RCX, shifting the real parameters into RDX/R8/R9, and
 * the callee must hand that same pointer back in RAX.
 *
 * Each function below is named for what the decompiler MUST say about it, so a
 * dump can be read as a scorecard:
 *   sret_*  -> hidden pointer: real arity is one LESS than it looks
 *   rax_*   -> returned in RAX: arity is exactly what it looks like (control group)
 */

typedef struct { float x, y, z; }        Vec3;    /* 12 -> sret */
typedef struct { double a, b; }          Pair;    /* 16 -> sret */
typedef struct { int a, b, c, d, e; }    Big;     /* 20 -> sret */
typedef struct { char a, b, c; }         Odd3;    /*  3 -> sret (odd size, not just big) */
typedef struct { int a, b; }             Small8;  /*  8 -> RAX  (control) */
typedef struct { short a, b; }           Small4;  /*  4 -> RAX  (control) */

__declspec(dllexport) Vec3 sret_make_vec(float x, float y, float z) {
    Vec3 v; v.x = x; v.y = y; v.z = z; return v;
}

__declspec(dllexport) Pair sret_make_pair(double a, double b) {
    Pair p; p.a = a + b; p.b = a - b; return p;
}

__declspec(dllexport) Big sret_make_big(int n) {
    Big b; b.a = n; b.b = n + 1; b.c = n + 2; b.d = n + 3; b.e = n + 4; return b;
}

__declspec(dllexport) Odd3 sret_make_odd(char c) {
    Odd3 o; o.a = c; o.b = (char)(c + 1); o.c = (char)(c + 2); return o;
}

/* >8-byte struct PARAMS are themselves passed by hidden reference in MSVC x64, so
 * this is sret on both sides: RCX = out, RDX = &a, R8 = &b. */
__declspec(dllexport) Vec3 sret_add_vec(Vec3 a, Vec3 b) {
    Vec3 r; r.x = a.x + b.x; r.y = a.y + b.y; r.z = a.z + b.z; return r;
}

/* Control group: fits in RAX, so RCX really IS parameter one. A detector that
 * fires here is WRONG. */
__declspec(dllexport) Small8 rax_make_small(int a, int b) {
    Small8 s; s.a = a; s.b = b; return s;
}

__declspec(dllexport) Small4 rax_make_small4(short a, short b) {
    Small4 s; s.a = a; s.b = b; return s;
}

/* THE ADVERSARIAL CASE. strcpy-shaped: returns its own first argument and stores
 * through it, which is precisely the naive sret signature. RCX here is a REAL
 * parameter and the return type is a REAL pointer. Any detector that keys only on
 * "returns incoming RCX + stores through RCX" misfires here and silently deletes a
 * live parameter. */
__declspec(dllexport) char* notsret_strcpy(char* dst, const char* src) {
    char* p = dst;
    while ((*p++ = *src++) != 0) { }
    return dst;
}

/* Second adversarial case: fills a caller-supplied OUT buffer and returns it, but
 * the buffer is a genuine parameter -- the function also returns it for chaining. */
__declspec(dllexport) Vec3* notsret_fill(Vec3* out, float v) {
    out->x = v; out->y = v; out->z = v; return out;
}

/* Callers, so the CALL-SITE shape is in the dump too: an sret call site allocates a
 * fresh stack temp, leas it into RCX, and the real args shift right. */
__declspec(dllexport) float call_sret_vec(float a) {
    Vec3 v = sret_make_vec(a, a + 1.0f, a + 2.0f);
    return v.x + v.y + v.z;
}

__declspec(dllexport) double call_sret_pair(double a) {
    Pair p = sret_make_pair(a, a * 2.0);
    return p.a * p.b;
}

__declspec(dllexport) int call_sret_big(int n) {
    Big b = sret_make_big(n);
    return b.a + b.e;
}

__declspec(dllexport) int call_rax_small(int n) {
    Small8 s = rax_make_small(n, n + 1);
    return s.a * s.b;
}
