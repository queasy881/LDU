/* FEATURE FIXTURE (C, x64, /O2) — ground truth for the instruction/semantic recoveries.
 *
 * Every function here exists to make ONE claim checkable. The claim is written next to it
 * and asserted by _qa/features/verify.py. If a feature regresses, exactly one line of the
 * report flips — that is the point. These are NOT behavioural tests (the corpus does that);
 * they assert that the decompiler SAYS the right thing.
 *
 * Build: cl /nologo /O2 /LD /TC feat_c.c
 */
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <stdint.h>

/* --- atomics: `lock xadd` must render as _InterlockedExchangeAdd, not a load/store pair.
 *     The whole point is that ATOMICITY is visible. */
__declspec(dllexport) long f_atomic_xadd(volatile long* p) {
    return _InterlockedExchangeAdd(p, -1);
}
/* the refcount-release idiom: the OLD value decides, exactly like NullWare's fn_00074260 */
__declspec(dllexport) int f_atomic_release(volatile long* p) {
    return _InterlockedExchangeAdd(p, -1) == 1;
}

/* --- rotate: C has no rotate operator; must be _rotl/_rotr, never dropped. */
__declspec(dllexport) unsigned f_rotl(unsigned x, int n) { return _rotl(x, n); }
__declspec(dllexport) unsigned f_rotr(unsigned x, int n) { return _rotr(x, n); }

/* --- bswap -> _byteswap_*. */
__declspec(dllexport) unsigned f_bswap32(unsigned x) { return _byteswap_ulong(x); }
__declspec(dllexport) unsigned long long f_bswap64(unsigned long long x) { return _byteswap_uint64(x); }

/* --- bit scan: bsf/bsr set ZF from the SOURCE being zero. The value AND the flag matter;
 *     a stale ZF here is what deleted memchr's loop in the real CRT. */
__declspec(dllexport) int f_bsf(unsigned x) {
    unsigned long i;
    if (_BitScanForward(&i, x)) return (int)i;
    return -1;                       /* this path is reached iff x == 0 */
}
__declspec(dllexport) int f_bsr(unsigned x) {
    unsigned long i;
    if (_BitScanReverse(&i, x)) return (int)i;
    return -1;
}

/* --- cpuid / rdtsc must become the named intrinsics, not phantom register reads. */
__declspec(dllexport) int f_cpuid_vendor(void) {
    int r[4];
    __cpuid(r, 0);
    return r[1];                     /* ebx = "Genu" */
}
__declspec(dllexport) unsigned long long f_rdtsc(void) { return __rdtsc(); }

/* --- string ops: rep movs -> __movsb, rep stos -> __stos*. */
__declspec(dllexport) void f_movs(char* d, const char* s, size_t n) { __movsb((unsigned char*)d, (const unsigned char*)s, n); }
__declspec(dllexport) void f_stos(char* d, char v, size_t n) { __stosb((unsigned char*)d, (unsigned char)v, n); }

/* --- magic division: MSVC turns /10 into a multiply-high + shift. It must read as `/ 10`. */
__declspec(dllexport) int f_div10(int x) { return x / 10; }
__declspec(dllexport) unsigned f_udiv7(unsigned x) { return x / 7u; }

/* --- __fastfail (int 0x29). */
__declspec(dllexport) void f_fastfail(void) { __fastfail(1); }

/* --- typelib: an imported Win32 API's prototype must carry REAL types (HANDLE/DWORD/LPVOID),
 *     not `long long` for every parameter. */
__declspec(dllexport) int f_heapfree(HANDLE h, void* p) { return HeapFree(h, 0, p); }

/* --- CROSS-FUNCTION type propagation. This is the case a direct-call-only rule cannot see:
 *     the type has to flow THROUGH a local wrapper.
 *       f_get_base  returns whatever GetModuleHandleW returned  -> it returns an HMODULE
 *       f_use_base  calls f_get_base                            -> ITS local is an HMODULE too
 *     NullWare has ZERO functions of this shape (measured: 0 local fns return an API result
 *     directly), which is exactly why it needs a fixture -- the real gate binary cannot
 *     validate it, and real-world code is full of these wrappers. */
/*     noinline is REQUIRED, not cosmetic: at /O2 MSVC inlines the wrapper and f_use_base
 *     calls GetModuleHandleW directly, so the fixture silently tests the DIRECT path and
 *     proves nothing about the cross-function one. (First cut did exactly that.) */
/*     g_touch is REQUIRED too: without it the wrapper compiles to a bare `jmp [IAT]` THUNK
 *     (no call, no ret), which is a different shape entirely and does not test the
 *     call-result path. Real wrappers do work; this makes the fixture one. */
static volatile int g_touch;
__declspec(noinline) __declspec(dllexport) HMODULE f_get_base(void) {
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    g_touch++;
    return h;
}
__declspec(dllexport) int f_use_base(void) {
    HMODULE m = f_get_base();          /* must recover as HMODULE, not int64_t */
    return m != 0;
}
/* the same shape one level deeper: a wrapper of a wrapper (tests the fixpoint's iteration) */
__declspec(noinline) __declspec(dllexport) HMODULE f_get_base2(void) { return f_get_base(); }
__declspec(dllexport) int f_use_base2(void) { HMODULE m = f_get_base2(); return m != 0; }

/* --- NAME A LOCAL AFTER THE API THAT PRODUCED IT -> hModule.
 *     The local must NOT be the return value: autoname's `result` rule runs first and claims
 *     the single returned local, which is correct for a returned value and means f_get_base
 *     can never exercise this. Storing through a volatile global forces the handle to be a
 *     real local that lives across a call and is not the return. */
static volatile HMODULE g_saved;
__declspec(dllexport) void f_apiname(void) {
    HMODULE m = GetModuleHandleW(L"user32.dll");
    Sleep(0);            /* forces m to survive across a call, so it stays a local */
    g_saved = m;
}

/* --- sret: >8-byte struct return. The return TYPE must follow the returned struct pointer
 *     (that is the decidable half; the phantom-arg half is proven undecidable — see
 *     _qa/sret/srettest.c). */
typedef struct { float x, y, z; } V3;
__declspec(dllexport) V3 f_sret_v3(float a, float b, float c) { V3 v; v.x = a; v.y = b; v.z = c; return v; }

/* --- SSE2 byte-lane compare: pcmpeqb must DEFINE its xmm dest, else the dest keeps the
 *     dep-breaking xorps zero and pmovmskb reads a fabricated 0. */
__declspec(dllexport) int f_pcmpeqb(const char* p) {
    __m128i z = _mm_setzero_si128();
    __m128i c = _mm_cmpeq_epi8(z, _mm_loadu_si128((const __m128i*)p));
    return _mm_movemask_epi8(c);
}

/* --- compound assignment: `v = v + x` is what the machine does; `v += x` is what the source
 *     said. Every loop body in the binary carries the long form.
 *     VOLATILE IS LOAD-BEARING: with a plain local, /O2 FUSES `s += a[i]; s ^= a[i]>>3;` into
 *     one expression (`s = (s + a[i]) ^ (a[i] >> 3)`) and there is no `v = v op x` statement
 *     left to fold -- the first cut of this fixture tested nothing. volatile forces a real
 *     read-modify-write per statement, which is the shape the binary actually contains. */
__declspec(dllexport) void f_compound(volatile int* acc, const int* a, int n) {
    for (int i = 0; i < n; i++) {
        *acc += a[i];       /* must read `*acc += ...`, not `*acc = *acc + ...` */
        *acc ^= a[i] >> 3;  /* must read `*acc ^= ...` */
        *acc |= 1;          /* must read `*acc |= 1` */
    }
}
/* --- ++ / -- : `v = v + 1` must read `++v`. Volatile again: a plain counter loop is folded
 *     to a closed form (`return n != 0 ? n : 0`) and never increments anything. */
__declspec(dllexport) void f_incr(volatile int* p, int n) {
    for (int i = 0; i < n; i++) { (*p)++; }
}

/* --- stack string: bytes built from immediates must be recovered as a char array. */
__declspec(dllexport) int f_stackstr(void) {
    char buf[8];
    buf[0]='A'; buf[1]='B'; buf[2]='C'; buf[3]='D';
    buf[4]='E'; buf[5]='F'; buf[6]='G'; buf[7]=0;
    return (int)strlen(buf);
}
