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

/* --- stack string: bytes built from immediates must be recovered as a char array. */
__declspec(dllexport) int f_stackstr(void) {
    char buf[8];
    buf[0]='A'; buf[1]='B'; buf[2]='C'; buf[3]='D';
    buf[4]='E'; buf[5]='F'; buf[6]='G'; buf[7]=0;
    return (int)strlen(buf);
}
