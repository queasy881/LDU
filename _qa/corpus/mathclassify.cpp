/* mathclassify.cpp - float/double BIT-CLASSIFICATION torture module.
 * Every exported fn is deterministic pure C. Build:
 *   cl /nologo /LD /Od mathclassify.cpp
 * Designed to exercise the movd/movq FLOAT-BITS REINTERPRET path (`*(int*)&f`):
 * isnan/isinf/signbit/ilogb/frexp/copysign/fabs/nextafter — the exponent/mantissa
 * bit tests that a bit-EXACT lift must recover. A value-cast (not bit) lift silently
 * gives wrong answers here, so this DLL is the behavioral guard for that class.
 */
#include <stdint.h>

#define EXPORT extern "C" __declspec(dllexport)

/* bit reinterprets via union type-pun (compile to a direct movd/movq, no memcpy
 * call — __forceinline so no helper fn is emitted at /Od, which would otherwise
 * make callers depend on a mis-recovered memcpy signature). */
static __forceinline uint32_t f2u(float f)   { union { float f; uint32_t u; } x; x.f = f; return x.u; }
static __forceinline float    u2f(uint32_t u){ union { uint32_t u; float f; } x; x.u = u; return x.f; }
static __forceinline uint64_t d2u(double d)  { union { double d; uint64_t u; } x; x.d = d; return x.u; }
static __forceinline double   u2d(uint64_t u){ union { uint64_t u; double d; } x; x.u = u; return x.d; }

/* ---- single-precision classification (movd bit extraction) ------------- */
EXPORT int f_signbit(float x)  { return (int)(f2u(x) >> 31); }
EXPORT int f_exponent(float x) { return (int)((f2u(x) >> 23) & 0xff); }        /* raw biased exp */
EXPORT int f_ilogb(float x)    { return (int)((f2u(x) >> 23) & 0xff) - 127; }  /* unbiased */
EXPORT uint32_t f_mantissa(float x) { return f2u(x) & 0x7fffff; }
EXPORT int f_isnan(float x)    { uint32_t u = f2u(x); return ((u & 0x7f800000) == 0x7f800000) && (u & 0x7fffff); }
EXPORT int f_isinf(float x)    { uint32_t u = f2u(x); return ((u & 0x7fffffff) == 0x7f800000); }
EXPORT int f_iszero(float x)   { return (f2u(x) & 0x7fffffff) == 0; }
EXPORT int f_isfinite(float x) { return (f2u(x) & 0x7f800000) != 0x7f800000; }
EXPORT float f_fabs(float x)   { return u2f(f2u(x) & 0x7fffffff); }
EXPORT float f_neg(float x)    { return u2f(f2u(x) ^ 0x80000000u); }
EXPORT float f_copysign(float mag, float sgn) { return u2f((f2u(mag) & 0x7fffffff) | (f2u(sgn) & 0x80000000u)); }
EXPORT float f_scalb2(float x, int n) {         /* x * 2^n via exponent add (normal range) */
    uint32_t u = f2u(x);
    if ((u & 0x7f800000) == 0) return x;        /* zero/denormal: leave */
    return u2f(u + ((uint32_t)n << 23));
}
EXPORT float f_nextup(float x) {                /* next representable toward +inf (finite +x) */
    uint32_t u = f2u(x);
    if ((u & 0x7f800000) == 0x7f800000) return x;
    return u2f(u + 1);
}

/* the acosf-style domain classifier: NaN/Inf/tiny/one/other via exponent bits */
EXPORT int f_classify(float x) {
    uint32_t u = f2u(x);
    uint32_t e = (u >> 23) & 0xff;
    if (e == 0xff) return (u & 0x7fffff) ? 3 : 2;   /* nan : inf */
    if (e == 0)    return (u & 0x7fffff) ? 4 : 0;   /* subnormal : zero */
    if (e < 0x65)  return 5;                        /* very small */
    if (e == 0x7f && (u & 0x7fffff) == 0) return 1; /* exactly +/-1.0 */
    return 6;
}

/* round-trip: extract mantissa+exp, rebuild -> identity for normals */
EXPORT float f_rebuild(float x) {
    uint32_t u = f2u(x);
    uint32_t s = u & 0x80000000u, e = (u >> 23) & 0xff, m = u & 0x7fffff;
    return u2f(s | (e << 23) | m);
}

/* ---- double-precision classification (movq bit extraction) ------------- */
EXPORT int d_signbit(double x)  { return (int)(d2u(x) >> 63); }
EXPORT int d_ilogb(double x)    { return (int)((d2u(x) >> 52) & 0x7ff) - 1023; }
EXPORT int d_isnan(double x)    { uint64_t u = d2u(x); return ((u & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) && (u & 0xfffffffffffffULL); }
EXPORT int d_isinf(double x)    { return (d2u(x) & 0x7fffffffffffffffULL) == 0x7ff0000000000000ULL; }
EXPORT double d_fabs(double x)  { return u2d(d2u(x) & 0x7fffffffffffffffULL); }
EXPORT double d_copysign(double mag, double sgn) { return u2d((d2u(mag) & 0x7fffffffffffffffULL) | (d2u(sgn) & 0x8000000000000000ULL)); }

/* mixed: frexp-style split (mantissa in [0.5,1), exponent) for a normal float */
EXPORT float f_frexp_mant(float x) {
    uint32_t u = f2u(x);
    if ((u & 0x7f800000) == 0 || (u & 0x7f800000) == 0x7f800000) return x;
    return u2f((u & 0x807fffff) | (0x7e << 23));   /* force exponent to 2^-1 range */
}
EXPORT int f_frexp_exp(float x) {
    uint32_t u = f2u(x);
    if ((u & 0x7f800000) == 0 || (u & 0x7f800000) == 0x7f800000) return 0;
    return (int)((u >> 23) & 0xff) - 126;
}
