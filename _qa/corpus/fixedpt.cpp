/* Q16.16 fixed-point arithmetic behavioral-test target.
 * Compile: cl /LD /Od /W3 fixedpt.cpp
 * Pure deterministic C-style functions exported with clean names.
 */
#include <stdint.h>

#define FX_SHIFT   16
#define FX_ONE     (1 << FX_SHIFT)
#define FX_HALF    (1 << (FX_SHIFT - 1))
#define FX_MASK    (FX_ONE - 1)

/* ---- Conversions ---- */

extern "C" __declspec(dllexport) int32_t fx_from_int(int32_t v)
{
    return v << FX_SHIFT;
}

extern "C" __declspec(dllexport) int32_t fx_to_int(int32_t a)
{
    if (a < 0) {
        /* round toward zero for negatives */
        return -((-a) >> FX_SHIFT);
    }
    return a >> FX_SHIFT;
}

extern "C" __declspec(dllexport) int32_t fx_round_to_int(int32_t a)
{
    int32_t adj = a + FX_HALF;
    return adj >> FX_SHIFT;
}

extern "C" __declspec(dllexport) int32_t fx_frac(int32_t a)
{
    return a & FX_MASK;
}

/* ---- Basic arithmetic ---- */

extern "C" __declspec(dllexport) int32_t fx_add(int32_t a, int32_t b)
{
    int64_t s = (int64_t)a + (int64_t)b;
    if (s > (int64_t)0x7fffffff) return 0x7fffffff;
    if (s < -(int64_t)0x80000000) return (int32_t)0x80000000;
    return (int32_t)s;
}

extern "C" __declspec(dllexport) int32_t fx_sub(int32_t a, int32_t b)
{
    int64_t s = (int64_t)a - (int64_t)b;
    if (s > (int64_t)0x7fffffff) return 0x7fffffff;
    if (s < -(int64_t)0x80000000) return (int32_t)0x80000000;
    return (int32_t)s;
}

extern "C" __declspec(dllexport) int32_t fx_mul(int32_t a, int32_t b)
{
    int64_t p = (int64_t)a * (int64_t)b;
    p += FX_HALF; /* round */
    p >>= FX_SHIFT;
    if (p > (int64_t)0x7fffffff) return 0x7fffffff;
    if (p < -(int64_t)0x80000000) return (int32_t)0x80000000;
    return (int32_t)p;
}

extern "C" __declspec(dllexport) int32_t fx_div(int32_t a, int32_t b)
{
    if (b == 0) {
        if (a > 0) return 0x7fffffff;
        if (a < 0) return (int32_t)0x80000000;
        return 0;
    }
    int64_t num = (int64_t)a << FX_SHIFT;
    int64_t q = num / (int64_t)b;
    if (q > (int64_t)0x7fffffff) return 0x7fffffff;
    if (q < -(int64_t)0x80000000) return (int32_t)0x80000000;
    return (int32_t)q;
}

extern "C" __declspec(dllexport) int32_t fx_neg(int32_t a)
{
    if (a == (int32_t)0x80000000) return 0x7fffffff;
    return -a;
}

/* ---- Sign and magnitude ---- */

extern "C" __declspec(dllexport) int32_t fx_abs(int32_t a)
{
    if (a < 0) {
        if (a == (int32_t)0x80000000) return 0x7fffffff;
        return -a;
    }
    return a;
}

extern "C" __declspec(dllexport) int32_t fx_sign(int32_t a)
{
    if (a > 0) return 1;
    if (a < 0) return -1;
    return 0;
}

extern "C" __declspec(dllexport) int32_t fx_copysign(int32_t mag, int32_t sgn)
{
    int32_t m = fx_abs(mag);
    if (sgn < 0) return fx_neg(m);
    return m;
}

/* ---- Rounding family ---- */

extern "C" __declspec(dllexport) int32_t fx_floor(int32_t a)
{
    return a & ~FX_MASK;
}

extern "C" __declspec(dllexport) int32_t fx_ceil(int32_t a)
{
    int32_t f = a & ~FX_MASK;
    if ((a & FX_MASK) != 0) {
        return f + FX_ONE;
    }
    return f;
}

extern "C" __declspec(dllexport) int32_t fx_round(int32_t a)
{
    int32_t f = a & ~FX_MASK;
    int32_t frac = a & FX_MASK;
    if (frac >= FX_HALF) {
        return f + FX_ONE;
    }
    return f;
}

extern "C" __declspec(dllexport) int32_t fx_trunc(int32_t a)
{
    if (a < 0) {
        int32_t f = (-a) & ~FX_MASK;
        return -f;
    }
    return a & ~FX_MASK;
}

/* ---- Min / max / clamp ---- */

extern "C" __declspec(dllexport) int32_t fx_min(int32_t a, int32_t b)
{
    return (a < b) ? a : b;
}

extern "C" __declspec(dllexport) int32_t fx_max(int32_t a, int32_t b)
{
    return (a > b) ? a : b;
}

extern "C" __declspec(dllexport) int32_t fx_clamp(int32_t v, int32_t lo, int32_t hi)
{
    if (lo > hi) {
        int32_t t = lo;
        lo = hi;
        hi = t;
    }
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

extern "C" __declspec(dllexport) int32_t fx_saturate(int32_t v)
{
    return fx_clamp(v, 0, FX_ONE);
}

/* ---- Blending ---- */

extern "C" __declspec(dllexport) int32_t fx_avg(int32_t a, int32_t b)
{
    int64_t s = (int64_t)a + (int64_t)b;
    return (int32_t)(s >> 1);
}

extern "C" __declspec(dllexport) int32_t fx_lerp(int32_t a, int32_t b, int32_t t)
{
    int32_t d = fx_sub(b, a);
    int32_t scaled = fx_mul(d, t);
    return fx_add(a, scaled);
}

extern "C" __declspec(dllexport) int32_t fx_inv_lerp(int32_t a, int32_t b, int32_t v)
{
    int32_t denom = fx_sub(b, a);
    if (denom == 0) return 0;
    return fx_div(fx_sub(v, a), denom);
}

/* ---- Higher level numeric routines ---- */

extern "C" __declspec(dllexport) int32_t fx_sqrt(int32_t a)
{
    if (a <= 0) return 0;
    /* Integer sqrt of (a << 16) gives Q16.16 root. */
    uint64_t n = (uint64_t)a << FX_SHIFT;
    uint64_t x = n;
    uint64_t guess = 1;
    while ((guess << 1) <= x && guess < ((uint64_t)1 << 40)) {
        guess <<= 1;
    }
    /* Newton iteration */
    uint64_t r = guess;
    int i;
    for (i = 0; i < 40; i++) {
        if (r == 0) break;
        uint64_t nr = (r + n / r) >> 1;
        if (nr >= r) break;
        r = nr;
    }
    return (int32_t)r;
}

extern "C" __declspec(dllexport) int32_t fx_pow_int(int32_t base, int32_t exp)
{
    if (exp < 0) return 0;
    int32_t result = FX_ONE;
    int32_t b = base;
    int32_t e = exp;
    while (e > 0) {
        if (e & 1) {
            result = fx_mul(result, b);
        }
        b = fx_mul(b, b);
        e >>= 1;
    }
    return result;
}

extern "C" __declspec(dllexport) int32_t fx_factorial_scaled(int32_t n)
{
    if (n < 0) return 0;
    if (n <= 1) return FX_ONE;
    int32_t acc = FX_ONE;
    int32_t k;
    for (k = 2; k <= n; k++) {
        acc = fx_mul(acc, fx_from_int(k));
    }
    return acc;
}

extern "C" __declspec(dllexport) int32_t fx_gcd_int(int32_t a, int32_t b)
{
    int32_t x = (a < 0) ? -a : a;
    int32_t y = (b < 0) ? -b : b;
    while (y != 0) {
        int32_t t = x % y;
        x = y;
        y = t;
    }
    return x;
}

/* ---- Aggregate / array helpers ---- */

extern "C" __declspec(dllexport) int32_t fx_sum(const int32_t *arr, int32_t count)
{
    if (arr == 0 || count <= 0) return 0;
    int64_t acc = 0;
    int32_t i;
    for (i = 0; i < count; i++) {
        acc += (int64_t)arr[i];
    }
    if (acc > (int64_t)0x7fffffff) return 0x7fffffff;
    if (acc < -(int64_t)0x80000000) return (int32_t)0x80000000;
    return (int32_t)acc;
}

extern "C" __declspec(dllexport) int32_t fx_mean(const int32_t *arr, int32_t count)
{
    if (arr == 0 || count <= 0) return 0;
    int64_t acc = 0;
    int32_t i;
    for (i = 0; i < count; i++) {
        acc += (int64_t)arr[i];
    }
    return (int32_t)(acc / count);
}

extern "C" __declspec(dllexport) int32_t fx_array_max(const int32_t *arr, int32_t count)
{
    if (arr == 0 || count <= 0) return 0;
    int32_t best = arr[0];
    int32_t i;
    for (i = 1; i < count; i++) {
        if (arr[i] > best) {
            best = arr[i];
        }
    }
    return best;
}

extern "C" __declspec(dllexport) int32_t fx_dot(const int32_t *a, const int32_t *b, int32_t count)
{
    if (a == 0 || b == 0 || count <= 0) return 0;
    int32_t acc = 0;
    int32_t i;
    for (i = 0; i < count; i++) {
        acc = fx_add(acc, fx_mul(a[i], b[i]));
    }
    return acc;
}

/* ---- Struct-based vector ops ---- */

typedef struct {
    int32_t x;
    int32_t y;
    int32_t z;
} fx_vec3;

extern "C" __declspec(dllexport) void fx_vec3_add(const fx_vec3 *a, const fx_vec3 *b, fx_vec3 *out)
{
    if (a == 0 || b == 0 || out == 0) return;
    out->x = fx_add(a->x, b->x);
    out->y = fx_add(a->y, b->y);
    out->z = fx_add(a->z, b->z);
}

extern "C" __declspec(dllexport) void fx_vec3_scale(const fx_vec3 *a, int32_t s, fx_vec3 *out)
{
    if (a == 0 || out == 0) return;
    out->x = fx_mul(a->x, s);
    out->y = fx_mul(a->y, s);
    out->z = fx_mul(a->z, s);
}

extern "C" __declspec(dllexport) int32_t fx_vec3_dot(const fx_vec3 *a, const fx_vec3 *b)
{
    if (a == 0 || b == 0) return 0;
    int32_t acc = 0;
    acc = fx_add(acc, fx_mul(a->x, b->x));
    acc = fx_add(acc, fx_mul(a->y, b->y));
    acc = fx_add(acc, fx_mul(a->z, b->z));
    return acc;
}

extern "C" __declspec(dllexport) int32_t fx_vec3_length(const fx_vec3 *a)
{
    if (a == 0) return 0;
    int32_t sq = fx_vec3_dot(a, a);
    return fx_sqrt(sq);
}

/* ---- Classification with switch / recursion ---- */

extern "C" __declspec(dllexport) int32_t fx_classify(int32_t a)
{
    int32_t s = fx_sign(a);
    switch (s) {
        case -1:
            if (a <= -FX_ONE) return 3; /* large negative */
            return 2;                   /* small negative */
        case 0:
            return 0;                   /* zero */
        case 1:
            if (a >= FX_ONE) return 5;  /* large positive */
            return 4;                   /* small positive */
        default:
            return -1;
    }
}

extern "C" __declspec(dllexport) int32_t fx_fib_scaled(int32_t n)
{
    if (n <= 0) return 0;
    if (n == 1) return FX_ONE;
    return fx_add(fx_fib_scaled(n - 1), fx_fib_scaled(n - 2));
}

extern "C" __declspec(dllexport) int32_t fx_count_set_bits(int32_t a)
{
    uint32_t v = (uint32_t)a;
    int32_t n = 0;
    do {
        if (v & 1u) n++;
        v >>= 1;
    } while (v != 0);
    return n;
}

extern "C" __declspec(dllexport) int32_t fx_in_range(int32_t v, int32_t lo, int32_t hi)
{
    int32_t i;
    int32_t hits = 0;
    for (i = 0; i < 1; i++) {
        if (v < lo) continue;
        if (v > hi) break;
        hits = 1;
    }
    return hits;
}
