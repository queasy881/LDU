/* floattorture.cpp - float/double-heavy decompiler torture module.
 * Every exported fn is deterministic pure C. Build BOTH:
 *   cl /nologo /LD /Od floattorture.cpp        (scalar SSE)
 *   cl /nologo /LD /O2 floattorture.cpp        (auto-vectorized packed SIMD)
 * Designed to trip: packed-float SIMD lanes, double vs float width, float->
 * struct stores, int<->float conversions, reductions, min/max cmov, sqrt/rsqrt,
 * struct-by-value (sret), mixed precision.
 */
#include <stdint.h>

#define EXPORT extern "C" __declspec(dllexport)

/* ---- plain vector/matrix structs (by value = xmm packing / sret) -------- */
typedef struct Vec2 { float x, y; } Vec2;
typedef struct Vec3 { float x, y, z; } Vec3;
typedef struct Vec4 { float x, y, z, w; } Vec4;
typedef struct DVec3 { double x, y, z; } DVec3;
typedef struct Mat2 { float m[4]; } Mat2;
typedef struct Cplx { double re, im; } Cplx;

/* ---- scalar float/double arithmetic ------------------------------------ */
EXPORT float f_add(float a, float b) { return a + b; }
EXPORT float f_mul3(float a, float b, float c) { return a * b * c; }
EXPORT double d_add(double a, double b) { return a + b; }
EXPORT double d_muladd(double a, double b, double c) { return a * b + c; }
EXPORT float f_div(float a, float b) { return b == 0.0f ? 0.0f : a / b; }
EXPORT double d_div(double a, double b) { return b == 0.0 ? 0.0 : a / b; }

/* fused multiply chains (FMA-ish) */
EXPORT double poly_horner(double x, double c0, double c1, double c2, double c3) {
    double r = c3;
    r = r * x + c2;
    r = r * x + c1;
    r = r * x + c0;
    return r;
}
EXPORT float poly5f(float x, float a, float b, float c, float d, float e) {
    return ((((a * x + b) * x + c) * x + d) * x + e);
}

/* ---- int <-> float conversions (cvt roundtrips) ------------------------ */
EXPORT float i_to_f(int n) { return (float)n; }
EXPORT double i_to_d(int n) { return (double)n; }
EXPORT int f_to_i(float x) { return (int)x; }
EXPORT int d_to_i(double x) { return (int)x; }
EXPORT double f_to_d(float x) { return (double)x; }
EXPORT float d_to_f(double x) { return (float)x; }
EXPORT long long d_to_ll(double x) { return (long long)x; }
EXPORT double ll_to_d(long long n) { return (double)n; }
EXPORT float convert_chain(int n) {
    float f = (float)n;
    double d = (double)f * 1.5;
    int i = (int)d;
    return (float)i + 0.25f;
}

/* ---- abs / negate / sign (xorps/andps sign-mask idioms) ---------------- */
EXPORT float f_abs(float x) { return x < 0.0f ? -x : x; }
EXPORT double d_abs(double x) { return x < 0.0 ? -x : x; }
EXPORT float f_neg(float x) { return -x; }
EXPORT double d_copysign(double m, double s) {
    double a = m < 0.0 ? -m : m;
    return s < 0.0 ? -a : a;
}
EXPORT int f_sign(float x) { return x > 0.0f ? 1 : (x < 0.0f ? -1 : 0); }

/* ---- min / max / clamp (comiss/maxss/cmov) ----------------------------- */
EXPORT float f_min(float a, float b) { return a < b ? a : b; }
EXPORT float f_max(float a, float b) { return a > b ? a : b; }
EXPORT double d_clamp(double x, double lo, double hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
EXPORT float f_min3(float a, float b, float c) {
    float m = a < b ? a : b;
    return m < c ? m : c;
}
EXPORT float clampf(float x, float lo, float hi) {
    return (x < lo) ? lo : ((x > hi) ? hi : x);
}

/* ---- sqrt / rsqrt / reciprocal ---------------------------------------- */
static double my_sqrt(double x) {
    if (x <= 0.0) return 0.0;
    double g = x;
    for (int i = 0; i < 20; ++i) g = 0.5 * (g + x / g);
    return g;
}
EXPORT double d_sqrt(double x) { return my_sqrt(x); }
EXPORT float f_hypot(float a, float b) {
    return (float)my_sqrt((double)a * a + (double)b * b);
}
EXPORT float f_rsqrt(float x) { return x <= 0.0f ? 0.0f : 1.0f / (float)my_sqrt(x); }

/* ---- Vec3 math (packed SIMD under /O2) --------------------------------- */
EXPORT float vec3_dot(const Vec3* a, const Vec3* b) {
    return a->x * b->x + a->y * b->y + a->z * b->z;
}
EXPORT float vec3_len(const Vec3* a) {
    return (float)my_sqrt((double)(a->x * a->x + a->y * a->y + a->z * a->z));
}
EXPORT void vec3_add(const Vec3* a, const Vec3* b, Vec3* out) {
    out->x = a->x + b->x;
    out->y = a->y + b->y;
    out->z = a->z + b->z;
}
EXPORT void vec3_scale(const Vec3* a, float s, Vec3* out) {
    out->x = a->x * s;
    out->y = a->y * s;
    out->z = a->z * s;
}
EXPORT void vec3_cross(const Vec3* a, const Vec3* b, Vec3* out) {
    out->x = a->y * b->z - a->z * b->y;
    out->y = a->z * b->x - a->x * b->z;
    out->z = a->x * b->y - a->y * b->x;
}
EXPORT void vec3_normalize(const Vec3* a, Vec3* out) {
    float len = (float)my_sqrt((double)(a->x * a->x + a->y * a->y + a->z * a->z));
    if (len == 0.0f) { out->x = out->y = out->z = 0.0f; return; }
    float inv = 1.0f / len;
    out->x = a->x * inv;
    out->y = a->y * inv;
    out->z = a->z * inv;
}
EXPORT void vec3_lerp(const Vec3* a, const Vec3* b, float t, Vec3* out) {
    out->x = a->x + (b->x - a->x) * t;
    out->y = a->y + (b->y - a->y) * t;
    out->z = a->z + (b->z - a->z) * t;
}

/* ---- Vec4 (16-byte, movaps/mulps a natural xmm) ------------------------ */
EXPORT float vec4_dot(const Vec4* a, const Vec4* b) {
    return a->x * b->x + a->y * b->y + a->z * b->z + a->w * b->w;
}
EXPORT void vec4_madd(const Vec4* a, const Vec4* b, float s, Vec4* out) {
    out->x = a->x + b->x * s;
    out->y = a->y + b->y * s;
    out->z = a->z + b->z * s;
    out->w = a->w + b->w * s;
}

/* ---- struct-by-value returns (sret / xmm packing) ---------------------- */
EXPORT Vec2 vec2_make(float x, float y) { Vec2 v; v.x = x; v.y = y; return v; }
EXPORT Vec2 vec2_add(Vec2 a, Vec2 b) { Vec2 r; r.x = a.x + b.x; r.y = a.y + b.y; return r; }
EXPORT double vec2_len(Vec2 v) { return my_sqrt((double)v.x * v.x + (double)v.y * v.y); }
EXPORT Vec3 vec3_make(float x, float y, float z) { Vec3 v; v.x = x; v.y = y; v.z = z; return v; }

/* ---- complex numbers (double pair, packed) ----------------------------- */
EXPORT Cplx cplx_mul(Cplx a, Cplx b) {
    Cplx r;
    r.re = a.re * b.re - a.im * b.im;
    r.im = a.re * b.im + a.im * b.re;
    return r;
}
EXPORT double cplx_abs(Cplx a) { return my_sqrt(a.re * a.re + a.im * a.im); }

/* ---- float array reductions (unrolled/vectorized) ---------------------- */
EXPORT float arr_sum(const float* a, int n) {
    float s = 0.0f;
    for (int i = 0; i < n; ++i) s += a[i];
    return s;
}
EXPORT double arr_sumd(const double* a, int n) {
    double s = 0.0;
    for (int i = 0; i < n; ++i) s += a[i];
    return s;
}
EXPORT float arr_dot(const float* a, const float* b, int n) {
    float s = 0.0f;
    for (int i = 0; i < n; ++i) s += a[i] * b[i];
    return s;
}
EXPORT float arr_max(const float* a, int n) {
    if (n <= 0) return 0.0f;
    float m = a[0];
    for (int i = 1; i < n; ++i) if (a[i] > m) m = a[i];
    return m;
}
EXPORT float arr_min(const float* a, int n) {
    if (n <= 0) return 0.0f;
    float m = a[0];
    for (int i = 1; i < n; ++i) if (a[i] < m) m = a[i];
    return m;
}
EXPORT double arr_mean(const double* a, int n) {
    if (n <= 0) return 0.0;
    double s = 0.0;
    for (int i = 0; i < n; ++i) s += a[i];
    return s / (double)n;
}
EXPORT double arr_variance(const double* a, int n) {
    if (n <= 0) return 0.0;
    double mean = 0.0;
    for (int i = 0; i < n; ++i) mean += a[i];
    mean /= (double)n;
    double v = 0.0;
    for (int i = 0; i < n; ++i) { double d = a[i] - mean; v += d * d; }
    return v / (double)n;
}
EXPORT double arr_stddev(const double* a, int n) { return my_sqrt(arr_variance(a, n)); }

/* ---- float array maps (element-wise, vectorized) ----------------------- */
EXPORT void arr_scale(float* a, int n, float s) {
    for (int i = 0; i < n; ++i) a[i] *= s;
}
EXPORT void arr_saxpy(float* y, const float* x, float alpha, int n) {
    for (int i = 0; i < n; ++i) y[i] += alpha * x[i];
}
EXPORT void arr_clamp(float* a, int n, float lo, float hi) {
    for (int i = 0; i < n; ++i) {
        if (a[i] < lo) a[i] = lo;
        else if (a[i] > hi) a[i] = hi;
    }
}
EXPORT void arr_abs(float* a, int n) {
    for (int i = 0; i < n; ++i) if (a[i] < 0.0f) a[i] = -a[i];
}
EXPORT void arr_normalize01(float* a, int n) {
    if (n <= 0) return;
    float mn = a[0], mx = a[0];
    for (int i = 1; i < n; ++i) { if (a[i] < mn) mn = a[i]; if (a[i] > mx) mx = a[i]; }
    float range = mx - mn;
    if (range == 0.0f) return;
    float inv = 1.0f / range;
    for (int i = 0; i < n; ++i) a[i] = (a[i] - mn) * inv;
}

/* ---- 2x2 matrix (float m[4], packed) ----------------------------------- */
EXPORT void mat2_mul(const Mat2* a, const Mat2* b, Mat2* out) {
    out->m[0] = a->m[0] * b->m[0] + a->m[1] * b->m[2];
    out->m[1] = a->m[0] * b->m[1] + a->m[1] * b->m[3];
    out->m[2] = a->m[2] * b->m[0] + a->m[3] * b->m[2];
    out->m[3] = a->m[2] * b->m[1] + a->m[3] * b->m[3];
}
EXPORT float mat2_det(const Mat2* a) { return a->m[0] * a->m[3] - a->m[1] * a->m[2]; }
EXPORT void mat2_vec(const Mat2* a, float vx, float vy, float* ox, float* oy) {
    *ox = a->m[0] * vx + a->m[1] * vy;
    *oy = a->m[2] * vx + a->m[3] * vy;
}

/* ---- DVec3 (double, packed-double SIMD under /O2) ---------------------- */
EXPORT double dvec3_dot(const DVec3* a, const DVec3* b) {
    return a->x * b->x + a->y * b->y + a->z * b->z;
}
EXPORT void dvec3_axpy(DVec3* y, const DVec3* x, double a) {
    y->x += a * x->x;
    y->y += a * x->y;
    y->z += a * x->z;
}

/* ---- interpolation / easing ------------------------------------------- */
EXPORT float lerpf(float a, float b, float t) { return a + (b - a) * t; }
EXPORT float smoothstep(float e0, float e1, float x) {
    float t = (x - e0) / (e1 - e0);
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    return t * t * (3.0f - 2.0f * t);
}
EXPORT double bilerp(double q00, double q01, double q10, double q11, double tx, double ty) {
    double a = q00 + (q10 - q00) * tx;
    double b = q01 + (q11 - q01) * tx;
    return a + (b - a) * ty;
}

/* ---- trig approximations (polynomial, FMA chains) ---------------------- */
EXPORT double approx_sin(double x) {
    /* Bhaskara-ish, x in radians reduced roughly */
    double x2 = x * x;
    double x3 = x2 * x;
    double x5 = x3 * x2;
    return x - x3 / 6.0 + x5 / 120.0;
}
EXPORT double approx_cos(double x) {
    double x2 = x * x;
    double x4 = x2 * x2;
    return 1.0 - x2 / 2.0 + x4 / 24.0;
}
EXPORT double deg2rad(double d) { return d * 3.14159265358979323846 / 180.0; }

/* ---- fixed-point <-> float (int scaling, cvt) -------------------------- */
EXPORT int float_to_fix16(float x) { return (int)(x * 65536.0f); }
EXPORT float fix16_to_float(int f) { return (float)f / 65536.0f; }
EXPORT int fix_mul(int a, int b) { return (int)(((long long)a * b) >> 16); }

/* ---- numerical: Simpson integration of x^2 over [a,b] ------------------ */
EXPORT double simpson_sq(double a, double b, int n) {
    if (n <= 0 || (n & 1)) n = 2;
    double h = (b - a) / (double)n;
    double s = a * a + b * b;
    for (int i = 1; i < n; ++i) {
        double x = a + h * i;
        s += (i & 1) ? 4.0 * (x * x) : 2.0 * (x * x);
    }
    return s * h / 3.0;
}

/* ---- running signal filter (double state, loop-carried) ---------------- */
EXPORT double ema_filter(const double* in, int n, double alpha) {
    if (n <= 0) return 0.0;
    double y = in[0];
    for (int i = 1; i < n; ++i) y = alpha * in[i] + (1.0 - alpha) * y;
    return y;
}
EXPORT double biquad_one(double x, double* s1, double* s2, double b0, double b1, double b2) {
    double y = b0 * x + *s1;
    *s1 = b1 * x + *s2;
    *s2 = b2 * x;
    return y;
}

/* ---- mixed: distance / geometry --------------------------------------- */
EXPORT double dist2d(double x1, double y1, double x2, double y2) {
    double dx = x2 - x1, dy = y2 - y1;
    return my_sqrt(dx * dx + dy * dy);
}
EXPORT float triangle_area(const Vec2* a, const Vec2* b, const Vec2* c) {
    float e0x = b->x - a->x, e0y = b->y - a->y;
    float e1x = c->x - a->x, e1y = c->y - a->y;
    float cross = e0x * e1y - e0y * e1x;
    return (cross < 0.0f ? -cross : cross) * 0.5f;
}
EXPORT int point_in_circle(float px, float py, float cx, float cy, float r) {
    float dx = px - cx, dy = py - cy;
    return (dx * dx + dy * dy) <= r * r ? 1 : 0;
}
