/* Self-authored test DLL: known source -> compile -> decompile -> diff.
 * Every function is so the export table carries its NAME
 * (tests name recovery) and a driver can call it by name (tests behaviour).
 * Deliberately spans the patterns we care about: pointer arithmetic through
 * temps, address reuse, comparisons, structs, floats, recursion, tail calls. */
#include <stdint.h>

#define API

/* --- integer arithmetic --- */
API int my_add(int a, int b)          { return a + b; }
API int my_sub(int a, int b)          { return a - b; }
API int my_mul(int a, int b)          { return a * b; }
API int my_max(int a, int b)          { return a > b ? a : b; }
API int my_abs(int x)                 { return x < 0 ? -x : x; }
API int my_clamp(int x, int lo, int hi) { return x < lo ? lo : (x > hi ? hi : x); }

/* --- loops --- */
API int sum_to(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) s += i;
    return s;
}
API int64_t sum_array(const int *a, int n) {
    int64_t s = 0;
    for (int i = 0; i < n; i++) s += a[i];
    return s;
}
API int my_strlen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}
API int count_bit(uint32_t x) {
    int c = 0;
    while (x) { c += x & 1; x >>= 1; }
    return c;
}

/* --- pointers / memory --- */
API void my_swap(int *a, int *b) { int t = *a; *a = *b; *b = t; }
API int  deref_off(const int *p, int i) { return p[i] + p[i + 1]; }
API void set_range(int *p, int n, int v) { for (int i = 0; i < n; i++) p[i] = v; }

/* --- struct (address arithmetic through a base) --- */
typedef struct { int x, y, z, w; } Vec4;
API int vec4_sum(const Vec4 *v) { return v->x + v->y + v->z + v->w; }
API void vec4_scale(Vec4 *v, int k) { v->x *= k; v->y *= k; v->z *= k; v->w *= k; }

/* --- floats --- */
API float  favg(float a, float b)     { return (a + b) * 0.5f; }
API double dmax(double a, double b)    { return a > b ? a : b; }
API float  frelu(float x)             { return x > 0.0f ? x : 0.0f; }

/* --- recursion --- */
API int my_fib(int n)  { return n < 2 ? n : my_fib(n - 1) + my_fib(n - 2); }
API int my_gcd(int a, int b) { while (b) { int t = a % b; a = b; b = t; } return a; }

/* --- switch --- */
API int classify(int c) {
    switch (c) {
        case 0: return 100;
        case 1: return 200;
        case 2: return 300;
        case 7: return 700;
        default: return -1;
    }
}

/* --- tail call (should stay void: sequence, discard) --- */
API void seq_two(int *p) { set_range(p, 2, 7); set_range(p + 2, 2, 9); }
/* --- tail call forwarding an int (genuine return) --- */
API int fwd_add(int a, int b) { return my_add(a, b); }

/* --- harder: struct-array field access, nested loops, pointer return, bits --- */
typedef struct { int id; int vals[4]; } Rec;
API int  rec_sum(const Rec *r) { int s = r->id; for (int i=0;i<4;i++) s += r->vals[i]; return s; }
API void rec_bump(Rec *r, int d) { r->id += d; for (int i=0;i<4;i++) r->vals[i] += d; }
API int  mat_trace(const int *m, int n) { int s=0; for (int i=0;i<n;i++) s += m[i*n+i]; return s; }
API int  dot(const int *a, const int *b, int n) { int s=0; for (int i=0;i<n;i++) s += a[i]*b[i]; return s; }
API const int *find_max(const int *a, int n) { const int *best=a; for (int i=1;i<n;i++) if (a[i]>*best) best=&a[i]; return best; }
API int  reverse_bits(unsigned x) { unsigned r=0; for (int i=0;i<32;i++){ r=(r<<1)|(x&1); x>>=1; } return (int)r; }
API int  str_eq(const char *a, const char *b) { while (*a && *a==*b){a++;b++;} return *a==*b; }
API long long poly(int x) { long long r=0; for (int i=5;i>=0;i--) r = r*x + i; return r; }

