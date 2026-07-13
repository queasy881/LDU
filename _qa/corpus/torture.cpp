#include <stdint.h>
#include <stddef.h>

/* ---- linked structures (circular-list-walk regression + variants) ---- */
typedef struct LN { struct LN* next; int v; } LN;

extern "C" __declspec(dllexport) int list_walk_to_head(LN* start) {
    /* walk until next wraps back to start (circular) */
    LN* p = start; int n = 0;
    if (!p) return 0;
    do { p = p->next; n++; } while (p && p != start && n < 1000);
    return n;
}
extern "C" __declspec(dllexport) int list_count_null(LN* h) {
    int n = 0; while (h) { n++; h = h->next; } return n;
}
extern "C" __declspec(dllexport) LN* list_last(LN* h) {
    if (!h) return 0;
    while (h->next) h = h->next;
    return h;
}
extern "C" __declspec(dllexport) int list_sum_bounded(LN* h, int cap) {
    int s = 0, i = 0;
    while (h && i < cap) { s += h->v; h = h->next; i++; }
    return s;
}

/* ---- unrolled/vectorized reductions (remainder regression) ---- */
extern "C" __declspec(dllexport) long long isum(const int* a, int n) {
    long long s = 0; for (int i = 0; i < n; i++) s += a[i]; return s;
}
extern "C" __declspec(dllexport) int imax(const int* a, int n) {
    int m = a[0]; for (int i = 1; i < n; i++) if (a[i] > m) m = a[i]; return m;
}
extern "C" __declspec(dllexport) int idot(const int* a, const int* b, int n) {
    int s = 0; for (int i = 0; i < n; i++) s += a[i] * b[i]; return s;
}
extern "C" __declspec(dllexport) double dsum(const double* a, int n) {
    double s = 0; for (int i = 0; i < n; i++) s += a[i]; return s;
}
extern "C" __declspec(dllexport) int count_pos(const int* a, int n) {
    int c = 0; for (int i = 0; i < n; i++) if (a[i] > 0) c++; return c;
}

/* ---- deep switch / jump table ---- */
extern "C" __declspec(dllexport) int classify16(int x) {
    switch (x) {
        case 0: return 10; case 1: return 11; case 2: return 12; case 3: return 13;
        case 4: return 14; case 5: return 15; case 6: return 16; case 7: return 17;
        case 8: return 18; case 9: return 19; case 10: return 20; case 11: return 21;
        case 12: return 22; case 13: return 23; case 14: return 24; case 15: return 25;
        default: return -1;
    }
}

/* ---- mutual recursion ---- */
extern "C" __declspec(dllexport) int is_even_r(int n);
extern "C" __declspec(dllexport) int is_odd_r(int n) { return n == 0 ? 0 : is_even_r(n - 1); }
extern "C" __declspec(dllexport) int is_even_r(int n) { return n == 0 ? 1 : is_odd_r(n - 1); }

/* ---- nested loops with break/continue ---- */
extern "C" __declspec(dllexport) int first_pair_sum(const int* a, int n, int target) {
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            if (a[i] + a[j] == target) return i * 1000 + j;
    return -1;
}
extern "C" __declspec(dllexport) int count_dup_rows(const int* m, int rows, int cols) {
    int c = 0;
    for (int i = 0; i < rows; i++) {
        int same = 1;
        for (int j = 1; j < cols; j++) if (m[i*cols+j] != m[i*cols]) { same = 0; break; }
        if (same) c++;
    }
    return c;
}

/* ---- bit manipulation ---- */
extern "C" __declspec(dllexport) unsigned rev_bits(unsigned x) {
    unsigned r = 0;
    for (int i = 0; i < 32; i++) { r = (r << 1) | (x & 1); x >>= 1; }
    return r;
}
extern "C" __declspec(dllexport) int trailing_zeros(unsigned x) {
    if (!x) return 32;
    int c = 0; while (!(x & 1)) { c++; x >>= 1; } return c;
}
extern "C" __declspec(dllexport) unsigned rotl(unsigned x, int k) {
    k &= 31; return (x << k) | (x >> ((32 - k) & 31));
}

/* ---- memory RMW (refcount off-by-one regression) ---- */
extern "C" __declspec(dllexport) int rc_dec(int* p) {
    *p = *p - 1;
    if (*p != 0) return 1;
    return 0;
}
extern "C" __declspec(dllexport) int rc_inc_check(int* p, int limit) {
    *p += 1;
    if (*p >= limit) return -1;
    return *p;
}

/* ---- signed/unsigned edges ---- */
extern "C" __declspec(dllexport) int clamp_s(int x, int lo, int hi) {
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}
extern "C" __declspec(dllexport) unsigned udiv_round(unsigned a, unsigned b) {
    if (b == 0) return 0;
    return (a + b/2) / b;
}
extern "C" __declspec(dllexport) int sign_of(int x) {
    if (x < 0) return -1;
    if (x > 0) return 1;
    return 0;
}

/* ---- short-circuit chains ---- */
extern "C" __declspec(dllexport) int in_ranges(int x) {
    return (x >= 0 && x < 10) || (x >= 100 && x < 110) || (x >= 1000 && x < 1010);
}

/* ---- struct field arithmetic + packed 2-float (vec2 regression) ---- */
typedef struct { float x, y; } V2;
extern "C" __declspec(dllexport) V2 v2add(V2 a, V2 b) { V2 r; r.x = a.x + b.x; r.y = a.y + b.y; return r; }
extern "C" __declspec(dllexport) float v2dot(V2 a, V2 b) { return a.x*b.x + a.y*b.y; }

typedef struct { int a; long long b; short c; } Rec;
extern "C" __declspec(dllexport) long long rec_fold(const Rec* r, int n) {
    long long s = 0;
    for (int i = 0; i < n; i++) s += (long long)r[i].a + r[i].b - r[i].c;
    return s;
}

/* ---- do-while + accumulator ---- */
extern "C" __declspec(dllexport) int digits10(unsigned n) {
    int d = 0; do { d++; n /= 10; } while (n); return d;
}
extern "C" __declspec(dllexport) unsigned gcd_u(unsigned a, unsigned b) {
    while (b) { unsigned t = a % b; a = b; b = t; } return a;
}

/* ---- byte scan / string ---- */
extern "C" __declspec(dllexport) int strlen8(const char* s) {
    int n = 0; while (s[n]) n++; return n;
}
extern "C" __declspec(dllexport) int hash_fnv(const char* s) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return (int)h;
}
extern "C" __declspec(dllexport) int count_char(const char* s, int ch) {
    int c = 0; while (*s) { if (*s == (char)ch) c++; s++; } return c;
}

/* ---- overflow-guarded arithmetic ---- */
extern "C" __declspec(dllexport) int sat_mul(int a, int b) {
    long long p = (long long)a * b;
    if (p > 2147483647LL) return 2147483647;
    if (p < -2147483648LL) return -2147483647 - 1;
    return (int)p;
}
