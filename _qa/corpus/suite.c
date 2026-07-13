#include <stdint.h>

typedef struct Node { struct Node* next; int val; } Node;
typedef struct Rec { int a; int b; long long c; short d; } Rec;

/* 1. sum array via pointer walk */
__declspec(dllexport) long long sum_array(const int* p, int n) {
    long long s = 0;
    for (int i = 0; i < n; i++) s += p[i];
    return s;
}
/* 2. strlen */
__declspec(dllexport) int my_strlen(const char* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}
/* 3. reverse in place, two pointers */
__declspec(dllexport) void reverse_int(int* a, int n) {
    int i = 0, j = n - 1;
    while (i < j) { int t = a[i]; a[i] = a[j]; a[j] = t; i++; j--; }
}
/* 4. binary search */
__declspec(dllexport) int bsearch_i(const int* a, int n, int key) {
    int lo = 0, hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid] == key) return mid;
        if (a[mid] < key) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
}
/* 5. recursive factorial */
__declspec(dllexport) long long fact_r(int n) {
    if (n <= 1) return 1;
    return (long long)n * fact_r(n - 1);
}
/* 6. gcd loop */
__declspec(dllexport) int gcd_loop(int a, int b) {
    while (b) { int t = a % b; a = b; b = t; }
    return a;
}
/* 7. count set bits */
__declspec(dllexport) int popcnt(unsigned x) {
    int c = 0;
    while (x) { c += x & 1; x >>= 1; }
    return c;
}
/* 8. linked list length */
__declspec(dllexport) int list_len(const Node* h) {
    int n = 0;
    while (h) { n++; h = h->next; }
    return n;
}
/* 9. linked list sum */
__declspec(dllexport) long long list_sum(const Node* h) {
    long long s = 0;
    for (; h; h = h->next) s += h->val;
    return s;
}
/* 10. struct field arithmetic */
__declspec(dllexport) long long rec_score(const Rec* r) {
    return (long long)r->a * 2 + r->b - r->c + r->d;
}
/* 11. switch dispatch */
__declspec(dllexport) int classify(int c) {
    switch (c) {
        case 0: return 100;
        case 1: return 200;
        case 2: return 300;
        case 5: return 500;
        default: return -1;
    }
}
/* 12. nested loop bubble sort */
__declspec(dllexport) void bubble(int* a, int n) {
    for (int i = 0; i < n - 1; i++)
        for (int j = 0; j < n - 1 - i; j++)
            if (a[j] > a[j+1]) { int t = a[j]; a[j] = a[j+1]; a[j+1] = t; }
}
/* 13. 2D matrix trace */
__declspec(dllexport) long long mat_trace(const int* m, int n) {
    long long s = 0;
    for (int i = 0; i < n; i++) s += m[i*n + i];
    return s;
}
/* 14. memcpy */
__declspec(dllexport) void mcpy(char* d, const char* s, int n) {
    for (int i = 0; i < n; i++) d[i] = s[i];
}
/* 15. do-while accumulate */
__declspec(dllexport) int digit_count(unsigned n) {
    int c = 0;
    do { c++; n /= 10; } while (n);
    return c;
}
/* 16. null-check then deref */
__declspec(dllexport) int safe_first(const int* p) {
    if (!p) return -1;
    return p[0];
}
/* 17. signed vs unsigned compare */
__declspec(dllexport) int clampu(int x, unsigned hi) {
    if (x < 0) return 0;
    if ((unsigned)x > hi) return (int)hi;
    return x;
}
/* 18. string compare */
__declspec(dllexport) int str_eq(const char* a, const char* b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *a == *b;
}
/* 19. find max */
__declspec(dllexport) int arr_max(const int* a, int n) {
    int m = a[0];
    for (int i = 1; i < n; i++) if (a[i] > m) m = a[i];
    return m;
}
/* 20. bit flags set/test */
__declspec(dllexport) int flags_op(unsigned* f, int bit, int set) {
    unsigned mask = 1u << bit;
    if (set) *f |= mask; else *f &= ~mask;
    return (*f & mask) != 0;
}
/* 21. Kadane max subarray */
__declspec(dllexport) long long kadane(const int* a, int n) {
    long long best = a[0], cur = a[0];
    for (int i = 1; i < n; i++) {
        cur = (a[i] > cur + a[i]) ? a[i] : cur + a[i];
        if (cur > best) best = cur;
    }
    return best;
}
/* 22. pointer chase to node value at depth */
__declspec(dllexport) int nth_val(const Node* h, int k) {
    while (k-- > 0 && h) h = h->next;
    return h ? h->val : -1;
}
/* 23. modulo hash */
__declspec(dllexport) unsigned hash_mod(const char* s, unsigned m) {
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h % m;
}
/* 24. saturating add */
__declspec(dllexport) int sat_add(int a, int b) {
    long long s = (long long)a + b;
    if (s > 2147483647LL) return 2147483647;
    if (s < -2147483648LL) return (-2147483647 - 1);
    return (int)s;
}
