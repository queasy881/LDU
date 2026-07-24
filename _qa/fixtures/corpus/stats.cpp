/* stats.cpp - integer running stats over (const int* a, int n).
 * Decompiler behavioral-test target. Build: cl /LD /Od stats.cpp
 * Pure deterministic C-style functions, each exported with a clean name.
 */
#include <stdint.h>

/* ---- shared plain struct ---------------------------------------------- */
typedef struct StatSummary {
    int count;
    int sum;
    int minv;
    int maxv;
    int range;
} StatSummary;

typedef struct Bucket {
    int lo;
    int hi;
    int n;
} Bucket;

/* ---- 1. sum of all elements ------------------------------------------- */
extern "C" __declspec(dllexport) int isum(const int* a, int n)
{
    int s = 0;
    int i;
    if (a == 0 || n <= 0)
        return 0;
    for (i = 0; i < n; ++i)
        s += a[i];
    return s;
}

/* ---- 2. integer mean (truncating toward zero) ------------------------- */
extern "C" __declspec(dllexport) int imean(const int* a, int n)
{
    int s;
    if (a == 0 || n <= 0)
        return 0;
    s = isum(a, n);
    return s / n;
}

/* ---- 3. minimum -------------------------------------------------------- */
extern "C" __declspec(dllexport) int imin(const int* a, int n)
{
    int m;
    int i;
    if (a == 0 || n <= 0)
        return 0;
    m = a[0];
    for (i = 1; i < n; ++i) {
        if (a[i] < m)
            m = a[i];
    }
    return m;
}

/* ---- 4. maximum -------------------------------------------------------- */
extern "C" __declspec(dllexport) int imax(const int* a, int n)
{
    int m;
    int i;
    if (a == 0 || n <= 0)
        return 0;
    m = a[0];
    for (i = 1; i < n; ++i) {
        if (a[i] > m)
            m = a[i];
    }
    return m;
}

/* ---- 5. range (max - min) --------------------------------------------- */
extern "C" __declspec(dllexport) int irange(const int* a, int n)
{
    int lo;
    int hi;
    if (a == 0 || n <= 0)
        return 0;
    lo = imin(a, n);
    hi = imax(a, n);
    return hi - lo;
}

/* ---- 6. count elements strictly greater than threshold ---------------- */
extern "C" __declspec(dllexport) int count_above(const int* a, int n, int thr)
{
    int c = 0;
    int i = 0;
    if (a == 0 || n <= 0)
        return 0;
    while (i < n) {
        if (a[i] > thr)
            ++c;
        ++i;
    }
    return c;
}

/* ---- 7. count elements in inclusive range [lo, hi] -------------------- */
extern "C" __declspec(dllexport) int count_in_range(const int* a, int n,
                                                    int lo, int hi)
{
    int c = 0;
    int i;
    int t;
    if (a == 0 || n <= 0)
        return 0;
    if (lo > hi) {
        t = lo;
        lo = hi;
        hi = t;
    }
    for (i = 0; i < n; ++i) {
        if (a[i] < lo)
            continue;
        if (a[i] > hi)
            continue;
        ++c;
    }
    return c;
}

/* ---- 8. mode for small non-negative value domain [0,255] -------------- */
extern "C" __declspec(dllexport) int mode_small(const int* a, int n)
{
    int freq[256];
    int i;
    int v;
    int best;
    int bestcnt;
    if (a == 0 || n <= 0)
        return 0;
    for (i = 0; i < 256; ++i)
        freq[i] = 0;
    for (i = 0; i < n; ++i) {
        v = a[i];
        if (v < 0 || v > 255)
            continue;
        freq[v]++;
    }
    best = 0;
    bestcnt = -1;
    for (i = 0; i < 256; ++i) {
        if (freq[i] > bestcnt) {
            bestcnt = freq[i];
            best = i;
        }
    }
    return best;
}

/* ---- 9. median of three scalars (no array) ---------------------------- */
extern "C" __declspec(dllexport) int median_of3(int x, int y, int z)
{
    if (x > y) {
        if (y > z)
            return y;
        else if (x > z)
            return z;
        else
            return x;
    } else {
        if (x > z)
            return x;
        else if (y > z)
            return z;
        else
            return y;
    }
}

/* ---- 10. variance times n (integer numerator) ------------------------- */
/* returns sum((x-mean)^2) using integer mean, fits the "variance_x_n" idea */
extern "C" __declspec(dllexport) int64_t variance_x_n(const int* a, int n)
{
    int m;
    int i;
    int64_t acc = 0;
    int64_t d;
    if (a == 0 || n <= 0)
        return 0;
    m = imean(a, n);
    for (i = 0; i < n; ++i) {
        d = (int64_t)a[i] - (int64_t)m;
        acc += d * d;
    }
    return acc;
}

/* ---- 11. running maximum prefix into out[] ---------------------------- */
extern "C" __declspec(dllexport) void running_max_to(const int* a, int n,
                                                     int* out)
{
    int cur;
    int i;
    if (a == 0 || out == 0 || n <= 0)
        return;
    cur = a[0];
    out[0] = cur;
    for (i = 1; i < n; ++i) {
        if (a[i] > cur)
            cur = a[i];
        out[i] = cur;
    }
}

/* ---- 12. histogram bucket index for a value --------------------------- */
/* uniform buckets across [lo,hi); returns -1 if out of range or bad input */
extern "C" __declspec(dllexport) int histogram_bucket(int value, int lo,
                                                      int hi, int nbuckets)
{
    int span;
    int width;
    int idx;
    if (nbuckets <= 0 || hi <= lo)
        return -1;
    if (value < lo || value >= hi)
        return -1;
    span = hi - lo;
    width = span / nbuckets;
    if (width <= 0)
        width = 1;
    idx = (value - lo) / width;
    if (idx >= nbuckets)
        idx = nbuckets - 1;
    return idx;
}

/* ---- 13. fill a StatSummary in one pass ------------------------------- */
extern "C" __declspec(dllexport) int summarize(const int* a, int n,
                                               StatSummary* out)
{
    int i;
    int lo;
    int hi;
    int s;
    if (a == 0 || out == 0 || n <= 0)
        return 0;
    lo = a[0];
    hi = a[0];
    s = 0;
    for (i = 0; i < n; ++i) {
        if (a[i] < lo)
            lo = a[i];
        if (a[i] > hi)
            hi = a[i];
        s += a[i];
    }
    out->count = n;
    out->sum = s;
    out->minv = lo;
    out->maxv = hi;
    out->range = hi - lo;
    return 1;
}

/* ---- 14. count sign changes between consecutive elements -------------- */
extern "C" __declspec(dllexport) int sign_changes(const int* a, int n)
{
    int i;
    int c = 0;
    int prev;
    int cur;
    if (a == 0 || n < 2)
        return 0;
    prev = (a[0] > 0) - (a[0] < 0);
    for (i = 1; i < n; ++i) {
        cur = (a[i] > 0) - (a[i] < 0);
        if (cur != 0 && prev != 0 && cur != prev)
            ++c;
        if (cur != 0)
            prev = cur;
    }
    return c;
}

/* ---- 15. longest non-decreasing run length ---------------------------- */
extern "C" __declspec(dllexport) int longest_nondec_run(const int* a, int n)
{
    int best;
    int cur;
    int i;
    if (a == 0 || n <= 0)
        return 0;
    best = 1;
    cur = 1;
    for (i = 1; i < n; ++i) {
        if (a[i] >= a[i - 1]) {
            ++cur;
            if (cur > best)
                best = cur;
        } else {
            cur = 1;
        }
    }
    return best;
}

/* ---- 16. clamp every element into [lo,hi] writing out[] --------------- */
extern "C" __declspec(dllexport) void clamp_to(const int* a, int n, int lo,
                                               int hi, int* out)
{
    int i;
    int v;
    if (a == 0 || out == 0 || n <= 0)
        return;
    if (lo > hi)
        return;
    for (i = 0; i < n; ++i) {
        v = a[i];
        if (v < lo)
            v = lo;
        else if (v > hi)
            v = hi;
        out[i] = v;
    }
}

/* ---- 17. dot product of two int arrays (int64 accumulate) ------------- */
extern "C" __declspec(dllexport) int64_t idot(const int* a, const int* b,
                                              int n)
{
    int64_t acc = 0;
    int i;
    if (a == 0 || b == 0 || n <= 0)
        return 0;
    for (i = 0; i < n; ++i)
        acc += (int64_t)a[i] * (int64_t)b[i];
    return acc;
}

/* ---- 18. recursive integer gcd ---------------------------------------- */
extern "C" __declspec(dllexport) int igcd(int x, int y)
{
    if (x < 0)
        x = -x;
    if (y < 0)
        y = -y;
    if (y == 0)
        return x;
    return igcd(y, x % y);
}

/* ---- 19. fold gcd across an array (uses recursion) -------------------- */
extern "C" __declspec(dllexport) int array_gcd(const int* a, int n)
{
    int g;
    int i;
    if (a == 0 || n <= 0)
        return 0;
    g = a[0];
    for (i = 1; i < n; ++i) {
        g = igcd(g, a[i]);
        if (g == 1)
            break;
    }
    return g;
}

/* ---- 20. classify mean into a band via switch ------------------------- */
extern "C" __declspec(dllexport) int classify_mean(const int* a, int n)
{
    int m;
    int band;
    if (a == 0 || n <= 0)
        return -1;
    m = imean(a, n);
    if (m < 0)
        band = 0;
    else if (m < 10)
        band = 1;
    else if (m < 100)
        band = 2;
    else
        band = 3;
    switch (band) {
    case 0:
        return -1;
    case 1:
        return 10;
    case 2:
        return 20;
    case 3:
        return 30;
    default:
        return 0;
    }
}

/* ---- 21. number of strictly increasing adjacent pairs ----------------- */
extern "C" __declspec(dllexport) int count_ascents(const int* a, int n)
{
    int i = 1;
    int c = 0;
    if (a == 0 || n < 2)
        return 0;
    do {
        if (a[i] > a[i - 1])
            ++c;
        ++i;
    } while (i < n);
    return c;
}

/* ---- 22. prefix-sum scan into out[] ----------------------------------- */
extern "C" __declspec(dllexport) void prefix_sum_to(const int* a, int n,
                                                    int* out)
{
    int i;
    int acc = 0;
    if (a == 0 || out == 0 || n <= 0)
        return;
    for (i = 0; i < n; ++i) {
        acc += a[i];
        out[i] = acc;
    }
}

/* ---- 23. nested-loop count of equal unordered pairs ------------------- */
extern "C" __declspec(dllexport) int count_equal_pairs(const int* a, int n)
{
    int i;
    int j;
    int c = 0;
    if (a == 0 || n < 2)
        return 0;
    for (i = 0; i < n; ++i) {
        for (j = i + 1; j < n; ++j) {
            if (a[i] == a[j])
                ++c;
        }
    }
    return c;
}

/* ---- 24. fill uniform Bucket histogram counts ------------------------- */
extern "C" __declspec(dllexport) int fill_buckets(const int* a, int n, int lo,
                                                  int hi, Bucket* buckets,
                                                  int nbuckets)
{
    int i;
    int idx;
    int width;
    if (a == 0 || buckets == 0 || n <= 0 || nbuckets <= 0 || hi <= lo)
        return 0;
    width = (hi - lo) / nbuckets;
    if (width <= 0)
        width = 1;
    for (i = 0; i < nbuckets; ++i) {
        buckets[i].lo = lo + i * width;
        buckets[i].hi = lo + (i + 1) * width;
        buckets[i].n = 0;
    }
    for (i = 0; i < n; ++i) {
        if (a[i] < lo || a[i] >= hi)
            continue;
        idx = (a[i] - lo) / width;
        if (idx >= nbuckets)
            idx = nbuckets - 1;
        buckets[idx].n++;
    }
    return nbuckets;
}
