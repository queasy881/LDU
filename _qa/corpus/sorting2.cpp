// sorting2.cpp - decompiler behavioral-test target
// More sorting / selection algorithms on (int* a, int n).
// Build: cl /LD /Od /W3 sorting2.cpp
#include <stdint.h>

// ---- small helpers (exported too) -------------------------------------

extern "C" __declspec(dllexport) void swap_ints(int* a, int i, int j)
{
    if (a == 0) return;
    if (i == j) return;
    int t = a[i];
    a[i] = a[j];
    a[j] = t;
}

extern "C" __declspec(dllexport) int int_min(int x, int y)
{
    if (x < y) return x;
    return y;
}

extern "C" __declspec(dllexport) int int_max(int x, int y)
{
    if (x > y) return x;
    return y;
}

extern "C" __declspec(dllexport) int array_min_index(const int* a, int n)
{
    if (a == 0 || n <= 0) return -1;
    int best = 0;
    for (int i = 1; i < n; ++i) {
        if (a[i] < a[best]) {
            best = i;
        }
    }
    return best;
}

extern "C" __declspec(dllexport) int array_max_value(const int* a, int n)
{
    if (a == 0 || n <= 0) return 0;
    int m = a[0];
    int i = 1;
    while (i < n) {
        if (a[i] > m) m = a[i];
        ++i;
    }
    return m;
}

extern "C" __declspec(dllexport) int is_sorted_asc(const int* a, int n)
{
    if (a == 0 || n < 2) return 1;
    for (int i = 1; i < n; ++i) {
        if (a[i - 1] > a[i]) return 0;
    }
    return 1;
}

// ---- quicksort partition (Lomuto) -------------------------------------

extern "C" __declspec(dllexport) int quicksort_partition(int* a, int lo, int hi)
{
    if (a == 0 || lo >= hi) return lo;
    int pivot = a[hi];
    int i = lo - 1;
    for (int j = lo; j < hi; ++j) {
        if (a[j] <= pivot) {
            ++i;
            swap_ints(a, i, j);
        }
    }
    swap_ints(a, i + 1, hi);
    return i + 1;
}

extern "C" __declspec(dllexport) void quicksort_range(int* a, int lo, int hi)
{
    if (a == 0 || lo >= hi) return;
    int p = quicksort_partition(a, lo, hi);
    quicksort_range(a, lo, p - 1);
    quicksort_range(a, p + 1, hi);
}

extern "C" __declspec(dllexport) void quicksort_full(int* a, int n)
{
    if (a == 0 || n < 2) return;
    quicksort_range(a, 0, n - 1);
}

// ---- shell sort -------------------------------------------------------

extern "C" __declspec(dllexport) void shell_sort(int* a, int n)
{
    if (a == 0 || n < 2) return;
    int gap = n / 2;
    while (gap > 0) {
        for (int i = gap; i < n; ++i) {
            int tmp = a[i];
            int j = i;
            while (j >= gap && a[j - gap] > tmp) {
                a[j] = a[j - gap];
                j -= gap;
            }
            a[j] = tmp;
        }
        gap /= 2;
    }
}

// ---- counting sort for small non-negative ranges ----------------------

extern "C" __declspec(dllexport) int counting_sort_small(int* a, int n, int maxv)
{
    if (a == 0 || n <= 0) return 0;
    if (maxv < 0 || maxv > 255) return -1;
    int counts[256];
    for (int i = 0; i <= maxv; ++i) counts[i] = 0;
    for (int i = 0; i < n; ++i) {
        int v = a[i];
        if (v < 0 || v > maxv) return -1;
        counts[v] += 1;
    }
    int pos = 0;
    for (int v = 0; v <= maxv; ++v) {
        int c = counts[v];
        for (int k = 0; k < c; ++k) {
            a[pos] = v;
            ++pos;
        }
    }
    return pos;
}

// ---- merge two sorted halves into out ---------------------------------

extern "C" __declspec(dllexport) int merge_two(const int* a, int la,
                                               const int* b, int lb,
                                               int* out)
{
    if (out == 0) return 0;
    int i = 0, j = 0, k = 0;
    if (a == 0) la = 0;
    if (b == 0) lb = 0;
    while (i < la && j < lb) {
        if (a[i] <= b[j]) {
            out[k++] = a[i++];
        } else {
            out[k++] = b[j++];
        }
    }
    while (i < la) out[k++] = a[i++];
    while (j < lb) out[k++] = b[j++];
    return k;
}

extern "C" __declspec(dllexport) void merge_sort_buf(int* a, int n, int* buf)
{
    if (a == 0 || buf == 0 || n < 2) return;
    int mid = n / 2;
    merge_sort_buf(a, mid, buf);
    merge_sort_buf(a + mid, n - mid, buf);
    int total = merge_two(a, mid, a + mid, n - mid, buf);
    for (int i = 0; i < total; ++i) {
        a[i] = buf[i];
    }
}

// ---- heap operations --------------------------------------------------

extern "C" __declspec(dllexport) void heap_sift_down(int* a, int n, int i)
{
    if (a == 0 || n <= 0) return;
    for (;;) {
        int largest = i;
        int l = 2 * i + 1;
        int r = 2 * i + 2;
        if (l < n && a[l] > a[largest]) largest = l;
        if (r < n && a[r] > a[largest]) largest = r;
        if (largest == i) break;
        swap_ints(a, i, largest);
        i = largest;
    }
}

extern "C" __declspec(dllexport) int is_heap(const int* a, int n)
{
    if (a == 0 || n < 2) return 1;
    for (int i = 0; i < n; ++i) {
        int l = 2 * i + 1;
        int r = 2 * i + 2;
        if (l < n && a[l] > a[i]) return 0;
        if (r < n && a[r] > a[i]) return 0;
    }
    return 1;
}

extern "C" __declspec(dllexport) void build_max_heap(int* a, int n)
{
    if (a == 0 || n < 2) return;
    for (int i = n / 2 - 1; i >= 0; --i) {
        heap_sift_down(a, n, i);
    }
}

extern "C" __declspec(dllexport) void heap_sort(int* a, int n)
{
    if (a == 0 || n < 2) return;
    build_max_heap(a, n);
    for (int end = n - 1; end > 0; --end) {
        swap_ints(a, 0, end);
        heap_sift_down(a, end, 0);
    }
}

// ---- partial selection: kth smallest (quickselect) --------------------

extern "C" __declspec(dllexport) int kth_smallest_partial(int* a, int n, int k)
{
    if (a == 0 || n <= 0) return 0;
    if (k < 0) k = 0;
    if (k >= n) k = n - 1;
    int lo = 0;
    int hi = n - 1;
    while (lo < hi) {
        int p = quicksort_partition(a, lo, hi);
        if (p == k) {
            return a[p];
        } else if (p < k) {
            lo = p + 1;
        } else {
            hi = p - 1;
        }
    }
    return a[k];
}

// ---- Dutch national flag partition around a pivot value ---------------
// Rearranges so values < pivot, == pivot, > pivot. Writes lt/gt boundaries.

extern "C" __declspec(dllexport) void dutch_flag_partition(int* a, int n,
                                                           int pivot,
                                                           int* lt_out,
                                                           int* gt_out)
{
    if (a == 0 || n <= 0) {
        if (lt_out) *lt_out = 0;
        if (gt_out) *gt_out = 0;
        return;
    }
    int lt = 0;
    int gt = n - 1;
    int i = 0;
    while (i <= gt) {
        if (a[i] < pivot) {
            swap_ints(a, lt, i);
            ++lt;
            ++i;
        } else if (a[i] > pivot) {
            swap_ints(a, i, gt);
            --gt;
        } else {
            ++i;
        }
    }
    if (lt_out) *lt_out = lt;
    if (gt_out) *gt_out = gt;
}

// ---- gnome sort -------------------------------------------------------

extern "C" __declspec(dllexport) void gnome_sort(int* a, int n)
{
    if (a == 0 || n < 2) return;
    int pos = 0;
    while (pos < n) {
        if (pos == 0 || a[pos] >= a[pos - 1]) {
            ++pos;
        } else {
            swap_ints(a, pos, pos - 1);
            --pos;
        }
    }
}

// ---- comb sort --------------------------------------------------------

extern "C" __declspec(dllexport) void comb_sort(int* a, int n)
{
    if (a == 0 || n < 2) return;
    int gap = n;
    int swapped = 1;
    while (gap > 1 || swapped) {
        gap = (gap * 10) / 13;
        if (gap < 1) gap = 1;
        swapped = 0;
        for (int i = 0; i + gap < n; ++i) {
            if (a[i] > a[i + gap]) {
                swap_ints(a, i, i + gap);
                swapped = 1;
            }
        }
    }
}

// ---- a couple of extra exercises for control-flow diversity -----------

extern "C" __declspec(dllexport) int classify_run_length(const int* a, int n)
{
    // returns length of the longest non-decreasing run
    if (a == 0 || n <= 0) return 0;
    int best = 1;
    int cur = 1;
    for (int i = 1; i < n; ++i) {
        if (a[i] >= a[i - 1]) {
            ++cur;
            if (cur > best) best = cur;
        } else {
            cur = 1;
        }
    }
    return best;
}

extern "C" __declspec(dllexport) int select_bucket(int v, int n)
{
    // map a value into one of 4 buckets via switch on a derived key
    if (n <= 0) return -1;
    int key = ((v % 4) + 4) % 4;
    int r;
    switch (key) {
        case 0:  r = 0; break;
        case 1:  r = n / 4; break;
        case 2:  r = n / 2; break;
        case 3:  r = (3 * n) / 4; break;
        default: r = -1; break;
    }
    return r;
}

extern "C" __declspec(dllexport) int64_t checksum_array(const int* a, int n)
{
    if (a == 0 || n <= 0) return 0;
    int64_t sum = 0;
    int i = 0;
    do {
        int64_t v = (int64_t)a[i];
        sum += v * (int64_t)(i + 1);
        ++i;
    } while (i < n);
    return sum;
}

extern "C" __declspec(dllexport) uint32_t hash_order(const int* a, int n)
{
    uint32_t h = 2166136261u;
    if (a == 0) return h;
    for (int i = 0; i < n; ++i) {
        uint32_t v = (uint32_t)a[i];
        h ^= v;
        h *= 16777619u;
        h = (h << 7) | (h >> 25);
    }
    return h;
}

extern "C" __declspec(dllexport) int count_inversions(const int* a, int n)
{
    if (a == 0 || n < 2) return 0;
    int inv = 0;
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (a[i] > a[j]) ++inv;
        }
    }
    return inv;
}
