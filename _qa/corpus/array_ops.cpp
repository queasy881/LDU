#include <stdint.h>

/* Array / buffer processing test corpus.
 * All functions are pure: they compute from parameters and either
 * return a value or write through an output pointer. No libc, no STL.
 */

extern "C" __declspec(dllexport) int arr_sum(const int* a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += a[i];
    }
    return s;
}

extern "C" __declspec(dllexport) int arr_max(const int* a, int n) {
    if (n <= 0) {
        return 0;
    }
    int m = a[0];
    for (int i = 1; i < n; i++) {
        if (a[i] > m) {
            m = a[i];
        }
    }
    return m;
}

extern "C" __declspec(dllexport) int arr_min(const int* a, int n) {
    if (n <= 0) {
        return 0;
    }
    int m = a[0];
    for (int i = 1; i < n; i++) {
        if (a[i] < m) {
            m = a[i];
        }
    }
    return m;
}

extern "C" __declspec(dllexport) double arr_avg(const int* a, int n) {
    if (n <= 0) {
        return 0.0;
    }
    int64_t s = 0;
    for (int i = 0; i < n; i++) {
        s += a[i];
    }
    return (double)s / (double)n;
}

extern "C" __declspec(dllexport) void arr_reverse(int* a, int n) {
    int i = 0;
    int j = n - 1;
    while (i < j) {
        int t = a[i];
        a[i] = a[j];
        a[j] = t;
        i++;
        j--;
    }
}

extern "C" __declspec(dllexport) int arr_contains(const int* a, int n, int key) {
    for (int i = 0; i < n; i++) {
        if (a[i] == key) {
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int index_of(const int* a, int n, int key) {
    for (int i = 0; i < n; i++) {
        if (a[i] == key) {
            return i;
        }
    }
    return -1;
}

extern "C" __declspec(dllexport) int count_eq(const int* a, int n, int key) {
    int c = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] == key) {
            c++;
        }
    }
    return c;
}

extern "C" __declspec(dllexport) int sum_even(const int* a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if ((a[i] & 1) == 0) {
            s += a[i];
        } else {
            continue;
        }
    }
    return s;
}

extern "C" __declspec(dllexport) int count_positive(const int* a, int n) {
    int c = 0;
    int i = 0;
    while (i < n) {
        if (a[i] > 0) {
            c++;
        }
        i++;
    }
    return c;
}

extern "C" __declspec(dllexport) void bubble_sort(int* a, int n) {
    for (int i = 0; i < n - 1; i++) {
        int swapped = 0;
        for (int j = 0; j < n - 1 - i; j++) {
            if (a[j] > a[j + 1]) {
                int t = a[j];
                a[j] = a[j + 1];
                a[j + 1] = t;
                swapped = 1;
            }
        }
        if (swapped == 0) {
            break;
        }
    }
}

extern "C" __declspec(dllexport) void selection_sort(int* a, int n) {
    for (int i = 0; i < n - 1; i++) {
        int mi = i;
        for (int j = i + 1; j < n; j++) {
            if (a[j] < a[mi]) {
                mi = j;
            }
        }
        if (mi != i) {
            int t = a[i];
            a[i] = a[mi];
            a[mi] = t;
        }
    }
}

extern "C" __declspec(dllexport) void insertion_sort(int* a, int n) {
    for (int i = 1; i < n; i++) {
        int key = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > key) {
            a[j + 1] = a[j];
            j--;
        }
        a[j + 1] = key;
    }
}

extern "C" __declspec(dllexport) int binary_search(const int* a, int n, int key) {
    int lo = 0;
    int hi = n - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (a[mid] == key) {
            return mid;
        } else if (a[mid] < key) {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return -1;
}

extern "C" __declspec(dllexport) int is_sorted(const int* a, int n) {
    for (int i = 1; i < n; i++) {
        if (a[i - 1] > a[i]) {
            return 0;
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int max_subarray(const int* a, int n) {
    if (n <= 0) {
        return 0;
    }
    int best = a[0];
    int cur = a[0];
    for (int i = 1; i < n; i++) {
        int ext = cur + a[i];
        if (a[i] > ext) {
            cur = a[i];
        } else {
            cur = ext;
        }
        if (cur > best) {
            best = cur;
        }
    }
    return best;
}

extern "C" __declspec(dllexport) void prefix_sum(const int* a, int n, int* out) {
    int run = 0;
    for (int i = 0; i < n; i++) {
        run += a[i];
        out[i] = run;
    }
}

extern "C" __declspec(dllexport) void rotate_left_k(int* a, int n, int k) {
    if (n <= 0) {
        return;
    }
    k = k % n;
    if (k < 0) {
        k += n;
    }
    for (int r = 0; r < k; r++) {
        int first = a[0];
        for (int i = 0; i < n - 1; i++) {
            a[i] = a[i + 1];
        }
        a[n - 1] = first;
    }
}

extern "C" __declspec(dllexport) int unique_count(const int* a, int n) {
    /* Assumes the input is sorted ascending. */
    if (n <= 0) {
        return 0;
    }
    int c = 1;
    for (int i = 1; i < n; i++) {
        if (a[i] != a[i - 1]) {
            c++;
        }
    }
    return c;
}

extern "C" __declspec(dllexport) int second_max(const int* a, int n) {
    if (n < 2) {
        return 0;
    }
    int first = a[0];
    int second = a[1];
    if (second > first) {
        int t = first;
        first = second;
        second = t;
    }
    for (int i = 2; i < n; i++) {
        if (a[i] > first) {
            second = first;
            first = a[i];
        } else if (a[i] > second) {
            second = a[i];
        }
    }
    return second;
}

extern "C" __declspec(dllexport) int partition_pivot(int* a, int n, int pivot) {
    int store = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] < pivot) {
            int t = a[i];
            a[i] = a[store];
            a[store] = t;
            store++;
        }
    }
    return store;
}

extern "C" __declspec(dllexport) int min_index(const int* a, int n) {
    if (n <= 0) {
        return -1;
    }
    int mi = 0;
    for (int i = 1; i < n; i++) {
        if (a[i] < a[mi]) {
            mi = i;
        }
    }
    return mi;
}

extern "C" __declspec(dllexport) void swap_ends(int* a, int n) {
    if (n < 2) {
        return;
    }
    int t = a[0];
    a[0] = a[n - 1];
    a[n - 1] = t;
}

extern "C" __declspec(dllexport) void running_max(const int* a, int n, int* out) {
    if (n <= 0) {
        return;
    }
    int m = a[0];
    out[0] = m;
    for (int i = 1; i < n; i++) {
        if (a[i] > m) {
            m = a[i];
        }
        out[i] = m;
    }
}

extern "C" __declspec(dllexport) int64_t dot_product(const int* a, const int* b, int n) {
    int64_t s = 0;
    for (int i = 0; i < n; i++) {
        s += (int64_t)a[i] * (int64_t)b[i];
    }
    return s;
}

extern "C" __declspec(dllexport) int is_palindrome_arr(const int* a, int n) {
    int i = 0;
    int j = n - 1;
    do {
        if (i >= j) {
            break;
        }
        if (a[i] != a[j]) {
            return 0;
        }
        i++;
        j--;
    } while (i < j);
    return 1;
}

extern "C" __declspec(dllexport) int range_span(const int* a, int n) {
    if (n <= 0) {
        return 0;
    }
    int lo = a[0];
    int hi = a[0];
    for (int i = 1; i < n; i++) {
        switch (a[i] > hi ? 1 : (a[i] < lo ? 2 : 0)) {
        case 1:
            hi = a[i];
            break;
        case 2:
            lo = a[i];
            break;
        default:
            break;
        }
    }
    return hi - lo;
}

extern "C" __declspec(dllexport) int count_runs(const int* a, int n) {
    if (n <= 0) {
        return 0;
    }
    int runs = 1;
    for (int i = 1; i < n; i++) {
        if (a[i] != a[i - 1]) {
            runs++;
        }
    }
    return runs;
}
