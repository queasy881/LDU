// matrix.cpp - row-major int matrix operations
// Decompiler behavioral-test target. Compile: cl /LD /Od matrix.cpp
#include <stdint.h>

typedef struct MatStat {
    int min_v;
    int max_v;
    int64_t sum;
    int count;
} MatStat;

typedef struct Mat3 {
    int e[9];
} Mat3;

// ---- basic accessors ----

extern "C" __declspec(dllexport) int mat_get(int* m, int rows, int cols, int r, int c)
{
    if (m == 0) {
        return 0;
    }
    if (r < 0 || c < 0 || r >= rows || c >= cols) {
        return 0;
    }
    return m[r * cols + c];
}

extern "C" __declspec(dllexport) int mat_set(int* m, int rows, int cols, int r, int c, int v)
{
    if (m == 0) {
        return -1;
    }
    if (r < 0 || c < 0 || r >= rows || c >= cols) {
        return -1;
    }
    m[r * cols + c] = v;
    return 0;
}

extern "C" __declspec(dllexport) int mat_index(int rows, int cols, int r, int c)
{
    (void)rows;
    if (r < 0 || c < 0) {
        return -1;
    }
    return r * cols + c;
}

extern "C" __declspec(dllexport) int mat_count(int rows, int cols)
{
    if (rows <= 0 || cols <= 0) {
        return 0;
    }
    return rows * cols;
}

// ---- transforms ----

extern "C" __declspec(dllexport) int transpose_square(int* m, int n)
{
    if (m == 0 || n <= 0) {
        return -1;
    }
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            int a = m[i * n + j];
            int b = m[j * n + i];
            m[i * n + j] = b;
            m[j * n + i] = a;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int transpose_into(int* src, int* dst, int rows, int cols)
{
    if (src == 0 || dst == 0) {
        return -1;
    }
    int r = 0;
    while (r < rows) {
        int c = 0;
        while (c < cols) {
            dst[c * rows + r] = src[r * cols + c];
            ++c;
        }
        ++r;
    }
    return 0;
}

extern "C" __declspec(dllexport) int scale(int* m, int rows, int cols, int factor)
{
    if (m == 0) {
        return -1;
    }
    int total = rows * cols;
    if (total <= 0) {
        return -1;
    }
    int i = 0;
    do {
        m[i] = m[i] * factor;
        ++i;
    } while (i < total);
    return 0;
}

extern "C" __declspec(dllexport) int mat_add_into(int* a, int* b, int* out, int rows, int cols)
{
    if (a == 0 || b == 0 || out == 0) {
        return -1;
    }
    int total = rows * cols;
    for (int i = 0; i < total; ++i) {
        out[i] = a[i] + b[i];
    }
    return 0;
}

// ---- reductions ----

extern "C" __declspec(dllexport) int64_t mat_trace(int* m, int n)
{
    if (m == 0 || n <= 0) {
        return 0;
    }
    int64_t acc = 0;
    for (int i = 0; i < n; ++i) {
        acc += m[i * n + i];
    }
    return acc;
}

extern "C" __declspec(dllexport) int64_t diagonal_sum(int* m, int n, int anti)
{
    if (m == 0 || n <= 0) {
        return 0;
    }
    int64_t acc = 0;
    for (int i = 0; i < n; ++i) {
        if (anti != 0) {
            acc += m[i * n + (n - 1 - i)];
        } else {
            acc += m[i * n + i];
        }
    }
    return acc;
}

extern "C" __declspec(dllexport) int64_t row_sum(int* m, int rows, int cols, int r)
{
    if (m == 0 || r < 0 || r >= rows) {
        return 0;
    }
    int64_t acc = 0;
    int base = r * cols;
    for (int c = 0; c < cols; ++c) {
        acc += m[base + c];
    }
    return acc;
}

extern "C" __declspec(dllexport) int64_t col_sum(int* m, int rows, int cols, int c)
{
    if (m == 0 || c < 0 || c >= cols) {
        return 0;
    }
    int64_t acc = 0;
    for (int r = 0; r < rows; ++r) {
        acc += m[r * cols + c];
    }
    return acc;
}

extern "C" __declspec(dllexport) int64_t mat_total(int* m, int rows, int cols)
{
    if (m == 0) {
        return 0;
    }
    int total = rows * cols;
    int64_t acc = 0;
    for (int i = 0; i < total; ++i) {
        acc += m[i];
    }
    return acc;
}

extern "C" __declspec(dllexport) int mat_max(int* m, int rows, int cols)
{
    if (m == 0) {
        return 0;
    }
    int total = rows * cols;
    if (total <= 0) {
        return 0;
    }
    int best = m[0];
    for (int i = 1; i < total; ++i) {
        if (m[i] > best) {
            best = m[i];
        }
    }
    return best;
}

extern "C" __declspec(dllexport) int mat_min(int* m, int rows, int cols)
{
    if (m == 0) {
        return 0;
    }
    int total = rows * cols;
    if (total <= 0) {
        return 0;
    }
    int best = m[0];
    for (int i = 1; i < total; ++i) {
        if (m[i] < best) {
            best = m[i];
        }
    }
    return best;
}

extern "C" __declspec(dllexport) int mat_stat(int* m, int rows, int cols, MatStat* out)
{
    if (m == 0 || out == 0) {
        return -1;
    }
    int total = rows * cols;
    if (total <= 0) {
        out->min_v = 0;
        out->max_v = 0;
        out->sum = 0;
        out->count = 0;
        return -1;
    }
    int mn = m[0];
    int mx = m[0];
    int64_t s = 0;
    for (int i = 0; i < total; ++i) {
        int v = m[i];
        if (v < mn) {
            mn = v;
        }
        if (v > mx) {
            mx = v;
        }
        s += v;
    }
    out->min_v = mn;
    out->max_v = mx;
    out->sum = s;
    out->count = total;
    return 0;
}

extern "C" __declspec(dllexport) int mat_argmax(int* m, int rows, int cols)
{
    if (m == 0) {
        return -1;
    }
    int total = rows * cols;
    if (total <= 0) {
        return -1;
    }
    int idx = 0;
    int best = m[0];
    for (int i = 1; i < total; ++i) {
        if (m[i] > best) {
            best = m[i];
            idx = i;
        }
    }
    return idx;
}

// ---- predicates ----

extern "C" __declspec(dllexport) int is_symmetric(int* m, int n)
{
    if (m == 0 || n <= 0) {
        return 0;
    }
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (m[i * n + j] != m[j * n + i]) {
                return 0;
            }
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int mat_eq(int* a, int* b, int rows, int cols)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    int total = rows * cols;
    for (int i = 0; i < total; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int is_identity(int* m, int n)
{
    if (m == 0 || n <= 0) {
        return 0;
    }
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            int want = (i == j) ? 1 : 0;
            if (m[i * n + j] != want) {
                return 0;
            }
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int is_zero(int* m, int rows, int cols)
{
    if (m == 0) {
        return 0;
    }
    int total = rows * cols;
    for (int i = 0; i < total; ++i) {
        if (m[i] != 0) {
            return 0;
        }
    }
    return 1;
}

// ---- fillers ----

extern "C" __declspec(dllexport) int identity_fill(int* m, int n)
{
    if (m == 0 || n <= 0) {
        return -1;
    }
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            m[i * n + j] = (i == j) ? 1 : 0;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int fill_const(int* m, int rows, int cols, int v)
{
    if (m == 0) {
        return -1;
    }
    int total = rows * cols;
    for (int i = 0; i < total; ++i) {
        m[i] = v;
    }
    return 0;
}

extern "C" __declspec(dllexport) int fill_ramp(int* m, int rows, int cols, int start, int step)
{
    if (m == 0) {
        return -1;
    }
    int total = rows * cols;
    int cur = start;
    for (int i = 0; i < total; ++i) {
        m[i] = cur;
        cur += step;
    }
    return 0;
}

// ---- multiplication ----

extern "C" __declspec(dllexport) int mat_mul_3x3(Mat3* a, Mat3* b, Mat3* out)
{
    if (a == 0 || b == 0 || out == 0) {
        return -1;
    }
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 3; ++j) {
            int acc = 0;
            for (int k = 0; k < 3; ++k) {
                acc += a->e[i * 3 + k] * b->e[k * 3 + j];
            }
            out->e[i * 3 + j] = acc;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int mat_mul(int* a, int* b, int* out, int n, int p, int q)
{
    if (a == 0 || b == 0 || out == 0) {
        return -1;
    }
    if (n <= 0 || p <= 0 || q <= 0) {
        return -1;
    }
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < q; ++j) {
            int64_t acc = 0;
            for (int k = 0; k < p; ++k) {
                acc += (int64_t)a[i * p + k] * (int64_t)b[k * q + j];
            }
            out[i * q + j] = (int)acc;
        }
    }
    return 0;
}

// ---- misc utility ----

extern "C" __declspec(dllexport) int swap_rows(int* m, int rows, int cols, int r1, int r2)
{
    if (m == 0) {
        return -1;
    }
    if (r1 < 0 || r2 < 0 || r1 >= rows || r2 >= rows) {
        return -1;
    }
    if (r1 == r2) {
        return 0;
    }
    for (int c = 0; c < cols; ++c) {
        int t = m[r1 * cols + c];
        m[r1 * cols + c] = m[r2 * cols + c];
        m[r2 * cols + c] = t;
    }
    return 0;
}

extern "C" __declspec(dllexport) int count_nonzero(int* m, int rows, int cols)
{
    if (m == 0) {
        return 0;
    }
    int total = rows * cols;
    int n = 0;
    for (int i = 0; i < total; ++i) {
        if (m[i] != 0) {
            ++n;
        }
    }
    return n;
}

extern "C" __declspec(dllexport) int64_t det_recursive(int* m, int n)
{
    if (m == 0 || n <= 0) {
        return 0;
    }
    if (n == 1) {
        return m[0];
    }
    if (n == 2) {
        return (int64_t)m[0] * m[3] - (int64_t)m[1] * m[2];
    }
    // expand along first row for n==3 only (bounded recursion target)
    if (n == 3) {
        int64_t d = 0;
        int sub2[4];
        for (int col = 0; col < 3; ++col) {
            int si = 0;
            for (int r = 1; r < 3; ++r) {
                for (int c = 0; c < 3; ++c) {
                    if (c == col) {
                        continue;
                    }
                    sub2[si++] = m[r * 3 + c];
                }
            }
            int64_t minor = det_recursive(sub2, 2);
            int64_t term = (int64_t)m[col] * minor;
            if (col % 2 == 0) {
                d += term;
            } else {
                d -= term;
            }
        }
        return d;
    }
    return 0;
}

extern "C" __declspec(dllexport) int classify_cell(int* m, int rows, int cols, int r, int c)
{
    if (m == 0 || r < 0 || c < 0 || r >= rows || c >= cols) {
        return -1;
    }
    int v = m[r * cols + c];
    switch (v > 0 ? 1 : (v < 0 ? 2 : 0)) {
        case 0:
            return 0;
        case 1:
            return (v > 100) ? 11 : 10;
        case 2:
            return (v < -100) ? 21 : 20;
        default:
            return -1;
    }
}
