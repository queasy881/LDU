/* board.cpp - grid logic decompiler behavioral-test target.
 * Compile: cl /LD /Od /W3 board.cpp
 * Pure deterministic C-style functions over a flat int grid (const int* g, w, h).
 */
#include <stdint.h>

/* A simple plain struct used by several helpers. */
typedef struct GridStats {
    int min_value;
    int max_value;
    int64_t sum;
    int count;
} GridStats;

/* A coordinate stack entry for the iterative flood fill. */
typedef struct CellPos {
    int x;
    int y;
} CellPos;

/* ----- 1: cell_at ------------------------------------------------------- */
extern "C" __declspec(dllexport)
int cell_at(const int* g, int w, int h, int x, int y, int oob)
{
    if (g == 0) {
        return oob;
    }
    if (w <= 0 || h <= 0) {
        return oob;
    }
    if (x < 0 || y < 0 || x >= w || y >= h) {
        return oob;
    }
    return g[(int64_t)y * w + x];
}

/* ----- 2: in_bounds ----------------------------------------------------- */
extern "C" __declspec(dllexport)
int in_bounds(int w, int h, int x, int y)
{
    if (x < 0 || y < 0) {
        return 0;
    }
    if (x >= w || y >= h) {
        return 0;
    }
    return 1;
}

/* ----- 3: count_neighbors_eq -------------------------------------------- */
extern "C" __declspec(dllexport)
int count_neighbors_eq(const int* g, int w, int h, int x, int y, int value)
{
    int dx;
    int dy;
    int total = 0;
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    for (dy = -1; dy <= 1; dy++) {
        for (dx = -1; dx <= 1; dx++) {
            if (dx == 0 && dy == 0) {
                continue;
            }
            int nx = x + dx;
            int ny = y + dy;
            if (nx < 0 || ny < 0 || nx >= w || ny >= h) {
                continue;
            }
            if (g[(int64_t)ny * w + nx] == value) {
                total++;
            }
        }
    }
    return total;
}

/* ----- 4: count_value --------------------------------------------------- */
extern "C" __declspec(dllexport)
int count_value(const int* g, int w, int h, int value)
{
    int total = 0;
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    int64_t n = (int64_t)w * h;
    for (int64_t i = 0; i < n; i++) {
        if (g[i] == value) {
            total++;
        }
    }
    return total;
}

/* ----- 5: ttt_line_winner (3x3) ----------------------------------------- */
extern "C" __declspec(dllexport)
int ttt_line_winner(const int* g)
{
    if (g == 0) {
        return 0;
    }
    int lines[8][3] = {
        { 0, 1, 2 }, { 3, 4, 5 }, { 6, 7, 8 },
        { 0, 3, 6 }, { 1, 4, 7 }, { 2, 5, 8 },
        { 0, 4, 8 }, { 2, 4, 6 }
    };
    for (int i = 0; i < 8; i++) {
        int a = g[lines[i][0]];
        int b = g[lines[i][1]];
        int c = g[lines[i][2]];
        if (a != 0 && a == b && b == c) {
            return a;
        }
    }
    return 0;
}

/* ----- 6: row_all_equal ------------------------------------------------- */
extern "C" __declspec(dllexport)
int row_all_equal(const int* g, int w, int h, int row)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    if (row < 0 || row >= h) {
        return 0;
    }
    const int* r = g + (int64_t)row * w;
    int first = r[0];
    int x = 1;
    while (x < w) {
        if (r[x] != first) {
            return 0;
        }
        x++;
    }
    return 1;
}

/* ----- 7: col_all_equal ------------------------------------------------- */
extern "C" __declspec(dllexport)
int col_all_equal(const int* g, int w, int h, int col)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    if (col < 0 || col >= w) {
        return 0;
    }
    int first = g[col];
    int y = 1;
    do {
        if (y >= h) {
            break;
        }
        if (g[(int64_t)y * w + col] != first) {
            return 0;
        }
        y++;
    } while (y < h);
    return 1;
}

/* ----- 8: has_adjacent_pair --------------------------------------------- */
extern "C" __declspec(dllexport)
int has_adjacent_pair(const int* g, int w, int h)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            int v = g[(int64_t)y * w + x];
            if (x + 1 < w && g[(int64_t)y * w + (x + 1)] == v) {
                return 1;
            }
            if (y + 1 < h && g[(int64_t)(y + 1) * w + x] == v) {
                return 1;
            }
        }
    }
    return 0;
}

/* ----- 9: border_sum ---------------------------------------------------- */
extern "C" __declspec(dllexport)
int64_t border_sum(const int* g, int w, int h)
{
    int64_t total = 0;
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    for (int x = 0; x < w; x++) {
        total += g[x];
        if (h > 1) {
            total += g[(int64_t)(h - 1) * w + x];
        }
    }
    for (int y = 1; y < h - 1; y++) {
        total += g[(int64_t)y * w];
        if (w > 1) {
            total += g[(int64_t)y * w + (w - 1)];
        }
    }
    return total;
}

/* ----- 10: diagonal_winner (square grid) -------------------------------- */
extern "C" __declspec(dllexport)
int diagonal_winner(const int* g, int n)
{
    if (g == 0 || n <= 0) {
        return 0;
    }
    int main_ok = 1;
    int anti_ok = 1;
    int main_v = g[0];
    int anti_v = g[n - 1];
    for (int i = 0; i < n; i++) {
        if (g[(int64_t)i * n + i] != main_v || main_v == 0) {
            main_ok = 0;
        }
        if (g[(int64_t)i * n + (n - 1 - i)] != anti_v || anti_v == 0) {
            anti_ok = 0;
        }
    }
    if (main_ok) {
        return main_v;
    }
    if (anti_ok) {
        return anti_v;
    }
    return 0;
}

/* ----- 11: max_run_in_row ----------------------------------------------- */
extern "C" __declspec(dllexport)
int max_run_in_row(const int* g, int w, int h, int row)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    if (row < 0 || row >= h) {
        return 0;
    }
    const int* r = g + (int64_t)row * w;
    int best = 1;
    int run = 1;
    for (int x = 1; x < w; x++) {
        if (r[x] == r[x - 1]) {
            run++;
            if (run > best) {
                best = run;
            }
        } else {
            run = 1;
        }
    }
    return best;
}

/* ----- 12: flood_fill_count_iter ---------------------------------------- */
extern "C" __declspec(dllexport)
int flood_fill_count_iter(const int* g, int w, int h, int sx, int sy,
                          int* visited, int cap)
{
    if (g == 0 || visited == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    if (sx < 0 || sy < 0 || sx >= w || sy >= h) {
        return 0;
    }
    int64_t total = (int64_t)w * h;
    if (cap < total) {
        return 0;
    }
    int target = g[(int64_t)sy * w + sx];
    for (int64_t i = 0; i < total; i++) {
        visited[i] = 0;
    }
    CellPos stack[4096];
    int top = 0;
    int count = 0;
    int stack_cap = 4096;
    stack[top].x = sx;
    stack[top].y = sy;
    top++;
    while (top > 0) {
        top--;
        int cx = stack[top].x;
        int cy = stack[top].y;
        int64_t idx = (int64_t)cy * w + cx;
        if (visited[idx]) {
            continue;
        }
        if (g[idx] != target) {
            continue;
        }
        visited[idx] = 1;
        count++;
        int ndx[4] = { 1, -1, 0, 0 };
        int ndy[4] = { 0, 0, 1, -1 };
        for (int k = 0; k < 4; k++) {
            int nx = cx + ndx[k];
            int ny = cy + ndy[k];
            if (nx < 0 || ny < 0 || nx >= w || ny >= h) {
                continue;
            }
            int64_t nidx = (int64_t)ny * w + nx;
            if (!visited[nidx] && g[nidx] == target && top < stack_cap) {
                stack[top].x = nx;
                stack[top].y = ny;
                top++;
            }
        }
    }
    return count;
}

/* ----- 13: grid_collect_stats ------------------------------------------- */
extern "C" __declspec(dllexport)
int grid_collect_stats(const int* g, int w, int h, GridStats* out)
{
    if (g == 0 || out == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    int64_t n = (int64_t)w * h;
    out->min_value = g[0];
    out->max_value = g[0];
    out->sum = 0;
    out->count = 0;
    for (int64_t i = 0; i < n; i++) {
        int v = g[i];
        if (v < out->min_value) {
            out->min_value = v;
        }
        if (v > out->max_value) {
            out->max_value = v;
        }
        out->sum += v;
        out->count++;
    }
    return 1;
}

/* ----- 14: is_symmetric_h ----------------------------------------------- */
extern "C" __declspec(dllexport)
int is_symmetric_h(const int* g, int w, int h)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w / 2; x++) {
            int left = g[(int64_t)y * w + x];
            int right = g[(int64_t)y * w + (w - 1 - x)];
            if (left != right) {
                return 0;
            }
        }
    }
    return 1;
}

/* ----- 15: transpose_into ----------------------------------------------- */
extern "C" __declspec(dllexport)
int transpose_into(const int* g, int w, int h, int* dst, int cap)
{
    if (g == 0 || dst == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    if (cap < (int64_t)w * h) {
        return 0;
    }
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            dst[(int64_t)x * h + y] = g[(int64_t)y * w + x];
        }
    }
    return 1;
}

/* ----- 16: row_sum ------------------------------------------------------ */
extern "C" __declspec(dllexport)
int64_t row_sum(const int* g, int w, int h, int row)
{
    if (g == 0 || w <= 0 || h <= 0 || row < 0 || row >= h) {
        return 0;
    }
    const int* r = g + (int64_t)row * w;
    int64_t s = 0;
    for (int x = 0; x < w; x++) {
        s += r[x];
    }
    return s;
}

/* ----- 17: col_sum ------------------------------------------------------ */
extern "C" __declspec(dllexport)
int64_t col_sum(const int* g, int w, int h, int col)
{
    if (g == 0 || w <= 0 || h <= 0 || col < 0 || col >= w) {
        return 0;
    }
    int64_t s = 0;
    int y = 0;
    while (y < h) {
        s += g[(int64_t)y * w + col];
        y++;
    }
    return s;
}

/* ----- 18: find_first_value --------------------------------------------- */
extern "C" __declspec(dllexport)
int find_first_value(const int* g, int w, int h, int value, int* ox, int* oy)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            if (g[(int64_t)y * w + x] == value) {
                if (ox != 0) {
                    *ox = x;
                }
                if (oy != 0) {
                    *oy = y;
                }
                return 1;
            }
        }
    }
    return 0;
}

/* ----- 19: manhattan_ring_count ----------------------------------------- */
extern "C" __declspec(dllexport)
int manhattan_ring_count(const int* g, int w, int h, int cx, int cy, int radius)
{
    if (g == 0 || w <= 0 || h <= 0 || radius < 0) {
        return 0;
    }
    int total = 0;
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            int dx = x - cx;
            int dy = y - cy;
            if (dx < 0) {
                dx = -dx;
            }
            if (dy < 0) {
                dy = -dy;
            }
            if (dx + dy == radius) {
                total += g[(int64_t)y * w + x];
            }
        }
    }
    return total;
}

/* ----- 20: gcd_of_grid -------------------------------------------------- */
extern "C" __declspec(dllexport)
int gcd_of_grid(const int* g, int w, int h)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    int64_t n = (int64_t)w * h;
    int acc = 0;
    for (int64_t i = 0; i < n; i++) {
        int v = g[i];
        if (v < 0) {
            v = -v;
        }
        int a = acc;
        int b = v;
        while (b != 0) {
            int t = a % b;
            a = b;
            b = t;
        }
        acc = a;
    }
    return acc;
}

/* ----- 21: count_distinct_small ----------------------------------------- */
extern "C" __declspec(dllexport)
int count_distinct_small(const int* g, int w, int h, int lo, int hi)
{
    if (g == 0 || w <= 0 || h <= 0 || hi < lo) {
        return 0;
    }
    int range = hi - lo + 1;
    if (range <= 0 || range > 1024) {
        return 0;
    }
    int seen[1024];
    for (int i = 0; i < range; i++) {
        seen[i] = 0;
    }
    int64_t n = (int64_t)w * h;
    for (int64_t i = 0; i < n; i++) {
        int v = g[i];
        if (v >= lo && v <= hi) {
            seen[v - lo] = 1;
        }
    }
    int distinct = 0;
    for (int i = 0; i < range; i++) {
        distinct += seen[i];
    }
    return distinct;
}

/* ----- 22: count_region_size_recursive ---------------------------------- */
static int region_helper(const int* g, int w, int h, int x, int y,
                         int target, int* visited)
{
    if (x < 0 || y < 0 || x >= w || y >= h) {
        return 0;
    }
    int64_t idx = (int64_t)y * w + x;
    if (visited[idx]) {
        return 0;
    }
    if (g[idx] != target) {
        return 0;
    }
    visited[idx] = 1;
    int sub = 1;
    sub += region_helper(g, w, h, x + 1, y, target, visited);
    sub += region_helper(g, w, h, x - 1, y, target, visited);
    sub += region_helper(g, w, h, x, y + 1, target, visited);
    sub += region_helper(g, w, h, x, y - 1, target, visited);
    return sub;
}

extern "C" __declspec(dllexport)
int count_region_size_recursive(const int* g, int w, int h, int sx, int sy,
                                int* visited, int cap)
{
    if (g == 0 || visited == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    if (sx < 0 || sy < 0 || sx >= w || sy >= h) {
        return 0;
    }
    int64_t n = (int64_t)w * h;
    if (cap < n) {
        return 0;
    }
    for (int64_t i = 0; i < n; i++) {
        visited[i] = 0;
    }
    int target = g[(int64_t)sy * w + sx];
    return region_helper(g, w, h, sx, sy, target, visited);
}

/* ----- 23: checkerboard_score ------------------------------------------- */
extern "C" __declspec(dllexport)
int checkerboard_score(const int* g, int w, int h)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    int score = 0;
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            int v = g[(int64_t)y * w + x];
            int parity = (x + y) & 1;
            switch (parity) {
                case 0:
                    score += v;
                    break;
                case 1:
                    score -= v;
                    break;
                default:
                    break;
            }
        }
    }
    return score;
}

/* ----- 24: longest_equal_diagonal --------------------------------------- */
extern "C" __declspec(dllexport)
int longest_equal_diagonal(const int* g, int w, int h)
{
    if (g == 0 || w <= 0 || h <= 0) {
        return 0;
    }
    int best = 1;
    for (int sy = 0; sy < h; sy++) {
        for (int sx = 0; sx < w; sx++) {
            int run = 1;
            int x = sx + 1;
            int y = sy + 1;
            while (x < w && y < h) {
                int prev = g[(int64_t)(y - 1) * w + (x - 1)];
                int cur = g[(int64_t)y * w + x];
                if (cur == prev) {
                    run++;
                    if (run > best) {
                        best = run;
                    }
                } else {
                    break;
                }
                x++;
                y++;
            }
        }
    }
    return best;
}
