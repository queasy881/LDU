/* ringbuf.cpp - circular buffer decompiler behavioral-test target.
 * Build: cl /LD /Od /W3 ringbuf.cpp
 * Pure deterministic C-style functions; no libc, no globals, no I/O.
 */
#include <stdint.h>

#define RING_CAP 64

typedef struct Ring {
    int buf[RING_CAP];
    int head;
    int tail;
    int count;
} Ring;

/* ---- core lifecycle ---- */

extern "C" __declspec(dllexport) void ring_init(Ring *r)
{
    int i;
    if (r == 0) {
        return;
    }
    for (i = 0; i < RING_CAP; ++i) {
        r->buf[i] = 0;
    }
    r->head = 0;
    r->tail = 0;
    r->count = 0;
}

extern "C" __declspec(dllexport) int ring_is_full(const Ring *r)
{
    if (r == 0) {
        return 0;
    }
    return r->count >= RING_CAP ? 1 : 0;
}

extern "C" __declspec(dllexport) int ring_is_empty(const Ring *r)
{
    if (r == 0) {
        return 1;
    }
    return r->count == 0 ? 1 : 0;
}

extern "C" __declspec(dllexport) int ring_size(const Ring *r)
{
    if (r == 0) {
        return 0;
    }
    return r->count;
}

extern "C" __declspec(dllexport) void ring_clear(Ring *r)
{
    if (r == 0) {
        return;
    }
    r->head = 0;
    r->tail = 0;
    r->count = 0;
}

/* ---- push / pop / peek ---- */

extern "C" __declspec(dllexport) int ring_push(Ring *r, int value)
{
    if (r == 0) {
        return -1;
    }
    if (r->count >= RING_CAP) {
        return 0;
    }
    r->buf[r->tail] = value;
    r->tail = (r->tail + 1) % RING_CAP;
    r->count = r->count + 1;
    return 1;
}

extern "C" __declspec(dllexport) int ring_pop(Ring *r, int *out)
{
    int v;
    if (r == 0) {
        return -1;
    }
    if (r->count <= 0) {
        return 0;
    }
    v = r->buf[r->head];
    r->head = (r->head + 1) % RING_CAP;
    r->count = r->count - 1;
    if (out != 0) {
        *out = v;
    }
    return 1;
}

extern "C" __declspec(dllexport) int ring_peek(const Ring *r, int *out)
{
    if (r == 0) {
        return -1;
    }
    if (r->count <= 0) {
        return 0;
    }
    if (out != 0) {
        *out = r->buf[r->head];
    }
    return 1;
}

extern "C" __declspec(dllexport) int ring_at(const Ring *r, int index, int *out)
{
    int pos;
    if (r == 0) {
        return -1;
    }
    if (index < 0 || index >= r->count) {
        return 0;
    }
    pos = (r->head + index) % RING_CAP;
    if (out != 0) {
        *out = r->buf[pos];
    }
    return 1;
}

extern "C" __declspec(dllexport) int64_t ring_sum(const Ring *r)
{
    int i;
    int pos;
    int64_t total;
    if (r == 0) {
        return 0;
    }
    total = 0;
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        total += (int64_t)r->buf[pos];
    }
    return total;
}

/* ---- bulk operations ---- */

extern "C" __declspec(dllexport) int ring_push_many(Ring *r, const int *src, int n)
{
    int pushed;
    int i;
    if (r == 0 || src == 0) {
        return -1;
    }
    pushed = 0;
    for (i = 0; i < n; ++i) {
        if (r->count >= RING_CAP) {
            break;
        }
        r->buf[r->tail] = src[i];
        r->tail = (r->tail + 1) % RING_CAP;
        r->count = r->count + 1;
        ++pushed;
    }
    return pushed;
}

extern "C" __declspec(dllexport) int ring_pop_many(Ring *r, int *dst, int n)
{
    int popped;
    int i;
    if (r == 0 || dst == 0) {
        return -1;
    }
    popped = 0;
    for (i = 0; i < n; ++i) {
        if (r->count <= 0) {
            break;
        }
        dst[i] = r->buf[r->head];
        r->head = (r->head + 1) % RING_CAP;
        r->count = r->count - 1;
        ++popped;
    }
    return popped;
}

extern "C" __declspec(dllexport) int ring_drop(Ring *r, int n)
{
    int dropped;
    if (r == 0 || n <= 0) {
        return 0;
    }
    dropped = 0;
    while (n > 0 && r->count > 0) {
        r->head = (r->head + 1) % RING_CAP;
        r->count = r->count - 1;
        ++dropped;
        --n;
    }
    return dropped;
}

extern "C" __declspec(dllexport) int ring_copy_out(const Ring *r, int *dst, int max)
{
    int i;
    int pos;
    int n;
    if (r == 0 || dst == 0) {
        return -1;
    }
    n = r->count < max ? r->count : max;
    if (n < 0) {
        n = 0;
    }
    for (i = 0; i < n; ++i) {
        pos = (r->head + i) % RING_CAP;
        dst[i] = r->buf[pos];
    }
    return n;
}

/* ---- queries / statistics ---- */

extern "C" __declspec(dllexport) int ring_capacity(const Ring *r)
{
    (void)r;
    return RING_CAP;
}

extern "C" __declspec(dllexport) int ring_free_space(const Ring *r)
{
    if (r == 0) {
        return 0;
    }
    return RING_CAP - r->count;
}

extern "C" __declspec(dllexport) int ring_contains(const Ring *r, int value)
{
    int i;
    int pos;
    if (r == 0) {
        return 0;
    }
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        if (r->buf[pos] == value) {
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int ring_index_of(const Ring *r, int value)
{
    int i;
    int pos;
    if (r == 0) {
        return -1;
    }
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        if (r->buf[pos] == value) {
            return i;
        }
    }
    return -1;
}

extern "C" __declspec(dllexport) int ring_max(const Ring *r, int *out)
{
    int i;
    int pos;
    int best;
    if (r == 0 || r->count <= 0) {
        return 0;
    }
    best = r->buf[r->head];
    for (i = 1; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        if (r->buf[pos] > best) {
            best = r->buf[pos];
        }
    }
    if (out != 0) {
        *out = best;
    }
    return 1;
}

extern "C" __declspec(dllexport) int ring_min(const Ring *r, int *out)
{
    int i;
    int pos;
    int best;
    if (r == 0 || r->count <= 0) {
        return 0;
    }
    best = r->buf[r->head];
    for (i = 1; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        if (r->buf[pos] < best) {
            best = r->buf[pos];
        }
    }
    if (out != 0) {
        *out = best;
    }
    return 1;
}

extern "C" __declspec(dllexport) int ring_count_if_gt(const Ring *r, int threshold)
{
    int i;
    int pos;
    int hits;
    if (r == 0) {
        return 0;
    }
    hits = 0;
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        if (r->buf[pos] > threshold) {
            ++hits;
        }
    }
    return hits;
}

/* ---- transforms ---- */

extern "C" __declspec(dllexport) void ring_scale(Ring *r, int factor)
{
    int i;
    int pos;
    if (r == 0) {
        return;
    }
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        r->buf[pos] = r->buf[pos] * factor;
    }
}

extern "C" __declspec(dllexport) int ring_replace(Ring *r, int oldv, int newv)
{
    int i;
    int pos;
    int changed;
    if (r == 0) {
        return 0;
    }
    changed = 0;
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        if (r->buf[pos] == oldv) {
            r->buf[pos] = newv;
            ++changed;
        }
    }
    return changed;
}

extern "C" __declspec(dllexport) void ring_reverse(Ring *r)
{
    int i;
    int j;
    int pa;
    int pb;
    int tmp;
    if (r == 0 || r->count <= 1) {
        return;
    }
    i = 0;
    j = r->count - 1;
    while (i < j) {
        pa = (r->head + i) % RING_CAP;
        pb = (r->head + j) % RING_CAP;
        tmp = r->buf[pa];
        r->buf[pa] = r->buf[pb];
        r->buf[pb] = tmp;
        ++i;
        --j;
    }
}

extern "C" __declspec(dllexport) int ring_rotate(Ring *r, int n)
{
    int moved;
    int v;
    if (r == 0 || r->count <= 0) {
        return 0;
    }
    moved = 0;
    while (n > 0) {
        v = r->buf[r->head];
        r->head = (r->head + 1) % RING_CAP;
        r->buf[r->tail] = v;
        r->tail = (r->tail + 1) % RING_CAP;
        ++moved;
        --n;
    }
    return moved;
}

/* ---- classification via switch + recursion ---- */

extern "C" __declspec(dllexport) int ring_classify(const Ring *r)
{
    int sz;
    if (r == 0) {
        return -1;
    }
    sz = r->count;
    switch (sz) {
    case 0:
        return 0;
    case RING_CAP:
        return 3;
    default:
        break;
    }
    if (sz < RING_CAP / 2) {
        return 1;
    }
    return 2;
}

extern "C" __declspec(dllexport) int64_t ring_checksum(const Ring *r)
{
    int i;
    int pos;
    int64_t acc;
    if (r == 0) {
        return 0;
    }
    acc = 1469598103934665603LL;
    for (i = 0; i < r->count; ++i) {
        pos = (r->head + i) % RING_CAP;
        acc = acc ^ (int64_t)r->buf[pos];
        acc = acc * 1099511628211LL;
    }
    return acc;
}

extern "C" __declspec(dllexport) int64_t ring_factorial_depth(int n)
{
    if (n <= 1) {
        return 1;
    }
    return (int64_t)n * ring_factorial_depth(n - 1);
}
