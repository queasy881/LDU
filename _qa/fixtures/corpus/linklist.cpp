/* Array-backed singly linked list decompiler behavioral-test target.
 * Build: cl /LD /Od linklist.cpp
 * Pure deterministic C-style functions, all exported with clean names.
 */
#include <stdint.h>

#define LL_CAP 64
#define LL_NIL (-1)

typedef struct Node {
    int val;
    int next;
} Node;

typedef struct List {
    Node nodes[LL_CAP];
    int  used[LL_CAP];
    int  head;
    int  count;
} List;

/* ---- internal-ish helpers (still exported for test coverage) ---- */

extern "C" __declspec(dllexport) int ll_alloc_slot(List *L)
{
    if (L == 0) {
        return LL_NIL;
    }
    for (int i = 0; i < LL_CAP; ++i) {
        if (L->used[i] == 0) {
            L->used[i] = 1;
            L->nodes[i].val = 0;
            L->nodes[i].next = LL_NIL;
            return i;
        }
    }
    return LL_NIL;
}

extern "C" __declspec(dllexport) void ll_free_slot(List *L, int idx)
{
    if (L == 0) {
        return;
    }
    if (idx < 0 || idx >= LL_CAP) {
        return;
    }
    L->used[idx] = 0;
    L->nodes[idx].val = 0;
    L->nodes[idx].next = LL_NIL;
}

extern "C" __declspec(dllexport) int ll_slot_valid(const List *L, int idx)
{
    if (L == 0) {
        return 0;
    }
    if (idx < 0 || idx >= LL_CAP) {
        return 0;
    }
    return L->used[idx] != 0 ? 1 : 0;
}

/* ---- core list API ---- */

extern "C" __declspec(dllexport) void list_init(List *L)
{
    if (L == 0) {
        return;
    }
    int i = 0;
    while (i < LL_CAP) {
        L->nodes[i].val = 0;
        L->nodes[i].next = LL_NIL;
        L->used[i] = 0;
        ++i;
    }
    L->head = LL_NIL;
    L->count = 0;
}

extern "C" __declspec(dllexport) int list_push_front(List *L, int value)
{
    if (L == 0) {
        return LL_NIL;
    }
    int slot = ll_alloc_slot(L);
    if (slot == LL_NIL) {
        return LL_NIL;
    }
    L->nodes[slot].val = value;
    L->nodes[slot].next = L->head;
    L->head = slot;
    L->count += 1;
    return slot;
}

extern "C" __declspec(dllexport) int list_append(List *L, int value)
{
    if (L == 0) {
        return LL_NIL;
    }
    int slot = ll_alloc_slot(L);
    if (slot == LL_NIL) {
        return LL_NIL;
    }
    L->nodes[slot].val = value;
    L->nodes[slot].next = LL_NIL;

    if (L->head == LL_NIL) {
        L->head = slot;
        L->count += 1;
        return slot;
    }

    int cur = L->head;
    int guard = 0;
    while (L->nodes[cur].next != LL_NIL) {
        cur = L->nodes[cur].next;
        if (++guard > LL_CAP) {
            break;
        }
    }
    L->nodes[cur].next = slot;
    L->count += 1;
    return slot;
}

extern "C" __declspec(dllexport) int list_len(const List *L)
{
    if (L == 0) {
        return 0;
    }
    int n = 0;
    int cur = L->head;
    while (cur != LL_NIL) {
        ++n;
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        cur = L->nodes[cur].next;
        if (n > LL_CAP) {
            break;
        }
    }
    return n;
}

extern "C" __declspec(dllexport) int list_find(const List *L, int value)
{
    if (L == 0) {
        return LL_NIL;
    }
    int cur = L->head;
    int steps = 0;
    for (;;) {
        if (cur == LL_NIL) {
            return LL_NIL;
        }
        if (cur < 0 || cur >= LL_CAP) {
            return LL_NIL;
        }
        if (L->nodes[cur].val == value) {
            return cur;
        }
        cur = L->nodes[cur].next;
        if (++steps > LL_CAP) {
            return LL_NIL;
        }
    }
}

extern "C" __declspec(dllexport) int list_get(const List *L, int pos, int *out)
{
    if (L == 0 || out == 0) {
        return 0;
    }
    if (pos < 0) {
        return 0;
    }
    int cur = L->head;
    int i = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            return 0;
        }
        if (i == pos) {
            *out = L->nodes[cur].val;
            return 1;
        }
        cur = L->nodes[cur].next;
        ++i;
        if (i > LL_CAP) {
            break;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int list_contains(const List *L, int value)
{
    int idx = list_find(L, value);
    if (idx == LL_NIL) {
        return 0;
    }
    return 1;
}

extern "C" __declspec(dllexport) int64_t list_sum(const List *L)
{
    if (L == 0) {
        return 0;
    }
    int64_t acc = 0;
    int cur = L->head;
    int steps = 0;
    do {
        if (cur == LL_NIL) {
            break;
        }
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        acc += (int64_t)L->nodes[cur].val;
        cur = L->nodes[cur].next;
        ++steps;
    } while (steps <= LL_CAP);
    return acc;
}

extern "C" __declspec(dllexport) int list_remove_at(List *L, int pos)
{
    if (L == 0) {
        return 0;
    }
    if (pos < 0 || L->head == LL_NIL) {
        return 0;
    }

    if (pos == 0) {
        int victim = L->head;
        L->head = L->nodes[victim].next;
        ll_free_slot(L, victim);
        L->count -= 1;
        return 1;
    }

    int prev = L->head;
    int i = 0;
    while (i < pos - 1) {
        if (prev < 0 || prev >= LL_CAP) {
            return 0;
        }
        prev = L->nodes[prev].next;
        if (prev == LL_NIL) {
            return 0;
        }
        ++i;
    }

    int victim = L->nodes[prev].next;
    if (victim == LL_NIL) {
        return 0;
    }
    L->nodes[prev].next = L->nodes[victim].next;
    ll_free_slot(L, victim);
    L->count -= 1;
    return 1;
}

extern "C" __declspec(dllexport) void list_reverse(List *L)
{
    if (L == 0) {
        return;
    }
    int prev = LL_NIL;
    int cur = L->head;
    int steps = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        int nxt = L->nodes[cur].next;
        L->nodes[cur].next = prev;
        prev = cur;
        cur = nxt;
        if (++steps > LL_CAP) {
            break;
        }
    }
    L->head = prev;
}

extern "C" __declspec(dllexport) int list_count_field(const List *L)
{
    if (L == 0) {
        return 0;
    }
    return L->count;
}

extern "C" __declspec(dllexport) int list_max(const List *L, int *out)
{
    if (L == 0 || out == 0) {
        return 0;
    }
    int cur = L->head;
    if (cur == LL_NIL) {
        return 0;
    }
    int best = L->nodes[cur].val;
    int steps = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        int v = L->nodes[cur].val;
        if (v > best) {
            best = v;
        }
        cur = L->nodes[cur].next;
        if (++steps > LL_CAP) {
            break;
        }
    }
    *out = best;
    return 1;
}

extern "C" __declspec(dllexport) int list_min(const List *L, int *out)
{
    if (L == 0 || out == 0) {
        return 0;
    }
    int cur = L->head;
    if (cur == LL_NIL) {
        return 0;
    }
    int best = L->nodes[cur].val;
    int steps = 0;
    for (; cur != LL_NIL; ) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        if (L->nodes[cur].val < best) {
            best = L->nodes[cur].val;
        }
        cur = L->nodes[cur].next;
        if (++steps > LL_CAP) {
            break;
        }
    }
    *out = best;
    return 1;
}

extern "C" __declspec(dllexport) int list_index_of(const List *L, int value)
{
    if (L == 0) {
        return LL_NIL;
    }
    int cur = L->head;
    int pos = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            return LL_NIL;
        }
        if (L->nodes[cur].val == value) {
            return pos;
        }
        cur = L->nodes[cur].next;
        ++pos;
        if (pos > LL_CAP) {
            break;
        }
    }
    return LL_NIL;
}

extern "C" __declspec(dllexport) int list_to_array(const List *L, int *buf, int cap)
{
    if (L == 0 || buf == 0 || cap <= 0) {
        return 0;
    }
    int cur = L->head;
    int n = 0;
    while (cur != LL_NIL && n < cap) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        buf[n] = L->nodes[cur].val;
        ++n;
        cur = L->nodes[cur].next;
    }
    return n;
}

extern "C" __declspec(dllexport) int list_set(List *L, int pos, int value)
{
    if (L == 0 || pos < 0) {
        return 0;
    }
    int cur = L->head;
    int i = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            return 0;
        }
        if (i == pos) {
            L->nodes[cur].val = value;
            return 1;
        }
        cur = L->nodes[cur].next;
        ++i;
        if (i > LL_CAP) {
            break;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int list_classify(const List *L, int value)
{
    int idx = list_index_of(L, value);
    switch (idx) {
        case LL_NIL:
            return 0;
        case 0:
            return 1;
        case 1:
            return 2;
        case 2:
            return 3;
        default:
            if (idx > 2) {
                return 4;
            }
            return -1;
    }
}

extern "C" __declspec(dllexport) int64_t ll_recursive_sum(const List *L, int node, int depth)
{
    if (L == 0) {
        return 0;
    }
    if (node == LL_NIL || node < 0 || node >= LL_CAP) {
        return 0;
    }
    if (depth > LL_CAP) {
        return 0;
    }
    int64_t here = (int64_t)L->nodes[node].val;
    return here + ll_recursive_sum(L, L->nodes[node].next, depth + 1);
}

extern "C" __declspec(dllexport) int list_count_even(const List *L)
{
    if (L == 0) {
        return 0;
    }
    int cur = L->head;
    int even = 0;
    int steps = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        int v = L->nodes[cur].val;
        if ((v & 1) == 0) {
            ++even;
        } else {
            /* odd: skip */
            ;
        }
        cur = L->nodes[cur].next;
        if (++steps > LL_CAP) {
            break;
        }
    }
    return even;
}

extern "C" __declspec(dllexport) int list_clear(List *L)
{
    if (L == 0) {
        return 0;
    }
    int cur = L->head;
    int removed = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        int nxt = L->nodes[cur].next;
        ll_free_slot(L, cur);
        cur = nxt;
        ++removed;
        if (removed > LL_CAP) {
            break;
        }
    }
    L->head = LL_NIL;
    L->count = 0;
    return removed;
}

extern "C" __declspec(dllexport) uint32_t list_hash(const List *L)
{
    if (L == 0) {
        return 0u;
    }
    uint32_t h = 2166136261u;
    int cur = L->head;
    int steps = 0;
    while (cur != LL_NIL) {
        if (cur < 0 || cur >= LL_CAP) {
            break;
        }
        uint32_t v = (uint32_t)L->nodes[cur].val;
        h ^= v;
        h *= 16777619u;
        cur = L->nodes[cur].next;
        if (++steps > LL_CAP) {
            break;
        }
    }
    return h;
}
