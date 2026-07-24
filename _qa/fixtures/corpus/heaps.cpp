/* heaps.cpp - binary max-heap behavioral-test target for decompiler QA.
 * Build: cl /LD /Od heaps.cpp
 * Pure deterministic C-style functions operating on caller-supplied int arrays.
 */
#include <stdint.h>

#define HEAP_CAP 256

typedef struct HeapView {
    int data[HEAP_CAP];
    int count;
} HeapView;

/* ---- index arithmetic -------------------------------------------------- */

extern "C" __declspec(dllexport) int heap_parent(int i)
{
    if (i <= 0) {
        return -1;
    }
    return (i - 1) / 2;
}

extern "C" __declspec(dllexport) int heap_left(int i)
{
    if (i < 0) {
        return -1;
    }
    return 2 * i + 1;
}

extern "C" __declspec(dllexport) int heap_right(int i)
{
    if (i < 0) {
        return -1;
    }
    return 2 * i + 2;
}

extern "C" __declspec(dllexport) int heap_is_leaf(int i, int count)
{
    int left = 2 * i + 1;
    if (i < 0 || i >= count) {
        return 0;
    }
    return left >= count ? 1 : 0;
}

/* ---- low level helpers ------------------------------------------------- */

extern "C" __declspec(dllexport) void heap_swap(int *a, int *b)
{
    int tmp;
    if (a == 0 || b == 0) {
        return;
    }
    tmp = *a;
    *a = *b;
    *b = tmp;
}

extern "C" __declspec(dllexport) int heap_max_child(const int *heap, int count, int i)
{
    int left = 2 * i + 1;
    int right = 2 * i + 2;
    int best = left;
    if (heap == 0 || left >= count) {
        return -1;
    }
    if (right < count && heap[right] > heap[left]) {
        best = right;
    }
    return best;
}

extern "C" __declspec(dllexport) int heap_peek(const int *heap, int count, int *out_max)
{
    if (heap == 0 || count <= 0) {
        return 0;
    }
    if (out_max != 0) {
        *out_max = heap[0];
    }
    return 1;
}

/* ---- sift operations --------------------------------------------------- */

extern "C" __declspec(dllexport) void heap_sift_up(int *heap, int count, int index)
{
    int i = index;
    if (heap == 0 || i < 0 || i >= count) {
        return;
    }
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (heap[parent] >= heap[i]) {
            break;
        }
        int tmp = heap[parent];
        heap[parent] = heap[i];
        heap[i] = tmp;
        i = parent;
    }
}

extern "C" __declspec(dllexport) void heap_sift_down(int *heap, int count, int index)
{
    int i = index;
    if (heap == 0 || i < 0) {
        return;
    }
    for (;;) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        int largest = i;
        if (left < count && heap[left] > heap[largest]) {
            largest = left;
        }
        if (right < count && heap[right] > heap[largest]) {
            largest = right;
        }
        if (largest == i) {
            break;
        }
        int tmp = heap[i];
        heap[i] = heap[largest];
        heap[largest] = tmp;
        i = largest;
    }
}

/* recursive variant of sift-down to exercise recursion */
extern "C" __declspec(dllexport) void heapify(int *heap, int count, int index)
{
    int left;
    int right;
    int largest;
    if (heap == 0 || index < 0 || index >= count) {
        return;
    }
    left = 2 * index + 1;
    right = 2 * index + 2;
    largest = index;
    if (left < count && heap[left] > heap[largest]) {
        largest = left;
    }
    if (right < count && heap[right] > heap[largest]) {
        largest = right;
    }
    if (largest != index) {
        int tmp = heap[index];
        heap[index] = heap[largest];
        heap[largest] = tmp;
        heapify(heap, count, largest);
    }
}

/* ---- construction ------------------------------------------------------ */

extern "C" __declspec(dllexport) int build_heap(int *heap, int count)
{
    int i;
    if (heap == 0 || count < 0) {
        return -1;
    }
    if (count <= 1) {
        return count;
    }
    for (i = count / 2 - 1; i >= 0; i--) {
        heapify(heap, count, i);
    }
    return count;
}

extern "C" __declspec(dllexport) int build_heap_from(const int *src, int n, int *dst)
{
    int i;
    if (src == 0 || dst == 0 || n < 0) {
        return -1;
    }
    if (n > HEAP_CAP) {
        n = HEAP_CAP;
    }
    for (i = 0; i < n; i++) {
        dst[i] = src[i];
    }
    return build_heap(dst, n);
}

/* ---- mutation ---------------------------------------------------------- */

extern "C" __declspec(dllexport) int heap_push(int *heap, int count, int cap, int value)
{
    if (heap == 0 || count < 0 || count >= cap) {
        return count;
    }
    heap[count] = value;
    count++;
    heap_sift_up(heap, count, count - 1);
    return count;
}

extern "C" __declspec(dllexport) int heap_pop_max(int *heap, int count, int *out_max)
{
    if (heap == 0 || count <= 0) {
        return count <= 0 ? 0 : count;
    }
    if (out_max != 0) {
        *out_max = heap[0];
    }
    count--;
    heap[0] = heap[count];
    heap[count] = 0;
    if (count > 0) {
        heap_sift_down(heap, count, 0);
    }
    return count;
}

extern "C" __declspec(dllexport) int heap_replace(int *heap, int count, int value, int *out_old)
{
    if (heap == 0 || count <= 0) {
        return 0;
    }
    if (out_old != 0) {
        *out_old = heap[0];
    }
    heap[0] = value;
    heap_sift_down(heap, count, 0);
    return 1;
}

extern "C" __declspec(dllexport) int heap_push_pop(int *heap, int count, int value, int *out_max)
{
    if (heap == 0 || count <= 0) {
        if (out_max != 0) {
            *out_max = value;
        }
        return 0;
    }
    if (value >= heap[0]) {
        if (out_max != 0) {
            *out_max = value;
        }
        return 1;
    }
    if (out_max != 0) {
        *out_max = heap[0];
    }
    heap[0] = value;
    heap_sift_down(heap, count, 0);
    return 1;
}

extern "C" __declspec(dllexport) int heap_delete_at(int *heap, int count, int index)
{
    int moved;
    if (heap == 0 || index < 0 || index >= count) {
        return count;
    }
    count--;
    moved = heap[count];
    heap[count] = 0;
    if (index < count) {
        heap[index] = moved;
        heap_sift_down(heap, count, index);
        heap_sift_up(heap, count, index);
    }
    return count;
}

/* ---- queries ----------------------------------------------------------- */

extern "C" __declspec(dllexport) int is_max_heap(const int *heap, int count)
{
    int i;
    if (heap == 0) {
        return 0;
    }
    if (count <= 1) {
        return 1;
    }
    for (i = 0; i < count; i++) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        if (left < count && heap[i] < heap[left]) {
            return 0;
        }
        if (right < count && heap[i] < heap[right]) {
            return 0;
        }
    }
    return 1;
}

extern "C" __declspec(dllexport) int heap_size_after(int count, int pushes, int pops, int cap)
{
    int size = count;
    int n;
    if (cap < 0) {
        cap = 0;
    }
    for (n = 0; n < pushes; n++) {
        if (size < cap) {
            size++;
        }
    }
    n = 0;
    do {
        if (pops <= 0) {
            break;
        }
        if (size > 0) {
            size--;
        }
        n++;
    } while (n < pops);
    return size;
}

extern "C" __declspec(dllexport) int heap_depth(int count)
{
    int depth = 0;
    int span = 1;
    int total = 0;
    if (count <= 0) {
        return 0;
    }
    while (total < count) {
        total += span;
        span *= 2;
        depth++;
    }
    return depth;
}

extern "C" __declspec(dllexport) int heap_level_of(int index)
{
    int level = 0;
    int i = index + 1;
    if (index < 0) {
        return -1;
    }
    while (i > 1) {
        i /= 2;
        level++;
    }
    return level;
}

extern "C" __declspec(dllexport) int64_t heap_sum(const int *heap, int count)
{
    int64_t sum = 0;
    int i;
    if (heap == 0 || count <= 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        sum += (int64_t)heap[i];
    }
    return sum;
}

extern "C" __declspec(dllexport) int heap_count_above(const int *heap, int count, int threshold)
{
    int i;
    int hits = 0;
    if (heap == 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (heap[i] > threshold) {
            hits++;
        } else {
            continue;
        }
    }
    return hits;
}

/* ---- heapsort + struct view ------------------------------------------- */

extern "C" __declspec(dllexport) int heap_sort(int *arr, int count)
{
    int end;
    if (arr == 0 || count < 0) {
        return -1;
    }
    if (count <= 1) {
        return count;
    }
    build_heap(arr, count);
    for (end = count - 1; end > 0; end--) {
        int tmp = arr[0];
        arr[0] = arr[end];
        arr[end] = tmp;
        heap_sift_down(arr, end, 0);
    }
    return count;
}

extern "C" __declspec(dllexport) int heap_kth_largest(const int *src, int n, int k, int *out_val)
{
    HeapView hv;
    int i;
    int popped = 0;
    int last = 0;
    if (src == 0 || n <= 0 || k <= 0 || k > n) {
        return 0;
    }
    if (n > HEAP_CAP) {
        n = HEAP_CAP;
    }
    if (k > n) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        hv.data[i] = src[i];
    }
    hv.count = build_heap(hv.data, n);
    for (i = 0; i < k; i++) {
        hv.count = heap_pop_max(hv.data, hv.count, &last);
        popped++;
    }
    if (out_val != 0 && popped == k) {
        *out_val = last;
    }
    return popped == k ? 1 : 0;
}

extern "C" __declspec(dllexport) void heap_view_init(HeapView *hv)
{
    int i;
    if (hv == 0) {
        return;
    }
    for (i = 0; i < HEAP_CAP; i++) {
        hv->data[i] = 0;
    }
    hv->count = 0;
}

extern "C" __declspec(dllexport) int heap_view_push(HeapView *hv, int value)
{
    if (hv == 0) {
        return -1;
    }
    hv->count = heap_push(hv->data, hv->count, HEAP_CAP, value);
    return hv->count;
}

extern "C" __declspec(dllexport) int heap_view_pop(HeapView *hv, int *out_max)
{
    if (hv == 0 || hv->count <= 0) {
        return 0;
    }
    hv->count = heap_pop_max(hv->data, hv->count, out_max);
    return 1;
}

extern "C" __declspec(dllexport) int heap_view_valid(const HeapView *hv)
{
    if (hv == 0) {
        return 0;
    }
    if (hv->count < 0 || hv->count > HEAP_CAP) {
        return 0;
    }
    return is_max_heap(hv->data, hv->count);
}

extern "C" __declspec(dllexport) int heap_merge(const int *a, int na, const int *b, int nb, int *dst)
{
    int i;
    int total = 0;
    if (dst == 0 || na < 0 || nb < 0) {
        return -1;
    }
    for (i = 0; i < na && total < HEAP_CAP; i++) {
        dst[total++] = a ? a[i] : 0;
    }
    for (i = 0; i < nb && total < HEAP_CAP; i++) {
        dst[total++] = b ? b[i] : 0;
    }
    return build_heap(dst, total);
}
