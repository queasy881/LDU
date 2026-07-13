// struct_ops.cpp
// Decompiler test target: plain structs passed by pointer.
// Compiled with: cl /LD /Od struct_ops.cpp
// C-style C++ only. Only <stdint.h> is included.

#include <stdint.h>

// ----------------------------------------------------------------------------
// Struct definitions
// ----------------------------------------------------------------------------

struct Point {
    int x;
    int y;
};

struct Rect {
    int x;
    int y;
    int w;
    int h;
};

struct Vec3 {
    int x;
    int y;
    int z;
};

struct Stack {
    int data[64];
    int top;
};

struct Counter {
    int n;
    int sum;
};

// ----------------------------------------------------------------------------
// Point operations
// ----------------------------------------------------------------------------

// Add two points component-wise, writing the result through out.
extern "C" __declspec(dllexport) void point_add(const Point* a, const Point* b, Point* out)
{
    if (a == 0 || b == 0 || out == 0) {
        return;
    }
    out->x = a->x + b->x;
    out->y = a->y + b->y;
}

// Squared Euclidean distance between two points.
extern "C" __declspec(dllexport) int64_t point_dist2(const Point* a, const Point* b)
{
    if (a == 0 || b == 0) {
        return -1;
    }
    int64_t dx = (int64_t)a->x - (int64_t)b->x;
    int64_t dy = (int64_t)a->y - (int64_t)b->y;
    return dx * dx + dy * dy;
}

// Returns 1 if the two points are equal, 0 otherwise.
extern "C" __declspec(dllexport) int point_eq(const Point* a, const Point* b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    if (a->x == b->x && a->y == b->y) {
        return 1;
    }
    return 0;
}

// Manhattan (L1) distance between two points.
extern "C" __declspec(dllexport) int manhattan(const Point* a, const Point* b)
{
    if (a == 0 || b == 0) {
        return -1;
    }
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    if (dx < 0) {
        dx = -dx;
    }
    if (dy < 0) {
        dy = -dy;
    }
    return dx + dy;
}

// Midpoint of two points (integer division), written through out.
extern "C" __declspec(dllexport) void midpoint(const Point* a, const Point* b, Point* out)
{
    if (a == 0 || b == 0 || out == 0) {
        return;
    }
    out->x = (a->x + b->x) / 2;
    out->y = (a->y + b->y) / 2;
}

// Swap the contents of two points via pointers.
extern "C" __declspec(dllexport) void swap_points(Point* a, Point* b)
{
    if (a == 0 || b == 0) {
        return;
    }
    int tx = a->x;
    int ty = a->y;
    a->x = b->x;
    a->y = b->y;
    b->x = tx;
    b->y = ty;
}

// ----------------------------------------------------------------------------
// Rect operations
// ----------------------------------------------------------------------------

// Area of a rectangle (w * h).
extern "C" __declspec(dllexport) int rect_area(const Rect* r)
{
    if (r == 0) {
        return 0;
    }
    int w = r->w;
    int h = r->h;
    if (w < 0) {
        w = 0;
    }
    if (h < 0) {
        h = 0;
    }
    return w * h;
}

// Perimeter of a rectangle.
extern "C" __declspec(dllexport) int rect_perimeter(const Rect* r)
{
    if (r == 0) {
        return 0;
    }
    return 2 * (r->w + r->h);
}

// Returns 1 if point p is inside rect r (inclusive lower, exclusive upper).
extern "C" __declspec(dllexport) int rect_contains_point(const Rect* r, const Point* p)
{
    if (r == 0 || p == 0) {
        return 0;
    }
    if (p->x < r->x) {
        return 0;
    }
    if (p->y < r->y) {
        return 0;
    }
    if (p->x >= r->x + r->w) {
        return 0;
    }
    if (p->y >= r->y + r->h) {
        return 0;
    }
    return 1;
}

// Returns 1 if two rectangles overlap, 0 otherwise.
extern "C" __declspec(dllexport) int rect_intersects(const Rect* a, const Rect* b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    if (a->x + a->w <= b->x) {
        return 0;
    }
    if (b->x + b->w <= a->x) {
        return 0;
    }
    if (a->y + a->h <= b->y) {
        return 0;
    }
    if (b->y + b->h <= a->y) {
        return 0;
    }
    return 1;
}

// Combined area of two rectangles minus their overlap (union area).
extern "C" __declspec(dllexport) int64_t rect_union_area(const Rect* a, const Rect* b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    int64_t area_a = (int64_t)a->w * (int64_t)a->h;
    int64_t area_b = (int64_t)b->w * (int64_t)b->h;
    int64_t overlap = 0;
    if (rect_intersects(a, b)) {
        int ix0 = a->x > b->x ? a->x : b->x;
        int iy0 = a->y > b->y ? a->y : b->y;
        int ax1 = a->x + a->w;
        int bx1 = b->x + b->w;
        int ay1 = a->y + a->h;
        int by1 = b->y + b->h;
        int ix1 = ax1 < bx1 ? ax1 : bx1;
        int iy1 = ay1 < by1 ? ay1 : by1;
        overlap = (int64_t)(ix1 - ix0) * (int64_t)(iy1 - iy0);
    }
    return area_a + area_b - overlap;
}

// ----------------------------------------------------------------------------
// Vec3 operations
// ----------------------------------------------------------------------------

// Add two 3D vectors, writing the result through out.
extern "C" __declspec(dllexport) void vec3_add(const Vec3* a, const Vec3* b, Vec3* out)
{
    if (a == 0 || b == 0 || out == 0) {
        return;
    }
    out->x = a->x + b->x;
    out->y = a->y + b->y;
    out->z = a->z + b->z;
}

// Subtract b from a, writing the result through out.
extern "C" __declspec(dllexport) void vec3_sub(const Vec3* a, const Vec3* b, Vec3* out)
{
    if (a == 0 || b == 0 || out == 0) {
        return;
    }
    out->x = a->x - b->x;
    out->y = a->y - b->y;
    out->z = a->z - b->z;
}

// Dot product of two 3D vectors.
extern "C" __declspec(dllexport) int64_t vec3_dot(const Vec3* a, const Vec3* b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    int64_t sum = 0;
    sum += (int64_t)a->x * (int64_t)b->x;
    sum += (int64_t)a->y * (int64_t)b->y;
    sum += (int64_t)a->z * (int64_t)b->z;
    return sum;
}

// Squared length of a 3D vector.
extern "C" __declspec(dllexport) int64_t vec3_len2(const Vec3* v)
{
    if (v == 0) {
        return 0;
    }
    return vec3_dot(v, v);
}

// Scale a 3D vector by an integer factor, writing the result through out.
extern "C" __declspec(dllexport) void vec3_scale(const Vec3* v, int factor, Vec3* out)
{
    if (v == 0 || out == 0) {
        return;
    }
    out->x = v->x * factor;
    out->y = v->y * factor;
    out->z = v->z * factor;
}

// ----------------------------------------------------------------------------
// Stack operations
// ----------------------------------------------------------------------------

// Initialize a stack to empty, zeroing the backing array.
extern "C" __declspec(dllexport) void stack_init(Stack* s)
{
    if (s == 0) {
        return;
    }
    int i = 0;
    while (i < 64) {
        s->data[i] = 0;
        i++;
    }
    s->top = 0;
}

// Push a value onto the stack. Returns 1 on success, 0 if full.
extern "C" __declspec(dllexport) int stack_push(Stack* s, int value)
{
    if (s == 0) {
        return 0;
    }
    if (s->top < 0 || s->top >= 64) {
        return 0;
    }
    s->data[s->top] = value;
    s->top++;
    return 1;
}

// Pop a value off the stack into out. Returns 1 on success, 0 if empty.
extern "C" __declspec(dllexport) int stack_pop(Stack* s, int* out)
{
    if (s == 0 || out == 0) {
        return 0;
    }
    if (s->top <= 0) {
        return 0;
    }
    s->top--;
    *out = s->data[s->top];
    return 1;
}

// Peek at the top value without removing it. Returns 1 on success, 0 if empty.
extern "C" __declspec(dllexport) int stack_peek(const Stack* s, int* out)
{
    if (s == 0 || out == 0) {
        return 0;
    }
    if (s->top <= 0) {
        return 0;
    }
    *out = s->data[s->top - 1];
    return 1;
}

// Number of elements currently on the stack.
extern "C" __declspec(dllexport) int stack_size(const Stack* s)
{
    if (s == 0) {
        return 0;
    }
    return s->top;
}

// Returns 1 if the stack is empty, 0 otherwise.
extern "C" __declspec(dllexport) int stack_is_empty(const Stack* s)
{
    if (s == 0) {
        return 1;
    }
    if (s->top <= 0) {
        return 1;
    }
    return 0;
}

// Sum all values currently on the stack.
extern "C" __declspec(dllexport) int64_t stack_sum(const Stack* s)
{
    if (s == 0) {
        return 0;
    }
    int64_t total = 0;
    for (int i = 0; i < s->top && i < 64; i++) {
        total += (int64_t)s->data[i];
    }
    return total;
}

// ----------------------------------------------------------------------------
// Counter operations
// ----------------------------------------------------------------------------

// Add a value to the counter, updating count and running sum.
extern "C" __declspec(dllexport) void counter_add(Counter* c, int value)
{
    if (c == 0) {
        return;
    }
    c->n++;
    c->sum += value;
}

// Integer average tracked by the counter; 0 if empty.
extern "C" __declspec(dllexport) int counter_avg(const Counter* c)
{
    if (c == 0) {
        return 0;
    }
    if (c->n == 0) {
        return 0;
    }
    return c->sum / c->n;
}

// Classify the counter's average into a small bucket via switch.
extern "C" __declspec(dllexport) int counter_bucket(const Counter* c)
{
    if (c == 0) {
        return -1;
    }
    int avg = counter_avg(c);
    int band = avg / 10;
    switch (band) {
        case 0:
            return 0;
        case 1:
        case 2:
            return 1;
        case 3:
        case 4:
            return 2;
        default:
            if (band < 0) {
                return -2;
            }
            return 3;
    }
}
