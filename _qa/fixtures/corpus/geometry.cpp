/* geometry.cpp - integer geometry decompiler behavioral-test target.
 * Build: cl /LD /Od /W3 geometry.cpp
 * Pure deterministic C-style functions exported with clean names.
 */
#include <stdint.h>

typedef struct Point { int x; int y; } Point;
typedef struct Rect { int x; int y; int w; int h; } Rect;

/* ------------------------------------------------------------------ */
/* Core scalar primitives                                             */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) int64_t cross3(int ax, int ay,
                                                int bx, int by,
                                                int cx, int cy)
{
    int64_t ux = (int64_t)bx - (int64_t)ax;
    int64_t uy = (int64_t)by - (int64_t)ay;
    int64_t vx = (int64_t)cx - (int64_t)ax;
    int64_t vy = (int64_t)cy - (int64_t)ay;
    return ux * vy - uy * vx;
}

extern "C" __declspec(dllexport) int64_t dot2(int ax, int ay,
                                              int bx, int by)
{
    int64_t r = (int64_t)ax * (int64_t)bx;
    r += (int64_t)ay * (int64_t)by;
    return r;
}

extern "C" __declspec(dllexport) int abs_i(int v)
{
    if (v < 0)
        return -v;
    return v;
}

extern "C" __declspec(dllexport) int manhattan(int ax, int ay,
                                               int bx, int by)
{
    int dx = ax - bx;
    int dy = ay - by;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    return dx + dy;
}

extern "C" __declspec(dllexport) int chebyshev(int ax, int ay,
                                               int bx, int by)
{
    int dx = ax - bx;
    int dy = ay - by;
    if (dx < 0) dx = -dx;
    if (dy < 0) dy = -dy;
    if (dx > dy)
        return dx;
    return dy;
}

extern "C" __declspec(dllexport) int64_t dist_sq(int ax, int ay,
                                                 int bx, int by)
{
    int64_t dx = (int64_t)ax - (int64_t)bx;
    int64_t dy = (int64_t)ay - (int64_t)by;
    return dx * dx + dy * dy;
}

/* ------------------------------------------------------------------ */
/* Rect / containment                                                 */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) int point_in_rect(int px, int py,
                                                   int x, int y,
                                                   int w, int h)
{
    if (w < 0 || h < 0)
        return 0;
    if (px < x)
        return 0;
    if (py < y)
        return 0;
    if (px > x + w)
        return 0;
    if (py > y + h)
        return 0;
    return 1;
}

extern "C" __declspec(dllexport) int64_t bbox_area(const Point *pts, int n)
{
    if (pts == 0 || n <= 0)
        return 0;
    int minx = pts[0].x, maxx = pts[0].x;
    int miny = pts[0].y, maxy = pts[0].y;
    for (int i = 1; i < n; ++i) {
        int cx = pts[i].x;
        int cy = pts[i].y;
        if (cx < minx) minx = cx;
        if (cx > maxx) maxx = cx;
        if (cy < miny) miny = cy;
        if (cy > maxy) maxy = cy;
    }
    int64_t w = (int64_t)maxx - (int64_t)minx;
    int64_t h = (int64_t)maxy - (int64_t)miny;
    return w * h;
}

extern "C" __declspec(dllexport) int rect_overlap(int ax, int ay, int aw, int ah,
                                                  int bx, int by, int bw, int bh)
{
    if (ax + aw < bx) return 0;
    if (bx + bw < ax) return 0;
    if (ay + ah < by) return 0;
    if (by + bh < ay) return 0;
    return 1;
}

extern "C" __declspec(dllexport) void rect_center(const Rect *r, Point *out)
{
    if (r == 0 || out == 0)
        return;
    out->x = r->x + r->w / 2;
    out->y = r->y + r->h / 2;
}

/* ------------------------------------------------------------------ */
/* Orientation / segments                                             */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) int seg_orientation(int ax, int ay,
                                                     int bx, int by,
                                                     int cx, int cy)
{
    int64_t v = cross3(ax, ay, bx, by, cx, cy);
    if (v > 0)
        return 1;   /* counter-clockwise */
    if (v < 0)
        return -1;  /* clockwise */
    return 0;       /* collinear */
}

extern "C" __declspec(dllexport) int on_segment(int ax, int ay,
                                                int bx, int by,
                                                int px, int py)
{
    if (cross3(ax, ay, bx, by, px, py) != 0)
        return 0;
    int lo, hi;
    lo = ax < bx ? ax : bx;
    hi = ax > bx ? ax : bx;
    if (px < lo || px > hi)
        return 0;
    lo = ay < by ? ay : by;
    hi = ay > by ? ay : by;
    if (py < lo || py > hi)
        return 0;
    return 1;
}

extern "C" __declspec(dllexport) int segments_intersect(int ax, int ay, int bx, int by,
                                                        int cx, int cy, int dx, int dy)
{
    int o1 = seg_orientation(ax, ay, bx, by, cx, cy);
    int o2 = seg_orientation(ax, ay, bx, by, dx, dy);
    int o3 = seg_orientation(cx, cy, dx, dy, ax, ay);
    int o4 = seg_orientation(cx, cy, dx, dy, bx, by);
    if (o1 != o2 && o3 != o4)
        return 1;
    if (o1 == 0 && on_segment(ax, ay, bx, by, cx, cy)) return 1;
    if (o2 == 0 && on_segment(ax, ay, bx, by, dx, dy)) return 1;
    if (o3 == 0 && on_segment(cx, cy, dx, dy, ax, ay)) return 1;
    if (o4 == 0 && on_segment(cx, cy, dx, dy, bx, by)) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Polygon                                                            */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) int64_t polygon_area_shoelace(const Point *pts, int n)
{
    if (pts == 0 || n < 3)
        return 0;
    int64_t acc = 0;
    int j = n - 1;
    for (int i = 0; i < n; ++i) {
        acc += (int64_t)pts[j].x * (int64_t)pts[i].y;
        acc -= (int64_t)pts[i].x * (int64_t)pts[j].y;
        j = i;
    }
    if (acc < 0)
        acc = -acc;
    return acc / 2;
}

extern "C" __declspec(dllexport) int64_t polygon_perimeter_manhattan(const Point *pts, int n)
{
    if (pts == 0 || n < 2)
        return 0;
    int64_t total = 0;
    for (int i = 0; i < n; ++i) {
        int k = (i + 1) % n;
        total += manhattan(pts[i].x, pts[i].y, pts[k].x, pts[k].y);
    }
    return total;
}

extern "C" __declspec(dllexport) int point_in_polygon(const Point *pts, int n,
                                                      int px, int py)
{
    if (pts == 0 || n < 3)
        return 0;
    int inside = 0;
    int j = n - 1;
    for (int i = 0; i < n; ++i) {
        int yi = pts[i].y, yj = pts[j].y;
        int xi = pts[i].x, xj = pts[j].x;
        if ((yi > py) != (yj > py)) {
            int64_t lhs = (int64_t)(xj - xi) * (int64_t)(py - yi);
            int64_t rhs = (int64_t)(yj - yi) * (int64_t)(px - xi);
            if (yj - yi > 0) {
                if (lhs > rhs)
                    inside = !inside;
            } else {
                if (lhs < rhs)
                    inside = !inside;
            }
        }
        j = i;
    }
    return inside;
}

extern "C" __declspec(dllexport) int polygon_is_convex(const Point *pts, int n)
{
    if (pts == 0 || n < 3)
        return 0;
    int sign = 0;
    for (int i = 0; i < n; ++i) {
        int a = i;
        int b = (i + 1) % n;
        int c = (i + 2) % n;
        int o = seg_orientation(pts[a].x, pts[a].y,
                                pts[b].x, pts[b].y,
                                pts[c].x, pts[c].y);
        if (o == 0)
            continue;
        if (sign == 0) {
            sign = o;
        } else if (sign != o) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Transforms                                                         */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) void reflect_x(Point *p)
{
    if (p == 0)
        return;
    p->y = -p->y;
}

extern "C" __declspec(dllexport) void reflect_y(Point *p)
{
    if (p == 0)
        return;
    p->x = -p->x;
}

extern "C" __declspec(dllexport) void rotate90(Point *p, int times)
{
    if (p == 0)
        return;
    int t = times % 4;
    if (t < 0)
        t += 4;
    while (t > 0) {
        int nx = -p->y;
        int ny = p->x;
        p->x = nx;
        p->y = ny;
        --t;
    }
}

extern "C" __declspec(dllexport) void translate_all(Point *pts, int n, int dx, int dy)
{
    if (pts == 0)
        return;
    for (int i = 0; i < n; ++i) {
        pts[i].x += dx;
        pts[i].y += dy;
    }
}

extern "C" __declspec(dllexport) void scale_point(Point *p, int sx, int sy)
{
    if (p == 0)
        return;
    p->x *= sx;
    p->y *= sy;
}

/* ------------------------------------------------------------------ */
/* Classification / misc                                             */
/* ------------------------------------------------------------------ */

extern "C" __declspec(dllexport) int nearest_axis(int dx, int dy)
{
    int adx = dx < 0 ? -dx : dx;
    int ady = dy < 0 ? -dy : dy;
    if (adx == 0 && ady == 0)
        return 0;
    if (adx >= ady) {
        if (dx >= 0)
            return 1;   /* +X (east) */
        return 3;       /* -X (west) */
    }
    if (dy >= 0)
        return 2;       /* +Y (north) */
    return 4;           /* -Y (south) */
}

extern "C" __declspec(dllexport) int quadrant(int x, int y)
{
    switch ((x >= 0 ? 0 : 1) | (y >= 0 ? 0 : 2)) {
    case 0: return 1;   /* x>=0, y>=0 */
    case 1: return 2;   /* x<0,  y>=0 */
    case 3: return 3;   /* x<0,  y<0  */
    case 2: return 4;   /* x>=0, y<0  */
    default: return 0;
    }
}

extern "C" __declspec(dllexport) int gcd_i(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b != 0) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

extern "C" __declspec(dllexport) int collinear_count(const Point *pts, int n)
{
    if (pts == 0 || n < 3)
        return 0;
    int count = 0;
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            for (int k = j + 1; k < n; ++k) {
                if (cross3(pts[i].x, pts[i].y,
                           pts[j].x, pts[j].y,
                           pts[k].x, pts[k].y) == 0)
                    ++count;
            }
        }
    }
    return count;
}

extern "C" __declspec(dllexport) int farthest_index(const Point *pts, int n,
                                                    int ox, int oy)
{
    if (pts == 0 || n <= 0)
        return -1;
    int best = 0;
    int64_t bestd = dist_sq(pts[0].x, pts[0].y, ox, oy);
    for (int i = 1; i < n; ++i) {
        int64_t d = dist_sq(pts[i].x, pts[i].y, ox, oy);
        if (d > bestd) {
            bestd = d;
            best = i;
        }
    }
    return best;
}

extern "C" __declspec(dllexport) int triangle_classify(int ax, int ay,
                                                       int bx, int by,
                                                       int cx, int cy)
{
    int64_t a = dist_sq(bx, by, cx, cy);
    int64_t b = dist_sq(ax, ay, cx, cy);
    int64_t c = dist_sq(ax, ay, bx, by);
    if (cross3(ax, ay, bx, by, cx, cy) == 0)
        return 0;   /* degenerate */
    int eq = 0;
    if (a == b) ++eq;
    if (b == c) ++eq;
    if (a == c) ++eq;
    if (eq >= 2)
        return 3;   /* equilateral */
    if (eq == 1)
        return 2;   /* isosceles */
    return 1;       /* scalene */
}

extern "C" __declspec(dllexport) int64_t winding_sum(const Point *pts, int n)
{
    if (pts == 0 || n < 2)
        return 0;
    int64_t sum = 0;
    for (int i = 0; i < n; ++i) {
        int k = (i + 1) % n;
        sum += (int64_t)pts[i].x * (int64_t)pts[k].y
             - (int64_t)pts[k].x * (int64_t)pts[i].y;
    }
    return sum;
}

extern "C" __declspec(dllexport) int clamp_point(Point *p,
                                                 int minx, int miny,
                                                 int maxx, int maxy)
{
    if (p == 0)
        return 0;
    int changed = 0;
    if (p->x < minx) { p->x = minx; changed = 1; }
    else if (p->x > maxx) { p->x = maxx; changed = 1; }
    if (p->y < miny) { p->y = miny; changed = 1; }
    else if (p->y > maxy) { p->y = maxy; changed = 1; }
    return changed;
}
