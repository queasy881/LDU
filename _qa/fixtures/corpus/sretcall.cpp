/* sretcall.cpp - struct-return (sret) fixture WITH INTERNAL CALLERS.
 *
 * Every other corpus file exports leaf functions with no internal call sites, so
 * a struct-returning function has zero xrefs and there is no caller-side evidence
 * to recover the hidden return buffer from. MSVC x64 returns a struct that is not
 * 1/2/4/8 bytes through a caller-supplied pointer in RCX and hands it back in RAX,
 * and the ONLY way to tell that apart from `char* strcpy(char*, const char*)` --
 * which also writes through its first argument and returns it -- is that the
 * CALLER passes the address of a temporary it then reads as the result.
 *
 * So the makers below are deliberately called from exported wrappers in the same
 * image, giving that evidence. Build: cl /LD /Od /W3 sretcall.cpp
 */
#include <stdint.h>

typedef struct Vec2 { float x, y; } Vec2;
typedef struct Vec3 { float x, y, z; } Vec3;
typedef struct Vec4 { float x, y, z, w; } Vec4;

/* ---- the struct-returning makers (called internally, NOT exported) ---- */

static Vec2 mk2(float x, float y) { Vec2 v; v.x = x; v.y = y; return v; }
static Vec3 mk3(float x, float y, float z) { Vec3 v; v.x = x; v.y = y; v.z = z; return v; }
static Vec4 mk4(float x, float y, float z, float w) { Vec4 v; v.x = x; v.y = y; v.z = z; v.w = w; return v; }

/* 8 bytes exactly -> returned in RAX, NOT sret. Present so the detector has to
 * tell the two apart instead of assuming every struct return is indirect. */
static Vec2 mk2_byreg(float x, float y) { Vec2 v; v.x = x + 1.0f; v.y = y + 1.0f; return v; }

/* ---- exported wrappers that CALL them (this is the caller-side evidence) ---- */

extern "C" __declspec(dllexport) float sum2(float x, float y) {
    Vec2 v = mk2(x, y);
    return v.x + v.y;
}

extern "C" __declspec(dllexport) float sum3(float x, float y, float z) {
    Vec3 v = mk3(x, y, z);
    return v.x + v.y + v.z;
}

extern "C" __declspec(dllexport) float sum4(float x, float y, float z, float w) {
    Vec4 v = mk4(x, y, z, w);
    return v.x + v.y + v.z + v.w;
}

extern "C" __declspec(dllexport) float sum2_byreg(float x, float y) {
    Vec2 v = mk2_byreg(x, y);
    return v.x + v.y;
}

/* A genuine "writes through arg0 and returns it" function, so a detector that
 * keys on that shape alone is caught deleting a real parameter. */
extern "C" __declspec(dllexport) char *copy_bytes(char *dst, const char *src, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];
    }
    return dst;
}
