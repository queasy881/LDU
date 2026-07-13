/*
 * vec.h — tiny realloc-based growable array helpers shared by the C core and
 * the C++ analysis passes. Header-only, no STL, no allocation tracking beyond
 * the (ptr,len,cap) triple embedded in each owning struct.
 *
 * Usage:
 *   ds_segment* segments; size_t segment_len, segment_cap;
 *   if (ds_vec_reserve((void**)&segments, &segment_cap, segment_len+1,
 *                      sizeof(ds_segment))) { segments[segment_len++] = s; }
 *
 * All helpers are bounds/OOM safe: on allocation failure they leave the array
 * untouched and return 0 so callers can bail without UB.
 */
#ifndef DS_VEC_H
#define DS_VEC_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ensure capacity for at least `need` elements of `elem` bytes each.
 * Grows geometrically (1.5x) to keep amortized push O(1). Returns 1 on success,
 * 0 on allocation failure (array left unchanged). */
static inline int ds_vec_reserve(void** data, size_t* cap, size_t need, size_t elem) {
    if (need <= *cap) return 1;
    size_t ncap = *cap ? *cap : 8;
    while (ncap < need) {
        size_t grown = ncap + (ncap >> 1) + 1;
        if (grown <= ncap) { ncap = need; break; } /* overflow guard */
        ncap = grown;
    }
    /* overflow check on the byte count */
    if (elem && ncap > (size_t)-1 / elem) return 0;
    void* p = realloc(*data, ncap * elem);
    if (!p) return 0;
    *data = p;
    *cap = ncap;
    return 1;
}

/* Free and reset an owning triple. */
static inline void ds_vec_free(void** data, size_t* len, size_t* cap) {
    free(*data);
    *data = NULL;
    *len = 0;
    *cap = 0;
}

/* Copy a C string into a fixed-size char buffer, always NUL-terminated,
 * truncating if necessary. Safe for NULL src (writes empty string). */
static inline void ds_strlcpy(char* dst, const char* src, size_t cap) {
    if (!cap) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    for (; i + 1 < cap && src[i]; ++i) dst[i] = src[i];
    dst[i] = '\0';
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DS_VEC_H */
