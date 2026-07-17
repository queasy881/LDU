/* FEATURE FIXTURE: subscript on a STRUCT-POINTER FIELD.
 *
 * `*(int*)((char*)a1->field_10 + i*4)` is what the machine does when a struct field holds a
 * pointer that is then indexed; `a1->field_10[i]` is what the source said. The plain-variable
 * form of this (try_array_subscript) already works; the field-base form does not, and it is
 * 1900+ sites on NullWare.
 *
 * Build: cl /nologo /O2 /LD /TC feat_fieldsub.c
 */
#include <stdint.h>

typedef struct {
    int32_t  count;
    int32_t* items;     /* field at offset 8: an int32_t* -- indexing it must scale by 4 */
    int64_t* longs;     /* field at offset 16: an int64_t* -- must scale by 8 */
    char*    bytes;     /* field at offset 24: a char* -- no scaling */
} Buf;

/* sum via a variable index -> a1->items[i] */
__declspec(dllexport) int32_t fs_sum(Buf* b) {
    int32_t s = 0;
    for (int32_t i = 0; i < b->count; i++) s += b->items[i];
    return s;
}
/* an 8-byte-element field -> a1->longs[i], scaled by 8 */
__declspec(dllexport) int64_t fs_sum64(Buf* b, int32_t n) {
    int64_t s = 0;
    for (int32_t i = 0; i < n; i++) s += b->longs[i];
    return s;
}
/* a char field -> a1->bytes[i], unscaled */
__declspec(dllexport) int32_t fs_bytes(Buf* b, int32_t n) {
    int32_t s = 0;
    for (int32_t i = 0; i < n; i++) s += b->bytes[i];
    return s;
}
/* a CONSTANT index -> a1->items[3] */
__declspec(dllexport) int32_t fs_const(Buf* b) {
    return b->items[3] + b->longs[1];
}
