/*
 * engine_internal.h — the real definition of `struct ds_engine`, shared by the
 * C core (src/*.c) and the C++ analysis passes (analysis/*.cpp).
 *
 * Layout rule: only C PODs and (ptr,len,cap) triples live here so C and C++
 * agree on the struct layout. STL is allowed only *inside* a .cpp body, never
 * stored in this struct.
 */
#ifndef DS_ENGINE_INTERNAL_H
#define DS_ENGINE_INTERNAL_H

#include "disasm.h"
#include "vec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* a seeded symbol name attached to an rva (export / debug) */
typedef struct {
    uint64_t rva;
    char     name[96];
} ds_symbol;

/* a seeded import: the IAT slot rva a thunk dereferences + the function name */
typedef struct {
    uint64_t iat_rva;
    char     name[96];
} ds_import;

/* an internal cross-reference edge (kind uses DS_XREF_*) */
typedef struct {
    uint64_t from;
    uint64_t to;
    uint32_t kind;
} ds_ref;

struct ds_engine {
    /* image (not owned; caller keeps alive) */
    const uint8_t* image;
    size_t         image_size;
    uint64_t       base;
    ds_arch        arch;
    int            is_dll;
    uint64_t       entry_rva;
    int            entry_set;

    /* segments */
    ds_segment* segments;
    size_t      segment_len, segment_cap;

    /* seeded symbols */
    ds_symbol* symbols;
    size_t     symbol_len, symbol_cap;

    /* seeded entries (entry point, exports, tls callbacks) */
    uint64_t* entries;
    size_t    entry_len, entry_cap;

    /* seeded imports */
    ds_import* imports;
    size_t     import_len, import_cap;

    /* decoded instructions, kept sorted by rva (unique) */
    ds_insn* insns;
    size_t   insn_len, insn_cap;

    /* cross-references discovered during the sweep */
    ds_ref* refs;
    size_t  ref_len, ref_cap;

    /* recovered functions, sorted by rva (unique) */
    ds_func* funcs;
    size_t   func_len, func_cap;
};

/* ---- shared helpers used across translation units ------------------------ */

/* Return the segment covering `rva`, or NULL. */
const ds_segment* ds_seg_for_rva(const struct ds_engine* e, uint64_t rva);
/* Is `rva` inside an executable segment? */
int ds_rva_is_exec(const struct ds_engine* e, uint64_t rva);
/* Is `rva` inside any mapped segment? */
int ds_rva_is_mapped(const struct ds_engine* e, uint64_t rva);

/* Find the index of the first instruction with rva >= `rva`; SIZE_MAX if none.
 * Binary search over the sorted insns array. */
size_t ds_insn_lower_bound(const struct ds_engine* e, uint64_t rva);
/* Find the instruction with exactly this rva, or NULL. */
const ds_insn* ds_insn_at(const struct ds_engine* e, uint64_t rva);

/* Push a ref edge (no dedup). Returns 1 on success. */
int ds_push_ref(struct ds_engine* e, uint64_t from, uint64_t to, uint32_t kind);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DS_ENGINE_INTERNAL_H */
