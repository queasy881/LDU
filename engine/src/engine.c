/*
 * engine.c — lifecycle, seeding setters, and read-only queries for ds_engine.
 *
 * The disassembly sweep lives in sweep.c; CFG / symbol / xref passes live in
 * the C++ files under analysis/. Everything here is plain C and never throws.
 */
#include "engine_internal.h"

#include <string.h>

/* ---- shared helpers (declared in engine_internal.h) ---------------------- */

const ds_segment* ds_seg_for_rva(const struct ds_engine* e, uint64_t rva) {
    for (size_t i = 0; i < e->segment_len; ++i) {
        const ds_segment* s = &e->segments[i];
        if (rva >= s->rva && rva < s->rva + s->size) return s;
    }
    return NULL;
}

int ds_rva_is_exec(const struct ds_engine* e, uint64_t rva) {
    const ds_segment* s = ds_seg_for_rva(e, rva);
    return s && (s->flags & DS_FLAG_X);
}

int ds_rva_is_mapped(const struct ds_engine* e, uint64_t rva) {
    return ds_seg_for_rva(e, rva) != NULL;
}

size_t ds_insn_lower_bound(const struct ds_engine* e, uint64_t rva) {
    size_t lo = 0, hi = e->insn_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->insns[mid].rva < rva) lo = mid + 1;
        else hi = mid;
    }
    return (lo < e->insn_len) ? lo : SIZE_MAX;
}

const ds_insn* ds_insn_at(const struct ds_engine* e, uint64_t rva) {
    size_t idx = ds_insn_lower_bound(e, rva);
    if (idx == SIZE_MAX) return NULL;
    if (e->insns[idx].rva == rva) return &e->insns[idx];
    return NULL;
}

int ds_push_ref(struct ds_engine* e, uint64_t from, uint64_t to, uint32_t kind) {
    if (!ds_vec_reserve((void**)&e->refs, &e->ref_cap, e->ref_len + 1, sizeof(ds_ref)))
        return 0;
    ds_ref* r = &e->refs[e->ref_len++];
    r->from = from;
    r->to = to;
    r->kind = kind;
    return 1;
}

/* ---- lifecycle ----------------------------------------------------------- */

ds_engine* ds_engine_create(const uint8_t* image, size_t image_size,
                            uint64_t base, ds_arch arch) {
    struct ds_engine* e = (struct ds_engine*)calloc(1, sizeof(struct ds_engine));
    if (!e) return NULL;
    e->image = image;
    e->image_size = image_size;
    e->base = base;
    e->arch = arch;
    e->is_dll = 0;
    e->entry_rva = 0;
    e->entry_set = 0;
    return e;
}

void ds_engine_destroy(ds_engine* e) {
    if (!e) return;
    free(e->segments);
    free(e->symbols);
    free(e->entries);
    free(e->imports);
    free(e->insns);
    free(e->refs);
    free(e->funcs);
    free(e->annos);
    free(e->anno_vars);
    free(e);
}

/* ---- seeding ------------------------------------------------------------- */

void ds_engine_add_segment(ds_engine* e, const char* name,
                           uint64_t rva, uint64_t size, uint32_t flags) {
    if (!e) return;
    if (!ds_vec_reserve((void**)&e->segments, &e->segment_cap,
                        e->segment_len + 1, sizeof(ds_segment)))
        return;
    ds_segment* s = &e->segments[e->segment_len++];
    memset(s, 0, sizeof(*s));
    ds_strlcpy(s->name, name, sizeof(s->name));
    s->rva = rva;
    s->size = size;
    s->flags = flags;
}

void ds_engine_add_symbol(ds_engine* e, uint64_t rva, const char* name) {
    if (!e) return;
    if (!ds_vec_reserve((void**)&e->symbols, &e->symbol_cap,
                        e->symbol_len + 1, sizeof(ds_symbol)))
        return;
    ds_symbol* s = &e->symbols[e->symbol_len++];
    s->rva = rva;
    ds_strlcpy(s->name, name, sizeof(s->name));
}

void ds_engine_add_entry(ds_engine* e, uint64_t rva) {
    if (!e) return;
    /* dedupe */
    for (size_t i = 0; i < e->entry_len; ++i)
        if (e->entries[i] == rva) return;
    if (!ds_vec_reserve((void**)&e->entries, &e->entry_cap,
                        e->entry_len + 1, sizeof(uint64_t)))
        return;
    e->entries[e->entry_len++] = rva;
}

void ds_engine_add_import(ds_engine* e, uint64_t iat_rva, const char* name) {
    if (!e) return;
    if (!ds_vec_reserve((void**)&e->imports, &e->import_cap,
                        e->import_len + 1, sizeof(ds_import)))
        return;
    ds_import* im = &e->imports[e->import_len++];
    im->iat_rva = iat_rva;
    ds_strlcpy(im->name, name, sizeof(im->name));
}

void ds_engine_set_is_dll(ds_engine* e, int is_dll) {
    if (e) e->is_dll = is_dll ? 1 : 0;
}

void ds_engine_set_entry_rva(ds_engine* e, uint64_t rva) {
    if (!e) return;
    e->entry_rva = rva;
    e->entry_set = 1;
    ds_engine_add_entry(e, rva);
}

/* ---- analysis driver ----------------------------------------------------- */

int ds_engine_analyze(ds_engine* e) {
    if (!e) return 1;
    int rc;
    if ((rc = ds_engine_disassemble(e)) != 0) return rc;
    if ((rc = ds_engine_build_cfg(e)) != 0) return rc;
    if ((rc = ds_engine_resolve_symbols(e)) != 0) return rc;
    if ((rc = ds_engine_build_xrefs(e)) != 0) return rc;
    return 0;
}

/* ---- queries ------------------------------------------------------------- */

void ds_engine_get_meta(ds_engine* e, ds_meta* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!e) return;
    out->arch = e->arch;
    out->base = e->base;
    out->entry = e->entry_set ? e->entry_rva : 0;
    out->image_size = e->image_size;
    out->segment_count = e->segment_len;
    out->function_count = e->func_len;
    out->instruction_count = e->insn_len;
}

size_t ds_segment_count(ds_engine* e) { return e ? e->segment_len : 0; }

size_t ds_get_segments(ds_engine* e, ds_segment* out, size_t max) {
    if (!e || !out) return 0;
    size_t n = e->segment_len < max ? e->segment_len : max;
    for (size_t i = 0; i < n; ++i) out[i] = e->segments[i];
    return n;
}

size_t ds_function_count(ds_engine* e) { return e ? e->func_len : 0; }

size_t ds_get_functions(ds_engine* e, ds_func* out, size_t max) {
    if (!e || !out) return 0;
    size_t n = e->func_len < max ? e->func_len : max;
    for (size_t i = 0; i < n; ++i) out[i] = e->funcs[i];
    return n;
}

size_t ds_instruction_count(ds_engine* e) { return e ? e->insn_len : 0; }

size_t ds_disasm_range(ds_engine* e, size_t start_index, size_t count, ds_insn* out) {
    if (!e || !out) return 0;
    if (start_index >= e->insn_len) return 0;
    size_t avail = e->insn_len - start_index;
    size_t n = count < avail ? count : avail;
    for (size_t i = 0; i < n; ++i) out[i] = e->insns[start_index + i];
    return n;
}

size_t ds_index_for_rva(ds_engine* e, uint64_t rva) {
    if (!e || e->insn_len == 0) return SIZE_MAX;
    return ds_insn_lower_bound(e, rva);
}

size_t ds_xrefs_to_count(ds_engine* e, uint64_t rva) {
    if (!e) return 0;
    size_t n = 0;
    for (size_t i = 0; i < e->ref_len; ++i)
        if (e->refs[i].to == rva) ++n;
    return n;
}

size_t ds_get_xrefs_to(ds_engine* e, uint64_t rva, ds_xref* out, size_t max) {
    if (!e || !out) return 0;
    size_t n = 0;
    for (size_t i = 0; i < e->ref_len && n < max; ++i) {
        if (e->refs[i].to != rva) continue;
        out[n].from_rva = e->refs[i].from;
        out[n].to_rva = e->refs[i].to;
        out[n].kind = e->refs[i].kind;
        out[n]._pad = 0;
        ++n;
    }
    return n;
}
