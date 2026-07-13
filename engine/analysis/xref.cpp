/*
 * xref.cpp — ds_engine_build_xrefs().
 *
 * The sweep already populated e->refs (one edge per control/data reference, in
 * instruction order, which is rva order after sorting). The query functions
 * ds_xrefs_to_count / ds_get_xrefs_to scan e->refs filtered by `to`, which is
 * correct and fast enough for interactive use.
 *
 * This pass:
 *   - de-duplicates identical (from,to,kind) edges so a target isn't listed
 *     twice for the same call site,
 *   - re-derives each function's call_count from the final ref set so the CFG
 *     pass and the xref view stay consistent,
 *   - leaves e->refs sorted by `to` (then `from`) so callers that want a
 *     contiguous range get one and the listing is stable.
 */
#include "disasm.h"
#include "engine_internal.h"

#include <algorithm>
#include <cstdint>

namespace {

size_t func_index_for_rva(const ds_engine* e, uint64_t rva) {
    /* find the function whose [rva, rva+size) contains `rva`; funcs sorted */
    if (e->func_len == 0) return SIZE_MAX;
    size_t lo = 0, hi = e->func_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->funcs[mid].rva <= rva) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return SIZE_MAX;
    size_t i = lo - 1;
    const ds_func* f = &e->funcs[i];
    if (rva >= f->rva && (f->size == 0 || rva < f->rva + f->size)) return i;
    /* if size is unknown/zero, accept membership up to the next function start */
    if (f->size == 0) {
        uint64_t next = (i + 1 < e->func_len) ? e->funcs[i + 1].rva : UINT64_MAX;
        if (rva >= f->rva && rva < next) return i;
    }
    return SIZE_MAX;
}

} // namespace

extern "C" int ds_engine_build_xrefs(ds_engine* e) {
    if (!e) return 1;

    if (e->ref_len > 1) {
        /* sort by (to, from, kind) */
        std::sort(e->refs, e->refs + e->ref_len,
                  [](const ds_ref& a, const ds_ref& b) {
                      if (a.to != b.to) return a.to < b.to;
                      if (a.from != b.from) return a.from < b.from;
                      return a.kind < b.kind;
                  });
        /* dedupe identical edges */
        size_t w = 1;
        for (size_t r = 1; r < e->ref_len; ++r) {
            const ds_ref& p = e->refs[w - 1];
            const ds_ref& c = e->refs[r];
            if (c.to == p.to && c.from == p.from && c.kind == p.kind) continue;
            if (w != r) e->refs[w] = e->refs[r];
            ++w;
        }
        e->ref_len = w;
    }

    /* re-derive call_count per function from CALL edges originating inside it.
     * This keeps the CFG-reported counts consistent with the xref database even
     * if function boundaries shifted. */
    if (e->func_len > 0) {
        for (size_t i = 0; i < e->func_len; ++i) e->funcs[i].call_count = 0;
        for (size_t i = 0; i < e->ref_len; ++i) {
            if (e->refs[i].kind != DS_XREF_CALL) continue;
            size_t fi = func_index_for_rva(e, e->refs[i].from);
            if (fi != SIZE_MAX) e->funcs[fi].call_count++;
        }
    }

    return 0;
}
