/*
 * sweep.c — ds_engine_disassemble().
 *
 * Strategy:
 *   1. Linear sweep across every executable segment so straight-line code is
 *      covered exhaustively.
 *   2. Recursive descent from all seeded entries/exports/import-targets and
 *      from every call/branch target discovered along the way, so code reached
 *      only via calls (and not contiguous with already-swept code) is picked up.
 *   3. Dedupe by rva, sort once by rva, then record cross-reference edges.
 *
 * Safety: every decode is bounds-checked inside the decoder; the sweep caps the
 * total instruction count and tracks visited rvas so it can never loop forever.
 */
#include "engine_internal.h"
#include "decoder.h"
#include "cs_decode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Decode one instruction through capstone when a handle is available, otherwise
 * via the built-in decoder. `dec` is the capstone handle (or NULL). */
static uint8_t decode_one(void* dec, const uint8_t* p, size_t avail,
                          uint64_t rva, int is64, ds_insn* ins) {
#ifdef DS_USE_CAPSTONE
    if (dec) return ds_cs_decode(dec, p, avail, rva, is64, ins);
#endif
    (void)dec;
    return ds_decode(p, avail, rva, is64, ins);
}

/* hard cap to guard against pathological inputs */
#define DS_MAX_INSNS (8u * 1024u * 1024u)

/* A simple open-addressing hash set of visited rvas. We use it to dedupe both
 * the linear and recursive sweeps cheaply without re-scanning the insn array. */
typedef struct {
    uint64_t* slots; /* slot value, 0 == empty (rva 0 stored via `has_zero`) */
    size_t    cap;   /* power of two */
    size_t    len;
    int       has_zero;
} rvaset;

static int rvaset_init(rvaset* s, size_t cap_hint) {
    size_t cap = 1024;
    while (cap < cap_hint * 2) cap <<= 1;
    s->slots = (uint64_t*)calloc(cap, sizeof(uint64_t));
    if (!s->slots) return 0;
    s->cap = cap;
    s->len = 0;
    s->has_zero = 0;
    return 1;
}
static void rvaset_free(rvaset* s) { free(s->slots); s->slots = NULL; }

static int rvaset_grow(rvaset* s);

/* returns 1 if newly inserted, 0 if already present (or OOM treated as present) */
static int rvaset_add(rvaset* s, uint64_t v) {
    if (v == 0) {
        if (s->has_zero) return 0;
        s->has_zero = 1;
        s->len++;
        return 1;
    }
    if ((s->len + 1) * 4 >= s->cap * 3) {
        if (!rvaset_grow(s)) return 0;
    }
    size_t mask = s->cap - 1;
    size_t h = (size_t)((v * 0x9E3779B97F4A7C15ull) >> 24) & mask;
    while (s->slots[h] != 0) {
        if (s->slots[h] == v) return 0;
        h = (h + 1) & mask;
    }
    s->slots[h] = v;
    s->len++;
    return 1;
}

static int rvaset_has(const rvaset* s, uint64_t v) {
    if (v == 0) return s->has_zero;
    size_t mask = s->cap - 1;
    size_t h = (size_t)((v * 0x9E3779B97F4A7C15ull) >> 24) & mask;
    while (s->slots[h] != 0) {
        if (s->slots[h] == v) return 1;
        h = (h + 1) & mask;
    }
    return 0;
}

static int rvaset_grow(rvaset* s) {
    size_t ncap = s->cap << 1;
    uint64_t* ns = (uint64_t*)calloc(ncap, sizeof(uint64_t));
    if (!ns) return 0;
    size_t mask = ncap - 1;
    for (size_t i = 0; i < s->cap; ++i) {
        uint64_t v = s->slots[i];
        if (!v) continue;
        size_t h = (size_t)((v * 0x9E3779B97F4A7C15ull) >> 24) & mask;
        while (ns[h] != 0) h = (h + 1) & mask;
        ns[h] = v;
    }
    free(s->slots);
    s->slots = ns;
    s->cap = ncap;
    return 1;
}

/* pointer into the flat image for a given rva, or NULL if not mapped/in range */
static const uint8_t* image_ptr(const struct ds_engine* e, uint64_t rva, size_t* avail) {
    if (rva >= e->image_size) { *avail = 0; return NULL; }
    *avail = e->image_size - (size_t)rva;
    return e->image + rva;
}

static int push_insn(struct ds_engine* e, const ds_insn* ins) {
    if (e->insn_len >= DS_MAX_INSNS) return 0;
    if (!ds_vec_reserve((void**)&e->insns, &e->insn_cap, e->insn_len + 1, sizeof(ds_insn)))
        return 0;
    e->insns[e->insn_len++] = *ins;
    return 1;
}

/* qsort comparator by rva */
static int cmp_insn(const void* a, const void* b) {
    uint64_t ra = ((const ds_insn*)a)->rva;
    uint64_t rb = ((const ds_insn*)b)->rva;
    if (ra < rb) return -1;
    if (ra > rb) return 1;
    return 0;
}

/* a small worklist of code starts to descend from */
typedef struct { uint64_t* v; size_t len, cap; } worklist;
static int wl_push(worklist* w, uint64_t rva) {
    if (!ds_vec_reserve((void**)&w->v, &w->cap, w->len + 1, sizeof(uint64_t)))
        return 0;
    w->v[w->len++] = rva;
    return 1;
}

/* Decode a run of straight-line instructions starting at `start`, stopping at a
 * terminating control-flow op (ret/unconditional jmp) or when leaving the
 * executable segment / hitting an already-visited rva. New call/branch targets
 * are pushed onto the worklist. */
static void sweep_run(struct ds_engine* e, uint64_t start, int is64,
                      rvaset* visited, worklist* wl, int linear_mode, void* dec) {
    uint64_t rva = start;
    while (e->insn_len < DS_MAX_INSNS) {
        if (!ds_rva_is_exec(e, rva)) return;
        /* In recursive mode, stop when we hit code we already decoded so we
         * don't re-walk. In linear mode the caller advances past visited. */
        if (!linear_mode && rvaset_has(visited, rva)) return;

        size_t avail = 0;
        const uint8_t* p = image_ptr(e, rva, &avail);
        if (!p || avail == 0) return;
        if (avail > 15) avail = 15;

        ds_insn ins;
        uint8_t len = decode_one(dec, p, avail, rva, is64, &ins);
        if (len == 0) len = 1;

        int newly = rvaset_add(visited, rva);
        if (newly) {
            if (!push_insn(e, &ins)) return;
        }

        /* queue control-flow targets for recursive descent */
        if (ins.ref_target != 0 &&
            (ins.ref_type == DS_REF_CALL || ins.ref_type == DS_REF_JMP ||
             ins.ref_type == DS_REF_BRANCH)) {
            if (ds_rva_is_exec(e, ins.ref_target) && !rvaset_has(visited, ins.ref_target))
                wl_push(wl, ins.ref_target);
        }

        /* terminate the straight-line run at ret / unconditional jmp.
         * conditional branches and calls fall through. */
        if (ins.ref_type == DS_REF_JMP) return;
        if (ins.mnemonic[0] == 'r' && ins.mnemonic[1] == 'e' &&
            ins.mnemonic[2] == 't') return; /* ret / retf */
        if (ins.mnemonic[0] == 'h' && ins.mnemonic[1] == 'l' &&
            ins.mnemonic[2] == 't') return; /* hlt */

        uint64_t next = rva + len;
        if (next <= rva) return; /* overflow guard */
        rva = next;
    }
}

/* little-endian u32 over the flat RVA image (bounds-checked) */
static int sweep_rd_u32(const struct ds_engine* e, uint64_t rva, uint32_t* out) {
    if (rva + 4 > e->image_size) return 0;
    *out = (uint32_t)e->image[rva] | ((uint32_t)e->image[rva+1] << 8) |
           ((uint32_t)e->image[rva+2] << 16) | ((uint32_t)e->image[rva+3] << 24);
    return 1;
}

/* Seed function entries from the x64 exception directory (.pdata). Each
 * RUNTIME_FUNCTION.BeginAddress is an AUTHORITATIVE function (or funclet) start —
 * IDA's primary function source — so this recovers functions that are neither
 * directly called nor address-taken (reached only via .pdata / indirect paths),
 * e.g. a DllMain-dispatched worker with a full cookie prologue. CHAINED entries
 * (UNW_FLAG_CHAININFO) are code FRAGMENTS of an existing function, not new
 * functions, so they are skipped (seeding one would split a real function).
 * Gated by DS_NO_PDATASEED. */
static void seed_pdata_entries(struct ds_engine* e) {
    if (!e || !e->image || getenv("DS_NO_PDATASEED")) return;
    if (e->arch != DS_ARCH_X64) return;                 /* .pdata layout is x64-specific */
    uint64_t pr = 0, psz = 0;
    for (size_t i = 0; i < e->segment_len; ++i)
        if (strncmp(e->segments[i].name, ".pdata", sizeof e->segments[i].name) == 0) {
            pr = e->segments[i].rva; psz = e->segments[i].size; break;
        }
    if (!pr || !psz) return;
    size_t n = (size_t)(psz / 12), added = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t base = pr + (uint64_t)i * 12;
        uint32_t begin, end, unwind;
        if (!sweep_rd_u32(e, base, &begin) || !sweep_rd_u32(e, base + 4, &end) ||
            !sweep_rd_u32(e, base + 8, &unwind)) break;
        if (begin == 0 && end == 0 && unwind == 0) break;   /* zero terminator */
        if (end <= begin) continue;
        if (!ds_rva_is_exec(e, begin)) continue;
        /* UNWIND_INFO byte0 = Version(3):Flags(5); Flags bit 2 = UNW_FLAG_CHAININFO */
        if (unwind + 1 <= e->image_size) {
            uint8_t vf = e->image[unwind];
            if ((vf >> 3) & 0x4) continue;                  /* chained fragment: skip */
        }
        ds_engine_add_entry(e, begin);
        added++;
    }
    if (getenv("DS_DBG_PDATASEED"))
        fprintf(stderr, "[pdataseed] seeded %zu .pdata function entries\n", added);
}

int ds_engine_disassemble(ds_engine* e) {
    if (!e) return 1;
    if (e->image_size == 0) return 0; /* nothing to do, not an error */
    seed_pdata_entries(e);

    int is64 = (e->arch == DS_ARCH_X64);
    /* ARM/ARM64 are not decoded by this built-in backend; produce an empty (but
     * valid) listing rather than mis-decoding. The contract's default path is
     * x86/x64 only. */
    if (e->arch == DS_ARCH_ARM || e->arch == DS_ARCH_ARM64)
        return 0;

    rvaset visited;
    /* size hint: roughly one instruction per 3 image bytes */
    if (!rvaset_init(&visited, e->image_size / 3 + 64)) return 2;

    /* Open the capstone decode handle for this run (NULL -> built-in decoder). */
    void* dec = ds_cs_open_arch((int)e->arch, is64);

    worklist wl;
    memset(&wl, 0, sizeof(wl));

    /* seed the worklist with all known code starts */
    if (e->entry_set) wl_push(&wl, e->entry_rva);
    for (size_t i = 0; i < e->entry_len; ++i) wl_push(&wl, e->entries[i]);
    for (size_t i = 0; i < e->symbol_len; ++i) {
        if (ds_rva_is_exec(e, e->symbols[i].rva)) wl_push(&wl, e->symbols[i].rva);
    }

    /* (1) linear sweep over each executable segment */
    for (size_t si = 0; si < e->segment_len && e->insn_len < DS_MAX_INSNS; ++si) {
        const ds_segment* s = &e->segments[si];
        if (!(s->flags & DS_FLAG_X)) continue;
        uint64_t rva = s->rva;
        uint64_t end = s->rva + s->size;
        if (end < s->rva) continue; /* overflow */
        while (rva < end && e->insn_len < DS_MAX_INSNS) {
            if (rvaset_has(&visited, rva)) {
                /* already decoded here; advance by that instruction's length */
                const ds_insn* at = ds_insn_at(e, rva);
                uint64_t step = at && at->size ? at->size : 1;
                /* note: at may be NULL if not yet pushed in this pass ordering;
                 * fall back to a 1-byte step which is always safe */
                rva += step;
                continue;
            }
            size_t avail = 0;
            const uint8_t* p = image_ptr(e, rva, &avail);
            if (!p || avail == 0) break;
            if (avail > 15) avail = 15;
            if (rva + 16 > end) {
                size_t seg_avail = (size_t)(end - rva);
                if (seg_avail < avail) avail = seg_avail;
            }
            ds_insn ins;
            uint8_t len = decode_one(dec, p, avail, rva, is64, &ins);
            if (len == 0) len = 1;
            if (rvaset_add(&visited, rva)) {
                if (!push_insn(e, &ins)) break;
            }
            if (ins.ref_target != 0 &&
                (ins.ref_type == DS_REF_CALL || ins.ref_type == DS_REF_JMP ||
                 ins.ref_type == DS_REF_BRANCH)) {
                if (ds_rva_is_exec(e, ins.ref_target))
                    wl_push(&wl, ins.ref_target);
            }
            uint64_t next = rva + len;
            if (next <= rva) break;
            rva = next;
        }
    }

    /* (2) recursive descent from the worklist. The linear pass already covered
     * most code; this fills in targets that landed mid-instruction-stream or in
     * segments that weren't linearly contiguous, and re-decodes overlapping code
     * paths reached only via calls. */
    size_t guard = 0;
    while (wl.len > 0 && e->insn_len < DS_MAX_INSNS) {
        if (++guard > DS_MAX_INSNS) break;
        uint64_t target = wl.v[--wl.len];
        if (rvaset_has(&visited, target)) continue;
        if (!ds_rva_is_exec(e, target)) continue;
        sweep_run(e, target, is64, &visited, &wl, 0, dec);
    }

    free(wl.v);
    rvaset_free(&visited);
    ds_cs_close(dec);

    /* (3) sort by rva. After sorting, drop any exact-duplicate rvas that may
     * have slipped in (defensive; the visited set should prevent them). */
    if (e->insn_len > 1) {
        qsort(e->insns, e->insn_len, sizeof(ds_insn), cmp_insn);
        size_t w = 1;
        for (size_t r = 1; r < e->insn_len; ++r) {
            if (e->insns[r].rva != e->insns[w - 1].rva) {
                if (w != r) e->insns[w] = e->insns[r];
                ++w;
            }
        }
        e->insn_len = w;
    }

    /* (4) record cross-reference edges from the final instruction set */
    for (size_t i = 0; i < e->insn_len; ++i) {
        const ds_insn* ins = &e->insns[i];
        if (ins->ref_target == 0 || ins->ref_type == DS_REF_NONE) continue;
        uint32_t kind;
        switch (ins->ref_type) {
            case DS_REF_CALL:   kind = DS_XREF_CALL; break;
            case DS_REF_JMP:    kind = DS_XREF_JMP;  break;
            case DS_REF_BRANCH: kind = DS_XREF_JMP;  break; /* cond branch -> jmp xref */
            case DS_REF_DATA:   kind = DS_XREF_DATA; break;
            default: continue;
        }
        ds_push_ref(e, ins->rva, ins->ref_target, kind);
    }

    return 0;
}
