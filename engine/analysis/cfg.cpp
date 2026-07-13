/*
 * cfg.cpp — ds_engine_build_cfg().
 *
 * Recovers the function set and a basic-block / call count per function:
 *   function starts = seeded entries (entry, exports, import targets, tls)
 *                     UNION call-instruction targets
 *                     UNION prologue-detected starts
 *   function end    = next function start, or the first ret/unconditional-jmp
 *                     that isn't re-entered by an internal branch.
 *   block_count     = number of basic blocks (split at branches and at any rva
 *                     inside the function that is a branch/call/jump target).
 *   call_count      = number of call instructions in the function body.
 *
 * Only the C PODs in engine_internal are touched; STL is used locally.
 */
#include "disasm.h"
#include "engine_internal.h"

#include <algorithm>
#include <vector>
#include <set>
#include <cstring>
#include <cstdint>

namespace {

/* Find the insn array index for an exact rva, or SIZE_MAX. Binary search. */
size_t insn_index_exact(const ds_engine* e, uint64_t rva) {
    size_t lo = 0, hi = e->insn_len;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (e->insns[mid].rva < rva) lo = mid + 1;
        else hi = mid;
    }
    if (lo < e->insn_len && e->insns[lo].rva == rva) return lo;
    return SIZE_MAX;
}

bool mnem_is(const ds_insn* in, const char* m) {
    return std::strncmp(in->mnemonic, m, sizeof(in->mnemonic)) == 0;
}
bool is_ret(const ds_insn* in) {
    return in->mnemonic[0] == 'r' && in->mnemonic[1] == 'e' && in->mnemonic[2] == 't';
}

/* the first register token inside `[...]` of an Intel-syntax memory operand. */
bool mem_base_reg(const char* ops, char* out, size_t outsz) {
    const char* lb = std::strchr(ops, '[');
    if (!lb) return false;
    ++lb; while (*lb == ' ') ++lb;
    size_t i = 0;
    while (*lb && *lb!=' ' && *lb!='+' && *lb!=']' && *lb!='*' && i+1 < outsz)
        out[i++] = *lb++;
    out[i] = 0;
    return i > 0;
}
/* the destination register (text before the first ','). */
bool dest_reg(const char* ops, char* out, size_t outsz) {
    size_t i = 0;
    for (const char* p = ops; *p && *p!=',' && *p!=' ' && i+1 < outsz; ++p) out[i++] = *p;
    out[i] = 0;
    return i > 0;
}
/* the signed `rip ± 0xN` displacement of a rip-relative operand. */
bool rip_disp(const char* ops, int64_t* disp) {
    const char* p = std::strstr(ops, "rip");
    if (!p) return false;
    p += 3; while (*p == ' ') ++p;
    int sign = 1;
    if (*p == '+') ++p; else if (*p == '-') { sign = -1; ++p; } else return false;
    while (*p == ' ') ++p;
    if (p[0] != '0' || (p[1] != 'x' && p[1] != 'X')) return false;
    *disp = sign * (int64_t)std::strtoull(p, nullptr, 16);
    return true;
}
/* the LAST `0x...` displacement inside `[...]` (the table offset of a scaled load). */
bool last_mem_disp(const char* ops, int64_t* disp) {
    const char* lb = std::strchr(ops, '[');
    const char* rb = std::strrchr(ops, ']');
    if (!lb || !rb || rb < lb) return false;
    const char* best = nullptr;
    for (const char* p = lb; p < rb; ++p)
        if (p[0]=='0' && (p[1]=='x'||p[1]=='X')) best = p;
    if (!best) return false;
    *disp = (int64_t)std::strtoull(best, nullptr, 16);
    return true;
}

/* Resolve a register-indirect `jmp reg` jump table by reading its .rdata table and
 * return the highest case-target RVA (or 0 if not a resolvable table). The dispatch
 * is the MSVC form `lea B,[rip±X]; mov r32,dword[B + idx*4 + OFF]; add tgt,B; jmp tgt`
 * — targets are `B_rva + table[i]`, table at `B_rva + OFF`. Reading the actual table
 * gives a PRECISE function extent (no over-extension into a following tail-call fn). */
uint64_t resolve_jumptable_max(const ds_engine* e, size_t jmp_idx,
                               uint64_t fstart, uint64_t seg_end) {
    const ds_insn* jmp = &e->insns[jmp_idx];
    if (!mnem_is(jmp, "jmp")) return 0;
    if (jmp->ref_type == DS_REF_JMP || jmp->ref_type == DS_REF_BRANCH) return 0;
    if (std::strchr(jmp->operands, '[')) return 0;          /* memory-indirect: skip */

    int64_t table_disp = -1; char base[16] = {0};
    int64_t lea_target = -1;
    size_t lo = (jmp_idx > 30) ? jmp_idx - 30 : 0;
    /* the scaled table load (gives OFF and the base register) */
    for (size_t k = jmp_idx; k-- > lo; ) {
        const ds_insn* in = &e->insns[k];
        if (mnem_is(in, "mov") && std::strstr(in->operands, "*4") &&
            last_mem_disp(in->operands, &table_disp) &&
            mem_base_reg(in->operands, base, sizeof base)) break;
        table_disp = -1;
    }
    if (table_disp < 0 || !base[0]) return 0;
    /* the `lea base, [rip±X]` that set that base register */
    for (size_t k = jmp_idx; k-- > lo; ) {
        const ds_insn* in = &e->insns[k];
        if (!mnem_is(in, "lea") || !std::strstr(in->operands, "rip")) continue;
        char dr[16]; int64_t d;
        if (dest_reg(in->operands, dr, sizeof dr) && std::strcmp(dr, base) == 0 &&
            rip_disp(in->operands, &d)) {
            lea_target = (int64_t)(in->rva + in->size) + d;
            break;
        }
    }
    if (lea_target < 0) return 0;

    uint64_t table_rva = (uint64_t)(lea_target + table_disp);
    uint64_t maxtgt = 0; int valid = 0;
    for (int i = 0; i < 1024; ++i) {
        uint64_t er = table_rva + (uint64_t)i * 4;
        if (er + 4 > e->image_size) break;
        int32_t entry = (int32_t)((uint32_t)e->image[er] | ((uint32_t)e->image[er+1]<<8) |
                                  ((uint32_t)e->image[er+2]<<16) | ((uint32_t)e->image[er+3]<<24));
        uint64_t tgt = (uint64_t)(lea_target + entry);
        if (tgt < fstart || tgt >= seg_end) break;        /* outside function range */
        if (insn_index_exact(e, tgt) == SIZE_MAX) break;  /* not an instruction start */
        if (tgt > maxtgt) maxtgt = tgt;
        ++valid;
    }
    return (valid >= 2) ? maxtgt : 0;   /* require a real table */
}

} // namespace

extern "C" int ds_engine_build_cfg(ds_engine* e) {
    if (!e) return 1;
    /* clear any previous result */
    e->func_len = 0;

    if (e->insn_len == 0) return 0;

    /* recover C++ class/virtual-function names from MSVC RTTI and seed them as
     * symbols BEFORE function-start collection: a vtable-only virtual (never
     * directly called) is then picked up by the e->symbols[] pass below and both
     * recovered as a function and named. Must precede `consider(symbols)`. */
    ds_engine_scan_rtti(e);

    /* ---- collect function-start RVAs ---- */
    std::set<uint64_t> starts;

    auto consider = [&](uint64_t rva) {
        if (insn_index_exact(e, rva) != SIZE_MAX && ds_rva_is_exec(e, rva))
            starts.insert(rva);
    };

    if (e->entry_set) consider(e->entry_rva);
    for (size_t i = 0; i < e->entry_len; ++i) consider(e->entries[i]);
    for (size_t i = 0; i < e->symbol_len; ++i) consider(e->symbols[i].rva);

    /* call targets are function starts */
    for (size_t i = 0; i < e->insn_len; ++i) {
        const ds_insn* in = &e->insns[i];
        if (in->ref_type == DS_REF_CALL && in->ref_target)
            consider(in->ref_target);
    }

    /* prologue detection: push rbp; mov rbp,rsp  | sub rsp, imm  | push regs run.
     * We scan the listing and flag an instruction as a likely function start
     * when it begins a recognizable prologue and isn't already covered. */
    /* A prologue-detected start is only a real function boundary when the
     * PRECEDING instruction is a terminator (ret/jmp/int3) or non-contiguous.
     * Without this, a frame setup that sits MID-prologue is wrongly flagged —
     * e.g. a function that saves nonvolatiles (`mov [rsp+8], rbx; mov [rsp+0x10],
     * rdi`) before its `push rbp; mov rbp,rsp` gets split in two at the push. */
    auto at_boundary = [&](size_t i) -> bool {
        if (i == 0) return true;
        const ds_insn* prev = &e->insns[i - 1];
        /* ud2/hlt are hard terminators (execution never continues past them) just
         * like ret/jmp/int3 — Rust and MSVC emit `ud2` for an unreachable/panic
         * tail, so a real function whose prologue directly follows one was NOT
         * recognized as a boundary and got MERGED into the preceding function,
         * corrupting register tracking (`mov rsi,rcx` in the merged body leaked
         * in_RSI). */
        return is_ret(prev) || mnem_is(prev, "jmp") || mnem_is(prev, "int3") ||
               mnem_is(prev, "ud2") || mnem_is(prev, "hlt") ||
               prev->rva + prev->size != e->insns[i].rva;
    };
    for (size_t i = 0; i < e->insn_len; ++i) {
        const ds_insn* in = &e->insns[i];
        if (!ds_rva_is_exec(e, in->rva)) continue;

        /* push rbp ; mov rbp, rsp */
        if (mnem_is(in, "push") &&
            (std::strstr(in->operands, "rbp") || std::strstr(in->operands, "ebp"))) {
            if (i + 1 < e->insn_len) {
                const ds_insn* n = &e->insns[i + 1];
                if (mnem_is(n, "mov") &&
                    (std::strstr(n->operands, "rbp, rsp") ||
                     std::strstr(n->operands, "ebp, esp"))) {
                    /* same boundary guard as `sub rsp` below: a mid-prologue
                     * `push rbp` (preceded by the function's own nonvolatile
                     * saves) must NOT start a new function. */
                    if (at_boundary(i)) starts.insert(in->rva);
                    continue;
                }
            }
        }
        /* sub rsp, imm  — a frame setup, often the very first insn of a
         * frame-pointer-omitted function. Only treat as a start when the
         * preceding instruction is a terminator (ret/jmp) or there is none,
         * to avoid splitting mid-function. */
        if (mnem_is(in, "sub") &&
            (std::strstr(in->operands, "rsp,") || std::strstr(in->operands, "esp,"))) {
            if (at_boundary(i)) starts.insert(in->rva);
        }
        /* A RUN of callee-saved pushes then `sub rsp,imm` (or `mov rbp,rsp`) is the
         * MSVC frame-pointer-omitted prologue for a function that saves several
         * nonvolatiles (`push r15;push r14;push rdi;push rsi;push rbx; sub rsp,0x60`).
         * Neither rule above fires — there is no `push rbp;mov rbp,rsp`, and the
         * `sub rsp` sits mid-push-run so it fails at_boundary — so a body sitting
         * after an int3/ud2 gap gets MERGED into the preceding function, leaking its
         * params as `in_<REG>` (fn_00012c90's real body at +0x30). Flag the push-run
         * HEAD when it is at a boundary and is followed by the frame setup. */
        auto is_nonvol_push = [&](const ds_insn* p) -> bool {
            return mnem_is(p, "push") &&
                (std::strstr(p->operands, "rbx") || std::strstr(p->operands, "rbp") ||
                 std::strstr(p->operands, "rsi") || std::strstr(p->operands, "rdi") ||
                 std::strstr(p->operands, "r12") || std::strstr(p->operands, "r13") ||
                 std::strstr(p->operands, "r14") || std::strstr(p->operands, "r15"));
        };
        if (is_nonvol_push(in) && at_boundary(i)) {
            size_t j = i;
            while (j < e->insn_len && is_nonvol_push(&e->insns[j]) &&
                   (j == i || e->insns[j - 1].rva + e->insns[j - 1].size == e->insns[j].rva))
                ++j;
            if (j > i && j < e->insn_len) {
                const ds_insn* f = &e->insns[j];
                bool contig = e->insns[j - 1].rva + e->insns[j - 1].size == f->rva;
                bool frame =
                    (mnem_is(f, "sub") && (std::strstr(f->operands, "rsp,") ||
                                           std::strstr(f->operands, "esp,"))) ||
                    (mnem_is(f, "mov") && (std::strstr(f->operands, "rbp, rsp") ||
                                           std::strstr(f->operands, "ebp, esp")));
                if (contig && frame) starts.insert(in->rva);
            }
        }
    }

    /* If still empty (e.g. a blob with no seeds), treat the first instruction of
     * each executable segment as a start so the listing has at least one func. */
    if (starts.empty()) {
        for (size_t si = 0; si < e->segment_len; ++si) {
            const ds_segment* s = &e->segments[si];
            if (!(s->flags & DS_FLAG_X)) continue;
            size_t idx = ds_insn_lower_bound(e, s->rva);
            if (idx != SIZE_MAX && idx < e->insn_len)
                starts.insert(e->insns[idx].rva);
        }
    }

    std::vector<uint64_t> sv(starts.begin(), starts.end()); /* sorted */
    if (sv.empty()) return 0;

    /* ---- build each function ---- */
    for (size_t fi = 0; fi < sv.size(); ++fi) {
        uint64_t fstart = sv[fi];
        uint64_t nextstart = (fi + 1 < sv.size()) ? sv[fi + 1] : UINT64_MAX;

        size_t si = insn_index_exact(e, fstart);
        if (si == SIZE_MAX) continue;
        const ds_segment* seg = ds_seg_for_rva(e, fstart);
        uint64_t seg_end = seg ? seg->rva + seg->size : UINT64_MAX;

        /* Walk instructions until: we reach the next function start, leave the
         * segment, or hit a terminator that isn't jumped back over. We collect
         * branch/call targets that fall inside [fstart, ...) to count blocks. */
        std::set<uint64_t> block_leaders;
        block_leaders.insert(fstart);
        uint32_t call_count = 0;
        uint64_t fend = fstart;
        size_t idx = si;
        uint64_t max_internal_target = fstart;

        while (idx < e->insn_len) {
            const ds_insn* in = &e->insns[idx];
            if (in->rva >= nextstart) break;
            if (in->rva >= seg_end) break;

            fend = in->rva + in->size;

            if (in->ref_type == DS_REF_CALL) ++call_count;
            /* a register-indirect `jmp reg` may be a jump-table dispatch whose case
             * bodies live PAST the first `ret`; resolve the .rdata table to learn the
             * real extent (precise — only a valid table extends, never a tail-call). */
            if (mnem_is(in, "jmp") && in->ref_type != DS_REF_JMP &&
                in->ref_type != DS_REF_BRANCH && !std::strchr(in->operands, '[')) {
                uint64_t jt = resolve_jumptable_max(e, idx, fstart, seg_end);
                if (jt > max_internal_target) max_internal_target = jt;
            }

            /* branch/jmp inside the function create block leaders */
            if (in->ref_type == DS_REF_BRANCH || in->ref_type == DS_REF_JMP) {
                /* instruction after a branch starts a block */
                if (idx + 1 < e->insn_len && e->insns[idx + 1].rva < nextstart)
                    block_leaders.insert(e->insns[idx + 1].rva);
                /* the target, if within the function, is a leader */
                uint64_t t = in->ref_target;
                if (t >= fstart && t < nextstart && t < seg_end) {
                    block_leaders.insert(t);
                    if (t > max_internal_target) max_internal_target = t;
                }
            }

            bool terminator = is_ret(in) ||
                              (in->ref_type == DS_REF_JMP) ||
                              mnem_is(in, "hlt");

            if (terminator) {
                /* If a later instruction (still before nextstart) is the target
                 * of an internal branch beyond this point, the function
                 * continues; otherwise it ends here. */
                if (in->rva + in->size > max_internal_target) {
                    ++idx;
                    /* peek: only continue if next insn is a known block leader
                     * reached by an internal jump; else stop. */
                    if (idx < e->insn_len &&
                        block_leaders.count(e->insns[idx].rva) &&
                        e->insns[idx].rva <= max_internal_target) {
                        continue;
                    }
                    break;
                }
            }
            ++idx;
        }

        uint64_t size = (fend > fstart) ? (fend - fstart) : 0;
        uint32_t block_count = (uint32_t)block_leaders.size();
        if (block_count == 0) block_count = 1;

        if (!ds_vec_reserve((void**)&e->funcs, &e->func_cap,
                            e->func_len + 1, sizeof(ds_func)))
            return 2;
        ds_func* f = &e->funcs[e->func_len++];
        std::memset(f, 0, sizeof(*f));
        f->rva = fstart;
        f->size = size;
        f->block_count = block_count;
        f->call_count = call_count;
        f->name[0] = '\0'; /* named later by symbols pass */
    }

    /* funcs already in rva order (sv was sorted); ensure dedupe just in case */
    if (e->func_len > 1) {
        std::sort(e->funcs, e->funcs + e->func_len,
                  [](const ds_func& a, const ds_func& b) { return a.rva < b.rva; });
        size_t w = 1;
        for (size_t r = 1; r < e->func_len; ++r) {
            if (e->funcs[r].rva != e->funcs[w - 1].rva) {
                if (w != r) e->funcs[w] = e->funcs[r];
                ++w;
            }
        }
        e->func_len = w;
    }

    return 0;
}
