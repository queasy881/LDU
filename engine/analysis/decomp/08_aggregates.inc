/* 08_aggregates.inc -- address-escaped stack aggregates / out-params
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    struct AggRegion { int64_t base; int64_t end; std::string name; };
    std::vector<AggRegion> agg_regions;
    const AggRegion* agg_region_for(int64_t off) const {
        for (auto& r : agg_regions)
            if (off >= r.base && off < r.end) return &r;
        return nullptr;
    }
    /* address of `off` inside an aggregate: `sN` (base, array decays to char*) or
     * `(char*)sN + d` for a field. is_unsigned marks "already a pointer". */
    ExprP agg_addr(const AggRegion& r, int64_t off) {
        ExprP base = mkVar(r.name, 8);
        base->is_unsigned = true;
        int64_t d = off - r.base;
        if (d == 0) return base;
        return mkBinary("+", base, mkConst(d, 8), 8);
    }
    /* `(char*)sN + (off-base) + index*scale` — an INDEXED access into the
     * aggregate. Without this a `lea &agg; call` (-> aggregate) PLUS an indexed
     * `agg[i]` access would split the SAME stack region into two locals (the
     * aggregate `sN` and a separate `bufM`), so a copy loop fills one while the
     * call/heap operates on the other (heap_kth_largest's `hv.data`). */
    ExprP agg_indexed(const AggRegion& r, int64_t off, Reg index, int scale) {
        ExprP a = agg_addr(r, off);
        ExprP idx = regfile[index] ? clone(regfile[index]) : mkConst(0, 8);
        if (scale > 1) idx = mkBinary("*", idx, mkConst((int64_t)scale, 8), 8);
        return mkBinary("+", a, idx, 8);
    }
    void scan_addressed_stack() {
        auto static_norm = [&](Reg base, int64_t disp, int64_t& norm)->bool {
            if (base == R_RSP) { norm = disp; return true; }
            if (base == R_RBP && uses_rbp_frame && rbp_offset_known) {
                norm = disp + rbp_minus_rsp; return true;
            }
            return false;
        };
        std::set<int64_t> escaped;
        /* A 16-byte SSE store to a plain stack slot (`movdqa [rsp+k], xmm`) is a
         * bulk buffer/array init (a compiler-materialized const array copied in, or
         * a memset), never a scalar. Seed an aggregate region so the store lowers to
         * an array MEMORY write that shares the SAME `sN` local as the later indexed
         * reads (`[rsp+idx*4]`) — otherwise the store is a dead scalar `vN` (a
         * different symbol) and DSE drops the whole initialization. Collect the
         * covered byte intervals and merge the contiguous ones into one region. */
        std::vector<std::pair<int64_t,int64_t>> sse_ivals;
        for (auto& in : insns) {
            const cs_x86& x = in.x86;
            if (in.id == X86_INS_LEA && x.op_count >= 2 &&
                x.operands[0].type == X86_OP_REG) {
                Reg dst; int dw; map_reg(x.operands[0].reg, dst, dw);
                /* gate: the address goes to a call (loaded into an arg register). This
                 * targets out-params/out-structs precisely and keeps the blast radius
                 * to functions that actually escape a stack address. */
                if (dst==R_RCX||dst==R_RDX||dst==R_R8||dst==R_R9) {
                    const cs_x86_op& mo = x.operands[1];
                    if (mo.type == X86_OP_MEM && mo.mem.index == X86_REG_INVALID) {
                        Reg base = R_NONE; int t;
                        if (mo.mem.base != X86_REG_INVALID) map_reg(mo.mem.base, base, t);
                        int64_t norm;
                        if (static_norm(base, mo.mem.disp, norm)) escaped.insert(norm);
                    }
                }
            }
            bool sse16 = (in.id==X86_INS_MOVAPS||in.id==X86_INS_MOVUPS||in.id==X86_INS_MOVDQA||
                          in.id==X86_INS_MOVDQU||in.id==X86_INS_MOVAPD||in.id==X86_INS_MOVUPD);
            if (sse16 && x.op_count >= 2 && x.operands[0].type == X86_OP_MEM &&
                x.operands[0].size == 16 && x.operands[0].mem.index == X86_REG_INVALID) {
                Reg base = R_NONE; int t;
                if (x.operands[0].mem.base != X86_REG_INVALID) map_reg(x.operands[0].mem.base, base, t);
                int64_t norm;
                if (static_norm(base, x.operands[0].mem.disp, norm))
                    sse_ivals.push_back({norm, norm + 16});
            }
        }
        /* merge contiguous/overlapping 16-byte-store intervals into array regions */
        if (!sse_ivals.empty()) {
            std::sort(sse_ivals.begin(), sse_ivals.end());
            int64_t cs = sse_ivals[0].first, ce = sse_ivals[0].second;
            auto flush = [&](int64_t s, int64_t e) {
                for (auto& r : agg_regions) if (s < r.end && e > r.base) return; /* overlaps escaped region */
                if (e - s < 16) return;
                AggRegion r; r.base = s; r.end = e;
                r.name = "s" + std::to_string((int)agg_regions.size() + 1);
                array_locals.insert(r.name);
                agg_regions.push_back(r);
            };
            for (size_t i = 1; i < sse_ivals.size(); ++i) {
                if (sse_ivals[i].first <= ce) ce = std::max(ce, sse_ivals[i].second);
                else { flush(cs, ce); cs = sse_ivals[i].first; ce = sse_ivals[i].second; }
            }
            flush(cs, ce);
        }
        if (escaped.empty()) return;
        std::vector<int64_t> bases(escaped.begin(), escaped.end());   /* sorted */
        /* locals live below the frame top: for an rbp frame the top is rbp (norm
         * 0, locals negative); for an rsp frame it is frame_size (incoming args
         * sit above it). The region never crosses the top, so outgoing-arg and
         * incoming-arg slots are never absorbed. */
        int64_t frame_top = uses_rbp_frame ? 0 : (frame_size > 0 ? frame_size : 0x1000);
        for (size_t i = 0; i < bases.size(); ++i) {
            int64_t base = bases[i];
            int64_t end = base + 0x100;
            if (base < frame_top && end > frame_top) end = frame_top;
            if (i + 1 < bases.size() && bases[i+1] > base && bases[i+1] < end)
                end = bases[i+1];
            if (end <= base) end = base + 8;
            AggRegion r; r.base = base; r.end = end;
            r.name = "s" + std::to_string((int)agg_regions.size() + 1);
            array_locals.insert(r.name);
            agg_regions.push_back(r);
        }
    }

    /* ===== STRUCT RECOVERY (v1, conservative, pointer-param, per-function) =====
     * A pointer PARAM accessed at a set of clean constant byte offsets is a struct.
     * We emit a packed `struct` typedef with named fields and render the recognized
     * accesses as `p->field_N`. ANYTHING that does not fit (variable index, a width
     * conflict at an offset, an overlap) falls back to the existing raw
     * `*(T*)((char*)p + N)` form — always valid — so this can never break compilation. */
