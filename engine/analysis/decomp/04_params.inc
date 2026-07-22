/* 04_params.inc -- parameter recovery (reg / cdecl / stack / float homes)
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* 32-bit cdecl/stdcall: ALL arguments are on the stack — there is no register
     * arg model. With an `ebp` frame (`push ebp; mov ebp,esp`) arg k sits at
     * [ebp + 8 + 4*(k-1)] (after the saved ebp at +0 and return address at +4);
     * frameless, at [esp + frame + 4*k]. The x64 detector misses these entirely
     * (it only looks above the 0x28 shadow), which is why a 32-bit `int add(int,
     * int)` decompiled to `void` with uninitialized locals. Map every read arg
     * slot to a1, a2, ... (read-before-write gated so a spill isn't counted). */
    void detect_cdecl_params() {
        if (e->arch != DS_ARCH_X86) return;
        /* Incoming args are addressed off the FRAME POINTER (ebp) for an ebp frame,
         * or off esp for a frameless one. Outgoing call args are written off esp
         * even in an ebp frame, so keying strictly on the frame base separates the
         * two and avoids miscounting an outgoing slot as an incoming param. */
        Reg want_base = uses_rbp_frame ? R_RBP : R_RSP;
        int64_t arg_base = uses_rbp_frame ? (8 + rbp_minus_rsp)
                                          : (frame_size + 4);
        std::map<int,int> found; std::set<int64_t> written;
        /* 1-based SLOT index -> FP width. The 32-bit ABI passes floats on the STACK, so
         * there is no XMM signal to key float-ness on (the x64 path's tell) — an x87 read
         * of the slot is the equivalent evidence, and without it every x87 float param
         * typed as an integer and its arithmetic rendered as integer math on the bit
         * pattern. FILD/FIADD/... are excluded: those read genuine integers. */
        std::map<int,int> fl_arg;
        auto x87_float_read = [](unsigned iid) {
            switch (iid) {
                case X86_INS_FLD:  case X86_INS_FADD: case X86_INS_FSUB: case X86_INS_FSUBR:
                case X86_INS_FMUL: case X86_INS_FDIV: case X86_INS_FDIVR:
                case X86_INS_FCOM: case X86_INS_FCOMP:
                    return true;
                default: return false;
            }
        };
        for (auto& in : insns) {
            const cs_x86& x = in.x86;
            for (int o = 0; o < x.op_count; ++o) {
                if (x.operands[o].type != X86_OP_MEM) continue;
                const x86_op_mem& m = x.operands[o].mem;
                if (m.index != X86_REG_INVALID) continue;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                if (base != want_base) continue;
                int64_t norm;
                if (!normalise_slot(base, m.disp, norm)) continue;
                int64_t rel = norm - arg_base;
                if (rel < 0 || (rel % 4) != 0) continue;
                int k = (int)(rel / 4) + 1;        /* 1-based slot index */
                if (k < 1 || k > 32) continue;
                bool is_w = (x.operands[o].access & CS_AC_WRITE) != 0;
                bool is_r = (x.operands[o].access & CS_AC_READ)  != 0;
                if (is_r && !written.count(norm)) {
                    int w = x.operands[o].size ? x.operands[o].size : 4;
                    if (w > found[k]) found[k] = w;
                    if (x87_float_read(in.id) && w >= 4 && w > fl_arg[k]) fl_arg[k] = w;
                }
                if (is_w) written.insert(norm);
            }
        }
        if (found.empty()) return;
        int maxk = found.rbegin()->first;
        /* Walk the arg area by each value's OWN width rather than in fixed 4-byte steps.
         * An 8-byte value (double / long long) occupies TWO slots, and the second one is
         * its HIGH HALF — never a parameter of its own. Stepping 4 at a time invented a
         * phantom middle param for every 8-byte arg (`add_d(int64_t a1, int32_t a2,
         * int64_t a3)` for what is really `add_d(double, double)`). Parameter names must
         * stay positional, so they are numbered sequentially as the area is consumed.
         * For all-4-byte (pure integer) arg lists this is identical to the old walk. */
        int p = 0;
        for (int64_t off = 0; off <= 4 * (int64_t)(maxk - 1); ) {
            int k = (int)(off / 4) + 1;
            int w = found.count(k) ? found[k] : 4;
            if (w <= 0) w = 4;
            std::string nm = "a" + std::to_string(++p);
            int64_t norm = arg_base + off;
            if (!param_home_off.count(norm)) param_home_off[norm] = nm;
            record_width(nm, w);
            if (w >= 8 && !fl_arg.count(k)) var_is_ll[nm] = true;
            if (fl_arg.count(k)) var_is_float[nm] = true;
            off += (w >= 8) ? 8 : 4;
        }
        if (p > num_params) num_params = p;
    }

    /* x64 args 5+ are passed on the stack, just above the 32-byte shadow space
     * and the return address. Under /Od they are NOT homed — the callee reads
     * them directly from normalized offset (frame_size + 8*k) for the k-th
     * argument (k>=5). Detect those read sites and map them to a5, a6, ... so
     * they become real parameters instead of uninitialized locals (the cause of
     * `v6`/`v7` appearing in any function with more than four arguments). */
    void detect_stack_params() {
        if (e->arch != DS_ARCH_X64) return;   /* 32-bit args handled by detect_cdecl_params */
        /* incoming args are at entry_rsp + 8*k (k>=5); in the body that is
         * frame_size + push_bytes + 8*k below the current rsp. Omitting the push
         * bytes shifted every arg index up by the push count (over-counting). */
        int64_t base_off = frame_size + prologue_push_bytes;
        std::map<int,int> found;   /* 1-based arg index -> max access width seen */
        std::set<int> float_arg;   /* args loaded via movss/movsd -> float/double */
        std::set<int64_t> written; /* normalized slots written first (spills/locals) */
        for (auto& in : insns) {
            const cs_x86& x = in.x86;
            for (int o = 0; o < x.op_count; ++o) {
                if (x.operands[o].type != X86_OP_MEM) continue;
                const x86_op_mem& m = x.operands[o].mem;
                if (m.index != X86_REG_INVALID) continue;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                int64_t norm;
                if (!normalise_slot(base, m.disp, norm)) continue;
                int64_t rel = norm - base_off;
                if (rel < 0x28 || (rel % 8) != 0) continue;   /* above shadow only */
                int k = (int)(rel / 8);                       /* 1-based arg index */
                if (k < 5 || k > 32) continue;
                bool is_w = (x.operands[o].access & CS_AC_WRITE) != 0;
                bool is_r = (x.operands[o].access & CS_AC_READ)  != 0;
                /* only a slot read before the function writes it is a real
                 * incoming arg; a write-first slot is a local/spill. */
                if (is_r && !written.count(norm)) {
                    int w = x.operands[o].size ? x.operands[o].size : 8;
                    if (w > found[k]) found[k] = w;
                    /* ANY scalar-FP op reading the slot (mulsd/addss/divsd/comisd/…)
                     * makes it a float/double param — not just an explicit movss/movsd
                     * load. poly_horner's 5th arg is consumed directly by `mulsd
                     * [rsp+0x28]`, so the movss/movsd-only test missed it (long long). */
                    int fw = fp_scalar_width(in.id);
                    if (fw) { float_arg.insert(k); if (fw > found[k]) found[k] = fw; }
                }
                if (is_w) written.insert(norm);
            }
        }
        if (found.empty()) return;
        int maxk = found.rbegin()->first;
        for (int k = 5; k <= maxk; ++k) {
            int64_t norm = base_off + 8 * (int64_t)k;
            if (param_home_off.count(norm)) continue;
            std::string nm = "a" + std::to_string(k);
            param_home_off[norm] = nm;
            int w = found.count(k) ? found[k] : 8;
            if (float_arg.count(k)) {
                var_is_float[nm] = true;
                record_width(nm, w >= 8 ? 8 : 4);
            } else {
                record_width(nm, w ? w : 8);
                if (w >= 8) var_is_ll[nm] = true;
            }
        }
        if (maxk > num_params) num_params = maxk;
    }

    bool is_float_param[4] = {false,false,false,false};

    /* Float / double arguments are passed in XMM0..XMM3 by POSITION (the same
     * slot the integer reg would occupy): f(int a1, float a2) -> a1 in RCX,
     * a2 in XMM1. The integer-home scan never sees these, so without this they
     * read as 0 ("if (0 > a2)") and float constants leak as raw bit patterns.
     * An XMM register that is READ before the function writes it is an incoming
     * float param at that position; one written first (xorps/movss/return value)
     * is a local, not a param. */
    /* True for SSE ops that FULLY define their destination (its prior value is
     * discarded). For these, a capstone READ on the dest is only upper-bits
     * preservation, not a use. Read-modify-write ops (addss/mulss/...) are NOT
     * here, so their dest read counts as a genuine value use. */
    static bool fp_def_only(unsigned id) {
        switch (id) {
            case X86_INS_MOVSS: case X86_INS_MOVSD: case X86_INS_MOVAPS:
            case X86_INS_MOVUPS: case X86_INS_MOVD: case X86_INS_MOVQ:
            case X86_INS_MOVLPS: case X86_INS_MOVDQA: case X86_INS_MOVDQU:
            case X86_INS_CVTSI2SS: case X86_INS_CVTSI2SD:
            case X86_INS_CVTSS2SD: case X86_INS_CVTSD2SS:
            case X86_INS_CVTTSS2SI: case X86_INS_CVTTSD2SI:
            case X86_INS_CVTSS2SI: case X86_INS_CVTSD2SI:
                return true;
            default: return false;
        }
    }
    void detect_float_params() {
        bool written[4] = {false,false,false,false};
        int float_param_w[4] = {0,0,0,0};   /* 8 if used in a double (*sd) op */
        int maxp = -1;
        for (size_t ii = 0; ii < insns.size(); ++ii) {
            const Insn& in = insns[ii];
            const cs_x86& x = in.x86;
            bool wrote[4] = {false,false,false,false};   /* deferred: reads-before-writes */
            /* a self-xor that is IMMEDIATELY followed by a ret is a `return 0.0`
             * on an early-exit path, NOT a scratch init — it must NOT mark the reg
             * written, else the real param read on the fall-through path (`xorps
             * xmm0,xmm0; ret` vs `divsd xmm0,xmm1; ret` in d_div/f_div) is suppressed
             * and the dividend param is mistyped long long. */
            bool sx_before_ret = false;
            /* `xorps/xorpd/pxor xmm,xmm` (same reg) is the zero idiom — a pure
             * DEFINITION to 0, not a read of the register's incoming value, even
             * though xor lists both operands as READ. Without this, the zeroing of
             * a scratch xmm0 marks position 0 as a float param (mistyping the int
             * color arg in the alpha-scale routine). */
            bool self_xor = (in.id==X86_INS_XORPS||in.id==X86_INS_XORPD||
                             in.id==X86_INS_PXOR) && x.op_count>=2 &&
                            x.operands[0].type==X86_OP_REG &&
                            x.operands[1].type==X86_OP_REG &&
                            x.operands[0].reg==x.operands[1].reg;
            if (self_xor && ii + 1 < insns.size()) {
                unsigned nid = insns[ii + 1].id;
                if (nid == X86_INS_RET || nid == X86_INS_RETF) sx_before_ret = true;
            }
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type != X86_OP_REG) continue;
                Reg r; int w; map_reg(op.reg, r, w);
                if (r < R_XMM0 || r > R_XMM3) continue;
                int p = r - R_XMM0;
                /* Operand 0 with WRITE is the destination. For a REPLACING op
                 * (movss/cvtsi2sd/...) its prior value is discarded — the capstone
                 * READ flag is only upper-bits preservation, NOT a read of an
                 * incoming value (counting it mistyped arr_avg's int count `a2`).
                 * For a READ-MODIFY-WRITE op (mulss/addss/subss/divss/max/min) the
                 * destination's prior value IS used, so a read-before-write of it
                 * IS an incoming float param (e.g. `mulss xmm1, ctx->alpha` — xmm1
                 * is the float factor argument). Only the replacing case is skipped. */
                bool is_dst = self_xor || (o == 0 && (op.access & CS_AC_WRITE) &&
                               fp_def_only(in.id));
                if ((op.access & CS_AC_READ) && !written[p] && !is_dst &&
                    !param_used[p]) {   /* never override a homed integer param */
                    is_float_param[p] = true;
                    if (p > maxp) maxp = p;
                    /* width: a param consumed by a DOUBLE-precision op (movsd/
                     * addsd/mulsd/comisd/...) is `double`, not the float default —
                     * fixes every numerical routine (alpha/coeff args typed float
                     * and the matching double return mis-sized). */
                    unsigned iid = in.id;
                    if (iid==X86_INS_MOVSD||iid==X86_INS_ADDSD||iid==X86_INS_SUBSD||
                        iid==X86_INS_MULSD||iid==X86_INS_DIVSD||iid==X86_INS_MAXSD||
                        iid==X86_INS_MINSD||iid==X86_INS_SQRTSD||iid==X86_INS_COMISD||
                        iid==X86_INS_UCOMISD||iid==X86_INS_CVTSD2SI||iid==X86_INS_CVTTSD2SI||
                        iid==X86_INS_CVTSD2SS)
                        float_param_w[p] = 8;
                    /* the andps/andpd ABS idiom (`andps xmm,[sign-mask]`) carries the
                     * precision in its .rdata mask — a DOUBLE mask ({0xffffffff,
                     * 0x7fffffff}) makes the param double (d_abs's `double x`). */
                    else if ((iid==X86_INS_ANDPS||iid==X86_INS_ANDPD) && x.op_count>=2 &&
                             x.operands[1].type==X86_OP_MEM &&
                             x.operands[1].mem.base==X86_REG_RIP &&
                             x.operands[1].mem.index==X86_REG_INVALID) {
                        uint64_t a = in.addr + in.size + (uint64_t)x.operands[1].mem.disp;
                        int32_t l2, h2;
                        if (read_i32(a, l2) && read_i32(a + 4, h2)) {
                            uint32_t lo=(uint32_t)l2, hi=(uint32_t)h2;
                            if (lo==0xffffffffu && hi==0x7fffffffu) float_param_w[p] = 8;
                            else if (lo==0x7fffffffu && hi==0x7fffffffu && iid==X86_INS_ANDPD)
                                float_param_w[p] = 8;
                        }
                    }
                }
                if (op.access & CS_AC_WRITE) wrote[p] = true;
            }
            /* apply deferred writes AFTER the read checks (so a same-instruction
             * dest write does not suppress a read of the SAME reg — cvtsd2ss
             * xmm0,xmm0 reads a double param into a float dest). A self-xor that is
             * a `return 0.0` early exit never marks its reg written. */
            for (int p = 0; p < 4; ++p)
                if (wrote[p] && !(self_xor && sx_before_ret)) written[p] = true;
            /* a CALL clobbers the volatile xmm0-5 (and returns a float in xmm0),
             * so an xmm0-3 READ after a call is the call's RESULT, not an incoming
             * float param. Without this, `call f; movaps xmm6, xmm0` (saving the
             * result) mistyped arg0 as `float`, unmapping the real integer rcx
             * object pointer -> `rsi=0` and 500+ `(char*)(0)` null derefs. */
            if (in.is_call) for (int p = 0; p < 4; ++p) written[p] = true;
        }
        if (maxp + 1 > num_params) num_params = maxp + 1;
        refine_float_param_widths(float_param_w);
        for (int p = 0; p <= maxp; ++p) {
            if (!is_float_param[p]) continue;
            std::string nm = "a" + std::to_string(p + 1);
            record_width(nm, float_param_w[p] >= 8 ? 8 : 4);   /* double vs float */
            var_is_float[nm] = true;
        }
        register_float_homes();
    }

    /* The width inference in detect_float_params only sees ops that read the param
     * register DIRECTLY. /O2 routinely copies the incoming xmm arg to a scratch xmm
     * (`movaps xmm3,xmm0`) and runs all the double-precision math on the COPY, so the
     * param's direct uses are ambiguous and it defaulted to float even though every
     * real use is mulsd/divsd (nr_sqrt's `double x` mistyped `float`, which injects a
     * narrowing convert on recompile). Track param value across register copies and
     * pin the width from the precision of the op that consumes it. */
    void refine_float_param_widths(int* float_param_w) {
        int alias[16]; for (int i = 0; i < 16; ++i) alias[i] = -1;
        for (int p = 0; p < 4; ++p) if (is_float_param[p]) alias[p] = p;
        bool pinned[4] = {false,false,false,false};
        auto xi = [](Reg r) -> int {
            return (r >= R_XMM0 && r <= R_XMM15) ? (int)(r - R_XMM0) : -1;
        };
        for (auto& in : insns) {
            const cs_x86& x = in.x86;
            unsigned id = in.id;
            bool copy16 = (id==X86_INS_MOVAPS||id==X86_INS_MOVUPS||id==X86_INS_MOVAPD||
                           id==X86_INS_MOVUPD||id==X86_INS_MOVDQA||id==X86_INS_MOVDQU);
            bool cmovsd = (id==X86_INS_MOVSD), cmovss = (id==X86_INS_MOVSS);
            if ((copy16||cmovsd||cmovss) && x.op_count==2 &&
                x.operands[0].type==X86_OP_REG && x.operands[1].type==X86_OP_REG) {
                Reg d,s; int dw,sw; map_reg(x.operands[0].reg,d,dw); map_reg(x.operands[1].reg,s,sw);
                int di=xi(d), si=xi(s);
                if (di>=0) {
                    int sp = (si>=0) ? alias[si] : -1;
                    if (sp>=0 && !pinned[sp]) {
                        if (cmovss) { float_param_w[sp]=4; pinned[sp]=true; }
                        else if (cmovsd) { float_param_w[sp]=8; pinned[sp]=true; }
                    }
                    alias[di] = sp;
                }
                continue;
            }
            int prec = 0;   /* 8 = double-precision op, 4 = single-precision op */
            switch (id) {
                case X86_INS_MULSD: case X86_INS_ADDSD: case X86_INS_SUBSD:
                case X86_INS_DIVSD: case X86_INS_COMISD: case X86_INS_UCOMISD:
                case X86_INS_SQRTSD: case X86_INS_MAXSD: case X86_INS_MINSD:
                case X86_INS_CVTSD2SS: case X86_INS_CVTSD2SI: case X86_INS_CVTTSD2SI:
                    prec = 8; break;
                case X86_INS_MULSS: case X86_INS_ADDSS: case X86_INS_SUBSS:
                case X86_INS_DIVSS: case X86_INS_COMISS: case X86_INS_UCOMISS:
                case X86_INS_SQRTSS: case X86_INS_MAXSS: case X86_INS_MINSS:
                case X86_INS_CVTSS2SD: case X86_INS_CVTSS2SI: case X86_INS_CVTTSS2SI:
                    prec = 4; break;
                default: break;
            }
            if (prec) {
                for (int o = 0; o < x.op_count; ++o) {
                    const cs_x86_op& op = x.operands[o];
                    if (op.type!=X86_OP_REG || !(op.access & CS_AC_READ)) continue;
                    Reg r; int w; map_reg(op.reg,r,w);
                    int ri=xi(r); if (ri<0) continue;
                    int p = alias[ri];
                    if (p>=0 && !pinned[p]) { float_param_w[p]=prec; pinned[p]=true; }
                }
            }
            /* a write to an xmm that isn't a tracked copy destroys its param alias */
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type!=X86_OP_REG || !(op.access & CS_AC_WRITE)) continue;
                Reg r; int w; map_reg(op.reg,r,w);
                int ri=xi(r); if (ri>=0) alias[ri] = -1;
            }
        }
    }

    /* Register the home stack slot for each XMM float/double parameter, mirroring
     * the integer homing in detect_param_homes. Under /Od MSVC spills every xmm arg
     * to its shadow slot (`movsd [rsp+8],xmm0`) and reloads it (`movsd xmm1,[rsp+8]`);
     * without registering the slot, the reload resolved to a fresh, never-assigned
     * `long long` local (`v2`/`v4`) instead of the parameter, leaving the double/float
     * argument completely unrecovered (nr_sqrt/convert_chain/poly_eval read garbage).
     * The shadow slot for parameter position p is [rsp+8+8p] at entry. */
    void register_float_homes() {
        bool sub_done = false;
        bool xmm_written[4] = {false,false,false,false};
        for (size_t i = 0; i < insns.size() && i < 24; ++i) {
            const Insn& in = insns[i];
            const cs_x86& x = in.x86;
            if (in.id == X86_INS_SUB && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_IMM) {
                Reg r; int w; map_reg(x.operands[0].reg, r, w);
                if (r == R_RSP) { sub_done = true; continue; }
            }
            bool is_movss = (in.id == X86_INS_MOVSS);
            bool is_movsd = (in.id == X86_INS_MOVSD);
            if ((is_movss || is_movsd) && x.op_count == 2 &&
                x.operands[0].type == X86_OP_MEM && x.operands[1].type == X86_OP_REG) {
                const x86_op_mem& m = x.operands[0].mem;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                Reg src; int sw; map_reg(x.operands[1].reg, src, sw);
                int p = (src >= R_XMM0 && src <= R_XMM3) ? (int)(src - R_XMM0) : -1;
                if (base == R_RSP && m.index == X86_REG_INVALID && p >= 0 &&
                    is_float_param[p] && !xmm_written[p] && m.disp == 8 + 8 * (int64_t)p) {
                    int64_t norm = m.disp + (sub_done ? 0 : (frame_size + prologue_push_bytes));
                    if (!param_home_off.count(norm)) {
                        std::string nm = "a" + std::to_string(p + 1);
                        param_home_off[norm] = nm;
                        home_store_addrs.insert(in.addr);
                        var_is_float[nm] = true;
                        record_width(nm, is_movsd ? 8 : 4);
                        /* the home slot holds the float param's BITS: a later GP read
                         * `mov rax,[home]` is the union/bit-reinterpret idiom (d_signbit/
                         * copysign/frexp inlined at /O2), not a value conversion. Mark it
                         * a float slot so the MOV handler reinterprets `*(long long*)&aN`
                         * instead of truncating `(unsigned long long)(aN)`. An int store
                         * to the slot (compiler slot reuse) erases it via the int path. */
                        float_slots[norm] = is_movsd ? 8 : 4;
                        if (p + 1 > num_params) num_params = p + 1;
                    }
                    xmm_written[p] = true;
                    continue;
                }
            }
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE)) {
                    Reg r; int w; map_reg(op.reg, r, w);
                    if (r >= R_XMM0 && r <= R_XMM3) xmm_written[r - R_XMM0] = true;
                }
            }
        }
    }

    void record_width(const std::string& nm, int w) {
        auto it = var_width.find(nm);
        if (it == var_width.end() || w > it->second) var_width[nm] = w;
    }

    /* Mark an SSE operand expression as floating-point: a raw .rdata bit pattern
     * Const becomes a float/double literal at render; a named var records its
     * float type. w = 4 (single) or 8 (double). Idempotent and cheap. */
    ExprP as_float(ExprP e, int w) {
        if (!e) return e;
        /* A Const (raw .rdata bit pattern) becomes a float literal; a Mem deref in
         * a float context (a movss load or an scalar-FP operand) is a float deref,
         * so it renders `*(float*)` and propagates `float*` to its pointer. We do
         * NOT taint Vars: a variable's float-ness comes from the reliable XMM param
         * detection, not "it flowed into a float op" (which mistyped arr_avg's int
         * count — that reaches a float op only via a cvtsi2sd `(double)` cast). */
        if (e->kind == EK::Const) { e->is_float = true; e->width = w; }
        else if (e->kind == EK::Mem) { e->is_float = true; if (w) e->width = w; }
        return e;
    }

    /* A static (no RegFile) form of operand->Expr, for the CFG/switch prepass.
     * Registers stack slots so the recovered switch index names a real local. */
    ExprP symbolic_operand_static(const cs_x86_op& op) {
        if (op.type == X86_OP_IMM) return mkConst(op.imm, op.size ? op.size : 4);
        if (op.type == X86_OP_MEM) {
            const x86_op_mem& m = op.mem;
            Reg base = R_NONE, index = R_NONE; int t;
            if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
            if (m.index != X86_REG_INVALID) map_reg(m.index, index, t);
            int64_t norm;
            if (index == R_NONE && base != R_RIP &&
                normalise_slot(base, m.disp, norm)) {
                int w = op.size ? op.size : 4;
                std::string nm = slot_name(norm, w);
                record_width(nm, w);
                return mkVar(nm, w);
            }
        }
        return nullptr;
    }

    /* Map a memory operand to a param Expr, a local Var, or a generic deref.
     * Uses the current symbolic register values to fold the address. */
    ExprP mem_to_expr(const cs_x86_op& op, int width, ExprP* regvals) {
        const x86_op_mem& m = op.mem;
        /* gs:/fs: TEB/TLS access — model as __readgsqword/__readfsqword, never an
         * absolute `*(0x58)` near-null deref (mirrors resolve_mem; this is the
         * cross-block/regfile lift path the state-machine functions hit). */
        {
            bool gs = (m.segment == X86_REG_GS) || cur_insn_seg == 1;
            bool fs = (m.segment == X86_REG_FS) || cur_insn_seg == 2;
            if ((gs || fs) && m.base == X86_REG_INVALID) {
                /* gs:[0x30] TEB self -> NtCurrentTeb() (mirrors resolve_mem). */
                if (gs && m.index == X86_REG_INVALID && m.disp == 0x30 &&
                    !std::getenv("DS_NO_TEBNAMES") && !std::getenv("DS_NO_TEB")) {
                    auto nt = std::make_shared<Expr>();
                    nt->kind = EK::Call; nt->callee = "NtCurrentTeb";
                    nt->width = 8; nt->ret_kind = 2;
                    used_segread = true; used_nt_current_teb = true;
                    return nt;
                }
                auto rd = std::make_shared<Expr>();
                rd->kind = EK::Call; rd->callee = gs ? "__readgsqword" : "__readfsqword";
                rd->width = 8; rd->ret_kind = 2;
                const char* tf = (gs && !std::getenv("DS_NO_TEB")) ? teb_field_name(m.disp) : nullptr;
                if (tf) { rd->args.push_back(mkText(tf, 8)); teb_fields_used[tf] = m.disp; }
                else rd->args.push_back(mkConst(m.disp, 8, true));
                used_segread = true;
                if (m.index == X86_REG_INVALID) return rd;
                Reg ir; int iw; map_reg(m.index, ir, iw);
                ExprP idx = regvals && regvals[ir] ? clone(regvals[ir]) : unknown_reg_value(ir, 8);
                if (m.scale > 1) idx = mkBinary("*", idx, mkConst((int64_t)m.scale, 8), 8);
                return mkMem(mkBinary("+", rd, idx, 8), width);
            }
        }
        Reg base = R_NONE, index = R_NONE; int t;
        if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
        if (m.index != X86_REG_INVALID) map_reg(m.index, index, t);
        int64_t disp = m.disp;

        /* Pure stack slot (no index): param or local */
        if (index == R_NONE && base != R_RIP) {
            int64_t norm;
            if (normalise_slot(base, disp, norm)) {
                std::string nm = slot_name(norm, width);
                record_width(nm, width);
                return mkVar(nm, width);
            }
        }

        /* General memory: build (base + index*scale + disp) using reg values */
        ExprP addr;
        auto regval = [&](Reg r) -> ExprP {
            if (regvals && regvals[r]) return clone(regvals[r]);
            /* An untracked base/index register read straight here BYPASSES
             * reg_value's backstop, so its old `mkReg` fallback rendered as a
             * literal-0 base (`*(char*)0`). Route it through the same invariant:
             * a declared in_<REG> local, never a null deref. */
            return unknown_reg_value(r, 8);
        };
        if (base != R_NONE && base != R_RIP) {
            addr = regval(base);
            ExprP fb = fold(clone(addr));
            bool base_zero = (fb && fb->kind == EK::Const && fb->cval == 0);
            /* A base that folds to a PAGE-ZERO constant (0 < v < 0x1000) is never a
             * valid x64 pointer (page zero is unmapped) — it is a lost object base
             * whose real value the fixpoint dropped, leaving a stray small constant
             * (a COM `this` collapsed to a nearby `mov r8d,0x7a` error code renders
             * `*(long long*)(0x7a)`). Route it through the backstop like a literal 0
             * so it reads as a declared in_<REG> instead of a bogus near-null deref. */
            bool base_pagezero = (fb && fb->kind == EK::Const &&
                                  fb->cval > 0 && fb->cval < 0x1000);
            bool base_backstop = expr_has_in_backstop(addr);
            /* LOST MODULE-BASE static array: an indexed access `[base + idx*s + disp]`
             * where `disp` is a large in-image DATA RVA is a static table indexed off
             * the module base (`lea rsi,[rip-X]` = RVA 0). Whether that base survived
             * as the constant 0 or was dropped to an `in_<REG>` live-in, the access is
             * `*(T*)(idx*s + disp)` — the real `mdays[i]`. Gated on a >=4KB disp so
             * struct-field offsets are never affected. */
            bool static_array = index != R_NONE && disp >= 0x1000 &&
                                (uint64_t)disp < e->image_size && in_data_rva((uint64_t)disp);
            if (static_array && (base_zero || base_backstop)) {
                addr = nullptr;   /* base = module base 0 */
            } else if ((base_zero || base_pagezero) && index == R_NONE) {
                /* GUARD: a small-constant/zero base is a LOST pointer only when it is the
                 * WHOLE address. With an INDEX register present, `[const + reg]` is a real
                 * pointer `reg` plus a displacement `const` — `movss [rcx+rax],xmm` after
                 * `mov ecx,4` is the store `a9[1]` (rax=a9 the pointer, 4 the byte offset).
                 * Backstopping the const base there mis-sent struct-field stores to the
                 * wrong pointer (`*(a1+a9)`, `*(a9+a3)`); keep the const as the displacement. */
                /* SECOND HALF OF THE NULL-BASE INVARIANT. A base register whose tracked
                 * value collapsed to literal 0 is a LOST pointer — a loop-carried object
                 * pointer the phi never materialized, a value folded away across a merge
                 * — NOT a genuine null dereference. Route it through the backstop so it
                 * renders as a declared in_<REG> local instead of `*(0 + off)`. */
                addr = unknown_reg_value(base, 8);
            }
        }
        if (index != R_NONE) {
            ExprP ie = regval(index);
            if (m.scale > 1) ie = mkBinary("*", ie, mkConst((int64_t)m.scale, 8), 8);
            addr = addr ? mkBinary("+", addr, ie, 8) : ie;
        }
        if (disp != 0 || !addr) {
            ExprP de = mkConst(disp, 8);
            addr = addr ? mkBinary("+", addr, de, 8) : de;
        }
        return mkMem(addr, width, false);
    }

    std::string cast_str(int w, bool uns) {
        switch (w) {
            case 1: return uns ? "(unsigned char)" : "(signed char)";
            case 2: return uns ? "(unsigned short)" : "(short)";
            case 4: return uns ? "(unsigned int)" : "(int)";
            case 8: return uns ? "(unsigned long long)" : "(long long)";
            default: return uns ? "(unsigned int)" : "(int)";
        }
    }
    std::string typ_str(int w, bool uns, bool ptr) {
        if (ptr) return "long long";   /* pointers modeled as 64-bit ints */
        switch (w) {
            case 1: return uns ? "unsigned char" : "signed char";
            case 2: return uns ? "unsigned short" : "short";
            case 4: return uns ? "unsigned int" : "int";
            case 8: return uns ? "unsigned long long" : "long long";
            default: return uns ? "unsigned int" : "int";
        }
    }

