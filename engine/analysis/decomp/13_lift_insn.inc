/* 13_lift_insn.inc -- THE LIFTER: exec_insn, the per-instruction switch
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    void set_flags_cmp(const cs_x86& x) {
        flags = FlagSrc();
        flags.valid = true; flags.is_cmp = true;
        flags.a = rvalue(x.operands[0]);
        flags.b = rvalue(x.operands[1]);
        flags.width = x.operands[0].size ? x.operands[0].size : 4;
    }
    void set_flags_test(const cs_x86& x) {
        flags = FlagSrc();
        flags.valid = true; flags.is_test = true;
        flags.a = rvalue(x.operands[0]);
        flags.b = rvalue(x.operands[1]);
        flags.width = x.operands[0].size ? x.operands[0].size : 4;
    }
    void set_flags_arith(ExprP res, int w) {
        flags = FlagSrc();
        flags.valid = true; flags.is_arith = true; flags.a = clone(res); flags.width = w;
    }
    /* Set arithmetic flags for a destination JUST written with `res`. For a MEMORY
     * destination, `res` embeds a LIVE `*p` read that re-evaluates to the POST-store
     * value at render time, double-counting the op: `*p = *p - 1; if (*p - 1 != 0)`
     * (the refcount off-by-one → premature free/UAF) and `*p = *p >> 1; if (*p >> 1)`
     * (double shift). The stored result IS the new *p, so read the lvalue back — it
     * renders as `if (*p != 0)`. A register keeps `res` (rvalue would return the same
     * updated expr, but avoid perturbing the common path). Must be called AFTER do_dst. */
    void set_flags_dst(const cs_x86_op& d, ExprP res, int w) {
        set_flags_arith(d.type == X86_OP_MEM ? rvalue(d) : res, w);
    }

    /* Canonical Intel/MS intrinsic NAME for a packed-SIMD mnemonic we don't lane-model,
     * so an unmodeled op reads as `_mm_shuffle_epi8(a, b)` — exactly what Hex-Rays prints —
     * instead of a home-grown `__vpshufb(a, b)`. This is the same industry choice IDA makes
     * (it emits Intel intrinsic names up to SSE4a and inlines the rest): we DON'T translate
     * the lane semantics to C, we NAME the operation with the name a reverse engineer greps
     * for. The names are declared old-style (`long long _mm_...();`) like every other opaque
     * call, which MSVC's C compiler accepts without <immintrin.h> — so the gate stays clean.
     * A leading VEX `v` on a 128-bit form maps to the same SSE intrinsic (this path only fires
     * for xmm destinations). Returns "" for anything not in the table (keep the __mnem form). */
    const std::string& simd_intrinsic_name(const std::string& mnem) {
        static const std::map<std::string, std::string> T = {
            /* packed integer arithmetic */
            {"paddb","_mm_add_epi8"},{"paddw","_mm_add_epi16"},{"paddd","_mm_add_epi32"},{"paddq","_mm_add_epi64"},
            {"psubb","_mm_sub_epi8"},{"psubw","_mm_sub_epi16"},{"psubd","_mm_sub_epi32"},{"psubq","_mm_sub_epi64"},
            {"paddsb","_mm_adds_epi8"},{"paddsw","_mm_adds_epi16"},{"paddusb","_mm_adds_epu8"},{"paddusw","_mm_adds_epu16"},
            {"psubsb","_mm_subs_epi8"},{"psubsw","_mm_subs_epi16"},{"psubusb","_mm_subs_epu8"},{"psubusw","_mm_subs_epu16"},
            {"pmullw","_mm_mullo_epi16"},{"pmulld","_mm_mullo_epi32"},{"pmulhw","_mm_mulhi_epi16"},{"pmulhuw","_mm_mulhi_epu16"},
            {"pmuludq","_mm_mul_epu32"},{"pmuldq","_mm_mul_epi32"},{"pmaddwd","_mm_madd_epi16"},{"psadbw","_mm_sad_epu8"},
            {"pavgb","_mm_avg_epu8"},{"pavgw","_mm_avg_epu16"},
            {"pmaxub","_mm_max_epu8"},{"pminub","_mm_min_epu8"},{"pmaxsw","_mm_max_epi16"},{"pminsw","_mm_min_epi16"},
            {"pmaxsb","_mm_max_epi8"},{"pminsb","_mm_min_epi8"},{"pmaxud","_mm_max_epu32"},{"pminud","_mm_min_epu32"},
            {"pmaxsd","_mm_max_epi32"},{"pminsd","_mm_min_epi32"},{"pabsb","_mm_abs_epi8"},{"pabsw","_mm_abs_epi16"},{"pabsd","_mm_abs_epi32"},
            /* bitwise (integer) */
            {"pand","_mm_and_si128"},{"por","_mm_or_si128"},{"pxor","_mm_xor_si128"},{"pandn","_mm_andnot_si128"},
            /* packed compares */
            {"pcmpeqb","_mm_cmpeq_epi8"},{"pcmpeqw","_mm_cmpeq_epi16"},{"pcmpeqd","_mm_cmpeq_epi32"},{"pcmpeqq","_mm_cmpeq_epi64"},
            {"pcmpgtb","_mm_cmpgt_epi8"},{"pcmpgtw","_mm_cmpgt_epi16"},{"pcmpgtd","_mm_cmpgt_epi32"},{"pcmpgtq","_mm_cmpgt_epi64"},
            /* shuffles / packs / blends */
            {"pshufb","_mm_shuffle_epi8"},{"pshufd","_mm_shuffle_epi32"},{"pshuflw","_mm_shufflelo_epi16"},{"pshufhw","_mm_shufflehi_epi16"},
            {"packsswb","_mm_packs_epi16"},{"packssdw","_mm_packs_epi32"},{"packuswb","_mm_packus_epi16"},{"packusdw","_mm_packus_epi32"},
            {"pblendw","_mm_blend_epi16"},{"pblendvb","_mm_blendv_epi8"},{"palignr","_mm_alignr_epi8"},
            {"punpcklbw","_mm_unpacklo_epi8"},{"punpckhbw","_mm_unpackhi_epi8"},{"punpcklwd","_mm_unpacklo_epi16"},{"punpckhwd","_mm_unpackhi_epi16"},
            {"punpckldq","_mm_unpacklo_epi32"},{"punpckhdq","_mm_unpackhi_epi32"},{"punpcklqdq","_mm_unpacklo_epi64"},{"punpckhqdq","_mm_unpackhi_epi64"},
            /* packed shifts */
            {"psllw","_mm_sll_epi16"},{"pslld","_mm_sll_epi32"},{"psllq","_mm_sll_epi64"},{"pslldq","_mm_slli_si128"},
            {"psrlw","_mm_srl_epi16"},{"psrld","_mm_srl_epi32"},{"psrlq","_mm_srl_epi64"},{"psrldq","_mm_srli_si128"},
            {"psraw","_mm_sra_epi16"},{"psrad","_mm_sra_epi32"},{"pmovmskb","_mm_movemask_epi8"},
            /* packed float arithmetic */
            {"addps","_mm_add_ps"},{"subps","_mm_sub_ps"},{"mulps","_mm_mul_ps"},{"divps","_mm_div_ps"},
            {"addpd","_mm_add_pd"},{"subpd","_mm_sub_pd"},{"mulpd","_mm_mul_pd"},{"divpd","_mm_div_pd"},
            {"sqrtps","_mm_sqrt_ps"},{"sqrtpd","_mm_sqrt_pd"},{"rsqrtps","_mm_rsqrt_ps"},{"rcpps","_mm_rcp_ps"},
            {"maxps","_mm_max_ps"},{"minps","_mm_min_ps"},{"maxpd","_mm_max_pd"},{"minpd","_mm_min_pd"},
            {"andps","_mm_and_ps"},{"orps","_mm_or_ps"},{"xorps","_mm_xor_ps"},{"andnps","_mm_andnot_ps"},
            {"andpd","_mm_and_pd"},{"orpd","_mm_or_pd"},{"xorpd","_mm_xor_pd"},
            {"shufps","_mm_shuffle_ps"},{"shufpd","_mm_shuffle_pd"},{"unpcklps","_mm_unpacklo_ps"},{"unpckhps","_mm_unpackhi_ps"},
            {"unpcklpd","_mm_unpacklo_pd"},{"unpckhpd","_mm_unpackhi_pd"},{"blendps","_mm_blend_ps"},{"blendpd","_mm_blend_pd"},
            {"haddps","_mm_hadd_ps"},{"hsubps","_mm_hsub_ps"},{"haddpd","_mm_hadd_pd"},{"addsubps","_mm_addsub_ps"},
            {"dpps","_mm_dp_ps"},{"dppd","_mm_dp_pd"},{"roundps","_mm_round_ps"},{"roundpd","_mm_round_pd"},
            /* NB: the packed CONVERSIONS (cvtdq2ps/cvtps2dq/cvtdq2pd/pmovsx.../etc) are
             * deliberately NOT mapped to their _mm_cvt* intrinsic names. MSVC's C
             * compiler recognizes those as builtins with a STRICT fixed arity, and our
             * opaque-call arg capture can drop the source operand -- a _mm_cvtepi32_pd()
             * with 0 args then fails the builtin arity check (C2168) and breaks the gate.
             * The binary-op intrinsics below are safe (2 operands captured reliably); the
             * conversions keep the __cvtdq2pd form, still readable, never a builtin. */
            /* crypto / crc */
            {"aesenc","_mm_aesenc_si128"},{"aesenclast","_mm_aesenclast_si128"},{"aesdec","_mm_aesdec_si128"},
            {"aesdeclast","_mm_aesdeclast_si128"},{"aesimc","_mm_aesimc_si128"},{"aeskeygenassist","_mm_aeskeygenassist_si128"},
            {"pclmulqdq","_mm_clmulepi64_si128"},
        };
        std::string key = mnem;
        auto it = T.find(key);
        if (it == T.end() && key.size() > 1 && key[0] == 'v') { it = T.find(key.substr(1)); }  /* VEX 128-bit */
        static const std::string none;
        return it == T.end() ? none : it->second;
    }

    /* ----- the main per-block executor ----- */
    void exec_block(Block& b) {
        for (int i = 0; i < R_COUNT; ++i) { regfile[i] = nullptr; regfile_hi[i] = nullptr; clear_xmm_f((Reg)i); }
        vec_load_addr.clear();
        vec_fill.clear();
        prev_vec_fill.clear();
        vec_op_value.clear();
        xmm_packed_var.clear(); stack_packed_var.clear(); int_slots.clear();
        if (b.is_switch) switch_resolved_index.erase(b.id);   /* recapture each pass */
        /* x87 stack: reset like regfile, then inherit from a SINGLE predecessor (the
         * same rule the flag state uses just below). Compiler-generated x87 keeps the
         * stack balanced within an expression and spills across joins, so a single-pred
         * chain is exactly the case that needs to carry values (`fld a; fld b; fcom;
         * jcc; ...; fcompp`). A multi-pred join starts empty rather than guessing. */
        for (int i = 0; i < 8; ++i) fpu[i] = nullptr;
        fpu_top = 0; fcom_a = nullptr; fcom_b = nullptr;
        if (b.pred.size() == 1 && b.pred[0] >= 0 &&
            b.pred[0] < (int)block_fpu_out.size() && block_fpu_valid[b.pred[0]]) {
            for (int i = 0; i < 8; ++i)
                fpu[i] = block_fpu_out[b.pred[0]][i] ? clone(block_fpu_out[b.pred[0]][i]) : nullptr;
            fpu_top = block_fpu_top_out[b.pred[0]];
        }
        flags = FlagSrc();
        /* Inherit the flag state from a single predecessor: a compare in one block
         * feeding a conditional jump in the next (`cmp; jcc1; jcc2`, or the float
         * `ucomisd; jp; jne` idiom) would otherwise lose its condition -> `if(1)`. */
        if (b.pred.size() == 1 && b.pred[0] >= 0 &&
            b.pred[0] < (int)block_flags_out.size())
            flags = block_flags_out[b.pred[0]];
        /* Multi-predecessor merge: if EVERY predecessor exits with the same flag
         * source, the condition is well-defined at the join. A conditional jump
         * whose `cmp` sits in a dominating block before a join (e.g. `cmp
         * [rbx+0x27fc],0x14` falling into a labelled `jne` that is also a jump
         * target) otherwise lost its flags here and folded to `if (1)` / `if
         * (0==0)`. This is the flag analog of the cross-block register fixpoint. */
        else if (b.pred.size() > 1) {
            FlagSrc first; bool init = false, agree = true;
            for (int p : b.pred) {
                if (p < 0 || p >= (int)block_flags_out.size()) { agree = false; break; }
                const FlagSrc& fp = block_flags_out[p];
                if (!fp.valid) { agree = false; break; }
                if (!init) { first = fp; init = true; }
                else if (!flagsrc_equal(first, fp)) { agree = false; break; }
            }
            if (init && agree) flags = first;
            /* Diamond flag merge: the two arms of an if/else each end in a compare
             * that differs in EXACTLY ONE operand (`test x,0x10; je L; comiss z,[p];
             * jmp M; L: comiss z,[q]; M: seta cl`). The operands disagree so the
             * all-agree merge above fails and the condition collapses to `if (1)`,
             * turning the seta/jcc it feeds into an UNCONDITIONAL action (the guard on
             * the store it controls is dropped). Rebuild the differing operand as a
             * ternary selected by the grandparent branch that chose the arm — bit-exact
             * for every input. Tightly guarded to the clean diamond so no other shape
             * is affected. */
            else if (!agree && b.pred.size() == 2) {
                int p0 = b.pred[0], p1 = b.pred[1];
                if (p0 >= 0 && p1 >= 0 &&
                    p0 < (int)block_flags_out.size() && p1 < (int)block_flags_out.size() &&
                    p0 < (int)blocks.size() && p1 < (int)blocks.size()) {
                    const FlagSrc& f0 = block_flags_out[p0];
                    const FlagSrc& f1 = block_flags_out[p1];
                    if (f0.valid && f1.valid &&
                        f0.is_cmp==f1.is_cmp && f0.is_test==f1.is_test &&
                        f0.is_arith==f1.is_arith && f0.is_bt==f1.is_bt &&
                        f0.is_fcmp==f1.is_fcmp && f0.width==f1.width) {
                        bool a_same = exprEqual(f0.a, f1.a);
                        bool b_same = exprEqual(f0.b, f1.b);
                        Block& A0 = blocks[p0]; Block& A1 = blocks[p1];
                        /* differ in exactly one operand; both arms are single-pred to a
                         * common conditional grandparent whose two edges are these arms */
                        if ((a_same ^ b_same) &&
                            A0.pred.size()==1 && A1.pred.size()==1 &&
                            A0.pred[0]==A1.pred[0]) {
                            int g = A0.pred[0];
                            if (g >= 0 && g < (int)blocks.size()) {
                                Block& G = blocks[g];
                                if (G.ends_jcc && G.cond &&
                                    ((G.taken==p0 && G.fall==p1) ||
                                     (G.taken==p1 && G.fall==p0))) {
                                    const FlagSrc& ft = (G.taken==p0) ? f0 : f1; /* taken arm */
                                    const FlagSrc& ff = (G.taken==p0) ? f1 : f0; /* fall arm  */
                                    FlagSrc m = f0;   /* copy kind/width */
                                    if (a_same) {     /* a agrees, b differs */
                                        m.a = clone(f0.a);
                                        m.b = mkTernary(clone(G.cond), clone(ft.b), clone(ff.b), f0.width);
                                        if (f0.is_fcmp) m.b->is_float = true;
                                    } else {          /* b agrees, a differs */
                                        m.a = mkTernary(clone(G.cond), clone(ft.a), clone(ff.a), f0.width);
                                        if (f0.is_fcmp) m.a->is_float = true;
                                        m.b = clone(f0.b);
                                    }
                                    flags = m;
                                }
                            }
                        }
                    }
                }
            }
        }
        /* RSP is the symbolic frame base: a register that captures it (`mov rax,rsp`)
         * stays frame-relative so `[rax+off]` resolves to a stack slot instead of
         * collapsing to `[0+off]`. (push/sub-rsp are no-ops, so the marker holds.) */
        regfile[R_RSP] = mkReg(R_RSP, 8);
        /* seed regfile from block entry phi/temps (set by phi pass) */
        for (int i = 0; i < R_COUNT; ++i)
            if (entry_reg[b.id][i]) regfile[i] = clone(entry_reg[b.id][i]);
        /* seed packed-SIMD high lanes (a broadcast that crossed a block boundary) */
        if (b.id >= 0 && b.id < (int)entry_reg_hi.size())
            for (int i = 0; i < R_COUNT; ++i)
                if (entry_reg_hi[b.id][i]) regfile_hi[i] = clone(entry_reg_hi[b.id][i]);
        /* seed packed-FLOAT lanes (a loop-invariant broadcast set up in a preheader
         * survives into the loop body where mulps/addps consumes it). */
        if (b.id >= 0 && b.id < (int)entry_xmm_f.size())
            for (int i = 0; i < R_COUNT; ++i)
                if (entry_xmm_f[b.id][i][0]) {
                    for (int L = 0; L < 4; ++L)
                        xmm_f[i][L] = entry_xmm_f[b.id][i][L] ? clone(entry_xmm_f[b.id][i][L]) : nullptr;
                    xmm_f_real[i] = entry_xmm_f_real[b.id][i];
                }
        /* seed packed-INT lanes (guard-block `movd;pshufd` broadcast into the SSE body) */
        if (b.id >= 0 && b.id < (int)entry_xmm_i.size())
            for (int i = 0; i < R_COUNT; ++i)
                if (entry_xmm_i[b.id][i][0]) {
                    for (int L = 0; L < 4; ++L)
                        xmm_i[i][L] = entry_xmm_i[b.id][i][L] ? clone(entry_xmm_i[b.id][i][L]) : nullptr;
                    xmm_i_real[i] = entry_xmm_i_real[b.id][i];
                }
        /* seed cross-block vec-load-address facts (a wide reg loaded in a
         * predecessor block, stored here — the jump-table-unrolled memcpy).
         * vec_load_addr was already cleared at the top of exec_block. */
        if (b.id >= 0 && b.id < (int)entry_vla.size())
            for (int i = 0; i < R_COUNT; ++i)
                if (entry_vla[b.id][i])
                    vec_load_addr[(Reg)i] = clone(entry_vla[b.id][i]);
        /* seed cross-block vec-fill facts (a wide reg broadcast/zeroed in a
         * predecessor block, streamed out here — the jump-table-unrolled memset). */
        if (b.id >= 0 && b.id < (int)entry_vfill.size())
            for (int i = 0; i < R_COUNT; ++i)
                if (entry_vfill[b.id][i] && entry_vfill_esz[b.id][i])
                    vec_fill[(Reg)i] = { clone(entry_vfill[b.id][i]), entry_vfill_esz[b.id][i] };

        prev_insn = nullptr;
        for (size_t k = 0; k < b.insn_idx.size(); ++k) {
            const Insn& in = insns[b.insn_idx[k]];
            cur_insn_addr = in.addr; cur_insn_size = in.size;
            /* capture a gs:/fs: segment-override prefix (x86-64 encodes it in the
             * prefix bytes, not always in mem.segment) so resolve_mem/mem_to_expr
             * can model TEB/TLS accesses even when mem.segment is unset. */
            cur_insn_seg = 0;
            for (int pi = 0; pi < 4; ++pi) {
                if (in.x86.prefix[pi] == X86_PREFIX_GS) { cur_insn_seg = 1; break; }
                if (in.x86.prefix[pi] == X86_PREFIX_FS) { cur_insn_seg = 2; break; }
            }
            exec_insn(b, in);
            prev_insn = &in;
        }

        /* record live-out register expressions */
        for (int i = 0; i < R_COUNT; ++i) {
            b.reg_out[i] = regfile[i] ? clone(regfile[i]) : nullptr;
            b.reg_out_hi[i] = regfile_hi[i] ? clone(regfile_hi[i]) : nullptr;
            b.reg_out_f_real[i] = xmm_f_real[i];
            for (int L = 0; L < 4; ++L)
                b.reg_out_f[i][L] = xmm_f[i][L] ? clone(xmm_f[i][L]) : nullptr;
            b.reg_out_i_real[i] = xmm_i_real[i];
            for (int L = 0; L < 4; ++L)
                b.reg_out_i[i][L] = xmm_i[i][L] ? clone(xmm_i[i][L]) : nullptr;
            /* publish the vec-load-address fact so a successor block (the store
             * side of a jump-table-unrolled memcpy) can inherit it. */
            auto vit = vec_load_addr.find((Reg)i);
            b.reg_out_vla[i] = (vit != vec_load_addr.end() && vit->second)
                                   ? clone(vit->second) : nullptr;
            /* publish the vec-fill fact (broadcast/zero) for the store side of a
             * jump-table-unrolled memset. */
            auto fit2 = vec_fill.find((Reg)i);
            if (fit2 != vec_fill.end() && fit2->second.val && fit2->second.esz) {
                b.reg_out_vfill[i] = clone(fit2->second.val);
                b.reg_out_vfill_esz[i] = fit2->second.esz;
            } else {
                b.reg_out_vfill[i] = nullptr;
                b.reg_out_vfill_esz[i] = 0;
            }
        }
        if (b.id >= 0 && b.id < (int)block_flags_out.size())
            block_flags_out[b.id] = flags;
        /* publish the x87 stack so a single successor can inherit it (see the reset above) */
        if (b.id >= 0 && b.id < (int)block_fpu_out.size()) {
            for (int i = 0; i < 8; ++i)
                block_fpu_out[b.id][i] = fpu[i] ? clone(fpu[i]) : nullptr;
            block_fpu_top_out[b.id] = fpu_top;
            block_fpu_valid[b.id] = 1;
        }

        /* branch condition */
        const Insn* last = b.insn_idx.empty() ? nullptr : &insns[b.insn_idx.back()];
        if (last && last->is_jcc && !b.drop_branch) {
            CC cc = jcc_of(last->id);
            b.cc = cc;
            b.cond = cc_to_expr(cc, flags);
        }
        /* tail call: a `jmp <func>` whose target leaves this function returns the
         * callee's result. Fires when there is no in-function successor (b.taken<0)
         * OR the target is OUTSIDE [f->rva, f->rva+size) — the engine sometimes
         * over-extends a neighbor's range so the jmp got linked to an in-image
         * block that is really foreign code (DllMain -> 0x5e34c, which sits inside
         * 0x5e2c8's range). In that case sever the spurious edge so the block is
         * terminal and the tail call is emitted instead of a goto into the neighbor. */
        bool jmp_outside = last && last->is_jmp && last->has_branch_target &&
            f && f->size && (last->branch_target < f->rva ||
                             last->branch_target >= f->rva + f->size);
        if (last && last->is_jmp && last->has_branch_target && !b.is_switch &&
            (b.taken < 0 || jmp_outside)) {
            if (jmp_outside && b.taken >= 0) {
                for (auto it = b.succ.begin(); it != b.succ.end(); )
                    it = (*it == b.taken) ? b.succ.erase(it) : it + 1;
                b.taken = -1;
            }
            uint64_t tgt = last->branch_target;
            bool is_func = false;
            for (size_t i = 0; i < e->func_len; ++i)
                if (e->funcs[i].rva == tgt) { is_func = true; break; }
            /* A terminal `jmp <addr>` with no in-function successor is a TAIL CALL
             * even when the engine didn't list <addr> as a function (DllMain ->
             * 0x5e34c, CRT thunks). Accept any in-image code RVA so the call —
             * `return fun_<addr>(args)` — is recovered instead of dropped. */
            if (is_func || (tgt > 0 && tgt < e->image_size)) {
                std::string callee = name_for_rva(tgt);
                int rk = 2, pc = 4; unsigned char fmask = 0;
                if (sigtab && sigtab->count(tgt)) {
                    rk = sigtab->at(tgt).ret_kind; pc = sigtab->at(tgt).param_count;
                    fmask = sigtab->at(tgt).float_mask;
                }
                /* A TAIL CALL to a `j_<api>` import thunk (`jmp j_memset`) or to a
                 * recognized API inherits that API's arity — the thunk's jmp-only
                 * body gave the sigtab 0 params, so `return j_memset()` dropped all
                 * args (cabinet fn_00019fd0/fn_00017e44). Mirrors the direct-call
                 * thunk override; strip a leading `j_` then consult known_api. */
                {
                    int aargc, ark;
                    std::string base = (callee.rfind("j_", 0) == 0) ? callee.substr(2) : callee;
                    if (known_api(base, aargc, ark)) { pc = aargc; rk = ark; fmask = 0; }
                }
                extern_callees[callee] = rk;
                auto call = new_expr();
                call->kind = EK::Call; call->callee = callee; call->width = 8;
                call->ret_kind = rk;
                Reg argregs[4] = { R_RCX, R_RDX, R_R8, R_R9 };
                Reg xmmregs[4] = { R_XMM0, R_XMM1, R_XMM2, R_XMM3 };
                if (pc < 0) pc = 0;
                if (pc > 16) pc = 16;
                for (int i = 0; i < pc; ++i) {
                    if (i < 4) {
                        /* a float/double param arrives in xmm[i], not the integer
                         * reg — pull the right class per the callee's float_mask so
                         * a tail call `jmp my_sqrt` passes the computed xmm0 value
                         * (dist2d's dx*dx+dy*dy) instead of the integer rcx. */
                        if (fmask & (1u << i)) {
                            ExprP fv = reg_value(xmmregs[i], 8);
                            if (fv) fv->is_float = true;
                            call->args.push_back(fv);
                        } else {
                            call->args.push_back(reg_value(argregs[i], 8));
                        }
                    } else {
                        int64_t off = 0x20 + 8 * (int64_t)(i - 4);
                        std::string nm = slot_name(off, 8);
                        int w = var_width.count(nm) ? var_width[nm] : 8;
                        call->args.push_back(mkVar(nm, w));
                    }
                }
                b.tail_call = call;
                if (rk != 0 && used_return) {
                    b.ret_value = truncate(call, ret_width >= 8 ? 8 : 4);
                    b.has_ret_value = true;
                }
            }
        }

        /* INDIRECT tail jump: `jmp dword ptr [IAT]` (import thunk), `jmp [vtable]`
         * or `jmp reg`, with no in-function successor. By the ABI the callee
         * returns to OUR caller — this is a TAIL CALL, not a fall-through to an
         * empty return. Emitting `return;` here is semantically wrong (the classic
         * flattened-thunk bug) and silently corrupts any caller that inlines it.
         * Render it as `return target(args);` so control visibly leaves. */
        if (last && last->is_jmp && !last->has_branch_target && !b.is_switch &&
            b.succ.empty() && last->x86.op_count >= 1) {
            const cs_x86_op& t = last->x86.operands[0];
            std::string callee; bool indirect = false;
            ExprP itgt;   /* indirect-call target, kept as a live child for dataflow */
            if (t.type == X86_OP_MEM) {
                const x86_op_mem& m = t.mem;
                /* candidate IAT-slot RVAs: rip-relative (x64) or absolute (x86,
                 * where the disp is a VA = base+rva). */
                std::vector<uint64_t> cands;
                if (m.base == X86_REG_RIP && m.index == X86_REG_INVALID)
                    cands.push_back(last->addr + last->size + (uint64_t)m.disp);
                if (m.base == X86_REG_INVALID && m.index == X86_REG_INVALID) {
                    cands.push_back((uint64_t)m.disp);
                    if ((uint64_t)m.disp >= e->base)
                        cands.push_back((uint64_t)m.disp - e->base);
                }
                std::string nm;
                for (uint64_t a : cands) {
                    for (size_t i = 0; i < e->import_len; ++i)
                        if (e->imports[i].iat_rva == a && e->imports[i].name[0]) {
                            nm = sani(e->imports[i].name); break;
                        }
                    if (!nm.empty()) break;
                }
                if (!nm.empty()) { callee = nm; extern_callees[nm] = 2; }
                else {
                    ExprP md = resolve_mem(t, 8);
                    std::string fn; int rk2, pc2;
                    if (const_callee_name(md, fn, rk2, pc2)) { callee = fn; extern_callees[fn] = rk2; }
                    else { callee = "((long long(*)())(" + render(md) + "))"; indirect = true; itgt = md; }
                }
            } else if (t.type == X86_OP_REG) {
                Reg r; int w; map_reg(t.reg, r, w);
                ExprP rv = reg_value(r, 8);
                std::string fn; int rk2, pc2;
                if (const_callee_name(rv, fn, rk2, pc2)) { callee = fn; extern_callees[fn] = rk2; }
                else { callee = "((long long(*)())(" + render(rv) + "))"; indirect = true; itgt = rv; }
            }
            if (!callee.empty()) {
                auto call = new_expr();
                call->kind = EK::Call; call->callee = callee; call->indirect = indirect;
                /* Keep the indirect target as a live child (call->a), NOT only baked
                 * into the callee string. Otherwise the target value (`t = f(); call
                 * t;`) is invisible to gather/DSE/copy-prop: its def gets eliminated
                 * as "unused" while the string use survives -> an UNDECLARED
                 * identifier (uncompilable C). With it as a child, the def is kept,
                 * the value is declared, and copy-prop can inline it. Rendered lazily
                 * (see EK::Call render) so the text always reflects the live child. */
                if (indirect && itgt) call->a = itgt;
                call->width = 8; call->ret_kind = 2;
                /* x64 forwards the register args; x86 thunks forward stack args
                 * transparently (we don't enumerate them). */
                if (e->arch == DS_ARCH_X64) {
                    Reg argregs[4] = { R_RCX, R_RDX, R_R8, R_R9 };
                    for (int i = 0; i < 4; ++i)
                        call->args.push_back(reg_value(argregs[i], 8));
                }
                b.tail_call = call;
                used_return = true;
                b.ret_value = truncate(call, ret_width >= 8 ? 8 : 4);
                b.has_ret_value = true;
            }
        }

        /* return value: xmm0 for a float/double return, else rax. A 32-bit /arch:IA32
         * function returns its float on the x87 stack in ST(0) instead, so prefer a live
         * ST(0) — on x64 the FPU stack is always empty and this falls through to xmm0. */
        if (b.ends_ret && used_return) {
            if (ret_is_float) {
                ExprP fsrc = fpu_slot(0) ? fpu_slot(0) : regfile[R_XMM0];
                ExprP rv = fsrc ? clone(fsrc) : nullptr;
                if (rv) {
                    rv->is_float = true; rv->width = ret_width;
                    b.ret_raw = clone(rv);
                    b.ret_value = rv;              /* no integer truncation on FP */
                    b.has_ret_value = true;
                }
            } else {
                ExprP rv = regfile[R_RAX] ? clone(regfile[R_RAX]) : nullptr;
                if (rv) {
                    b.ret_raw = clone(rv);
                    int rw = ret_byte_return ? 1 : (ret_width >= 8 ? 8 : 4);
                    /* fold so the byte mask collapses: `(signed char)(t2 & -256)`
                     * -> 0 (the byte-return / `xor al,al` case). */
                    b.ret_value = fold(truncate(rv, rw));
                    b.has_ret_value = true;
                }
            }
        }
        /* rebind a recovered jump-table switch to the index register's REAL
         * dataflow value, but ONLY when (a) the CFG-time index is trivial (folds
         * to a constant — the broken `switch(0)`), and (b) the resolved value is
         * CLEAN (no `in_<REG>` backstop). A 2-level sparse table's index register
         * holds a byte-table load off an unrecovered base (in_R8) and dispatches on
         * the table rank — keeping its already-correct real-value index instead. */
        if (b.is_switch) {
            bool trivial = !b.switch_var;
            if (b.switch_var) { ExprP f = fold(clone(b.switch_var)); trivial = (f && f->kind == EK::Const); }
            if (trivial) {
                /* Prefer the value snapshotted AT the table load (the real selector);
                 * fall back to the block-exit register value for simple tables where
                 * the index survives to the end. */
                auto snap = switch_resolved_index.find(b.id);
                if (snap != switch_resolved_index.end() && snap->second &&
                    !expr_has_in_backstop(snap->second)) {
                    b.switch_var = clone(snap->second);
                } else {
                    auto it = switch_cmp_reg.find(b.id);
                    if (it != switch_cmp_reg.end() && regfile[it->second] &&
                        !expr_has_in_backstop(regfile[it->second]))
                        b.switch_var = clone(regfile[it->second]);
                }
            }
        }
    }

    /* High half of a 2w-bit product (the RDX output of one-operand `imul`/`mul`).
     * For w<=4 the high half is portable C: `(int)(((long long)a * b) >> 32)`. For
     * the 64-bit case there is no portable 2x type, so emit a `mulh`/`umulh` node
     * that renders as the MSVC `__mulh`/`__umulh` intrinsic — correct and the input
     * to magic-number division reconstruction. */
    ExprP mulhi_expr(const ExprP& a, const ExprP& src, int w, bool uns) {
        if (w <= 4) {
            int wide = w * 2;
            ExprP wa = mkCast(cast_str(wide, uns), clone(a), wide, uns);
            ExprP wb = mkCast(cast_str(wide, uns), clone(src), wide, uns);
            ExprP prod = mkBinary("*", wa, wb, wide, uns);
            ExprP hi = mkBinary(">>", prod, mkConst((int64_t)w * 8, wide), wide, uns);
            return mkCast(cast_str(w, uns), hi, w, uns);
        }
        ExprP r = mkBinary(uns ? "umulh" : "mulh", clone(a), clone(src), w);
        used_mulh = true;
        return r;
    }
    bool used_mulh = false;   /* a __mulh/__umulh appears -> emit its prototype */
    bool used_mxcsr = false;  /* __readmxcsr/__writemxcsr appears -> emit prototypes */
    bool used_fabs = false;   /* fabs/fabsf appears (andps abs idiom) -> emit prototypes */
    bool used_sqrt = false;   /* sqrtss/sqrtsd (inlined sqrt) appears -> emit prototypes */
    bool used_fdiv0 = false;   /* `x / 0.0` inf idiom -> emit a volatile zero divisor */
    bool used_while_true = false; /* emitted `while (true)` -> needs <stdbool.h> in C mode */
    std::string self_fname;   /* sanitized name of THIS function (for recursive-call arity) */
    bool used_stos = false;   /* __stosb/w/d/q appears (rep stos fill) -> emit prototypes */
    bool used_movs = false;   /* __movsb/w/d/q appears (rep movs copy) -> emit prototypes */
    bool used_meminstr = false; /* an emitted memcpy/memset -> #include <string.h> */
    std::set<std::string> used_interlocked;  /* _Interlocked* named -> emit prototypes */
    std::set<std::string> used_byteswap;      /* _byteswap_* named -> emit prototypes */
    bool used_null = false;   /* `NULL` was rendered -> pull in <stddef.h> */
    bool used_fastfail = false; /* __fastfail appears (int 0x29) -> emit prototype */
    bool used_nearbyint = false; /* nearbyintf appears (cvtps2dq rounding) -> prototype */
    std::set<std::string> used_mathfn;  /* floorf/ceilf/truncf/nearbyint/sqrtf from round/rsqrt -> protos */
    bool used_shift128 = false;  /* __shiftright128/__shiftleft128 (64-bit shrd/shld) */
    bool used_rdtsc = false;     /* __rdtsc (rdtsc/rdtscp) -> prototype */
    bool used_xgetbv = false;    /* _xgetbv (xgetbv) -> prototype */
    bool used_syscall = false;   /* __syscall (syscall/sysenter) -> prototype */
    /* exactly which _rotl/_rotr forms this function used -> declare only those */
    std::set<std::string> used_rot_fns;
    /* likewise for the __scas*_eq/_ne scan forms (rep scas) -> declare only those */
    std::set<std::string> used_scas_fns;
    /* likewise for the __cmps*_eq/_ne compare forms (rep cmps = inlined memcmp) */
    std::set<std::string> used_cmps_fns;
    bool used_cpuid = false;  /* __cpuid_e?x appears -> emit prototypes */
    bool used_segread = false; /* __readgsqword/__readfsqword appears -> emit prototypes */
    bool used_nt_current_teb = false; /* NtCurrentTeb() emitted -> emit its macro prelude */
    bool used_u2f = false;     /* __u2f (uint bits -> float) helper for a movd xmm,r bit reinterpret */
    bool used_f32hi = false;   /* __f32_hi (clear low 16 mantissa bits) — the Dekker high-part idiom */
    bool used_min = false, used_max = false; /* __min/__max recovered from a select ternary */

    /* Classify a VEX FMA opcode: element width (4/8), operand variant (132/213/231),
     * whether the product is negated (fnmadd/fnmsub), whether the addend is
     * subtracted (fmsub/fnmsub). Returns false for a non-FMA id. */
    static bool fma_props(unsigned id, int& w, int& variant, bool& negp, bool& subc) {
        switch (id) {
            case X86_INS_VFMADD132SS:  w=4; variant=132; negp=false; subc=false; return true;
            case X86_INS_VFMADD213SS:  w=4; variant=213; negp=false; subc=false; return true;
            case X86_INS_VFMADD231SS:  w=4; variant=231; negp=false; subc=false; return true;
            case X86_INS_VFMADD132SD:  w=8; variant=132; negp=false; subc=false; return true;
            case X86_INS_VFMADD213SD:  w=8; variant=213; negp=false; subc=false; return true;
            case X86_INS_VFMADD231SD:  w=8; variant=231; negp=false; subc=false; return true;
            case X86_INS_VFNMADD132SS: w=4; variant=132; negp=true;  subc=false; return true;
            case X86_INS_VFNMADD213SS: w=4; variant=213; negp=true;  subc=false; return true;
            case X86_INS_VFNMADD231SS: w=4; variant=231; negp=true;  subc=false; return true;
            case X86_INS_VFNMADD132SD: w=8; variant=132; negp=true;  subc=false; return true;
            case X86_INS_VFNMADD213SD: w=8; variant=213; negp=true;  subc=false; return true;
            case X86_INS_VFNMADD231SD: w=8; variant=231; negp=true;  subc=false; return true;
            case X86_INS_VFMSUB132SS:  w=4; variant=132; negp=false; subc=true;  return true;
            case X86_INS_VFMSUB213SS:  w=4; variant=213; negp=false; subc=true;  return true;
            case X86_INS_VFMSUB231SS:  w=4; variant=231; negp=false; subc=true;  return true;
            case X86_INS_VFMSUB132SD:  w=8; variant=132; negp=false; subc=true;  return true;
            case X86_INS_VFMSUB213SD:  w=8; variant=213; negp=false; subc=true;  return true;
            case X86_INS_VFMSUB231SD:  w=8; variant=231; negp=false; subc=true;  return true;
            case X86_INS_VFNMSUB132SS: w=4; variant=132; negp=true;  subc=true;  return true;
            case X86_INS_VFNMSUB213SS: w=4; variant=213; negp=true;  subc=true;  return true;
            case X86_INS_VFNMSUB231SS: w=4; variant=231; negp=true;  subc=true;  return true;
            case X86_INS_VFNMSUB132SD: w=8; variant=132; negp=true;  subc=true;  return true;
            case X86_INS_VFNMSUB213SD: w=8; variant=213; negp=true;  subc=true;  return true;
            case X86_INS_VFNMSUB231SD: w=8; variant=231; negp=true;  subc=true;  return true;
            default: return false;
        }
    }

    /* `rep movs` copies rcx elements from [rsi] to [rdi] — how the compiler spells an
     * inlined memcpy (a fixed-size struct/array copy). It was UNMODELED, so the whole
     * copy was silently dropped: the destination kept its stale value and every use
     * downstream read a lie. Same failure mode the `rep stos` fill had. Model it as the
     * MSVC __movs* intrinsic (a real side-effecting call), then advance rsi/rdi and zero
     * rcx exactly as the rep does. A bare (non-rep) movs copies one element.
     * The direction flag is assumed forward, as `rep stos` already does — compilers do
     * not emit `std`-prefixed copies. */
    void emit_string_move(Block& b, const Insn& in, int sz, bool has_rep) {
        if (has_rep) {
            const char* fn = (sz==1)?"__movsb":(sz==2)?"__movsw":(sz==4)?"__movsd":"__movsq";
            const char* pt = (sz==1)?"(unsigned char*)":(sz==2)?"(unsigned short*)":
                             (sz==4)?"(unsigned long*)":"(unsigned long long*)";
            const char* st = (sz==1)?"(const unsigned char*)":(sz==2)?"(const unsigned short*)":
                             (sz==4)?"(const unsigned long*)":"(const unsigned long long*)";
            auto call = new_expr();
            call->kind = EK::Call; call->callee = fn; call->width = 0; call->ret_kind = 5;
            ExprP dst = reg_value(R_RDI, 8), src = reg_value(R_RSI, 8), cnt = reg_value(R_RCX, 8);
            if (dst) call->args.push_back(mkCast(pt, dst, 8, true));
            if (src) call->args.push_back(mkCast(st, src, 8, true));
            if (cnt) call->args.push_back(mkCast("(unsigned long long)", cnt, 8, true));
            Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
            b.stmts.push_back(std::move(s));
            used_movs = true;
            /* rcx is read into both advances BEFORE it is zeroed. */
            regfile[R_RDI] = mkBinary("+", reg_value(R_RDI,8),
                             mkBinary("*", reg_value(R_RCX,8), mkConst(sz,8), 8), 8);
            regfile[R_RSI] = mkBinary("+", reg_value(R_RSI,8),
                             mkBinary("*", reg_value(R_RCX,8), mkConst(sz,8), 8), 8);
            regfile[R_RCX] = mkConst(0, 8);
        } else {
            ExprP lv = mkMem(reg_value(R_RDI, 8), sz, false);
            emit_store(b, lv, mkMem(reg_value(R_RSI, 8), sz, false), in.addr);
            regfile[R_RDI] = mkBinary("+", reg_value(R_RDI,8), mkConst(sz,8), 8);
            regfile[R_RSI] = mkBinary("+", reg_value(R_RSI,8), mkConst(sz,8), 8);
        }
    }

    /* Which rep prefix an instruction carries: 0 none, 1 rep/repe (0xf3), 2 repne (0xf2).
     * The scan ops are the first lifter code that has to tell repe from repne, and the
     * `== X86_PREFIX_REP` test the movs/stos cases use CANNOT: X86_PREFIX_REP and
     * X86_PREFIX_REPE are the SAME enumerator (0xf3), and repne (0xf2) equals neither.
     * movs/stos keep their own test — they only ever carry 0xf3. */
    int rep_kind(const cs_x86& x) {
        for (int pi = 0; pi < 4; ++pi) {
            if (x.prefix[pi] == X86_PREFIX_REPNE) return 2;
            if (x.prefix[pi] == X86_PREFIX_REP) return 1;    /* == X86_PREFIX_REPE */
        }
        return 0;
    }

    /* Does this instruction carry the LOCK prefix (0xf0)?
     *
     * Unlike most gaps this one is NOT a correctness bug: the xadd/cmpxchg/xchg handlers
     * below already model the read-modify-write faithfully, old-value semantics included.
     * What a load/store pair cannot express is ATOMICITY. A refcount release currently
     * reads as
     *     v1 = *(int32_t*)(qword_174c80);
     *     *(int32_t*)(qword_174c80) = v1 - 1;
     *     if (v1 != 1 || ...)
     * which is correct, and tells the reader nothing about why it is safe or that the
     * `v1 != 1` test is the classic "was I the last reference" check. Naming the intrinsic
     * says both in one line, and is what Hex-Rays emits. */
    bool has_lock(const cs_x86& x) {
        for (int pi = 0; pi < 4; ++pi)
            if (x.prefix[pi] == X86_PREFIX_LOCK) return true;
        return false;
    }

    /* `lock <op> [mem], src` IS an _Interlocked* intrinsic. Handles the read-modify-writes
     * that DISCARD the old value and keep only the flags (lock or/and/xor/add/inc/dec — 48 of
     * NullWare's 66 lock sites); `lock xadd` and `lock cmpxchg` have their own cases because
     * they hand the old value to a register.
     *
     * Every one of these renders today as an ordinary non-atomic statement. The VALUE is
     * right; what is missing is that the operation is indivisible, which is the only reason
     * the surrounding code is correct. `_InterlockedOr(&flags, 4)` and `flags |= 4` are the
     * same arithmetic and completely different programs.
     *
     * The old value is bound to a temp even when only the flags are wanted, because that is
     * what the intrinsic RETURNS -- rebuilding the new value from it keeps the following jcc
     * exact instead of leaving the flags holding an earlier, unrelated compare. The temp is
     * never dead-stripped: _Interlocked* starts with ONE underscore, so is_pure_callee treats
     * it as impure and DSE must keep the call.
     * `cop` is the C operator; `nm` the intrinsic base name. DS_NO_INTERLOCKED. */
    bool try_interlocked_rmw(Block& b, const Insn& in, const cs_x86& x,
                             const char* cop, const char* nm, ExprP src_override = nullptr) {
        if (std::getenv("DS_NO_INTERLOCKED")) return false;
        if (!has_lock(x)) return false;
        if (x.op_count < 1 || x.operands[0].type != X86_OP_MEM) return false;
        int w = x.operands[0].size ? x.operands[0].size : 4;
        if (w != 4 && w != 8) return false;          /* only the widths with an intrinsic */
        ExprP src = src_override ? src_override
                                 : (x.op_count >= 2 ? rvalue(x.operands[1]) : nullptr);
        if (!src) return false;
        auto call = new_expr();
        call->kind = EK::Call;
        call->callee = std::string(nm) + (w == 8 ? "64" : "");
        call->width = w;
        call->ret_kind = (w == 8) ? 2 : 1;
        call->args.push_back(mkCast(w == 8 ? "(volatile long long*)" : "(volatile long*)",
                                    addr_of_mem(x.operands[0]), 8, true));
        call->args.push_back(clone(src));
        used_interlocked.insert(call->callee);
        ExprP oldv = snapshot_to_temp(b, call, w, in.addr);   /* the call, emitted exactly once */
        /* flags come from the NEW value = old <op> src */
        set_flags_arith(mkBinary(cop, clone(oldv), clone(src), w), w);
        return true;
    }

    /* `repne scas` is an inlined strlen/memchr (scan UNTIL al matches), `repe scas` an
     * inlined "skip while equal" (ntdll's RtlCompareMemoryUlong). Both were UNMODELED,
     * and the damage ran well past the dropped scan: the op's only architectural purpose
     * is to feed the following jcc via ZF, so that jcc silently read whatever wrote the
     * flags LAST — two blocks up — and rendered a confident LIE rather than a stale value.
     * rcx never advancing then folded the trip count to a constant.
     * There is no MSVC intrinsic for scas, so declare our own (as __movs* does) returning
     * the FINAL rdi: that one value expresses the new rdi, the consumed count AND the ZF
     * exactly, so a single call models the entire op.
     * ZF: once the rep terminates, ZF reflects the LAST compare — `val == *(rdi_end - sz)`
     * — for repe and repne alike. That is exact whenever at least one iteration ran. A rep
     * entered with rcx==0 leaves ZF untouched instead, which this does NOT model; compilers
     * guard the zero case with a jcc first (the `je` just above this very scasd does), so
     * real code always enters with rcx != 0.
     * Direction is assumed forward, exactly as the movs/stos cases already assume. */
    void emit_string_scan(Block& b, const Insn& in, int sz, int rk) {
        if (rk == 0) {
            /* A bare scas is just `cmp al,[rdi]; rdi += sz` — exact, and needs no call. */
            flags = FlagSrc();
            flags.valid = true; flags.is_cmp = true;
            flags.a = reg_value(R_RAX, sz);
            flags.b = mkMem(reg_value(R_RDI, 8), sz, true);
            flags.width = sz;
            regfile[R_RDI] = mkBinary("+", reg_value(R_RDI,8), mkConst(sz,8), 8);
            return;
        }
        const char* fn = (rk == 2) ? ((sz==1)?"__scasb_ne":(sz==2)?"__scasw_ne":
                                      (sz==4)?"__scasd_ne":"__scasq_ne")
                                   : ((sz==1)?"__scasb_eq":(sz==2)?"__scasw_eq":
                                      (sz==4)?"__scasd_eq":"__scasq_eq");
        const char* pt = (sz==1)?"(const unsigned char*)":(sz==2)?"(const unsigned short*)":
                         (sz==4)?"(const unsigned long*)":"(const unsigned long long*)";
        const char* vt = (sz==1)?"(unsigned char)":(sz==2)?"(unsigned short)":
                         (sz==4)?"(unsigned long)":"(unsigned long long)";
        /* rdi and rcx are read into the call AND into the post-scan arithmetic, so take
         * their values BEFORE either is overwritten (emit_string_move's warning). */
        ExprP base = reg_value(R_RDI, 8), base_pre = reg_value(R_RDI, 8);
        ExprP cnt = reg_value(R_RCX, 8);
        ExprP val = reg_value(R_RAX, sz);
        auto call = new_expr();
        call->kind = EK::Call; call->callee = fn; call->width = 8; call->ret_kind = 2;
        if (base) call->args.push_back(mkCast(pt, base, 8, true));
        if (val)  call->args.push_back(mkCast(vt, val, sz, true));
        if (cnt)  call->args.push_back(mkCast("(unsigned long long)", cnt, 8, true));
        /* The temp is MANDATORY, not a readability choice: set_reg stores the expr BY
         * VALUE, so letting rdi AND rcx each take the Call directly would CLONE it and
         * emit the scan TWICE. simplify_unused_call_temps folds it back to a bare call
         * statement when the returned pointer turns out to be dead. */
        std::string tn = "t" + std::to_string(++temp_seq);
        call_temps.insert(tn);
        var_width[tn] = 8; var_is_ll[tn] = true;
        Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, 8); s.rhs = call; s.addr = in.addr;
        b.stmts.push_back(std::move(s));
        used_scas_fns.insert(fn);
        /* elements consumed = (rdi_end - rdi_start) / sz; the divide is elided for scasb. */
        ExprP adv = mkBinary("-", mkVar(tn, 8), base_pre, 8);
        if (sz != 1) adv = mkBinary("/", adv, mkConst(sz, 8), 8, true);
        regfile[R_RCX] = mkBinary("-", cnt, adv, 8);
        regfile[R_RDI] = mkVar(tn, 8);
        flags = FlagSrc();
        flags.valid = true; flags.is_cmp = true;
        flags.a = reg_value(R_RAX, sz);
        flags.b = mkMem(mkBinary("-", mkVar(tn, 8), mkConst(sz, 8), 8), sz, true);
        flags.width = sz;
    }

    /* `rep cmps` is an inlined memcmp: `repe cmps` compares [rsi] vs [rdi] while EQUAL until
     * a mismatch or rcx==0; `repne cmps` while NOT equal (RtlCompareMemory's inverse). Both
     * were UNMODELED — the compare vanished and the following jcc read whatever wrote the
     * flags LAST (two blocks up), a confident LIE, exactly the failure emit_string_scan
     * documents for scas. There is no MSVC intrinsic for cmps, so declare our own returning
     * the FINAL rdi: the two pointers advance in lock-step, so that one value expresses the
     * new rdi, the new rsi (rsi_start + the same advance), the consumed count AND the ZF.
     * ZF reflects the LAST compare — `*(rsi_end - sz) == *(rdi_end - sz)` — for repe and repne
     * alike, exact whenever at least one iteration ran (compilers guard rcx==0 with a jcc, as
     * the movs/scas cases already rely on). Forward direction assumed, as movs/stos/scas do. */
    void emit_string_cmp(Block& b, const Insn& in, int sz, int rk) {
        if (rk == 0) {
            /* bare cmps: `cmp [rsi],[rdi]; rsi += sz; rdi += sz` — exact, no call needed. */
            flags = FlagSrc();
            flags.valid = true; flags.is_cmp = true;
            flags.a = mkMem(reg_value(R_RSI, 8), sz, true);
            flags.b = mkMem(reg_value(R_RDI, 8), sz, true);
            flags.width = sz;
            regfile[R_RSI] = mkBinary("+", reg_value(R_RSI,8), mkConst(sz,8), 8);
            regfile[R_RDI] = mkBinary("+", reg_value(R_RDI,8), mkConst(sz,8), 8);
            return;
        }
        const char* fn = (rk == 2) ? ((sz==1)?"__cmpsb_ne":(sz==2)?"__cmpsw_ne":
                                      (sz==4)?"__cmpsd_ne":"__cmpsq_ne")
                                   : ((sz==1)?"__cmpsb_eq":(sz==2)?"__cmpsw_eq":
                                      (sz==4)?"__cmpsd_eq":"__cmpsq_eq");
        const char* pt = (sz==1)?"(const unsigned char*)":(sz==2)?"(const unsigned short*)":
                         (sz==4)?"(const unsigned long*)":"(const unsigned long long*)";
        ExprP src  = reg_value(R_RSI, 8), src_pre = reg_value(R_RSI, 8);
        ExprP dst  = reg_value(R_RDI, 8), dst_pre = reg_value(R_RDI, 8);
        ExprP cnt  = reg_value(R_RCX, 8);
        auto call = new_expr();
        call->kind = EK::Call; call->callee = fn; call->width = 8; call->ret_kind = 2;
        if (src) call->args.push_back(mkCast(pt, src, 8, true));
        if (dst) call->args.push_back(mkCast(pt, dst, 8, true));
        if (cnt) call->args.push_back(mkCast("(unsigned long long)", cnt, 8, true));
        std::string tn = "t" + std::to_string(++temp_seq);
        call_temps.insert(tn);
        var_width[tn] = 8; var_is_ll[tn] = true;
        Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, 8); s.rhs = call; s.addr = in.addr;
        b.stmts.push_back(std::move(s));
        used_cmps_fns.insert(fn);
        /* advance (bytes) = rdi_end - rdi_start; both pointers move by it, rcx by adv/sz. */
        ExprP adv = mkBinary("-", mkVar(tn, 8), dst_pre, 8);
        ExprP advElems = (sz == 1) ? clone(adv) : mkBinary("/", clone(adv), mkConst(sz, 8), 8, true);
        regfile[R_RDI] = mkVar(tn, 8);
        regfile[R_RSI] = mkBinary("+", src_pre, clone(adv), 8);
        regfile[R_RCX] = mkBinary("-", cnt, advElems, 8);
        flags = FlagSrc();
        flags.valid = true; flags.is_cmp = true;
        flags.a = mkMem(mkBinary("-", mkBinary("+", clone(src_pre), clone(adv), 8), mkConst(sz,8), 8), sz, true);
        flags.b = mkMem(mkBinary("-", mkVar(tn, 8), mkConst(sz, 8), 8), sz, true);
        flags.width = sz;
    }

    void exec_insn(Block& b, const Insn& in) {
        const cs_x86& x = in.x86;
        unsigned id = in.id;
        int nop = x.op_count;
        const cs_x86_op* ops = x.operands;      /* repointed for VEX normalization */
        cs_x86_op vnops[4];
        auto OP = [&](int i) -> const cs_x86_op& { return ops[i]; };
        /* Set when the VEX width guard below refuses to remap a 256/512-bit form. It is the
         * ONLY thing that licenses the opaque memory-store fallback in the default case:
         * capstone reports a VEX store's memory operand as access=READ (1), not WRITE (2)
         * — measured on `vmovdqu ymmword ptr [rcx], ymm0` — so the access bits cannot be
         * trusted to identify the destination, and "operand 0 is memory" alone would also
         * catch read-only `cmp [mem], reg` / `test [mem], reg`. */
        bool vex_wide_refused = false;

        /* ---- AVX / VEX scalar-float normalization ---------------------------
         * The VEX-encoded float ops are the non-destructive 3-operand forms of
         * the SSE ops the lifter already models. For the ops that do NOT read the
         * destination as a source (moves, sqrt, convert, compare) we can remap the
         * id to the SSE opcode and, for the 3-operand forms, present a 2-operand
         * {dst, src2} view — every existing SSE handler then applies unchanged, so
         * AVX-built binaries (all of NullWare) recover their float math instead of
         * dropping it (empty branches / `return 0`). Binary arith, xorps/andps and
         * FMA — where dst != src1 carries data — get dedicated cases below. */
        {
            unsigned sse = 0; bool take_op2 = false;
            /* THE REMAP IS ONLY SOUND AT 128 BITS. Every SSE handler below hardcodes 16
             * bytes — the store paths gate on `OP(0).size == 16` and the lane arrays are
             * xmm_f[..][4]. A 256-bit ymm operand is 32 bytes, so it FAILS that gate, skips
             * the packed-store block entirely, and falls through to the bare `do_dst` at the
             * bottom of the case — which commits a NARROW store of an unmapped (backstop)
             * register. Measured, before this guard, on _qa/fixtures/ymm/ymmtest.c:
             *
             *   void ymm_copy32(char* dst, const char* src)   <- the truth: 32 bytes copied
             *   void ymm_copy32(int32_t*a1) { *a1 = 0; }      <- what we emitted
             *
             * The `src` param is gone, and a 32-byte copy is reported as a 4-byte zero. It
             * compiles clean, so the 1497/1497 cl gate is blind to it: a textbook confident
             * lie. Refusing the remap makes the op fall to the unmodeled path, which is a
             * loud, honest gap instead.
             *
             * ymm is detected by REGISTER ID, not operand size: `vmovdqu ymm0, [rdx]` has a
             * 32-byte MEM src but capstone reports the reg operand's size as 32 too, and
             * keying on the register range is exact for the reg-reg forms as well. zmm is
             * included for the same reason, pre-emptively.
             * The 128-bit VEX forms — which is most of an /arch:AVX2 binary, including all
             * the scalar float math this remap was built to recover — are untouched.
             * DS_NO_VEXWIDTH restores the old (lying) behaviour. */
            bool wide_vec = false;
            for (int vi = 0; vi < nop; ++vi)
                if (ops[vi].type == X86_OP_REG &&
                    ((ops[vi].reg >= X86_REG_YMM0 && ops[vi].reg <= X86_REG_YMM15) ||
                     (ops[vi].reg >= X86_REG_ZMM0 && ops[vi].reg <= X86_REG_ZMM31)))
                    { wide_vec = true; break; }
            if (wide_vec && !std::getenv("DS_NO_VEXWIDTH")) { sse = 0; vex_wide_refused = true; }
            else switch (id) {
                case X86_INS_VMOVAPS: sse = X86_INS_MOVAPS; break;
                case X86_INS_VMOVUPS: sse = X86_INS_MOVUPS; break;
                case X86_INS_VMOVAPD: sse = X86_INS_MOVAPD; break;
                case X86_INS_VMOVUPD: sse = X86_INS_MOVUPD; break;
                case X86_INS_VMOVDQA: sse = X86_INS_MOVDQA; break;
                case X86_INS_VMOVDQU: sse = X86_INS_MOVDQU; break;
                case X86_INS_VMOVNTDQ:  sse = X86_INS_MOVNTDQ;  break;
                case X86_INS_VMOVNTPS:  sse = X86_INS_MOVNTPS;  break;
                case X86_INS_VMOVNTPD:  sse = X86_INS_MOVNTPD;  break;
                case X86_INS_VMOVNTDQA: sse = X86_INS_MOVNTDQA; break;
                case X86_INS_VMOVD:   sse = X86_INS_MOVD;   break;
                case X86_INS_VMOVQ:   sse = X86_INS_MOVQ;   break;
                case X86_INS_VUCOMISS: sse = X86_INS_UCOMISS; break;
                case X86_INS_VUCOMISD: sse = X86_INS_UCOMISD; break;
                case X86_INS_VCOMISS:  sse = X86_INS_COMISS;  break;
                case X86_INS_VCOMISD:  sse = X86_INS_COMISD;  break;
                case X86_INS_VCVTTSS2SI: sse = X86_INS_CVTTSS2SI; break;
                case X86_INS_VCVTTSD2SI: sse = X86_INS_CVTTSD2SI; break;
                case X86_INS_VCVTSS2SI:  sse = X86_INS_CVTSS2SI;  break;
                case X86_INS_VCVTSD2SI:  sse = X86_INS_CVTSD2SI;  break;
                /* 3-operand, destination not a source: present {dst, src2}. */
                case X86_INS_VSQRTSS:  sse = X86_INS_SQRTSS;  take_op2 = true; break;
                case X86_INS_VSQRTSD:  sse = X86_INS_SQRTSD;  take_op2 = true; break;
                case X86_INS_VCVTSS2SD: sse = X86_INS_CVTSS2SD; take_op2 = true; break;
                case X86_INS_VCVTSD2SS: sse = X86_INS_CVTSD2SS; take_op2 = true; break;
                case X86_INS_VCVTSI2SS: sse = X86_INS_CVTSI2SS; take_op2 = true; break;
                case X86_INS_VCVTSI2SD: sse = X86_INS_CVTSI2SD; take_op2 = true; break;
                case X86_INS_VMOVSS:
                case X86_INS_VMOVSD:
                    sse = (id == X86_INS_VMOVSD) ? X86_INS_MOVSD : X86_INS_MOVSS;
                    if (nop >= 3) take_op2 = true;   /* reg-merge form: dst <- src2 low lane */
                    break;
                default: break;
            }
            if (sse) {
                if (take_op2 && nop >= 3) {
                    vnops[0] = x.operands[0]; vnops[1] = x.operands[2];
                    ops = vnops; nop = 2;
                }
                id = sse;
            }
        }

        /* Skip prologue argument-homing stores. They write an arg register to its
         * shadow-space home BEFORE `sub rsp`, so normalise_slot (which assumes the
         * post-sub frame) would mis-resolve their offset and emit a bogus
         * param-to-param assignment (e.g. `a1 = a4`). Reads of a param resolve to
         * its name via param_home_off, so the store carries no information. */
        if (home_store_addrs.count(in.addr)) return;
        /* Snapshot the switch index register's value at the EXACT table-load insn
         * (recover_jump_table recorded its address): the computed goto reuses that
         * register as the jump target right after, and it is also briefly reused
         * for the in-block `code[pc]` access, so reading it at block exit or at the
         * first indexed access binds the wrong value. */
        if (b.is_switch) {
            auto la = switch_index_load.find(b.id);
            if (la != switch_index_load.end() && la->second == in.addr) {
                auto sc = switch_cmp_reg.find(b.id);
                if (sc != switch_cmp_reg.end() && sc->second > R_NONE && regfile[sc->second])
                    switch_resolved_index[b.id] = clone(regfile[sc->second]);
            }
        }
        /* Skip callee-saved register save/restore (mov [rsp+X], r14 / mov r14,
         * [rsp+X]). Preserving and restoring a non-volatile register has no
         * observable effect on the recovered C; modeling the save read the
         * register's incoming value (rendering `v5 = ctx_r14` — a phantom). */
        if (callee_save_addrs.count(in.addr)) return;

        /* Any instruction that writes a vector register invalidates the wide-vec load
         * AND fill tracking for it (a wide vmov LOAD / broadcast / zero re-establishes
         * it below). This keeps the memcpy/memset modeling bulletproof: a store only
         * copies from a source that was loaded/filled and NOT since clobbered. The
         * broadcast/zero cases below re-set vec_fill after this erase, so a genuine fill
         * survives while any later overwrite drops it. */
        prev_vec_fill.clear();
        if (nop >= 1 && OP(0).type == X86_OP_REG &&
            (!vec_load_addr.empty() || !vec_fill.empty() || !vec_op_value.empty())) {
            Reg d0 = vec_reg(OP(0).reg);
            if (d0 != R_NONE) {
                auto pf = vec_fill.find(d0);   /* snapshot for the byte-broadcast memset chain */
                if (pf != vec_fill.end() && pf->second.val)
                    prev_vec_fill[d0] = { clone(pf->second.val), pf->second.esz };
                vec_load_addr.erase(d0); vec_fill.erase(d0);
            }
            vec_op_value.erase(OP(0).reg);   /* AVX2: overwriting a ymm/zmm drops its op result */
        }

        /* STALE-FLAG INVALIDATION (snapshot half): record the current flag signature so
         * the post-switch check can tell whether THIS instruction's handler modeled the
         * flags. Every set_flags_* does `flags = FlagSrc()` with freshly built a/b
         * expressions, so an unchanged (valid, kind, a-ptr, b-ptr, width) after the switch
         * means the handler left the flags untouched. */
        /* Hold OWNING references, not bare addresses. A handler that models the
         * flags overwrites flags.a/flags.b, which can drop the old node's last
         * reference and free it — and the allocator is then free to hand that exact
         * address back for one of the NEW flag expressions. The post-switch compare
         * would see `flags.a.get() == _flg_a`, conclude the handler left the flags
         * alone, and invalidate a perfectly good condition (cc_to_expr then emits
         * `if (1)`). Whether the address gets recycled depends on the allocator's
         * free list, i.e. on everything decompiled earlier in the process — which is
         * why the same function decompiled alone was stable but drifted inside a
         * full run. Keeping the shared_ptrs alive across the window makes the
         * addresses un-reusable, so identity means what the check assumes it means.
         * (Found by diffing DS_PASS_TRACE fingerprints across two runs.) */
        const ExprP _flg_a_hold = flags.a;
        const ExprP _flg_b_hold = flags.b;
        const void* _flg_a = _flg_a_hold.get();
        const void* _flg_b = _flg_b_hold.get();
        const bool  _flg_v = flags.valid;
        const unsigned _flg_k = (flags.is_cmp ? 1u : 0u) | (flags.is_test ? 2u : 0u) |
                                (flags.is_arith ? 4u : 0u) | (flags.is_bt ? 8u : 0u) |
                                (flags.is_fcmp ? 16u : 0u);
        const int _flg_w = flags.width;

        switch (id) {
            case X86_INS_MOV: case X86_INS_MOVABS: {
                if (nop < 2) break;
                ExprP src = rvalue(OP(1));
                /* `mov gpr, [float_slot]` — reading a movss/movsd-written slot into a GP
                 * register is a bit REINTERPRET of the float's bits (`*(int*)&f`), the
                 * union/bit-cast idiom (isnan/frexp/signbit/copysign). */
                int64_t sn;
                if (src && OP(1).type == X86_OP_MEM && OP(0).type == X86_OP_REG &&
                    op_slot_norm(OP(1), sn) && float_slots.count(sn)) {
                    Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                    int fw = float_slots[sn];
                    if (!is_xmm(dr) && (int)OP(1).size == fw && !expr_has_in_backstop(src)) {
                        src->is_float = true; src->width = fw;
                        ExprP lvv = src;
                        if (src->kind != EK::Var) {
                            std::string tn = "t" + std::to_string(++temp_seq);
                            spill_temps.insert(tn);
                            var_width[tn] = fw < 8 ? 4 : 8; var_is_float[tn] = true;
                            Stmt st; st.kind = SK::Assign; st.lhs = mkVar(tn, var_width[tn]);
                            st.lhs->is_float = true; st.rhs = src; b.stmts.push_back(std::move(st));
                            lvv = mkVar(tn, var_width[tn]); lvv->is_float = true;
                        }
                        force_float_vars.insert(lvv->name);
                        src = mkMem(mkAddrOf(clone(lvv)), fw, true);
                    }
                }
                /* an INTEGER store to a slot invalidates its float-ness (reused as int)
                 * and records it as an int slot: a following `movss/movsd xmm,[slot]`
                 * is then the int->float bit reinterpret (`*(float*)&i`, the u2f/u2d
                 * builders). */
                { int64_t dn; if (OP(0).type == X86_OP_MEM && op_slot_norm(OP(0), dn)) {
                      float_slots.erase(dn);
                      int iw = OP(0).size ? (int)OP(0).size : 4;
                      if (iw == 4 || iw == 8) int_slots[dn] = iw; else int_slots.erase(dn);
                  } }
                /* record the store for stack-string recovery. Taken HERE rather than in a
                 * raw-insn scan because `src` is already folded: x86 has no `mov m64,imm64`,
                 * so an 8-byte stack string arrives via a register (`movabs rax,K; mov
                 * [rsp+X],rax`) and only rvalue() resolves that back to a Const. A
                 * non-constant store is recorded too — it POISONS its bytes. */
                { int64_t dn;
                  if (OP(0).type == X86_OP_MEM && op_slot_norm(OP(0), dn)) {
                      int w = OP(0).size ? (int)OP(0).size : 4;
                      if (w >= 1 && w <= 8) {
                          StrStore ss;
                          ss.norm = dn; ss.width = w;
                          ss.is_const = (src && src->kind == EK::Const && !src->is_float);
                          ss.val = ss.is_const ? (uint64_t)src->cval : 0;
                          stack_str_stores[in.addr] = ss;
                      }
                  } }
                do_dst(b, OP(0), src, in.addr);
                break;
            }
            case X86_INS_MOVZX: {
                if (nop < 2) break;
                ExprP src = rvalue(OP(1));
                /* a zero-extending load reveals the source element is UNSIGNED:
                 * `movzx eax, byte [data+i]` => `data` is `unsigned char*`. Mark the
                 * Mem so pointer-element typing recovers the unsigned element. */
                if (src && src->kind == EK::Mem) src->is_unsigned = true;
                int sw = OP(1).size ? OP(1).size : 1;
                int dw = OP(0).size ? OP(0).size : 4;
                ExprP c = ext_to(src, sw, dw, true);
                do_dst(b, OP(0), c, in.addr);
                break;
            }
            case X86_INS_MOVSX: case X86_INS_MOVSXD: {
                if (nop < 2) break;
                ExprP src = rvalue(OP(1));
                int sw = OP(1).size ? OP(1).size : 4;
                int dw = OP(0).size ? OP(0).size : 8;
                ExprP c = ext_to(src, sw, dw, false);
                do_dst(b, OP(0), c, in.addr);
                break;
            }
            case X86_INS_LEA: {
                if (nop < 2) break;
                ExprP addr = addr_of_mem(OP(1));
                do_dst(b, OP(0), addr, in.addr);
                break;
            }
            case X86_INS_PUSH: case X86_INS_POP:
            case X86_INS_NOP: case X86_INS_ENDBR64: case X86_INS_ENDBR32:
            case X86_INS_INT3:
                break;
            case X86_INS_ADD:
                if (try_interlocked_rmw(b, in, x, "+", "_InterlockedExchangeAdd")) break;
                arith2(b, x, "+", in.addr); break;
            case X86_INS_SUB:
                /* drop `sub rsp,N` / `add rsp,N` housekeeping */
                if (is_rsp_adjust(x)) break;
                arith2(b, x, "-", in.addr); break;
            case X86_INS_AND:
                if (try_interlocked_rmw(b, in, x, "&", "_InterlockedAnd")) break;
                arith2(b, x, "&", in.addr); break;
            case X86_INS_OR:
                if (try_interlocked_rmw(b, in, x, "|", "_InterlockedOr")) break;
                arith2(b, x, "|", in.addr); break;
            case X86_INS_XOR: {
                if (nop >= 2 && OP(0).type == X86_OP_REG && OP(1).type == X86_OP_REG &&
                    OP(0).reg == OP(1).reg) {
                    int dw = OP(0).size ? OP(0).size : 4;
                    do_dst(b, OP(0), mkConst(0, dw), in.addr);
                    set_flags_arith(mkConst(0, dw), dw);
                    break;
                }
                /* stack-canary setup/verify `xor reg, rsp`: rsp carries no modeled
                 * scalar value and degrades to 0, so the real
                 * `cookie ^ (uintptr_t)&frame` renders as a bogus `cookie ^ 0`. The
                 * value is the /GS cookie stored to the frame (and re-xored + checked
                 * in the epilogue, whose call is already dropped) -- no observable
                 * effect. Keep the destination's current value (the cookie). */
                if (is_cookie_xor(&in)) { do_dst(b, OP(0), rvalue(OP(0)), in.addr); break; }
                arith2(b, x, "^", in.addr); break;
            }
            /* ROTATE. C has no rotate operator, so an unmodeled rol/ror DROPPED the whole
             * operation: the destination silently kept its old value (and for a memory
             * destination — `ror byte ptr [rbx+rcx*4+0x56], 0x30` — the store vanished
             * outright). Emit the MSVC _rotl/_rotr intrinsic family, which lowers back to
             * this exact instruction and so preserves x86's count-masking (& 0x1f / & 0x3f)
             * semantics precisely — a hand-rolled `(x<<n)|(x>>(w-n))` would NOT, and is UB
             * at n==0. Flags: rol/ror write only CF/OF, never ZF/SF, and no compiler
             * branches on a rotate's carry — so leaving `flags` untouched keeps every
             * ZF/SF-consuming condition exactly right. */
            case X86_INS_ROL: case X86_INS_ROR: {
                if (nop < 2) break;
                int w = OP(0).size ? OP(0).size : 4;
                bool left = (id == X86_INS_ROL);
                const char* fn = left ? ((w==1)?"_rotl8":(w==2)?"_rotl16":(w==8)?"_rotl64":"_rotl")
                                      : ((w==1)?"_rotr8":(w==2)?"_rotr16":(w==8)?"_rotr64":"_rotr");
                const char* vt = (w==1)?"(unsigned char)":(w==2)?"(unsigned short)":
                                 (w==8)?"(unsigned long long)":"(unsigned int)";
                /* the 8/16-bit forms take an `unsigned char` shift, the 32/64-bit an `int` */
                const char* ct = (w<=2) ? "(unsigned char)" : "(int)";
                auto call = new_expr();
                call->kind = EK::Call; call->callee = fn; call->width = w;
                call->ret_kind = (w==8) ? 2 : 1; call->is_unsigned = true;
                call->args.push_back(mkCast(vt, rvalue(OP(0)), w, true));
                call->args.push_back(mkCast(ct, rvalue(OP(1)), 1, true));
                do_dst(b, OP(0), call, in.addr);
                used_rot_fns.insert(fn);
                break;
            }
            /* SHRD/SHLD — the double-precision shift (a 64-bit shift built from two
             * 32-bit halves, and the tail of many hashes). C has no such operator, so
             * unmodeled it DROPPED the whole operation and the destination silently kept
             * its stale value.
             *   shrd d,s,n = low  half of ((s:d) >> n)
             *   shld d,s,n = high half of ((d:s) << n)
             * The 32-bit form is EXACT as a 64-bit shift of the concatenated pair — and
             * unlike a hand-rolled `(d>>n)|(s<<(32-n))` it is well-defined at n==0, where
             * x86 makes the instruction a no-op. The 64-bit form needs a real 128-bit
             * shift, which is precisely MSVC's __shiftright128/__shiftleft128 (both take
             * (LowPart, HighPart, Shift)). Flags: shrd/shld write CF/ZF/SF but nothing
             * branches on them, so `flags` is left alone (as the rotates do). */
            case X86_INS_SHRD: case X86_INS_SHLD: {
                if (nop < 3) break;
                int w = OP(0).size ? OP(0).size : 4;
                bool right = (id == X86_INS_SHRD);
                ExprP d = rvalue(OP(0)), s = rvalue(OP(1)), c = rvalue(OP(2));
                if (!d || !s || !c) break;
                if (w == 8) {
                    auto call = new_expr();
                    call->kind = EK::Call;
                    call->callee = right ? "__shiftright128" : "__shiftleft128";
                    call->width = 8; call->ret_kind = 2; call->is_unsigned = true;
                    call->args.push_back(mkCast("(unsigned long long)", right ? d : s, 8, true));
                    call->args.push_back(mkCast("(unsigned long long)", right ? s : d, 8, true));
                    call->args.push_back(mkCast("(unsigned char)", c, 1, true));
                    do_dst(b, OP(0), call, in.addr);
                    used_shift128 = true;
                    break;
                }
                if (w != 4) break;                 /* the 16-bit form does not occur */
                /* widen through the UNSIGNED same-width type first: a direct
                 * `(unsigned long long)` of a signed 32-bit value sign-extends and
                 * would corrupt the high half of the pair. */
                auto zx64 = [&](ExprP v) {
                    return mkCast("(unsigned long long)", mkCast("(unsigned int)", v, 4, true), 8, true);
                };
                ExprP pair = mkBinary("|",
                    mkBinary("<<", zx64(right ? s : d), mkConst(32, 8, true), 8, true),
                    zx64(right ? d : s), 8, true);
                ExprP cm = mkBinary("&", c, mkConst(31, 4, true), 4, true);
                ExprP r = right
                    ? mkBinary(">>", pair, cm, 8, true)
                    : mkBinary(">>", mkBinary("<<", pair, cm, 8, true), mkConst(32, 8, true), 8, true);
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            /* RCL/RCR — rotate THROUGH carry by 1. The bit shifted in is the INCOMING CF,
             * which the shift ops now record in flags.cf (see record_shift_cf). This is the
             * back half of a multi-precision shift: `shl lo,1; rcl hi,1` is a 64-bit `<<1`
             * of the (hi:lo) pair; `shr hi,1; rcr lo,1` / `sar hi,1; rcr lo,1` the `>>1`.
             *   rcl x,1 = (x << 1) | CF_in ;  CF_out = MSB(x)
             *   rcr x,1 = (x >> 1) | (CF_in << (bits-1)) ;  CF_out = LSB(x)
             * Only count==1 with a KNOWN incoming CF is modelled (the real idiom); any other
             * form leaves the destination as the prior deliberate no-model rather than emit a
             * guessed carry. Emitting the OLD behaviour (drop) here would be unsound now that
             * a jc could read a real cf, so we bail explicitly. */
            case X86_INS_RCL: case X86_INS_RCR: {
                static const bool off = std::getenv("DS_NO_RCLRCR") != nullptr;
                if (off || nop < 2 || OP(0).type != X86_OP_REG) break;   /* reg dst only (stable value) */
                int w = OP(0).size ? OP(0).size : 4;
                int bits = w * 8;
                ExprP cin = flags.valid ? flags.cf : nullptr;
                ExprP cnt = fold(rvalue(OP(1)));
                long n = (cnt && cnt->kind == EK::Const) ? (long)(cnt->cval & (bits==64?63:31)) : -1;
                if (n != 1 || !cin) break;    /* sound subset: rotate-by-1 with a real CF */
                ExprP x  = mkCast(cast_str(w, true), rvalue(OP(0)), w, true);  /* unsigned view */
                ExprP c1 = mkBinary("&", clone(cin), mkConst(1, w, true), w, true);   /* 0/1 */
                ExprP res, newcf;
                if (id == X86_INS_RCL) {
                    res   = mkBinary("|", mkBinary("<<", clone(x), mkConst(1, w, true), w, true),
                                     c1, w, true);
                    newcf = mkBinary("&", mkBinary(">>", clone(x), mkConst(bits-1, w, true), w, true),
                                     mkConst(1, w, true), w, true);
                } else {
                    res   = mkBinary("|", mkBinary(">>", clone(x), mkConst(1, w, true), w, true),
                                     mkBinary("<<", c1, mkConst(bits-1, w, true), w, true), w, true);
                    newcf = mkBinary("&", clone(x), mkConst(1, w, true), w, true);
                }
                do_dst(b, OP(0), res, in.addr);
                flags = FlagSrc();
                flags.valid = true; flags.is_arith = true; flags.a = clone(res); flags.width = w;
                flags.cf = fold(newcf);
                break;
            }
            case X86_INS_SHL: case X86_INS_SAL: arith2(b, x, "<<", in.addr); break;
            case X86_INS_SHR: arith2(b, x, ">>", in.addr, true); break;
            case X86_INS_SAR: sar_or_div(b, x, in.addr); break;
            /* BMI2 variable shifts: SHRX/SHLX/SARX dst, src, count. Three-operand, and
             * crucially they set NO FLAGS (that is the entire reason they exist over SHR/SHL) --
             * so unlike the plain shifts there is no flag state to model, just the value. They
             * were hitting the opaque fallback (__shrx/__shlx) and dropping the shift. */
            case X86_INS_SHRX: case X86_INS_SHLX: case X86_INS_SARX: {
                if (nop < 3) break;
                int w = OP(0).size ? OP(0).size : 8;
                ExprP src = rvalue(OP(1)), cnt = rvalue(OP(2));
                if (!src || !cnt) break;
                const char* op = (id == X86_INS_SHLX) ? "<<" : ">>";
                bool logical = (id == X86_INS_SHRX);   /* SHRX unsigned; SARX signed */
                ExprP val = mkBinary(op,
                              logical ? mkCast(w >= 8 ? "(unsigned long long)" : "(unsigned int)", src, w, true)
                              : (id == X86_INS_SARX) ? mkCast(w >= 8 ? "(long long)" : "(int)", src, w, false)
                              : src,
                              cnt, w, logical);
                do_dst(b, OP(0), val, in.addr);
                break;
            }
            /* `lock inc [m]` is _InterlockedExchangeAdd(&m, 1). The x86 form discards the old
             * value, and _InterlockedIncrement returns the NEW one, so ExchangeAdd keeps ONE
             * shape across the whole locked-RMW family and lets the flags be rebuilt exactly.
             * `lock dec` is the same with -1. */
            case X86_INS_INC:
                if (try_interlocked_rmw(b, in, x, "+", "_InterlockedExchangeAdd",
                        mkConst(1, x.op_count >= 1 && x.operands[0].size ? x.operands[0].size : 4)))
                    break;
                incdec(b, x, "+", in.addr); break;
            case X86_INS_DEC:
                if (try_interlocked_rmw(b, in, x, "+", "_InterlockedExchangeAdd",
                        mkConst(-1, x.op_count >= 1 && x.operands[0].size ? x.operands[0].size : 4)))
                    break;
                incdec(b, x, "-", in.addr); break;
            case X86_INS_NEG: {
                if (nop < 1) break;
                int w = OP(0).size ? OP(0).size : 4;
                ExprP x = rvalue(OP(0));
                ExprP r = fold(mkUnary("-", clone(x), w));
                do_dst(b, OP(0), r, in.addr);
                /* NEG computes `0 - x`: CF = (x != 0), ZF = (x == 0), SF = (-x < 0).
                 * Modeling the flags as `cmp 0, x` recovers the carry-consuming
                 * idiom `neg; sbb r,r` => -(x != 0) (the regex_search 0/-1 return)
                 * and the jz/js conditions. The old set_flags_arith(-x) gave a bogus
                 * carry, collapsing `match ? 0 : -1` to a constant -1. */
                flags = FlagSrc();
                flags.valid = true; flags.is_cmp = true;
                flags.a = mkConst(0, w); flags.b = x; flags.width = w;
                break;
            }
            case X86_INS_NOT: {
                if (nop < 1) break;
                int w = OP(0).size ? OP(0).size : 4;
                do_dst(b, OP(0), fold(mkUnary("~", rvalue(OP(0)), w)), in.addr);
                break;
            }
            /* `mov ecx,<code>; int 0x29` is MSVC's __fastfail: the security abort behind
             * /GS cookie checks, bounds checks and the invalid-parameter path. Unmodeled,
             * the entire failure path VANISHED, so a validating function read as if it
             * checked nothing. The FAST_FAIL_* code in ecx names the check that tripped
             * (5 = INVALID_ARG, 2 = STACK_COOKIE_CHECK_FAILURE), so it is kept as the
             * argument. Only int 0x29 is modeled; other software interrupts do not occur
             * in compiler output. */
            case X86_INS_INT: {
                if (nop < 1 || OP(0).type != X86_OP_IMM || OP(0).imm != 0x29) break;
                auto call = new_expr();
                call->kind = EK::Call; call->callee = "__fastfail";
                call->width = 0; call->ret_kind = 0;
                call->args.push_back(mkCast("(unsigned int)", reg_value(R_RCX, 4), 4, true));
                Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
                b.stmts.push_back(std::move(s));
                used_fastfail = true;
                break;
            }
            case X86_INS_BSWAP: {
                /* BSWAP reverses byte order. capstone gives no semantic model, so
                 * leaving it unmodeled silently DROPS the swap (reverse_bits then
                 * returned a half-reversed value). Reconstruct as a portable
                 * shift/mask shuffle (MSVC-compilable, header-free): source byte i
                 * moves to byte (w-1-i). fold collapses the redundant masks. */
                if (nop < 1) break;
                int w = OP(0).size ? OP(0).size : 4;
                ExprP x = rvalue(OP(0));
                /* ONE instruction deserves ONE call. The shuffle below is CORRECT but it
                 * renders a single bswap as a 4- or 8-term bit assembly — the 64-bit form is
                 * a 400+ character line — and the reader has to decode it back into "this is
                 * a byte swap". _byteswap_* is exactly what the source said and what
                 * Hex-Rays emits; MSVC recognises it as the intrinsic, so the recompiled
                 * form is the same instruction again. It is also the htons/htonl reading.
                 * Only the widths that HAVE an intrinsic (2/4/8); anything else keeps the
                 * shuffle. DS_NO_BSWAPFN. */
                if ((w == 2 || w == 4 || w == 8) && !std::getenv("DS_NO_BSWAPFN")) {
                    auto call = new_expr();
                    call->kind = EK::Call;
                    call->callee = (w == 2) ? "_byteswap_ushort"
                                 : (w == 4) ? "_byteswap_ulong" : "_byteswap_uint64";
                    call->width = w;
                    call->ret_kind = (w >= 8) ? 2 : 1;
                    call->args.push_back(clone(x));
                    used_byteswap.insert(call->callee);
                    do_dst(b, OP(0), call, in.addr);
                    break;
                }
                ExprP acc = nullptr;
                for (int i = 0; i < w; ++i) {
                    int srcsh = 8 * i, dstsh = 8 * (w - 1 - i);
                    ExprP byte = srcsh ? mkBinary(">>", clone(x), mkConst(srcsh, w), w, true)
                                       : clone(x);
                    byte = mkBinary("&", byte, mkConst(0xff, w), w, true);
                    ExprP term = dstsh ? mkBinary("<<", byte, mkConst(dstsh, w), w, true) : byte;
                    acc = acc ? mkBinary("|", acc, term, w, true) : term;
                }
                do_dst(b, OP(0), fold(acc), in.addr);
                break;
            }
            case X86_INS_ADC: {
                /* ADD-WITH-CARRY: dst = dst + src + CF. The carry-IN comes from the preceding
                 * flag-setter. The dominant use is the 64-bit-add idiom `add lo,x; adc hi,y`:
                 * after the ADD, flags.a is the sum `(lo + x)` and the carry-out is the
                 * UNSIGNED wrap `(lo + x) < lo`. cc_to_expr(CC::B) is WRONG here -- it only
                 * decomposes a SUBTRACTION, so for an add result it folds to the always-false
                 * `(lo+x) < 0u` and would silently DROP the carry. A preceding compare/subtract
                 * (the `cmp; adc mask` idiom) does use the below condition. Without this case
                 * ADC was opaque and the high word lost its carry. Mirrors the SBB case below. */
                if (nop < 2) break;
                int w = OP(0).size ? OP(0).size : 4;
                ExprP cf;
                if (flags.valid && flags.a && flags.a->kind == EK::Binary &&
                    flags.a->op == "+" && flags.a->a) {
                    cf = fold(mkBinary("<", clone(flags.a), clone(flags.a->a), w, true));  /* unsigned add carry-out */
                } else {
                    cf = flags.valid ? cc_to_expr(CC::B, flags) : mkConst(0, w);
                }
                ExprP r = mkBinary("+", mkBinary("+", rvalue(OP(0)), rvalue(OP(1)), w), cf, w);
                do_dst(b, OP(0), fold(r), in.addr);
                set_flags_arith(r, w);
                break;
            }
            case X86_INS_SBB: {
                /* `sbb r,r` (same reg) is the carry-to-mask idiom: r = r-r-CF =
                 * -CF (0 or -1) from the preceding cmp. `cmp a,b; sbb eax,eax;
                 * and eax,C` => `(a<b)?C:0`. Unmodeled, capstone's SBB was a no-op,
                 * so eax kept its incoming value -> an `in_RAX` leak. */
                if (nop < 2) break;
                int w = OP(0).size ? OP(0).size : 4;
                if (OP(0).type == X86_OP_REG && OP(1).type == X86_OP_REG &&
                    OP(0).reg == OP(1).reg && flags.valid) {
                    ExprP cf = cc_to_expr(CC::B, flags);     /* CF = unsigned-below */
                    do_dst(b, OP(0), fold(mkUnary("-", cf, w)), in.addr);
                    break;
                }
                ExprP cf = flags.valid ? cc_to_expr(CC::B, flags) : mkConst(0, w);
                ExprP r = mkBinary("-", mkBinary("-", rvalue(OP(0)), rvalue(OP(1)), w), cf, w);
                do_dst(b, OP(0), fold(r), in.addr);
                set_flags_arith(r, w);
                break;
            }
            case X86_INS_IMUL: {
                if (nop == 1) {
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP a = reg_value(R_RAX, w);
                    ExprP src = rvalue(OP(0));
                    ExprP lo = mkBinary("*", clone(a), clone(src), w);
                    /* RDX gets the HIGH half of the 2w-bit product (the 128-bit
                     * `imul r/m64` feeds MSVC's 64-bit magic-number division). Model
                     * it so `sar rdx,S` does not read an unrecovered `in_RDX`. */
                    set_reg(R_RDX, w, fold(mulhi_expr(a, src, w, /*uns=*/false)), b);
                    set_reg(R_RAX, w, lo, b); set_flags_arith(lo, w);
                } else if (nop == 2) {
                    arith2(b, x, "*", in.addr);
                } else if (nop == 3) {
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP o1 = rvalue(OP(1));
                    ExprP o2 = rvalue(OP(2));
                    /* a 64-bit imul multiplies at 64-bit width: widen a narrower
                     * (movsxd-derived) operand so the C multiply is
                     * `(long long)(int)t1 * 0x38`, not a 32-bit `(int)t1 * 0x38`
                     * that overflows when the product is used as a pointer offset
                     * (fun_00015580's array stride). */
                    if (w >= 8 && o1 && (o1->width ? o1->width : 4) < 8)
                        o1 = ext_to(o1, o1->width ? o1->width : 4, 8, false);
                    ExprP r = mkBinary("*", o1, o2, w);
                    do_dst(b, OP(0), r, in.addr); set_flags_arith(r, w);
                }
                break;
            }
            /* BMI2 MULX: {OP(0):OP(1)} = rdx * OP(2), high in OP(0), low in OP(1), and
             * unlike MUL it touches NO flags — which is exactly why bignum/crypto code
             * uses it, and why leaving it unmodeled dropped BOTH halves of a multiply
             * that a carry chain then read as stale. The high half is expressible via
             * the same mulhi_expr the magic-division recovery already consumes.
             * Both halves are computed BEFORE either is stored: OP(0)/OP(1) may alias
             * rdx or the source, so storing first would corrupt the second read. */
            case X86_INS_MULX: {
                if (nop < 3) break;
                int w = OP(0).size ? OP(0).size : 8;
                ExprP a = reg_value(R_RDX, w), s = rvalue(OP(2));
                if (!a || !s) break;
                ExprP lo = fold(mkBinary("*", clone(a), clone(s), w, true));
                ExprP hi = fold(mulhi_expr(clone(a), clone(s), w, /*uns=*/true));
                do_dst(b, OP(1), lo, in.addr);
                do_dst(b, OP(0), hi, in.addr);
                break;
            }
            case X86_INS_MUL: {
                if (nop >= 1) {
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP a = mkCast(cast_str(w, true), reg_value(R_RAX, w), w, true);
                    ExprP src = mkCast(cast_str(w, true), rvalue(OP(0)), w, true);
                    ExprP r = mkBinary("*", clone(a), clone(src), w, true);
                    set_reg(R_RDX, w, fold(mulhi_expr(a, src, w, /*uns=*/true)), b);
                    set_reg(R_RAX, w, r, b);
                }
                break;
            }
            case X86_INS_IDIV: {
                if (nop >= 1) {
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP src = rvalue(OP(0));
                    ExprP num = reg_value(R_RAX, w);
                    ExprP rem = mkBinary("%", clone(num), clone(src), w);
                    ExprP quo = mkBinary("/", num, src, w);
                    set_reg(R_RAX, w, quo, b);
                    set_reg(R_RDX, w, rem, b);
                }
                break;
            }
            case X86_INS_DIV: {
                if (nop >= 1) {
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP src = rvalue(OP(0));
                    ExprP num = mkCast(cast_str(w, true), reg_value(R_RAX, w), w, true);
                    ExprP den = mkCast(cast_str(w, true), src, w, true);
                    ExprP rem = mkBinary("%", clone(num), clone(den), w, true);
                    ExprP quo = mkBinary("/", num, den, w, true);
                    set_reg(R_RAX, w, quo, b);
                    set_reg(R_RDX, w, rem, b);
                }
                break;
            }
            /* Sign-extend helpers. These DO define a register (CDQ/CQO/CWD set the
             * high reg to the sign bits; CDQE/CWDE/CBW widen rax in place), and
             * that value is used by more than idiv — e.g. the signed `/2` idiom
             * `(x - (x>>31)) >> 1`. Leaving them as no-ops let a stale register
             * value leak into such expressions (masked before only because the
             * register happened to read as 0). Model them explicitly. */
            case X86_INS_CDQ:   /* EDX:EAX = sign-extend(EAX); EDX = EAX>>31 */
                set_reg(R_RDX, 4, mkBinary(">>", reg_value(R_RAX, 4), mkConst(31, 4), 4), b);
                break;
            /* ---- BIT SCANS: keep the opaque value, ADD the flags.
             * bsf/bsr/lzcnt/tzcnt were unmodeled, so they fell to the default: opaque path.
             * That path gives a correct-enough VALUE (`eax = __bsr(x)`) but sets NO FLAGS —
             * and these instructions DO write ZF. The `flags` state therefore kept an
             * earlier, unrelated compare and the following jcc rendered a confidently WRONG
             * condition. 48 real sites in NullWare (bsr 34, bsf 7, lzcnt 6, tzcnt 1), and in
             * fn_000849f0 the stale-ZF `jne` is always-taken, which makes the structurer DROP
             * AN ENTIRE LOOP.
             *
             * The ZF semantics differ between the two families and getting them backwards
             * would just be a different lie:
             *   bsf/bsr    ZF = (SRC == 0)      -- "no bit was found"; dest is undefined then
             *   lzcnt/tzcnt ZF = (RESULT == 0)  -- a real count; CF (unmodelled) is the src==0 flag
             * so bsf/bsr build a cmp against 0 on the SOURCE, not on the result.
             *
             * Embedding a memory src in flags.a is safe here (8 of the bsr sites have one):
             * bsf/bsr do not write their source, so re-evaluating it at render time yields the
             * same value — the hazard set_flags_dst warns about does not apply.
             * DS_NO_BITSCAN. */
            case X86_INS_BSF: case X86_INS_BSR:
            case X86_INS_TZCNT: case X86_INS_LZCNT: {
                if (nop < 2) break;
                int w = OP(0).size ? OP(0).size : 4;
                ExprP src = rvalue(OP(1));
                if (!src) break;
                auto call = new_expr();
                call->kind = EK::Call;
                call->callee = "__" + sani(in.mnem);   /* __bsf/__bsr/__tzcnt/__lzcnt — the
                                                        * names the default: path already
                                                        * synthesised, so no output churn */
                int cw = (w >= 8) ? 8 : 4;
                call->width = cw; call->ret_kind = (cw >= 8) ? 2 : 1;
                call->args.push_back(clone(src));
                extern_callees[call->callee] = call->ret_kind;
                opaque_ops[call->callee]++;            /* keep the confidence header honest */
                do_dst(b, OP(0), call, in.addr);
                if (!std::getenv("DS_NO_BITSCAN")) {
                    flags = FlagSrc();
                    flags.valid = true;
                    flags.width = w;
                    if (id == X86_INS_BSF || id == X86_INS_BSR) {
                        flags.is_cmp = true;           /* ZF = (src == 0) */
                        flags.a = clone(src);
                        flags.b = mkConst(0, w);
                    } else {
                        flags.is_arith = true;         /* ZF = (result == 0) */
                        flags.a = clone(call);
                    }
                }
                break;
            }
            case X86_INS_CQO:   /* RDX:RAX = sign-extend(RAX); RDX = RAX>>63 */
                set_reg(R_RDX, 8, mkBinary(">>", reg_value(R_RAX, 8), mkConst(63, 8), 8), b);
                break;
            case X86_INS_CWD:   /* DX:AX = sign-extend(AX); DX = AX>>15 */
                set_reg(R_RDX, 2, mkBinary(">>", reg_value(R_RAX, 2), mkConst(15, 2), 2), b);
                break;
            case X86_INS_CDQE:  /* RAX = (int64)(int32)EAX */
                set_reg(R_RAX, 8, mkCast(cast_str(8, false), reg_value(R_RAX, 4), 8, false), b);
                break;
            case X86_INS_CWDE:  /* EAX = (int32)(int16)AX */
                set_reg(R_RAX, 4, mkCast(cast_str(4, false), reg_value(R_RAX, 2), 4, false), b);
                break;
            case X86_INS_CBW:   /* AX = (int16)(int8)AL */
                set_reg(R_RAX, 2, mkCast(cast_str(2, false), reg_value(R_RAX, 1), 2, false), b);
                break;
            /* Bit test family: CF = bit `n` of the destination. `bt` only tests;
             * bts/btr/btc also set/clear/complement it. Without this every
             * `bt; jc/jae` (the ubiquitous flag-field check) lost its condition and
             * rendered as `if (1)`. */
            case X86_INS_BT: case X86_INS_BTS:
            case X86_INS_BTR: case X86_INS_BTC: {
                if (nop < 2) break;
                int w = OP(0).size ? OP(0).size : 4;
                ExprP base = rvalue(OP(0));
                ExprP idx = rvalue(OP(1));
                ExprP bit = mkBinary("&", mkBinary(">>", clone(base), clone(idx), w),
                                     mkConst(1, w), w);
                flags = FlagSrc();
                flags.valid = true; flags.is_bt = true; flags.a = fold(bit); flags.width = w;
                if (id != X86_INS_BT) {
                    ExprP mask = mkBinary("<<", mkConst(1, w), clone(idx), w);
                    ExprP nv;
                    if (id == X86_INS_BTS) nv = mkBinary("|", clone(base), mask, w);
                    else if (id == X86_INS_BTR) nv = mkBinary("&", clone(base), mkUnary("~", mask, w), w);
                    else nv = mkBinary("^", clone(base), mask, w);   /* BTC */
                    do_dst(b, OP(0), nv, in.addr);
                }
                break;
            }
            /* ---- SSE scalar floating point ----
             * Without this, all float code (positions, distances, lengths — the
             * bulk of a game-ish binary) is lost: values collapse to 0 and float
             * comparisons set no flags so every `comiss; ja` became `if (1)`. */
            case X86_INS_MOVSS: case X86_INS_MOVSD: {
                /* The string `movsd` (rep movs dword) shares MOVSD's capstone id with the
                 * SSE scalar move, so split it off first. Only the string form has two
                 * MEMORY operands (es:[rdi], ds:[rsi]) or none — an SSE movsd always
                 * names an xmm register, so this can never steal a float move. */
                if (id == X86_INS_MOVSD &&
                    (nop == 0 || (nop == 2 && OP(0).type == X86_OP_MEM
                                           && OP(1).type == X86_OP_MEM))) {
                    bool has_rep = false;
                    for (int pi = 0; pi < 4; ++pi)
                        if (x.prefix[pi] == X86_PREFIX_REP) { has_rep = true; break; }
                    emit_string_move(b, in, 4, has_rep);
                    break;
                }
                /* scalar float load/move: a .rdata constant source is a float
                 * literal (4B single / 8B double). */
                if (nop < 2) break;
                int w = (id==X86_INS_MOVSD) ? 8 : 4;
                /* Vec2 lane RELOAD forwarding: `movss xmm, [slot(+4)]` where `slot`
                 * held a spilled packed value => the float lane directly, bypassing
                 * the (dead) memory round-trip the compiler used to extract .y. */
                if (id == X86_INS_MOVSS && OP(0).type==X86_OP_REG && OP(1).type==X86_OP_MEM
                    && !stack_packed_var.empty()) {
                    const x86_op_mem& m = OP(1).mem;
                    Reg mb=R_NONE; int mt; if (m.base!=X86_REG_INVALID) map_reg(m.base, mb, mt);
                    int64_t norm;
                    if (m.index==X86_REG_INVALID && normalise_slot(mb, m.disp, norm)) {
                        for (auto& kv : stack_packed_var) {
                            int64_t off = norm - kv.first;
                            if (off==0 || off==4) {
                                ExprP lane = packed_flane(kv.second, (int)off);
                                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                                do_dst(b, OP(0), lane, in.addr);
                                goto movss_handled;
                            }
                        }
                    }
                }
                /* Vec2 packed SPILL: `movsd [slot], xmm` of a packed value — record
                 * the slot so the .y reload forwards; skip emitting the dead store. */
                if (OP(0).type==X86_OP_MEM && OP(1).type==X86_OP_REG) {
                    Reg sr; int sw; map_reg(OP(1).reg, sr, sw);
                    auto pit = xmm_packed_var.find(sr);
                    if (pit != xmm_packed_var.end()) {
                        const x86_op_mem& m = OP(0).mem;
                        Reg mb=R_NONE; int mt; if (m.base!=X86_REG_INVALID) map_reg(m.base, mb, mt);
                        int64_t norm;
                        if (m.index==X86_REG_INVALID && normalise_slot(mb, m.disp, norm)) {
                            stack_packed_var[norm] = pit->second;
                            goto movss_handled;
                        }
                    }
                }
                /* `movsd m64, xmm` STORE whose xmm carries two REAL float lanes from a
                 * 2-wide addps/mulps/subps/... remainder (fadd_v `a[i]+=b[i]` tail):
                 * commit two faithful `*(float*)` lanes, not one scalar 8-byte store
                 * (which would drop lane 1 and leave the array unchanged). */
                if (id == X86_INS_MOVSD && OP(0).type == X86_OP_MEM && OP(0).size == 8 &&
                    OP(1).type == X86_OP_REG) {
                    Reg sr; int sw; map_reg(OP(1).reg, sr, sw);
                    if (is_xmm(sr) && xmm_f_real[sr] && xmm_f[sr][0] && xmm_f[sr][1] &&
                        !xmm_f[sr][2] && !xmm_f[sr][3] &&
                        !expr_has_in_backstop(xmm_f[sr][0]) && !expr_has_in_backstop(xmm_f[sr][1])) {
                        ExprP g[2] = { clone(xmm_f[sr][0]), clone(xmm_f[sr][1]) };
                        if (emit_simd8_store_flanes(b, OP(0), g, in.addr)) goto movss_handled;
                    }
                }
                {
                ExprP v;
                /* `movss/movsd xmm, [int_slot]` LOAD — reading a slot last written by
                 * a GP integer store as a float is the int->float bit REINTERPRET
                 * (`*(float*)&i`, the u2f/u2d union idiom that rebuilds a float from
                 * its bits: fabs/neg/copysign/nextup/rebuild/scalb). Mirror of the
                 * `mov gpr,[float_slot]` float->int reinterpret above. */
                int64_t isn;
                if (OP(0).type == X86_OP_REG && OP(1).type == X86_OP_MEM &&
                    op_slot_norm(OP(1), isn) && int_slots.count(isn) &&
                    (int)OP(1).size == int_slots[isn]) {
                    Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                    ExprP iv = rvalue(OP(1));
                    if (is_xmm(dr) && iv && !expr_has_in_backstop(iv)) {
                        ExprP lvv = iv;
                        if (iv->kind != EK::Var) {
                            std::string tn = "t" + std::to_string(++temp_seq);
                            spill_temps.insert(tn);
                            var_width[tn] = (w < 8) ? 4 : 8; var_is_float[tn] = false;
                            Stmt st; st.kind = SK::Assign; st.lhs = mkVar(tn, var_width[tn]);
                            st.rhs = iv; b.stmts.push_back(std::move(st));
                            lvv = mkVar(tn, var_width[tn]);
                        }
                        v = mkMem(mkAddrOf(clone(lvv)), w, true);
                        v->is_float = true; v->width = w;
                    }
                }
                if (!v) v = as_float(rvalue(OP(1)), w);
                /* movss/movsd MOVES float bits — the value is float of width w.
                 * Tagging it (even for a bare temp/Var, which as_float leaves
                 * untouched) stops do_dst's int `truncate(val,w)` from wrapping a
                 * width-8 phi temp in `(int)`, which would truncate a stored float
                 * (e.g. an AABB coord 3.7 -> 3) AND leave the store typed int. */
                if (v) { v->is_float = true; v->width = w; }
                /* record the slot as float-holding: a later `mov eax,[slot]` (union/
                 * bit-cast) is then a bit reinterpret, not a value read. Storing a
                 * float to a slot also clears any stale int-slot tag. */
                int64_t fsn;
                if (OP(0).type == X86_OP_MEM && op_slot_norm(OP(0), fsn)) { float_slots[fsn] = w; int_slots.erase(fsn); }
                do_dst(b, OP(0), v, in.addr);
                }
                /* `movsd xmm, m64` LOAD: stock two low float lanes so a following 2-wide
                 * packed-float op stays faithful (real=false until a packed op reads). */
                if (id == X86_INS_MOVSD && OP(0).type == X86_OP_REG &&
                    OP(1).type == X86_OP_MEM && OP(1).size == 8) {
                    Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                    if (is_xmm(dr)) {
                        ExprP m0 = rvalue(OP(1));
                        if (m0 && m0->kind == EK::Mem && m0->a) {
                            ExprP l0 = mkMem(clone(m0->a), 4, false); l0->is_float = true;
                            ExprP l1 = mkMem(mkBinary("+", clone(m0->a), mkConst(4, 8), 8), 4, false); l1->is_float = true;
                            populate_xmm_f2(dr, l0, l1);
                        }
                    }
                }
                movss_handled:;
                break;
            }
            case X86_INS_MOVAPS:  case X86_INS_MOVUPS:
            case X86_INS_MOVDQA:  case X86_INS_MOVDQU:
            case X86_INS_MOVUPD:  case X86_INS_MOVAPD:
            /* non-temporal 16-byte moves are the same store/load for our purposes */
            case X86_INS_MOVNTDQ: case X86_INS_MOVNTPS:
            case X86_INS_MOVNTPD: case X86_INS_MOVNTDQA: {
                if (nop < 2) break;
                /* 16-byte packed move. */
                if (OP(0).type == X86_OP_MEM && OP(0).size == 16) {
                    /* STORE. A source that came through packed-FLOAT ops commits four
                     * faithful `*(float*)` lanes (vec3/vec4 math). Else the 2x64
                     * integer-lane path, else the scalar fallback. */
                    if (OP(1).type == X86_OP_REG) {
                        Reg sr; int sw; map_reg(OP(1).reg, sr, sw);
                        if (is_xmm(sr) && xmm_f_real[sr]) {
                            ExprP f[4]; bool ok = true;
                            for (int i = 0; i < 4; ++i) { f[i] = xmm_f[sr][i] ? clone(xmm_f[sr][i]) : nullptr; if (!f[i] || expr_has_in_backstop(f[i])) ok = false; }
                            if (ok && emit_simd16_store_flanes(b, OP(0), f, in.addr)) break;
                        }
                        /* packed-INT lanes (a[i]*=k / a[i]+=b[i]) -> four `*(int*)` stores */
                        if (is_xmm(sr) && xmm_i_real[sr]) {
                            ExprP g[4]; bool ok = true;
                            for (int i = 0; i < 4; ++i) { g[i] = xmm_i[sr][i] ? clone(xmm_i[sr][i]) : nullptr; if (!g[i] || expr_has_in_backstop(g[i])) ok = false; }
                            if (ok && emit_simd16_store_ilanes(b, OP(0), g, in.addr)) break;
                        }
                    }
                    ExprP lo, hi;
                    if (OP(1).type == X86_OP_REG && simd_src_lanes(OP(1), lo, hi) &&
                        !expr_has_in_backstop(lo) && !expr_has_in_backstop(hi) &&
                        emit_simd16_store_lanes(b, OP(0), lo, hi, in.addr)) break;
                    if (emit_simd16_store(b, OP(0), rvalue(OP(1)), in.addr)) break;
                    do_dst(b, OP(0), rvalue(OP(1)), in.addr);
                    break;
                }
                /* register destination: track both 64-bit lanes when the source's
                 * lanes are known (reg→reg copy, or 128-bit load split into halves)
                 * so a following packed op / lane store stays faithful. */
                if (OP(0).type == X86_OP_REG) {
                    Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                    if (is_xmm(dr)) {
                        ExprP lo, hi;
                        bool lanes = simd_src_lanes(OP(1), lo, hi);
                        /* set the scalar/64-bit view FIRST — both set_xmm_lanes and
                         * do_dst call set_reg, which CLEARS xmm_f — so the float-lane
                         * side-channel must be populated AFTER them. */
                        if (lanes) set_xmm_lanes(dr, lo, hi, b);
                        else do_dst(b, OP(0), rvalue(OP(1)), in.addr);   /* scalar fallback */
                        /* stock the float-lane side-channel — ALSO for a 16-byte
                         * MEMORY load (xmm_f_lanes synthesizes 4 `*(float*)` lanes),
                         * so a following packed-FLOAT op (mulps/addps/divps) stays
                         * faithful instead of being dropped (arr_scale `a[i]*=s`,
                         * arr_normalize01). real=false: a raw load is int-vs-float
                         * ambiguous until a packed-FLOAT op reads it. */
                        ExprP f[4];
                        if (xmm_f_lanes(OP(1), f)) {
                            bool src_real = false;
                            if (OP(1).type == X86_OP_REG) { Reg s2; int sw2; map_reg(OP(1).reg, s2, sw2); src_real = is_xmm(s2) && xmm_f_real[s2]; }
                            populate_xmm_f(dr, f, src_real);
                        }
                        /* ALSO stock the packed-INT side-channel from the raw load, so a
                         * following pmulld/paddd (a[i]*=k) stays faithful. real=false. */
                        ExprP g[4];
                        if (xmm_i_lanes(OP(1), g)) populate_xmm_i(dr, g);
                        break;
                    }
                }
                do_dst(b, OP(0), rvalue(OP(1)), in.addr);
                break;
            }
            case X86_INS_VMOVD: case X86_INS_VMOVQ:
            case X86_INS_MOVD: case X86_INS_MOVQ:
                if (nop >= 2) {
                    /* movd/movq r32/r64, xmm : moving a FLOAT's bits into a GP register is a
                     * bit REINTERPRET (`*(int*)&f`), NOT a value store — the exponent/mantissa
                     * bit tests that follow (isnan/ilogb/frexp/copysign domain checks) operate
                     * on the raw IEEE bits. Without this, `movd eax,xmm; eax>>23` reads a
                     * phantom (`__vmovd(a1)` for the unmodeled AVX form). */
                    /* `movd/movq r_gpr, xmm(scalar float)` extracts the raw IEEE bits — a bit
                     * REINTERPRET `*(int*)&f`, NOT a value store (isnan/ilogb/frexp exponent
                     * tests read the bits). Safe now: the AddrOf guard in mark_ptr_in_addr
                     * keeps `f` a float value, not a pointer. Skips a packed-INTEGER lane
                     * (xmm_i_real) and a Vec2 2-float pack (handled below). */
                    if (OP(0).type == X86_OP_REG && OP(1).type == X86_OP_REG) {
                        Reg dr, sr; int dw, sw; map_reg(OP(0).reg, dr, dw); map_reg(OP(1).reg, sr, sw);
                        bool packed2 = xmm_f[sr][0] && xmm_f[sr][1];   /* a Vec2 -> the pack case below */
                        if (!is_xmm(dr) && is_xmm(sr) && !xmm_i_real[sr] && !packed2) {
                            int rw = (id == X86_INS_MOVQ || id == X86_INS_VMOVQ) ? 8 : 4;
                            ExprP sv = as_float(rvalue(OP(1)), rw);
                            bool srcf = sv && (sv->is_float ||
                                (sv->kind == EK::Var && var_is_float.count(sv->name) && var_is_float[sv->name]) ||
                                (xmm_f[sr][0] != nullptr));
                            if (sv && srcf && !expr_has_in_backstop(sv)) {
                                /* materialize a non-var source into a float temp so its bits
                                 * can be taken by address (mirrors pack_two_floats). */
                                ExprP lv = sv;
                                if (sv->kind != EK::Var) {
                                    std::string tn = "t" + std::to_string(++temp_seq);
                                    spill_temps.insert(tn);
                                    var_width[tn] = rw < 8 ? 4 : 8; var_is_float[tn] = true;
                                    Stmt st; st.kind = SK::Assign; st.lhs = mkVar(tn, var_width[tn]);
                                    st.lhs->is_float = true; st.rhs = sv; b.stmts.push_back(std::move(st));
                                    lv = mkVar(tn, var_width[tn]); lv->is_float = true;
                                }
                                force_float_vars.insert(lv->name);
                                do_dst(b, OP(0), mkMem(mkAddrOf(clone(lv)), rw, true), in.addr);
                                break;
                            }
                        }
                    }
                    /* `movq xmm, r64` where r64 is a GP VAR holding a packed 2-float
                     * struct (Vec2 by value) feeding single-float ops: reinterpret the
                     * two 32-bit halves as float lanes so `.x`/`.y` render as
                     * `*(float*)&v` / `*(float*)((char*)&v+4)` instead of integer ops. */
                    if (id == X86_INS_MOVQ && OP(0).type == X86_OP_REG &&
                        OP(1).type == X86_OP_REG) {
                        Reg dr, sr; int dw, sw; map_reg(OP(0).reg, dr, dw); map_reg(OP(1).reg, sr, sw);
                        /* `movq r64, xmm` where the xmm holds two tracked float lanes:
                         * pack them into the GP register (Vec2 returned by value). */
                        if (!is_xmm(dr) && is_xmm(sr) && dw == 8 &&
                            xmm_f[sr][0] && xmm_f[sr][1]) {
                            ExprP packed = pack_two_floats(clone(xmm_f[sr][0]), clone(xmm_f[sr][1]), b);
                            do_dst(b, OP(0), packed, in.addr);
                            break;
                        }
                        ExprP sv = (is_xmm(dr) && !is_xmm(sr) && sw == 8) ? rvalue(OP(1)) : nullptr;
                        size_t idx = (size_t)(&in - insns.data());
                        if (sv && sv->kind == EK::Var && movq_feeds_single_float(idx)) {
                            const std::string& vn = sv->name;
                            ExprP lanes[4] = { packed_flane(vn, 0), packed_flane(vn, 4), nullptr, nullptr };
                            regfile[dr] = clone(lanes[0]);
                            regfile_hi[dr] = nullptr;
                            populate_xmm_f(dr, lanes, true);
                            xmm_packed_var[dr] = vn;
                            break;
                        }
                    }
                    /* `movq m64, xmm` STORE whose xmm carries two REAL int lanes from a
                     * 2-wide paddd/pmulld/psubd remainder (iadd/isub `a[i]+=b[i]` tail):
                     * commit two faithful `*(int*)` lanes instead of one scalar 8-byte
                     * store (which would drop lane 1 and leave the array unchanged). */
                    if (id == X86_INS_MOVQ && OP(0).type == X86_OP_MEM && OP(0).size == 8 &&
                        OP(1).type == X86_OP_REG) {
                        Reg sr; int sw; map_reg(OP(1).reg, sr, sw);
                        if (is_xmm(sr) && xmm_i_real[sr] && xmm_i[sr][0] && xmm_i[sr][1] &&
                            !expr_has_in_backstop(xmm_i[sr][0]) && !expr_has_in_backstop(xmm_i[sr][1])) {
                            ExprP g[2] = { clone(xmm_i[sr][0]), clone(xmm_i[sr][1]) };
                            if (emit_simd8_store_ilanes(b, OP(0), g, in.addr)) break;
                        }
                    }
                    /* ---- float<->int bit REINTERPRET for movd/movq reg<->xmm (the
                     * scalar-reinterpret block above can miss it under stale packed-lane
                     * tracking; these register-aware lookaheads recover the Dekker
                     * hi/lo split `movd r,xmm; and r,mask; movd xmm,r`). ---- */
                    if (nop >= 2 && OP(0).type == X86_OP_REG && OP(1).type == X86_OP_REG) {
                        Reg dr0, sr0; int dw0, sw0;
                        map_reg(OP(0).reg, dr0, dw0); map_reg(OP(1).reg, sr0, sw0);
                        size_t ix = (size_t)(&in - insns.data());
                        int rw = (id == X86_INS_MOVQ || id == X86_INS_VMOVQ) ? 8 : 4;
                        /* READ  `movd r_gpr, xmm(float)` whose bits feed an int bit-op:
                         *   -> `*(int*)&f`, not a value-truncating `(int)f`. */
                        if (!is_xmm(dr0) && is_xmm(sr0) && !xmm_i_real[sr0]) {
                            ExprP sv = rvalue(OP(1));
                            /* `*(unsigned int*)&v & mask` is the correct bit view for ANY
                             * type (an int reads back its own value; a float reads its
                             * IEEE bits), so no source-type check is needed — the
                             * !xmm_i_real guard (not a real packed-int lane) plus the
                             * bit-op lookahead already scope this to the float-bits
                             * idioms (isnan/ilogb/frexp + the Dekker hi/lo split). var
                             * typing (var_is_float) isn't populated yet at lift time. */
                            if (sv && gpr_bits_int_op(ix, dr0)) {
                                ExprP lv = sv;
                                if (sv->kind != EK::Var) {
                                    std::string tn = "t" + std::to_string(++temp_seq);
                                    spill_temps.insert(tn); var_width[tn] = rw < 8 ? 4 : 8; var_is_float[tn] = true;
                                    Stmt st; st.kind = SK::Assign; st.lhs = mkVar(tn, var_width[tn]);
                                    st.lhs->is_float = true; st.rhs = sv; b.stmts.push_back(std::move(st));
                                    lv = mkVar(tn, var_width[tn]); lv->is_float = true;
                                }
                                force_float_vars.insert(lv->name);
                                do_dst(b, OP(0), mkMem(mkAddrOf(clone(lv)), rw, true), in.addr);  /* *(unsigned int*)&f */
                                break;
                            }
                        }
                        /* WRITE `movd xmm, r_gpr` whose int bits are consumed by a scalar
                         *   float op: `*(float*)&t`, not a raw int the op value-converts. */
                        if (is_xmm(dr0) && !is_xmm(sr0)) {
                            ExprP iv = rvalue(OP(1));
                            if (iv && !iv->is_float && xmm_bits_scalar_float(ix, dr0)) {
                                /* Recognize the Dekker HIGH-PART idiom `*(float*)&(
                                 * *(u32*)&X & 0xffff0000)` — clearing a float's low 16
                                 * mantissa bits for an extra-precision split — and emit a
                                 * single semantic helper `__f32_hi(X)` (reads clean even
                                 * inlined). Otherwise `__u2f(bits)` for a generic bits->
                                 * float. Both width-4 only; width-8 keeps the mem form. */
                                ExprP hiX;
                                if (rw == 4 && iv->kind == EK::Binary && iv->op == "&" &&
                                    iv->b && iv->b->kind == EK::Const &&
                                    (uint32_t)iv->b->cval == 0xffff0000u &&
                                    iv->a && iv->a->kind == EK::Mem && iv->a->a &&
                                    iv->a->a->kind == EK::AddrOf && iv->a->a->a)
                                    hiX = iv->a->a->a;
                                if (rw == 4 && hiX) {
                                    auto call = new_expr();
                                    call->kind = EK::Call; call->callee = "__f32_hi";
                                    call->width = 4; call->is_float = true; call->ret_kind = 3;
                                    call->args.push_back(clone(hiX));
                                    used_f32hi = true;
                                    do_dst(b, OP(0), call, in.addr);
                                } else if (rw == 4) {
                                    auto call = new_expr();
                                    call->kind = EK::Call; call->callee = "__u2f";
                                    call->width = 4; call->is_float = true; call->ret_kind = 3;
                                    call->args.push_back(iv);
                                    used_u2f = true;
                                    do_dst(b, OP(0), call, in.addr);
                                } else {
                                    std::string tn = "t" + std::to_string(++temp_seq);
                                    spill_temps.insert(tn); var_width[tn] = rw;   /* integer temp */
                                    Stmt st; st.kind = SK::Assign; st.lhs = mkVar(tn, rw); st.rhs = iv;
                                    b.stmts.push_back(std::move(st));
                                    ExprP reint = mkMem(mkAddrOf(mkVar(tn, rw)), rw, false);  /* *(double*)&t */
                                    reint->is_float = true;
                                    do_dst(b, OP(0), reint, in.addr);
                                }
                                if (rw < 8) { regfile_hi[dr0] = mkConst(0, 8); xmm_packed_var.erase(dr0); }
                                break;
                            }
                        }
                    }
                    do_dst(b, OP(0), rvalue(OP(1)), in.addr);
                    /* movd/movq into an xmm zero-extends the upper bits: lane 1 = 0.
                     * (Enables the `movq xmm,r64; punpcklqdq xmm,xmm` broadcast.) */
                    if (OP(0).type == X86_OP_REG) {
                        Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                        if (is_xmm(dr)) { regfile_hi[dr] = mkConst(0, 8); xmm_packed_var.erase(dr); }
                    }
                    /* MSVC memset byte-broadcast: `movq xmm, r` where r = c*0x0101010101010101
                     * (splatting byte c to 8 bytes) -> a byte fill, so the following
                     * punpcklqdq/vinsertf128 broadcast it and the wide store becomes
                     * memset(dst,c,n). DS_NO_MEMSETBCAST. */
                    if (id == X86_INS_MOVQ && OP(0).type == X86_OP_REG &&
                        OP(1).type == X86_OP_REG && !std::getenv("DS_NO_MEMSETBCAST")) {
                        Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                        Reg sr; int sw; map_reg(OP(1).reg, sr, sw);
                        if (is_xmm(dr) && !is_xmm(sr)) {
                            ExprP r = fold(rvalue(OP(1)));
                            ExprP byte = nullptr;
                            if (r && r->kind == EK::Binary && r->op == "*") {
                                if (r->b && r->b->kind == EK::Const &&
                                    (uint64_t)r->b->cval == 0x0101010101010101ULL) byte = clone(r->a);
                                else if (r->a && r->a->kind == EK::Const &&
                                    (uint64_t)r->a->cval == 0x0101010101010101ULL) byte = clone(r->b);
                            }
                            if (byte) vec_fill[dr] = { byte, 1 };
                        }
                    }
                    /* `movq xmm, m64` LOAD: stock the two low int lanes so a following
                     * 2-wide packed-int op stays faithful (real=false until it reads). */
                    if (id == X86_INS_MOVQ && OP(0).type == X86_OP_REG &&
                        OP(1).type == X86_OP_MEM && OP(1).size == 8) {
                        Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                        if (is_xmm(dr)) {
                            ExprP m0 = rvalue(OP(1));
                            if (m0 && m0->kind == EK::Mem && m0->a) {
                                ExprP l0 = mkMem(clone(m0->a), 4, false);
                                ExprP l1 = mkMem(mkBinary("+", clone(m0->a), mkConst(4, 8), 8), 4, false);
                                populate_xmm_i2(dr, l0, l1);
                            }
                        }
                    }
                }
                break;
            case X86_INS_MOVLPS:
                if (nop >= 2) do_dst(b, OP(0), rvalue(OP(1)), in.addr);
                break;
            case X86_INS_PUNPCKLQDQ: {
                /* result = { dst[63:0], src[63:0] }: lane0 keeps dst's low half,
                 * lane1 becomes src's low half. `punpcklqdq x,x` broadcasts. */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                ExprP dlo = xmm_lo(dr), slo = simd_lane0(OP(1));
                if (dlo && slo) set_xmm_lanes(dr, dlo, slo, b);
                /* memset byte-broadcast: `punpcklqdq x,x` broadcasts low 64 -> 128; the per-op
                 * erase dropped the byte fill -- re-establish it from the snapshot so it
                 * survives to vinsertf128/the store. Same-reg only. */
                if (OP(1).type == X86_OP_REG && OP(0).reg == OP(1).reg &&
                    !std::getenv("DS_NO_MEMSETBCAST")) {
                    auto pf = prev_vec_fill.find(dr);
                    if (pf != prev_vec_fill.end() && pf->second.val)
                        vec_fill[dr] = { clone(pf->second.val), pf->second.esz };
                }
                break;
            }
            case X86_INS_PADDQ:  case X86_INS_VPADDQ:
            case X86_INS_PSUBQ:  case X86_INS_VPSUBQ:
            case X86_INS_VPMULLQ:
            case X86_INS_PAND:   case X86_INS_VPAND:
            /* ORPS/ORPD are bit-identical to POR (only the encoding's type tag differs),
             * so they belong on the same lane-wise `|`. Unmodeled, the dest kept a stale
             * value — the float-select/sign-merge idiom `andps a,mask; andnps b,mask;
             * orps a,b` silently lost its merge. */
            case X86_INS_ORPS:   case X86_INS_ORPD:
            case X86_INS_VORPS:  case X86_INS_VORPD:
            case X86_INS_POR:    case X86_INS_VPOR: {
                /* packed 64-bit-lane ALU. 2-operand form: dst = dst OP src.
                 * 3-operand VEX form: dst = src1 OP src2. Modeled lanewise; only
                 * commits a result when BOTH lanes of both sources are tracked,
                 * otherwise leaves the dest untouched (exactly the prior behavior). */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP alo, ahi, blo, bhi;
                if (!simd_src_lanes(OP(ai), alo, ahi)) break;
                if (!simd_src_lanes(OP(bi), blo, bhi)) break;
                const char* fop =
                    (id==X86_INS_PADDQ||id==X86_INS_VPADDQ) ? "+" :
                    (id==X86_INS_PSUBQ||id==X86_INS_VPSUBQ) ? "-" :
                    (id==X86_INS_VPMULLQ)                   ? "*" :
                    (id==X86_INS_PAND||id==X86_INS_VPAND)   ? "&" : "|";
                set_xmm_lanes(dr, mkBinary(fop, alo, blo, 8),
                                  mkBinary(fop, ahi, bhi, 8), b);
                break;
            }
            /* AND-NOT: dst = ~dst & src — note it inverts the FIRST source, and is NOT
             * ~(a & b). It is the other half of the branchless float-select idiom
             * (`andps a,mask; andnps b,mask; orps a,b`), so leaving it unmodeled dropped
             * the "else" side of every such select. */
            case X86_INS_PANDN:  case X86_INS_VPANDN:
            case X86_INS_ANDNPS: case X86_INS_ANDNPD:
            case X86_INS_VANDNPS: case X86_INS_VANDNPD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP alo, ahi, blo, bhi;
                if (!simd_src_lanes(OP(ai), alo, ahi)) break;
                if (!simd_src_lanes(OP(bi), blo, bhi)) break;
                set_xmm_lanes(dr, mkBinary("&", mkUnary("~", alo, 8), blo, 8),
                                  mkBinary("&", mkUnary("~", ahi, 8), bhi, 8), b);
                break;
            }
            /* Lane-wise compare. The result per lane is an all-ones / all-zero MASK
             * (0 or -1), NOT a 0/1 boolean — the mask is then AND-ed with data to select
             * it, so rendering a boolean would silently zero every selected lane.
             * `-(a == b)` is exactly that mask in C. */
            /* ---- 16x8 BYTE-lane ops: OPAQUE intrinsics, deliberately NOT modeled lane-wise.
             * The SSE2 strlen/strchr/memchr idiom is `xorps m,m; pcmpeqb m,[p]; pmovmskb r,m;
             * bsf r`. There is no byte-lane geometry here (xmm_f/xmm_i are 4x32) and building
             * one is the wrong altitude: nothing in NullWare reads an individual byte lane —
             * across all 26 pcmpeqb sites the mask's only consumer is pmovmskb -> and/test ->
             * bsf — and a symbolic 16-lane pmovmskb would be a 400-char bit-assembly that
             * set_reg's own node_count>400 guard would just spill again.
             *
             * But leaving pcmpeqb unmodeled is far worse than ugly. The generic fallback at
             * the bottom of this switch fires only for a GPR dest, so an xmm-dest pcmpeqb is
             * SILENTLY DROPPED: the dest keeps its pre-compare value, and after the customary
             * dep-breaking `xorps m,m` that value is the CONSTANT 0. Measured in fn_00084848
             * (the real strlen) — the compare vanishes and the loop exit is gated on a
             * fabricated zero:
             *     if (__pmovmskb(0)) break;
             * Defining the dest with an opaque call keeps the load in the tree and lets the
             * confidence header disclose it. pmovmskb itself needs no case — the existing GPR
             * fallback picks it up. DS_NO_LANES16. */
            /* Vector BROADCAST: replicate one scalar element across a (possibly wide)
             * vector register. Recorded as a fill so a later store of the register models
             * a real memset/element-fill instead of a dropped __vpbroadcast/__vmov store.
             * Source scalar is memory (`*(intN*)src`), the low element of an xmm, or a GP
             * register (the AVX-512 form). The lane model can't hold a >16-byte value, but
             * a uniform broadcast IS knowable at every byte, so the full width is sound. */
            case X86_INS_VPBROADCASTB: case X86_INS_VPBROADCASTW:
            case X86_INS_VPBROADCASTD: case X86_INS_VPBROADCASTQ:
            case X86_INS_VBROADCASTSS: case X86_INS_VBROADCASTSD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg vf = vec_reg(OP(0).reg);
                if (vf == R_NONE) break;
                int esz = (id == X86_INS_VPBROADCASTB) ? 1 :
                          (id == X86_INS_VPBROADCASTW) ? 2 :
                          (id == X86_INS_VPBROADCASTD || id == X86_INS_VBROADCASTSS) ? 4 : 8;
                ExprP val;
                if (OP(1).type == X86_OP_MEM) {
                    val = mkMem(addr_of_mem(OP(1)), esz);
                } else if (OP(1).type == X86_OP_REG) {
                    Reg sr; int sw; map_reg(OP(1).reg, sr, sw);
                    if (is_xmm(sr)) {
                        if (esz <= 4) {
                            ExprP l[4];
                            ExprP le = (xmm_i_lanes(OP(1), l) && l[0]) ? l[0] : nullptr;
                            /* the lanes were not stocked (e.g. `vmovd xmm,r32; vpbroadcastb`
                             * -- movd from a GP reg does not populate xmm_i_lanes): fall back
                             * to the xmm's scalar low value. This is the g++ inlined-memset
                             * idiom (vmovd edx,xmm; vpbroadcastb ymm,xmm; vmovdqu [dst],ymm),
                             * so without it the byte fill is lost and the store stays opaque. */
                            if (!le) le = simd_lane0(OP(1));
                            if (!le) { ExprP rv = rvalue(OP(1)); if (rv) le = rv; }
                            if (le)
                                val = (esz == 4) ? le
                                    : mkCast(esz == 1 ? "(unsigned __int8)" : "(unsigned __int16)", le, esz, true);
                        } else {
                            ExprP lo, hi;
                            if (simd_src_lanes(OP(1), lo, hi) && lo) val = lo;
                        }
                    } else {
                        ExprP r = rvalue(OP(1));
                        if (r) val = (esz >= 8) ? r
                            : mkCast(esz == 1 ? "(unsigned __int8)" : esz == 2 ? "(unsigned __int16)" : "(unsigned __int32)", r, esz, true);
                    }
                }
                if (val) vec_fill[vf] = { val, esz };
                break;
            }
            case X86_INS_PCMPEQB:  case X86_INS_VPCMPEQB:
            case X86_INS_PSHUFB:   case X86_INS_VPSHUFB: {
                if (std::getenv("DS_NO_LANES16")) break;
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                /* all-ones fill: `pcmpeqb x,x` (covers the ymm/wide form declined by the
                 * lane model below) -> a later store is memset(dst, 0xFF, n). */
                if (id == X86_INS_PCMPEQB || id == X86_INS_VPCMPEQB) {
                    int ai0 = (nop >= 3) ? 1 : 0, bi0 = (nop >= 3) ? 2 : 1;
                    if (OP(ai0).type == X86_OP_REG && OP(bi0).type == X86_OP_REG &&
                        OP(ai0).reg == OP(bi0).reg) {
                        Reg vf = vec_reg(OP(0).reg);
                        if (vf != R_NONE) vec_fill[vf] = { mkConst(0xFF, 1), 1 };
                    }
                }
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) {
                    /* YMM/ZMM dest: map_reg -> R_NONE, so the xmm lane path below can't hold
                     * it and the result was DROPPED -- the ymm vpcmpeqb vanished and the
                     * vpmovmskb that reads it fell to a phantom in_YMM that trim strips, so
                     * the AVX2 strlen/memchr/strchr scan loop got a FABRICATED zero-arg
                     * __vpmovmskb() exit that no longer depends on the scanned memory (32
                     * sites). Mirror the default AVX path: DEFINE the reg with a load-bearing
                     * opaque intrinsic in vec_op_value so the movmsk reads the real
                     * compare(+load). Same-reg all-ones is already a vec_fill above -- don't
                     * turn it into a bogus compare. DS_NO_SSESCAN. */
                    int aiy = (nop >= 3) ? 1 : 0, biy = (nop >= 3) ? 2 : 1;
                    bool samereg = OP(aiy).type == X86_OP_REG && OP(biy).type == X86_OP_REG &&
                                   OP(aiy).reg == OP(biy).reg;
                    bool wide = (OP(0).reg >= X86_REG_YMM0 && OP(0).reg <= X86_REG_YMM15) ||
                                (OP(0).reg >= X86_REG_ZMM0 && OP(0).reg <= X86_REG_ZMM31);
                    if (samereg || !wide ||
                        std::getenv("DS_NO_SSESCAN") || std::getenv("DS_NO_AVXMODEL")) break;
                    ExprP a0 = rvalue(OP(aiy)), a1v = rvalue(OP(biy));
                    if (!a0 || !a1v) break;   /* untracked src: leave the dest alone */
                    auto call = new_expr();
                    call->kind = EK::Call;
                    call->callee = "__" + sani(in.mnem);   /* __vpcmpeqb / __vpshufb extern */
                    call->width = 8; call->ret_kind = 2;
                    call->args.push_back(a0);              /* char broadcast */
                    call->args.push_back(a1v);             /* the scanned load *[rcx] */
                    extern_callees[call->callee] = call->ret_kind;
                    opaque_ops[call->callee]++;
                    vec_op_value[OP(0).reg] = call;        /* read back by rvalue() for R_NONE */
                    break;
                }
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;   /* VEX: dst,src1,src2 */
                /* `pcmpeqb x,x` is the canonical set-ALL-ONES idiom (the -1 twin of
                 * `xorps x,x`), NOT a real compare. Fold it — an opaque call here would
                 * DESTROY a known -1 mask. Both operands must be the SAME register: the
                 * dst==src1-against-memory form is a real compare. */
                if ((id == X86_INS_PCMPEQB || id == X86_INS_VPCMPEQB) &&
                    OP(ai).type == X86_OP_REG && OP(bi).type == X86_OP_REG &&
                    OP(ai).reg == OP(bi).reg) {
                    set_xmm_lanes(dr, mkConst(-1, 8), mkConst(-1, 8), b);
                    break;
                }
                ExprP a0 = rvalue(OP(ai)), a1v = rvalue(OP(bi));
                if (!a0 || !a1v) break;      /* untracked source: leave the dest alone */
                auto call = new_expr();
                call->kind = EK::Call;
                call->callee = "__" + sani(in.mnem);
                call->width = 8; call->ret_kind = 2;
                call->args.push_back(a0);
                call->args.push_back(a1v);
                extern_callees[call->callee] = call->ret_kind;
                opaque_ops[call->callee]++;      /* feeds the confidence header */
                do_dst(b, OP(0), call, in.addr);
                break;
            }
            case X86_INS_PCMPEQD: case X86_INS_VPCMPEQD:
            case X86_INS_PCMPGTD: case X86_INS_VPCMPGTD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                if (id == X86_INS_PCMPEQD || id == X86_INS_VPCMPEQD) {
                    int ai0 = (nop >= 3) ? 1 : 0, bi0 = (nop >= 3) ? 2 : 1;
                    if (OP(ai0).type == X86_OP_REG && OP(bi0).type == X86_OP_REG &&
                        OP(ai0).reg == OP(bi0).reg) {
                        Reg vf = vec_reg(OP(0).reg);        /* pcmpeqd x,x -> all-ones fill */
                        if (vf != R_NONE) vec_fill[vf] = { mkConst(0xFF, 1), 1 };
                    }
                }
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP a[4], bb[4];
                if (!xmm_i_lanes(OP(ai), a) || !xmm_i_lanes(OP(bi), bb)) break;
                bool eq = (id == X86_INS_PCMPEQD || id == X86_INS_VPCMPEQD);
                ExprP r[4];
                for (int i = 0; i < 4; ++i)
                    r[i] = mkUnary("-", mkBinary(eq ? "==" : ">", a[i], bb[i], 4), 4);
                set_xmm_i4(dr, r[0], r[1], r[2], r[3], b);
                break;
            }
            /* Packed shift by a SCALAR count. x86 and C disagree at the edges: a count
             * >= the lane width yields ZERO on x86 (all sign bits for psrad), where C's
             * shift is UNDEFINED — so only a constant count within the lane is modeled,
             * and anything else is left alone rather than mis-rendered. */
            /* The VEX spellings reach the SAME body: it was written 3-operand-aware from the
             * start (`int ai = (nop >= 3) ? 1 : 0` -- "VEX: dst,src,imm") and only the case
             * labels were missing, so every vps* site was silently dropped. 11 real sites in
             * NullWare (vpsrlq 5, vpsllq 3, vpsrld 2, vpsrad 1), all xmm.
             * A 256-bit form is declined for free by the is_xmm check below: map_reg gives
             * R_NONE for ymm, and the lane arrays are 4x32 -- see the VEX width guard. */
            case X86_INS_PSLLD:  case X86_INS_PSRLD:  case X86_INS_PSRAD:
            case X86_INS_VPSLLD: case X86_INS_VPSRLD: case X86_INS_VPSRAD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, si = (nop >= 3) ? 2 : 1;   /* VEX: dst,src,imm */
                if (OP(si).type != X86_OP_IMM) break;                   /* xmm count: not modeled */
                int64_t n = OP(si).imm;
                if (n < 0 || n > 31) break;
                ExprP a[4];
                if (!xmm_i_lanes(OP(ai), a)) break;
                ExprP r[4];
                for (int i = 0; i < 4; ++i) {
                    if (id == X86_INS_PSLLD)
                        r[i] = mkBinary("<<", a[i], mkConst(n, 4), 4);
                    else if (id == X86_INS_PSRLD)   /* logical: force an unsigned shift */
                        r[i] = mkBinary(">>", mkCast("(unsigned int)", a[i], 4, true),
                                        mkConst(n, 4), 4, true);
                    else                            /* psrad: arithmetic -> signed */
                        r[i] = mkBinary(">>", mkCast("(int)", a[i], 4, false),
                                        mkConst(n, 4), 4, false);
                }
                set_xmm_i4(dr, r[0], r[1], r[2], r[3], b);
                break;
            }
            case X86_INS_PSLLQ:  case X86_INS_PSRLQ:
            case X86_INS_VPSLLQ: case X86_INS_VPSRLQ: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, si = (nop >= 3) ? 2 : 1;
                if (OP(si).type != X86_OP_IMM) break;
                int64_t n = OP(si).imm;
                if (n < 0 || n > 63) break;
                ExprP alo, ahi;
                if (!simd_src_lanes(OP(ai), alo, ahi)) break;
                bool left = (id == X86_INS_PSLLQ);
                auto sh = [&](ExprP v) {
                    return left ? mkBinary("<<", v, mkConst(n, 8), 8)
                                : mkBinary(">>", mkCast("(unsigned long long)", v, 8, true),
                                           mkConst(n, 8), 8, true);
                };
                set_xmm_lanes(dr, sh(alo), sh(ahi), b);
                break;
            }
            /* packed sqrt over the two 64-bit (double) lanes. Unmodeled, the dest kept a
             * stale value — the same failure the SCALAR sqrtss/sqrtsd fix addressed, where
             * a dep-breaking `xorps dst,dst` then left the result as 0.0. */
            case X86_INS_SQRTPD: case X86_INS_VSQRTPD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                ExprP alo, ahi;
                if (!simd_src_lanes(OP(nop >= 2 ? 1 : 0), alo, ahi)) break;
                auto mk = [&](ExprP v) {
                    auto c = new_expr();
                    c->kind = EK::Call; c->callee = "sqrt"; c->width = 8;
                    c->is_float = true; c->ret_kind = 4;
                    c->args.push_back(v);
                    return c;
                };
                used_sqrt = true;
                set_xmm_lanes(dr, mk(alo), mk(ahi), b);
                break;
            }
            /* unpcklpd dst,src = {dst.lo, src.lo} — the low doubles interleaved (it is how
             * a {x,y} pair is assembled). unpckhpd takes the HIGH lanes: {dst.hi, src.hi}. */
            /* PACKED DOUBLE arithmetic: dst[i] = a[i] OP b[i] over the two 64-bit doubles.
             * The 2x64 lane view (simd_src_lanes) IS the double representation the engine
             * already uses for unpcklpd/movsd, so this is exact, not opaque. */
            case X86_INS_ADDPD: case X86_INS_SUBPD: case X86_INS_MULPD: case X86_INS_DIVPD:
            case X86_INS_MAXPD: case X86_INS_MINPD:
            case X86_INS_VADDPD: case X86_INS_VSUBPD: case X86_INS_VMULPD: case X86_INS_VDIVPD:
            case X86_INS_VMAXPD: case X86_INS_VMINPD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP alo, ahi, blo, bhi;
                if (!simd_src_lanes(OP(ai), alo, ahi) || !simd_src_lanes(OP(bi), blo, bhi)) break;
                bool ismax = (id==X86_INS_MAXPD||id==X86_INS_VMAXPD);
                bool ismin = (id==X86_INS_MINPD||id==X86_INS_VMINPD);
                const char* fop =
                    (id==X86_INS_MULPD||id==X86_INS_VMULPD) ? "*" :
                    (id==X86_INS_ADDPD||id==X86_INS_VADDPD) ? "+" :
                    (id==X86_INS_SUBPD||id==X86_INS_VSUBPD) ? "-" : "/";
                auto dlane = [&](ExprP x, ExprP y) -> ExprP {
                    x->is_float = true; y->is_float = true;
                    if (ismax || ismin) {   /* x86 max/min: `(a OP b) ? a : b` */
                        ExprP c = mkBinary(ismax ? ">" : "<", clone(x), clone(y), 8);
                        ExprP t = mkTernary(c, x, y, 8); t->is_float = true; return t;
                    }
                    ExprP e = mkBinary(fop, x, y, 8); e->is_float = true; return e;
                };
                set_xmm_lanes(dr, dlane(alo, blo), dlane(ahi, bhi), b);
                break;
            }
            /* PACKED QWORD compare-equal: dst[qw] = (a==b) ? -1 : 0, over the two 64-bit lanes. */
            case X86_INS_PCMPEQQ: case X86_INS_VPCMPEQQ: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                {
                    int ai0 = (nop >= 3) ? 1 : 0, bi0 = (nop >= 3) ? 2 : 1;
                    if (OP(ai0).type == X86_OP_REG && OP(bi0).type == X86_OP_REG &&
                        OP(ai0).reg == OP(bi0).reg) {
                        Reg vf = vec_reg(OP(0).reg);        /* pcmpeqq x,x -> all-ones fill */
                        if (vf != R_NONE) vec_fill[vf] = { mkConst(0xFF, 1), 1 };
                    }
                }
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP alo, ahi, blo, bhi;
                if (!simd_src_lanes(OP(ai), alo, ahi) || !simd_src_lanes(OP(bi), blo, bhi)) break;
                set_xmm_lanes(dr, mkUnary("-", mkBinary("==", alo, blo, 8), 8),
                                  mkUnary("-", mkBinary("==", ahi, bhi, 8), 8), b);
                break;
            }
            /* PUNPCKLDQ: interleave the low two 32-bit lanes -> {a0, b0, a1, b1}. Pure lane
             * rearrange over the 4x32 int model, exact. */
            case X86_INS_PUNPCKLDQ: case X86_INS_VPUNPCKLDQ: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP a[4], bb[4];
                if (!xmm_i_lanes(OP(ai), a) || !xmm_i_lanes(OP(bi), bb)) break;
                set_xmm_i4(dr, a[0], bb[0], a[1], bb[1], b);
                break;
            }
            case X86_INS_UNPCKLPD: case X86_INS_VUNPCKLPD:
            case X86_INS_UNPCKHPD: case X86_INS_VUNPCKHPD: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                ExprP alo, ahi, blo, bhi;
                if (!simd_src_lanes(OP(ai), alo, ahi)) break;
                if (!simd_src_lanes(OP(bi), blo, bhi)) break;
                bool hi = (id == X86_INS_UNPCKHPD || id == X86_INS_VUNPCKHPD);
                set_xmm_lanes(dr, hi ? ahi : alo, hi ? bhi : blo, b);
                break;
            }
            case X86_INS_PSRLDQ: {
                /* byte-granular logical right shift. The horizontal-reduction idiom
                 * `psrldq xmm,8` moves lane1 into lane0 (lane1<-0); model only that.
                 * (VPSRLDQ's VEX form has a separate source operand, so it is not just a
                 * label here; it falls to the opaque SIMD fallback, 1 site.) */
                if (nop < 2 || OP(0).type != X86_OP_REG || OP(1).type != X86_OP_IMM) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int shb = (int)OP(1).imm;
                /* 4x32 horizontal-reduce: `psrldq acc,8`/`,4` shifts the higher int32
                 * lanes down (0-filled) so a following paddd folds the vector toward
                 * lane 0 — isum's `paddd; psrldq 8; paddd; psrldq 4; paddd; movd` tree
                 * collapsing the 4-lane accumulator to a scalar total. */
                if ((shb % 4) == 0 && xmm_i[dr][0] && xmm_i[dr][1] &&
                    xmm_i[dr][2] && xmm_i[dr][3]) {
                    int sh = shb / 4;
                    ExprP nl[4];
                    for (int L = 0; L < 4; ++L)
                        nl[L] = (L + sh < 4) ? clone(xmm_i[dr][L + sh]) : mkConst(0, 4);
                    set_xmm_i4(dr, nl[0], nl[1], nl[2], nl[3], b);
                    break;
                }
                ExprP hi = xmm_hi(dr);
                if (shb == 8 && hi) { set_xmm_lanes(dr, hi, mkConst(0, 8), b); break; }
                /* A byte-granular shift the lane model cannot express (an odd/unaligned
                 * count, e.g. the SSE2 strcspn/strpbrk `psrldq xmm,3`). Do NOT fall off
                 * the end with the destination UNCHANGED — that silently reuses the
                 * pre-shift bytes and every downstream pcmpeqb compares the wrong lanes.
                 * Define the dest with an opaque `__psrldq(src, n)` intrinsic (the same
                 * honest floor pslldq already gets from the default fallback) so the shift
                 * survives as a real data dependency instead of being dropped. Only the
                 * SSE PSRLDQ form (dst is BOTH source and destination) reaches here; the
                 * VEX VPSRLDQ has a separate source and takes the default path. */
                if (!std::getenv("DS_NO_SIMDOPAQUE")) {
                    auto call = new_expr();
                    call->kind = EK::Call;
                    call->callee = "__" + sani(in.mnem);
                    call->width = 8; call->ret_kind = 2;   /* carry the xmm as an 8-byte view */
                    call->args.push_back(rvalue(OP(0)));    /* current value (RMW dest) */
                    call->args.push_back(rvalue(OP(1)));    /* shift byte count */
                    extern_callees[call->callee] = call->ret_kind;
                    opaque_ops[call->callee]++;             /* keep the confidence header honest */
                    do_dst(b, OP(0), call, in.addr);
                }
                break;
            }
            case X86_INS_PMOVSXDQ: case X86_INS_PMOVZXDQ:
            case X86_INS_VPMOVSXDQ: case X86_INS_VPMOVZXDQ: {
                /* widen 2 packed int32 -> 2 int64 (sign/zero extend). The head of an
                 * auto-vectorized int->int64 sum reduction: `pmovsxdq xmm,[p]; paddq
                 * acc,xmm`. Lane 0 = (i64)*(int*)p, lane 1 = (i64)*(int*)(p+4). */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                bool sx = (id == X86_INS_PMOVSXDQ);
                if (OP(1).type == X86_OP_MEM) {
                    ExprP m0 = rvalue(OP(1));
                    if (!m0 || m0->kind != EK::Mem || !m0->a) break;
                    ExprP lo = mkMem(clone(m0->a), 4, !sx);
                    ExprP hi = mkMem(mkBinary("+", clone(m0->a), mkConst(4, 8), 8), 4, !sx);
                    set_xmm_lanes(dr, mkCast(sx ? "(long long)" : "(unsigned long long)", lo, 8),
                                      mkCast(sx ? "(long long)" : "(unsigned long long)", hi, 8), b);
                }
                break;
            }
            /* ---- packed 32-bit FLOAT vector ops (4 lanes) ---- */
            case X86_INS_MULPS: case X86_INS_ADDPS: case X86_INS_SUBPS:
            case X86_INS_DIVPS: case X86_INS_MAXPS: case X86_INS_MINPS:
            case X86_INS_VMULPS: case X86_INS_VADDPS: case X86_INS_VSUBPS:
            case X86_INS_VDIVPS: case X86_INS_VMAXPS: case X86_INS_VMINPS: {
                /* dst = dst OP src (2-op) / src1 OP src2 (3-op VEX), lane-wise over
                 * the four floats. Only commits when BOTH sources yield 4 float lanes
                 * (a memory operand supplies `*(float*)(p+4i)`), else leaves dst. */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                bool ismax = (id==X86_INS_MAXPS||id==X86_INS_VMAXPS);
                bool ismin = (id==X86_INS_MINPS||id==X86_INS_VMINPS);
                const char* fop =
                    (id==X86_INS_MULPS||id==X86_INS_VMULPS) ? "*" :
                    (id==X86_INS_ADDPS||id==X86_INS_VADDPS) ? "+" :
                    (id==X86_INS_SUBPS||id==X86_INS_VSUBPS) ? "-" : "/";
                auto flane_op = [&](ExprP x, ExprP y) -> ExprP {
                    ExprP e;
                    if (ismax || ismin) {
                        ExprP c = mkBinary(ismax ? ">" : "<", clone(x), clone(y), 4);
                        e = mkTernary(c, clone(x), clone(y), 4);
                    } else e = mkBinary(fop, x, y, 4);
                    e->is_float = true; return e;
                };
                ExprP a[4], bb[4];
                if (xmm_f_lanes(OP(ai), a) && xmm_f_lanes(OP(bi), bb)) {
                    ExprP r[4];
                    for (int i = 0; i < 4; ++i) r[i] = flane_op(a[i], bb[i]);
                    set_xmm_f4(dr, r[0], r[1], r[2], r[3], b);
                    break;
                }
                /* 2-wide (8-byte movsd-as-2-floats) remainder: only lanes 0,1 live. */
                ExprP a2[2], b2[2];
                if (xmm_f_lanes2(OP(ai), a2) && xmm_f_lanes2(OP(bi), b2)) {
                    set_xmm_f2(dr, flane_op(a2[0], b2[0]), flane_op(a2[1], b2[1]), b);
                }
                break;
            }
            /* ---- packed 32-bit INTEGER arithmetic (4 lanes) ---- */
            case X86_INS_PMULLD: case X86_INS_PADDD: case X86_INS_PSUBD:
            case X86_INS_VPMULLD: case X86_INS_VPADDD: case X86_INS_VPSUBD: {
                /* dst = src1 OP src2, lane-wise over the four ints. Only commits when BOTH
                 * sources yield 4 int lanes (a movdqu load / prior packed-int op).
                 * SSE: dst is src1 (2 operands). VEX: dst,src1,src2 (3 operands) -- read the
                 * sources from ai/bi so the VEX form does not shift the wrong lanes. */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int ai = (nop >= 3) ? 1 : 0, bi = (nop >= 3) ? 2 : 1;
                const char* iop = (id==X86_INS_PMULLD || id==X86_INS_VPMULLD) ? "*" :
                                  (id==X86_INS_PADDD  || id==X86_INS_VPADDD)  ? "+" : "-";
                ExprP a[4], bb[4];
                if (xmm_i_lanes(OP(ai), a) && xmm_i_lanes(OP(bi), bb)) {
                    ExprP r[4];
                    for (int i = 0; i < 4; ++i) r[i] = mkBinary(iop, a[i], bb[i], 4);
                    set_xmm_i4(dr, r[0], r[1], r[2], r[3], b);
                    break;
                }
                /* 2-wide (8-byte movq) remainder: only lanes 0,1 are live. */
                ExprP a2[2], b2[2];
                if (xmm_i_lanes2(OP(ai), a2) && xmm_i_lanes2(OP(bi), b2)) {
                    ExprP r0 = mkBinary(iop, a2[0], b2[0], 4);
                    ExprP r1 = mkBinary(iop, a2[1], b2[1], 4);
                    set_xmm_i2(dr, r0, r1, b);
                }
                break;
            }
            case X86_INS_PSHUFD: case X86_INS_VPSHUFD: {
                /* pshufd dst, src, imm: dst[i] = src[(imm >> 2*i) & 3]. `pshufd x,x,0`
                 * broadcasts lane 0 (the scalar splat after `movd xmm,reg`). The VEX form
                 * has the SAME dst,src,imm layout, so it shares the body directly. */
                if (nop < 3 || OP(0).type != X86_OP_REG || OP(2).type != X86_OP_IMM) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int imm = (int)OP(2).imm;
                ExprP s[4];
                bool have = xmm_i_lanes(OP(1), s);
                /* broadcast of a scalar lane-0 (`movd`-loaded) that has no full vector */
                ExprP sc = nullptr;
                if (!have && OP(1).type == X86_OP_REG) {
                    Reg s2; int sw2; map_reg(OP(1).reg, s2, sw2);
                    if (is_xmm(s2) && xmm_i[s2][0]) sc = clone(xmm_i[s2][0]);
                    else if (is_xmm(s2) && regfile[s2]) sc = clone(regfile[s2]);
                }
                auto lane = [&](int j) -> ExprP {
                    if (have) return clone(s[j]);
                    return (j == 0 && sc) ? clone(sc) : nullptr;
                };
                ExprP r0 = lane(imm & 3), r1 = lane((imm >> 2) & 3);
                ExprP r2 = lane((imm >> 4) & 3), r3 = lane((imm >> 6) & 3);
                if (r0 && r1 && r2 && r3) set_xmm_i4(dr, r0, r1, r2, r3, b);
                break;
            }
            case X86_INS_SHUFPS: case X86_INS_VSHUFPS: {
                /* shufps dst, src, imm: dst[0]=dst[imm&3], dst[1]=dst[(imm>>2)&3],
                 * dst[2]=src[(imm>>4)&3], dst[3]=src[(imm>>6)&3]. `shufps x,x,0xff`
                 * broadcasts lane 3; `shufps x,x,0` broadcasts a SCALAR lane 0 (the
                 * `vec * scalar` splat) — for the latter a full vector isn't tracked,
                 * so fall back to the scalar lane-0 value when a selector picks 0. */
                int ii = 2;
                if (nop < 3 || OP(0).type != X86_OP_REG || OP(ii).type != X86_OP_IMM) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                int imm = (int)OP(ii).imm;
                ExprP d[4], s[4];
                bool haveD = xmm_f_lanes(OP(0), d);
                bool haveS = xmm_f_lanes(OP(1), s);
                ExprP dscal = haveD ? nullptr : xmm_scalar_f(OP(0));
                ExprP sscal = haveS ? nullptr : xmm_scalar_f(OP(1));
                auto dlane = [&](int i)->ExprP { if (haveD) return clone(d[i]); return (i==0 && dscal) ? clone(dscal) : nullptr; };
                auto slane = [&](int i)->ExprP { if (haveS) return clone(s[i]); return (i==0 && sscal) ? clone(sscal) : nullptr; };
                ExprP r0 = dlane(imm & 3), r1 = dlane((imm >> 2) & 3);
                ExprP r2 = slane((imm >> 4) & 3), r3 = slane((imm >> 6) & 3);
                if (r0 && r1 && r2 && r3) set_xmm_f4(dr, r0, r1, r2, r3, b);
                break;
            }
            case X86_INS_UNPCKLPS: case X86_INS_UNPCKHPS:
            case X86_INS_MOVLHPS:  case X86_INS_MOVHLPS: {
                /* unpcklps dst,src -> {d0,s0,d1,s1}; unpckhps -> {d2,s2,d3,s3};
                 * movlhps -> {d0,d1,s0,s1}; movhlps -> {s2,s3,d2,d3}. */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                ExprP d[4], s[4];
                bool dok = xmm_f_lanes(OP(0), d), sok = xmm_f_lanes(OP(1), s);
                /* `unpcklps` combining two SCALARS (each xmm holds one float in lane0,
                 * the Vec2 return-pack idiom `{x,y}` before `movq rax,xmm`): fall back
                 * to the scalar lane-0 value so the pack is tracked. */
                if (id == X86_INS_UNPCKLPS && (!dok || !sok)) {
                    ExprP ds = dok ? clone(d[0]) : xmm_scalar_f(OP(0));
                    ExprP ss = sok ? clone(s[0]) : xmm_scalar_f(OP(1));
                    if (ds && ss) { set_xmm_f4(dr, ds, ss, nullptr, nullptr, b); break; }
                }
                if (!dok || !sok) break;
                if (id == X86_INS_UNPCKLPS)
                    set_xmm_f4(dr, clone(d[0]), clone(s[0]), clone(d[1]), clone(s[1]), b);
                else if (id == X86_INS_UNPCKHPS)
                    set_xmm_f4(dr, clone(d[2]), clone(s[2]), clone(d[3]), clone(s[3]), b);
                else if (id == X86_INS_MOVLHPS)
                    set_xmm_f4(dr, clone(d[0]), clone(d[1]), clone(s[0]), clone(s[1]), b);
                else /* MOVHLPS */
                    set_xmm_f4(dr, clone(s[2]), clone(s[3]), clone(d[2]), clone(d[3]), b);
                break;
            }
            /* SCALAR ROUND: roundss dst, src, imm -- imm[1:0] picks the mode. Model as the C
             * function that mode really is, so the value is exact, not opaque:
             *   0 nearbyint  1 floor  2 ceil  3 trunc. (imm bit 2 = "use MXCSR" -> nearbyint) */
            case X86_INS_ROUNDSS: case X86_INS_VROUNDSS:
            case X86_INS_ROUNDSD: case X86_INS_VROUNDSD: {
                if (nop < 2) break;
                bool dbl = (id==X86_INS_ROUNDSD||id==X86_INS_VROUNDSD);
                int w = dbl ? 8 : 4;
                int si = (nop >= 3) ? 1 : (nop >= 2 ? 1 : 0);
                int imm = (nop >= 3 && OP(nop-1).type==X86_OP_IMM) ? (int)OP(nop-1).imm : 0;
                const char* fn = (imm & 4) ? (dbl?"nearbyint":"nearbyintf")
                               : (imm & 3) == 1 ? (dbl?"floor":"floorf")
                               : (imm & 3) == 2 ? (dbl?"ceil":"ceilf")
                               : (imm & 3) == 3 ? (dbl?"trunc":"truncf") : (dbl?"nearbyint":"nearbyintf");
                auto call = new_expr();
                call->kind = EK::Call; call->callee = fn; call->width = w; call->ret_kind = dbl?4:3;
                call->args.push_back(fp_src(OP(si), w));
                call->is_float = true;
                used_mathfn.insert(fn);
                do_dst(b, OP(0), call, in.addr);
                break;
            }
            /* RSQRTSS: approximate 1/sqrt(x). Model as 1.0f/sqrtf(x) -- the exact function it
             * approximates; the ~11-bit HW approximation is not observable in decompiled C. */
            case X86_INS_RSQRTSS: case X86_INS_VRSQRTSS: {
                if (nop < 1) break;
                int si = (nop >= 2) ? 1 : 0;
                auto sq = new_expr();
                sq->kind = EK::Call; sq->callee = "sqrtf"; sq->width = 4; sq->ret_kind = 3;
                sq->args.push_back(fp_src(OP(si), 4)); sq->is_float = true;
                used_mathfn.insert("sqrtf");
                ExprP one = mkConst(0x3f800000LL, 4); one->is_float = true;   /* bits of 1.0f */
                ExprP r = mkBinary("/", one, sq, 4); r->is_float = true;
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            case X86_INS_ADDSS: case X86_INS_ADDSD: case X86_INS_SUBSS:
            case X86_INS_SUBSD: case X86_INS_MULSS: case X86_INS_MULSD:
            case X86_INS_DIVSS: case X86_INS_DIVSD: {
                if (nop < 2) break;
                const char* fop =
                    (id==X86_INS_ADDSS||id==X86_INS_ADDSD) ? "+" :
                    (id==X86_INS_SUBSS||id==X86_INS_SUBSD) ? "-" :
                    (id==X86_INS_MULSS||id==X86_INS_MULSD) ? "*" : "/";
                int w = (id==X86_INS_ADDSD||id==X86_INS_SUBSD||
                         id==X86_INS_MULSD||id==X86_INS_DIVSD) ? 8 : 4;
                ExprP r = mkBinary(fop, fp_src(OP(0), w), fp_src(OP(1), w), w);
                r->is_float = true;
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            case X86_INS_MAXSS: case X86_INS_MAXSD:
            case X86_INS_MINSS: case X86_INS_MINSD: {
                /* dest = max/min(dest, src). x86 MAXSS/MINSS return the SECOND
                 * operand (src) when the compare is unordered (either is NaN) or
                 * equal-to-src: `MAX = (dst > src) ? dst : src`, `MIN = (dst < src)
                 * ? dst : src`. Modeling it the other way round — `(dst<src)?src:dst`
                 * — is algebraically equal for ordered values but picks DST (=NaN)
                 * on a NaN dst instead of src, so a maxss-reduction over an array
                 * with a NaN element returned NaN where the CPU returns the running
                 * value. Select dst on the ordered compare, fall through to src. */
                if (nop < 2) break;
                int w = (id==X86_INS_MAXSD||id==X86_INS_MINSD) ? 8 : 4;
                bool ismax = (id==X86_INS_MAXSS||id==X86_INS_MAXSD);
                ExprP d = as_float(rvalue(OP(0)), w), s = as_float(rvalue(OP(1)), w);
                ExprP cmp = mkBinary(ismax ? ">" : "<", clone(d), clone(s), w);
                ExprP r = mkTernary(cmp, clone(d), clone(s), w);
                r->is_float = true;
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            case X86_INS_SQRTSS: case X86_INS_SQRTSD: {
                /* dest = sqrt(src). MSVC INLINES sqrtf/sqrt as a fast path
                 * (`xorps dst,dst; ucomiss 0,x; ja slow; sqrtss dst,x`), and the
                 * dep-breaking `xorps dst,dst` sits right before it — so WITHOUT
                 * modeling sqrtss the dst keeps the const-0 and the function returns
                 * 0.0 instead of the root (a normalize/length scale collapses to 0,
                 * zeroing all output geometry). Value-lift it as a float intrinsic;
                 * the src is OP(1) (fp_src forwards a spilled lane). */
                if (nop < 2) break;
                int w = (id==X86_INS_SQRTSD) ? 8 : 4;
                ExprP src = fp_src(OP(1), w);
                auto call = new_expr();
                call->kind = EK::Call; call->callee = (w >= 8) ? "sqrt" : "sqrtf";
                call->width = w; call->is_float = true; call->ret_kind = (w >= 8) ? 4 : 3;
                if (src) call->args.push_back(src);
                used_sqrt = true;
                do_dst(b, OP(0), call, in.addr);
                break;
            }
            case X86_INS_COMISS: case X86_INS_UCOMISS:
            case X86_INS_COMISD: case X86_INS_UCOMISD: {
                if (nop < 2) break;
                int w = (id==X86_INS_COMISD||id==X86_INS_UCOMISD) ? 8 : 4;
                flags = FlagSrc();
                flags.valid = true; flags.is_fcmp = true;
                flags.a = as_float(rvalue(OP(0)), w);
                flags.b = as_float(rvalue(OP(1)), w); flags.width = w;
                break;
            }
            case X86_INS_CVTSI2SS: case X86_INS_CVTSI2SD: {
                /* int -> float/double. Emit an EXPLICIT (float)/(double) cast so
                 * the integer value is converted (not reinterpreted) AND the
                 * downstream float op sees a float-typed Cast, never the bare int
                 * variable — otherwise a divisor like cvtsi2sd xmm1,[n] would taint
                 * the int count `n` as float. */
                if (nop < 2) break;
                int w = (id==X86_INS_CVTSI2SD) ? 8 : 4;
                ExprP c = mkCast(w >= 8 ? "(double)" : "(float)", rvalue(OP(1)), w, false);
                c->is_float = true;
                do_dst(b, OP(0), c, in.addr);
                break;
            }
            case X86_INS_CVTSS2SD: case X86_INS_CVTSD2SS:
            case X86_INS_CVTPS2PD: case X86_INS_CVTPD2PS: {
                /* float<->double precision change. Emit an EXPLICIT (double)/(float)
                 * cast of the source so the value's WIDTH changes (4<->8) via a fresh
                 * Cast node — otherwise a following `movsd [d],xmm` widens the source
                 * `*(float*)` Mem IN PLACE to `*(double*)`, silently dropping the
                 * cvtps2pd float->double conversion (fun_00013750). The packed
                 * cvtps2pd/cvtpd2ps are modeled on their low (scalar) element — better
                 * than the previous total drop; genuine 2-wide use stays approximate. */
                if (nop < 2) break;
                bool to_double = (id==X86_INS_CVTSS2SD || id==X86_INS_CVTPS2PD);
                int w = to_double ? 8 : 4;
                ExprP src = rvalue(OP(1));
                ExprP c = mkCast(to_double ? "(double)" : "(float)", src, w, false);
                c->is_float = true;
                do_dst(b, OP(0), c, in.addr);
                break;
            }
            /* ==== AVX/VEX scalar float: dst != src operands (data-carrying) ==== */
            case X86_INS_VADDSS: case X86_INS_VADDSD: case X86_INS_VSUBSS:
            case X86_INS_VSUBSD: case X86_INS_VMULSS: case X86_INS_VMULSD:
            case X86_INS_VDIVSS: case X86_INS_VDIVSD: {
                if (nop < 3) break;
                const char* fop =
                    (id==X86_INS_VADDSS||id==X86_INS_VADDSD) ? "+" :
                    (id==X86_INS_VSUBSS||id==X86_INS_VSUBSD) ? "-" :
                    (id==X86_INS_VMULSS||id==X86_INS_VMULSD) ? "*" : "/";
                int w = (id==X86_INS_VADDSD||id==X86_INS_VSUBSD||
                         id==X86_INS_VMULSD||id==X86_INS_VDIVSD) ? 8 : 4;
                ExprP r = mkBinary(fop, fp_src(OP(1), w), fp_src(OP(2), w), w);
                r->is_float = true;
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            case X86_INS_VMAXSS: case X86_INS_VMAXSD:
            case X86_INS_VMINSS: case X86_INS_VMINSD: {
                if (nop < 3) break;
                int w = (id==X86_INS_VMAXSD||id==X86_INS_VMINSD) ? 8 : 4;
                bool ismax = (id==X86_INS_VMAXSS||id==X86_INS_VMAXSD);
                ExprP d = as_float(fp_src(OP(1), w), w), s = as_float(fp_src(OP(2), w), w);
                ExprP cmp = mkBinary(ismax ? ">" : "<", clone(d), clone(s), w);
                ExprP r = mkTernary(cmp, clone(d), clone(s), w); r->is_float = true;
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            case X86_INS_VXORPS: case X86_INS_VXORPD: case X86_INS_VPXOR: {
                /* zero when both sources are the same reg; else FP negate when src2 is a
                 * sign mask (dst = -src1). Value is src1(OP1), mask is src2(OP2). */
                if (nop < 3) break;
                if (OP(1).type==X86_OP_REG && OP(2).type==X86_OP_REG && OP(1).reg==OP(2).reg) {
                    do_dst(b, OP(0), mkConst(0, (id==X86_INS_VXORPD)?8:4), in.addr);
                    Reg zr; int zw; map_reg(OP(0).reg, zr, zw);
                    if (is_xmm(zr)) {
                        regfile_hi[zr] = mkConst(0, 8);
                        ExprP zl[4] = { mkConst(0,4), mkConst(0,4), mkConst(0,4), mkConst(0,4) };
                        populate_xmm_i(zr, zl);
                    }
                    /* a zeroed wide reg that is later stored is a memset(dst,0,n). */
                    { Reg vf = vec_reg(OP(0).reg); if (vf != R_NONE) vec_fill[vf] = { mkConst(0, 1), 1 }; }
                    break;
                }
                if (id != X86_INS_VPXOR && OP(0).type==X86_OP_REG) {
                    uint32_t lo=0, hi=0; bool have=false;
                    if (OP(2).type==X86_OP_MEM && OP(2).mem.base==X86_REG_RIP &&
                        OP(2).mem.index==X86_REG_INVALID) {
                        uint64_t a = cur_insn_addr + cur_insn_size + (uint64_t)OP(2).mem.disp;
                        int32_t l2,h2; if (read_i32(a,l2)&&read_i32(a+4,h2)) { lo=(uint32_t)l2; hi=(uint32_t)h2; have=true; }
                    } else if (OP(2).type==X86_OP_REG) {
                        ExprP mv=rvalue(OP(2));
                        if (mv && mv->kind==EK::Const) { lo=(uint32_t)(uint64_t)mv->cval; hi=(mv->width>=8)?(uint32_t)((uint64_t)mv->cval>>32):0u; have=true; }
                    }
                    if (have) {
                        int negw=0;
                        if (lo==0x80000000u&&hi==0) negw=4;
                        else if (lo==0&&hi==0x80000000u) negw=8;
                        else if (lo==0x80000000u&&hi==0x80000000u) negw=(id==X86_INS_VXORPD)?8:4;
                        if (negw) { ExprP r=mkUnary("-", fp_src(OP(1),negw), negw); r->is_float=true; do_dst(b, OP(0), r, in.addr); }
                    }
                }
                break;
            }
            case X86_INS_VANDPS: case X86_INS_VANDPD: {
                /* fabs: dst = src1 & abs-mask. value=OP1, mask=OP2. */
                if (nop < 3 || OP(0).type != X86_OP_REG) break;
                uint32_t lo=0, hi=0; bool have=false;
                if (OP(2).type==X86_OP_MEM && OP(2).mem.base==X86_REG_RIP && OP(2).mem.index==X86_REG_INVALID) {
                    uint64_t a = cur_insn_addr + cur_insn_size + (uint64_t)OP(2).mem.disp;
                    int32_t l2,h2; if (read_i32(a,l2)&&read_i32(a+4,h2)) { lo=(uint32_t)l2; hi=(uint32_t)h2; have=true; }
                } else if (OP(2).type==X86_OP_REG) {
                    ExprP mv=rvalue(OP(2));
                    if (mv && mv->kind==EK::Const) { lo=(uint32_t)(uint64_t)mv->cval; hi=(mv->width>=8)?(uint32_t)((uint64_t)mv->cval>>32):0u; have=true; }
                }
                int absw=0;
                if (have) {
                    if (lo==0x7fffffffu && hi==0) absw=4;
                    else if (lo==0xffffffffu && hi==0x7fffffffu) absw=8;
                    else if (lo==0x7fffffffu && hi==0x7fffffffu) absw=(id==X86_INS_VANDPD)?8:4;
                }
                if (absw) {
                    auto call = new_expr();
                    call->kind=EK::Call; call->callee=(absw>=8)?"__fabs":"__fabsf";
                    call->width=absw; call->is_float=true;
                    call->args.push_back(fp_src(OP(1), absw));
                    used_fabs=true;
                    do_dst(b, OP(0), call, in.addr);
                }
                break;
            }
            case X86_INS_VFMADD132SS: case X86_INS_VFMADD213SS: case X86_INS_VFMADD231SS:
            case X86_INS_VFMADD132SD: case X86_INS_VFMADD213SD: case X86_INS_VFMADD231SD:
            case X86_INS_VFNMADD132SS: case X86_INS_VFNMADD213SS: case X86_INS_VFNMADD231SS:
            case X86_INS_VFNMADD132SD: case X86_INS_VFNMADD213SD: case X86_INS_VFNMADD231SD:
            case X86_INS_VFMSUB132SS: case X86_INS_VFMSUB213SS: case X86_INS_VFMSUB231SS:
            case X86_INS_VFMSUB132SD: case X86_INS_VFMSUB213SD: case X86_INS_VFMSUB231SD:
            case X86_INS_VFNMSUB132SS: case X86_INS_VFNMSUB213SS: case X86_INS_VFNMSUB231SS:
            case X86_INS_VFNMSUB132SD: case X86_INS_VFNMSUB213SD: case X86_INS_VFNMSUB231SD: {
                /* Fused multiply-add: dst = ±(m1*m2) ± addend. The 132/213/231 suffix
                 * selects which operands are the two multiplicands vs the addend:
                 *   132: dst = dst*src2 + src1     213: dst = src1*dst + src2
                 *   231: dst = src1*src2 + dst
                 * fnmadd negates the product; fmsub subtracts the addend; fnmsub both. */
                if (nop < 3) break;
                int w, variant; bool negp, subc;
                if (!fma_props(id, w, variant, negp, subc)) break;
                ExprP a = fp_src(OP(0), w), b1 = fp_src(OP(1), w), c = fp_src(OP(2), w);
                ExprP m1, m2, add;
                if (variant == 132)      { m1 = a;  m2 = c;  add = b1; }
                else if (variant == 213) { m1 = b1; m2 = a;  add = c;  }
                else                     { m1 = b1; m2 = c;  add = a;  }
                ExprP prod = mkBinary("*", m1, m2, w); prod->is_float = true;
                if (negp) { prod = mkUnary("-", prod, w); prod->is_float = true; }
                ExprP r = mkBinary(subc ? "-" : "+", prod, add, w); r->is_float = true;
                do_dst(b, OP(0), r, in.addr);
                break;
            }
            case X86_INS_CVTTSS2SI: case X86_INS_CVTTSD2SI:
            case X86_INS_CVTSS2SI: case X86_INS_CVTSD2SI: {
                /* float/double -> signed int (truncating). The SOURCE is FP: a mem
                 * operand must render `*(double*)`/`*(float*)` (not the raw qword/dword
                 * bit pattern) so `(long long)m->d` converts the VALUE. */
                if (nop < 2) break;
                int w = OP(0).size ? OP(0).size : 4;
                bool src_dbl = (id==X86_INS_CVTTSD2SI || id==X86_INS_CVTSD2SI);
                ExprP src = rvalue(OP(1));
                if (src) {
                    src->is_float = true;
                    if (src->kind == EK::Mem) src->width = src_dbl ? 8 : 4;
                }
                do_dst(b, OP(0), mkCast(cast_str(w, false), src, w, false), in.addr);
                break;
            }
            /* packed float -> int32. The INVERSE (CVTDQ2PS, just below) was modeled but
             * this direction never was — and since the `default:` intrinsic fallback only
             * rescues a GPR destination, an XMM destination received NO def at all. The
             * register then rendered as the phantom `in_XMM<n>` live-in, which a surviving
             * `movdqu [rdx],xmm` store wrote to memory: compile-clean, plausible C holding
             * an entry-value phantom in place of the converted data (windowscodecs.dll's
             * pixel loop). Lane-wise, because a scalar-only model would silently drop
             * lanes 1..3 of a genuinely vectorized convert.
             * Rounding differs and is NOT interchangeable: CVTTPS2DQ truncates (exactly
             * C's `(int)`), while CVTPS2DQ rounds per MXCSR — nearest-even by default,
             * which is what nearbyintf() means. */
            case X86_INS_CVTTPS2DQ: case X86_INS_CVTPS2DQ: {
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                if (!is_xmm(dr)) break;
                ExprP f[4];
                if (!xmm_f_lanes(OP(1), f)) break;
                ExprP r[4];
                for (int i = 0; i < 4; ++i) {
                    ExprP v = f[i];
                    if (id == X86_INS_CVTPS2DQ) {
                        auto nb = new_expr();
                        nb->kind = EK::Call; nb->callee = "nearbyintf"; nb->width = 4;
                        nb->ret_kind = 1; nb->is_float = true;
                        nb->args.push_back(v);
                        v = nb;
                        used_nearbyint = true;
                    }
                    r[i] = mkCast("(int)", v, 4, false);
                }
                set_xmm_i4(dr, r[0], r[1], r[2], r[3], b);
                break;
            }
            case X86_INS_CVTDQ2PS: case X86_INS_CVTDQ2PD: {
                /* packed int32 -> float/double. Modeled as an explicit float cast
                 * of the (scalar) source. This completes the truncate idiom
                 * `cvttss2si; movd xmm,eax; cvtdq2ps` so a float-returning function
                 * renders `(float)(int)x` — clearly a deliberate float-valued
                 * truncation, not a stray `(int)` in a float return. */
                if (nop < 2) break;
                int w = (id==X86_INS_CVTDQ2PD) ? 8 : 4;
                ExprP c = mkCast(w >= 8 ? "(double)" : "(float)", rvalue(OP(1)), w, false);
                c->is_float = true;
                do_dst(b, OP(0), c, in.addr);
                break;
            }
            case X86_INS_XORPS: case X86_INS_XORPD: case X86_INS_PXOR:
                /* `xorps/xorpd/pxor x,x` zeroes an xmm — but xorps is ALSO the
                 * shortest encoding the compiler uses to zero an INTEGER SIMD
                 * accumulator (paddq/paddd reductions: popcount, integer dot/saxpy).
                 * Marking the zero `is_float` then mis-types the whole integer
                 * reduction `float` (0.0f seed -> float temps -> `double*` result).
                 * Leave it a plain integer 0: a GENUINE float accumulator re-acquires
                 * float-ness from its actual scalar-FP def (addss/mulss via as_float),
                 * so float code is unaffected while integer reductions stay integer. */
                if (nop >= 2 && OP(0).type==X86_OP_REG && OP(1).type==X86_OP_REG &&
                    OP(0).reg == OP(1).reg) {
                    ExprP z = mkConst(0, (id==X86_INS_XORPD) ? 8 : 4);
                    do_dst(b, OP(0), z, in.addr);
                    /* zero lane 1 too so a 2x64 packed accumulator (`xorps acc,acc;
                     * paddq acc,x` int64-sum reduction) has BOTH lanes tracked. */
                    Reg zr; int zw; map_reg(OP(0).reg, zr, zw);
                    if (is_xmm(zr)) {
                        regfile_hi[zr] = mkConst(0, 8);
                        /* zero all four 32-bit lanes too so a 4x32 packed accumulator
                         * (`xorps acc,acc; paddd acc,x` int-sum reduction, isum) has
                         * every lane tracked from the seed. real=false: ambiguous until
                         * a paddd reads them (a genuine float acc re-acquires float-ness
                         * from its scalar-FP def, and never reads these int lanes). */
                        ExprP zl[4] = { mkConst(0,4), mkConst(0,4), mkConst(0,4), mkConst(0,4) };
                        populate_xmm_i(zr, zl);
                    }
                    /* a zeroed wide reg that is later stored is a memset(dst,0,n). */
                    { Reg vf = vec_reg(OP(0).reg); if (vf != R_NONE) vec_fill[vf] = { mkConst(0, 1), 1 }; }
                    break;
                }
                /* `xorps/xorpd xmm, [sign-mask const]` is the scalar FP NEGATE
                 * idiom (`-x`, flipping just the sign bit); wrapped in an
                 * `if (x<0)` it forms fabs. Unmodeled, the negate was silently
                 * DROPPED -> gauss_solve picked the wrong pivot and vec_norms summed
                 * signed values. Recognize the .rdata mask and emit `-x`. */
                if (id != X86_INS_PXOR && nop >= 2 && OP(0).type==X86_OP_REG) {
                    /* Read the sign-mask lanes from EITHER a rip-relative memory
                     * operand OR a register holding the mask (loaded earlier via
                     * `movss xmm1,[mask]; xorps xmm0,xmm1` — the register-mask negate
                     * that arr_abs's scalar-unrolled `a[i]=-a[i]` uses). Mirrors the
                     * andps abs handler; without the register form the negate — and
                     * thus the store of `a[i]=a[i]` — was DSE'd away. */
                    uint32_t lo = 0, hi = 0; bool have = false;
                    if (OP(1).type==X86_OP_MEM && OP(1).mem.base == X86_REG_RIP &&
                        OP(1).mem.index == X86_REG_INVALID) {
                        uint64_t addr = cur_insn_addr + cur_insn_size + (uint64_t)OP(1).mem.disp;
                        int32_t l2, h2;
                        if (read_i32(addr, l2) && read_i32(addr + 4, h2)) { lo=(uint32_t)l2; hi=(uint32_t)h2; have=true; }
                    } else if (OP(1).type == X86_OP_REG) {
                        ExprP mv = rvalue(OP(1));
                        if (mv && mv->kind == EK::Const) {
                            /* a movss-loaded 4-byte mask is sign-extended to 64-bit
                             * (0x80000000 -> 0xffffffff80000000); only `lo` is real
                             * for a width-4 const, so force hi=0 there. */
                            lo = (uint32_t)(uint64_t)mv->cval;
                            hi = (mv->width >= 8) ? (uint32_t)((uint64_t)mv->cval >> 32) : 0u;
                            have = true;
                        } else if (mv && mv->kind == EK::Mem && mv->a && mv->a->kind == EK::Const) {
                            uint64_t a = (uint64_t)mv->a->cval; int32_t l2, h2;
                            if (read_i32(a, l2) && read_i32(a + 4, h2)) { lo=(uint32_t)l2; hi=(uint32_t)h2; have=true; }
                        }
                    }
                    if (have) {
                        /* xorps is used for BOTH single and double negate (it is a
                         * bitwise sign flip). single mask = {0x80000000,0}; double
                         * mask = {0,0x80000000} (sign bit 63 lands in the high
                         * dword of the low qword). Infer the width from which. */
                        int negw = 0;
                        if (lo == 0x80000000u && hi == 0) negw = 4;
                        else if (lo == 0 && hi == 0x80000000u) negw = 8;
                        else if (lo == 0x80000000u && hi == 0x80000000u)
                            negw = (id == X86_INS_XORPD) ? 8 : 4;
                        if (negw) {
                            ExprP r = mkUnary("-", rvalue(OP(0)), negw);
                            r->is_float = true;
                            do_dst(b, OP(0), r, in.addr);
                        }
                    }
                }
                break;
            case X86_INS_ANDPS: case X86_INS_ANDPD: {
                /* `andps/andpd xmm, [abs-mask]` clears the FP sign bit(s) = absolute
                 * value (`fabs`). single mask lane = 0x7fffffff, double lane =
                 * 0x7fffffffffffffff ({0xffffffff,0x7fffffff}). The mask is often
                 * loaded into a register first (`movdqa xmm0,[m]; andps x,xmm0`), so we
                 * read it from BOTH a rip-relative memory operand AND a register whose
                 * tracked value is the folded mask const / .rdata Mem. Unmodeled, the
                 * abs was dropped, changing range-check semantics (fun_000057d0). */
                if (nop < 2 || OP(0).type != X86_OP_REG) break;
                uint32_t lo = 0, hi = 0; bool have = false;
                if (OP(1).type == X86_OP_MEM && OP(1).mem.base == X86_REG_RIP &&
                    OP(1).mem.index == X86_REG_INVALID) {
                    uint64_t a = cur_insn_addr + cur_insn_size + (uint64_t)OP(1).mem.disp;
                    int32_t l2, h2;
                    if (read_i32(a, l2) && read_i32(a + 4, h2)) { lo=(uint32_t)l2; hi=(uint32_t)h2; have=true; }
                } else if (OP(1).type == X86_OP_REG) {
                    ExprP mv = rvalue(OP(1));
                    if (mv && mv->kind == EK::Const) {
                        /* width-4 mask const is sign-extended; only lo is real. */
                        lo = (uint32_t)(uint64_t)mv->cval;
                        hi = (mv->width >= 8) ? (uint32_t)((uint64_t)mv->cval >> 32) : 0u;
                        have = true;
                    } else if (mv && mv->kind == EK::Mem && mv->a && mv->a->kind == EK::Const) {
                        uint64_t a = (uint64_t)mv->a->cval; int32_t l2, h2;
                        if (read_i32(a, l2) && read_i32(a + 4, h2)) { lo=(uint32_t)l2; hi=(uint32_t)h2; have=true; }
                    }
                }
                int absw = 0;
                if (have) {
                    if (lo==0x7fffffffu && hi==0) absw = 4;
                    else if (lo==0xffffffffu && hi==0x7fffffffu) absw = 8;
                    else if (lo==0x7fffffffu && hi==0x7fffffffu) absw = (id==X86_INS_ANDPD) ? 8 : 4;
                }
                if (absw) {
                    ExprP src = rvalue(OP(0));
                    auto call = new_expr();
                    call->kind = EK::Call; call->callee = (absw >= 8) ? "__fabs" : "__fabsf";
                    call->width = absw; call->is_float = true;
                    if (src) call->args.push_back(src);
                    used_fabs = true;
                    do_dst(b, OP(0), call, in.addr);
                }
                break;
            }
            case X86_INS_CMP:
                if (nop >= 2) set_flags_cmp(x);
                break;
            case X86_INS_TEST:
                if (nop >= 2) set_flags_test(x);
                break;
            /* PTEST/VPTEST set ZF = ((a & b) == 0) and CF = ((~a & b) == 0). The overwhelming
             * use is `ptest x,x; jz/jnz` = "is the whole 128-bit value zero", and unmodeled it
             * left `flags` holding an EARLIER compare so the branch read a stale condition. Model
             * the ZF as a test of the two operands' low 64 bits (the scalar view the rest of the
             * engine carries), which is exact for the `x,x` all-zero test and the common
             * mask-nonzero test. Keeps this out of the stale-flag class. */
            case X86_INS_PTEST: case X86_INS_VPTEST: {
                if (nop < 2) break;
                /* Only the 128-bit form is modelable: a 256-bit vptest reads a ymm the engine
                 * cannot represent, and forcing its low half would surface an undeclared
                 * in_YMM placeholder (C2065 on fn_0005f200). For any non-xmm operand, INVALIDATE
                 * the flags so the following jcc renders a disclosed unknown rather than a stale,
                 * unrelated compare -- honest, not a lie, and never a compile break. */
                auto lo = [&](const cs_x86_op& op, bool& ok) -> ExprP {
                    ok = false;
                    if (op.type == X86_OP_REG) {
                        Reg r; int w; map_reg(op.reg, r, w);
                        if (!is_xmm(r)) return nullptr;      /* ymm/zmm -> unrepresentable */
                        ok = true; return xmm_lo(r);
                    }
                    if (op.type == X86_OP_MEM) { ok = true; return rvalue(op); }
                    return nullptr;
                };
                bool oka = false, okb = false;
                ExprP a = lo(OP(0), oka), bb = lo(OP(1), okb);
                if (!oka || !okb || !a || !bb) { flags = FlagSrc(); break; }  /* invalidate, don't lie */
                flags = FlagSrc();
                flags.valid = true; flags.is_test = true;
                flags.a = a; flags.b = exprEqual(a, bb) ? clone(a) : bb; flags.width = 8;
                break;
            }
            case X86_INS_CALL:
                lift_call(b, in);
                break;
            case X86_INS_XCHG: {
                /* xchg dst, src atomically SWAPS the two operands: tmp=dst; dst=src;
                 * src=tmp. When dst is memory this is the lock-release/lock-acquire
                 * idiom (`xor eax,eax; xchg [lock],eax` stores 0 to release). With no
                 * handler the whole instruction fell through and the STORE to memory
                 * was DROPPED — the recompiled code never released the lock
                 * (fun_0005bf90/c400/c680/c710/c8a0). Read BOTH operands before either
                 * write (they swap). The memory store is a real side effect; the
                 * register half is usually a dead load the DSE removes. */
                if (nop < 2) break;
                int w0 = OP(0).size ? OP(0).size : 4;
                ExprP d_old = rvalue(OP(0));
                ExprP s_old = rvalue(OP(1));
                /* freeze a memory dst's old value so the register half sees the
                 * PRE-swap value, not the just-stored one (the mem expr re-reads). */
                if (OP(0).type == X86_OP_MEM) d_old = snapshot_to_temp(b, d_old, w0, in.addr);
                do_dst(b, OP(0), s_old, in.addr);   /* dst = old src (the store) */
                do_dst(b, OP(1), d_old, in.addr);   /* src = old dst */
                break;
            }
            case X86_INS_XADD: {
                /* lock xadd dst, src atomically: tmp = dst; dst = dst + src; src =
                 * tmp — InterlockedExchangeAdd. The src REGISTER receives the OLD
                 * dst value; dst gets the sum. With no handler the whole insn fell
                 * through: the memory ADD was DROPPED and src kept its input, so
                 * `mov eax,1; lock xadd [ctr],eax; inc eax; mov [obj+0x10],eax`
                 * folded to the constant 2 and never incremented the shared counter
                 * (profapi fun_000098d4: the per-object sequence id). */
                if (nop < 2) break;
                int w0 = OP(0).size ? OP(0).size : 4;
                ExprP d_old = rvalue(OP(0));      /* old dst value */
                ExprP s_old = rvalue(OP(1));      /* addend (src register) */
                /* `lock xadd [m], r` IS _InterlockedExchangeAdd: it returns the OLD value
                 * and performs the store itself, so one call replaces the load/store pair
                 * and states the atomicity the pair cannot. Only the locked MEMORY form —
                 * an unlocked or register-dst xadd is not the intrinsic and falls through.
                 * DS_NO_INTERLOCKED. */
                if (has_lock(x) && OP(0).type == X86_OP_MEM && (w0 == 4 || w0 == 8) &&
                    !std::getenv("DS_NO_INTERLOCKED")) {
                    auto call = new_expr();
                    call->kind = EK::Call;
                    call->callee = (w0 == 8) ? "_InterlockedExchangeAdd64"
                                             : "_InterlockedExchangeAdd";
                    call->width = w0;
                    call->ret_kind = (w0 == 8) ? 2 : 1;
                    call->args.push_back(mkCast(w0 == 8 ? "(volatile long long*)"
                                                        : "(volatile long*)",
                                                addr_of_mem(OP(0)), 8, true));
                    call->args.push_back(clone(s_old));
                    used_interlocked.insert(call->callee);
                    /* Bind the result to a temp FIRST: the call must be emitted exactly
                     * once (it has the side effect), so neither the register nor the flag
                     * expression may hold a second copy of it. */
                    ExprP oldv = snapshot_to_temp(b, call, w0, in.addr);
                    do_dst(b, OP(1), oldv, in.addr);         /* src reg = OLD dst */
                    /* xadd sets ZF/SF/CF from the SUM. The intrinsic yields the old value,
                     * so rebuild the sum from the temp — dropping this would leave the
                     * flags holding an earlier, unrelated compare and the next jcc would
                     * render a confidently WRONG condition. */
                    set_flags_arith(mkBinary("+", clone(oldv), clone(s_old), w0), w0);
                    break;
                }
                /* freeze the old dst so the src half sees the PRE-add value, not the
                 * just-stored sum (a mem dst expr would otherwise re-read it). */
                if (OP(0).type == X86_OP_MEM) d_old = snapshot_to_temp(b, d_old, w0, in.addr);
                ExprP sum = mkBinary("+", clone(d_old), s_old, w0);
                do_dst(b, OP(0), sum, in.addr);   /* dst = old dst + src (the store) */
                do_dst(b, OP(1), d_old, in.addr); /* src = old dst */
                set_flags_arith(clone(sum), w0);  /* xadd sets ZF/SF/CF from the sum */
                break;
            }
            case X86_INS_CMPXCHG: {
                /* lock cmpxchg dst, src: compares the accumulator (al/ax/eax/rax)
                 * with dst and sets ZF = (acc == dst); if equal dst=src, else
                 * acc=dst. The following je/jne tests CAS success. Model the FLAG
                 * as cmp(acc, dst) so the spin-lock renders the REAL condition
                 * (`if (0 == *(int*)0x174200)`) instead of the stale `if (0 == 0)`
                 * left over from a preceding `xor eax,eax` (the atomics gap).
                 * AFTER cmpxchg, rax = dst ALWAYS (on failure acc<-dst; on success
                 * acc==dst so acc IS dst) — so set rax to the dst VALUE, not a
                 * backstop: a spin-loop's `cmp rcx,rax; jne` re-reads the current
                 * memory value, not `in_RAX` (fun_0005d828). */
                if (nop >= 2) {
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP av = reg_value(R_RAX, w);
                    /* freeze the accumulator too when it is ITSELF a live memory read:
                     * a CAS whose expected value came from `mov eax,[p]` on the SAME
                     * cell (`cas_add`: do{old=*p;new=old+d;}while(cmpxchg(p,new,old)!=old)).
                     * Otherwise the post-store flag `av == dv` re-reads the now-updated
                     * *p, so `new == old` is false for any nonzero delta and the retry
                     * `jne` loop NEVER exits (infinite spin). */
                    if (reads_mem(av)) av = snapshot_to_temp(b, av, w, in.addr);
                    ExprP dv = rvalue(OP(0));      /* old dst (memory) value */
                    /* freeze old dst so the CAS ternary, the ZF flag, AND rax all see
                     * the pre-store value (else the flag re-reads the stored value and
                     * inverts the acquire/release test — fun_0005bf90 spin lock). */
                    if (OP(0).type == X86_OP_MEM) dv = snapshot_to_temp(b, dv, w, in.addr);
                    ExprP sv = rvalue(OP(1));      /* desired (src) */
                    /* CAS STORE: if (acc == dst) dst = src; else dst is unchanged.
                     * The old handler modeled only the FLAG and left rax = dst, but
                     * DROPPED the store — so a lock acquire (`lock cmpxchg [lock],
                     * tid`) or an atomic bit-set (`bts;lock cmpxchg`) never wrote back
                     * (fun_0005d828 spin-lock, fun_00076164). A ternary store is
                     * behavior-faithful under the single-threaded oracle and captures
                     * the write. do_dst handles both a memory and a register dst. */
                    ExprP casv = mkTernary(mkBinary("==", clone(av), clone(dv), w),
                                           sv, clone(dv), w);
                    do_dst(b, OP(0), casv, in.addr);
                    flags = FlagSrc();
                    flags.valid = true; flags.is_cmp = true;
                    flags.a = av; flags.b = clone(dv); flags.width = w;
                    regfile[R_RAX] = dv;           /* cmpxchg leaves acc = old dst */
                }
                break;
            }
            case X86_INS_CPUID: {
                /* CPUID(leaf in eax, subleaf in ecx) writes the 4 result registers.
                 * Model each as a `__cpuid_e{a,b,c,d}x(leaf, subleaf)` intrinsic so
                 * the CPU-feature/vendor-string reads render `__cpuid_ebx(0,0) ^
                 * 0x756e6547` ("Genu") instead of leaking `in_RBX` (fun_0005de58,
                 * the __isa_available dispatcher). Each intrinsic is a well-defined
                 * pure function of (leaf,subleaf), so this is faithful, not a guess. */
                ExprP leaf = reg_value(R_RAX, 4);
                ExprP sub  = reg_value(R_RCX, 4);
                auto mk = [&](const char* fn)->ExprP {
                    auto c = new_expr();
                    c->kind = EK::Call; c->callee = fn; c->width = 4; c->ret_kind = 1;
                    c->args.push_back(clone(leaf)); c->args.push_back(clone(sub));
                    return c;
                };
                used_cpuid = true;
                regfile[R_RAX] = mk("__cpuid_eax"); regfile[R_RBX] = mk("__cpuid_ebx");
                regfile[R_RCX] = mk("__cpuid_ecx"); regfile[R_RDX] = mk("__cpuid_edx");
                break;
            }
            case X86_INS_STMXCSR: case X86_INS_VSTMXCSR: {
                /* store MXCSR -> m32. Model as `*(unsigned*)m = __readmxcsr();` so the
                 * destination slot is DEFINED with the real control word (a later
                 * read-modify-write of it is meaningful, not a stale backstop). */
                if (nop < 1) break;
                auto call = new_expr();
                call->kind = EK::Call; call->callee = "__readmxcsr";
                call->width = 4; call->ret_kind = 1;
                used_mxcsr = true;
                do_dst(b, OP(0), call, in.addr);
                break;
            }
            case X86_INS_LDMXCSR: case X86_INS_VLDMXCSR: {
                /* load MXCSR <- m32. A genuine SIDE EFFECT that CONSUMES m32: emit
                 * `__writemxcsr(*(unsigned*)m);` as a call statement. Without a live
                 * consumer the whole control-word construction (the bt/jcc field
                 * selects feeding it) is dead-store-eliminated, leaving empty `{}`
                 * branch bodies (fun_000828f0). The read keeps that dataflow live. */
                if (nop < 1) break;
                ExprP arg = rvalue(OP(0));
                auto call = new_expr();
                call->kind = EK::Call; call->callee = "__writemxcsr";
                call->width = 0; call->ret_kind = 5; /* void */
                used_mxcsr = true;
                if (arg) call->args.push_back(arg);
                Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
                b.stmts.push_back(std::move(s));
                break;
            }
            /* ================= x87 (the 32-bit float unit) =================
             * See the fpu[] stack model for why this matters: unmodeled, a /arch:IA32
             * float function decompiled to an empty `void f(void) { return; }`. */
            case X86_INS_FLD: case X86_INS_FILD: {
                if (nop < 1) break;
                if (OP(0).type == X86_OP_MEM) {
                    int sz = OP(0).size ? OP(0).size : (id == X86_INS_FILD ? 4 : 8);
                    if (id == X86_INS_FILD) {
                        /* integer load: x87 CONVERTS to its internal float format */
                        ExprP c = mkCast("(double)", rvalue(OP(0)), 8);
                        c->is_float = true;
                        fpu_push(c);
                    } else {
                        fpu_push(as_float(rvalue(OP(0)), sz == 4 ? 4 : 8));
                    }
                } else {
                    int i = st_index(OP(0).reg);
                    if (i >= 0) fpu_push(fpu_get(i));
                }
                break;
            }
            case X86_INS_FLD1:  fpu_push(fpu_const(1.0)); break;
            case X86_INS_FLDZ:  fpu_push(fpu_const(0.0)); break;
            case X86_INS_FST: case X86_INS_FSTP: {
                if (nop < 1) break;
                ExprP v = fpu_get(0);
                if (OP(0).type == X86_OP_MEM) {
                    int sz = OP(0).size ? OP(0).size : 8;
                    do_dst(b, OP(0), fpu_round(v, sz), in.addr);
                } else {
                    int i = st_index(OP(0).reg);
                    if (i >= 0) fpu_slot(i) = v;
                }
                if (id == X86_INS_FSTP) fpu_pop();
                break;
            }
            case X86_INS_FIST: case X86_INS_FISTP: {
                if (nop < 1) break;
                ExprP v = fpu_get(0);
                if (OP(0).type == X86_OP_MEM) {
                    /* The int store rounds per the FPU control word; MSVC sets
                     * truncate-toward-zero around a C cast, which is what `(int)` means. */
                    int sz = OP(0).size ? OP(0).size : 4;
                    do_dst(b, OP(0), mkCast(cast_str(sz, false), v, sz, false), in.addr);
                }
                if (id == X86_INS_FISTP) fpu_pop();
                break;
            }
            /* Arithmetic. OP(0) is always the destination and OP(1) the source; the R
             * (reversed) forms compute src OP dst, which matters only for `-` and `/`.
             *
             * The POP is decided by the opcode byte, not the id: capstone has NO
             * X86_INS_FADDP — its table maps X86_ADD_FPrST0 (the popping `faddp`) to
             * plain X86_INS_FADD, unlike FSUBP/FMULP/FDIVP which do get their own ids.
             * Every popping register form is encoded DE, so that byte is the reliable
             * discriminator (and agrees with the ids that do exist).
             *
             * The D8-vs-DC encodings swap FSUB/FSUBR (and FDIV/FDIVR), but capstone
             * decodes that quirk and reports the correct id, so keying off the id is
             * right. Memory forms never pop. */
            case X86_INS_FADD:  case X86_INS_FSUB: case X86_INS_FSUBR:
            case X86_INS_FMUL:  case X86_INS_FDIV: case X86_INS_FDIVR:
            case X86_INS_FSUBP: case X86_INS_FSUBRP:
            case X86_INS_FMULP: case X86_INS_FDIVP: case X86_INS_FDIVRP: {
                bool isadd = (id == X86_INS_FADD);
                bool ismul = (id == X86_INS_FMUL || id == X86_INS_FMULP);
                bool issub = (id == X86_INS_FSUB || id == X86_INS_FSUBR ||
                              id == X86_INS_FSUBP || id == X86_INS_FSUBRP);
                const char* fop = isadd ? "+" : ismul ? "*" : issub ? "-" : "/";
                bool rev = (id == X86_INS_FSUBR || id == X86_INS_FSUBRP ||
                            id == X86_INS_FDIVR || id == X86_INS_FDIVRP);
                if (nop >= 1 && OP(0).type == X86_OP_MEM) {   /* ST(0) OP= mem */
                    int sz = OP(0).size ? OP(0).size : 8;
                    ExprP m = as_float(rvalue(OP(0)), sz == 4 ? 4 : 8);
                    ExprP a = fpu_get(0);
                    ExprP r = rev ? mkBinary(fop, m, a, 8) : mkBinary(fop, a, m, 8);
                    r->is_float = true;
                    fpu_slot(0) = r;
                    break;
                }
                int di = -1, si = -1;
                if (nop >= 2) { di = st_index(OP(0).reg); si = st_index(OP(1).reg); }
                else if (nop == 1) { di = 0; si = st_index(OP(0).reg); }  /* `fadd st(i)` */
                if (di < 0 || si < 0) break;
                ExprP a = fpu_get(di), s = fpu_get(si);
                ExprP r = rev ? mkBinary(fop, s, a, 8) : mkBinary(fop, a, s, 8);
                r->is_float = true;
                fpu_slot(di) = r;          /* index is relative to the CURRENT top */
                if (x.opcode[0] == 0xDE) fpu_pop();
                break;
            }
            case X86_INS_FCHS: {
                ExprP r = mkUnary("-", fpu_get(0), 8); r->is_float = true;
                fpu_slot(0) = r; break;
            }
            case X86_INS_FABS: {
                auto c = new_expr();
                c->kind = EK::Call; c->callee = "fabs"; c->width = 8;
                c->ret_kind = 1; c->is_float = true;
                c->args.push_back(fpu_get(0));
                fpu_slot(0) = c; break;
            }
            case X86_INS_FSQRT: {
                auto c = new_expr();
                c->kind = EK::Call; c->callee = "sqrt"; c->width = 8;
                c->ret_kind = 1; c->is_float = true;
                c->args.push_back(fpu_get(0));
                fpu_slot(0) = c; break;
            }
            case X86_INS_FXCH: {
                int i = 1;
                if (nop >= 1 && OP(0).type == X86_OP_REG) { int t = st_index(OP(0).reg); if (t >= 0) i = t; }
                ExprP t0 = fpu_slot(0); fpu_slot(0) = fpu_slot(i); fpu_slot(i) = t0;
                break;
            }
            /* The modern compares write EFLAGS directly, exactly like comiss — so they
             * reuse the existing float-compare flag model and every jcc downstream just
             * works. (The legacy FCOM + `fnstsw ax` idiom routes through the status
             * word and is not modeled here.) */
            case X86_INS_FUCOMI: case X86_INS_FUCOMPI:
            case X86_INS_FCOMI:  case X86_INS_FCOMPI: {
                /* capstone spells the popping forms FCOMPI/FUCOMPI (not FCOMIP/FUCOMIP) */
                int i = 1;
                for (int k = nop - 1; k >= 0; --k)
                    if (OP(k).type == X86_OP_REG) { int t = st_index(OP(k).reg); if (t > 0) { i = t; break; } }
                flags = FlagSrc();
                flags.valid = true; flags.is_fcmp = true;
                flags.a = fpu_get(0); flags.b = fpu_get(i); flags.width = 8;
                if (id == X86_INS_FUCOMPI || id == X86_INS_FCOMPI) fpu_pop();
                break;
            }
            /* The LEGACY compare. Unlike FCOMI it does NOT touch EFLAGS — it writes the
             * C0/C2/C3 condition bits of the FPU STATUS WORD, which the compiler then
             * reads back with `fnstsw ax` and tests with `test ah, imm`. Record the
             * operands; FNSTSW below materialises the status word from them. */
            case X86_INS_FCOM:  case X86_INS_FCOMP:  case X86_INS_FCOMPP:
            case X86_INS_FUCOM: case X86_INS_FUCOMP: case X86_INS_FUCOMPP: {
                ExprP ca = fpu_get(0), cb;
                if (nop >= 1 && OP(0).type == X86_OP_MEM) {
                    int sz = OP(0).size ? OP(0).size : 8;
                    cb = as_float(rvalue(OP(0)), sz == 4 ? 4 : 8);
                } else {
                    int i = 1;
                    if (nop >= 1 && OP(0).type == X86_OP_REG) {
                        int t = st_index(OP(0).reg); if (t >= 0) i = t;
                    }
                    cb = fpu_get(i);
                }
                fcom_a = ca; fcom_b = cb;
                if (id == X86_INS_FCOMP || id == X86_INS_FUCOMP) fpu_pop();
                else if (id == X86_INS_FCOMPP || id == X86_INS_FUCOMPP) { fpu_pop(); fpu_pop(); }
                break;
            }
            case X86_INS_FNSTSW: {
                /* Materialise the status word from the pending compare:
                 *   C0 (bit 8)  = a < b      C3 (bit 14) = a == b
                 * which the compiler tests as `test ah, 0x41` (C0|C3 => a <= b) or
                 * `test ah, 5` (C0|C2 => a < b or unordered). C2 (unordered/NaN) is
                 * modeled as 0 — the ordered reading, correct for non-NaN operands. */
                if (!fcom_a || !fcom_b) break;
                ExprP lt = mkBinary("<",  clone(fcom_a), clone(fcom_b), 4);
                ExprP eq = mkBinary("==", clone(fcom_a), clone(fcom_b), 4);
                ExprP sw = mkBinary("|",
                    mkTernary(lt, mkConst(0x100, 4),  mkConst(0, 4), 4),
                    mkTernary(eq, mkConst(0x4000, 4), mkConst(0, 4), 4), 4);
                if (nop >= 1 && OP(0).type == X86_OP_MEM) do_dst(b, OP(0), sw, in.addr);
                else set_reg(R_RAX, 2, sw, b);
                break;
            }
            case X86_INS_FLDCW: case X86_INS_FNSTCW: break;  /* rounding control: no value effect */
            /* RDTSC/RDTSCP read the 64-bit timestamp counter into EDX:EAX; XGETBV reads
             * the extended control register selected by ECX into EDX:EAX. None has an
             * explicit destination operand, so the `default:` fallback — which requires a
             * written REGISTER operand — never fired and BOTH halves were dropped: the
             * AVX-support check `xgetbv; and eax,6; cmp eax,6` tested an entry-value
             * phantom, and every timing/seed value read as a live-in. Snapshot the result
             * to a temp so the two halves come from ONE read, not two separate calls. */
            case X86_INS_RDTSC: case X86_INS_RDTSCP: case X86_INS_XGETBV: {
                bool xg = (id == X86_INS_XGETBV);
                auto call = new_expr();
                call->kind = EK::Call; call->callee = xg ? "_xgetbv" : "__rdtsc";
                call->width = 8; call->ret_kind = 2; call->is_unsigned = true;
                if (xg) call->args.push_back(mkCast("(unsigned int)", reg_value(R_RCX, 4), 4, true));
                ExprP t = snapshot_to_temp(b, call, 8, in.addr);
                set_reg(R_RAX, 4, mkCast("(unsigned int)", clone(t), 4, true), b);
                set_reg(R_RDX, 4, mkCast("(unsigned int)",
                        mkBinary(">>", clone(t), mkConst(32, 8, true), 8, true), 4, true), b);
                if (xg) used_xgetbv = true; else used_rdtsc = true;
                break;
            }
            /* The kernel transition. It returns its status in RAX (and clobbers RCX/R11),
             * but has NO explicit operands — so the `default:` fallback, which requires a
             * written REGISTER operand, never fired and the RAX definition was DROPPED.
             * An ntdll stub is literally `mov eax,<n>; syscall; ret`, so without this the
             * function "returns" the syscall NUMBER instead of the syscall's result: a
             * compile-clean, entirely plausible, wrong value. The number in eax IS the
             * selector, so keep it as the argument. */
            case X86_INS_SYSCALL: case X86_INS_SYSENTER: {
                auto call = new_expr();
                call->kind = EK::Call; call->callee = "__syscall";
                call->width = 8; call->ret_kind = 2; call->is_unsigned = true;
                call->args.push_back(mkCast("(unsigned int)", reg_value(R_RAX, 4), 4, true));
                set_reg(R_RAX, 8, call, b);
                used_syscall = true;
                break;
            }
            case X86_INS_FFREE: break;                    /* tag-word only: no value effect */
            case X86_INS_FINCSTP: fpu_top = (fpu_top + 1) & 7; break;
            case X86_INS_FDECSTP: fpu_top = (fpu_top + 7) & 7; break;
            /* rep movs -> inlined memcpy. MOVSD is NOT here: capstone spells the SSE
             * `movsd xmm` with the same id, so the string form is split out inside that
             * case (two MEM operands / no operands can only be the string op). */
            case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSQ: {
                bool has_rep = false;
                for (int pi = 0; pi < 4; ++pi)
                    if (x.prefix[pi] == X86_PREFIX_REP) { has_rep = true; break; }
                emit_string_move(b, in, (id==X86_INS_MOVSB)?1:(id==X86_INS_MOVSW)?2:8, has_rep);
                break;
            }
            case X86_INS_STOSB: case X86_INS_STOSW:
            case X86_INS_STOSD: case X86_INS_STOSQ: {
                /* `rep stos` fills rcx elements at [rdi] with al/ax/eax/rax. Unmodeled,
                 * the whole memory fill was silently DROPPED (fun_0000dc70's
                 * `rep stosw 0xffff` init of 0x9b words). Model as the MSVC __stos*
                 * intrinsic (a real side-effecting call), then advance rdi and zero
                 * rcx as the rep does. A bare (non-rep) stos stores one element. */
                int sz = (id==X86_INS_STOSB)?1:(id==X86_INS_STOSW)?2:(id==X86_INS_STOSD)?4:8;
                bool has_rep = false;
                for (int pi = 0; pi < 4; ++pi)
                    if (x.prefix[pi] == X86_PREFIX_REP) { has_rep = true; break; }
                ExprP val = reg_value(R_RAX, sz);
                if (has_rep) {
                    ExprP dst = reg_value(R_RDI, 8);
                    ExprP cnt = reg_value(R_RCX, 8);
                    const char* fn = (sz==1)?"__stosb":(sz==2)?"__stosw":(sz==4)?"__stosd":"__stosq";
                    auto call = new_expr();
                    call->kind = EK::Call; call->callee = fn; call->width = 0; call->ret_kind = 5;
                    /* cast args to the emitted __stos* prototype so the call is not
                     * C4024/C4047 (dst is a `unsigned <T>*`, val `unsigned <T>`, cnt
                     * `unsigned long long`). */
                    const char* pt = (sz==1)?"(unsigned char*)":(sz==2)?"(unsigned short*)":
                                     (sz==4)?"(unsigned long*)":"(unsigned long long*)";
                    const char* vt = (sz==1)?"(unsigned char)":(sz==2)?"(unsigned short)":
                                     (sz==4)?"(unsigned long)":"(unsigned long long)";
                    if (dst) call->args.push_back(mkCast(pt, dst, 8, true));
                    if (val) call->args.push_back(mkCast(vt, val, sz, true));
                    if (cnt) call->args.push_back(mkCast("(unsigned long long)", cnt, 8, true));
                    Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
                    b.stmts.push_back(std::move(s));
                    used_stos = true;
                    regfile[R_RDI] = mkBinary("+", reg_value(R_RDI,8),
                                     mkBinary("*", reg_value(R_RCX,8), mkConst(sz,8), 8), 8);
                    regfile[R_RCX] = mkConst(0, 8);
                } else {
                    ExprP lv = mkMem(reg_value(R_RDI, 8), sz, false);
                    emit_store(b, lv, truncate(val, sz), in.addr);
                    regfile[R_RDI] = mkBinary("+", reg_value(R_RDI,8), mkConst(sz,8), 8);
                }
                break;
            }
            /* rep scas -> inlined strlen / memchr / compare. Safe as a direct case: unlike
             * MOVSD/CMPSD, capstone gives SCASD an id of its own (no SSE form collides),
             * so no operand-shape split is needed. Without this the op fell to `default:`,
             * whose opaque-intrinsic fallback needs a WRITTEN register operand — scas has
             * none (al and [rdi] are both read-only), so it was a total no-op. */
            case X86_INS_SCASB: case X86_INS_SCASW:
            case X86_INS_SCASD: case X86_INS_SCASQ: {
                static const bool off = std::getenv("DS_NO_SCAS") != nullptr;
                if (off) break;
                int sz = (id==X86_INS_SCASB)?1:(id==X86_INS_SCASW)?2:(id==X86_INS_SCASD)?4:8;
                emit_string_scan(b, in, sz, rep_kind(x));
                break;
            }
            /* rep cmps -> inlined memcmp. CMPSB/W/Q have capstone ids of their own (no SSE
             * form collides); CMPSD is deliberately NOT handled here because its id is shared
             * with SSE scalar `cmpsd`, and the byte form is the memcmp the compiler inlines.
             * Unmodeled, cmps fell to default:, whose opaque fallback needs a WRITTEN register
             * operand — cmps has none ([rsi] and [rdi] are both read-only) — so it was a no-op
             * that left the following jcc reading stale flags. */
            case X86_INS_CMPSB: case X86_INS_CMPSW: case X86_INS_CMPSQ: {
                static const bool off = std::getenv("DS_NO_CMPS") != nullptr;
                if (off) break;
                int sz = (id==X86_INS_CMPSB)?1:(id==X86_INS_CMPSW)?2:8;
                emit_string_cmp(b, in, sz, rep_kind(x));
                break;
            }
            default: {
                CC sc = setcc_of(id);
                if (sc != CC::NONE) {
                    if (nop < 1) break;
                    ExprP cond = cc_to_expr(sc, flags);
                    do_dst(b, OP(0), cond, in.addr);
                    break;
                }
                CC mc = cmovcc_of(id);
                if (mc != CC::NONE) {
                    if (nop < 2) break;
                    int w = OP(0).size ? OP(0).size : 4;
                    ExprP cond = cc_to_expr(mc, flags);
                    ExprP newv = rvalue(OP(1));
                    ExprP cur  = rvalue(OP(0));
                    ExprP tern = mkTernary(cond, newv, cur, w);
                    /* Bind a non-trivial cmov result to a temp so a dest register
                     * reused across later accesses (a cmov index threaded through a
                     * chain of array/struct derefs) re-reads the temp instead of
                     * re-inlining — and EXPONENTIALLY nesting — the ternary at every
                     * use (an 81x-cloned index -> a 5 KB line). copy_propagate folds
                     * it straight back when the result is used only once, so simple
                     * cmovs stay clean. */
                    if (node_count(tern) > 6 && OP(0).type == X86_OP_REG) {
                        std::string tn = "t" + std::to_string(++temp_seq);
                        var_width[tn] = w; if (w >= 8) var_is_ll[tn] = true;
                        Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, w);
                        s.rhs = tern; s.addr = in.addr;
                        b.stmts.push_back(std::move(s));
                        do_dst(b, OP(0), mkVar(tn, w), in.addr);
                    } else {
                        do_dst(b, OP(0), tern, in.addr);
                    }
                    break;
                }
                if (in.is_jcc || in.is_jmp || in.is_ret) break;
                /* WIDE (ymm/zmm) vector LOAD tracking — MUST run before the register-write
                 * opaque handler just below. map_reg returns R_NONE for a ymm/zmm dest, so
                 * that handler emits nothing for a wide load yet still `break`s, which would
                 * drop the load and leave vec_load_addr unset — so the matching store never
                 * finds a source and stays an opaque `__vmovdqu(dst)`. Recording the source
                 * address here (via vec_reg, which DOES map ymm/zmm) lets the store below
                 * turn the pair into a real chunked memcpy. DS_NO_VECCOPY. */
                if (nop >= 2 && !std::getenv("DS_NO_VECCOPY") &&
                    OP(0).type == X86_OP_REG && OP(1).type == X86_OP_MEM &&
                    (in.mnem.rfind("vmov", 0) == 0 || in.mnem.rfind("movnt", 0) == 0)) {
                    Reg dr = vec_reg(OP(0).reg);
                    ExprP sm = rvalue(OP(1));
                    if (dr != R_NONE && sm && sm->kind == EK::Mem && sm->a) {
                        vec_load_addr[dr] = clone(sm->a);
                        break;
                    }
                }
                /* An unmodeled op that WRITES a register still DEFINES it: leaving
                 * the dest undefined makes a later read fall back to the misleading
                 * entry-value placeholder `in_<REG>` (pmovmskb/tzcnt/lzcnt/... in
                 * SIMD/bit-twiddling code read a garbage "incoming" value). Represent
                 * the result as an opaque intrinsic of the mnemonic so the register
                 * is DEFINED and the op is documented, not silently dropped. Only for
                 * a single GPR destination; side-effect-free ops (fences, prefetch,
                 * with no reg dest) are still ignored. */
                if (nop >= 1 && OP(0).type == X86_OP_REG &&
                    (OP(0).access & CS_AC_WRITE) && !in.mnem.empty()) {
                    Reg dr; int dw; map_reg(OP(0).reg, dr, dw);
                    bool gpr = (dr >= R_RAX && dr <= R_R15);
                    /* An unmodeled op that writes an XMM destination is DROPPED today, not made
                     * opaque: the GPR fallback below is GPR-only, so every packed op the lane
                     * model does not cover (addpd, cvtpd2dq, pcmpeqw, punpcklbw, the SSE4.2
                     * string ops, ...) silently lost its result and any read of that xmm fell
                     * back to a stale/backstop value. A correct 4x32 lane model cannot express
                     * a 256-bit shuffle or an 8x16 word compare, so the honest floor is the
                     * same as the GPR case: DEFINE the dest with an opaque intrinsic of the
                     * mnemonic, carrying the sources, so the value dependency survives, nothing
                     * is dropped, and the confidence header discloses it. DS_NO_SIMDOPAQUE. */
                    bool xmm = is_xmm(dr) && !std::getenv("DS_NO_SIMDOPAQUE");
                    if (gpr || xmm) {
                        auto call = new_expr();
                        call->kind = EK::Call;
                        /* xmm packed op -> canonical Intel intrinsic name (Hex-Rays parity);
                         * GPR / unmapped ops keep the __mnem form. */
                        { const std::string& intr = xmm ? simd_intrinsic_name(in.mnem) : std::string();
                          call->callee = intr.empty() ? ("__" + sani(in.mnem)) : intr; }
                        int cw = gpr ? ((dw >= 8) ? 8 : 4) : 8;   /* xmm: carry as an 8-byte view */
                        call->width = cw; call->ret_kind = (cw >= 8) ? 2 : 1;
                        /* A floating-point BLEND/SELECT (blendvpd/blendvps and their VEX
                         * forms) returns one of its two source VALUES unchanged — a value
                         * select, not a bit shuffle. Typed `long long`, its opaque result
                         * forces a spurious int->double CONVERSION at every use: here the
                         * atan2 max/min lane select feeds `/` and `>`, so
                         * `__vblendvpd(...)/__vblendvpd(...) > 0.0625` decayed to INTEGER
                         * division. Type it by the operand domain the mnemonic encodes
                         * (pd/sd = double, ps/ss = float) so the float math is faithful. */
                        if (xmm && in.mnem.find("blendv") != std::string::npos && in.mnem.size() >= 2) {
                            const std::string& mn = in.mnem;
                            size_t sp = mn.size() - 2;
                            if (mn.compare(sp, 2, "pd") == 0 || mn.compare(sp, 2, "sd") == 0) {
                                call->width = 8; call->ret_kind = 4;   /* double */
                            } else if (mn.compare(sp, 2, "ps") == 0 || mn.compare(sp, 2, "ss") == 0) {
                                call->width = 4; call->ret_kind = 3;   /* float */
                            }
                        }
                        /* A read-modify-write dest (rol/ror/adc/sbb: OP(0) is BOTH
                         * source and destination) contributes its CURRENT value as
                         * the first arg — else `rol x,n` renders `x = __rol(n)`,
                         * DROPPING the rotated value `x` entirely (`__rol()` empty). */
                        int start = 1;
                        if (OP(0).access & CS_AC_READ) {
                            call->args.push_back(rvalue(OP(0)));
                            start = 1;   /* still add the other operands below */
                        }
                        for (int k = start; k < nop && k < 4; ++k)
                            if (OP(k).type == X86_OP_REG || OP(k).type == X86_OP_MEM ||
                                OP(k).type == X86_OP_IMM)
                                call->args.push_back(rvalue(OP(k)));
                        extern_callees[call->callee] = call->ret_kind;
                        opaque_ops[call->callee]++;   /* feeds the confidence header */
                        do_dst(b, OP(0), call, in.addr);
                    } else if (((OP(0).reg >= X86_REG_YMM0 && OP(0).reg <= X86_REG_YMM15) ||
                                (OP(0).reg >= X86_REG_ZMM0 && OP(0).reg <= X86_REG_ZMM31)) &&
                               !std::getenv("DS_NO_SIMDOPAQUE") && !std::getenv("DS_NO_AVXMODEL")) {
                        /* AVX2/AVX-512 register-write op. map_reg gives R_NONE for ymm/zmm so the
                         * xmm path above skipped it and the op was DROPPED, leaving the register
                         * read-before-write (an in_YMM / scrubbed local). DEFINE its value with
                         * the 256/512-bit Intel intrinsic (or the __mnem fallback) and stash it in
                         * vec_op_value keyed by the capstone reg id, so a later read (e.g. the
                         * vmovdqu store) picks it up: `_mm256_storeu_si256(dst, _mm256_add_epi32(
                         * a, b))` instead of a lost op. DS_NO_AVXMODEL disables. */
                        auto call = new_expr();
                        call->kind = EK::Call;
                        /* Deliberately use the __mnem extern, NOT the _mm256_/_mm512_ intrinsic
                         * name: MSVC builtin-recognizes many 256/512-bit intrinsics with strict
                         * arity, and our pipeline can fold/drop a source operand (C2168 "too few
                         * parameters"). A plain __vpaddd(...) extern accepts any arity, is never
                         * mis-modeled as a semantically-wrong short call, and still makes the op
                         * (and its value) visible instead of dropping it — which is the whole
                         * point of AVX modeling. */
                        call->callee = "__" + sani(in.mnem);
                        call->width = 8; call->ret_kind = 2;
                        if (OP(0).access & CS_AC_READ) call->args.push_back(rvalue(OP(0)));
                        for (int k = 1; k < nop && k < 4; ++k)
                            if (OP(k).type == X86_OP_REG || OP(k).type == X86_OP_MEM ||
                                OP(k).type == X86_OP_IMM)
                                call->args.push_back(rvalue(OP(k)));
                        extern_callees[call->callee] = call->ret_kind;
                        opaque_ops[call->callee]++;
                        vec_op_value[OP(0).reg] = call;
                        /* memset byte-broadcast: `vinsertf128 ymm,ymm,xmm,1` with the inserted
                         * xmm the SAME slot as the base -> a uniform 256-bit byte fill.
                         * Re-establish the snapshotted fill so the wide store becomes memset. */
                        if ((id == X86_INS_VINSERTF128 || id == X86_INS_VINSERTI128) &&
                            nop >= 3 && OP(2).type == X86_OP_REG &&
                            !std::getenv("DS_NO_MEMSETBCAST")) {
                            Reg dr2 = vec_reg(OP(0).reg);
                            if (dr2 != R_NONE && vec_reg(OP(2).reg) == dr2) {
                                auto pf = prev_vec_fill.find(dr2);
                                if (pf != prev_vec_fill.end() && pf->second.val)
                                    vec_fill[dr2] = { clone(pf->second.val), pf->second.esz };
                            }
                        }
                    }
                    break;
                }
                /* An unmodeled op that WRITES MEMORY is worse than one that writes a
                 * register: the store is a side effect that simply VANISHES, and the
                 * function then reads as complete. A 256-bit `vmovdqu ymmword [rcx],ymm0`
                 * (the VEX remap above refuses it — see the width guard) left
                 * `void ymm_copy32(void) { return; }` labelled "confidence: HIGH": an
                 * empty function asserting it had nothing to do, which is exactly the x87
                 * failure this project already paid for once.
                 *
                 * Emit an opaque void call naming the mnemonic and the DESTINATION ADDRESS.
                 * The address is knowable; the stored VALUE is not (the source is an
                 * unmapped vector register that would read back as a backstop 0 — the very
                 * lie being removed), so only immediates join the address as arguments.
                 * This also makes the op appear in the body text, which is the ONLY way the
                 * confidence header counts it. DS_NO_OPAQUEMEM. */
                /* WIDE (YMM/ZMM) / non-temporal vector MOVE modeling. The lane model can't
                 * hold a >16-byte value, but a load-then-store IS a memcpy. Record the
                 * address a wide reg was loaded from; turn a later store of that (un-
                 * clobbered) reg into a chunked `*(int64_t*)(dst+8k) = *(int64_t*)(src+8k)`
                 * copy so the memcpy survives instead of a valueless `__vmovdqu(dst)`.
                 * The reg's tracking was erased above if anything else wrote it, so this
                 * never copies a stale value. DS_NO_VECCOPY. */
                if (nop >= 2 && !std::getenv("DS_NO_VECCOPY") &&
                    (in.mnem.rfind("vmov", 0) == 0 || in.mnem.rfind("movnt", 0) == 0)) {
                    if (OP(0).type == X86_OP_REG && OP(1).type == X86_OP_MEM) {
                        Reg dr = vec_reg(OP(0).reg);
                        ExprP sm = rvalue(OP(1));
                        if (dr != R_NONE && sm && sm->kind == EK::Mem && sm->a) {
                            vec_load_addr[dr] = clone(sm->a);
                            break;
                        }
                    } else if (OP(0).type == X86_OP_MEM && OP(1).type == X86_OP_REG) {
                        Reg sr = vec_reg(OP(1).reg);
                        auto it = vec_load_addr.find(sr);
                        int vsz = OP(0).size ? OP(0).size : 16;
                        if (sr != R_NONE && it != vec_load_addr.end() && it->second &&
                            (vsz == 16 || vsz == 32 || vsz == 64)) {
                            ExprP daddr = addr_of_mem(OP(0));
                            ExprP saddr = it->second;
                            /* a load-then-store of a whole wide reg IS a memcpy. Emit the one
                             * readable call instead of vsz/8 scalar `*(int64_t*)(dst+8k)=...`
                             * lines (297 of them in __memmove_avx). Behaviorally identical: the
                             * chunked stores are already FORWARD-order and non-overlapping for a
                             * single wide reg copy, exactly memcpy's contract. DS_NO_SSEMEMCPY
                             * reverts to the (gate-proven) chunked stores. */
                            if (!std::getenv("DS_NO_SSEMEMCPY")) {
                                auto call = new_expr();
                                call->kind = EK::Call; call->callee = "memcpy";
                                call->width = 8; call->ret_kind = 2;
                                call->args.push_back(mkCast("(void*)", clone(daddr), 8, true));
                                call->args.push_back(mkCast("(void*)", clone(saddr), 8, true));
                                call->args.push_back(mkConst(vsz, 8));
                                extern_callees["memcpy"] = 2; used_meminstr = true;
                                Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
                                b.stmts.push_back(std::move(s));
                                break;
                            }
                            for (int k = 0; k < vsz / 8; ++k) {
                                ExprP d = mkMem(k ? mkBinary("+", clone(daddr), mkConst(8 * k, 8), 8) : clone(daddr), 8);
                                ExprP s = mkMem(k ? mkBinary("+", clone(saddr), mkConst(8 * k, 8), 8) : clone(saddr), 8);
                                emit_store(b, d, s, in.addr);
                            }
                            break;
                        }
                        /* Broadcast/zero/all-ones FILL of a wide reg -> a real memset,
                         * rendered as chunked stores (identical, gate-proven mechanism to
                         * the copy above — deliberately NOT an emitted `memset()` call,
                         * which would risk an extern-prototype conflict). Sound: vec_fill
                         * is set only by zero/ones/broadcast idioms and erased on any other
                         * write to the reg. Element fill value is `val` (a Const for
                         * zero/ones/immediate, or a resolved scalar for a runtime
                         * broadcast); `esz` is the element size in bytes. DS_NO_VECFILL. */
                        auto fit = vec_fill.find(sr);
                        if (sr != R_NONE && fit != vec_fill.end() && fit->second.val &&
                            fit->second.esz >= 1 && !std::getenv("DS_NO_VECFILL") &&
                            (vsz == 16 || vsz == 32 || vsz == 64)) {
                            ExprP daddr = addr_of_mem(OP(0));
                            int esz = fit->second.esz;
                            ExprP fv = fit->second.val;
                            bool isConst = (fv->kind == EK::Const);
                            if (esz == 1) {
                                /* byte fill of a whole wide reg IS a memset. Emit the one call
                                 * instead of vsz/8 chunked `*(int64_t*)(dst+8k)=byte*0x0101..`
                                 * stores. DS_NO_SSEMEMCPY reverts to the chunked stores. */
                                if (!std::getenv("DS_NO_SSEMEMCPY")) {
                                    ExprP byteval = isConst
                                        ? mkConst((int64_t)((uint64_t)fv->cval & 0xFF), 4)
                                        : mkCast("(unsigned __int8)", clone(fv), 1, true);
                                    auto call = new_expr();
                                    call->kind = EK::Call; call->callee = "memset";
                                    call->width = 8; call->ret_kind = 2;
                                    call->args.push_back(mkCast("(void*)", clone(daddr), 8, true));
                                    call->args.push_back(byteval);
                                    call->args.push_back(mkConst(vsz, 8));
                                    extern_callees["memset"] = 2; used_meminstr = true;
                                    Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
                                    b.stmts.push_back(std::move(s));
                                    break;
                                }
                                /* byte fill: replicate to a 64-bit pattern, chunk by 8. */
                                for (int k = 0; k < vsz / 8; ++k) {
                                    ExprP q = isConst
                                        ? mkConst((int64_t)(((uint64_t)fv->cval & 0xFF) * 0x0101010101010101ULL), 8)
                                        : mkBinary("*", mkCast("(unsigned __int8)", clone(fv), 1, true),
                                                   mkConst((int64_t)0x0101010101010101ULL, 8), 8);
                                    ExprP d = mkMem(k ? mkBinary("+", clone(daddr), mkConst(8 * k, 8), 8) : clone(daddr), 8);
                                    emit_store(b, d, q, in.addr);
                                }
                                break;
                            }
                            if (isConst) {
                                /* wider constant element: fold to a 64-bit pattern, chunk by 8. */
                                uint64_t e = (uint64_t)fv->cval, pat;
                                if (esz == 2)      { uint64_t x = e & 0xFFFF;     pat = x | x << 16 | x << 32 | x << 48; }
                                else if (esz == 4) { uint64_t x = e & 0xFFFFFFFF; pat = x | x << 32; }
                                else               pat = e;                        /* esz == 8 */
                                for (int k = 0; k < vsz / 8; ++k) {
                                    ExprP d = mkMem(k ? mkBinary("+", clone(daddr), mkConst(8 * k, 8), 8) : clone(daddr), 8);
                                    emit_store(b, d, mkConst((int64_t)pat, 8), in.addr);
                                }
                                break;
                            }
                            /* runtime wider element (vpbroadcastd/q with a variable): store
                             * element-granular so the exact value is preserved. */
                            for (int k = 0; k < vsz / esz; ++k) {
                                ExprP d = mkMem(k ? mkBinary("+", clone(daddr), mkConst(esz * k, 8), 8) : clone(daddr), esz);
                                emit_store(b, d, clone(fv), in.addr);
                            }
                            break;
                        }
                    }
                }
                if (nop >= 2 && vex_wide_refused && OP(0).type == X86_OP_MEM &&
                    !in.mnem.empty() && !std::getenv("DS_NO_OPAQUEMEM")) {
                    auto call = new_expr();
                    call->kind = EK::Call;
                    call->callee = "__" + sani(in.mnem);
                    call->width = 0; call->ret_kind = 0;
                    call->args.push_back(mkCast("(void*)", addr_of_mem(OP(0)), 8, true));
                    for (int k = 1; k < nop && k < 4; ++k)
                        if (OP(k).type == X86_OP_IMM) call->args.push_back(rvalue(OP(k)));
                    extern_callees[call->callee] = 0;
                    opaque_ops[call->callee]++;
                    Stmt s; s.kind = SK::Call; s.rhs = call; s.addr = in.addr;
                    b.stmts.push_back(std::move(s));
                }
                break;
            }
        }

        /* STALE-FLAG INVALIDATION (check half): if this instruction WRITES an arithmetic
         * flag (CF/SF/ZF/OF per capstone's eflags MODIFY bits) but its handler did NOT
         * model the flags (signature unchanged), the previous compare's flags are now
         * STALE -- a following jcc would render a confidently WRONG condition. Invalidate
         * so cc_to_expr emits `if (1)` (an honest placeholder) instead of a plausible lie.
         * EXCLUDE x87 (mnemonic starts with 'f'): cs_x86 unions fpu_flags over eflags, so
         * an x87 op's status-word bits would be read as bogus eflags MODIFY bits.
         * DS_NO_FLAGINVAL disables. */
        if (flags.valid && !in.mnem.empty() && in.mnem[0] != 'f' &&
            !std::getenv("DS_NO_FLAGINVAL")) {
            const uint64_t MOD = X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_SF |
                                 X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_OF;
            if (in.x86.eflags & MOD) {
                unsigned fk = (flags.is_cmp ? 1u : 0u) | (flags.is_test ? 2u : 0u) |
                              (flags.is_arith ? 4u : 0u) | (flags.is_bt ? 8u : 0u) |
                              (flags.is_fcmp ? 16u : 0u);
                bool modeled = !(flags.a.get() == _flg_a && flags.b.get() == _flg_b &&
                                 flags.valid == _flg_v && fk == _flg_k && flags.width == _flg_w);
                if (!modeled) flags.valid = false;
            }
        }
    }

    bool is_rsp_adjust(const cs_x86& x) {
        if (x.op_count != 2) return false;
        if (x.operands[0].type != X86_OP_REG || x.operands[1].type != X86_OP_IMM)
            return false;
        Reg r; int w; map_reg(x.operands[0].reg, r, w);
        return r == R_RSP;
    }

