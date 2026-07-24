/* 03_prologue_frame.inc -- prologue scan, frame/callee-saves, stack slots
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Collapse the SSE float-compare NaN-guard idiom:
     *     ucomiss a, b ; jp T ; jne T          (both jumps -> the SAME target T)
     * The `jp` (parity / unordered = NaN) and the `jne` test one comparison and
     * branch to the same place, so the recovered C otherwise shows TWO identical
     * `if (a != b) goto T;` lines. The jp block's branch is fully redundant: if
     * the condition is false we fall to the jne block, which re-tests it
     * identically (NaN already excluded, so `!=` alone is exact). Drop the jp
     * block's taken edge so it falls through and only the `jne` survives.
     *
     * Gated tightly to avoid touching the OTHER float idiom `jp L1; je L2` (an
     * ordered-equality test to DIFFERENT targets): we require the fall-through to
     * be a LONE `jne` to the SAME target, and the jp block's flag source to be a
     * genuine float compare. Runs after build_cfg, before dominators, so the
     * edge removal is reflected in the dominator tree. */
    void collapse_fp_parity_branches() {
        auto flagsrc_is_float_cmp = [&](const Block& b) -> bool {
            for (int i = (int)b.insn_idx.size() - 1; i >= 0; --i) {
                unsigned id = insns[b.insn_idx[i]].id;
                if (id == X86_INS_COMISS || id == X86_INS_UCOMISS ||
                    id == X86_INS_COMISD || id == X86_INS_UCOMISD) return true;
                if (id == X86_INS_CMP || id == X86_INS_TEST) return false;
            }
            return false;
        };
        for (auto& b : blocks) {
            if (!b.ends_jcc || b.cc != CC::P) continue;
            if (b.taken < 0 || b.fall < 0 || b.taken == b.fall) continue;
            if (!flagsrc_is_float_cmp(b)) continue;
            Block& fb = blocks[b.fall];
            /* The fall-through must be a LONE float-compare jcc that, for a NaN input,
             * routes to the SAME place the jp does (b.taken) — then dropping the jp
             * edge is behavior-preserving and removes the duplicate `a != b` line.
             * Two shapes:
             *   `jp T ; jne T`        (a != b, same target) — NaN!=  -> fb.taken==T
             *   `jp L1; je L2`        (a != b, `if(a!=b){L1}else{L2}`) — NaN is not
             *                          equal, so je falls through to L1==b.taken.
             * Both collapse to a clean single `a == b`/`a != b`. The second shape was
             * NOT handled before, leaving `*(float*)x != y || *(float*)x != y`. */
            if (!fb.ends_jcc || fb.insn_idx.size() != 1) continue;
            bool ok = (fb.cc == CC::NE && fb.taken == b.taken) ||
                      (fb.cc == CC::E  && fb.fall  == b.taken);
            if (!ok) continue;
            /* neutralize the jp branch: unconditional fall-through to fb */
            int t = b.taken;
            b.taken = -1; b.cc = CC::NONE; b.ends_jcc = false;
            b.cond = nullptr; b.drop_branch = true;
            b.succ.erase(std::remove(b.succ.begin(), b.succ.end(), t), b.succ.end());
            auto& tp = blocks[t].pred;
            tp.erase(std::remove(tp.begin(), tp.end(), b.id), tp.end());
        }
    }

    /* =================================================================== */
    /*  Stack / param model                                                 */
    /* =================================================================== */

    int64_t frame_size = 0;
    int64_t prologue_push_bytes = 0;   /* rsp lowered by pre-frame `push`es */
    Reg     frame_rsp_alias = R_NONE;  /* a reg that froze rsp (`mov r11,rsp`) = frame base */
    int64_t frame_alias_push = 0;      /* prologue_push_bytes at the alias capture */
    bool    uses_rbp_frame = false;
    bool    rbp_offset_known = false;
    int64_t rbp_minus_rsp = 0;

    void scan_prologue() {
        bool sub_seen = false;
        /* a register that froze rsp (`mov r11,rsp`) so a later `lea rbp,[r11-K]`
         * can be resolved to a frame offset (large-frame MSVC idiom). */
        Reg rsp_alias = R_NONE; int64_t alias_push_at_capture = 0;
        bool alias_pre_sub = false;   /* the `mov r,rsp` froze rsp BEFORE `sub rsp,Y` */
        bool rbp_from_alias = false; int64_t rbp_alias_disp = 0, rbp_alias_push = 0;
        bool rbp_lea_pre_sub = false; int64_t rbp_lea_disp = 0;
        /* last constant moved into each register, for the large-frame chkstk idiom
         * `mov eax,IMM; call __chkstk; sub rsp,rax` where the frame size arrives in a
         * register, not as a `sub rsp,imm` immediate. */
        std::vector<int64_t> reg_const(R_COUNT, INT64_MIN);
        uint64_t pending_call = 0;   /* last prologue call (the __chkstk probe candidate) */
        for (size_t i = 0; i < insns.size() && i < 24; ++i) {
            const Insn& in = insns[i];
            const cs_x86& x = in.x86;
            if (in.is_call) pending_call = in.addr;
            /* `push reg` before the frame `sub rsp` lowers rsp by 8 each, so the
             * incoming stack args sit 8*N higher than frame_size alone implies.
             * Count them so arg-index recovery is not off-by-(pushes). */
            if (!sub_seen && in.id == X86_INS_PUSH) prologue_push_bytes += 8;
            /* track `mov reg,imm` (chkstk frame-size carrier). A call (to __chkstk)
             * preserves rax per its contract, so do NOT invalidate across it. */
            if (in.id == X86_INS_MOV && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_IMM) {
                Reg r; int w; map_reg(x.operands[0].reg, r, w);
                if (r > R_NONE && r < R_COUNT) reg_const[r] = x.operands[1].imm;
            }
            if (in.id == X86_INS_SUB && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_IMM) {
                Reg r; int w; map_reg(x.operands[0].reg, r, w);
                if (r == R_RSP) { frame_size = x.operands[1].imm; sub_seen = true; }
            }
            /* large frame: `sub rsp, rax` where rax was loaded with the size. */
            if (in.id == X86_INS_SUB && !sub_seen && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_REG) {
                Reg d, s; int wd, ws;
                map_reg(x.operands[0].reg, d, wd); map_reg(x.operands[1].reg, s, ws);
                if (d == R_RSP && s > R_NONE && s < R_COUNT && reg_const[s] != INT64_MIN) {
                    frame_size = reg_const[s]; sub_seen = true;
                    /* the `call` between `mov eax,size` and `sub rsp,rax` is the
                     * __chkstk stack probe (often an unnamed local in a DLL): elide
                     * it so it doesn't render as a spurious `fun_xxxx();`. */
                    if (pending_call) chkstk_call_addrs.insert(pending_call);
                }
            }
            if (in.id == X86_INS_MOV && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_REG) {
                Reg d, s; int wd, ws;
                map_reg(x.operands[0].reg, d, wd);
                map_reg(x.operands[1].reg, s, ws);
                if (d == R_RBP && s == R_RSP) {
                    uses_rbp_frame = true;
                    if (sub_seen) {
                        rbp_offset_known = true; rbp_minus_rsp = 0;
                    } else {
                        /* `mov rbp,rsp` BEFORE `sub rsp,Y`: rbp is the frame base and
                         * every offset must be measured against the FINAL rsp, so the
                         * distance is Y — not 0. Recording 0 here shifted every
                         * rbp-relative slot by the whole frame, which pushed the
                         * incoming stack arguments out of the range detect_stack_params
                         * scans: kernel32 fn_00050938 reads its 5th/6th args at
                         * [rbp+0x80]/[rbp+0x88], and they were instead recovered as
                         * fresh zero-initialised locals, emitting
                         *     int32_t*v6 = 0; ... *v6 = 0;
                         * i.e. a guaranteed null-pointer write where the disassembly
                         * stores through a real parameter.
                         *
                         * This is the same deferral the `lea rbp,[rsp-X]` branch below
                         * already does; the mov form simply never got it. MSVC emits
                         * `push rbp; <more pushes>; mov rbp,rsp; sub rsp,N` routinely,
                         * so this is a common shape, not a corner case. */
                        rbp_lea_pre_sub = true;
                        rbp_lea_disp = 0;
                    }
                } else if (s == R_RSP && d != R_RSP && d != R_RBP) {
                    /* `mov r11,rsp` — r11 now holds the (push-adjusted) frame base */
                    rsp_alias = d; alias_push_at_capture = prologue_push_bytes;
                    alias_pre_sub = !sub_seen;
                }
            }
            if (in.id == X86_INS_LEA && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_MEM) {
                Reg d; int wd; map_reg(x.operands[0].reg, d, wd);
                Reg mb = R_NONE; int mbw;
                if (x.operands[1].mem.base != X86_REG_INVALID)
                    map_reg(x.operands[1].mem.base, mb, mbw);
                if (d == R_RBP && mb == R_RSP &&
                    x.operands[1].mem.index == X86_REG_INVALID) {
                    uses_rbp_frame = true;
                    if (sub_seen) {
                        rbp_offset_known = true;
                        rbp_minus_rsp = x.operands[1].mem.disp;
                    } else {
                        /* `lea rbp,[rsp-X]` BEFORE `sub rsp,Y`: rbp points into the
                         * mid-frame (Y-X above the final rsp), so the offset vs the
                         * FINAL rsp is disp+frame_size. Deferred until frame_size is
                         * known (it is set by the later sub). Without this every
                         * rbp-relative local/arg is mis-normalized and the 5th+ stack
                         * param is lost. */
                        rbp_lea_pre_sub = true;
                        rbp_lea_disp = x.operands[1].mem.disp;
                    }
                } else if (d == R_RBP && rsp_alias != R_NONE && mb == rsp_alias &&
                           x.operands[1].mem.index == X86_REG_INVALID) {
                    /* `lea rbp,[r11+disp]`: r11 froze rsp `pushes_between` bytes
                     * before this point, so it equals `[rsp_here + disp + between]`,
                     * matching the direct `lea rbp,[rsp+disp]` convention. Deferred
                     * because the final push count is known only after the scan. */
                    rbp_from_alias = true;
                    rbp_alias_disp = x.operands[1].mem.disp;
                    rbp_alias_push = prologue_push_bytes;
                }
            }
        }
        if (rbp_from_alias && !rbp_offset_known) {
            uses_rbp_frame = true; rbp_offset_known = true;
            /* NOTE: a pre-sub alias capture SHOULD also add frame_size here (mirroring
             * rbp_lea_pre_sub below; verified correct offset for fn_00050a00). DEFERRED
             * — the correct offset re-resolves ambiguous /O2 slots (a param slot reused
             * as a spilled float) and surfaces a float/pointer type conflict (fn_0001e870
             * a6) the type-inference must disambiguate FIRST. See [[decompiler-known-gaps]]. */
            rbp_minus_rsp = rbp_alias_disp + (rbp_alias_push - alias_push_at_capture);
        }
        (void)alias_pre_sub;
        if (rbp_lea_pre_sub && !rbp_offset_known) {
            uses_rbp_frame = true; rbp_offset_known = true;
            rbp_minus_rsp = rbp_lea_disp + frame_size;   /* offset vs the FINAL rsp */
        }
        /* publish the rsp-alias so the param-home / float-home passes can recognize
         * an alias-based arg home (`mov r11,rsp; mov [r11+0x10],rdx`), not only the
         * literal-RSP form. */
        frame_rsp_alias = rsp_alias;
        frame_alias_push = alias_push_at_capture;
    }

    /* Is `e` the symbolic frame base (entry RSP) plus a constant? Recognises a
     * register that captured the frame base (`mov rax,rsp`; `lea rbp,[rax+k]`),
     * accumulating the constant displacement. */
    bool frame_rel(const ExprP& e, int64_t& off) const {
        if (!e) return false;
        if (e->kind == EK::Reg && e->reg == R_RSP) { off = 0; return true; }
        if (e->kind == EK::Binary && (e->op == "+" || e->op == "-") && e->a && e->b) {
            int64_t lo;
            if (e->op == "+") {
                if (e->b->kind == EK::Const && frame_rel(e->a, lo)) { off = lo + e->b->cval; return true; }
                if (e->a->kind == EK::Const && frame_rel(e->b, lo)) { off = lo + e->a->cval; return true; }
            } else { /* a - const */
                if (e->b->kind == EK::Const && frame_rel(e->a, lo)) { off = lo - e->b->cval; return true; }
            }
        }
        return false;
    }

    bool normalise_slot(Reg base, int64_t disp, int64_t& norm) {
        if (base == R_RSP) { norm = disp; return true; }
        if (base == R_RBP && uses_rbp_frame && rbp_offset_known) {
            norm = disp + rbp_minus_rsp; return true;
        }
        /* base register holds the frame base (entry RSP) + k: `[base+disp]` is the
         * stack slot at (k + disp) in the post-sub frame, i.e. + frame_size. */
        if (base > R_NONE && base < R_COUNT && regfile[base]) {
            int64_t k;
            if (frame_rel(regfile[base], k)) { norm = disp + k + frame_size; return true; }
        }
        return false;
    }

    void detect_param_homes() {
        bool sub_done = false;
        bool argreg_written[4] = {false,false,false,false};   /* rcx/rdx/r8/r9 clobbered */
        /* the rsp-alias (`mov r11,rsp`) is a valid frame base for arg homes only
         * between its capture and any later reassignment of that register. */
        bool alias_valid = false;
        for (size_t i = 0; i < insns.size() && i < 24; ++i) {
            const Insn& in = insns[i];
            const cs_x86& x = in.x86;
            /* arm/disarm the rsp-alias: `mov alias,rsp` captures the frame base; any
             * other write to that register invalidates it for alias homing. */
            if (frame_rsp_alias != R_NONE) {
                for (int o = 0; o < x.op_count; ++o) {
                    const cs_x86_op& op = x.operands[o];
                    if (op.type != X86_OP_REG || !(op.access & CS_AC_WRITE)) continue;
                    Reg wr; int ww; map_reg(op.reg, wr, ww);
                    if (wr != frame_rsp_alias) continue;
                    bool cap = (in.id == X86_INS_MOV && x.op_count == 2 &&
                                x.operands[1].type == X86_OP_REG);
                    if (cap) { Reg s; int sw; map_reg(x.operands[1].reg, s, sw); cap = (s == R_RSP); }
                    alias_valid = cap;
                }
            }
            if (in.id == X86_INS_SUB && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_IMM) {
                Reg r; int w; map_reg(x.operands[0].reg, r, w);
                if (r == R_RSP) { sub_done = true; continue; }
            }
            /* SIGNEDNESS of a homed narrow param, read off how it is widened.
             *
             * On the /Od path the argument is spilled (`mov [rsp+8], cl`) and every
             * use reads it BACK from memory, so the register-site evidence never
             * fires: `movzx eax, byte ptr [rsp+0x20]` proves the value is unsigned
             * and `movsx` proves it signed. Without this an `unsigned char`
             * parameter recovered its width correctly and still declared int8_t.
             * The homing store precedes the reads in program order, so
             * param_home_off is already populated by the time we get here. */
            if ((in.id == X86_INS_MOVZX || in.id == X86_INS_MOVSX || in.id == X86_INS_MOVSXD) &&
                x.op_count == 2 && x.operands[1].type == X86_OP_MEM &&
                x.operands[1].size && x.operands[1].size <= 2) {
                const x86_op_mem& sm = x.operands[1].mem;
                Reg bs; int bw;
                if (sm.index == X86_REG_INVALID && sm.base != X86_REG_INVALID) {
                    map_reg(sm.base, bs, bw);
                    bool via_al = (frame_rsp_alias != R_NONE && bs == frame_rsp_alias && alias_valid);
                    if (bs == R_RSP || bs == R_RBP || via_al) {
                        int64_t nrm = via_al
                            ? (sm.disp + frame_size + prologue_push_bytes - frame_alias_push)
                            : (sm.disp + (sub_done ? 0 : (frame_size + prologue_push_bytes)));
                        auto hit = param_home_off.find(nrm);
                        if (hit != param_home_off.end())
                            var_unsigned[hit->second] = (in.id == X86_INS_MOVZX);
                    }
                }
            }
            if (in.id != X86_INS_MOV || x.op_count != 2) {
                /* track clobbers of the arg registers so a later reuse-store of a
                 * different value to the same slot is NOT mistaken for homing. */
                for (int o = 0; o < x.op_count; ++o) {
                    const cs_x86_op& op = x.operands[o];
                    if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE)) {
                        Reg r; int w; map_reg(op.reg, r, w);
                        int p = (r==R_RCX)?0:(r==R_RDX)?1:(r==R_R8)?2:(r==R_R9)?3:-1;
                        if (p >= 0) argreg_written[p] = true;
                    }
                }
                continue;
            }
            if (x.operands[0].type != X86_OP_MEM ||
                x.operands[1].type != X86_OP_REG) {
                if (x.operands[0].type == X86_OP_REG && (x.operands[0].access & CS_AC_WRITE)) {
                    Reg r; int w; map_reg(x.operands[0].reg, r, w);
                    int p = (r==R_RCX)?0:(r==R_RDX)?1:(r==R_R8)?2:(r==R_R9)?3:-1;
                    if (p >= 0) argreg_written[p] = true;
                }
                continue;
            }
            const x86_op_mem& m = x.operands[0].mem;
            Reg base = R_NONE; int bw;
            if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
            bool via_alias = (frame_rsp_alias != R_NONE && alias_valid && base == frame_rsp_alias);
            if ((base != R_RSP && !via_alias) || m.index != X86_REG_INVALID) continue;
            Reg src; int sw; map_reg(x.operands[1].reg, src, sw);
            int pidx = -1;
            if (src == R_RCX) pidx = 0;
            else if (src == R_RDX) pidx = 1;
            else if (src == R_R8)  pidx = 2;
            else if (src == R_R9)  pidx = 3;
            else continue;
            /* The store only HOMES the arg if the register still holds the incoming
             * value. After `mov ecx,1` a later `mov [rsp+8],ecx` stores 1, not the
             * arg — homing it would alias the reused local to `a1` and drop the
             * real store (the `1 << i` -> `a1 << i` bug in parity32). */
            if (argreg_written[pidx]) continue;
            /* the shadow slot for arg p is entry_rsp+8+8p; a frozen rsp-alias equals
             * (entry_rsp - alias_push), so through the alias the disp is offset by the
             * pushes at capture. */
            int64_t expect = 8 + 8 * pidx + (via_alias ? frame_alias_push : 0);
            if (m.disp != expect) continue;
            /* The home-store writes the shadow slot at ENTRY rsp (m.disp matches the
             * shadow offset only when no rsp adjustment preceded it). In the body the
             * same slot sits frame_size + prologue_push_bytes below the current rsp —
             * the push bytes were MISSING here (detect_stack_params already adds them),
             * so a /O2 frame that `push`es callee-saves before `sub rsp` mapped a4's
             * home to the wrong offset and its later spill-reload read fell through to
             * an undefined `v1` (csr_matvec/csr_transpose nrows loop bound). */
            /* an alias base froze entry_rsp (minus the pushes at capture) and never
             * moves with the sub, so its slot is always entry-relative: add the full
             * frame adjustment and back out the capture pushes. An RSP base is
             * body-relative once the sub ran (sub_done). */
            int64_t norm = via_alias
                ? (m.disp + frame_size + prologue_push_bytes - frame_alias_push)
                : (m.disp + (sub_done ? 0 : (frame_size + prologue_push_bytes)));
            std::string nm = "a" + std::to_string(pidx + 1);
            param_home_off[norm] = nm;
            home_store_addrs.insert(in.addr);   /* skip this no-op store when lifting */
            if (pidx + 1 > num_params) num_params = pidx + 1;
            param_used[pidx] = true;
            if (sw >= 8) var_is_ll[nm] = true;
            record_width(nm, sw ? sw : 8);
        }
    }

    /* Detect callee-saved register save/restore so it can be elided. A SAVE is
     * `mov [rsp+X], reg` (or push reg) where reg is non-volatile and has NOT yet
     * been written — i.e. it stores the register's INCOMING value to spill it for
     * the duration of the function. The matching RESTORE is `mov reg, [rsp+X]`
     * from the same slot. Both are pure preservation with no observable effect;
     * without eliding them the save reads the incoming reg value and renders the
     * phantom `v = ctx_r14`. Keyed on raw disp so save and restore match
     * regardless of frame/push accounting. */
    void scan_callee_saves() {
        std::map<int64_t, Reg> save_slot;       /* raw disp -> reg saved there */
        bool written[R_COUNT] = {false};
        /* registers currently holding rsp (`mov r11,rsp`/`mov rax,rsp`): large
         * frames spill the nonvolatiles through such an alias (`mov [rax-0x28],
         * r12`), not [rsp+X]. Without recognizing the alias those saves are not
         * elided and leak as `v = ctx_r12`. */
        std::set<Reg> rsp_alias;
        auto is_frame_base = [&](Reg b){ return b == R_RSP || rsp_alias.count(b); };
        for (auto& in : insns) {
            const cs_x86& x = in.x86;
            /* SAVE: mov [frame+disp], nonvol_reg, reg not yet written */
            if (in.id == X86_INS_MOV && x.op_count == 2 &&
                x.operands[0].type == X86_OP_MEM &&
                x.operands[1].type == X86_OP_REG) {
                const x86_op_mem& m = x.operands[0].mem;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                Reg src; int sw; map_reg(x.operands[1].reg, src, sw);
                if (is_frame_base(base) && m.index == X86_REG_INVALID &&
                    is_nonvol_gpr(src) && !written[src] && sw >= 8) {
                    save_slot[m.disp] = src;
                    callee_save_addrs.insert(in.addr);
                }
            }
            /* xmm6..xmm15 are callee-saved on Win64, spilled via movups/movaps/
             * movdqu/movsd. Same SAVE elision so the prologue spill of the untouched
             * entry value does not leak `in_XMM6` (the float sibling of ctx_<gpr>). */
            bool xmm_mov = (in.id==X86_INS_MOVUPS||in.id==X86_INS_MOVAPS||
                            in.id==X86_INS_MOVDQU||in.id==X86_INS_MOVDQA||
                            in.id==X86_INS_MOVSD||in.id==X86_INS_MOVSS||
                            in.id==X86_INS_MOVUPD||in.id==X86_INS_MOVAPD);
            if (xmm_mov && x.op_count == 2 &&
                x.operands[0].type == X86_OP_MEM &&
                x.operands[1].type == X86_OP_REG) {
                const x86_op_mem& m = x.operands[0].mem;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                Reg src; int sw; map_reg(x.operands[1].reg, src, sw);
                if (is_frame_base(base) && m.index == X86_REG_INVALID &&
                    is_nonvol_xmm(src) && !written[src]) {
                    save_slot[m.disp] = src;
                    callee_save_addrs.insert(in.addr);
                }
            }
            /* RESTORE: mov nonvol_reg, [frame+disp] from a recorded save slot */
            if (in.id == X86_INS_MOV && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_MEM) {
                const x86_op_mem& m = x.operands[1].mem;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                Reg dst; int dw; map_reg(x.operands[0].reg, dst, dw);
                if (is_frame_base(base) && m.index == X86_REG_INVALID &&
                    save_slot.count(m.disp) && save_slot[m.disp] == dst)
                    callee_save_addrs.insert(in.addr);
            }
            /* xmm RESTORE: movups/... xmm6-15, [frame+disp] from a recorded slot */
            if (xmm_mov && x.op_count == 2 &&
                x.operands[0].type == X86_OP_REG &&
                x.operands[1].type == X86_OP_MEM) {
                const x86_op_mem& m = x.operands[1].mem;
                Reg base = R_NONE; int bw;
                if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                Reg dst; int dw; map_reg(x.operands[0].reg, dst, dw);
                if (is_frame_base(base) && m.index == X86_REG_INVALID &&
                    save_slot.count(m.disp) && save_slot[m.disp] == dst &&
                    is_nonvol_xmm(dst))
                    callee_save_addrs.insert(in.addr);
            }
            /* track register writes + maintain the rsp-alias set: `mov r,rsp`
             * captures the frame base; any other write to r invalidates it. */
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE)) {
                    Reg r; int w; map_reg(op.reg, r, w);
                    if (r <= R_NONE || r >= R_COUNT) continue;
                    written[r] = true;
                    bool rsp_capture = (o == 0 && in.id == X86_INS_MOV &&
                        x.op_count == 2 && x.operands[1].type == X86_OP_REG &&
                        [&]{ Reg s; int sw; map_reg(x.operands[1].reg, s, sw); return s == R_RSP; }());
                    if (rsp_capture) rsp_alias.insert(r); else rsp_alias.erase(r);
                }
            }
        }
    }

    int reg_param_max = 0;   /* highest GPR-arg param count from read-before-write */

    /* Recover integer/pointer arguments that are READ straight out of their arg
     * register without being homed to a stack slot — the /O2 (release) pattern
     * that detect_param_homes (which only sees prologue homing stores) misses.
     * This is the 858a0-style "missing incoming arg -> uninitialized local /
     * call f(0)" cause. Read-before-write of RCX/RDX/R8/R9 (a destination write
     * and prologue push/pop excluded) means the register holds an incoming value.
     * Contiguity from a1 is required so an isolated scratch read of (say) rdx in
     * a function that takes no rcx arg cannot invent a phantom parameter.
     * For /Od this exactly reproduces the homed count (the homing store reads the
     * arg reg as a source), so the behavioral corpus is unaffected. */
    void detect_reg_params() {
        if (e->arch != DS_ARCH_X64) return;   /* GPR-arg ABI is Win64-only here */
        /* If the prologue homed ANY argument this is a partially-/Od-style frame.
         * Register read-before-write recovery (extending the param COUNT) is only
         * safe for fully-unhomed /O2 frames — otherwise scratch register use (an
         * idiv temp) would invent a phantom param the call sites don't pass (the
         * is_prime C2198 regression). But the param-WIDTH narrowing below only sets
         * var_width (pointers ignore it), so it stays safe even on homed frames: a
         * partially-homed /O2 frame that homes r8/r9 but keeps an UNHOMED 32-bit
         * `unsigned n`/`int n` in rdx (lu_decompose) must still narrow it to `int`
         * rather than defaulting to the 64-bit slot. So: scan + narrow always; only
         * gate reg_param_max (the count extension) on the fully-unhomed case. */
        bool any_homed = param_used[0]||param_used[1]||param_used[2]||param_used[3];
        bool written[4] = {false,false,false,false};
        bool used[4]    = {false,false,false,false};
        int  argw[4]    = {0,0,0,0};   /* max sub-register read width per arg */
        int  argu[4]    = {0,0,0,0};   /* +1 unsigned (movzx), -1 signed (movsx), 0 unknown */
        auto argpos = [](Reg r)->int {
            return (r==R_RCX)?0:(r==R_RDX)?1:(r==R_R8)?2:(r==R_R9)?3:-1;
        };
        for (auto& in : insns) {
            if (in.id == X86_INS_PUSH || in.id == X86_INS_POP) continue;
            const cs_x86& x = in.x86;
            /* self-zeroing idiom (`xor r,r` / `sub r,r`) DEFINES the reg to 0;
             * capstone still flags operand[1] as a READ, but it is NOT a use of
             * the incoming value. Counting it marks a zeroed scratch reg (a
             * vectorized-loop accumulator `xor r8d,r8d`) as a phantom parameter.
             * Distinct from `or r8,r8` below, whose read IS a real test. */
            bool self_zero = (in.id==X86_INS_XOR || in.id==X86_INS_SUB) &&
                             x.op_count==2 && x.operands[0].type==X86_OP_REG &&
                             x.operands[1].type==X86_OP_REG &&
                             x.operands[0].reg==x.operands[1].reg;
            /* READS first, against the written-state BEFORE this instruction. A
             * read+write of the same arg reg (`or r8,r8` — the MSVC `test`-that-
             * also-writes idiom used to check the strncpy count) would otherwise
             * have its dest write processed first, masking the read and losing the
             * parameter -> `if (0 == 0)`. */
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type == X86_OP_REG) {
                    Reg r; int w; map_reg(op.reg, r, w);
                    int p = argpos(r);
                    if (p < 0) continue;
                    /* Skip only a PURE-WRITE destination (`mov r8d,x`); a read-modify-
                     * write of an arg reg (`not r8d`, `add r8d,eax`) genuinely reads
                     * the incoming param and must record its (narrow) read width — else
                     * an `unsigned init` only ever touched as `not r8d` defaults to the
                     * full 64-bit slot (`long long a3`). A pure write has no READ flag,
                     * so the CS_AC_READ test below already excludes it; keeping the
                     * guard for RMW was what lost the width. */
                    bool is_pure_write = (o == 0 && (op.access & CS_AC_WRITE) &&
                                          !(op.access & CS_AC_READ));
                    if ((op.access & CS_AC_READ) && !written[p] && !is_pure_write && !self_zero) {
                        used[p] = true;
                        /* record the sub-register width this arg is read at, so a
                         * param only ever touched as ecx/edx narrows to `int`. */
                        if (w > argw[p]) argw[p] = w;
                        /* SIGNEDNESS comes free from HOW the narrow read is widened:
                         * movzx zero-extends (the value is unsigned), movsx sign-
                         * extends (it is signed). Without this a `unsigned char`
                         * parameter recovered its width correctly and still declared
                         * int8_t. Only the sub-register reads carry the evidence, so
                         * a wider read leaves it alone. */
                        if (w <= 2 && o == 1) {
                            if (in.id == X86_INS_MOVZX) argu[p] = 1;
                            else if (in.id == X86_INS_MOVSX || in.id == X86_INS_MOVSXD) argu[p] = -1;
                        }
                    }
                } else if (op.type == X86_OP_MEM) {
                    const x86_op_mem& m = op.mem;
                    Reg bi[2] = {R_NONE,R_NONE}; int t;
                    if (m.base  != X86_REG_INVALID) map_reg(m.base,  bi[0], t);
                    if (m.index != X86_REG_INVALID) map_reg(m.index, bi[1], t);
                    /* a register feeding an address is normally a 64-bit pointer, so
                     * keep the param wide. EXCEPT `lea r32,[a+b]` / `lea r32,[a-1]`
                     * which the compiler uses for 32-bit ARITHMETIC, not addressing:
                     * there the components are plain ints (avg_signed's `(a+b)/2`,
                     * next_pow2's `x-1`), so a 32-bit lea dest means 32-bit operands. */
                    int mem_reg_w = 8;
                    if (in.id == X86_INS_LEA && x.op_count >= 1 &&
                        x.operands[0].size && x.operands[0].size <= 4)
                        mem_reg_w = 4;
                    for (Reg r : bi) { int p = argpos(r); if (p>=0 && !written[p]) { used[p]=true; if (mem_reg_w > argw[p]) argw[p] = mem_reg_w; } }
                }
            }
            /* then WRITES */
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE)) {
                    Reg r; int w; map_reg(op.reg, r, w);
                    int p = argpos(r);
                    if (p >= 0) written[p] = true;
                }
            }
            /* Implicit-def opcodes write rdx/rax with NO explicit operand, so the
             * operand walk above misses them. The sign-extend `cdq/cqo/cwd` sets
             * rdx right before `idiv` reads it; without recording that write,
             * idiv's implicit rdx read looks like a read-before-write and invents
             * a phantom rdx parameter (the historical is_prime C2198 regression).
             * The 1-operand mul/div family also leaves its result in rdx. */
            switch (in.id) {
                case X86_INS_CDQ: case X86_INS_CQO: case X86_INS_CWD:
                    written[1] = true; break;                 /* rdx */
                case X86_INS_DIV:  case X86_INS_IDIV:
                case X86_INS_MUL:  case X86_INS_IMUL:
                    if (x.op_count <= 1) written[1] = true;    /* rdx:rax result */
                    break;
                default: break;
            }
        }
        /* Highest read-before-write arg register = the parameter count. A gap is
         * only fatal BEFORE the first arg (an isolated scratch read of rdx in a
         * function that takes no rcx arg must not invent a param). A gap AFTER an
         * arg is just an UNUSED positional parameter (`fun(a1, [unused rdx], char
         * flag)` reads rcx and r8b but never rdx) — the higher arg reg being read
         * incoming proves the slot exists, so keep scanning. */
        /* The highest GENUINELY read-before-write arg position is the parameter
         * count; MS x64 args are positional, so every LOWER slot is a parameter
         * too even if unused. An unused rcx with a read rdx is `fun(undefined a1,
         * T* a2)`, NOT scratch rdx — the old `break` on the position-0 gap dropped
         * a2 entirely and collapsed every [rdx+off] deref to `(char*)0` (0x17320,
         * 0x5cf90, 0x7a628, ... — the dominant null-base family). The read-before-
         * write gating + implicit-def handling above already exclude idiv/scratch
         * false positives, so filling the lower slots is safe. */
        int maxp = -1;
        for (int p = 0; p < 4; ++p)
            if (used[p] || param_used[p]) maxp = p;
        /* Extend the param COUNT only on fully-unhomed frames (C2198 guard); on a
         * homed frame the count is already established by the homing/finalize pass. */
        if (!any_homed) reg_param_max = maxp + 1;
        /* Narrow a param that is only ever read at a 32-bit-or-narrower sub-
         * register (ecx/edx/r8d/...) to `int`. /O2 frames read args straight from
         * registers, so without this the declared type defaults to the 64-bit
         * slot (long long) and every use is buried under an `(int)` cast
         * (`int gcd(long long a1, long long a2){ return (int)a1 ... }`). A 64-bit
         * read (rcx) or any address-base use (a pointer) already set argw[p]=8 and
         * is left wide. Only narrows the un-homed /O2 path; /Od returned above. */
        for (int p = 0; p <= maxp; ++p) {
            if (!((used[p] || param_used[p]) && argw[p] >= 1 && argw[p] <= 4)) continue;
            /* Keep the ACTUAL width, do not flatten 1 and 2 up to 4.
             *
             * argw is the widest sub-register the callee ever reads for this
             * argument, and under the x64 ABI a `char`/`short` parameter arrives
             * with the rest of the register undefined — so a callee that only ever
             * reads CL is being handed a byte, and one that reads ECX is not.
             * Rounding every narrow argument to 4 declared 8 of the corpus's
             * `char`/`unsigned char` parameters as int32_t (measured by
             * _qa/sigdiff.py against the original sources). */
            int w = argw[p];
            std::string nm = "a" + std::to_string(p + 1);
            var_width[nm] = (w == 1 || w == 2) ? w : 4;
            if ((w == 1 || w == 2) && argu[p] != 0) var_unsigned[nm] = argu[p] > 0;
        }
    }

