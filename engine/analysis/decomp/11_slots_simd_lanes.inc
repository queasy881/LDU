/* 11_slots_simd_lanes.inc -- stack-slot naming, xmm lane model (2x64 / 4x32)
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Write a value to a register: just update the symbolic map (no statement).
     * 32-bit writes zero-extend (clear upper 32 bits): we fold by storing the
     * (already-narrow) value and recording that the register now holds a 32-bit
     * value. For our purposes the stored Expr carries its own width. */
    void set_reg(Reg r, int w, ExprP val, Block& b) {
        if (r <= R_NONE || r >= R_COUNT) return;
        ExprP v = fold(val);
        if (w == 4) {
            /* 32-bit write zero-extends into the 64-bit register. The value
             * already carries width 4 (extension ops widen explicitly). We do
             * NOT mutate the expr's width (that would corrupt a Mem's access
             * size); the value is stored as-is. If a narrow byte/word value
             * leaked here, wrap it in a widening cast WITHOUT touching the inner
             * access. */
            if (v->width && v->width < 4)
                v = mkCast(cast_str(4, v->is_unsigned), v, 4, v->is_unsigned);
        } else if (w == 2 || w == 1) {
            /* partial write merges with old upper bits. Under /Od this almost
             * never feeds a wider read of the same reg before a full rewrite;
             * model the merge conservatively only if old value exists. */
            ExprP old = regfile[r];
            if (old) {
                int64_t keepmask = (w == 2) ? ~0xFFFFLL : ~0xFFLL;
                int64_t lowmask  = (w == 2) ?  0xFFFFLL :  0xFFLL;
                ExprP keep = mkBinary("&", clone(old), mkConst(keepmask, 8), 8);
                ExprP low  = mkBinary("&",
                    mkCast("(unsigned long long)", set_width(v, w), 8, true),
                    mkConst(lowmask, 8), 8);
                v = fold(mkBinary("|", keep, low, 8));
            } else {
                v = set_width(v, w);
            }
        }
        /* Safety valve: cap the symbolic SIZE of a register value. A fully /O2-
         * unrolled loop with a self-referential register (TEA's mutual v0/v1
         * recursion: v0 += f(v1); v1 += g(v0)) otherwise grows the expression
         * ~3x per round, reaching a multi-million-node tree that hangs the tool
         * building/folding/rendering it. Spilling to a named temp once it exceeds
         * a threshold caps the growth AND reads as the natural `tN = ...` chain.
         * Inputs are already capped, so node_count here is cheap (<= ~2*limit). */
        if (v && v->kind != EK::Var && v->kind != EK::Const && v->kind != EK::Reg &&
            node_count(v) > 400) {
            std::string tn = "t" + std::to_string(++temp_seq);
            cse_temps.insert(tn);
            int cw = v->width >= 8 ? 8 : 4;
            var_width[tn] = cw; if (cw >= 8) var_is_ll[tn] = true;
            if (v->is_float) var_is_float[tn] = true;
            Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, cw);
            if (v->is_float) s.lhs->is_float = true;
            s.rhs = v;
            b.stmts.push_back(std::move(s));
            ExprP tv = mkVar(tn, cw); if (cw >= 8) tv->is_unsigned = false;
            if (v->is_float) tv->is_float = true;
            v = tv;
        }
        regfile[r] = v;
        /* A scalar write to an xmm invalidates any tracked high lane AND the packed
         * float-lane vector: only an explicit packed op re-establishes them. */
        if (is_xmm(r)) { regfile_hi[r] = nullptr; clear_xmm_f(r); xmm_packed_var.erase(r); }
    }

    void clear_xmm_f(Reg r) {
        for (int k = 0; k < 4; ++k) xmm_f[r][k] = nullptr;
        xmm_f_real[r] = false;
        for (int k = 0; k < 4; ++k) xmm_i[r][k] = nullptr;
        xmm_i_real[r] = false;
    }
    /* Get the 4 INT lanes of an operand. Register: tracked xmm_i (all 4 present).
     * Memory: four `*(int*)(addr + 4*i)` loads. Mirrors xmm_f_lanes for integers. */
    bool xmm_i_lanes(const cs_x86_op& op, ExprP out[4]) {
        for (int i = 0; i < 4; ++i) out[i] = nullptr;
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            if (!is_xmm(r)) return false;
            if (xmm_i[r][0] && xmm_i[r][1] && xmm_i[r][2] && xmm_i[r][3]) {
                for (int i = 0; i < 4; ++i) out[i] = clone(xmm_i[r][i]);
                return true;
            }
            return false;
        }
        if (op.type == X86_OP_MEM) {
            ExprP m0 = rvalue(op);
            if (m0 && m0->kind == EK::Mem && m0->a) {
                for (int i = 0; i < 4; ++i) {
                    ExprP a = (i == 0) ? clone(m0->a)
                             : mkBinary("+", clone(m0->a), mkConst(4 * i, 8), 8);
                    out[i] = mkMem(a, 4, false);   /* *(int*)(p + 4i) */
                }
                return true;
            }
        }
        return false;
    }
    /* Set the 4 int lanes from a packed-INT op; mark real so a 128-bit store commits
     * four `*(int*)` lanes, and drive lane 0 into the scalar regfile. */
    void set_xmm_i4(Reg r, ExprP i0, ExprP i1, ExprP i2, ExprP i3, Block& b) {
        if (!is_xmm(r)) return;
        ExprP L[4] = { i0, i1, i2, i3 };
        clear_xmm_f(r);
        for (int k = 0; k < 4; ++k) xmm_i[r][k] = L[k] ? cap_lane(fold(clone(L[k])), b) : nullptr;
        xmm_i_real[r] = true;
        regfile[r] = i0 ? cap_lane(fold(clone(i0)), b) : nullptr;
        regfile_hi[r] = nullptr;
    }
    /* Populate the 4 float lanes WITHOUT disturbing the scalar regfile (used on a
     * movups/movaps memory load: ambiguous int-vs-float, so a side-channel only a
     * later float op reads; `real` stays false until a float op commits). */
    void populate_xmm_f(Reg r, ExprP f[4], bool real) {
        if (!is_xmm(r)) return;
        for (int k = 0; k < 4; ++k) { xmm_f[r][k] = f[k] ? fold(clone(f[k])) : nullptr; if (xmm_f[r][k]) xmm_f[r][k]->is_float = true; }
        xmm_f_real[r] = real;
    }
    /* Set the 4 float lanes from a definite float OP (arith/shuffle): also drives
     * lane 0 into the scalar regfile (so a following scalar movss/store reads it)
     * and marks the vector `real` so a 128-bit store commits four float lanes. */
    void set_xmm_f4(Reg r, ExprP f0, ExprP f1, ExprP f2, ExprP f3, Block& b) {
        if (!is_xmm(r)) return;
        ExprP L[4] = { f0, f1, f2, f3 };
        for (int k = 0; k < 4; ++k) {
            xmm_f[r][k] = L[k] ? cap_lane(fold(clone(L[k])), b) : nullptr;
            if (xmm_f[r][k]) xmm_f[r][k]->is_float = true;
        }
        xmm_f_real[r] = true;
        ExprP l0 = f0 ? clone(f0) : nullptr;
        if (l0) { l0->is_float = true; l0->width = 4; }
        regfile[r] = l0 ? cap_lane(fold(l0), b) : nullptr;
        regfile_hi[r] = nullptr;
    }

    /* --- 2-lane (8-byte `movsd`-as-2-floats) packed-float side-channel. MSVC uses
     * `movsd xmm,[m]; addps; movsd [m],xmm` as the 2-wide float remainder after the
     * 16-byte main loop (fadd_v `a[i]+=b[i]`). Modeled with the LOW two xmm_f lanes;
     * lanes 2,3 stay null. Mirror of the int populate_xmm_i2/set_xmm_i2 path. --- */
    void populate_xmm_f2(Reg r, ExprP f0, ExprP f1) {
        if (!is_xmm(r)) return;
        xmm_f[r][0] = f0 ? fold(clone(f0)) : nullptr; if (xmm_f[r][0]) xmm_f[r][0]->is_float = true;
        xmm_f[r][1] = f1 ? fold(clone(f1)) : nullptr; if (xmm_f[r][1]) xmm_f[r][1]->is_float = true;
        xmm_f[r][2] = nullptr; xmm_f[r][3] = nullptr;
        xmm_f_real[r] = false;
    }
    bool xmm_f_lanes2(const cs_x86_op& op, ExprP out[2]) {
        out[0] = out[1] = nullptr;
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            if (!is_xmm(r) || !xmm_f[r][0] || !xmm_f[r][1]) return false;
            out[0] = clone(xmm_f[r][0]); out[1] = clone(xmm_f[r][1]);
            return true;
        }
        if (op.type == X86_OP_MEM) {
            ExprP m0 = rvalue(op);
            if (m0 && m0->kind == EK::Mem && m0->a) {
                ExprP a0 = mkMem(clone(m0->a), 4, false); a0->is_float = true;
                ExprP a1 = mkMem(mkBinary("+", clone(m0->a), mkConst(4, 8), 8), 4, false); a1->is_float = true;
                out[0] = a0; out[1] = a1;
                return true;
            }
        }
        return false;
    }
    void set_xmm_f2(Reg r, ExprP f0, ExprP f1, Block& b) {
        if (!is_xmm(r)) return;
        xmm_f[r][0] = f0 ? cap_lane(fold(clone(f0)), b) : nullptr; if (xmm_f[r][0]) xmm_f[r][0]->is_float = true;
        xmm_f[r][1] = f1 ? cap_lane(fold(clone(f1)), b) : nullptr; if (xmm_f[r][1]) xmm_f[r][1]->is_float = true;
        xmm_f[r][2] = nullptr; xmm_f[r][3] = nullptr;
        xmm_f_real[r] = true;
        ExprP l0 = f0 ? clone(f0) : nullptr;
        if (l0) { l0->is_float = true; l0->width = 4; }
        regfile[r] = l0 ? cap_lane(fold(l0), b) : nullptr;
        regfile_hi[r] = nullptr;
    }
    bool emit_simd8_store_flanes(Block& b, const cs_x86_op& dst, ExprP f[2], uint64_t addr) {
        int w = 8; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, w, isr, r, wreg);
        if (isr || !lv || lv->kind != EK::Mem || !lv->a) return false;
        if (!f[0] || !f[1]) return false;
        ExprP daddr = lv->a;
        ExprP m0 = mkMem(clone(daddr), 4, false); m0->is_float = true;
        ExprP m1 = mkMem(mkBinary("+", clone(daddr), mkConst(4, 8), 8), 4, false); m1->is_float = true;
        emit_store(b, m0, f[0], addr);
        emit_store(b, m1, f[1], addr);
        return true;
    }
    /* The scalar (lane-0) float value of an xmm operand — a movss-loaded scalar in
     * the regfile, or a `*(float*)` memory load. Used for the `shufps x,x,0` splat
     * that broadcasts a scalar into a vector (`vec * scalar`). */
    ExprP xmm_scalar_f(const cs_x86_op& op) {
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            if (is_xmm(r) && regfile[r]) { ExprP v = clone(regfile[r]); v->is_float = true; if (v->width > 4) v->width = 4; return v; }
            return nullptr;
        }
        if (op.type == X86_OP_MEM) {
            ExprP m = rvalue(op);
            if (m) { m->is_float = true; if (m->kind == EK::Mem) m->width = 4; }
            return m;
        }
        return nullptr;
    }
    /* Get the 4 float lanes of an operand. Register: the tracked xmm_f (all 4 must
     * be present). Memory: four `*(float*)(addr + 4*i)` loads. Returns false if the
     * source can't yield a full float vector. */
    bool xmm_f_lanes(const cs_x86_op& op, ExprP out[4]) {
        for (int i = 0; i < 4; ++i) out[i] = nullptr;
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            if (!is_xmm(r)) return false;
            if (xmm_f[r][0] && xmm_f[r][1] && xmm_f[r][2] && xmm_f[r][3]) {
                for (int i = 0; i < 4; ++i) out[i] = clone(xmm_f[r][i]);
                return true;
            }
            return false;
        }
        if (op.type == X86_OP_MEM) {
            ExprP m0 = rvalue(op);
            if (m0 && m0->kind == EK::Mem && m0->a) {
                for (int i = 0; i < 4; ++i) {
                    ExprP a = (i == 0) ? clone(m0->a)
                             : mkBinary("+", clone(m0->a), mkConst(4 * i, 8), 8);
                    ExprP mem = mkMem(a, 4, false); mem->is_float = true;
                    out[i] = mem;
                }
                return true;
            }
        }
        return false;
    }

    /* Materialize an expr into a named temp if it has grown large (same valve as
     * set_reg) so loop-carried lane expressions can't blow up. Returns a Var. */
    ExprP cap_lane(ExprP v, Block& b) {
        if (!v || v->kind == EK::Var || v->kind == EK::Const || v->kind == EK::Reg ||
            node_count(v) <= 400) return v;
        std::string tn = "t" + std::to_string(++temp_seq);
        cse_temps.insert(tn);
        int cw = v->width >= 8 ? 8 : 4;
        var_width[tn] = cw; if (cw >= 8) var_is_ll[tn] = true;
        if (v->is_float) var_is_float[tn] = true;
        Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, cw);
        if (v->is_float) s.lhs->is_float = true;
        s.rhs = v; b.stmts.push_back(std::move(s));
        ExprP tv = mkVar(tn, cw);
        if (v->is_float) tv->is_float = true;
        return tv;
    }

    /* Set both lanes of an xmm from a packed op. lo goes through the normal scalar
     * path (so scalar reads see lane 0); hi is recorded in the side map. */
    void set_xmm_lanes(Reg r, ExprP lo, ExprP hi, Block& b) {
        set_reg(r, 16, lo, b);                 /* sets regfile[r], clears regfile_hi[r] */
        if (is_xmm(r)) regfile_hi[r] = hi ? cap_lane(fold(hi), b) : nullptr;
    }
    ExprP xmm_lo(Reg r) const { return regfile[r] ? clone(regfile[r]) : nullptr; }
    ExprP xmm_hi(Reg r) const {
        return (is_xmm(r) && regfile_hi[r]) ? clone(regfile_hi[r]) : nullptr;
    }

    ExprP set_width(ExprP v, int w) {
        if (!v) return v;
        auto c = std::make_shared<Expr>(*v);
        c->a = v->a; c->b = v->b; c->c = v->c; c->args = v->args;
        c->width = w;
        return c;
    }

    /* Emit a store to a recovered variable / memory location (a real statement). */
    void emit_store(Block& b, ExprP lhs, ExprP rhs, uint64_t addr) {
        Stmt s; s.kind = SK::Assign; s.lhs = lhs; s.rhs = fold(rhs); s.addr = addr;
        b.stmts.push_back(std::move(s));
    }

    /* A 128-bit SIMD store (movups/movaps/movdqu of an xmm to memory) copies all
     * 16 bytes — emitting a single scalar store dropped 12 (a `movups [ctx],xmm0`
     * ImVec4/rect copy became `*(int*)ctx = *a1`). Split it into two 8-byte halves
     * when the source is a memory load or a constant: always compiles (plain
     * `long long`, no 128-bit type), and is behavior-faithful. Returns false (caller
     * falls back to the scalar store) when the source can't be cleanly halved. */
    bool emit_simd16_store(Block& b, const cs_x86_op& dst, ExprP src, uint64_t addr) {
        int w = 16; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, w, isr, r, wreg);
        if (isr || !lv || lv->kind != EK::Mem || !lv->a) return false;
        ExprP slo, shi;
        if (src && src->kind == EK::Mem && src->a) {
            slo = mkMem(clone(src->a), 8);
            shi = mkMem(mkBinary("+", clone(src->a), mkConst(8, 8), 8), 8);
        } else if (src && src->kind == EK::Const) {
            slo = mkConst(src->cval, 8); shi = mkConst(0, 8);
        } else return false;
        ExprP daddr = lv->a;
        emit_store(b, mkMem(clone(daddr), 8), slo, addr);
        emit_store(b, mkMem(mkBinary("+", clone(daddr), mkConst(8, 8), 8), 8), shi, addr);
        return true;
    }

    /* A 128-bit store whose FOUR 32-bit float lanes were tracked through packed-
     * float ops (mulps/addps/shufps). Emits four faithful `*(float*)(d + 4*i)`
     * stores — the packed-float analogue of the 2x64 lane store. */
    bool emit_simd16_store_flanes(Block& b, const cs_x86_op& dst, ExprP f[4], uint64_t addr) {
        int w = 16; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, w, isr, r, wreg);
        if (isr || !lv || lv->kind != EK::Mem || !lv->a) return false;
        for (int i = 0; i < 4; ++i) if (!f[i]) return false;
        ExprP daddr = lv->a;
        for (int i = 0; i < 4; ++i) {
            ExprP a = (i == 0) ? clone(daddr)
                     : mkBinary("+", clone(daddr), mkConst(4 * i, 8), 8);
            ExprP m = mkMem(a, 4, false); m->is_float = true;
            emit_store(b, m, f[i], addr);
        }
        return true;
    }

    /* A 128-bit store whose FOUR 32-bit INT lanes were tracked through packed-int
     * ops (pmulld/paddd/...): commit four faithful `*(int*)(p + 4i) = lane` stores. */
    bool emit_simd16_store_ilanes(Block& b, const cs_x86_op& dst, ExprP f[4], uint64_t addr) {
        int w = 16; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, w, isr, r, wreg);
        if (isr || !lv || lv->kind != EK::Mem || !lv->a) return false;
        for (int i = 0; i < 4; ++i) if (!f[i]) return false;
        ExprP daddr = lv->a;
        for (int i = 0; i < 4; ++i) {
            ExprP a = (i == 0) ? clone(daddr)
                     : mkBinary("+", clone(daddr), mkConst(4 * i, 8), 8);
            emit_store(b, mkMem(a, 4, false), f[i], addr);   /* *(int*)(p+4i) = lane */
        }
        return true;
    }
    /* Stock the packed-INT side-channel from a raw movdqu load (real=false: int-vs-
     * float ambiguous until a packed op reads it). */
    void populate_xmm_i(Reg r, ExprP f[4]) {
        if (!is_xmm(r)) return;
        for (int k = 0; k < 4; ++k) xmm_i[r][k] = f[k] ? fold(clone(f[k])) : nullptr;
        xmm_i_real[r] = false;
    }

    /* --- 2-lane (8-byte `movq`) packed-int side-channel. MSVC emits a movq /
     * paddd / movq loop as the 2-wide remainder after the 16-byte main loop
     * (iadd/isub `a[i]+=b[i]`, n not a multiple of 4). Modeled with the LOW two
     * xmm_i lanes only; lanes 2,3 stay null. --- */
    void populate_xmm_i2(Reg r, ExprP f0, ExprP f1) {
        if (!is_xmm(r)) return;
        xmm_i[r][0] = f0 ? fold(clone(f0)) : nullptr;
        xmm_i[r][1] = f1 ? fold(clone(f1)) : nullptr;
        xmm_i[r][2] = nullptr; xmm_i[r][3] = nullptr;
        xmm_i_real[r] = false;
    }
    /* Recover the low TWO int32 lanes of an 8-byte packed-int operand (a tracked
     * xmm with lanes 0,1, or an 8-byte memory load). Returns false otherwise. */
    bool xmm_i_lanes2(const cs_x86_op& op, ExprP out[2]) {
        out[0] = out[1] = nullptr;
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            if (!is_xmm(r) || !xmm_i[r][0] || !xmm_i[r][1]) return false;
            out[0] = clone(xmm_i[r][0]); out[1] = clone(xmm_i[r][1]);
            return true;
        }
        if (op.type == X86_OP_MEM) {
            ExprP m0 = rvalue(op);
            if (m0 && m0->kind == EK::Mem && m0->a) {
                out[0] = mkMem(clone(m0->a), 4, false);
                out[1] = mkMem(mkBinary("+", clone(m0->a), mkConst(4, 8), 8), 4, false);
                return true;
            }
        }
        return false;
    }
    /* Set the low two int lanes from a 2-wide packed op; mark real so a following
     * `movq m64, xmm` commits two `*(int*)` lanes. */
    void set_xmm_i2(Reg r, ExprP i0, ExprP i1, Block& b) {
        if (!is_xmm(r)) return;
        clear_xmm_f(r);
        xmm_i[r][0] = i0 ? cap_lane(fold(clone(i0)), b) : nullptr;
        xmm_i[r][1] = i1 ? cap_lane(fold(clone(i1)), b) : nullptr;
        xmm_i[r][2] = nullptr; xmm_i[r][3] = nullptr;
        xmm_i_real[r] = true;
        regfile[r] = i0 ? cap_lane(fold(clone(i0)), b) : nullptr;
        regfile_hi[r] = nullptr;
    }
    /* An 8-byte store whose low two 32-bit int lanes were tracked through a 2-wide
     * packed-int op: emits two faithful `*(int*)(d + 4i)` stores. */
    bool emit_simd8_store_ilanes(Block& b, const cs_x86_op& dst, ExprP f[2], uint64_t addr) {
        int w = 8; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, w, isr, r, wreg);
        if (isr || !lv || lv->kind != EK::Mem || !lv->a) return false;
        if (!f[0] || !f[1]) return false;
        ExprP daddr = lv->a;
        emit_store(b, mkMem(clone(daddr), 4, false), f[0], addr);
        emit_store(b, mkMem(mkBinary("+", clone(daddr), mkConst(4, 8), 8), 4, false), f[1], addr);
        return true;
    }

    /* A 128-bit store whose two 64-bit lanes were tracked through packed ops
     * (lo/hi already computed). Splits into two faithful 8-byte lane stores. */
    bool emit_simd16_store_lanes(Block& b, const cs_x86_op& dst, ExprP lo, ExprP hi, uint64_t addr) {
        int w = 16; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, w, isr, r, wreg);
        if (isr || !lv || lv->kind != EK::Mem || !lv->a) return false;
        ExprP daddr = lv->a;
        emit_store(b, mkMem(clone(daddr), 8), lo, addr);
        emit_store(b, mkMem(mkBinary("+", clone(daddr), mkConst(8, 8), 8), 8), hi, addr);
        return true;
    }

    /* Recover the two 64-bit lanes of a 128-bit SIMD source operand (a tracked xmm
     * register, or a 16-byte memory load split into lo/hi halves). Returns true
     * only when BOTH lanes are known. */
    /* A 16-byte load from a READ-ONLY image address (a compiler-materialized const
     * vector in .rdata) as its two 64-bit lanes. The scalar image reader collapses a
     * 16-byte load to ONE Const (low 8 bytes only), and the store then zeroes the high
     * half — losing half the constant array. Read BOTH 8-byte halves so both lanes
     * commit as real constants (correct AND recompilable, no absolute derefs). */
    bool image_const_lanes(const cs_x86_op& op, ExprP& lo, ExprP& hi) {
        if (op.type != X86_OP_MEM) return false;
        const x86_op_mem& m = op.mem;
        if (m.index != X86_REG_INVALID) return false;
        uint64_t abs;
        if (m.base == X86_REG_RIP) abs = cur_insn_addr + cur_insn_size + (uint64_t)m.disp;
        else if (m.base == X86_REG_INVALID && m.segment == X86_REG_INVALID) abs = (uint64_t)m.disp;
        else return false;
        if (addr_writable(abs)) return false;   /* a mutable global is not a constant */
        int64_t a = 0, b = 0;
        if (!read_i64(abs, a) || !read_i64(abs + 8, b)) return false;
        lo = mkConst(a, 8); hi = mkConst(b, 8);
        return true;
    }
    bool simd_src_lanes(const cs_x86_op& op, ExprP& lo, ExprP& hi) {
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            if (!is_xmm(r)) return false;
            lo = xmm_lo(r); hi = xmm_hi(r);
            return lo && hi;
        }
        if (op.type == X86_OP_MEM) {
            if (image_const_lanes(op, lo, hi)) return true;
            ExprP m = rvalue(op);
            if (m && m->kind == EK::Mem && m->a) {
                lo = mkMem(clone(m->a), 8);
                hi = mkMem(mkBinary("+", clone(m->a), mkConst(8, 8), 8), 8);
                return true;
            }
        }
        return false;
    }
    /* Lane 0 (low 64 bits) of a SIMD source operand, or null if unknown. */
    ExprP simd_lane0(const cs_x86_op& op) {
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            return is_xmm(r) ? xmm_lo(r) : nullptr;
        }
        if (op.type == X86_OP_MEM) {
            ExprP m = rvalue(op);
            if (m && m->kind == EK::Mem && m->a) return mkMem(clone(m->a), 8);
        }
        return nullptr;
    }

    /* Build the lvalue for a destination operand; returns null for reg dst. */
    ExprP store_lvalue(const cs_x86_op& op, int& width, bool& is_reg, Reg& which, int& wreg) {
        is_reg = false; which = R_NONE; wreg = 0;
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            is_reg = true; which = r; wreg = w; width = w; return nullptr;
        }
        if (op.type == X86_OP_MEM) {
            width = op.size ? op.size : 4;
            const x86_op_mem& m = op.mem;
            if (m.base == X86_REG_RIP && m.index == X86_REG_INVALID) {
                uint64_t abs = cur_insn_addr + cur_insn_size + (uint64_t)m.disp;
                return mkMem(mkConst((int64_t)abs, 8), width);
            }
            Reg base = R_NONE, index = R_NONE; int t;
            if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
            if (m.index != X86_REG_INVALID) map_reg(m.index, index, t);
            if (index == R_NONE && base != R_RIP) {
                int64_t norm;
                if (normalise_slot(base, m.disp, norm)) {
                    /* store into an address-escaped aggregate field -> memory store
                     * into `sN`, so the pre-call init (zeroing, byte/movdqu fills)
                     * the callee reads is preserved, not dropped as a dead scalar. */
                    if (!param_home_off.count(norm)) {
                        if (const AggRegion* r = agg_region_for(norm))
                            return mkMem(agg_addr(*r, norm), width);
                    }
                    std::string nm = resolved_slot_name(norm, width);
                    record_width(nm, width);
                    return mkVar(nm, width);
                }
            }
            /* stack-array store: *(T*)(&buf + index*scale) = val */
            if (index != R_NONE) {
                int64_t norm;
                if (normalise_slot(base, m.disp, norm)) {
                    if (!param_home_off.count(norm)) {
                        if (const AggRegion* r = agg_region_for(norm))
                            return mkMem(agg_indexed(*r, norm, index, m.scale), width);
                    }
                    return mkMem(stack_array_addr(norm, index, m.scale), width);
                }
            }
            return mem_to_expr(op, width, regfile);
        }
        return nullptr;
    }

    /* Before a store to memory, any register whose cached value was READ from the
     * SAME address must be spilled to a temp — otherwise the cached memory-load
     * expression silently re-reads the just-overwritten cell. This is the swap
     * bug: `r9 = a[i]; a[i] = a[j]; a[j] = r9` lifted as `a[j] = a[i]` after a[i]
     * was clobbered (both elements ended up equal, destroying every quicksort/
     * heapsort/partition swap). Materialize the snapshot so the deferred use reads
     * the OLD value. Spilling is always value-preserving; dead temps are DSE'd. */
    void clobber_mem_before_store(Block& b, const ExprP& storeAddr, uint64_t addr) {
        if (!storeAddr) return;
        for (int r = R_RAX; r < R_COUNT; ++r) {
            if (r == R_RSP || r == R_RIP) continue;
            /* RBP is a GENERAL register under /O2 (no frame pointer): it routinely
             * holds a memory load (sl_insert keeps `idx = sl->count` in rbp). Skip
             * it only when it is the frame base; a frame-base rbp is an EK::Reg and
             * is filtered out below anyway. Skipping it unconditionally left a
             * post-increment's old value re-read from the just-overwritten cell
             * (sl_insert stored idx+1 into the back-links and returned idx+1). */
            if (r == R_RBP && uses_rbp_frame) continue;
            ExprP cur = regfile[r];
            if (!cur || cur->kind == EK::Var || cur->kind == EK::Const ||
                cur->kind == EK::Reg) continue;
            if (!expr_loads_addr(cur, storeAddr)) continue;
            std::string tn = "t" + std::to_string(++temp_seq);
            spill_temps.insert(tn);
            int cw = cur->width >= 8 ? 8 : 4;
            var_width[tn] = cw; if (cw == 8) var_is_ll[tn] = true;
            if (cur->is_float) var_is_float[tn] = true;
            Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, cw);
            s.rhs = fold(clone(cur)); s.addr = addr;
            b.stmts.push_back(std::move(s));
            regfile[r] = mkVar(tn, cw);
        }
    }

    /* Generic dst = value: register => map update; mem/var => statement. */
    void do_dst(Block& b, const cs_x86_op& dst, ExprP val, uint64_t addr) {
        int width = 4; bool isr; Reg r; int wreg;
        ExprP lv = store_lvalue(dst, width, isr, r, wreg);
        /* NOTE (deferred): a raw FLOAT landing in a GP register via `movss [slot],xmm;
         * mov eax,[slot]` (union/bit-cast — isnan/frexp/signbit) is a bit reinterpret
         * `*(int*)&f`, decompiled here as a value conversion. Fixing it needs SLOT-level
         * float tracking (the int-read value carries no is_float at lift), unlike the movd
         * register form (handled). mathclassify.dll's 18 spill-reload fails are this class. */
        if (isr) { set_reg(r, wreg, val, b); return; }
        if (lv) {
            ExprP sv = truncate(val, width);
            /* storing a float value through a pointer makes the target a float
             * deref (`*(float*)`), so the destination pointer is float* too. */
            if (lv->kind == EK::Mem && val && val->is_float) {
                lv->is_float = true;
                if (sv) sv->is_float = true;
            }
            if (lv->kind == EK::Mem && lv->a)
                clobber_mem_before_store(b, lv->a, addr);
            emit_store(b, lv, sv, addr);
        }
    }

    /* Freeze an expression into a fresh `t<N> = <expr>;` statement and return a Var
     * for it. For an atomic RMW (xchg/cmpxchg) whose destination is memory, the
     * swapped-out register half, the ZF flag, and rax must all see the PRE-store
     * value — but the memory operand is a re-reading expression (`*(T*)addr` / a
     * `#define` global), so after the store it would read back the NEW value and
     * invert the lock logic. Snapshotting the old value first keeps them consistent. */
    ExprP snapshot_to_temp(Block& b, ExprP v, int w, uint64_t addr) {
        std::string tn = "t" + std::to_string(++temp_seq);
        spill_temps.insert(tn);
        int cw = w >= 8 ? 8 : 4;
        var_width[tn] = cw; if (cw >= 8) var_is_ll[tn] = true;
        Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, cw); s.rhs = fold(v); s.addr = addr;
        b.stmts.push_back(std::move(s));
        return mkVar(tn, cw);
    }

    /* ----- flag / condition recovery ----- */
