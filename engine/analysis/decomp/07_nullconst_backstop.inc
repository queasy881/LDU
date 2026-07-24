/* 07_nullconst_backstop.inc -- NULL consts, unknown-value backstop, mem addressing
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    ExprP pack_two_floats(ExprP lo, ExprP hi, Block& b) {
        auto bits = [&](ExprP lane) -> ExprP {
            ExprP lv = lane;
            if (!lane || lane->kind != EK::Var) {
                std::string tn = "t" + std::to_string(++temp_seq);
                spill_temps.insert(tn);
                var_width[tn] = 4; var_is_float[tn] = true;
                Stmt s; s.kind = SK::Assign; s.lhs = mkVar(tn, 4); s.lhs->is_float = true;
                s.rhs = lane; b.stmts.push_back(std::move(s));
                lv = mkVar(tn, 4); lv->is_float = true;
            }
            /* the lane's own type stays `float`; `&lane` is only reinterpreted here,
             * which must not mark it a pointer. */
            force_float_vars.insert(lv->name);
            ExprP m = mkMem(mkAddrOf(clone(lv)), 4, true);   /* *(unsigned int*)&lv */
            return m;
        };
        ExprP hib = mkCast("(long long)", bits(hi), 8, false);
        ExprP shifted = mkBinary("<<", hib, mkConst(32, 8), 8);
        return mkBinary("|", shifted, bits(lo), 8);
    }
    ExprP packed_flane(const std::string& v, int off) {
        packed_gp_vars.insert(v);
        ExprP addr = mkAddrOf(mkVar(v, 8));
        if (off) addr = mkBinary("+", mkCast("(char*)", addr, 8), mkConst(off, 8), 8);
        ExprP m = mkMem(addr, 4, false);
        m->is_float = true;
        return m;
    }
    /* Lookahead: does `movq xmm,r64` at insn index `i` feed a SINGLE-precision float
     * op (movss/addss/.../unpcklps/cvtss2sd) — i.e. the reg held 2 packed floats, not
     * a scalar double or an integer SIMD value? Bounded scan of the next insns. */
    bool movq_feeds_single_float(size_t i) {
        for (size_t j = i + 1; j < insns.size() && j < i + 16; ++j) {
            switch (insns[j].id) {
                case X86_INS_MOVSS: case X86_INS_ADDSS: case X86_INS_SUBSS:
                case X86_INS_MULSS: case X86_INS_DIVSS: case X86_INS_UNPCKLPS:
                case X86_INS_CVTSS2SD: case X86_INS_COMISS: case X86_INS_UCOMISS:
                case X86_INS_MAXSS: case X86_INS_MINSS: case X86_INS_SQRTSS:
                    return true;
                case X86_INS_ADDSD: case X86_INS_MULSD:
                case X86_INS_SUBSD: case X86_INS_DIVSD:
                    /* scalar-double ARITHMETIC first => it was a double, not 2 floats.
                     * (movss/movsd MOVES are spills/reloads of the packed pair — NOT a
                     * disambiguating signal, so they are skipped.) */
                    return false;
                default: break;
            }
        }
        return false;
    }

    /* Does GP register `dr` (just written by `movd r,xmm`) get consumed by an
     * integer BIT op (and/or/xor/shl/shr/sar) before being overwritten? Marks the
     * `movd r,xmm` as a float-BITS reinterpret (`*(int*)&f`), not a value cast —
     * exponent/mantissa tests, and the Dekker split `movd r,xmm; and r,mask`. */
    bool gpr_bits_int_op(size_t i, Reg dr) {
        for (size_t j = i + 1; j < insns.size() && j < i + 6; ++j) {
            const cs_x86& xj = insns[j].x86;
            bool uses = false, writes_only = false;
            for (int k = 0; k < xj.op_count; ++k) {
                if (xj.operands[k].type != X86_OP_REG) continue;
                Reg r; int w; map_reg(xj.operands[k].reg, r, w);
                if (r == dr) uses = true;
            }
            if (!uses) continue;
            switch (insns[j].id) {
                case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR:
                case X86_INS_SHL: case X86_INS_SHR: case X86_INS_SAR:
                case X86_INS_SHLD: case X86_INS_SHRD:
                    return true;
                default: (void)writes_only; return false;   /* first use is not a bit op */
            }
        }
        return false;
    }

    /* Does xmm `dr` (just written by `movd xmm,r`) get consumed FIRST by a scalar
     * FLOAT op — i.e. the GP bits it received are a float value (`*(float*)&t`),
     * the write side of the Dekker split. A packed/integer/other first use => no. */
    bool xmm_bits_scalar_float(size_t i, Reg dr) {
        for (size_t j = i + 1; j < insns.size() && j < i + 8; ++j) {
            const cs_x86& xj = insns[j].x86;
            bool uses = false;
            for (int k = 0; k < xj.op_count; ++k) {
                if (xj.operands[k].type != X86_OP_REG) continue;
                Reg r; int w; map_reg(xj.operands[k].reg, r, w);
                if (r == dr) uses = true;
            }
            if (!uses) continue;
            switch (insns[j].id) {
                case X86_INS_ADDSS: case X86_INS_SUBSS: case X86_INS_MULSS:
                case X86_INS_DIVSS: case X86_INS_COMISS: case X86_INS_UCOMISS:
                case X86_INS_MAXSS: case X86_INS_MINSS: case X86_INS_SQRTSS:
                case X86_INS_CVTSS2SD: case X86_INS_CVTSS2SI: case X86_INS_CVTTSS2SI:
                case X86_INS_ADDSD: case X86_INS_SUBSD: case X86_INS_MULSD:
                case X86_INS_DIVSD: case X86_INS_COMISD: case X86_INS_UCOMISD:
                case X86_INS_MAXSD: case X86_INS_MINSD: case X86_INS_SQRTSD:
                case X86_INS_VADDSS: case X86_INS_VSUBSS: case X86_INS_VMULSS:
                case X86_INS_VDIVSS: case X86_INS_VCOMISS: case X86_INS_VUCOMISS:
                case X86_INS_VMAXSS: case X86_INS_VMINSS: case X86_INS_VSQRTSS:
                case X86_INS_VCVTSS2SD:
                case X86_INS_VADDSD: case X86_INS_VSUBSD: case X86_INS_VMULSD:
                case X86_INS_VDIVSD: case X86_INS_VFMADD213SS: case X86_INS_VFNMADD213SS:
                case X86_INS_VFMSUB213SS: case X86_INS_VFNMSUB213SS:
                case X86_INS_VFMADD231SS: case X86_INS_VFNMADD231SS:
                case X86_INS_VFMADD132SS: case X86_INS_VFNMADD132SS:
                    return true;
                default: return false;   /* first use is packed / integer / move */
            }
        }
        return false;
    }

    /* pending flag source from cmp/test/arith for the following jcc/setcc */
    struct FlagSrc {
        bool valid = false;
        bool is_cmp = false;
        bool is_test = false;
        bool is_arith = false;
        bool is_bt = false;    /* CF = the tested bit (a); jb/jc => set, jae/jnc => clear */
        bool is_fcmp = false;  /* comiss/ucomiss: float compare, unsigned jcc => ordering */
        ExprP a, b;
        int width = 4;
        /* EXPLICIT CARRY-OUT value (null = derive CF from the kind above). A shift by an
         * immediate records the bit it shifted out here, so a following RCL/RCR (rotate
         * THROUGH carry) can read the real incoming CF -- the multi-precision `shl lo,1;
         * rcl hi,1` / `shr hi,1; rcr lo,1` idioms -- and so a `jc`/`jnc` on a shift's carry
         * is exact instead of the is_arith fallback. Cleared automatically by `flags =
         * FlagSrc()`, so any intervening flag-writer (cmp/test/add) drops it; a non-flag op
         * (mov/lea) preserves it, exactly as the hardware leaves CF untouched. */
        ExprP cf;
    };
    FlagSrc flags;
    std::vector<FlagSrc> block_flags_out;   /* flag state at each block's exit */

    /* two flag sources are equivalent iff same kind and same compared operands —
     * lets a merge block inherit a condition when every predecessor agrees. */
    bool flagsrc_equal(const FlagSrc& x, const FlagSrc& y) {
        if (x.valid != y.valid) return false;
        if (!x.valid) return true;
        if (x.is_cmp != y.is_cmp || x.is_test != y.is_test ||
            x.is_arith != y.is_arith || x.is_bt != y.is_bt ||
            x.is_fcmp != y.is_fcmp || x.width != y.width) return false;
        if ((bool)x.cf != (bool)y.cf) return false;
        if (x.cf && !exprEqual(x.cf, y.cf)) return false;
        return exprEqual(x.a, y.a) && exprEqual(x.b, y.b);
    }

    uint64_t cur_insn_addr = 0;
    int cur_insn_seg = 0;   /* current insn segment override: 0 none, 1 gs, 2 fs */
    const Insn* prev_insn = nullptr;   /* instruction lifted just before this one */

    /* `xor reg, rsp` — the stack-canary verification idiom (`mov reg,[cookie];
     * xor reg,rsp; call __security_check_cookie`). A call right after it is the
     * cookie check even when the target has no symbol name. */
    bool is_cookie_xor(const Insn* in) {
        if (!in || in->id != X86_INS_XOR || in->x86.op_count != 2) return false;
        if (in->x86.operands[0].type != X86_OP_REG ||
            in->x86.operands[1].type != X86_OP_REG) return false;
        Reg a, b2; int wa, wb; map_reg(in->x86.operands[0].reg, a, wa);
        map_reg(in->x86.operands[1].reg, b2, wb);
        return b2 == R_RSP && a != R_RSP;
    }
    std::set<uint64_t> cookie_call_addrs;   /* dropped stack-cookie-check calls */
    /* Precompute the addresses of stack-cookie-check calls (`xor reg,rsp; call`)
     * so BOTH lifting and liveness ignore them. If only lifting drops the call,
     * liveness still counts its implicit rax-def, marks rax not-live-in at the
     * epilogue merge, and skips the rax phi — losing the real return value. */
    /* Stores that write the PROLOGUE stack cookie — suppressed when lifting.
     *
     * `is_cookie_xor` deliberately models `xor reg,rsp` as a no-op, which is right
     * for the epilogue CHECK (`xor rcx,rsp; call __security_check_cookie`, whose
     * value is only compared and whose call is dropped anyway). But the canonical
     * prologue is
     *     mov rax, [__security_cookie]
     *     xor rax, rsp                 <- modelled as a no-op
     *     mov [rsp+0x48], rax          <- so this stores the RAW cookie
     * and that store IS emitted, as `field_28 = qword_bf230;` — a value the machine
     * never writes, since the real one is mixed with rsp. Modelling the xor
     * faithfully is not an option either: rsp is a frame base with no C spelling.
     *
     * The whole sequence is compiler housekeeping with no effect on recovered
     * semantics — the epilogue check is already dropped — so the store is dropped
     * with it. Silence beats a confidently wrong value. */
    std::set<uint64_t> cookie_store_addrs;

    void scan_cookie_calls() {
        for (size_t i = 1; i < insns.size(); ++i) {
            if (insns[i].is_call && is_cookie_xor(&insns[i-1]))
                cookie_call_addrs.insert(insns[i].addr);
            /* `xor reg,rsp` immediately followed by a store of that same reg to a
             * stack slot: the prologue cookie write. */
            if (!is_cookie_xor(&insns[i-1])) continue;
            const cs_x86& xr = insns[i-1].x86;
            Reg cr; int crw; map_reg(xr.operands[0].reg, cr, crw);
            const cs_x86& st = insns[i].x86;
            if (insns[i].id != X86_INS_MOV || st.op_count != 2) continue;
            if (st.operands[0].type != X86_OP_MEM || st.operands[1].type != X86_OP_REG) continue;
            Reg sr; int srw; map_reg(st.operands[1].reg, sr, srw);
            if (sr != cr) continue;
            Reg mb = R_NONE; int mbw;
            if (st.operands[0].mem.base != X86_REG_INVALID)
                map_reg(st.operands[0].mem.base, mb, mbw);
            if (mb != R_RSP && mb != R_RBP) continue;
            cookie_store_addrs.insert(insns[i].addr);
        }
    }
    uint32_t cur_insn_size = 0;

    /* Get the symbolic value of a register (folded). Width-truncate as needed. */
    static bool is_nonvol_gpr(Reg r) {
        return r==R_RBX||r==R_RBP||r==R_RSI||r==R_RDI||
               r==R_R12||r==R_R13||r==R_R14||r==R_R15;
    }
    static const char* reg_abi_name(Reg r) {
        static const char* N[R_COUNT] = {
            "NONE",
            "RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
            "R8","R9","R10","R11","R12","R13","R14","R15",
            "XMM0","XMM1","XMM2","XMM3","XMM4","XMM5","XMM6","XMM7",
            "XMM8","XMM9","XMM10","XMM11","XMM12","XMM13","XMM14","XMM15",
            "RIP"
        };
        return (r > R_NONE && r < R_COUNT) ? N[r] : "REG";
    }
    static bool is_xmm(Reg r) { return r >= R_XMM0 && r <= R_XMM15; }
    /* Win64 callee-saved (nonvolatile) SSE registers: xmm6..xmm15. Saved in the
     * prologue (movups/movaps to the frame) and restored in the epilogue. */
    static bool is_nonvol_xmm(Reg r) { return r >= R_XMM6 && r <= R_XMM15; }
    std::map<Reg,std::string> unknown_reg_name;
    std::map<std::string,std::string> named_globals;  /* qword_174148 -> (*(long long*)0x174148) */
    std::map<std::string,std::string> global_struct_local;  /* qword_174148 -> local `gs_174148` (read-only global struct base cached in a typed local) */
    int unknown_value_count = 0;   /* PERMANENT-INVARIANT backstop firings: how
                                    * many distinct values the dataflow could not
                                    * reconstruct. Kept visible so a clean census
                                    * means "recovered OR honestly named", never
                                    * "faked". */
    /* THE BACKSTOP. A value the dataflow could not reconstruct is emitted as a
     * clean DECLARED local using Ghidra's `in_<REG>` convention (the value the
     * register held on input) — NEVER a `ctx_` sentinel and NEVER a literal-0
     * pointer base (`*(0+off)` null deref). This is the permanent guarantee: those
     * two artifacts are structurally unable to reach the output, on ANY input,
     * forever. Stable per register so every read of one lost value shares a name. */
    ExprP unknown_reg_value(Reg r, int w) {
        auto it = unknown_reg_name.find(r);
        std::string nm;
        if (it != unknown_reg_name.end()) nm = it->second;
        else {
            nm = std::string("in_") + reg_abi_name(r);
            unknown_reg_name[r] = nm;
            record_width(nm, w >= 8 ? 8 : 4);
            if (w >= 8) var_is_ll[nm] = true;
            if (is_xmm(r)) var_is_float[nm] = true;   /* declare float, not int */
            ++unknown_value_count;
        }
        return mkVar(nm, w >= 8 ? 8 : 4);
    }

    /* an opaque `in_<REG>` placeholder (a lost incoming/callee-saved value). */
    static bool is_ctx_value(const ExprP& e) {
        return e && e->kind == EK::Var && e->name.rfind("in_", 0) == 0;
    }

    /* Label an UNMAPPED capstone register — one map_reg does not model at all, so it has
     * no Reg id and collapses to R_NONE: ymm/zmm, mmx, mask, segment, control, debug, x87.
     * Keyed on the CAPSTONE id, because every one of them maps to the single R_NONE value
     * and naming them off that would merge ymm0 and ymm1 into one variable. */
    static std::string cs_reg_label(unsigned cr) {
        char b[24];
        if (cr >= X86_REG_YMM0 && cr <= X86_REG_YMM15) { snprintf(b, sizeof b, "YMM%u", cr - X86_REG_YMM0); return b; }
        if (cr >= X86_REG_ZMM0 && cr <= X86_REG_ZMM31) { snprintf(b, sizeof b, "ZMM%u", cr - X86_REG_ZMM0); return b; }
        if (cr >= X86_REG_MM0  && cr <= X86_REG_MM7)   { snprintf(b, sizeof b, "MM%u",  cr - X86_REG_MM0);  return b; }
        if (cr >= X86_REG_K0   && cr <= X86_REG_K7)    { snprintf(b, sizeof b, "K%u",   cr - X86_REG_K0);   return b; }
        if (cr >= X86_REG_ST0  && cr <= X86_REG_ST0 + 7) { snprintf(b, sizeof b, "ST%u", cr - X86_REG_ST0); return b; }
        switch (cr) {
            case X86_REG_ES: return "ES";  case X86_REG_CS: return "CS";
            case X86_REG_SS: return "SS";  case X86_REG_DS: return "DS";
            case X86_REG_FS: return "FS";  case X86_REG_GS: return "GS";
            default: break;
        }
        snprintf(b, sizeof b, "REG%u", cr);
        return b;
    }
    std::map<unsigned,std::string> unknown_csreg_name;
    /* The R_NONE sibling of unknown_reg_value. Same contract: a value the dataflow cannot
     * reconstruct becomes a NAMED, DECLARED local — never a literal. Stable per capstone
     * register so every read of the same lost value shares one name, and counted in
     * unknown_value_count so the confidence header reports it as a phantom live-in. */
    ExprP unknown_csreg_value(unsigned cr, int w) {
        int cw = (w >= 8) ? 8 : (w > 0 ? w : 8);
        auto it = unknown_csreg_name.find(cr);
        std::string nm;
        if (it != unknown_csreg_name.end()) nm = it->second;
        else {
            nm = "in_" + cs_reg_label(cr);
            unknown_csreg_name[cr] = nm;
            record_width(nm, cw >= 8 ? 8 : 4);
            if (cw >= 8) var_is_ll[nm] = true;
            ++unknown_value_count;
        }
        return mkVar(nm, cw >= 8 ? 8 : 4);
    }

    /* Promote a leaked ARG-register backstop to its PARAMETER. `in_RCX` means "the
     * value rcx held on input" — which, by the Win64 ABI, IS the first integer
     * argument a1 (rdx->a2, r8->a3, r9->a4; xmm0-3 -> a1-a4 float). So an
     * `in_<argreg>` that survived recovery is exactly a missed parameter; renaming
     * it to aN and declaring the parameter is the CORRECT fix, not a cosmetic one,
     * and eliminates the backstop. The corpus has zero leaks, so this only ever
     * fires on real binaries — never perturbing the 484/0 gate. */
    void promote_leaked_arg_params() {
        /* only promote a leak that ACTUALLY survives into the emitted IR (a trailing
         * `in_R8`/`in_R9` trimmed off a call by trim_phantom_call_args still lingers
         * in unknown_reg_name but must NOT invent params a3/a4). */
        /* A leak only counts as a FUNCTION INPUT if it is read on a path the
         * function itself can take. A block unreachable from the entry — an SEH /
         * C++ EH funclet placed inside the function's address range — is entered by
         * the OS unwinder, and the registers live at its head are supplied by the
         * unwinder, not by the caller. Promoting those invented a trailing
         * parameter out of thin air: kernel32 s_AslpFileGetCrcChecksum's __except
         * handler reads eax (the exception code) and the function grew a bogus
         * third argument. Uses in unreachable blocks still reach
         * scrub_in_placeholders, which gives them an ordinary declared local. */
        std::vector<char> reach(blocks.size(), 0);
        {
            int eb = entry_block();
            std::vector<int> st;
            if (eb >= 0 && eb < (int)blocks.size()) { reach[eb] = 1; st.push_back(eb); }
            while (!st.empty()) {
                int b = st.back(); st.pop_back();
                for (int s : blocks[b].succ)
                    if (s >= 0 && s < (int)blocks.size() && !reach[s]) { reach[s] = 1; st.push_back(s); }
            }
        }
        std::set<std::string> used;
        std::function<void(const ExprP&)> mark = [&](const ExprP& e){
            if (!e) return;
            if (e->kind == EK::Var) used.insert(e->name);
            mark(e->a); mark(e->b); mark(e->c);
            for (auto& ar : e->args) mark(ar);
        };
        for (auto& b : blocks) {
            if (b.id >= 0 && b.id < (int)reach.size() && !reach[b.id]) continue;
            for (auto& s : b.stmts) { mark(s.lhs); mark(s.rhs); }
            mark(b.cond); mark(b.ret_value); mark(b.ret_raw); mark(b.switch_var); mark(b.tail_call);
        }
        struct AR { Reg r; int pos; bool fl; };
        static const AR ARGS[8] = {
            {R_RCX,0,false},{R_RDX,1,false},{R_R8,2,false},{R_R9,3,false},
            {R_XMM0,0,true},{R_XMM1,1,true},{R_XMM2,2,true},{R_XMM3,3,true}
        };
        for (const AR& a : ARGS) {
            auto it = unknown_reg_name.find(a.r);
            if (it == unknown_reg_name.end()) continue;
            std::string leak = it->second;   /* "in_RCX" / "in_XMM2" ... */
            if (!used.count(leak)) continue;   /* trimmed/phantom — don't invent a param */
            std::string pn = "a" + std::to_string(a.pos + 1);
            if (a.pos + 1 > num_params) num_params = a.pos + 1;
            if (a.fl) is_float_param[a.pos] = true;
            record_width(pn, a.fl ? 4 : 8);
            if (a.fl) var_is_float[pn] = true; else var_is_ll[pn] = true;
            ExprP pv = mkVar(pn, a.fl ? 4 : 8); if (a.fl) pv->is_float = true;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) { s.lhs = subst_named_var(s.lhs, leak, pv); s.rhs = subst_named_var(s.rhs, leak, pv); }
                b.cond = subst_named_var(b.cond, leak, pv);
                b.ret_value = subst_named_var(b.ret_value, leak, pv);
                b.switch_var = subst_named_var(b.switch_var, leak, pv);
                b.tail_call = subst_named_var(b.tail_call, leak, pv);
            }
            unknown_reg_name.erase(a.r);   /* no longer declared as a backstop */
        }
        /* Any STILL-surviving leak is a register the function reads on ENTRY by a
         * non-standard, hand-written convention that the ABI arg-register promotion
         * above did not cover: __chkstk takes its allocation size in rax; setjmp
         * saves the caller's callee-saved rbx/rsi/rdi/rbp into the jmp_buf; an SEH
         * trampoline restores and tail-jumps to the caller's rbp (`pop rbp; jmp
         * rbp`). Each is a genuine INPUT, so promote it to a trailing parameter and
         * rename every use — the honest, compilable form (mirrors IDA naming `_RBX`
         * as an input) — instead of leaving an uninitialized `in_<REG>` local. This
         * drives the residual backstop-leak count to zero. Corpus functions never
         * reach here (they have no surviving leak), so the gate is untouched. */
        std::vector<std::pair<Reg,std::string>> rest;
        for (auto& kv : unknown_reg_name)
            if (used.count(kv.second)) rest.push_back({kv.first, kv.second});
        std::sort(rest.begin(), rest.end(),
                  [](const std::pair<Reg,std::string>& a, const std::pair<Reg,std::string>& b){
                      return a.first < b.first; });
        for (auto& pr : rest) {
            const std::string& leak = pr.second;
            int idx = num_params;                 /* next 0-based param slot */
            std::string pn = "a" + std::to_string(idx + 1);
            num_params = idx + 1;
            int w = var_width.count(leak) ? var_width[leak] : 8;
            record_width(pn, w >= 8 ? 8 : 4);
            if (w >= 8) var_is_ll[pn] = true;
            /* carry pointer typing so a promoted `int*in_RSI` stays `int*` */
            if (var_pointer.count(leak) && var_pointer[leak]) {
                var_pointer[pn] = true; var_is_ll[pn] = true;
                if (ptr_elem_width.count(leak)) ptr_elem_width[pn] = ptr_elem_width[leak];
                if (ptr_elem_uns.count(leak))   ptr_elem_uns[pn]   = ptr_elem_uns[leak];
                if (ptr_elem_float.count(leak)) ptr_elem_float[pn] = ptr_elem_float[leak];
            }
            ExprP pv = mkVar(pn, w >= 8 ? 8 : 4);
            for (auto& b : blocks) {
                for (auto& s : b.stmts) { s.lhs = subst_named_var(s.lhs, leak, pv); s.rhs = subst_named_var(s.rhs, leak, pv); }
                b.cond = subst_named_var(b.cond, leak, pv);
                b.ret_value = subst_named_var(b.ret_value, leak, pv);
                b.switch_var = subst_named_var(b.switch_var, leak, pv);
                b.tail_call = subst_named_var(b.tail_call, leak, pv);
            }
            unknown_reg_name.erase(pr.first);     /* no longer a declared backstop */
        }
    }

    /* HARD GUARANTEE: no in_<X> phantom EVER reaches the output, for ANY binary in the world.
     * promote_leaked_arg_params turns every GP in_<reg> into the parameter aN it represents.
     * This final scrub catches everything ELSE named in_<X> -- specifically the unmapped
     * register backstops (in_YMM3 / in_MM0 / in_FS / in_ST0: a ymm/zmm/mmx/mask/x87/segment
     * register the lifter cannot model, held in unknown_csreg_name and never promoted) -- plus
     * any straggler from a late rvalue() call. Each is renamed to an ordinary DECLARED local,
     * exactly the way IDA renders a value it could not trace (an undefined local), never the
     * in_ marker. It scans the actual IR, so it is producer- and timing-independent: a
     * surviving in_ is structurally impossible after this runs. Runs before display renumber
     * so the fresh locals fold into the contiguous v1,v2,... naming. */
    void scrub_in_placeholders() {
        std::set<std::string> leaks;
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Var && e->name.rfind("in_", 0) == 0) leaks.insert(e->name);
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { scan(s.lhs); scan(s.rhs); }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw); scan(b.switch_var); scan(b.tail_call);
        }
        for (const std::string& leak : leaks) {
            int w = var_width.count(leak) ? var_width[leak] : 8;
            std::string ln = "v" + std::to_string(++temp_seq);
            record_width(ln, w >= 8 ? 8 : 4);
            if (w >= 8) var_is_ll[ln] = true;
            if (var_is_float.count(leak) && var_is_float[leak]) var_is_float[ln] = true;
            if (var_pointer.count(leak) && var_pointer[leak]) {
                var_pointer[ln] = true; var_is_ll[ln] = true;
                if (ptr_elem_width.count(leak)) ptr_elem_width[ln] = ptr_elem_width[leak];
                if (ptr_elem_uns.count(leak))   ptr_elem_uns[ln]   = ptr_elem_uns[leak];
                if (ptr_elem_float.count(leak)) ptr_elem_float[ln] = ptr_elem_float[leak];
            }
            ExprP lv = mkVar(ln, w >= 8 ? 8 : 4);
            if (var_is_float.count(ln) && var_is_float[ln]) lv->is_float = true;
            for (auto& b : blocks) {
                for (auto& s : b.stmts) { s.lhs = subst_named_var(s.lhs, leak, lv); s.rhs = subst_named_var(s.rhs, leak, lv); }
                b.cond = subst_named_var(b.cond, leak, lv);
                b.ret_value = subst_named_var(b.ret_value, leak, lv);
                b.ret_raw = subst_named_var(b.ret_raw, leak, lv);
                b.switch_var = subst_named_var(b.switch_var, leak, lv);
                b.tail_call = subst_named_var(b.tail_call, leak, lv);
            }
        }
    }

    /* getenv on every register read is a syscall-ish lookup on the hottest path in
     * the lifter; cache it once (mirrors the cached env accessors in the emitter). */
    static bool dbg_regread() {
        static const bool on = std::getenv("DS_DBG_REGREAD") != nullptr;
        return on;
    }
    ExprP reg_value(Reg r, int w) {
        ExprP v = regfile[r] ? clone(regfile[r]) : nullptr;
        if (dbg_regread()) {
            std::string s; dbg_expr(v, s);
            fprintf(stderr, "[REGREAD] %llx r=%s w=%d -> %s\n",
                    (unsigned long long)cur_insn_addr, reg_abi_name(r), w, s.c_str());
        }
        if (!v) {
            /* Untracked read -> THE BACKSTOP (see unknown_reg_value): emit a clean
             * declared `in_<REG>` local for ANY register, callee-saved OR volatile.
             * The old volatile `0` fallback was the SOLE source of `(char*)0` null
             * bases (a lost arg pointer like r8 collapsed to `*(0+off)`) and of
             * `if (0 == 0)` folds — both now structurally impossible. The /Od corpus
             * never reads a volatile uninitialized, so it never hits this path; the
             * value is identical (it was already untracked), only its NAME changed
             * from a broken sentinel to a declared variable. */
            v = unknown_reg_value(r, w);
        }
        /* x86-64: writing a 32-bit sub-register zero-extends into the full 64-bit
         * register (the upper 32 bits are cleared). So a width-4 value read back at
         * 64-bit width has KNOWN-ZERO upper bits and must promote by ZERO extension,
         * not C's signed default. Without this, `mov eax,ecx; imul rax,rcx` renders
         * `a1 * 0x100000001LL` — which SIGN-extends a negative int param, the wrong
         * value. The genuine sign-extend path (`movsxd rax,ecx`) already produces a
         * width-8 value, so it is untouched. Non-negative values are unaffected in
         * VALUE (positive int == unsigned), so this only ever corrects, never breaks.
         * NB: not applied to address-index reads (resolve_mem passes for_addr) to
         * avoid `(unsigned int)` noise on non-negative array indices. */
        if (w >= 8 && !zx_suppress && !is_xmm(r) && v && v->width == 4 &&
            !v->is_unsigned && !v->is_float) {
            /* xmm lanes are excluded: a `movd xmm,ecx; cvtdq2pd` converts the int32
             * as SIGNED, so the GP zero-extension rule must not pollute it. */
            if (v->kind == EK::Const)
                v = mkConst(v->cval & 0xFFFFFFFFLL, 8, true);
            else
                v = mkCast("(unsigned int)", v, 4, true);
        }
        return truncate(v, w);
    }
    /* When true, reg_value skips the 32->64 zero-extension cast (used for address
     * index reads, where a non-negative index needs no `(unsigned int)` clutter). */
    bool zx_suppress = false;

    /* Truncate/extend an expression to width w preserving low-bit value. */
    ExprP truncate(ExprP v, int w) {
        if (!v) return mkConst(0, w);
        if (w >= 8 || w == 0) return v;
        if (v->kind == EK::Const) {
            int64_t m = (w == 4) ? (int64_t)(int32_t)v->cval
                       : (w == 2) ? (int64_t)(int16_t)v->cval
                                  : (int64_t)(int8_t)v->cval;
            return mkConst(m, w, v->is_unsigned);
        }
        if (v->width == w) return v;
        return mkCast(cast_str(w, false), v, w, false);
    }

    /* Resolve an rvalue operand to an Expr using current reg values. */
    ExprP rvalue(const cs_x86_op& op) {
        if (op.type == X86_OP_IMM)
            return mkConst(op.imm, op.size ? op.size : 4);
        if (op.type == X86_OP_REG) {
            Reg r; int w; map_reg(op.reg, r, w);
            /* An UNMAPPED register (ymm/zmm/mmx/mask/segment/control/debug/x87 — anything
             * map_reg does not model) used to read back as the literal constant 0. That is
             * not a "value unknown" marker, it is a specific FALSE CLAIM, and it propagates:
             * constant folding believes it, so the fabricated zero reaches conditions. It
             * gated loop exits in NullWare's AVX2 strlen —
             *     if (__vpmovmskb(0)) break;
             * where the argument is the string being scanned. It also contradicted this
             * file's own stated guarantee, three lines up in unknown_reg_value: "NEVER a
             * literal-0 pointer base ... structurally unable to reach the output, on ANY
             * input, forever". R_NONE was the hole in that forever.
             * Now it is a named, declared phantom live-in like every other unrecoverable
             * value, and the confidence header counts it. DS_NO_REGPLACEHOLDER restores the
             * old fabricated zero. */
            if (r == R_NONE) {
                /* AVX2/AVX-512: a wide-vector reg DEFINED by an unmodeled op earlier in this
                 * block (see the reg-write handler's vec_op_value) reads back as that op's
                 * value, so the computation flows to its use instead of being lost. */
                auto vo = vec_op_value.find(op.reg);
                if (vo != vec_op_value.end() && vo->second) return clone(vo->second);
                static const bool off = std::getenv("DS_NO_REGPLACEHOLDER") != nullptr;
                if (off) return mkConst(0, w ? w : 8);
                return unknown_csreg_value(op.reg, w);
            }
            /* high-byte registers (ah/bh/ch/dh) are bits 8-15 of the parent, NOT
             * the low byte — model them as `(parent >> 8) & 0xFF`. Without this a
             * `test dh,dh` reads as `test dl,dl`, which silently breaks every SWAR
             * byte scan (strlen/strcpy/strncpy/memchr test dl then dh per word). */
            if (is_high_byte_reg(op.reg)) {
                ExprP full = reg_value(r, 8);
                return truncate(mkBinary(">>", full, mkConst(8, 8), 8, true), 1);
            }
            return reg_value(r, w);
        }
        if (op.type == X86_OP_MEM)
            return resolve_mem(op, op.size ? op.size : 4);
        return mkConst(0, 4);
    }
    static bool is_high_byte_reg(unsigned reg) {
        return reg == X86_REG_AH || reg == X86_REG_BH ||
               reg == X86_REG_CH || reg == X86_REG_DH;
    }

    /* Resolve a memory operand, handling rip-relative + stack slots + general. */
    ExprP resolve_mem(const cs_x86_op& op, int width) {
        /* Everything computed here is ADDRESS arithmetic (base + index*scale);
         * a 32-bit index needs no `(unsigned int)` zero-ext clutter (indices are
         * non-negative). Suppress the reg_value zero-ext cast for the duration. */
        bool _saved_zx = zx_suppress; zx_suppress = true;
        struct ZxGuard { bool* p; bool v; ~ZxGuard() { *p = v; } } _zg{&zx_suppress, _saved_zx};
        const x86_op_mem& m = op.mem;
        /* SEGMENT-relative (gs:/fs:) = TEB/TLS access, NOT an absolute deref. Win64
         * puts the TEB at gs:, so `mov rax, gs:[0x30]` (self-ptr), `gs:[0x58]` (TLS
         * array) etc. Flattening the segment override turned these into near-null
         * `*(long long*)0x30` derefs (fun_0005d828/fun_0006dcd0). Model the load as
         * the MSVC `__readgsqword(disp)` / `__readfsqword(disp)` intrinsic; an
         * indexed form keeps the index off that base. */
        {
            bool gs = (m.segment == X86_REG_GS) || cur_insn_seg == 1;
            bool fs = (m.segment == X86_REG_FS) || cur_insn_seg == 2;
            if ((gs || fs) && m.base == X86_REG_INVALID) {
                /* gs:[0x30] is the TEB self-pointer -> the canonical MSVC accessor
                 * NtCurrentTeb() (a macro expanding to (char*)__readgsqword(0x30), so the
                 * recompiled bytes are unchanged). DS_NO_TEBNAMES reverts to __readgsqword(TEB_Self). */
                if (gs && m.index == X86_REG_INVALID && m.disp == 0x30 &&
                    !std::getenv("DS_NO_TEBNAMES") && !std::getenv("DS_NO_TEB")) {
                    auto nt = new_expr();
                    nt->kind = EK::Call; nt->callee = "NtCurrentTeb";
                    nt->width = 8; nt->ret_kind = 2;
                    used_segread = true; used_nt_current_teb = true;
                    return nt;
                }
                auto rd = new_expr();
                rd->kind = EK::Call; rd->callee = gs ? "__readgsqword" : "__readfsqword";
                rd->width = 8; rd->ret_kind = 2;
                const char* tf = (gs && !std::getenv("DS_NO_TEB")) ? teb_field_name(m.disp) : nullptr;
                if (tf) { rd->args.push_back(mkText(tf, 8)); teb_fields_used[tf] = m.disp; }
                else rd->args.push_back(mkConst(m.disp, 8, true));
                used_segread = true;
                if (m.index == X86_REG_INVALID) return rd;   /* scalar TEB/TLS field */
                /* indexed: `*(T*)(__readgsqword(disp) + idx*scale)` */
                Reg ir; int iw; map_reg(m.index, ir, iw);
                ExprP idx = reg_value(ir, 8);
                if (m.scale > 1) idx = mkBinary("*", idx, mkConst((int64_t)m.scale, 8), 8);
                return mkMem(mkBinary("+", rd, idx, 8), width);
            }
        }
        /* Resolve to an image RVA and read the constant out of the image: rip-relative
         * (x64), or a bare ABSOLUTE address (32-bit, which has no rip-relative mode and
         * addresses globals by their full VA — so subtract the image base to get the RVA
         * this code, and the `byte_<rva>` global naming, work in).
         * Without the 32-bit arm every x87 float constant — and x87 loads EVERY constant
         * from memory — rendered as a raw `*(double*)0x1000e150` instead of its literal.
         * The range test is the guard: only a disp that actually lands inside the image
         * is treated as a global reference. */
        bool rip_rel = (m.base == X86_REG_RIP && m.index == X86_REG_INVALID);
        bool abs32 = (e && e->arch == DS_ARCH_X86 && m.base == X86_REG_INVALID &&
                      m.index == X86_REG_INVALID && m.segment == X86_REG_INVALID &&
                      (uint64_t)m.disp >= e->base &&
                      (uint64_t)m.disp - e->base < e->image_size);
        if (rip_rel || abs32) {
            uint64_t abs = rip_rel ? (cur_insn_addr + cur_insn_size + (uint64_t)m.disp)
                                   : ((uint64_t)m.disp - e->base);
            /* A load from an IMPORT's IAT slot yields the imported object/function
             * address. The IAT lives in read-only .rdata but is filled by the LOADER,
             * so the file bytes are a stale hint — inlining them as a constant below
             * would be flat wrong. Name the import instead: a data import like
             * `?cout@std@@3V?$basic_ostream@...@A` renders as `std__cout`
             * (demangled by sani), which is what `std::cout << x` loads.
             * DS_NO_IMPDATA. */
            if (width == 8 && !std::getenv("DS_NO_IMPDATA")) {
                for (size_t i = 0; i < e->import_len; ++i)
                    if (e->imports[i].iat_rva == abs && e->imports[i].name[0]) {
                        std::string inm = sani(e->imports[i].name);
                        imported_data.insert(inm);   /* -> `extern void* <inm>;` */
                        return mkText(inm, 8);
                    }
            }
            /* A load from a WRITABLE global is a mutable variable: emit a deref of
             * its address, not the (initial) image byte — otherwise `mov r8,[g];
             * test r8,r8` collapses to `if (0 != 0)`. Read-only data (string/float
             * constants, tables) still inlines as a constant. */
            if (addr_writable(abs)) return mkMem(mkConst((int64_t)abs, 8), width);
            int64_t cv = 0;
            bool ok = false;
            if (width <= 1) { uint8_t b; if (read_u8(abs, b)) { cv = (int8_t)b; ok = true; } }
            else if (width <= 4) { int32_t v; if (read_i32(abs, v)) { cv = v; ok = true; } }
            else { int64_t v; if (read_i64(abs, v)) { cv = v; ok = true; } }
            /* reloc-typed read-only pointer global: an 8-byte read-only slot the
             * PE base-reloc table marks IMAGE_REL_BASED_DIR64 holds a real absolute
             * pointer, not an integer. When it points at a read-only C string,
             * inline the string literal (Hex-Rays shows the string, not the raw
             * VA). Authoritative (reloc-gated) so no false positives. DS_NO_RELOC. */
            if (ok && width == 8 && petab && petab->reloc64.count(abs) &&
                !getenv("DS_NO_RELOC")) {
                uint64_t tgt = (uint64_t)cv;
                if (tgt >= e->base && tgt - e->base < e->image_size) {
                    std::string s;
                    if (read_cstring(tgt - e->base, s))
                        return mkText("\"" + s + "\"", 8, tgt - e->base);
                }
            }
            if (ok) return mkConst(cv, width, false);
            /* could not read: emit a deref of the absolute address */
            return mkMem(mkConst((int64_t)abs, 8), width);
        }
        /* stack slot? */
        Reg base = R_NONE, index = R_NONE; int t;
        if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
        if (m.index != X86_REG_INVALID) map_reg(m.index, index, t);
        if (index == R_NONE && base != R_RIP) {
            int64_t norm;
            if (normalise_slot(base, m.disp, norm)) {
                /* in an address-escaped aggregate -> a field memory access */
                if (!param_home_off.count(norm)) {
                    if (const AggRegion* r = agg_region_for(norm))
                        return mkMem(agg_addr(*r, norm), width);
                }
                std::string nm = resolved_slot_name(norm, width);
                if (!nm.empty()) { record_width(nm, width); return mkVar(nm, width); }
            }
        }
        /* stack array: [rsp/rbp + index*scale + disp] => *(T*)(&buf + index*scale) */
        if (index != R_NONE) {
            int64_t norm;
            if (normalise_slot(base, m.disp, norm)) {
                if (!param_home_off.count(norm)) {
                    if (const AggRegion* r = agg_region_for(norm))
                        return mkMem(agg_indexed(*r, norm, index, m.scale), width);
                }
                ExprP a = stack_array_addr(norm, index, m.scale);
                return mkMem(a, width);
            }
        }
        /* general address using folded reg values */
        return mem_to_expr(op, width, regfile);
    }

    /* Build `(char*)&buf + index*scale` for a stack-array access whose frame
     * base offset is `norm`. `buf` is a dedicated array local for that offset. */
    ExprP stack_array_addr(int64_t norm, Reg index, int scale) {
        std::string nm = array_name(norm);
        ExprP idx = regfile[index] ? clone(regfile[index]) : mkConst(0, 8);
        ExprP scaled = idx;
        if (scale > 1) scaled = mkBinary("*", idx, mkConst((int64_t)scale, 8), 8);
        /* the array name decays to char*; address = buf + index*scale */
        ExprP base = mkVar(nm, 8);
        base->is_unsigned = true;   /* marks "already a pointer", skip (char*) */
        return mkBinary("+", base, scaled, 8);
    }

    std::map<int64_t,std::string> stack_array_name;  /* frame off -> buf local */
    std::set<std::string> array_locals;
    std::map<int,Reg> switch_cmp_reg;   /* switch block -> bound-check reg, resolved post-exec */
    std::map<int,uint64_t> switch_index_load;   /* switch block -> table-load insn addr */
    /* switch block -> the index register's value snapshotted AT the table load,
     * before the computed goto reuses the register as the jump target. The index
     * reg is also briefly reused for the `code[pc]` access earlier in the same
     * block, so we must snapshot at the EXACT table-load address, not the first
     * indexed access. */
    std::map<int,ExprP> switch_resolved_index;

    /* ---- address-escaped stack aggregates (out-structs / out-params) ----
     * When a stack region's ADDRESS is passed to a call (`lea argreg,[rbp-X];
     * call F`), the callee may write the whole region through that pointer. The
     * region must therefore be modeled as ONE memory aggregate (`char sN[size]`)
     * with every in-region `[rbp-X+k]` access routed through memory — NOT as a
     * set of independent SSA scalar locals (which would look uninitialised after
     * the call, dropping the call's writes and the direct movdqu/byte inits). */
