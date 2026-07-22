/* 10_operator_new.inc -- operator new recovery, struct field render helpers
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    void recover_operator_new() {
        if (std::getenv("DS_NO_OPNEW")) return;
        std::set<std::string> allocs;
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Mem || !s.lhs->a || !s.rhs) continue;
            ExprP rc = s.rhs; while (rc && rc->kind == EK::Cast) rc = rc->a;
            if (!rc || rc->kind != EK::Const) continue;
            if (class_for_vtable((uint64_t)rc->cval).empty()) continue;   /* rhs is a known vtable */
            std::string bp; int64_t boff;
            if (!(struct_base_offset(s.lhs->a, bp, boff) && boff == 0)) continue;   /* stored at field_0 */
            for (auto& b2 : blocks) for (auto& s2 : b2.stmts)   /* find bp's definition: bp = Call(f) */
                if (s2.kind == SK::Assign && s2.lhs && s2.lhs->kind == EK::Var &&
                    s2.lhs->name == bp && s2.rhs) {
                    ExprP rr = s2.rhs; while (rr && rr->kind == EK::Cast) rr = rr->a;
                    if (rr && rr->kind == EK::Call && rr->callee.rfind("fun_", 0) == 0)
                        allocs.insert(rr->callee);
                }
        }
        if (allocs.empty()) return;
        std::function<void(ExprP&)> ren = [&](ExprP& e) {
            if (!e) return;
            if (e->kind == EK::Call && allocs.count(e->callee)) e->callee = "operator_new";
            ren(e->a); ren(e->b); ren(e->c);
            for (auto& a : e->args) ren(a);
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { ren(s.lhs); ren(s.rhs); }
            ren(b.cond); ren(b.ret_value); ren(b.ret_raw); ren(b.switch_var); ren(b.tail_call);
        }
        /* the forward-decl set is keyed by the pre-rename names — retarget it so the emitted
         * prototype is `void* operator_new(size_t)` and the stale `fun_X` decl is dropped. */
        for (auto& a : allocs) extern_callees.erase(a);
        extern_callees["operator_new"] = 2;
        used_opnew = true;
    }
    /* Render `*(T*)((char*)p + K)` as `p->field_K` when p is a recovered struct pointer
     * and K/width match a field; else return false (caller uses the raw form). */
    bool try_struct_field(const ExprP& mem, std::string& out) {
        if (param_structs.empty() || !mem || mem->kind != EK::Mem || !mem->a) return false;
        std::string p; int64_t off;
        /* ARRAY-OF-STRUCT: `*(T*)((char*)(i*stride + base) + off)` -> `((struct elem*)base)[i].field_off`.
         * Disjoint from the nested/struct-field paths (those require a CONST offset base). */
        {
            std::string ak; ExprP ab, ai; int64_t astride, aoff;
            if (array_struct_access(mem, ak, ab, ai, astride, aoff)) {
                auto ait = param_structs.find(ak);
                if (ait != param_structs.end()) {
                    auto af = ait->second.fw.find(aoff);
                    int w = mem->width ? mem->width : 1;
                    if (af != ait->second.fw.end() && af->second == w) {
                        /* clean subscript when the index strips to a plain integer; keep the
                         * original coercion casts when it doesn't (a pointer/float-typed index
                         * value is `[(long long)((unsigned int)t1)]`, not an illegal `[t1]`). */
                        ExprP ix = ai; while (ix && ix->kind == EK::Cast) ix = ix->a;
                        bool ix_ok = ix && !ix->is_float && !renders_as_pointer(ix) &&
                            !(ix->kind == EK::Var && var_is_float.count(ix->name) && var_is_float[ix->name]);
                        std::string idxs = ix_ok ? rsub(ix, 15) : rsub(ai, 15);
                        out = "((struct " + ait->second.tag + "*)" + rsub(ab, 14) + ")[" +
                              idxs + "].field_" + hex(aoff).substr(2);
                        return true;
                    }
                }
                return false;
            }
        }
        /* NESTED field-load base (a1->field_d0->field_K): inline-cast the parent field
         * load, which itself renders via the top-level struct. Tried first; disjoint from
         * struct_base_offset (which rejects a Mem-load base). */
        {
            std::string np; int64_t noff;
            if (nested_base_offset(mem->a, np, noff)) {
                auto nit = param_structs.find(np);
                if (nit != param_structs.end()) {
                    auto nf = nit->second.fw.find(noff);
                    int w = mem->width ? mem->width : 1;
                    if (nf != nit->second.fw.end() && nf->second == w) {
                        /* the parent field is RETYPED `struct T*`, so a clean chained arrow
                         * compiles — no inline cast (a1->f_28->f_K). Route through fld so a
                         * nested Vec2/3/4 field uses x/y/z/w (matching its struct def). */
                        out = render(nested_base_load(mem->a)) + "->" + fld(nit->second, noff);
                        return true;
                    }
                }
                return false;   /* nested base but no matching field -> raw form */
            }
        }
        if (!struct_base_offset(mem->a, p, off)) return false;
        auto it = param_structs.find(p);
        if (it == param_structs.end()) return false;
        auto fit = it->second.fw.find(off);
        if (fit == it->second.fw.end()) return false;
        int w = mem->width ? mem->width : 1;
        if (fit->second != w) return false;      /* different width at this offset -> raw */
        if (is_global_struct_name(p)) {          /* global: cast the long-long value to the struct ptr */
            /* register the #define — this arrow render bypasses the bare-load Mem path
             * that normally emits it, so a global used ONLY as a struct base would be an
             * undeclared identifier (C2065) without this. */
            named_globals[p] = "(*(long long*)0x" + p.substr(6) + ")";
            auto lit = global_struct_local.find(p);
            if (lit != global_struct_local.end())          /* read-only: use the cached local */
                out = lit->second + "->" + fld(it->second, off);
            else
                out = "((struct " + it->second.tag + "*)" + disp(p) + ")->" + fld(it->second, off);
        } else if (struct_var.count(p)) {                  /* pointer temp / stack local */
            /* A POINTER temp is declared `struct <tag>*` (decl_type puts every param_structs
             * name there), so the inline `(struct <tag>*)` cast is redundant — emit a bare
             * arrow. A STACK BUFFER (`char sN[20]`, in array_locals) is NOT a struct pointer,
             * so it still needs the cast to decay+reinterpret the array as the struct ptr. */
            if (!array_locals.count(p))                    /* decl_type is always the struct ptr here */
                out = disp(p) + "->" + fld(it->second, off);
            else
                out = "((struct " + it->second.tag + "*)" + disp(p) + ")->" + fld(it->second, off);
        } else
            out = disp(p) + "->" + fld(it->second, off);
        return true;
    }
    /* Address-of a recognized struct field: a bare `(char*)p + K` (used AS a pointer,
     * not deref'd) renders `&p->field_K` instead of a raw byte-offset cast, when K is
     * EXACTLY a declared field offset. Turns `(int*)((char*)a1+0x54)` into
     * `&a1->field_54`. */
    bool try_struct_field_addr(const ExprP& e, std::string& out) {
        if (param_structs.empty() || !e || e->kind != EK::Binary || e->op != "+") return false;
        std::string p; int64_t off;
        /* NESTED field address: `&a1->field_d0->field_K` (inline-cast the parent field). */
        {
            std::string np; int64_t noff;
            if (nested_base_offset(e, np, noff) && noff != 0) {
                auto nit = param_structs.find(np);
                if (nit != param_structs.end() && nit->second.fw.count(noff)) {
                    out = "&" + render(nested_base_load(e)) + "->" + fld(nit->second, noff);
                    return true;
                }
                return false;
            }
        }
        if (!struct_base_offset(e, p, off) || off == 0) return false;
        auto it = param_structs.find(p);
        if (it == param_structs.end() || !it->second.fw.count(off)) return false;
        if (is_global_struct_name(p)) {          /* global: cast the long-long value first */
            named_globals[p] = "(*(long long*)0x" + p.substr(6) + ")";
            auto lit = global_struct_local.find(p);
            if (lit != global_struct_local.end())
                out = "&" + lit->second + "->" + fld(it->second, off);
            else
                out = "&((struct " + it->second.tag + "*)" + disp(p) + ")->" + fld(it->second, off);
        } else if (struct_var.count(p)) {         /* pointer temp -> bare arrow; stack buffer -> keep cast */
            if (!array_locals.count(p))                    /* decl_type is always the struct ptr here */
                out = "&" + disp(p) + "->" + fld(it->second, off);
            else
                out = "&((struct " + it->second.tag + "*)" + disp(p) + ")->" + fld(it->second, off);
        } else
            out = "&" + disp(p) + "->" + fld(it->second, off);
        return true;
    }

    std::string array_name(int64_t norm) {
        auto it = stack_array_name.find(norm);
        if (it != stack_array_name.end()) return it->second;
        std::string nm = "buf" + std::to_string((int)stack_array_name.size() + 1);
        stack_array_name[norm] = nm;
        array_locals.insert(nm);
        return nm;
    }

    /* Address expression (no deref) for lea / address-of. */
    ExprP addr_of_mem(const cs_x86_op& op) {
        const x86_op_mem& m = op.mem;
        if (m.base == X86_REG_RIP && m.index == X86_REG_INVALID) {
            uint64_t abs = cur_insn_addr + cur_insn_size + (uint64_t)m.disp;
            /* `lea reg,[rip+str]` of a read-only C string -> the string literal.
             * A lea result IS a pointer, so this is the known-pointer context the
             * bare-constant string guard requires (no arithmetic-constant risk):
             * `return "foo";` instead of `return 0xe2f0;`. DS_NO_LEASTR. */
            if (!getenv("DS_NO_LEASTR")) {
                std::string s;
                if (read_cstring(abs, s)) return mkText("\"" + s + "\"", 8);
                /* UTF-16 twin: `lea rcx,[wide_str]` (an LPCWSTR argument or a stored
                 * wchar_t* — `28 00 6e 00 ...` = L"(null)") is invisible to the byte-wise
                 * read_cstring, which sees '(' then a NUL and gives up, leaving a bare
                 * address. read_wstring is equally conservative (read-only, aligned, BMP
                 * printable, min length), so a genuine numeric pointer is still left raw. */
                std::string ws;
                if (read_wstring(abs, ws)) return mkText("L\"" + ws + "\"", 8);
            }
            /* `lea reg,[rip+func]` taking the address of code -> the function's name
             * (a function pointer: callbacks, thread procs, vtable init). Executable
             * target => a function; if the engine did not recover it (address-taken
             * only, never called) name_for_rva still yields a clean `sub_<rva>`, like
             * IDA recovering it from the lea xref. Registered in extern_callees for a
             * proto; a func name decays to its pointer in C. DS_NO_FNPTR. */
            if (!getenv("DS_NO_FNPTR") && ds_rva_is_exec(e, abs)) {
                std::string nm = name_for_rva(abs);
                if (!nm.empty() && !(f && f->name[0] && nm == f->name)) {
                    if (!extern_callees.count(nm)) extern_callees[nm] = 2;
                    return mkText(nm, 8);
                }
            }
            return mkConst((int64_t)abs, 8, true);
        }
        Reg base = R_NONE, index = R_NONE; int t;
        if (m.base != X86_REG_INVALID) map_reg(m.base, base, t);
        if (m.index != X86_REG_INVALID) map_reg(m.index, index, t);
        if (index == R_NONE && base != R_RIP) {
            int64_t norm;
            if (normalise_slot(base, m.disp, norm)) {
                /* address of an escaped aggregate field: `sN` / `(char*)sN + d`
                 * (already a pointer — no extra `&`). */
                if (!param_home_off.count(norm)) {
                    if (const AggRegion* r = agg_region_for(norm))
                        return agg_addr(*r, norm);
                }
                std::string nm = resolved_slot_name(norm, 4);
                if (!nm.empty()) {
                    var_pointer[nm] = false;
                    return mkAddrOf(mkVar(nm, var_width.count(nm)?var_width[nm]:4));
                }
            }
        }
        /* lea of an INDEXED stack slot: `lea reg,[rsp+idx*8+disp]` — taken by
         * NEG/SWAP for an in-place stack[] element RMW. Route to the stack-array
         * model so it is `&buf[idx]`, not a `0 + idx*8` null base (mirrors the
         * mem_to_expr indexed path). */
        if (index != R_NONE && base != R_RIP) {
            int64_t norm;
            if (normalise_slot(base, m.disp, norm)) {
                if (!param_home_off.count(norm)) {
                    if (const AggRegion* r = agg_region_for(norm))
                        return agg_indexed(*r, norm, index, m.scale);
                }
                return stack_array_addr(norm, index, m.scale);
            }
        }
        ExprP addr;
        auto rv = [&](Reg r) -> ExprP {
            return regfile[r] ? clone(regfile[r]) : mkReg(r, 8);
        };
        if (base != R_NONE && base != R_RIP) addr = rv(base);
        if (index != R_NONE) {
            ExprP ie = rv(index);
            if (m.scale > 1) ie = mkBinary("*", ie, mkConst((int64_t)m.scale, 8), 8);
            addr = addr ? mkBinary("+", addr, ie, 8) : ie;
        }
        if (m.disp != 0 || !addr) {
            ExprP de = mkConst(m.disp, 8);
            addr = addr ? mkBinary("+", addr, de, 8) : de;
        }
        return addr ? addr : mkConst(0, 8);
    }

    /* Resolve a slot offset to its variable name, registering it. */
    std::string slot_name(int64_t norm, int width) {
        auto ph = param_home_off.find(norm);
        if (ph != param_home_off.end()) return ph->second;
        auto it = stack_slot_name.find(norm);
        if (it != stack_slot_name.end()) return it->second;
        std::string nm = "v" + std::to_string((int)stack_slot_name.size() + 1);
        stack_slot_name[norm] = nm;
        record_width(nm, width);
        return nm;
    }

    /* MSVC /O2 spill-and-reuse: a stack-passed (or homed) parameter is loaded into a
     * callee-saved register in the prologue, then its now-dead home slot is recycled
     * as a scratch local. Because param_home_off names the slot after the parameter,
     * the recycle store printed as `a9 = 0` and every later deref of the (pointer)
     * parameter read the clobbered slot -> "pointer used as int". We split the slot's
     * live range by ADDRESS: the capture read(s) before the first recycle store keep
     * the parameter name; the recycle store and everything at-or-after it become a
     * fresh local. cur_insn_addr drives the split, so it is stable across the lift
     * fixpoint. */
    std::map<int64_t, uint64_t> home_reuse_split;    /* norm -> first recycle-store addr */
    std::map<int64_t, std::string> home_reuse_local; /* norm -> recycled-life local name  */

    void detect_reused_param_homes() {
        if (param_home_off.empty() || insns.empty()) return;
        std::vector<int64_t> loop_carried;
        for (auto& kv : param_home_off) {
            int64_t norm = kv.first;
            uint64_t first_reuse = 0; bool has_reuse = false;
            uint64_t first_read  = 0; bool has_read  = false;
            std::vector<uint64_t> reads;
            for (auto& in : insns) {
                const cs_x86& x = in.x86;
                for (int o = 0; o < x.op_count; ++o) {
                    if (x.operands[o].type != X86_OP_MEM) continue;
                    const x86_op_mem& m = x.operands[o].mem;
                    if (m.index != X86_REG_INVALID) continue;
                    Reg base = R_NONE; int bw;
                    if (m.base != X86_REG_INVALID) map_reg(m.base, base, bw);
                    int64_t n;
                    if (!normalise_slot(base, m.disp, n) || n != norm) continue;
                    bool is_w = (x.operands[o].access & CS_AC_WRITE) != 0;
                    bool is_r = (x.operands[o].access & CS_AC_READ)  != 0;
                    if (is_r) { if (!has_read) { first_read = in.addr; has_read = true; } reads.push_back(in.addr); }
                    /* a PURE write (`mov [slot],x`) replaces the slot's value -> a
                     * reuse boundary; a read-modify-write (`add [slot],x`) keeps it as
                     * the same logical variable, so it does NOT count. The prologue
                     * homing store is excluded (it writes the parameter to its slot). */
                    if (is_w && !is_r && !has_reuse && !home_store_addrs.count(in.addr)) {
                        first_reuse = in.addr; has_reuse = true;
                    }
                }
            }
            /* Split only when the parameter is provably captured (read) before the
             * slot is recycled. Without a capture, a conditional `param = x` would
             * lose the incoming value on the not-taken path, so leave it alone. */
            if (has_reuse && has_read && first_read < first_reuse) {
                /* Loop-carried reassignment: the recycle store lives inside a loop
                 * (a back-edge [T,S] with T <= first_reuse <= S) that ALSO contains
                 * a read of the slot before that store (T <= R < first_reuse). Then
                 * the read on iteration N+1 consumes the store from iteration N, so
                 * the address-based split would freeze the loop read at `aN` (and the
                 * store, going to a never-read fresh local, is dead-store-eliminated
                 * -> the in-loop update vanishes -> infinite loop, e.g.
                 * count_trailing_zeros' `while((a1&1)==0) a1>>=1`). Model the slot as
                 * ONE mutable local initialized to aN instead. */
                bool loopc = false;
                for (auto& j : insns) {
                    if (!((j.is_jcc || j.is_jmp) && j.has_branch_target)) continue;
                    uint64_t T = j.branch_target, S = j.addr;
                    if (!(T < S && T <= first_reuse && first_reuse <= S)) continue;
                    for (uint64_t R : reads) if (T <= R && R < first_reuse) { loopc = true; break; }
                    if (loopc) break;
                }
                if (loopc) loop_carried.push_back(norm);
                else home_reuse_split[norm] = first_reuse;
            }
        }
        /* Demote loop-carried homed params from immutable alias to a real local
         * initialized to the parameter (the home store is already skipped). */
        for (int64_t norm : loop_carried) {
            auto it = param_home_off.find(norm);
            if (it == param_home_off.end()) continue;
            slot_init_param[norm] = it->second;
            param_home_off.erase(it);
        }
    }

    /* slot_name, but honoring the param-home live-range split (above). */
    std::string resolved_slot_name(int64_t norm, int width) {
        auto it = home_reuse_split.find(norm);
        if (it != home_reuse_split.end() && cur_insn_addr >= it->second) {
            std::string& nm = home_reuse_local[norm];
            if (nm.empty()) nm = slot_name(norm ^ (int64_t)0x5EA5000000LL, width);
            record_width(nm, width);
            return nm;
        }
        return slot_name(norm, width);
    }

