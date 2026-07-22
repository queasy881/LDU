/* 17_render.inc -- expression rendering
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Strip a WIDENING integer cast (e.g. (long long)idx, (int)idx) to expose the
     * index. A sub-int cast ((unsigned char)/(short)) is NOT noise — it is a real
     * modulo truncation: `table[(idx+1) & 0xFF]` lowers to `inc eax; movzx ecx,al`
     * => `(unsigned char)(idx+1)`; stripping it drops the wrap and turns a wrapping
     * index into an out-of-bounds read. Stop at any cast narrower than int. */
    ExprP strip_index_cast(const ExprP& e) {
        ExprP x = e;
        while (x && x->kind == EK::Cast && x->a && x->width >= 4) x = x->a;
        return x;
    }

    /* A callee whose emitted prototype is FIXED-ARITY (float params typed, so it is
     * NOT the arity-tolerant K&R `()` form) — the call site MUST pass exactly its
     * param_count args or the recompile is a hard C2197/C2198. Single source of
     * truth shared by the proto emitter (build_body_string) and the call renderer:
     * both gate on the identical sigtab condition, so a typed proto always has a
     * matching clamped call site. On true, `pcount` = the required arg count. */
    bool callee_typed_proto_arity(const std::string& c, int& pcount) const {
        /* A recognized imported API has an EXACT arity from the built-in table, so
         * emit a TYPED proto and clamp its call sites to it — otherwise the bare
         * K&R `HeapFree()` is declared with no params yet called with three, and the
         * declaration never matches the call. Gating both the proto emitter and the
         * call-site clamp on this one predicate keeps them consistent (no C2197/8). */
        { int aargc, ark; if (known_api(c, aargc, ark)) { pcount = aargc; return true; } }
        if (!sigtab) return false;
        if (c.rfind("fun_", 0) != 0 && c.rfind("sub_", 0) != 0) return false;
        uint64_t crva = strtoull(c.c_str() + 4, nullptr, 16);
        auto sit = sigtab->find(crva);
        if (sit == sigtab->end()) return false;
        const FuncSig& s = sit->second;
        if (!(s.float_mask && s.param_count > 0 &&
              (s.float_mask & ~s.float_typed_mask) == 0)) return false;
        pcount = (s.param_count < 16) ? s.param_count : 16;
        return true;
    }

    /* Recognize `*(T*)(base + index*sizeof(T))` and render it as `base[index]`
     * when `base` is a typed pointer (a pointer parameter, or a value the
     * type-recovery marked as a pointer). This collapses the verbose
     * `*(int*)((char*)(a1) + (long long)v4 * 4)` form into clean `a1[v4]`,
     * matching Hex-Rays output. General: works for any element width and any
     * base whose name was recorded as a pointer. */
    bool try_array_subscript(const ExprP& mem, std::string& out) {
        if (!mem || mem->kind != EK::Mem || !mem->a) return false;
        const ExprP& addr = mem->a;
        int esize = mem->width ? mem->width : 1;
        /* base must be a pointer-typed variable whose element width matches */
        auto is_ptr_base = [&](const ExprP& x) -> bool {
            if (!x || x->kind != EK::Var) return false;
            /* stack arrays are declared `char buf[N]` and indexed in BYTES via
             * an explicit (T*) cast; never collapse those to `buf[i]` (which
             * would index elements, not bytes). Only real pointer values. */
            if (array_locals.count(x->name)) return false;
            /* a conflict-raw var is declared `long long`, not a pointer — a bare
             * `*t` / `t[i]` would be C2100/C2109. Route it through the casting
             * `*(T*)t` path instead. */
            if (conflict_raw_vars.count(x->name)) return false;
            /* a struct-recovered param is `struct*`; a bare `*a2` would be a struct
             * VALUE. Its non-field accesses must use the raw `*(T*)a2` cast form. */
            if (param_structs.count(x->name)) return false;
            auto it = var_pointer.find(x->name);
            if (it == var_pointer.end() || !it->second) return false;
            /* the access width must equal the DECLARED element width, or `base[i]`
             * scales by the wrong size. decl_type declares a float pointer via
             * ptr_elem_float_w (MIN-wins: a movss => `float*`), so an 8-byte packed
             * movsd copy (`Vector2` = 2 floats; ptr_elem_width MAX-wins = 8) through a
             * declared `float*` must NOT collapse to `a2[i]` (which would step by 4) —
             * it falls through to the correct `*(double*)((char*)a2 + i*8)`. Mirror the
             * printer's width choice exactly so subscripter and decl stay in lockstep. */
            int decl_ew;
            if (ptr_elem_float.count(x->name) && ptr_elem_float[x->name]) {
                decl_ew = ptr_elem_float_w.count(x->name) ? ptr_elem_float_w[x->name]
                        : (ptr_elem_width.count(x->name) ? ptr_elem_width[x->name] : 4);
            } else {
                auto ew = ptr_elem_width.find(x->name);
                if (ew == ptr_elem_width.end()) return false;
                decl_ew = ew->second;
            }
            if (decl_ew != esize) return false;
            /* A NARROW (byte/word) load is about to be sign/zero-EXTENDED, and the
             * extension sign is taken from how the deref renders. Collapsing to
             * `*p` / `p[i]` uses the POINTER's element sign; if this load's sign
             * differs — the same `signed char* s` read `movsx` for `while(*s)` AND
             * `movzx` for `h ^= (unsigned char)*s` — the collapse would silently
             * sign-extend a zero-extended load (FNV-1a hash wrong on bytes >= 0x80).
             * Keep the explicit `*(unsigned char*)s` form so the sign is preserved. */
            if (esize < 4) {
                auto eu = ptr_elem_uns.find(x->name);
                bool ptr_uns = (eu != ptr_elem_uns.end()) && eu->second;
                if (ptr_uns != (bool)mem->is_unsigned) return false;
            }
            return true;
        };
        /* bare deref of a typed pointer => `*base` */
        if (is_ptr_base(addr)) { out = "*" + rsub(addr, 14); return true; }

        /* SUBSCRIPT ON A STRUCT-POINTER FIELD: `*(T*)((char*)a1->field_8 + i*sizeof(T))`
         * -> `a1->field_8[i]`. The plain-variable form above already collapses; a FIELD base
         * (a1->field_8, an EK::Mem) never reached is_ptr_base, which is Var-only, so 1900+
         * such accesses on NullWare stayed raw pointer arithmetic.
         *
         * Strictly gated, because a wrong stride corrupts every element:
         *   - the base must be a field the engine ALREADY PROVED is a pointer
         *     (is_struct_ptr_field -> it declared the field `void*`);
         *   - the address must be exactly `field + <index-scaled-by-esize>` or
         *     `field + <const multiple of esize>` -- the SAME shape the Var path accepts,
         *     and esize is the access width, which IS the element size here;
         *   - byte accesses keep their explicit cast (the sign-extension hazard the Var path
         *     documents applies identically), so esize>=2 only.
         * DS_NO_FIELDSUB. */
        if (!std::getenv("DS_NO_FIELDSUB") && esize >= 2 && addr->kind == EK::Binary &&
            addr->op == "+" && addr->a && addr->b) {
            /* the field base is the (char*)-cast side; the other operand is the index */
            auto field_base = [&](const ExprP& x) -> ExprP {
                ExprP m = x;
                while (m && m->kind == EK::Cast && m->a) m = m->a;   /* peel (char*) */
                return (m && is_struct_ptr_field(m)) ? m : nullptr;
            };
            ExprP fb = field_base(addr->a), other = addr->b;
            if (!fb) { fb = field_base(addr->b); other = addr->a; }
            if (fb) {
                ExprP o = strip_index_cast(other);
                ExprP index;
                if (o && o->kind == EK::Const && o->cval >= 0 && o->cval % esize == 0)
                    index = mkConst(o->cval / esize, 4);           /* const offset -> [k] */
                else if (o && o->kind == EK::Binary && o->op == "*") {
                    if (isConst(o->b) && o->b->cval == esize) index = strip_index_cast(o->a);
                    else if (isConst(o->a) && o->a->cval == esize) index = strip_index_cast(o->b);
                }
                if (index) {
                    /* the field renders `a1->field_8`; cast a pointer-typed index to int */
                    std::string istr = expr_is_pointer(index) ? "(long long)" + rsub(index, 14)
                                                              : rsub(index, 15);
                    out = "((" + (mem->is_float ? std::string(esize >= 8 ? "double" : "float")
                                                : typ_str(esize, mem->is_unsigned, false)) +
                          "*)" + rsub(fb, 14) + ")[" + istr + "]";
                    return true;
                }
            }
        }
        if (addr->kind != EK::Binary || addr->op != "+") return false;
        /* stack-array base: one operand is a `char buf[N]` local — it is the BASE
         * (the other operand the byte offset), even though such locals are not
         * pointer-typed vars. Without this, an offset that got mis-typed as a
         * pointer is chosen as the base, producing nonsense like `idx[buf]`. */
        {
            auto is_arr = [&](const ExprP& x) {
                return x && x->kind == EK::Var && array_locals.count(x->name);
            };
            ExprP ab = addr->a, ob = addr->b;
            if (is_arr(ob)) std::swap(ab, ob);
            if (is_arr(ab)) {
                /* A pointer-typed index (the offset got mis-inferred as a pointer)
                 * must be cast to an integer, else `buf[ptr]` is an illegal
                 * pointer+pointer subscript. */
                auto idx_str = [&](const ExprP& x) -> std::string {
                    if (expr_is_pointer(x)) return "(long long)" + rsub(x, 14);
                    return rsub(x, 15);
                };
                ExprP idx = strip_index_cast(ob);
                if (esize == 1) { out = render(ab) + "[" + idx_str(idx) + "]"; return true; }
                /* honour a float store/load (movss/movsd) so a float written into a
                 * char[] at a non-zero offset renders `*(float*)`/`*(double*)`, not
                 * `*(int*)` — matching the offset-0 path's EK::Mem render. Otherwise
                 * the value is silently truncated to an int on recompile. */
                std::string ety = mem->is_float ? (esize >= 8 ? "double" : "float")
                                                : typ_str(esize, mem->is_unsigned, false);
                out = "*(" + ety + "*)((char*)" +
                      render(ab) + " + " + idx_str(ob) + ")";
                return true;
            }
        }
        /* G5 GLOBAL-ADDRESS array base: `*(T*)((char*)0xADDR + idx*esize)` -> `((T*)0xADDR)[idx]`
         * (a global table indexed by a variable). The access width IS the element width (the
         * scale must equal esize), so this is width-sound with no elem-width tracking. The base
         * is rendered as the RAW address hex — NOT the `qword_X` named-global (which #defines to
         * a DEREFERENCED value, so `((T*)qword_X)` would double-deref). */
        {
            auto peel = [](ExprP x){ while (x && x->kind == EK::Cast) x = x->a; return x; };
            ExprP pa = peel(addr->a), pb = peel(addr->b);
            ExprP gaddr, goff;
            if (pa && pa->kind == EK::Const && (uint64_t)pa->cval > 0x10000 && !pa->is_float) { gaddr = pa; goff = addr->b; }
            else if (pb && pb->kind == EK::Const && (uint64_t)pb->cval > 0x10000 && !pb->is_float) { gaddr = pb; goff = addr->a; }
            if (gaddr) {
                ExprP gidx;
                if (esize == 1) gidx = strip_index_cast(goff);
                else {
                    ExprP o = strip_index_cast(goff);
                    if (o && o->kind == EK::Const && o->cval >= 0 && esize > 0 && o->cval % esize == 0)
                        gidx = mkConst(o->cval / esize, 4);
                    else if (o && o->kind == EK::Binary && o->op == "*") {
                        if (isConst(o->b) && o->b->cval == esize) gidx = strip_index_cast(o->a);
                        else if (isConst(o->a) && o->a->cval == esize) gidx = strip_index_cast(o->b);
                    } else if (o && o->kind == EK::Binary && o->op == "<<" && isConst(o->b) &&
                               o->b->cval >= 0 && o->b->cval < 12 && (1LL << o->b->cval) == esize)
                        gidx = strip_index_cast(o->a);
                }
                if (gidx && !expr_is_pointer(gidx)) {
                    std::string ety = mem->is_float ? (esize >= 8 ? "double" : "float")
                                                    : typ_str(esize, mem->is_unsigned, false);
                    std::string istr = (gidx->is_float || (gidx->kind == EK::Var &&
                                        var_is_float.count(gidx->name) && var_is_float[gidx->name]))
                                       ? "(long long)" + rsub(gidx, 14) : rsub(gidx, 15);
                    out = "((" + ety + "*)" + hex((uint64_t)gaddr->cval) + ")[" + istr + "]";
                    return true;
                }
            }
        }
        ExprP base = addr->a, off = addr->b;
        /* the base may be on either side of the + */
        bool ba = is_ptr_base(base), bo = is_ptr_base(off);
        /* When BOTH operands look like pointers — a loop index gets mis-typed as a
         * pointer because it is added to one — prefer a PARAMETER as the array base
         * (the real pointer; the index is a temp). Avoids the confusing `i[out]` for
         * `out[i]`. */
        auto is_param_ptr = [](const ExprP& x) {
            return x && x->kind==EK::Var && x->name.size()>=2 &&
                   x->name[0]=='a' && x->name[1]>='1' && x->name[1]<='9';
        };
        if (ba && bo) {
            if (!is_param_ptr(base) && is_param_ptr(off)) std::swap(base, off);
        } else if (!ba) {
            std::swap(base, off);
        }
        if (!is_ptr_base(base)) return false;
        ExprP index;
        if (esize == 1) {
            /* char array: offset is the raw index (no scaling) */
            index = strip_index_cast(off);
        } else {
            ExprP o = strip_index_cast(off);
            /* G1: a CONSTANT byte offset that is a whole number of elements collapses
             * to a constant subscript — `*(int*)((char*)p + 0x10)` -> `p[4]` — matching
             * Hex-Rays. is_ptr_base already excluded struct pointers, so a still-typed
             * `T* p` genuinely means element indexing here. */
            if (o && o->kind == EK::Const && esize > 0 && o->cval >= 0 && o->cval % esize == 0) {
                index = mkConst(o->cval / esize, 4);
            } else if (!o || o->kind != EK::Binary || o->op != "*") return false;
            else {
                ExprP a2 = o->a, b2 = o->b;
                if (isConst(b2) && b2->cval == esize) index = strip_index_cast(a2);
                else if (isConst(a2) && a2->cval == esize) index = strip_index_cast(b2);
                else return false;
            }
        }
        if (!index) return false;
        /* a pointer-typed index (an integer index mis-inferred as a pointer, or a
         * pointer-valued EXPRESSION like `t5 - t1`) is an illegal array subscript
         * (C2107). Cast it to an integer — the byte/element index is its numeric
         * value. expr_is_pointer catches both a bare pointer var and pointer +/-. */
        std::function<bool(const ExprP&)> addr_idx = [&](const ExprP& x) -> bool {
            if (!x) return false;
            if (expr_is_pointer(x)) return true;
            if (x->kind == EK::Var && array_locals.count(x->name)) return true;   /* char buf[N] decays */
            if (x->kind == EK::Binary && (x->op=="+"||x->op=="-")) return addr_idx(x->a) || addr_idx(x->b);
            if (x->kind == EK::Cast) return addr_idx(x->a);
            return false;
        };
        /* a FLOAT-typed index (`a1[t22]` where t22 is a mis-merged float holding an
         * integer counter) is C2108 — you cannot subscript with a float. Truncate to
         * an integer; a genuine float array index cannot exist, so this is always the
         * intended integer. */
        auto is_flt_idx = [&](const ExprP& x) -> bool {
            return x && (x->is_float ||
                (x->kind==EK::Var && var_is_float.count(x->name) && var_is_float[x->name]));
        };
        auto idx_str = [&](const ExprP& x) -> std::string {
            if (addr_idx(x)) return "(long long)" + rsub(x, 14);
            if (is_flt_idx(x)) return "(long long)" + rsub(x, 14);
            return rsub(x, 15);
        };
        out = render(base) + "[" + idx_str(index) + "]";
        return true;
    }

    std::string render_addr(const ExprP& e) {
        if (!e) return "0";
        /* address arithmetic uses byte pointers: cast the BASE to char* so the
         * `+ off` stays a BYTE displacement (a typed pointer would scale it). The
         * base is the POINTER operand; the other is the byte offset and MUST be an
         * integer. This code used to cast e->a unconditionally — so `[rdx+rcx]`
         * with rdx=(a2-a1) (an integer offset) and rcx=t3 (the pointer) rendered
         * `(char*)(a2-a1) + t3` == char* + pointer (C2110). Pick the pointer as the
         * base and keep the offset integer. */
        if (e->kind == EK::Binary && (e->op == "+" || e->op == "-")) {
            /* Flatten a chained byte displacement `(p + c1) + c2` -> `p + (c1+c2)`: a temp
             * `rsi = a1 + 8` then a store `[rsi + 8]` otherwise renders the nested
             * `(char*)((char*)a1 + 8) + 8` instead of `(char*)a1 + 0x10`. Guarded to a
             * pointer base plus two integer constants (value-identical byte arithmetic). */
            if (e->op == "+" && e->b && e->b->kind == EK::Const && !e->b->is_float &&
                e->a && e->a->kind == EK::Binary && e->a->op == "+" &&
                e->a->b && e->a->b->kind == EK::Const && !e->a->b->is_float && e->a->a &&
                (e->a->a->kind == EK::AddrOf || expr_is_pointer(e->a->a) ||
                 is_struct_ptr_field(e->a->a))) {
                ExprP folded = mkBinary("+", clone(e->a->a),
                                        mkConst(e->a->b->cval + e->b->cval, 8), 8);
                return render_addr(folded);
            }
            /* a retyped `struct T*` field counts as a pointer here (else `(char*)idx +
             * a2->field_90` = char* + struct* = C2110); pick it as the base / cast it as
             * an integer offset like any other pointer. */
            auto is_ptr = [&](const ExprP& x) -> bool {
                /* `&field` is a TYPED pointer that scales `+ off`, so it must be the
                 * char*-cast base — without this it fell through to the wide64 escape
                 * (an AddrOf is 8 bytes wide) and emitted `&field_10 + 8`, which scales
                 * by sizeof(field) (e.g. +64 bytes) instead of the +8 BYTES the lea did. */
                return x && (x->kind == EK::AddrOf || expr_is_pointer(x) || is_struct_ptr_field(x));
            };
            ExprP base = e->a, off = e->b;
            if (e->op == "+" && is_ptr(off) && !is_ptr(base))
                std::swap(base, off);
            std::string off_s;
            if (off && off->kind == EK::Cast &&
                off->op.find('*') != std::string::npos && !is_ptr(off->a))
                off_s = rsub(off->a, 12, true);        /* drop a spurious (char*) on an int */
            else if (is_ptr(off))
                off_s = "(long long)" + rsub(off, 14, true);
            else
                off_s = rsub(off, 12, true);
            /* A10: the `(char*)` on the BASE is only needed when the base is a TYPED pointer
             * that would scale the offset. For an INTEGER base (a named global `qword_X`, a
             * `__readgsqword`, a `long long` var, or a hex address literal) the add is already
             * byte arithmetic and the enclosing `*(T*)(...)` reinterprets the result — so the
             * cast is pure noise (`*(int*)(qword_174148 + 0x1450)`, exactly Hex-Rays). Drop it,
             * but ONLY when base or off is provably >=64-bit so a 32-bit literal+offset sum never
             * narrows (keep the `(char*)` form otherwise). */
            std::function<bool(const ExprP&)> wide64 = [&](const ExprP& x) -> bool {
                if (!x) return false;
                if (x->kind == EK::Const) return (uint64_t)x->cval > 0x7fffffffULL;
                if (x->kind == EK::Cast)
                    return x->op == "(long long)" || x->op == "(unsigned long long)" || wide64(x->a);
                if (x->kind == EK::Var) { std::string dt = decl_type(x->name);
                    return dt == "long long" || dt == "unsigned long long"; }
                return x->width >= 8 && !x->is_float;   /* Mem/Call width-8 integer */
            };
            if (!is_ptr(base) && (wide64(base) || wide64(off)))
                return rsub(base, 12) + " " + e->op + " " + off_s;
            return "(char*)" + rsub(base, 14, true) + " " + e->op + " " + off_s;
        }
        /* plain base / bare address: the enclosing `*(T*)(...)` already reinterprets
         * the pointer, so a `(char*)` cast on the bare address is pure noise —
         * `*(long long*)((char*)(x))` == `*(long long*)(x)`. Drop it (readability). */
        return render(e);
    }

    /* Should never appear in final output; a safety net if a register survives. */
    std::string reg_value_fallback(Reg r, int w) {
        (void)r; (void)w;
        return "0";
    }

    /* =================================================================== */
    /*  5. Dominators / post-dominators / loops                             */
    /* =================================================================== */

    std::vector<int> idom, ipdom;
    std::vector<int> rpo, rpo_num;

    int entry_block() {
        auto it = block_by_addr.find(f->rva);
        return it != block_by_addr.end() ? it->second : 0;
    }

    void compute_rpo() {
        rpo.clear();
        rpo_num.assign(blocks.size(), -1);
        if (blocks.empty()) return;
        std::vector<char> vis(blocks.size(), 0);
        std::vector<int> post;
        std::vector<std::pair<int,size_t>> stk;
        int start = entry_block();
        stk.push_back({start, 0}); vis[start] = 1;
        while (!stk.empty()) {
            int u = stk.back().first; size_t& ix = stk.back().second;
            if (ix < blocks[u].succ.size()) {
                int v = blocks[u].succ[ix++];
                if (!vis[v]) { vis[v] = 1; stk.push_back({v, 0}); }
            } else { post.push_back(u); stk.pop_back(); }
        }
        for (auto it = post.rbegin(); it != post.rend(); ++it) rpo.push_back(*it);
        for (size_t i = 0; i < rpo.size(); ++i) rpo_num[rpo[i]] = (int)i;
    }

    void compute_dominators() {
        int n = (int)blocks.size();
        idom.assign(n, -1);
        if (n == 0) return;
        int start = entry_block();
        idom[start] = start;
        compute_rpo();
        auto intersect = [&](int a, int b2) {
            while (a != b2) {
                while (rpo_num[a] > rpo_num[b2]) a = idom[a];
                while (rpo_num[b2] > rpo_num[a]) b2 = idom[b2];
            }
            return a;
        };
        bool changed = true; int guard = 0;
        while (changed && guard++ < n + 4) {
            changed = false;
            for (int rn : rpo) {
                if (rn == start) continue;
                int ni = -1;
                for (int p : blocks[rn].pred) {
                    if (rpo_num[p] < 0 || idom[p] == -1) continue;
                    ni = (ni == -1) ? p : intersect(p, ni);
                }
                if (ni != -1 && idom[rn] != ni) { idom[rn] = ni; changed = true; }
            }
        }
    }

    /* post-dominators: dominators on the reverse CFG with a virtual exit. */
    /* Post-dominators via Cooper-Harvey-Kennedy on the reverse CFG with a single
     * virtual exit node `V = n`. ipdom[i] is the immediate post-dominator block
     * id (or n for "virtual exit", which we then treat as -1 / "function end").
     * A unique virtual exit is essential: with multiple ret blocks, intersect
     * would otherwise never converge and spin. */
    std::vector<int> prpo, prpo_num;
    void compute_postdom() {
        int n = (int)blocks.size();
        ipdom.assign(n, -1);
        if (n == 0) return;
        int V = n;                       /* virtual exit node id */
        /* successors on the reverse graph = predecessors on the forward graph;
         * plus V is a "predecessor" (reverse-succ) of every exit block. */
        std::vector<int> pdom(n + 1, -1);
        pdom[V] = V;

        /* reverse post-order of the reverse CFG starting at V. */
        std::vector<char> vis(n + 1, 0);
        std::vector<int> post;
        /* iterative DFS to avoid deep recursion / stack overflow */
        std::vector<std::pair<int,size_t>> stk;
        /* build reverse-succ lists: for V -> all exits; for block u -> its preds */
        auto rsucc = [&](int u, std::vector<int>& out_) {
            out_.clear();
            if (u == V) {
                for (auto& b : blocks) if (b.succ.empty()) out_.push_back(b.id);
            } else {
                for (int p : blocks[u].pred) out_.push_back(p);
            }
        };
        std::vector<int> tmp;
        stk.push_back({V, 0}); vis[V] = 1;
        std::vector<std::vector<int>> cache(n + 1);
        rsucc(V, cache[V]);
        while (!stk.empty()) {
            int u = stk.back().first; size_t& ix = stk.back().second;
            if (cache[u].empty() && ix == 0) rsucc(u, cache[u]);
            if (ix < cache[u].size()) {
                int w = cache[u][ix++];
                if (!vis[w]) { vis[w] = 1; rsucc(w, cache[w]); stk.push_back({w, 0}); }
            } else { post.push_back(u); stk.pop_back(); }
        }
        prpo.clear(); prpo_num.assign(n + 1, -1);
        for (auto it = post.rbegin(); it != post.rend(); ++it) prpo.push_back(*it);
        for (size_t i = 0; i < prpo.size(); ++i) prpo_num[prpo[i]] = (int)i;

        auto intersect = [&](int a, int b2) -> int {
            int guard = 0;
            while (a != b2) {
                if (++guard > 4 * (n + 2)) return V;   /* safety */
                while (prpo_num[a] >= 0 && prpo_num[b2] >= 0 &&
                       prpo_num[a] > prpo_num[b2]) {
                    if (pdom[a] < 0) return V;
                    a = pdom[a];
                }
                while (prpo_num[a] >= 0 && prpo_num[b2] >= 0 &&
                       prpo_num[b2] > prpo_num[a]) {
                    if (pdom[b2] < 0) return V;
                    b2 = pdom[b2];
                }
                if (prpo_num[a] < 0 || prpo_num[b2] < 0) return V;
            }
            return a;
        };

        bool changed = true; int guard = 0;
        while (changed && guard++ < n + 8) {
            changed = false;
            for (int rn : prpo) {
                if (rn == V) continue;
                /* reverse-predecessors = forward-successors; for an exit block its
                 * reverse-pred is V. */
                int ni = -1;
                if (blocks[rn].succ.empty()) ni = V;
                for (int s : blocks[rn].succ) {
                    if (prpo_num[s] < 0 || pdom[s] == -1) continue;
                    ni = (ni == -1) ? s : intersect(s, ni);
                }
                if (ni != -1 && pdom[rn] != ni) { pdom[rn] = ni; changed = true; }
            }
        }
        for (int i = 0; i < n; ++i) ipdom[i] = (pdom[i] == V) ? -1 : pdom[i];
        (void)tmp;
    }

    bool dominates(int a, int b2) {
        if (a < 0 || b2 < 0) return false;
        int x = b2;
        while (true) {
            if (x == a) return true;
            if (idom[x] == x) break;
            x = idom[x];
            if (x < 0) break;
        }
        return false;
    }

    struct Loop { int header = -1; std::set<int> body; std::set<int> latches; };
    std::vector<Loop> loops;
    std::map<int,int> loop_of_header;

    /* LOOP-LOCAL post-dominators (for non-duplicating in-loop forward structuring): post-doms on
     * the loop body's FORWARD flow, where the back-edge (to header) and every loop-exit edge are
     * routed to a single virtual exit. loop_ipdom[u] is the block all of u's in-loop forward paths
     * funnel through before continue/break — an in-loop join J that loop-post-dominates its feeding
     * region is a loop-forward-SINK: emit J once, nested arms fall through, ZERO gotos, ZERO code
     * duplication. Returns block-id -> loop-ipdom (-1 = virtual exit). Loops are small. */
    std::map<int,int> compute_loop_postdom(const Loop& lp) {
        std::vector<int> B(lp.body.begin(), lp.body.end());
        int m = (int)B.size();
        std::map<int,int> idx; for (int i = 0; i < m; ++i) idx[B[i]] = i;
        int V = m;                                   /* virtual exit */
        auto fsucc = [&](int i, std::set<int>& out) {
            out.clear();
            for (int s : blocks[B[i]].succ) {
                if (s == lp.header) { out.insert(V); continue; }   /* back-edge -> exit */
                auto it = idx.find(s);
                if (it == idx.end()) out.insert(V);                /* loop exit -> exit */
                else out.insert(it->second);
            }
            if (blocks[B[i]].succ.empty()) out.insert(V);
        };
        std::vector<int> order; std::vector<char> vis(m + 1, 0);
        std::function<void(int)> dfs = [&](int u) {
            if (u == V || vis[u]) return; vis[u] = 1;
            std::set<int> ss; fsucc(u, ss);
            for (int w : ss) if (w != V) dfs(w);
            order.push_back(u);
        };
        if (idx.count(lp.header)) dfs(idx[lp.header]);
        std::reverse(order.begin(), order.end());
        std::vector<int> rpo(m + 1, -1); for (size_t i = 0; i < order.size(); ++i) rpo[order[i]] = (int)i;
        rpo[V] = (int)order.size();                  /* V is last in the forward order */
        std::vector<int> pd(m + 1, -1); pd[V] = V;
        auto inter = [&](int a, int b2) {
            int g = 0;
            while (a != b2) {
                if (a == V || b2 == V) return V;   /* a node that can exit/continue has no in-loop postdom */
                if (++g > 4 * (m + 2)) return V;
                while (rpo[a] > rpo[b2]) { if (pd[a] < 0 || pd[a] == a) return V; a = pd[a]; }
                while (rpo[b2] > rpo[a]) { if (pd[b2] < 0 || pd[b2] == b2) return V; b2 = pd[b2]; }
            }
            return a;
        };
        bool ch = true; int g = 0;
        while (ch && g++ < m + 8) {
            ch = false;
            for (auto it = order.rbegin(); it != order.rend(); ++it) {
                int u = *it; std::set<int> ss; fsucc(u, ss);
                int ni = -1;
                for (int s : ss) { if (rpo[s] < 0 || pd[s] < 0) continue; ni = (ni < 0) ? s : inter(s, ni); }
                if (ni >= 0 && pd[u] != ni) { pd[u] = ni; ch = true; }
            }
        }
        std::map<int,int> out;
        for (int i = 0; i < m; ++i) out[B[i]] = (pd[i] == V || pd[i] < 0) ? -1 : B[pd[i]];
        return out;
    }

    /* for-loop reconstruction: a counted pretest loop (init in the preheader, a
     * single `IV = IV +/- c` latch increment, IV in the exit condition) renders as
     * `for(init; cond; incr)`. ForInfo carries the hoisted init/incr text; the init
     * + increment statements are suppressed at their original sites. Pure re-render
     * of the existing pretest-while — GOTO-neutral. Gated by DS_NO_FORLOOP. */
    struct ForInfo { bool ok = false; std::string iv; char op = '+'; int64_t step = 0;
                     int init_blk = -1, init_idx = -1; };  /* rendered at EMIT time (post-autoname) */
    std::map<int,ForInfo> for_of_header;
    std::set<std::pair<int,int>> iv_suppressed_stmts;   /* (block_id, stmt_idx) to skip */
    std::map<int,std::string> induction_var_of_header;  /* header -> IV name (shared with naming) */

    void find_loops() {
        loops.clear(); loop_of_header.clear();
        std::map<int, Loop> byh;
        for (auto& b : blocks) {
            for (int s : b.succ) {
                if (dominates(s, b.id)) {   /* back edge b->s */
                    Loop& lp = byh[s];
                    lp.header = s;
                    lp.latches.insert(b.id);
                    lp.body.insert(s);
                    std::vector<int> work;
                    if (b.id != s) { lp.body.insert(b.id); work.push_back(b.id); }
                    while (!work.empty()) {
                        int u = work.back(); work.pop_back();
                        for (int p : blocks[u].pred)
                            if (!lp.body.count(p)) { lp.body.insert(p); work.push_back(p); }
                    }
                }
            }
        }
        for (auto& kv : byh) {
            loop_of_header[kv.first] = (int)loops.size();
            loops.push_back(kv.second);
        }
    }

