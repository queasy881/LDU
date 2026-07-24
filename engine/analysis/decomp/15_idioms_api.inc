/* 15_idioms_api.inc -- idiom + API recovery (min/max, locks, known_api, STL)
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    void lift_call(Block& b, const Insn& in) {
        std::string callee; bool indirect = false; int ret_kind = 1; int pc = 4;
        ExprP itgt;   /* indirect-call target, kept as a live child for dataflow */
        const cs_x86& x = in.x86;
        uint64_t target = 0; bool have_target = false;
        cc_float_mask = 0;   /* reset; set when a callee sig is resolved */
        cc_ptr_param_mask = 0;   /* reset; set when a callee sig is resolved */
        for (int _p = 0; _p < 4; ++_p) cc_ptr_param_w[_p] = 0;
        cc_pc_from_sig = false;  /* reset; set true when pc comes from sigtab */

        /* Drop compiler-inserted security/runtime housekeeping calls entirely:
         * the stack cookie check and CRT init guards have no observable effect on
         * the recovered C and would crash the recompiled output (cookie mismatch)
         * or fail to link. */
        /* `... xor reg, rsp; call F` is the stack-cookie check regardless of
         * whether F resolved to a name. Dropping it (and NOT clobbering rax) is
         * essential: otherwise the call's return-temp overwrites the function's
         * real return value set just before the epilogue (ip_octet_valid returned
         * 0 instead of 1, my_itoa returned 0 instead of len). */
        if (cookie_call_addrs.count(in.addr) || is_cookie_xor(prev_insn)) return;
        /* drop the prologue __chkstk stack-probe call (recorded by scan_prologue).
         * It only touches rsp; eliding it keeps rax intact for the `sub rsp,rax`. */
        if (chkstk_call_addrs.count(in.addr)) return;
        if (in.has_branch_target) {
            std::string nm = name_for_rva(in.branch_target);
            if (nm == "__security_check_cookie" ||
                nm == "__GSHandlerCheck" ||
                nm.rfind("__security", 0) == 0 ||
                nm == "_RTC_CheckEsp" ||
                nm.rfind("_RTC_", 0) == 0 ||
                nm.rfind("__chkstk", 0) == 0 ||
                nm == "__chkstk") {
                /* drop entirely; these housekeeping calls preserve all
                 * caller-visible state including the return value in rax, so we
                 * must NOT clobber regfile[RAX] here. */
                return;
            }
        }

        if (in.has_branch_target) {
            target = in.branch_target; have_target = true;
            callee = name_for_rva(in.branch_target);
            /* import? render via the imported name directly */
            bool is_import = false;
            for (size_t i = 0; i < e->import_len; ++i)
                if (e->imports[i].iat_rva == in.branch_target) { is_import = true; break; }
            if (sigtab && sigtab->count(in.branch_target)) {
                const FuncSig& s = sigtab->at(in.branch_target);
                ret_kind = s.ret_kind; pc = s.param_count;
                cc_float_mask = s.float_mask;
                cc_ptr_param_mask = s.ptr_param_mask;
                for (int _p = 0; _p < 4; ++_p) cc_ptr_param_w[_p] = s.ptr_param_w[_p];
                cc_pc_from_sig = true;
                extern_callees[callee] = ret_kind;
            } else {
                /* unknown direct target: assume returns long long, 4 args */
                ret_kind = 2; pc = 4;
                extern_callees[callee] = ret_kind;
            }
            /* A `j_<api>` import thunk (`jmp qword ptr [IAT]`) has a jmp-only body,
             * so build_sig_table recovered 0 params for it and EVERY call site
             * dropped all args (`j_memset()` for a 3-arg memset, `j_memcmp()` for a
             * 3-arg memcmp). Recover the true arity/return-kind from the API it
             * forwards to: strip the `j_` and consult the known-API table. This
             * overrides the thunk's under-counted sigtab entry. */
            if (callee.rfind("j_", 0) == 0) {
                int aargc, ark;
                if (known_api(callee.substr(2), aargc, ark)) {
                    pc = aargc; ret_kind = ark; cc_float_mask = 0;
                    cc_pc_from_sig = true;
                }
            }
            (void)is_import;
        } else if (x.op_count >= 1) {
            const cs_x86_op& t = x.operands[0];
            if (t.type == X86_OP_MEM) {
                /* indirect call through memory (IAT / vtable). rip-relative IAT
                 * slot: name it if it is an import slot. */
                const x86_op_mem& m = t.mem;
                if (m.base == X86_REG_RIP && m.index == X86_REG_INVALID) {
                    uint64_t abs = in.addr + in.size + (uint64_t)m.disp;
                    std::string nm;
                    for (size_t i = 0; i < e->import_len; ++i)
                        if (e->imports[i].iat_rva == abs && e->imports[i].name[0]) {
                            nm = sani(e->imports[i].name); break;
                        }
                    if (!nm.empty()) {
                        callee = nm; ret_kind = 2; pc = 4;
                        extern_callees[nm] = 2;
                    } else {
                        ExprP md = resolve_mem(t, 8);
                        std::string fn; int rk2, pc2;
                        if (const_callee_name(md, fn, rk2, pc2)) {
                            callee = fn; ret_kind = rk2; pc = pc2; extern_callees[fn] = rk2;
                        } else {
                            callee = "((long long(*)())(" + render(md) + "))";
                            indirect = true; ret_kind = 2; pc = 4; itgt = md;
                        }
                    }
                } else {
                    ExprP md = resolve_mem(t, 8);
                    std::string nm; int rk2, pc2;
                    if (const_callee_name(md, nm, rk2, pc2)) {
                        callee = nm; ret_kind = rk2; pc = pc2; extern_callees[nm] = rk2;
                    } else {
                        callee = "((long long(*)())(" + render(md) + "))";
                        indirect = true; ret_kind = 2; pc = 4; itgt = md;
                    }
                }
            } else if (t.type == X86_OP_REG) {
                Reg r; int w; map_reg(t.reg, r, w);
                ExprP rv = reg_value(r, 8);
                std::string nm; int rk2, pc2;
                if (const_callee_name(rv, nm, rk2, pc2)) {
                    callee = nm; ret_kind = rk2; pc = pc2; extern_callees[nm] = rk2;
                } else {
                    callee = "((long long(*)())(" + render(rv) + "))";
                    indirect = true; ret_kind = 2; pc = 4; itgt = rv;
                }
            } else {
                callee = "((long long(*)())0)"; indirect = true; ret_kind = 2; pc = 4;
            }
        }
        (void)have_target; (void)target;

        /* Exact arity/return-kind for a recognized imported API — definitive for
         * every binary, so it overrides the pc=4 default and skips the reaching-def
         * heuristic (which cannot see a 1-arg `GetSystemMetrics` when the caller's
         * own params still sit in rdx/r8/r9). */
        /* known_api WINS over the sig table, including when the sig table already
         * spoke. It used to be gated on `!cc_pc_from_sig`, which sounds harmless and
         * is not: a call that reaches an API through a LOCAL JMP-THUNK gets a sigtab
         * entry for the thunk, and a thunk's body is one `jmp`, so its recovered
         * param_count is 0. That 0 then set cc_pc_from_sig and locked out the very
         * override meant to fix it, so the call lifted with NO arguments —
         *     0x5f3de  movzx r8d,[rsp+0x116]
         *     0x5f3e7  mov   rdx,[rsp+0xb0]
         *     0x5f3ef  mov   rcx,[rbx+0x28]
         *     0x5f3f3  call  0x56cb0
         * lifted as zero args, and the renderer then PADDED the call back out to the
         * declared 3-parameter prototype with literal `0`s, printing
         * `RtlMoveMemory(0, 0, 0)`: three real operands replaced by a confident lie
         * about NULL. (kernel32 fn_0005ed50, 11 sites; the audit's top finding.)
         *
         * The API's arity is a fixed SDK fact and the thunk's is an artifact of the
         * thunk having no body, so the fact must win. */
        if (!indirect && !callee.empty()) {
            int aargc, ark;
            if (known_api(callee, aargc, ark)) {
                pc = aargc; ret_kind = ark; cc_float_mask = 0;
                cc_pc_from_sig = true;
                extern_callees[callee] = ret_kind;
            }
        }

        /* UNKNOWN-arity callee (import / indirect, pc defaulted to 4): gate the arg
         * count by reaching definitions. A volatile arg register (rcx/rdx/r8/r9,
         * xmm0-3) not written since the prior in-block call holds a clobbered
         * leftover, never an argument — `GetTickCount()`, `ShowCursor(0)` were
         * rendered with 1-3 stale args. NARROWS ONLY (never widens), and is gated to
         * NON-sigtab callees so a typed internal call is never touched (corpus-safe).*/
        if (!cc_pc_from_sig) {
            bool xmm_arg[4];
            int rc = reaching_argc(in, b, xmm_arg);
            if (rc >= 0 && rc < pc) {
                pc = rc;
                cc_float_mask = 0;
                for (int k = 0; k < 4; ++k) if (xmm_arg[k]) cc_float_mask |= (1u << k);
            }
        }

        auto call = new_expr();
        call->kind = EK::Call; call->callee = callee; call->indirect = indirect;
        call->width = 8; call->ret_kind = ret_kind;
        /* Keep an indirect target as a live child (see the tail-call path): a value
         * used ONLY inside the callee string is invisible to dataflow, so its def is
         * eliminated as "unused" while the string use survives -> undeclared temp. */
        if (indirect && itgt) call->a = itgt;
        Reg argregs[4] = { R_RCX, R_RDX, R_R8, R_R9 };
        /* Caller-side stack-arg recovery (Win64 args 5+ at [rsp+0x20],[rsp+0x28],...).
         * Restricted to ANONYMOUS callees (`fun_/sub_/j_`, declared unparenthesized)
         * that already consume all 4 register args. A NAMED/exported callee has a
         * real prototype, so passing it an extra arg is a hard error (`dist_sq(int,
         * int,int,int)` -> C2197) AND a 4-arg callee's `[rsp+0x20]` store is just a
         * local spill — both excluded by the name gate. An unparenthesized callee
         * accepts extra args harmlessly, so this only ever ADDS a genuinely-present
         * stack arg (fun_0006708c: 4 reg args + 2 stack -> 6, recovering the va_list)
         * and never breaks a typed call. */
        bool anon_callee = !indirect &&
            (callee.rfind("fun_", 0) == 0 || callee.rfind("sub_", 0) == 0 ||
             callee.rfind("j_", 0) == 0);
        if (anon_callee && pc >= 4) {
            int sa = outgoing_stack_args(in, b);
            if (sa > 0 && 4 + sa > pc) pc = 4 + sa;
        }
        if (pc < 0) pc = 0;
        if (pc > 16) pc = 16;
        Reg xmmregs[4] = { R_XMM0, R_XMM1, R_XMM2, R_XMM3 };
        for (int i = 0; i < pc; ++i) {
            if (i < 4) {
                /* a float/double param at position i arrives in xmm[i], not the
                 * integer reg — pull from the right register class per the callee's
                 * recovered float_mask so `nr_sqrt((double)len2)` keeps its argument
                 * instead of rendering `nr_sqrt()`. */
                if (cc_float_mask & (1u << i)) {
                    ExprP fv = reg_value(xmmregs[i], 8);
                    /* a float const passed in the INTEGER reg (`mov r8d,0x3f800000; call`,
                     * varargs) — xmm[i] was never written (a backstop), so use the int-reg
                     * const as the float bits. The callee's float_mask already proves this
                     * position is float, so reinterpreting its constant is value-correct. */
                    if ((!fv || expr_has_in_backstop(fv))) {
                        ExprP iv = reg_value(argregs[i], 8);
                        if (iv && iv->kind == EK::Const && !iv->is_float) fv = iv;
                    }
                    if (fv) {
                        fv->is_float = true;
                        /* pick float vs double for a raw immediate: a 32-bit-fitting bit
                         * pattern is a `float` (1.0f), a wider one a `double`. */
                        if (fv->kind == EK::Const)
                            fv->width = (fv->cval >= -0x80000000LL && fv->cval <= 0xFFFFFFFFLL) ? 4 : 8;
                    }
                    call->args.push_back(fv);
                } else {
                    ExprP av = reg_value(argregs[i], 8);
                    /* the callee dereferences this arg => it is a pointer; type the
                     * caller's argument local accordingly (cross-function propagation). */
                    static const bool no_ptrparam = std::getenv("DS_NO_PTRPARAM") != nullptr;
                    if (!no_ptrparam && av && (cc_ptr_param_mask & (1u << i)))
                        apply_ptr_param_type(av, cc_ptr_param_w[i]);
                    /* a bare CONSTANT in the same proven-pointer position, whose value is a
                     * static-data address, is `&<global>` -- stamp addr_hint so render_const
                     * emits `&byte_<addr>` instead of raw hex. */
                    static const bool no_moreglobals = std::getenv("DS_NO_MOREGLOBALS") != nullptr;
                    if (!no_moreglobals && av && av->kind == EK::Const && !av->is_float &&
                        (uint64_t)av->cval > 0x1000 && (cc_ptr_param_mask & (1u << i)) &&
                        in_data_rva((uint64_t)av->cval)) {
                        av = new_expr(*av);   /* don't mutate a shared regfile node */
                        av->addr_hint = true;
                    }
                    call->args.push_back(av);
                }
            } else {
                /* 5th+ argument: the caller stores it to the outgoing arg area at
                 * [rsp + 0x20 + 8*(i-4)] before the call (x64 convention). Read
                 * that slot's tracked value so the call passes the right count. */
                int64_t off = 0x20 + 8 * (int64_t)(i - 4);
                std::string nm = slot_name(off, 8);
                int w = var_width.count(nm) ? var_width[nm] : 8;
                call->args.push_back(mkVar(nm, w));
            }
        }

        /* ALWAYS bind the result to a temp, even for a "void" callee: return-type
         * detection is imperfect, and a caller that reads `ax`/`eax`/`rax` after
         * the call (e.g. `call f; movsx edi,ax; cmp edi,2`) must see the real value
         * instead of the `0` fallback. Genuinely-void calls whose temp is never
         * read are reduced back to a bare call statement by
         * simplify_unused_call_temps() after dataflow. */
        {
            std::string tn = "t" + std::to_string(++temp_seq);
            call_temps.insert(tn);
            /* a float/double callee (ret_kind 3/4) returns in XMM0, NOT rax. Binding
             * the result to rax dropped the value: `my_sqrt(len2)` rendered as a
             * void `fun_x();` and the following divsd read a stale xmm0, so
             * vec3_normalize/ray_sphere lost the sqrt entirely. Bind to XMM0 and
             * type the temp float so the value flows into the FP dataflow. */
            bool fret = (ret_kind == 3 || ret_kind == 4);
            int cw = fret ? (ret_kind == 4 ? 8 : 4)
                          : ((ret_kind == 2) ? 8 : (ret_kind == 0) ? 8 : 4);
            var_width[tn] = cw;
            if (fret) { var_is_float[tn] = true; call->is_float = true; }
            else if (cw == 8) var_is_ll[tn] = true;
            ExprP lhs = mkVar(tn, cw); if (fret) lhs->is_float = true;
            Stmt s; s.kind = SK::Assign; s.lhs = lhs; s.rhs = call;
            s.addr = in.addr; b.stmts.push_back(std::move(s));
            ExprP tv = mkVar(tn, cw); if (fret) tv->is_float = true;
            /* Bind the result to RAX ALWAYS, and to XMM0 as well when float. The
             * return CLASS detection is imperfect: a callee mis-typed float binds
             * only XMM0, so the caller's integer use of the result (`call f; mov
             * [x],rax`) reads a stale rax and leaks `in_RAX`. Binding both means a
             * read of either register class sees the value regardless — the float
             * dataflow (XMM0) is preserved AND the integer view (RAX) is present. */
            regfile[R_RAX] = tv;
            if (fret) regfile[R_XMM0] = tv;
        }
    }

    std::set<std::string> call_temps;
    std::set<std::string> spill_temps;   /* memory-clobber snapshot temps */
    std::set<std::string> cse_temps;     /* common-subexpression temps */

    /* Intra-statement CSE / let-insertion: a chain of register ops (`x = x+C;
     * x = (x^(x>>30))*C2; ...`) is kept symbolic and only materialized at the
     * statement that consumes it, so each reuse of `x` re-inlines the whole prior
     * expression — splitmix/morton/popcount collapse into one 600-char monster.
     * Here we hoist repeated NON-trivial pure subexpressions of one statement's
     * RHS (or a terminator) into named temps emitted just before it, smallest-
     * first so inner values are bound before the outer ones that reference them.
     * Value-preserving (a temp == the subexpr, no intervening write within one
     * expression), so behaviour and the corpus are unchanged. */
    /* Hoist pointer-shared subtrees: a single shared_ptr node referenced by >=2
     * parent edges (a cmov index / address reused across an unrolled access) is
     * bound to one temp, so render() prints the value ONCE instead of re-expanding
     * the DAG (fn_0000ce70: an 81x-shared cmov index -> a 5 KB line). O(distinct
     * nodes). Value-preserving — the shared node is literally one value. Runs
     * before cse_expr so the flattened tree it sees is small. */
    ExprP hoist_shared(ExprP root, std::vector<Stmt>& hoists) {
        if (!root) return root;
        std::map<const Expr*, ExprP> node;
        std::map<const Expr*, int> refs;
        /* DETERMINISM: `refs`/`node` are keyed by the node's HEAP ADDRESS, so
         * iterating them walks the tree in pointer order — which changes on every
         * process launch (ASLR + allocation history). Temps are minted inside that
         * loop, so the same function produced DIFFERENT temp numbering, and hence
         * different declarations and types, from one run to the next: measured
         * 21/600 ntdll functions differing between two identical single-threaded
         * runs of the unmodified engine. It also broke the parallel-vs-serial
         * equality the throughput test asserts, and meant reopening a binary could
         * show different pseudocode. Record first-visit (DFS pre-order) sequence
         * and drive every later loop off THAT, so the traversal is a property of
         * the expression tree instead of the allocator. */
        std::vector<const Expr*> order;
        std::function<void(const ExprP&)> cnt = [&](const ExprP& e) {
            if (!e) return;
            node[e.get()] = e;
            if (refs[e.get()]++ > 0) return;   /* children already counted */
            order.push_back(e.get());
            cnt(e->a); cnt(e->b); cnt(e->c);
            for (auto& ar : e->args) cnt(ar);
        };
        cnt(root);
        /* which shared nodes are worth binding: referenced >=2x and non-trivial. */
        std::map<const Expr*, ExprP> repl;
        for (const Expr* key : order) {
            auto rf = refs.find(key);
            if (rf == refs.end() || rf->second < 2) continue;
            const ExprP& e = node[key];
            if (!e) continue;
            EK k = e->kind;
            if (k == EK::Const || k == EK::Var || k == EK::Reg || k == EK::Str) continue;
            if (k == EK::Cast && e->a &&
                (e->a->kind == EK::Const || e->a->kind == EK::Var)) continue;  /* trivial */
            std::string tn = "t" + std::to_string(++temp_seq);
            cse_temps.insert(tn);
            int w = e->width ? e->width : 8;
            var_width[tn] = w; if (w >= 8) var_is_ll[tn] = true;
            if (e->is_float) var_is_float[tn] = true;
            ExprP tv = mkVar(tn, w); if (e->is_float) tv->is_float = true;
            repl[key] = tv;
        }
        if (repl.empty()) return root;
        /* memoized pointer-subst: replace each shared node with its temp var; the
         * temp DEFs are rebuilt too so nested sharing collapses (inner temps are
         * referenced by outer temp defs). */
        std::map<const Expr*, ExprP> memo;
        std::function<ExprP(const ExprP&, bool)> rebuild = [&](const ExprP& e, bool top) -> ExprP {
            if (!e) return e;
            auto rit = repl.find(e.get());
            if (rit != repl.end() && !top) return rit->second;   /* use the temp var */
            auto mit = memo.find(e.get());
            if (mit != memo.end()) return mit->second;
            ExprP c = new_expr(*e);
            c->a = rebuild(e->a, false); c->b = rebuild(e->b, false); c->c = rebuild(e->c, false);
            for (auto& ar : c->args) ar = rebuild(ar, false);
            memo[e.get()] = c;
            return c;
        };
        /* emit temp DEFs; a def's RHS is the node with its OWN shared children
         * replaced by their temps (top=true so the node itself isn't self-replaced). */
        std::vector<std::pair<int,Stmt>> defs;  /* (depth-ish order via temp seq) */
        /* Same reason as above: drive this off the recorded traversal order, not
         * `repl`'s pointer-keyed order, so the emitted defs are in a stable
         * sequence. The dependency sort below is stable, so its input order
         * decides the output. */
        for (const Expr* key : order) {
            auto rp = repl.find(key);
            if (rp == repl.end()) continue;
            const ExprP& e = node[key];
            Stmt def; def.kind = SK::Assign; def.lhs = clone(rp->second);
            def.rhs = rebuild(e, true);
            defs.push_back({0, std::move(def)});
        }
        /* Order defs so an inner temp is defined before an outer one that uses it:
         * a def whose RHS references temp T must come after T's def. Simple stable
         * pass: repeatedly emit defs whose RHS temps are all already emitted. */
        std::set<std::string> emitted;
        std::vector<Stmt> ordered;
        bool progress = true;
        while (progress && ordered.size() < defs.size()) {
            progress = false;
            for (auto& pr : defs) {
                Stmt& d = pr.second;
                if (d.kind != SK::Assign || !d.lhs) continue;   /* already taken */
                std::set<std::string> used;
                collect_var_names(d.rhs, used);
                bool ready = true;
                for (auto& u : used)
                    if (cse_temps.count(u) && repl_has_temp(repl, u) && !emitted.count(u)) { ready = false; break; }
                if (!ready) continue;
                emitted.insert(d.lhs->name);
                ordered.push_back(d);
                d.kind = SK::Comment; d.lhs = nullptr;   /* mark taken */
                progress = true;
            }
        }
        for (auto& pr : defs) if (pr.second.kind == SK::Assign && pr.second.lhs) ordered.push_back(pr.second);
        for (auto& d : ordered) hoists.push_back(std::move(d));
        return rebuild(root, true);
    }
    /* true if `nm` is one of the temp vars we just created for a shared node */
    bool repl_has_temp(const std::map<const Expr*, ExprP>& repl, const std::string& nm) {
        for (auto& kv : repl) if (kv.second && kv.second->name == nm) return true;
        return false;
    }
    ExprP cse_expr(ExprP e, std::vector<Stmt>& hoists) {
        if (!e) return e;
        e = hoist_shared(e, hoists);           /* collapse pointer-shared DAG first */
        if (node_count(e) > 2500) return e;   /* skip pathological unrolled trees */
        for (int iter = 0; iter < 60; ++iter) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            std::vector<ExprP> subs;
            collect_subs(e, subs);
            for (auto& h : hoists) collect_subs(h.rhs, subs);
            ExprP best = nullptr; int bestsz = 0;
            std::vector<ExprP> seen;
            for (auto& sub : subs) {
                bool dup = false;
                for (auto& s2 : seen) if (exprEqual(s2, sub)) { dup = true; break; }
                if (dup) continue;
                seen.push_back(sub);
                int sz = node_count(sub);
                if (sz < 3 || has_impure_call(sub)) continue;
                int cnt = count_occ(e, sub);
                for (auto& h : hoists) cnt += count_occ(h.rhs, sub);
                if (cnt < 2) continue;
                if (!best || sz < bestsz) { best = sub; bestsz = sz; }
            }
            if (!best) break;
            std::string tn = "t" + std::to_string(++temp_seq);
            cse_temps.insert(tn);
            int w = best->width ? best->width : 8;
            var_width[tn] = w; if (w >= 8) var_is_ll[tn] = true;
            if (best->is_float) var_is_float[tn] = true;
            ExprP tv = mkVar(tn, w); if (best->is_float) tv->is_float = true;
            Stmt def; def.kind = SK::Assign; def.lhs = mkVar(tn, w);
            if (best->is_float) def.lhs->is_float = true;
            def.rhs = clone(best);
            e = subst_subtree(e, best, tv);
            for (auto& h : hoists) h.rhs = subst_subtree(h.rhs, best, tv);
            hoists.push_back(std::move(def));
            if ((int)hoists.size() > 100) break;
        }
        return e;
    }
    void cse_materialize() {
        for (auto& b : blocks) {
            std::vector<Stmt> out;
            for (auto& s : b.stmts) {
                /* SK::Call is a BARE call statement (`fun_x(bigexpr, bigexpr);`);
                 * its args were never run through intra-statement CSE, so a
                 * repeated address/load subexpression re-inlined at each arg blew
                 * the line to ~1KB (fn_0000bc40). Treat it like an assigned call
                 * (`t = f(...)`), which already collapses via this path. */
                if ((s.kind == SK::Assign || s.kind == SK::Call) && s.rhs) {
                    std::vector<Stmt> hoists;
                    ExprP nr = cse_expr(s.rhs, hoists);
                    for (auto& h : hoists) out.push_back(std::move(h));
                    Stmt ns = s; ns.rhs = nr;
                    /* Drop a store byte-identical to the immediately-preceding one:
                     * MSVC re-emits the same aggregate/field copy twice (a movdqu-
                     * lowered pair copied through overlapping slots), the second write
                     * being a provable no-op. Guarded HARD: assign-only (never a bare
                     * call side effect), pure (no call in lhs/rhs), and the lhs must
                     * NOT occur in the rhs so a self-update `x = x + 1; x = x + 1;`
                     * (or a store read back through its own address) is never
                     * collapsed. Runtime aliasing is safe: copying a value onto its
                     * own storage twice is idempotent. */
                    if (s.kind == SK::Assign && ns.lhs && ns.rhs && !out.empty() &&
                        out.back().kind == SK::Assign && out.back().lhs && out.back().rhs &&
                        exprEqual(out.back().lhs, ns.lhs) && exprEqual(out.back().rhs, ns.rhs) &&
                        !has_call(ns.lhs) && !has_call(ns.rhs) &&
                        count_occ(ns.rhs, ns.lhs) == 0) {
                        continue;   /* redundant duplicate store */
                    }
                    out.push_back(std::move(ns));
                } else out.push_back(s);
            }
            if (b.cond)       { std::vector<Stmt> h; b.cond       = cse_expr(b.cond, h);       for (auto& x : h) out.push_back(std::move(x)); }
            if (b.ret_value)  { std::vector<Stmt> h; b.ret_value  = cse_expr(b.ret_value, h);  for (auto& x : h) out.push_back(std::move(x)); }
            if (b.switch_var) { std::vector<Stmt> h; b.switch_var = cse_expr(b.switch_var, h); for (auto& x : h) out.push_back(std::move(x)); }
            b.stmts = std::move(out);
        }
    }

    /* Block-local GVN for loop-invariant PURE-ARITHMETIC subexpressions. An
     * address like `&A[i*4]` (= (char*)a1 + sext(i)*4) is recomputed once per
     * store in unrolled array code (mat4_mul/transform_points), exploding the
     * line count. Hoist a pure (no Mem, no Call) subexpr that recurs across >=2
     * statements into one temp at its first use — value-preserving as long as no
     * leaf var is reassigned in the span. Mem-reading subexprs are excluded to
     * sidestep store aliasing. */
    /* Common dominator of two blocks (walk idom). */
    int common_dom(int a, int b) {
        if (a < 0) return b; if (b < 0) return a;
        std::set<int> anc; int x = a, guard = 0;
        while (guard++ < 100000) { anc.insert(x); if (idom[x] == x || idom[x] < 0) break; x = idom[x]; }
        int y = b; guard = 0;
        while (!anc.count(y) && guard++ < 100000) { if (idom[y] == y || idom[y] < 0) return -1; y = idom[y]; }
        return anc.count(y) ? y : -1;
    }
    /* True iff none of `leaves` is reassigned on any control path from block D to a
     * `use` block (so the expression's value at D equals its value at each use).
     * Forward BFS from D's successors; a use block is not expanded past (the use
     * sits inside it); reaching D again (loop back) stops that path. */
    bool leaves_stable(int D, const std::set<int>& uses, const std::set<std::string>& leaves) {
        (void)uses;
        /* Over-conservative: ANY block forward-reachable from D (until D loops back)
         * that reassigns a leaf makes the value unstable — even one after the last
         * use (e.g. a loop latch's `i = i + 1`). Rejecting those is safe (fewer
         * CSEs), never wrong. Covers all real D->use paths since D dominates uses. */
        std::set<int> vis; std::vector<int> work(blocks[D].succ.begin(), blocks[D].succ.end());
        int guard = 0;
        while (!work.empty()) {
            if (guard++ > 200000) return false;
            int b = work.back(); work.pop_back();
            if (b < 0 || b == D || vis.count(b)) continue;
            vis.insert(b);
            for (auto& s : blocks[b].stmts)
                if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && leaves.count(s.lhs->name))
                    return false;
            for (int s : blocks[b].succ) work.push_back(s);
        }
        return true;
    }
    /* Companion to leaves_stable for the case where D is ITSELF a use block: true iff no
     * leaf of `sub` is assigned inside D from the def's INSERTION POINT to D's end, so
     * the one shared temp is valid for every later use in D and in D's successors.
     * MIRRORS the placement in cse_global exactly — the def goes before D's first
     * STATEMENT use of sub, or at D's end when sub occurs only in D's cond/ret_value
     * (those are evaluated after every statement, so an end-of-block def is consistent).
     * leaves_stable() cannot cover this: it walks D's SUCCESSORS and skips D itself. */
    bool leaves_stable_within(int D, const ExprP& sub, const std::set<std::string>& leaves) {
        Block& DB = blocks[D];
        int insert_at = (int)DB.stmts.size();
        for (int si = 0; si < (int)DB.stmts.size(); ++si)
            if (DB.stmts[si].kind == SK::Assign &&
                (count_occ(DB.stmts[si].rhs, sub) + count_occ(DB.stmts[si].lhs, sub)) > 0) {
                insert_at = si; break;
            }
        for (int si = insert_at; si < (int)DB.stmts.size(); ++si) {
            const Stmt& s = DB.stmts[si];
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind == EK::Var && leaves.count(s.lhs->name))
                return false;
        }
        return true;
    }
    /* True if `e` contains a `/` or `%` — hoisting such a value to a dominator could
     * move a guarded division ahead of its guard (a new divide-by-zero fault). */
    /* (Measured 2026-07-16: relaxing this to allow a non-zero, non-(-1) CONSTANT divisor
     * — which cannot trap and so is safe to hoist — changed NullWare output by exactly
     * ZERO lines. This guard is not what keeps `x % 7` out of cse_global; its other
     * conditions are. Don't "fix" it again without measuring first.) */
    bool has_div(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Binary && (e->op == "/" || e->op == "%")) return true;
        return has_div(e->a) || has_div(e->b) || has_div(e->c);
    }
    /* Structural key for CSE occurrence-counting. Built so that
     *     cse_key(a) == cse_key(b)   <=>   exprEqual(a, b)
     * for every expr kind (impure calls get a per-NODE unique key, mirroring that
     * exprEqual never treats a real call as equal to anything). Memoized per node,
     * so populating the whole occurrence table is LINEAR in the tree size — the
     * previous cse_global did an O(candidates^2) pairwise exprEqual dedup plus an
     * O(candidates * statements) re-scan every iteration (measured 29.5 s on a
     * 774-block function). Output is byte-identical; only the bookkeeping changed. */
    void cse_key(const ExprP& e, std::string& out,
                 std::unordered_map<const Expr*, std::string>& memo) {
        if (!e) { out += '#'; return; }
        auto it = memo.find(e.get());
        if (it != memo.end()) { out += it->second; return; }
        std::string k;
        switch (e->kind) {
            case EK::Const: k = "C" + std::to_string((long long)e->cval) + ";"; break;
            case EK::Reg:   k = "R" + std::to_string((int)e->reg) + ";"; break;
            case EK::Var:   k = "V" + e->name + ";"; break;
            case EK::Str:   k = "S" + e->text + ";"; break;
            case EK::Mem:   { std::string a; cse_key(e->a, a, memo); k = "M" + std::to_string(e->width) + "(" + a + ")"; break; }
            case EK::Unary: { std::string a; cse_key(e->a, a, memo); k = "U" + e->op + "(" + a + ")"; break; }
            case EK::Cast:  { std::string a; cse_key(e->a, a, memo); k = "K" + e->op + "(" + a + ")"; break; }
            case EK::AddrOf:{ std::string a; cse_key(e->a, a, memo); k = "A(" + a + ")"; break; }
            case EK::Binary:{ std::string a, b; cse_key(e->a, a, memo); cse_key(e->b, b, memo); k = "B" + e->op + "(" + a + "," + b + ")"; break; }
            case EK::Ternary:{ std::string a, b, c; cse_key(e->a, a, memo); cse_key(e->b, b, memo); cse_key(e->c, c, memo); k = "T(" + a + "," + b + "," + c + ")"; break; }
            case EK::Call:
                if (e->callee.rfind("__", 0) == 0 && !e->indirect) {   /* pure intrinsic: value-equal, like exprEqual */
                    k = "P" + e->callee + "(";
                    for (auto& ar : e->args) { std::string a; cse_key(ar, a, memo); k += a; k += ","; }
                    k += ")";
                } else {                                               /* impure call: never merges -> unique key */
                    char buf[24]; std::snprintf(buf, sizeof buf, "Q%p", (void*)e.get()); k = buf;
                }
                break;
            default: k = "?"; break;
        }
        out += k;
        memo.emplace(e.get(), std::move(k));
    }
    /* Recurse every subtree POSITION (so a value used N times counts N — matching
     * count_occ's DAG-expanded semantics), tallying count + block-set by key. */
    void cse_hash(const ExprP& e, int blk,
                  std::unordered_map<std::string, std::pair<int, std::set<int>>>& occ,
                  std::unordered_map<const Expr*, std::string>& memo) {
        if (!e) return;
        std::string k; cse_key(e, k, memo);
        auto& slot = occ[k]; slot.first++; slot.second.insert(blk);
        cse_hash(e->a, blk, occ, memo); cse_hash(e->b, blk, occ, memo); cse_hash(e->c, blk, occ, memo);
        for (auto& ar : e->args) cse_hash(ar, blk, occ, memo);
    }
    /* GLOBAL (cross-block) CSE / materialization. Hex-Rays' readability comes from
     * propagation that REFUSES to duplicate a multi-use value — so a value used >=2
     * times survives as ONE named temp. Here: a PURE (no memory, no call) arithmetic
     * subexpression that occurs >=2 times across >=2 blocks is hoisted to a single
     * temp at the common dominator of its uses (when no leaf is reassigned between),
     * collapsing the per-iteration hash/index recomputation (ht_get/ht_put/csv) and
     * any propagation-duplicated multi-use value into one definition. */
    void cse_global() {
        for (int iter = 0; iter < 60; ++iter) {
            if (!budget_ok()) break;   /* deadline: stop refining, keep what we have */
            /* One linear pass: collect candidate subexprs (in the SAME order as
             * before, so the count/size tie-break is unchanged) AND tally every
             * subexpr's occurrence count + block-set by structural key. */
            std::vector<ExprP> cand;
            std::unordered_map<std::string, std::pair<int, std::set<int>>> occ;
            std::unordered_map<const Expr*, std::string> memo;
            for (auto& b : blocks) {
                auto scan = [&](const ExprP& e) { if (e) { collect_subs(e, cand); cse_hash(e, b.id, occ, memo); } };
                for (auto& s : b.stmts) if (s.kind==SK::Assign) { scan(s.rhs); scan(s.lhs); }
                scan(b.cond); scan(b.ret_value); scan(b.switch_var);
            }
            ExprP best=nullptr; int bestcnt=0, bestsz=0, bestD=-1; std::set<int> bestUses;
            std::unordered_set<std::string> seen;
            for (auto& sub : cand) {
                int sz = node_count(sub);
                if (sz < 4 || sz > 400 || has_call(sub) || reads_mem(sub) || has_div(sub)) continue;
                std::string k; cse_key(sub, k, memo);
                if (!seen.insert(k).second) continue;          /* dedup: O(1) key hash */
                auto oit = occ.find(k);
                if (oit == occ.end()) continue;
                int cnt = oit->second.first;
                const std::set<int>& ublocks = oit->second.second;
                if (cnt < 2 || ublocks.size() < 2) continue;   /* single-block: cse_cross_statement */
                int D = -1; for (int ub : ublocks) { D = common_dom(D, ub); if (D < 0) break; }
                if (D < 0 || (size_t)D >= blocks.size()) continue;
                /* Hard-assert real dominance so a common_dom slip can't cause a
                 * use-before-def. */
                bool dom_ok = true;
                for (int ub : ublocks) if (!dominates(D, ub)) { dom_ok = false; break; }
                if (!dom_ok) continue;
                std::set<std::string> leaves; collect_var_names(sub, leaves);
                if (leaves.empty()) continue;
                if (!leaves_stable(D, ublocks, leaves)) continue;
                /* D may be a USE block itself. That used to be refused outright, which
                 * also left the "place the def before the first use in D" branch below
                 * permanently dead — and forced every propagation-duplicated value whose
                 * dominator also uses it to stay duplicated at every site (NullWare's
                 * decryptor re-derives one xorshift hash 18 times across 15 blocks).
                 * The real hazard is narrow: leaves_stable() walks only D's SUCCESSORS
                 * and never inspects D itself, so a leaf reassigned INSIDE D after the
                 * insertion point would leave the shared temp stale. Check exactly that
                 * instead of rejecting the whole case.
                 * Require 3+ uses here: hoisting a mere 2-use value out of its own
                 * dominator costs a decl + a def line to save ONE duplicate, which
                 * measured as a NET +327 lines across NullWare. */
                if (ublocks.count(D) && (cnt < 3 || !leaves_stable_within(D, sub, leaves))) continue;
                if (cnt > bestcnt || (cnt==bestcnt && sz>bestsz)) { best=sub; bestcnt=cnt; bestsz=sz; bestD=D; bestUses=ublocks; }
            }
            if (!best) break;
            std::string tn = "t" + std::to_string(++temp_seq);
            cse_temps.insert(tn);
            int w = best->width ? best->width : 8;
            var_width[tn]=w; if (w>=8) var_is_ll[tn]=true; if (best->is_float) var_is_float[tn]=true;
            ExprP tv = mkVar(tn, w); if (best->is_float) tv->is_float=true;
            Stmt def; def.kind=SK::Assign; def.lhs=mkVar(tn,w); if(best->is_float) def.lhs->is_float=true; def.rhs=clone(best);
            /* place the def: before the first use IN D if D is a use block, else at D's end */
            Block& DB = blocks[bestD];
            int insert_at = (int)DB.stmts.size();
            if (bestUses.count(bestD)) {
                for (int si=0; si<(int)DB.stmts.size(); ++si)
                    if (DB.stmts[si].kind==SK::Assign &&
                        (count_occ(DB.stmts[si].rhs,best)+count_occ(DB.stmts[si].lhs,best))>0) { insert_at = si; break; }
            }
            for (auto& b : blocks) {
                for (auto& s : b.stmts) if (s.kind==SK::Assign) { s.rhs=subst_subtree(s.rhs,best,tv); s.lhs=subst_subtree(s.lhs,best,tv); }
                b.cond=subst_subtree(b.cond,best,tv); b.ret_value=subst_subtree(b.ret_value,best,tv); b.switch_var=subst_subtree(b.switch_var,best,tv);
            }
            DB.stmts.insert(DB.stmts.begin()+insert_at, std::move(def));
        }
    }

    /* The address `addr` is rooted at a global: after peeling +/-const and casts, the
     * base is a bare Const (`qword_G`) or a deref of a global-rooted address (a global
     * pointer chain). */
    bool mem_addr_global_rooted(const ExprP& addr) {
        ExprP base = addr;
        while (base && ((base->kind==EK::Binary && (base->op=="+"||base->op=="-") &&
                         base->b && base->b->kind==EK::Const) || base->kind==EK::Cast))
            base = base->a;
        if (!base) return false;
        if (base->kind==EK::Const) return true;
        if (base->kind==EK::Mem && base->a) return mem_addr_global_rooted(base->a);
        return false;
    }
    /* `e` reads memory ONLY through global bases (every Mem is global-rooted) and calls
     * nothing — so its value is stable across calls into other functions. */
    bool is_global_base_stable(const ExprP& e) {
        if (!e) return true;
        if (e->kind == EK::Call) return false;
        if (e->kind == EK::Mem) {
            if (!e->a || !mem_addr_global_rooted(e->a)) return false;
            return is_global_base_stable(e->a);
        }
        if (!is_global_base_stable(e->a) || !is_global_base_stable(e->b) ||
            !is_global_base_stable(e->c)) return false;
        for (auto& ar : e->args) if (!is_global_base_stable(ar)) return false;
        return true;
    }
