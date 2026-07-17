/* 20_loop_sinks.inc -- loop sinks, ladders, tail merging
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Emit a loop-body region [entry, body_stop) with its forward-sink chain: activate all sinks
     * (nested reaches fall through), emit the region, then emit each convergence ONCE in order. */
    void emit_loop_region(int entry, int body_stop, int header, std::string& dst) {
        std::vector<int> sinks = loop_sinks_for(header, body_stop);
        std::set<int> saved = active_loop_sinks;
        for (int Ji : sinks) active_loop_sinks.insert(Ji);
        emit_region(entry, body_stop, dst, header);
        for (int Ji : sinks) {
            if (structured.count(Ji)) continue;
            active_loop_sinks.erase(Ji);
            emit_region(Ji, body_stop, dst, header);
        }
        active_loop_sinks = saved;
    }
    void emit_loop_body(int header, int follow, std::string& dst, bool emit_latch = true) {
        Block& H = blocks[header];
        int body_stop = (cur_loop_latch >= 0) ? cur_loop_latch : header;
        /* LOOP-FORWARD-SINK CHAIN: each in-loop convergence J (all non-break/continue forward paths
         * funnel through it) is emitted ONCE at the loop-body level. Activate ALL of the loop's sinks
         * so nested arms fall through to whichever they reach (no goto, no duplication), emit the branch
         * structure, then emit each sink in reachability order — J1's tail falls through to J2, etc. */
        std::vector<int> sinks = loop_sinks_for(header, body_stop);
        std::set<int> saved_active = active_loop_sinks;
        for (int Ji : sinks) active_loop_sinks.insert(Ji);
        emit_stmts(header, dst);
        if (H.ends_jcc && H.cond && H.taken >= 0 && H.fall >= 0) {
            /* if branch leaves to follow, that's a break */
            int t = H.taken, fl = H.fall;
            if (t == follow) {
                dst += ind() + "if (" + render_cond(H.cond) + ") break;\n";
                emit_region(fl, body_stop, dst, header);
            } else if (fl == follow) {
                dst += ind() + "if (" + render_cond(negate_expr(H.cond)) + ") break;\n";
                emit_region(t, body_stop, dst, header);
            } else {
                emit_if_else(header, body_stop, dst, header);
            }
        } else if (H.ends_ret) {
            dst += ind() + ret_text(header) + "\n";
        } else {
            int nxt = H.ends_jmp ? H.taken : H.fall;
            if (nxt == header) { /* self loop */ }
            else if (nxt >= 0) emit_region(nxt, body_stop, dst, header);
        }
        for (int Ji : sinks) {                       /* emit each convergence ONCE, in reachability order */
            if (structured.count(Ji)) continue;
            active_loop_sinks.erase(Ji);             /* Ji about to be emitted -> stop suppressing it */
            emit_region(Ji, body_stop, dst, header); /* Ji's tail falls through to the later sinks */
        }
        active_loop_sinks = saved_active;
        if (emit_latch) emit_shared_latch(header, dst);
    }

    /* Emit the loop's shared latch ONCE at the bottom of the body — but ONLY when
     * the body emission left it unemitted (every internal path fell through to
     * body_stop == the latch). Behaviour-safe: the latch is a real post-dominator
     * of the body reached by fall-through, never skipping intervening code. */
    void emit_shared_latch(int header, std::string& dst) {
        if (cur_loop_latch < 0 || structured.count(cur_loop_latch)) return;
        int L = cur_loop_latch;
        int saved = cur_loop_latch; cur_loop_latch = -1;
        emit_region(L, header, dst, header);
        cur_loop_latch = saved;
    }

    ExprP negate_expr(const ExprP& c) {
        if (!c) return mkConst(0, 4);
        /* double-negation: !(!x) -> x. The only producer of a logical-not node
         * is this function, so a unary "!" here is always a boolean condition;
         * negating it again recovers the original predicate instead of stacking
         * a redundant `!(!cond)`. Behavior-preserving and generalizes to any
         * binary where a negated condition is re-negated by structuring. */
        if (c->kind == EK::Unary && c->op == "!" && c->a) return c->a;
        if (c->kind == EK::Binary) {
            const std::string& op = c->op;
            /* De Morgan: !(a && b) -> !a || !b, !(a || b) -> !a && !b. Pushes the
             * negation inward instead of stacking `!(...)`, so a structurer-negated
             * range check `!(x<lo || x>hi)` renders as the clean `x>=lo && x<=hi`.
             * Gated with the idiom pass for a clean A/B (getenv cached). */
            static const bool demorgan = std::getenv("DS_NO_IDIOM") == nullptr;
            if (demorgan && op == "&&")
                return mkBinary("||", negate_expr(c->a), negate_expr(c->b), c->width, false);
            if (demorgan && op == "||")
                return mkBinary("&&", negate_expr(c->a), negate_expr(c->b), c->width, false);
            /* An ORDERED-relation inversion is NaN-UNSAFE for floating point:
             * `!(a > b)` is NOT `a <= b` when either operand is NaN (all ordered
             * comparisons are FALSE for unordered operands, so `!(a>b)` is TRUE but
             * `a<=b` is FALSE). Keep the `!` wrapper for float `< <= > >=`. The
             * equality inversion `!(a==b) -> a!=b` IS NaN-consistent (a==b is false
             * for NaN, a!=b is true), so it stays for all types. */
            bool fcmp = (c->is_float) || (c->a && c->a->is_float) || (c->b && c->b->is_float);
            std::string n;
            if (op=="==") n="!="; else if (op=="!=") n="==";
            else if (!fcmp) {
                if (op=="<") n=">="; else if (op==">=") n="<";
                else if (op==">") n="<="; else if (op=="<=") n=">";
            }
            if (!n.empty()) {
                auto e = std::make_shared<Expr>(*c); e->op = n; return e;
            }
        }
        return mkUnary("!", clone(c), c ? c->width : 4);
    }

    /* Simplify an expression rendered in BOOLEAN context (an if/while/for condition
     * or an &&/||/! operand): Hex-Rays drops the redundant `!= 0` / `== 0` our flag
     * lifting leaves. `X != 0` -> `X`; `X == 0` -> `!X` (negate_expr gives a clean
     * relational inversion, `(a<b)==0` -> `a>=b`). Recurses through &&/||/!. Builds
     * NEW nodes for changed parts and shares unchanged subtrees WITHOUT mutating the
     * original, so calling it on b.cond never perturbs value/CFG semantics — it only
     * reshapes how the condition renders. Gated DS_NO_BOOLCOND. */
    ExprP bool_simplify(const ExprP& e) {
        if (!e) return e;
        if (e->kind == EK::Binary) {
            const std::string& op = e->op;
            if ((op == "!=" || op == "==") && e->b && e->b->kind == EK::Const &&
                e->b->cval == 0 && !e->b->is_float && e->a && !e->a->is_float) {
                ExprP inner = bool_simplify(e->a);
                return op == "!=" ? inner : negate_expr(inner);
            }
            if (op == "&&" || op == "||") {
                auto c = std::make_shared<Expr>(*e);
                c->a = bool_simplify(e->a); c->b = bool_simplify(e->b);
                return c;
            }
        }
        if (e->kind == EK::Unary && e->op == "!" && e->a)
            return negate_expr(bool_simplify(e->a));
        return e;
    }
    std::string render_cond(const ExprP& e) {
        if (std::getenv("DS_NO_BOOLCOND")) return render(e);
        return render(bool_simplify(e));
    }

    /* Does the (acyclic, forward) region rooted at `b` always terminate the
     * function -- i.e. every path out of it reaches a `ret`/tail-jmp -- without
     * ever falling through to `stop` or re-entering already-structured code?
     * Conservative: any block that branches outside the region, loops, or hits
     * a not-yet-known edge makes us answer false. Used to turn a return-guard
     * (`if (cond) goto RET;`) into a structured single-armed `if`. */
    bool region_terminates(int b, int stop) {
        std::set<int> seen;
        std::vector<int> work{b};
        int guard = 0;
        while (!work.empty()) {
            if (++guard > 100000) return false;
            int cur = work.back(); work.pop_back();
            if (cur < 0) return false;
            if (cur == stop) return false;            /* falls through to fall-arm */
            if (structured.count(cur)) return false;  /* would alias emitted code */
            if (!seen.insert(cur).second) continue;   /* back-edges revisit -> skip */
            Block& C = blocks[cur];
            if (C.ends_ret) continue;                 /* path ends in return: ok */
            if (C.is_switch) return false;            /* keep switches out of guards */
            if (C.ends_jmp) {
                if (C.taken < 0) continue;            /* tail/extern jmp == return */
                work.push_back(C.taken);
            } else if (C.ends_jcc && C.taken >= 0 && C.fall >= 0) {
                work.push_back(C.taken);
                work.push_back(C.fall);
            } else if (C.fall >= 0) {
                work.push_back(C.fall);
            } else {
                continue;                              /* no successor == return */
            }
        }
        return true;
    }

    /* Can control flow reach `target` from `start` along CFG successor edges?
     * (Used to detect a re-convergence join reached from BOTH arms of a branch.) */
    bool block_reaches(int start, int target) {
        if (start < 0 || target < 0) return false;
        if (start == target) return true;
        std::set<int> seen;
        std::vector<int> work{start};
        int guard = 0;
        while (!work.empty()) {
            if (++guard > 100000) return false;
            int cur = work.back(); work.pop_back();
            if (cur < 0 || !seen.insert(cur).second) continue;
            for (int s : blocks[cur].succ) {
                if (s == target) return true;
                work.push_back(s);
            }
        }
        return false;
    }

    /* A "pure return epilogue" is a block whose entire job is to return: it ends
     * in a `ret`, carries no side-effecting statements of its own, and is neither
     * a switch dispatch nor a loop header. The classic shared function exit
     * (`L_xxx: return v;`) that many guard arms converge to. We can safely inline
     * its return into a guard arm, turning a `goto EPILOGUE` into an early
     * `return`. */
    bool is_return_epilogue(int blk) {
        if (blk < 0 || (size_t)blk >= blocks.size()) return false;
        Block& B = blocks[blk];
        if (!B.ends_ret) return false;
        if (B.is_switch || B.is_switch_guard) return false;
        if (loop_of_header.count(blk)) return false;
        if (!B.stmts.empty()) return false;
        return true;
    }

    /* Like region_terminates, but also accepts paths that converge to `stop`
     * when `stop` is a pure return epilogue: such a path "returns" via the shared
     * exit. Lets us recognise the very common "set the result, jmp to the single
     * ret" guard-clause pattern (classify_char / letter_grade style chains) and
     * inline the epilogue return instead of degrading to goto/label spaghetti. */
    bool region_returns_via_epilogue(int b, int stop) {
        if (!is_return_epilogue(stop)) return false;
        std::set<int> seen;
        std::vector<int> work{b};
        int guard = 0;
        while (!work.empty()) {
            if (++guard > 100000) return false;
            int cur = work.back(); work.pop_back();
            if (cur < 0) return false;
            if (cur == stop) continue;                /* reaches shared ret: ok */
            if (structured.count(cur)) return false;  /* would alias emitted code */
            if (!seen.insert(cur).second) continue;   /* back-edges revisit -> skip */
            Block& C = blocks[cur];
            if (C.ends_ret) continue;                 /* path ends in return: ok */
            if (C.is_switch) return false;            /* keep switches out of guards */
            if (C.ends_jmp) {
                if (C.taken < 0) continue;            /* tail/extern jmp == return */
                work.push_back(C.taken);
            } else if (C.ends_jcc && C.taken >= 0 && C.fall >= 0) {
                work.push_back(C.taken);
                work.push_back(C.fall);
            } else if (C.fall >= 0) {
                work.push_back(C.fall);
            } else {
                continue;                              /* no successor == return */
            }
        }
        return true;
    }

    /* The Boehm-Jacopini reaching-flag structurer lived here (fl_R/fl_joins/flag_var/
     * fl_arm/emit_flag_chain/emit_flagged_region/emit_function_flagged) and is REMOVED.
     * It rendered a tangled acyclic region goto-free by inventing one `char __at_<addr>`
     * per lifted join. That is sound in the Boehm-Jacopini sense and unreadable in the
     * Hex-Rays sense: the flags do not exist in the binary, so the output asserted control
     * flow the machine never had. A residual goto is now simply a goto.
     * See the commit and the note at the cross_joins precompute in decompiler.cpp. */

    /* Proper-region lift wrapper: if this conditional is the entry of a region that
     * contains a cross-join (a >=2-pred block that post-dominates no branch, so normal
     * structuring must goto it), trial the normal emission and, if it gotos, restructure
     * [b, stop) with reaching-flags. Fires at the OUTERMOST such if (emit_region is
     * top-down) = the region's true single entry, so nothing inside is emitted yet. */
    /* cross_joins stays declared and permanently EMPTY: it is still read by the emitters
     * as "a join normal structuring must goto", and an empty set simply means none is
     * special-cased. The reaching-flag trial that consumed it is gone. */
    std::set<int> cross_joins;
    bool in_flag_region = false;
    int flag_trial_budget = 0;
    void emit_if_else(int b, int stop, std::string& dst, int loop_header) {
        emit_if_else_body(b, stop, dst, loop_header);
    }

    void emit_if_else_body(int b, int stop, std::string& dst, int loop_header) {
        Block& B = blocks[b];
        int t = B.taken, fl = B.fall;
        ExprP cond = B.cond ? B.cond : mkConst(1, 4);
        if (std::getenv("DS_DBG_IF") && f && f->rva == (getenv("DS_DBG_RVA") ? strtoull(getenv("DS_DBG_RVA"),0,16) : 0x1ab40)) {
            int jj = (ipdom.size() > (size_t)b) ? ipdom[b] : -1;
            fprintf(stderr, "[IF] b=%d(0x%llx) t=%d fl=%d ipdom=%d stop=%d cur_lh=%d cur_fl=%d cur_latch=%d s(t)=%d s(fl)=%d s(join)=%d\n",
                    b, (unsigned long long)B.addr, t, fl, jj, stop, cur_loop_header, cur_loop_follow, cur_loop_latch,
                    (int)structured.count(t), (int)structured.count(fl), jj>=0?(int)structured.count(jj):-1);
        }
        /* FORWARD-SINK join: b's ipdom is a T=-1 pure-convergence sink. Emit both arms
         * with the sink active (every reach to it falls through), then the sink ONCE. */
        {
            int jj = (ipdom.size() > (size_t)b) ? ipdom[b] : -1;
            if (jj >= 0 && jj != b && jj != stop && fwd_sinks.count(jj) && cur_fwd_sink != jj &&
                !structured.count(jj)) {   /* handles t==jj / fl==jj too: that arm emits empty */
                int saved = cur_fwd_sink; cur_fwd_sink = jj;
                std::string tbody, fbody;
                indent_lvl++; emit_region(t,  jj, tbody, loop_header); indent_lvl--;
                indent_lvl++; emit_region(fl, jj, fbody, loop_header); indent_lvl--;
                cur_fwd_sink = saved;
                if (is_blank(fbody))
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + tbody + ind() + "}\n";
                else if (is_blank(tbody))
                    dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n" + fbody + ind() + "}\n";
                else
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + tbody + ind() + "} else {\n" + fbody + ind() + "}\n";
                emit_region(jj, stop, dst, loop_header);   /* the sink, once */
                return;
            }
        }


        /* GUARD CLAUSE: an arm that is a side-effect-free chain ending in `return`
         * becomes an inline `if (cond) { return X; }`, with the OTHER arm continuing
         * at the same level. Return chains are duplicate-safe, so this is always
         * legal and eliminates the dominant goto source — a shared `return`
         * epilogue reached from many guards / loop exits (arena_alloc's `return -1`,
         * every early-return ladder). Try the taken arm first, then the fall arm. */
        if (t != fl) {
            int tt = thread_target(t), ff = thread_target(fl);
            if (tt != ff) {
                std::string body;
                indent_lvl++;
                bool tok = (tt != stop) && try_emit_return_dup(tt, body);
                indent_lvl--;
                if (tok) {
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + body + ind() + "}\n";
                    emit_region(fl, stop, dst, loop_header);
                    return;
                }
                body.clear();
                indent_lvl++;
                bool fok = (ff != stop) && try_emit_return_dup(ff, body);
                indent_lvl--;
                if (fok) {
                    dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n" + body + ind() + "}\n";
                    emit_region(t, stop, dst, loop_header);
                    return;
                }
            }
        }

        /* break/continue inside loops (thread through empty goto landing blocks
         * so an `if (c) goto L; L: goto HEADER/FOLLOW` is recovered as
         * continue/break instead of a dangling goto). */
        if (loop_header >= 0) {
            int follow = cur_loop_follow;
            int tt = thread_target(t), ff = thread_target(fl);
            /* C2: one edge continues (-> header), the OTHER breaks (-> follow). Emit a
             * single `if (!C) break;` / `if (C) break;` — the continue is the implicit
             * fall-through to the loop tail — instead of `if(C) continue; break;`. Uses
             * the loop's own header/follow block ids, so it can never mis-target an inner
             * switch's break. Both edges are terminal, so nothing else is emitted here. */
            bool c2 = !std::getenv("DS_NO_CONTBREAK");
            if (c2 && tt == cur_loop_header && ff == follow && follow != stop) {
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") break;\n";
                mark_threaded(t); mark_threaded(fl); return;
            }
            if (c2 && ff == cur_loop_header && tt == follow && follow != stop) {
                dst += ind() + "if (" + render_cond(cond) + ") break;\n";
                mark_threaded(t); mark_threaded(fl); return;
            }
            if (tt == cur_loop_header) {
                dst += ind() + "if (" + render_cond(cond) + ") continue;\n";
                mark_threaded(t);
                emit_region(fl, stop, dst, loop_header); return;
            }
            if (ff == cur_loop_header) {
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") continue;\n";
                mark_threaded(fl);
                emit_region(t, stop, dst, loop_header); return;
            }
            if (tt == follow && follow != stop) {
                dst += ind() + "if (" + render_cond(cond) + ") break;\n";
                mark_threaded(t);
                emit_region(fl, stop, dst, loop_header); return;
            }
            if (ff == follow && follow != stop) {
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") break;\n";
                mark_threaded(fl);
                emit_region(t, stop, dst, loop_header); return;
            }
        }

        /* find the join = immediate post-dominator of b */
        int join = (ipdom.size() > (size_t)b) ? ipdom[b] : -1;
        if (join == b) join = -1;

        /* RE-CONVERGENCE FOLLOW (loop-with-remainder ladder): one arm is a join
         * that the OTHER arm also reaches (e.g. a small-n path enters the scalar
         * remainder tail directly, while the vectorized path falls into that same
         * tail after its loop). The ipdom cases below emit the tail INSIDE the
         * taken arm and leave the other arm's edge back to it as a `goto` — which
         * then trips the whole function into a switch(__state) machine. Instead,
         * emit the OTHER arm as a single-armed `if` whose edge to the join becomes
         * a fall-through (stop = join) and whose non-join exits become inline
         * returns, then place the join sequentially. We trial-emit with rollback
         * and commit only when the body is goto-free — so this can never worsen
         * structure and is always behavior-preserving. Skip when the arm already
         * IS the ipdom join (the clean single-arm cases below handle that). */
        for (int trial = 0; trial < 2; ++trial) {
            int follow = trial ? fl : t;    /* candidate sequential join      */
            int other  = trial ? t  : fl;   /* arm rendered as the if-body    */
            if (follow < 0 || other < 0 || follow == stop || follow == join) continue;
            if (follow == b || other == b || follow == other) continue;
            /* The `other` arm must NOT be the immediate post-dominator: if it is,
             * it is the real sequential join and belongs AFTER the if, not inside
             * it. Emitting the ipdom-join as the if-body inverts a loop latch —
             * `block_reaches(other, follow)` is satisfied only through the loop
             * back-edge (latch -> header -> other-block), so this trial would wrap
             * the latch in `if(cond){ continue; break; }` and leave the real body
             * to `goto` back to it. Let the taken_is_join / fall_is_join cases
             * below emit `if(!cond){ body } <latch>` with zero gotos. */
            if (other == join) continue;
            /* If a proper shared post-dominator join exists that BOTH arms reach
             * and it is NEITHER arm, the ipdom `!taken_is_join && !fall_is_join`
             * case below emits both arms up to it and the join ONCE — goto-free.
             * Do not let this trial preempt that by treating one arm as the follow
             * on the strength of a BACK-EDGE reachability (the CRC/hash loop latch:
             * both the table-lookup arm and the reset arm reach the latch, neither
             * IS it, and `block_reaches(other,follow)` only holds via latch->header). */
            if (join >= 0 && join != follow && join != other &&
                block_reaches(other, join) && block_reaches(follow, join)) continue;
            if (structured.count(follow) || structured.count(other)) continue;
            if (!block_reaches(other, follow)) continue;   /* not a re-convergence */
            auto s_struct = structured; auto s_label = need_label;
            auto s_thread = threaded;   int s_dup = dup_budget;
            std::string body;
            indent_lvl++;
            emit_region(other, follow, body, loop_header);
            indent_lvl--;
            if (body.find("goto ") == std::string::npos && !is_blank(body)) {
                ExprP guard_cond = (follow == t) ? negate_expr(cond) : cond;
                dst += ind() + "if (" + render_cond(guard_cond) + ") {\n";
                dst += body;
                dst += ind() + "}\n";
                emit_region(follow, stop, dst, loop_header);
                return;
            }
            structured = s_struct; need_label = s_label;
            threaded = s_thread;   dup_budget = s_dup;
        }

        /* Prefer the structured if/else only when the join is reachable and not
         * inside either arm prematurely. We emit:
         *   if (cond) { <taken..join> } else { <fall..join> }
         * choosing the arm with the cond as-is. If one arm IS the join, emit a
         * single-armed if. */
        bool taken_is_join = (t == join);
        bool fall_is_join  = (fl == join);

        if (fall_is_join && !taken_is_join) {
            std::string body;
            indent_lvl++; emit_region(t, join, body, loop_header); indent_lvl--;
            /* an if with an empty body and no else is a no-op: drop it entirely
             * rather than emit `if (cond) {}` (general dead-code cleanup). */
            if (!is_blank(body)) {
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += body;
                dst += ind() + "}\n";
            }
            emit_region(join, stop, dst, loop_header);
            return;
        }
        if (taken_is_join && !fall_is_join) {
            std::string body;
            indent_lvl++; emit_region(fl, join, body, loop_header); indent_lvl--;
            if (!is_blank(body)) {
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n";
                dst += body;
                dst += ind() + "}\n";
            }
            emit_region(join, stop, dst, loop_header);
            return;
        }
        if (join >= 0 && !taken_is_join && !fall_is_join) {
            /* Decide structure BEFORE rendering, so each arm is emitted exactly
             * once at the correct indentation. If one arm always returns before
             * reaching the join (a guard clause), de-nest the other arm to the
             * outer level and drop the redundant `else` (Hex-Rays form):
             *   if (cond) { <then; return> }
             *   <fall...>
             * Behavior-preserving: when the then-arm always terminates, control
             * after the if can only have come from the fall arm. */
            bool taken_guard = !structured.count(t) && region_terminates(t, join);
            bool fall_guard  = !structured.count(fl) && region_terminates(fl, join);

            /* When the join is itself the shared return epilogue, an arm that
             * converges to it is a guard clause whose `return` we inline (the arm
             * sets the result then jumps to the single ret). This lets the join
             * (the ret) be de-nested out of the if and continued at the outer
             * level, collapsing value-and-return comparison chains into a
             * Hex-Rays-style `if (cond) return X;` ladder rather than nested
             * if/else. We only do this when exactly one arm is such a guard so the
             * other arm clearly continues; the epilogue return is emitted inside
             * the guard body and the post-if region picks up at the join's
             * successor as usual. */
            bool join_is_epi = is_return_epilogue(join);
            bool taken_epi_guard = join_is_epi && !structured.count(t) &&
                                   region_returns_via_epilogue(t, join);
            bool fall_epi_guard  = join_is_epi && !structured.count(fl) &&
                                   region_returns_via_epilogue(fl, join);

            std::string taken_body, fall_body;
            indent_lvl++; emit_region(t, join, taken_body, loop_header); indent_lvl--;
            indent_lvl++; emit_region(fl, join, fall_body, loop_header); indent_lvl--;
            bool taken_empty = is_blank(taken_body);
            bool fall_empty  = is_blank(fall_body);

            /* Both arms converge to the shared ret: each is a guard. Inline the
             * epilogue return into both and emit a plain if/else; the join's ret
             * is fully consumed here so we do NOT re-emit it afterward. */
            if (taken_epi_guard && fall_epi_guard && !taken_empty && !fall_empty) {
                taken_body += ind(indent_lvl + 1) + ret_text(join) + "\n";
                fall_body  += ind(indent_lvl + 1) + ret_text(join) + "\n";
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += taken_body;
                dst += ind() + "} else {\n";
                dst += fall_body;
                dst += ind() + "}\n";
                structured.insert(join);   /* ret consumed by both arms */
                return;
            }

            /* epilogue-guard: inline the shared ret into the converging arm and
             * de-nest the sibling (handled before the generic guard cases). */
            if (taken_epi_guard && !taken_empty && !fall_epi_guard) {
                taken_body += ind(indent_lvl + 1) + ret_text(join) + "\n";
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += taken_body;
                dst += ind() + "}\n";
                dst += dedent_one(fall_body);
                emit_region(join, stop, dst, loop_header);
                return;
            }
            if (fall_epi_guard && !fall_empty && !taken_epi_guard) {
                fall_body += ind(indent_lvl + 1) + ret_text(join) + "\n";
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n";
                dst += fall_body;
                dst += ind() + "}\n";
                dst += dedent_one(taken_body);
                emit_region(join, stop, dst, loop_header);
                return;
            }

            if (fall_empty && !taken_empty) {
                /* empty else: emit a single-armed if, drop the `else {}` noise */
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += taken_body;
                dst += ind() + "}\n";
            } else if (taken_empty && !fall_empty) {
                /* empty then: invert and emit only the else arm */
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n";
                dst += fall_body;
                dst += ind() + "}\n";
            } else if (taken_guard && !taken_empty) {
                /* then-arm is a terminating guard: de-nest the fall arm by one
                 * level (it was rendered at indent_lvl+1). */
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += taken_body;
                dst += ind() + "}\n";
                dst += dedent_one(fall_body);
            } else if (fall_guard && !fall_empty) {
                /* symmetric: fall-arm is a terminating guard, invert and de-nest. */
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n";
                dst += fall_body;
                dst += ind() + "}\n";
                dst += dedent_one(taken_body);
            } else {
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += taken_body;
                dst += ind() + "} else {\n";
                dst += fall_body;
                dst += ind() + "}\n";
            }
            emit_region(join, stop, dst, loop_header);
            return;
        }

        /* No shared post-dominator join, but if one arm is a self-contained
         * region that always returns (a guard clause), we can still structure it
         * as a single-armed `if` and continue with the other arm afterward. This
         * removes the `goto RET` noise from comparison chains that branch
         * straight to the function's return block (the common Hex-Rays form
         *   if (cond) return X;  ...rest...). Try the taken arm first, then the
         * fall arm (inverting the condition). */
        if (!structured.count(t) && region_terminates(t, stop)) {
            std::string taken_body;
            indent_lvl++; emit_region(t, stop, taken_body, loop_header); indent_lvl--;
            if (!is_blank(taken_body)) {
                dst += ind() + "if (" + render_cond(cond) + ") {\n";
                dst += taken_body;
                dst += ind() + "}\n";
                emit_region(fl, stop, dst, loop_header);
                return;
            }
        }
        if (!structured.count(fl) && region_terminates(fl, stop)) {
            std::string fall_body;
            indent_lvl++; emit_region(fl, stop, fall_body, loop_header); indent_lvl--;
            if (!is_blank(fall_body)) {
                dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n";
                dst += fall_body;
                dst += ind() + "}\n";
                emit_region(t, stop, dst, loop_header);
                return;
            }
        }

        /* Guard arm that converges to the shared return epilogue (`stop`): the
         * arm sets the result and jumps to the single `ret`. Inline that return
         * so it becomes a true early-return guard clause and continue with the
         * other arm at the outer level. Behavior-preserving: the arm originally
         * jumped to the epilogue (which returns); we render the epilogue's return
         * in place instead of via goto. This is what collapses comparison chains
         * like classify_char into Hex-Rays-style `if (cond) return X;` ladders. */
        if (!structured.count(t) && region_returns_via_epilogue(t, stop)) {
            std::string taken_body;
            indent_lvl++;
            emit_region(t, stop, taken_body, loop_header);
            taken_body += ind() + ret_text(stop) + "\n";
            indent_lvl--;
            dst += ind() + "if (" + render_cond(cond) + ") {\n";
            dst += taken_body;
            dst += ind() + "}\n";
            emit_region(fl, stop, dst, loop_header);
            return;
        }
        if (!structured.count(fl) && region_returns_via_epilogue(fl, stop)) {
            std::string fall_body;
            indent_lvl++;
            emit_region(fl, stop, fall_body, loop_header);
            fall_body += ind() + ret_text(stop) + "\n";
            indent_lvl--;
            dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n";
            dst += fall_body;
            dst += ind() + "}\n";
            emit_region(t, stop, dst, loop_header);
            return;
        }

        /* TRIAL plain if/else with rollback. No clean post-dominator join was
         * found, but if BOTH arms are self-contained (each terminates or diverges
         * without re-entering the other), emitting them as a literal if/else is
         * goto-free and behavior-exact. region_terminates() can't gate this when an
         * arm is a LOOP (it won't prove a loop exits), so a `cmp;ja L; loopA; L:
         * loopB` (two independent loops each ending in ret — fn_0006ac90) fell to
         * the guarded-goto below and tripped the whole function into a state
         * machine. Emit both arms into scratch bodies and commit only if NEITHER
         * produced a goto; otherwise roll back the structuring state untouched. */
        if (t != fl && !structured.count(t) && !structured.count(fl)) {
            auto s_struct = structured; auto s_label = need_label;
            auto s_thread = threaded;   int s_dup = dup_budget;
            std::string tb, fb;
            indent_lvl++; emit_region(t, stop, tb, loop_header); indent_lvl--;
            indent_lvl++; emit_region(fl, stop, fb, loop_header); indent_lvl--;
            if (tb.find("goto ") == std::string::npos &&
                fb.find("goto ") == std::string::npos &&
                !is_blank(tb) && !is_blank(fb)) {
                if (body_ends_in_transfer(tb)) {
                    /* taken arm always transfers control away -> de-nest the fall
                     * arm to the outer level (Hex-Rays guard-clause form). */
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + tb + ind() + "}\n";
                    dst += dedent_one(fb);
                } else {
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + tb +
                           ind() + "} else {\n" + fb + ind() + "}\n";
                }
                return;
            }
            structured = s_struct; need_label = s_label;
            threaded = s_thread;   dup_budget = s_dup;
        }

        /* The taken arm was already emitted elsewhere (a shared guard/exit body
         * reached from several `if`s). Try DUPLICATING its region into this guard —
         * emit_dup_region handles branching bodies, bounded by dup_budget — before
         * falling back to a goto. This is the multi-block analog of the return-tail
         * duplication and clears the shared-exit guards that otherwise trip a state
         * machine (fn_0004f510: 6 guards jumping to one shared validation block). */
        if (structured.count(t) && t != stop) {
            int saved = dup_budget;
            std::string db;
            indent_lvl++;
            bool ok = emit_dup_region(t, stop, db, loop_header);
            indent_lvl--;
            if (ok && db.find("goto ") == std::string::npos && !is_blank(db)) {
                dst += ind() + "if (" + render_cond(cond) + ") {\n" + db + ind() + "}\n";
                emit_region(fl, stop, dst, loop_header);
                return;
            }
            dup_budget = saved;
        }

        /* EFFECTIVE-JOIN TRIAL (rollback). No strict post-dominator exists (a
         * sibling path returns early), but the two arms reconverge at J — the point
         * where the NON-returning paths meet. Emit both arms up to J, then J ONCE
         * after, so a shared continuation reached from several guards is placed
         * once with the paths falling into it (the guard-clause path duplicates it;
         * a diamond then doubles and blows up). Trial-emit with rollback: commit
         * only if BOTH arms come out goto-free, so this can never worsen structure. */
        {
            int J = effective_join(b);
            /* SINGLE-ARMED if whose join IS one of the immediate arms (empty then or
             * else): one edge goes straight to the reconvergence point J, the other
             * does work then falls into it. The strict ipdom missed it — e.g. a
             * LOOP-HEADER branch whose ipdom is the loop EXIT, not the in-loop join
             * (fn_0002b5d0: `if (*t1+8 != 0) call(); <join>` came out as a labeled
             * goto). Recover it from effective_join with the same rollback safety:
             * emit ONLY the non-join arm as the if-body, then J sequentially. */
            if (J >= 0 && (J == t || J == fl) && J != b && J != stop &&
                !structured.count(J)) {
                int body_arm = (J == t) ? fl : t;
                ExprP g = (J == t) ? negate_expr(cond) : cond;
                if (body_arm >= 0 && body_arm != stop && !structured.count(body_arm)) {
                    auto s_struct = structured; auto s_label = need_label;
                    auto s_thread = threaded; int s_dup = dup_budget;
                    std::string body;
                    indent_lvl++; emit_region(body_arm, J, body, loop_header); indent_lvl--;
                    if (body.find("goto ") == std::string::npos) {
                        if (!is_blank(body))
                            dst += ind() + "if (" + render_cond(g) + ") {\n" + body + ind() + "}\n";
                        emit_region(J, stop, dst, loop_header);
                        return;
                    }
                    structured = s_struct; need_label = s_label;
                    threaded = s_thread; dup_budget = s_dup;
                }
            }
            if (J >= 0 && J != b && J != stop && J != t && J != fl &&
                !structured.count(J) && !structured.count(t) && !structured.count(fl)) {
                auto s_struct = structured; auto s_label = need_label;
                auto s_thread = threaded; int s_dup = dup_budget;
                std::string tb, fb;
                indent_lvl++; emit_region(t, J, tb, loop_header); indent_lvl--;
                indent_lvl++; emit_region(fl, J, fb, loop_header); indent_lvl--;
                if (tb.find("goto ") == std::string::npos &&
                    fb.find("goto ") == std::string::npos) {
                    if (is_blank(fb) && !is_blank(tb))
                        dst += ind() + "if (" + render_cond(cond) + ") {\n" + tb + ind() + "}\n";
                    else if (is_blank(tb) && !is_blank(fb))
                        dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n" + fb + ind() + "}\n";
                    else if (!is_blank(tb) && !is_blank(fb))
                        dst += ind() + "if (" + render_cond(cond) + ") {\n" + tb +
                               ind() + "} else {\n" + fb + ind() + "}\n";
                    emit_region(J, stop, dst, loop_header);
                    return;
                }
                structured = s_struct; need_label = s_label;
                threaded = s_thread; dup_budget = s_dup;
            }
        }

        /* no usable join: fall back to a guarded goto (still correct) */
        need_label.insert(t);
        dst += ind() + "if (" + render_cond(cond) + ") goto " + block_label(t) + ";\n";
        emit_region(fl, stop, dst, loop_header);
        if (!structured.count(t)) {
            std::string tmp;
            emit_region(t, stop, tmp, loop_header);
            dst += tmp;
        }
    }

    /* True if `body`'s last non-blank line is an unconditional control transfer
     * (return/continue/break/goto) — appending a switch-case `break;` after one
     * would be dead code (`continue; break;`). */
    bool body_ends_in_transfer(const std::string& body) {
        size_t end = body.find_last_not_of(" \t\r\n");
        if (end == std::string::npos) return false;
        size_t ls = body.rfind('\n', end);
        ls = (ls == std::string::npos) ? 0 : ls + 1;
        std::string line = body.substr(ls, end - ls + 1);
        size_t f = line.find_first_not_of(" \t");
        if (f != std::string::npos) line = line.substr(f);
        return line.rfind("return", 0) == 0 || line.rfind("continue;", 0) == 0 ||
               line.rfind("break;", 0) == 0 || line.rfind("goto ", 0) == 0;
    }
    void emit_switch(int b, int stop, std::string& dst, int loop_header) {
        Block& B = blocks[b];
        int join = (ipdom.size() > (size_t)b) ? ipdom[b] : -1;
        dst += ind() + "switch (" + switch_sel(B.switch_var) + ") {\n";
        /* group identical case targets */
        std::map<int, std::vector<int>> by_target;   /* succ block -> case idxs */
        for (size_t i = 0; i < B.case_succ.size(); ++i)
            if (B.case_succ[i] >= 0) by_target[B.case_succ[i]].push_back((int)i);
        indent_lvl++;
        for (auto& kv : by_target) {
            for (int ci : kv.second)
                dst += ind() + "case " + std::to_string(ci) + ":\n";
            indent_lvl++;
            int tgt = kv.first;
            std::string cbody;
            if (!structured.count(tgt)) {
                emit_region(tgt, join, cbody, loop_header);
            } else if (try_emit_return_dup(tgt, cbody)) {
                /* another case already emitted this target (a shared return/epilogue
                 * tail — the switch's default arm and a case both `return a3`).
                 * Duplicate the return tail into this case instead of a goto, which
                 * would otherwise trip the whole function to a state machine
                 * (fn_0007cb60 and most jump-table dispatchers with a shared tail). */
            } else {
                need_label.insert(tgt);
                cbody += ind() + "goto " + block_label(tgt) + ";\n";
            }
            dst += cbody;
            /* terminate the case — but only if the body didn't already transfer
             * control (a `continue;`/`return;`/`break;`/`goto` makes a trailing
             * `break;` dead code: `continue; break;`). */
            if (!body_ends_in_transfer(cbody)) dst += ind() + "break;\n";
            indent_lvl--;
        }
        if (B.default_succ >= 0 && !by_target.count(B.default_succ)) {
            dst += ind() + "default:\n";
            indent_lvl++;
            std::string dbody;
            emit_region(B.default_succ, join, dbody, loop_header);
            dst += dbody;
            if (!body_ends_in_transfer(dbody)) dst += ind() + "break;\n";
            indent_lvl--;
        }
        indent_lvl--;
        dst += ind() + "}\n";
        if (join >= 0) emit_region(join, stop, dst, loop_header);
    }

    /* Net brace balance of a line, IGNORING braces inside string/char literals and
     * `//` comments (printf format strings carry `{`/`}`). Used by collapse_else_if. */
    static int net_braces_ol(const std::string& s) {
        int depth = 0; bool instr = false, inch = false;
        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (instr || inch) {
                if (c == '\\') { ++i; continue; }
                if ((instr && c == '"') || (inch && c == '\'')) { instr = inch = false; }
                continue;
            }
            if (c == '/' && i + 1 < s.size() && s[i + 1] == '/') break;
            if (c == '"') instr = true;
            else if (c == '\'') inch = true;
            else if (c == '{') ++depth;
            else if (c == '}') --depth;
        }
        return depth;
    }
    /* Collapse `} else {` whose ELSE-BLOCK IS a single if-statement into `} else if`.
     * `} else {\n  if (C) {...}\n}`  ->  `} else if (C) {...}`. Pure text reshaping of
     * already-correct C (Hex-Rays emits else-if; we never do). Iterates so an
     * else-{if}-staircase folds into a full else-if chain. A bug can only yield
     * non-compiling C (caught by the 1445-fn compile gate) or identical control flow
     * (a merge is semantics-preserving by construction). Gated DS_NO_ELSEIF. */
