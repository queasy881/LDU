/* 16_globals_phis.inc -- global bases, entry regs, phi injection
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    void cse_cross_statement() {
        for (auto& b : blocks) {
            int ns = (int)b.stmts.size();
            if (ns > 250) continue;                  /* keep it cheap */
            for (int iter = 0; iter < 30; ++iter) {
                std::vector<ExprP> cand;
                for (auto& s : b.stmts) if (s.kind==SK::Assign) { collect_subs(s.rhs, cand); collect_subs(s.lhs, cand); }
                collect_subs(b.cond, cand); collect_subs(b.ret_value, cand); collect_subs(b.switch_var, cand);
                ExprP best=nullptr; int bestcnt=0, bestsz=0, bestfirst=-1;
                std::vector<ExprP> seen;
                for (auto& sub : cand) {
                    int sz = node_count(sub);
                    if (sz < 4 || has_call(sub)) continue;
                    /* A memory-LOADING address expression (`*(long long*)((char*)a2+0x48)
                     * + idx*8`, re-derived on N consecutive field stores) IS hoistable,
                     * but only when it is provably invariant across its uses — guarded
                     * below (`sub_mem`). Pure arithmetic needs no memory guard. */
                    bool sub_mem = reads_mem(sub);
                    bool dup=false; for (auto& s2:seen) if (exprEqual(s2,sub)){dup=true;break;}
                    if (dup) continue; seen.push_back(sub);
                    int cnt=0, first=-1, last=-1;
                    for (int si=0; si<ns; ++si) if (b.stmts[si].kind==SK::Assign) {
                        int c2 = count_occ(b.stmts[si].rhs, sub) + count_occ(b.stmts[si].lhs, sub);
                        if (c2>0) { if (first<0) first=si; last=si; cnt+=c2; }
                    }
                    int tcnt = count_occ(b.cond,sub)+count_occ(b.ret_value,sub)+count_occ(b.switch_var,sub);
                    cnt += tcnt;
                    if (cnt < 2 || first < 0) continue;
                    bool crossstmt = (first != last) || (tcnt>0);   /* >1 statement involved */
                    if (!crossstmt) continue;                       /* intra handled by cse_materialize */
                    std::set<std::string> leaves; collect_var_names(sub, leaves);
                    bool inv = true;
                    for (int si=first; si<=last && inv; ++si)
                        if (b.stmts[si].kind==SK::Assign && b.stmts[si].lhs &&
                            b.stmts[si].lhs->kind==EK::Var && leaves.count(b.stmts[si].lhs->name))
                            inv = false;
                    if (!inv) continue;
                    /* MEMORY SAFETY for a load-bearing sub: its loaded value must not be
                     * clobbered between uses. Every statement in [first,last] must be a
                     * call-free Assign, and every memory STORE must write THROUGH sub —
                     * sub appears in the store's ADDRESS (`lhs->a`), i.e. `*(sub + C) =`.
                     * A store whose target IS sub's own load address (`lhs == sub`, so
                     * sub is NOT in lhs->a) is a direct clobber — the swap-through-memory
                     * hazard (`a[i] = a[j]` with sub = *a[i]) — and bails. A store to an
                     * unrelated address (sub absent from lhs->a) may alias — also bails. */
                    if (sub_mem) {
                        bool safe = true;
                        for (int si=first; si<=last && safe; ++si) {
                            const Stmt& st = b.stmts[si];
                            if (st.kind != SK::Assign) { safe=false; break; }
                            if (has_call(st.rhs)) { safe=false; break; }
                            if (st.lhs && st.lhs->kind == EK::Mem &&
                                (!st.lhs->a || count_occ(st.lhs->a, sub) == 0)) { safe=false; break; }
                        }
                        if (!safe) continue;
                    }
                    if (cnt > bestcnt || (cnt==bestcnt && sz>bestsz)) { best=sub; bestcnt=cnt; bestsz=sz; bestfirst=first; }
                }
                if (!best) break;
                std::string tn = "t" + std::to_string(++temp_seq);
                cse_temps.insert(tn);
                int w = best->width ? best->width : 8;
                var_width[tn]=w; if (w>=8) var_is_ll[tn]=true; if (best->is_float) var_is_float[tn]=true;
                ExprP tv = mkVar(tn, w); if (best->is_float) tv->is_float=true;
                Stmt def; def.kind=SK::Assign; def.lhs=mkVar(tn,w); if(best->is_float) def.lhs->is_float=true; def.rhs=clone(best);
                for (auto& s : b.stmts) if (s.kind==SK::Assign) { s.rhs=subst_subtree(s.rhs,best,tv); s.lhs=subst_subtree(s.lhs,best,tv); }
                b.cond=subst_subtree(b.cond,best,tv); b.ret_value=subst_subtree(b.ret_value,best,tv); b.switch_var=subst_subtree(b.switch_var,best,tv);
                b.stmts.insert(b.stmts.begin()+bestfirst, std::move(def));
                ns = (int)b.stmts.size();
            }
        }
    }

    /* =================================================================== */
    /*  Constant folding / simplification                                   */
    /* =================================================================== */

    ExprP fold(ExprP e) {
        if (!e) return e;
        e->a = fold(e->a); e->b = fold(e->b); e->c = fold(e->c);
        for (auto& ar : e->args) ar = fold(ar);

        if (e->kind == EK::Cast && e->a) {
            /* fold cast of const */
            if (e->a->kind == EK::Const) {
                int w = e->width;
                int64_t v = e->a->cval;
                if (e->is_unsigned) {
                    uint64_t m = (w==1)?(v&0xFF):(w==2)?(v&0xFFFF):(w==4)?(uint32_t)v:(uint64_t)v;
                    return mkConst((int64_t)m, w, true);
                } else {
                    int64_t m = (w==1)?(int8_t)v:(w==2)?(int16_t)v:(w==4)?(int32_t)v:v;
                    return mkConst(m, w, false);
                }
            }
            /* A NARROWING cast of `(X & C)` whose mask zeroes every bit the cast
             * keeps -> 0. This collapses the byte-return `(signed char)(t2 & -256)`
             * (from `xor al,al; ret`, where the low byte is provably 0) to a clean
             * `0`, and is generally true for any sub-width masked-off slice. */
            if (!e->is_float && e->width >= 1 && e->width < 8 &&
                e->a->kind == EK::Binary && e->a->op == "&" && e->a->b &&
                e->a->b->kind == EK::Const) {
                uint64_t lowmask = (e->width >= 8) ? ~0ULL
                                  : ((1ULL << (8 * e->width)) - 1);
                if (((uint64_t)e->a->b->cval & lowmask) == 0)
                    return mkConst(0, e->width, e->is_unsigned);
            }
            /* (narrowN)((X & C) | Y) -> (narrowN)(Y) when C zeroes every kept bit:
             * the masked-off operand contributes nothing to the narrowed result.
             * Collapses the byte-write merge `(parent & -256) | byteop` read back
             * as a byte (`movzx eax,cl`) — the is_even `(~x)&1` cascade. Recurses. */
            if (!e->is_float && e->width >= 1 && e->width < 8 &&
                e->a->kind == EK::Binary && e->a->op == "|" && e->a->a && e->a->b) {
                uint64_t lowmask = (e->width >= 8) ? ~0ULL
                                  : ((1ULL << (8 * e->width)) - 1);
                auto masks_off = [&](const ExprP& s)->bool {
                    return s && s->kind==EK::Binary && s->op=="&" && s->b &&
                           s->b->kind==EK::Const &&
                           ((uint64_t)s->b->cval & lowmask)==0;
                };
                if (masks_off(e->a->a)) { auto c=std::make_shared<Expr>(*e); c->a=e->a->b; return fold(c); }
                if (masks_off(e->a->b)) { auto c=std::make_shared<Expr>(*e); c->a=e->a->a; return fold(c); }
            }
            /* drop nested no-op cast: (T)((T)x) -> (T)x */
            if (e->a->kind == EK::Cast && e->a->op == e->op) return e->a;
            /* collapse two adjacent casts of the SAME width (the inner one is
             * subsumed by the outer reinterpretation): (sN)(uN)x -> (sN)x.
             * NOT across the int<->float DOMAIN boundary: `(float)(int)x`
             * truncates the float to an integer value then converts back — a real
             * value change, not a redundant reinterpretation. */
            if (e->a->kind == EK::Cast && e->a->width == e->width &&
                e->is_float == e->a->is_float) {
                auto c = std::make_shared<Expr>(*e);
                c->a = e->a->a; /* skip the inner cast */
                return fold(c);
            }
            /* a cast no wider than an inner cast of strictly larger width is a
             * pure truncation of an extended value: (sN)((sM)x) with N<=M keeps
             * only the truncation: (sN)x. (Same int<->float domain guard.) */
            if (e->a->kind == EK::Cast && e->a->width > e->width &&
                e->is_float == e->a->is_float) {
                auto c = std::make_shared<Expr>(*e);
                c->a = e->a->a;
                return fold(c);
            }
            /* drop a cast over a value masked to fit the cast width:
             * (T_w)(x & mask) where mask < 2^(8*w) and the cast is value-
             * preserving -> x & mask. */
            if (e->a->kind == EK::Binary && e->a->op == "&" && e->a->b &&
                e->a->b->kind == EK::Const) {
                uint64_t mask = (uint64_t)e->a->b->cval;
                uint64_t cap = (e->width >= 8) ? ~0ULL
                             : ((1ULL << (8 * e->width)) - 1);
                if ((mask & ~cap) == 0) return e->a;
            }
            /* drop a same-width cast over a plain var/mem read of that width — but
             * NOT across the int<->float domain: `(long long)*(double*)p` is a real
             * FP->int conversion (cvttsd2si), not a redundant reinterpret. */
            if ((e->a->kind == EK::Var || e->a->kind == EK::Mem) &&
                e->a->width == e->width && e->is_unsigned == e->a->is_unsigned &&
                e->is_float == e->a->is_float)
                return e->a;
        }

        if (e->kind == EK::Unary && e->a && e->a->kind == EK::Const) {
            if (e->op == "-") return mkConst(-e->a->cval, e->width, false);
            if (e->op == "~") return mkConst(~e->a->cval, e->width, false);
        }

        if (e->kind == EK::Binary && e->a && e->b) {
            ExprP a = e->a, bb = e->b;
            bool ac = a->kind == EK::Const, bc = bb->kind == EK::Const;
            const std::string& op = e->op;
            /* NEVER apply integer constant-folding or algebraic identities to a
             * float operation: the operands are IEEE-754 bit patterns, so int
             * arithmetic on them is nonsense (0x40800000 + 0x40800000 != 8.0f's
             * bits) and identities like x*1 don't hold (1.0f's bits are not 1).
             * Just keep the FP type flowing up for rendering. */
            /* Unsigned comparison against 0 is a tautology or a simpler test — an
             * UNSIGNED value is always >= 0. A CF-based `jae/jb/cmovae/cmovb` on a
             * single (non-subtraction) value renders `(unsigned)X >= 0` (always
             * true) / `< 0` (always false); collapse them. Sound for ANY X. */
            if (!e->is_float && e->is_unsigned && bc && bb->cval == 0 &&
                !a->is_float) {
                if (op == ">=") return mkConst(1, e->width, false);   /* always true  */
                if (op == "<")  return mkConst(0, e->width, false);   /* always false */
                if (op == ">")  return fold(mkBinary("!=", a, mkConst(0, e->width), e->width));
                if (op == "<=") return fold(mkBinary("==", a, mkConst(0, e->width), e->width));
            }
            if (e->is_float || a->is_float || bb->is_float) {
                e->is_float = true;
                /* float doubling: x + x  ->  2.0 * x. Multiply-by-two is exact in
                 * IEEE-754 (an exponent bump, no rounding), so this is bit-identical
                 * to the addition — pure readability, turning the decompiled
                 * `*t15 + *t15` register-doubling noise into a real coefficient. */
                if (op == "+" && exprEqual(a, bb)) {
                    int fw = e->width ? e->width : (a->width ? a->width : 4);
                    bool is32 = fw < 8;
                    ExprP two = mkConst(is32 ? 0x40000000LL : 0x4000000000000000LL,
                                        is32 ? 4 : 8, false);
                    two->is_float = true;
                    ExprP m = mkBinary("*", two, a, fw);
                    m->is_float = true;
                    return m;
                }
                return e;
            }
            /* both const */
            if (ac && bc) {
                int64_t x = a->cval, y = bb->cval; int w = e->width;
                bool u = e->is_unsigned;
                auto wrap = [&](int64_t r)->ExprP{ return mkConst(r, w, u); };
                if (op=="+") return wrap(x+y);
                if (op=="-") return wrap(x-y);
                if (op=="*") return wrap(x*y);
                if (op=="&") return wrap(x&y);
                if (op=="|") return wrap(x|y);
                if (op=="^") return wrap(x^y);
                if (op=="<<") return wrap((y>=0&&y<64)?(x<<y):0);
                if (op==">>") {
                    if (u) return wrap((int64_t)((uint64_t)x >> (y&63)));
                    return wrap(x >> (y&63));
                }
                if (op=="/" && y!=0) return wrap(u?(int64_t)((uint64_t)x/(uint64_t)y):x/y);
                if (op=="%" && y!=0) return wrap(u?(int64_t)((uint64_t)x%(uint64_t)y):x%y);
            }
            /* integer register-doubling: x + x -> 2 * x. Value-exact mod 2^w and
             * mirrors the IEEE-754 float doubling handled above. Guarded to a
             * call-free, non-pointer operand so a side-effecting sub-expression is
             * never evaluated a different number of times, and ptr+ptr is left
             * alone. The constant sits on the RIGHT so the x*const folds below can
             * compose it, collapsing the compiler's (v*3)+(v*3) lea-doubling to v*6. */
            if (op=="+" && exprEqual(a, bb) && !has_call(a) && !renders_as_pointer(a)) {
                int ew = e->width ? e->width : (a->width ? a->width : 4);
                return fold(mkBinary("*", clone(a), mkConst(2, ew, e->is_unsigned), ew, e->is_unsigned));
            }
            /* `base == base ± K`  ⟺  `K == 0` (and !=). The compiler wrote an
             * empty / "== end" check as `p == p + count*stride`; EXACT, and turns a
             * baffling self-referential compare into a plain `count*stride == 0`. */
            if (op=="==" || op=="!=") {
                auto extra = [&](const ExprP& base, const ExprP& sum)->ExprP {
                    if (!sum || sum->kind!=EK::Binary || !(sum->op=="+"||sum->op=="-") || !sum->a) return nullptr;
                    if (exprEqual(base, sum->a)) return sum->b;                       /* base ± X */
                    if (sum->op=="+" && sum->b && exprEqual(base, sum->b)) return sum->a; /* X + base */
                    return nullptr;
                };
                int ew = e->width ? e->width : 8;
                if (ExprP x = extra(a, bb)) return fold(mkBinary(op, x, mkConst(0, ew), ew, e->is_unsigned));
                if (ExprP x = extra(bb, a)) return fold(mkBinary(op, x, mkConst(0, ew), ew, e->is_unsigned));
            }
            /* constant re-association for address/index math (never on floats — the
             * float guard above already returned): `(Y ± c1) ± c2 -> Y + (c1±c2)`,
             * so `(char*)((char*)p + 0x10) + 8` collapses to `p + 0x18`. */
            if ((op=="+"||op=="-") && bc && a->kind==EK::Binary && (a->op=="+"||a->op=="-") &&
                a->b && a->b->kind==EK::Const) {
                int ew = e->width?e->width:8;
                int64_t c1 = (a->op=="+") ? a->b->cval : -a->b->cval;
                int64_t c2 = (op=="+")    ? bb->cval   : -bb->cval;
                return fold(mkBinary("+", clone(a->a), mkConst(c1+c2, ew), ew, e->is_unsigned));
            }
            /* index-math strength un-reduction: fold the lea/shift-add longhand of a
             * constant multiply back into ONE multiply, so `(n + n*8) * 8 -> n * 72`
             * and `(m + m*2) << 5 -> m * 96`. Value-exact (mod 2^w). */
            if (op=="+" && a->kind==EK::Binary && a->op=="*" && a->b && a->b->kind==EK::Const &&
                exprEqual(a->a, bb)) {
                int ew=e->width?e->width:8; return fold(mkBinary("*", clone(bb), mkConst(a->b->cval+1, ew), ew, e->is_unsigned));
            }
            if (op=="+" && bb->kind==EK::Binary && bb->op=="*" && bb->b && bb->b->kind==EK::Const &&
                exprEqual(bb->a, a)) {
                int ew=e->width?e->width:8; return fold(mkBinary("*", clone(a), mkConst(bb->b->cval+1, ew), ew, e->is_unsigned));
            }
            if (op=="*" && bc && a->kind==EK::Binary && a->op=="*" && a->b && a->b->kind==EK::Const) {
                int ew=e->width?e->width:8; return fold(mkBinary("*", clone(a->a), mkConst(a->b->cval*bb->cval, ew), ew, e->is_unsigned));
            }
            if (op=="<<" && bc && bb->cval>=0 && bb->cval<62 &&
                a->kind==EK::Binary && a->op=="*" && a->b && a->b->kind==EK::Const) {
                int ew=e->width?e->width:8; return fold(mkBinary("*", clone(a->a), mkConst(a->b->cval << bb->cval, ew), ew, e->is_unsigned));
            }
            /* signed division by 2 recovered from the compiler idiom
             * `(x - (x >> N)) >> 1` (N = 31 for int, 63 for long long; both shifts
             * arithmetic) == `x / 2` (round toward zero). Pure readability. */
            if (op==">>" && !e->is_unsigned && bc && bb->cval==1 &&
                a->kind==EK::Binary && a->op=="-" && a->b &&
                a->b->kind==EK::Binary && a->b->op==">>" && !a->b->is_unsigned &&
                a->b->b && a->b->b->kind==EK::Const &&
                (a->b->b->cval==31 || a->b->b->cval==63) &&
                exprEqual(a->a, a->b->a)) {
                int ew = e->width ? e->width : 4;
                return fold(mkBinary("/", clone(a->a), mkConst(2, ew), ew));
            }
            /* identities */
            if (op=="+" && bc && bb->cval==0) return a;
            if (op=="+" && ac && a->cval==0) return bb;
            if (op=="-" && bc && bb->cval==0) return a;
            if (op=="*" && bc && bb->cval==1) return a;
            if (op=="*" && ac && a->cval==1) return bb;
            if (op=="*" && bc && bb->cval==0) return mkConst(0, e->width, e->is_unsigned);
            if (op=="*" && ac && a->cval==0) return mkConst(0, e->width, e->is_unsigned);
            if (op=="&" && bc && bb->cval==0) return mkConst(0, e->width, e->is_unsigned);
            if (op=="&" && ac && a->cval==0) return mkConst(0, e->width, e->is_unsigned);
            /* combine nested masks: `(X & C1) & C2` -> `X & (C1 & C2)`; then a
             * redundant wider mask folds away (`x & 0xff & 1` -> `x & 1`). */
            if (op=="&" && bc && a->kind==EK::Binary && a->op=="&" && a->b &&
                a->b->kind==EK::Const) {
                int ew = e->width ? e->width : 4;
                return fold(mkBinary("&", clone(a->a),
                            mkConst(a->b->cval & bb->cval, ew), ew, e->is_unsigned));
            }
            /* distribute a mask over a byte/word-write MERGE and drop the low half:
             * `((P) | (R & L)) & M` where the merged-in operand's mask L clears every
             * bit M keeps (L & M == 0) -> `P & M`. AND distributes over OR and
             * (R & L) & M == 0, so this is an exact value identity. It collapses the
             * nested partial-register merge chains a run of 8/16-bit sub-register
             * writes produces -- `(((old & 0xffffff00) | x) & 0xffffff00) | y` folds
             * down to `(old & 0xffffff00) | y` one level per write, then the narrowing
             * cast at the byte store drops the surviving high part entirely. Mirrors
             * the masks_off logic already used on the cast side above. */
            if (op=="&" && bc && a->kind==EK::Binary && a->op=="|" && a->a && a->b) {
                uint64_t M = (uint64_t)bb->cval;
                auto masks_off = [&](const ExprP& s)->bool {
                    return s && s->kind==EK::Binary && s->op=="&" && s->b &&
                           s->b->kind==EK::Const &&
                           ((uint64_t)s->b->cval & M)==0;
                };
                int ew = e->width ? e->width : 4;
                if (masks_off(a->b))
                    return fold(mkBinary("&", clone(a->a), clone(bb), ew, e->is_unsigned));
                if (masks_off(a->a))
                    return fold(mkBinary("&", clone(a->b), clone(bb), ew, e->is_unsigned));
            }
            /* redundant narrowing cast before a small-mask AND: `(signed char)X & K` == `X & K`
             * when K's set bits all fit the cast width — the AND masks out the sign/zero-
             * extended bits, so the truncation is a no-op. Removes `(signed char)`/`(short)`
             * noise on flag/bitfield tests. */
            if (op=="&" && bc && bb->cval >= 0 && a && a->kind==EK::Cast && a->a &&
                a->op.find('*')==std::string::npos && !a->is_float && !a->a->is_float &&
                a->width >= 1 && a->width <= 8 &&
                (a->width >= 8 || (uint64_t)bb->cval <= (((uint64_t)1 << (a->width * 8)) - 1))) {
                /* peel ANY integer cast (byte..qword) whose width covers the mask:
                 * `(uint64_t)((int8_t)v1) & 0xf` -> `v1 & 0xf`, dropping both the
                 * widening and the sign-changing truncation the mask makes dead.
                 * fold() re-applies, so a chain of casts unwinds one level at a time. */
                int ew = e->width ? e->width : 4;
                return fold(mkBinary("&", clone(a->a), clone(bb), ew, e->is_unsigned));
            }
            if (op=="|" && bc && bb->cval==0) return a;
            if (op=="|" && ac && a->cval==0) return bb;
            if (op=="^" && bc && bb->cval==0) return a;
            if (op=="^" && ac && a->cval==0) return bb;
            /* idempotent self idioms: the lifter renders `test r,r` as `r & r`
             * (the flag computation), which surfaced as a redundant self-AND in
             * fmt_into's `(n & n) >= 0`. X & X -> X, X | X -> X, X ^ X -> 0. The
             * operands are pure register/memory value expressions. */
            if ((op=="&" || op=="|") && exprEqual(a, bb)) return a;
            if (op=="^" && exprEqual(a, bb)) return mkConst(0, e->width, e->is_unsigned);
            /* idempotent LOGICAL connective: `X && X` -> `X`, `X || X` -> `X`. The
             * ordered float-equality idiom `ucomiss; jp L; jne L` models BOTH the
             * unordered(NaN) edge and the not-equal edge as the same `x == c`, so the
             * combined condition is a duplicated `x==c && x==c`. Collapse it. Safe only
             * when X is side-effect-free — a call would otherwise lose an evaluation. */
            if ((op=="&&" || op=="||") && exprEqual(a, bb) && !has_call(a)) return a;
            /* a setcc/comparison value is already 0/1; the movzx that zero-extends
             * it lifts as `bool & 0xff`, and any odd mask is then a no-op. Drop it
             * (`(x != 0) & 0xff` -> `x != 0`); an even mask kills bit 0 -> 0. */
            if (op=="&" && bc && is_bool_value(a)) return (bb->cval & 1) ? a : mkConst(0, e->width, e->is_unsigned);
            if (op=="&" && ac && is_bool_value(bb)) return (a->cval & 1) ? bb : mkConst(0, e->width, e->is_unsigned);
            /* all-ones identities: `x | -1 == -1`, `x & -1 == x` (at the op width).
             * This folds the `ctx_rdi | -1` shape — a callee-saved-register leak
             * OR'd with all ones is just -1, so the phantom value is irrelevant and
             * the result is the intended `-1` (e.g. a "count = -1 / unlimited"
             * sentinel). Only a FULL-width all-ones mask counts, so a real low-byte
             * mask like `x & 0xff` is left intact. */
            {
                auto all_ones = [&](const ExprP& c)->bool {
                    if (!c || c->kind != EK::Const) return false;
                    if (c->cval == -1) return true;
                    int w = e->width ? e->width : 8;
                    if (w >= 8) return false;
                    uint64_t mask = (1ull << (w * 8)) - 1;
                    return (uint64_t)c->cval == mask;
                };
                if (op=="|" && (bc && all_ones(bb))) return mkConst(-1, e->width, e->is_unsigned);
                if (op=="|" && (ac && all_ones(a)))  return mkConst(-1, e->width, e->is_unsigned);
                if (op=="&" && bc && all_ones(bb)) return a;
                if (op=="&" && ac && all_ones(a))  return bb;
            }
            /* scratch-register idiom: the compiler set only the low byte(s) of a
             * register that still held a local's address (`lea rdx,[v]; mov dl,1`).
             * Masking/or-ing a stack address with constants is never meaningful C;
             * the intended value is just the immediate written into the low byte. */
            {
                auto addr_masked = [](const ExprP& x)->bool {
                    if (!x) return false;
                    if (x->kind==EK::AddrOf) return true;
                    if (x->kind==EK::Binary && x->op=="&" &&
                        ((x->a && x->a->kind==EK::AddrOf) ||
                         (x->b && x->b->kind==EK::AddrOf))) return true;
                    return false;
                };
                if (op=="|" && bc && addr_masked(a))  return bb;
                if (op=="|" && ac && addr_masked(bb)) return a;
            }
            if ((op=="<<"||op==">>") && bc && bb->cval==0) return a;
            if (op=="^" && exprEqual(a, bb)) return mkConst(0, e->width, e->is_unsigned);
            if (op=="-" && exprEqual(a, bb)) return mkConst(0, e->width, e->is_unsigned);
            /* idempotent: `x | x` and `x & x` are just `x` — cleans up the MSVC
             * `or r8,r8`/`and` test idioms that read as `(a3 | a3)`. */
            if ((op=="|" || op=="&") && exprEqual(a, bb)) return a;
            /* fold (x + c1) + c2 -> x + (c1+c2) */
            if (op=="+" && bc && a->kind==EK::Binary && a->op=="+" && a->b &&
                a->b->kind==EK::Const) {
                return mkBinary("+", a->a, mkConst(a->b->cval + bb->cval, e->width), e->width);
            }
        }
        return e;
    }

    /* LATE READABILITY PEEPHOLE (Hex-Rays parity). fold() runs per-expr at LIFT
     * time — before copy_propagate/inlining stack casts and expose `x + (-K)`
     * forms — so those never get re-normalized. This pass re-walks the FINAL
     * expressions (after all inlining) applying ONLY value-identical rewrites:
     *   - redundant nested integer casts:  (T)((T)x) / (uN)(sN)x / (sN)((sM)x),N<=M
     *   - `x + (-K)` -> `x - K`
     *   - `(a - b) ==/!= 0` -> `a ==/!= b`   (both are the same 0/1 value)
     *   - `(a + C1) ==/!= C2` -> `a ==/!= (C2 - C1)`   (offset-compare normalize)
     * All context-free (safe anywhere the expr appears). Gated DS_NO_PEEPHOLE. */
    /* `c ? K1 : K2` with two CONSTANT arms — the shape the x87 status word is built from */
    static bool ternary_of_consts(const ExprP& e) {
        return e && e->kind == EK::Ternary && e->a && e->b && e->c &&
               e->b->kind == EK::Const && e->c->kind == EK::Const &&
               !e->b->is_float && !e->c->is_float && !e->is_float;
    }
    /* If `x` is `c ? nonzero : 0` (or the inverted `c ? 0 : nonzero`), return the
     * condition under which x is TRUE — i.e. x's truth value as a plain expression. */
    ExprP ternary_truth(const ExprP& x) {
        if (!ternary_of_consts(x)) return nullptr;
        bool t = (x->b->cval != 0), f = (x->c->cval != 0);
        if (t == f) return nullptr;                       /* carries no information */
        ExprP c = clone(x->a);
        return t ? c : mkUnary("!", c, 4);
    }

    ExprP peephole_expr(ExprP e) {
        if (!e) return e;
        e->a = peephole_expr(e->a); e->b = peephole_expr(e->b); e->c = peephole_expr(e->c);
        for (auto& ar : e->args) ar = peephole_expr(ar);

        /* ---- x87 status-word collapse -------------------------------------------
         * The legacy compare idiom `fcom; fnstsw ax; test ah,<mask>` is modeled
         * faithfully as the FPU status word `(a<b ? 0x100 : 0) | (a==b ? 0x4000 : 0)`
         * — correct, but unreadable. Bitwise ops distribute over shifts and masks, so
         * pushing the shift/mask down into the constant arms collapses the whole thing
         * back into the comparison it started as. Every rule below is generic
         * (any ternary-of-constants) and value-identical; they are guarded to
         * constant-ternary operands so ordinary expressions are never bloated.
         * DS_NO_TERNFOLD. */
        static const bool tf_off = std::getenv("DS_NO_TERNFOLD") != nullptr;
        if (!tf_off && e->kind == EK::Binary && (e->op == ">>" || e->op == "&") && !e->is_float &&
            e->b && e->b->kind == EK::Const && e->a) {
            /* Every constant arm involved is a small NON-NEGATIVE status-word bit, so a
             * widening cast over them is value-preserving and can be peeled — without
             * this the renderer's `(uint64_t)(...)` sits between the shift and the `|`
             * and blocks the whole collapse. all_cty() is what makes the peel safe: it
             * admits only constants and constant-ternaries. */
            std::function<bool(const ExprP&)> all_cty = [&](const ExprP& x) -> bool {
                if (!x) return false;
                if (x->kind == EK::Const) return x->cval >= 0;
                if (ternary_of_consts(x)) return x->b->cval >= 0 && x->c->cval >= 0;
                if (x->kind == EK::Cast) return all_cty(x->a);
                return x->kind == EK::Binary && x->op == "|" && all_cty(x->a) && all_cty(x->b);
            };
            ExprP src = e->a;
            while (src && src->kind == EK::Cast && src->a && all_cty(src)) src = src->a;
            int64_t m = e->b->cval;
            bool shr = (e->op == ">>");
            auto ap = [&](int64_t v) -> int64_t {
                return shr ? (int64_t)((uint64_t)v >> (uint64_t)(m & 63)) : (v & m);
            };
            /* (A|B) >> s -> (A>>s)|(B>>s) ;  (A|B) & M -> (A&M)|(B&M) */
            if (src && src->kind == EK::Binary && src->op == "|" && all_cty(src)) {
                auto side = [&](ExprP s) {
                    auto n = std::make_shared<Expr>(*e); n->a = s; n->b = clone(e->b);
                    return peephole_expr(n);
                };
                return peephole_expr(mkBinary("|", side(src->a), side(src->b),
                                              e->width, e->is_unsigned));
            }
            /* (c ? K1 : K2) >> s / & M  ->  c ? (K1 op s) : (K2 op s) */
            if (ternary_of_consts(src) && src->b->cval >= 0 && src->c->cval >= 0) {
                return peephole_expr(mkTernary(clone(src->a),
                                               mkConst(ap(src->b->cval), e->width, e->is_unsigned),
                                               mkConst(ap(src->c->cval), e->width, e->is_unsigned),
                                               e->width));
            }
        }
        /* `(x % N) % N` -> `(x % N)`. An UNSIGNED modulo already lies in [0, N-1], so a
         * second reduction by the same N is identity. NullWare's obfuscator reduces twice
         * (a 64-bit magic then a 32-bit one) and, now that both magics fold, the
         * redundancy is visible — 22 sites. Requirements that make this sound: the INNER
         * modulo must be UNSIGNED (a signed remainder can be negative, and a widening
         * cast of that would wrap to a huge value where `% N` is NOT identity), and N
         * must be small enough that any intervening narrowing cast still holds it. */
        if (!tf_off && e->kind == EK::Binary && e->op == "%" && !e->is_float &&
            e->b && e->b->kind == EK::Const && e->b->cval > 0 && e->b->cval <= 127 && e->a) {
            ExprP inner = e->a;
            while (inner && inner->kind == EK::Cast && inner->a) inner = inner->a;
            if (inner && inner->kind == EK::Binary && inner->op == "%" && inner->is_unsigned &&
                inner->b && inner->b->kind == EK::Const && inner->b->cval == e->b->cval)
                return e->a;
        }
        /* `(x * c1) * c2` -> `x * (c1*c2)` on the FINAL tree. fold() has this exact
         * rule but runs at LIFT time; a pointer/index byte-offset assembled later by
         * copy-propagation (a lea `*9` composed with the `*8` address scale, or the
         * `x+x`->`*2` doubling composed with `*8`) reaches the renderer un-refolded as
         * `x * 9 * 8` / `x * 2 * 8`. Integer only, value-exact mod 2^w. */
        if (!tf_off && e->kind == EK::Binary && e->op == "*" && !e->is_float &&
            e->b && e->b->kind == EK::Const &&
            e->a && e->a->kind == EK::Binary && e->a->op == "*" && !e->a->is_float &&
            e->a->b && e->a->b->kind == EK::Const) {
            int ew = e->width ? e->width : 8;
            return peephole_expr(mkBinary("*", clone(e->a->a),
                        mkConst(e->a->b->cval * e->b->cval, ew, e->is_unsigned),
                        ew, e->is_unsigned));
        }
        /* both arms the same constant -> that constant (the condition is dead) */
        if (!tf_off && ternary_of_consts(e) && e->b->cval == e->c->cval)
            return mkConst(e->b->cval, e->width, e->is_unsigned);
        /* X | 0 -> X (same width only: returning a narrower operand would silently
         * change the expression's width for every consumer). */
        if (!tf_off && e->kind == EK::Binary && e->op == "|" && !e->is_float) {
            if (e->b && e->b->kind == EK::Const && e->b->cval == 0 &&
                e->a && e->a->width == e->width) return e->a;
            if (e->a && e->a->kind == EK::Const && e->a->cval == 0 &&
                e->b && e->b->width == e->width) return e->b;
        }
        /* partial-register byte/word merge onto a POINTER's stale bits:
         * `(P & 0xFFFFFF00) | Y` where P is a pointer value comes from a
         * `mov pl,byte` whose kept high bits are a leftover address. Masking a
         * pointer to keep only its high bytes and OR-ing in a low byte is never
         * meaningful C -- the value is observable only as its low part Y (the code
         * ties a scanned character to `a2->field_0`). Drop the dead high half.
         * Mirrors the byte-cast merge strip in mkCast, but keyed on the merged-in
         * base being a POINTER rather than on a truncating cast. The keep-mask has
         * its low byte(s) all zero; pointer-tag idioms (`(p & ~7) | tag`) keep low
         * bits set and so never match. */
        if (!tf_off && e->kind == EK::Binary && e->op == "|" && !e->is_float && e->a && e->b) {
            auto is_keepmask = [](int64_t m) -> bool {
                uint64_t u = (uint64_t)m;
                return u == 0xFFFFFF00ull || u == 0xFFFFFFFFFFFFFF00ull ||   /* ~0xFF   (byte write) */
                       u == 0xFFFF0000ull || u == 0xFFFFFFFFFFFF0000ull;     /* ~0xFFFF (word write) */
            };
            auto hi_ptr_merge = [&](const ExprP& masked, const ExprP& low) -> bool {
                return masked && masked->kind == EK::Binary && masked->op == "&" &&
                       masked->a && masked->b && masked->b->kind == EK::Const &&
                       is_keepmask(masked->b->cval) &&
                       expr_is_pointer(masked->a) && low && !expr_is_pointer(low);
            };
            if (hi_ptr_merge(e->a, e->b)) return e->b;
            if (hi_ptr_merge(e->b, e->a)) return e->a;
        }
        /* a constant-ternary tested against 0 IS its condition */
        if (!tf_off && e->kind == EK::Binary && (e->op == "!=" || e->op == "==") &&
            e->b && e->b->kind == EK::Const && e->b->cval == 0 && !e->b->is_float) {
            if (ExprP c = ternary_truth(e->a))
                return (e->op == "!=") ? c : peephole_expr(mkUnary("!", c, 4));
            /* `(c1?NZ:0) | (c2?NZ:0)` tested against 0 -> c1 || c2 */
            if (e->a && e->a->kind == EK::Binary && e->a->op == "|") {
                ExprP c1 = ternary_truth(e->a->a), c2 = ternary_truth(e->a->b);
                if (c1 && c2) {
                    /* re-peephole the `||`: it is BUILT here, so without another pass the
                     * `a<b || a==b` -> `a<=b` rule below would never see it */
                    ExprP o = peephole_expr(mkBinary("||", c1, c2, 4));
                    return (e->op == "!=") ? o : peephole_expr(mkUnary("!", o, 4));
                }
            }
        }
        /* `a<b || a==b` -> `a<=b` (and the `>` mirror) — the shape the status-word
         * collapse leaves behind for the C0|C3 mask. Side-effect-free operands only. */
        if (!tf_off && e->kind == EK::Binary && e->op == "||" && e->a && e->b &&
            e->a->kind == EK::Binary && e->b->kind == EK::Binary && e->b->op == "==" &&
            (e->a->op == "<" || e->a->op == ">") &&
            exprEqual(e->a->a, e->b->a) && exprEqual(e->a->b, e->b->b) &&
            !has_call(e->a) && !has_call(e->b) && !reads_mem(e->a)) {
            auto n = std::make_shared<Expr>(*e->a);
            n->op = (e->a->op == "<") ? "<=" : ">=";
            return n;
        }

        /* redundant nested integer cast (same domain, non-float) */
        if (e->kind == EK::Cast && e->a && e->a->kind == EK::Cast &&
            !e->is_float && !e->a->is_float) {
            if (e->a->op == e->op) return e->a;                              /* (T)((T)x) */
            if (e->a->width == e->width ||                                   /* (uN)(sN)x */
                e->a->width >  e->width) {                                   /* (sN)((sM)x) N<M: truncation wins */
                auto c = std::make_shared<Expr>(*e); c->a = e->a->a; return peephole_expr(c);
            }
            /* A8 + movzx idiom: a WIDENING cast over a NARROWER cast is redundant — the
             * narrow cast already promotes to `int` value-identically in any expression
             * context (`(int)((signed char)x)` -> `(signed char)x`, `(unsigned int)((
             * unsigned char)x)` -> `(unsigned char)x`). Drop the outer widening cast,
             * keeping the narrower one — UNLESS the outer is unsigned and the inner is
             * signed, where the promotion's sign-extended negative would be reinterpreted
             * as a large unsigned (`(unsigned int)((signed char)0xFF)` = 0xFFFFFFFF, not
             * (signed char)0xFF = -1). */
            /* Only when the OUTER cast is int-width (<=4): there the narrow inner cast
             * promotes to `int` value-identically, so the outer widening is pure noise.
             * A width-8 (`long long`) outer cast is a REAL 64-bit widening — C promotes
             * to `int`, not to 64-bit — so dropping it silently narrows a wide multiply
             * `(unsigned long long)((unsigned int)a) * b` to a 32-bit product (mod 2^32),
             * losing the high half (every bignum limb carry `product >> 32`). Keep it. */
            if (e->a->width < e->width && e->width <= 4 &&
                !(e->is_unsigned && !e->a->is_unsigned))
                return peephole_expr(e->a);
        }
        /* a same-width, same-signedness integer cast over a plain var/mem read of that
         * width is a no-op — `(int)v1` after D1 narrowed v1 to `int`. (fold has this rule
         * but runs at lift, before narrowing; re-apply it here on the FINAL widths.) */
        if (e->kind == EK::Cast && e->a && !e->is_float && !e->a->is_float &&
            (e->a->kind == EK::Var || e->a->kind == EK::Mem) &&
            e->a->width == e->width && e->is_unsigned == e->a->is_unsigned)
            return e->a;
        /* An `int`-width integer cast over a comparison/logical result is pure noise:
         * a C relational or logical operator (`a > b`, `x && y`) already yields `int`
         * 0/1, so `(int32_t)(a > b)` == `(a > b)` value-identically. Restricted to
         * width==4 (a width-8 cast is a REAL widening that matters if the 0/1 is then
         * shifted or multiplied at 64-bit width) and to non-pointer, non-float casts. */
        if (e->kind == EK::Cast && !e->is_float && e->width == 4 &&
            e->op.find('*') == std::string::npos && e->a && e->a->kind == EK::Binary) {
            const std::string& io = e->a->op;
            if (io=="<"||io=="<="||io==">"||io==">="||io=="=="||io=="!="||io=="&&"||io=="||")
                return e->a;
        }
        /* A2: `(char*)((char*)p + off)` -> `(char*)p + off`. A `(char*)` cast over a `+`/`-`
         * whose base operand is ALREADY a `(char*)` is redundant — the byte-pointer sum is
         * already char*. Drop the outer cast so nested byte-arithmetic doesn't stack casts. */
        if (e->kind == EK::Cast && e->op == "(char*)" && e->a &&
            e->a->kind == EK::Binary && (e->a->op == "+" || e->a->op == "-")) {
            auto is_charptr = [](const ExprP& x){ return x && x->kind == EK::Cast && x->op == "(char*)"; };
            if (is_charptr(e->a->a) || is_charptr(e->a->b)) return e->a;
        }
        if (e->kind == EK::Binary && e->a && e->b) {
            const std::string& op = e->op;
            /* x + (-K) -> x - K  (integers only; guard INT64_MIN) */
            if (op == "+" && !e->is_float && e->b->kind == EK::Const &&
                !e->b->is_unsigned && e->b->cval < 0 && e->b->cval != INT64_MIN) {
                auto c = std::make_shared<Expr>(*e);
                c->op = "-"; c->b = mkConst(-e->b->cval, e->b->width, false);
                return c;
            }
            /* (x + x) * K  ->  x * (2*K)  (and the mirror K * (x + x)). A doubled
             * operand scaled by a constant is a strength-reduced array index
             * (`(idx + idx) * 8` == idx*16 for a 16-byte stride) that Hex-Rays folds.
             * Value-identical in modular arithmetic (2*x*K == x*(2K)); integer only,
             * K bounded so 2*K cannot overflow int64, and it reads x ONCE where the
             * sum read it twice (strictly fewer evaluations, so no aliasing concern).
             * Guarded to a call-free doubled operand so nothing side-effecting moves. */
            if (op == "*" && !e->is_float) {
                for (int sw = 0; sw < 2; ++sw) {
                    ExprP kc  = sw ? e->a : e->b;   /* constant side       */
                    ExprP sum = sw ? e->b : e->a;   /* the (x + x) side     */
                    if (kc && kc->kind == EK::Const && !kc->is_float &&
                        kc->cval > -0x40000000LL && kc->cval < 0x40000000LL &&
                        sum && sum->kind == EK::Binary && sum->op == "+" && !sum->is_float &&
                        sum->a && sum->b && exprEqual(sum->a, sum->b) && !has_call(sum->a)) {
                        return peephole_expr(mkBinary("*", clone(sum->a),
                                             mkConst(kc->cval * 2, e->width, e->is_unsigned),
                                             e->width, e->is_unsigned));
                    }
                }
            }
            /* comparison normalizations (value-identical: == / != yield the same 0/1) */
            if (op == "==" || op == "!=") {
                /* (a - b) ==/!= 0  ->  a ==/!= b */
                if (e->b->kind == EK::Const && e->b->cval == 0 && !e->b->is_float &&
                    e->a->kind == EK::Binary && e->a->op == "-" && e->a->a && e->a->b &&
                    !e->a->is_float) {
                    auto c = std::make_shared<Expr>(*e);
                    c->a = e->a->a; c->b = e->a->b; return peephole_expr(c);
                }
                /* (a + C1) ==/!= C2  ->  a ==/!= (C2 - C1) */
                if (e->b->kind == EK::Const && !e->b->is_float && !e->a->is_float &&
                    e->a->kind == EK::Binary && (e->a->op == "+" || e->a->op == "-") &&
                    e->a->a && e->a->b && e->a->b->kind == EK::Const) {
                    int64_t c1 = e->a->op == "+" ? e->a->b->cval : -e->a->b->cval;
                    int64_t nc = e->b->cval - c1;
                    /* At a sub-word width the hardware ZF/compare truncates the add
                     * result to w bytes, but C promotes the operand (e.g. (int8_t)x)
                     * to int -- so an out-of-range folded constant makes the equality
                     * a tautology. A byte counter `add r10b,0xff; jne` folded to the
                     * impossible `(int8_t)x != -255` (never false), silently losing
                     * the 16-iteration loop bound. Reduce the constant modulo 2^(8w)
                     * into the range the promoted operand spans, matching the inner
                     * operand's signedness. Value-identical mod 2^(8w). */
                    int fw = e->a->width;
                    if (fw == 1 || fw == 2) {
                        int bits = fw * 8;
                        uint64_t mask = (1ull << bits) - 1;
                        uint64_t u = (uint64_t)nc & mask;
                        bool lhs_uns = false;
                        ExprP inr = e->a->a;
                        if (inr && inr->kind == EK::Cast)
                            lhs_uns = inr->is_unsigned || inr->op == "(unsigned char)" ||
                                      inr->op == "(unsigned short)";
                        if (lhs_uns) nc = (int64_t)u;
                        else { uint64_t sgn = 1ull << (bits - 1);
                               nc = (u & sgn) ? (int64_t)(u | ~mask) : (int64_t)u; }
                    }
                    auto c = std::make_shared<Expr>(*e);
                    c->a = e->a->a; c->b = mkConst(nc, e->b->width, e->b->is_unsigned);
                    return peephole_expr(c);
                }
            }
            /* A6/A7: a NEGATIVE constant operand of a bitwise op is a bitmask/magic
             * (bit63 or a two's-complement mask) — render it in hex, not signed decimal
             * (`& -9223372036854775808LL` -> `& 0x8000000000000000uLL`). Signedness is
             * irrelevant to `& | ^`, so this is value-identical. For a 32-bit op, narrow
             * to the low 32 bits so the float sign-clear `-2147483649` reads as its true
             * `0x7FFFFFFF` mask rather than an over-wide 64-bit value. */
            if (op == "&" || op == "|" || op == "^") {
                for (ExprP* o : { &e->a, &e->b }) {
                    ExprP& k = *o;
                    if (k && k->kind == EK::Const && !k->is_float && !k->hex_hint && k->cval < 0) {
                        auto c = std::make_shared<Expr>(*k); c->hex_hint = true;
                        if (e->width == 4) { c->cval = (int64_t)(int32_t)k->cval; c->width = 4; }
                        k = c;
                    }
                }
            }
            /* H4: a printable-ASCII constant compared against a BYTE value -> char literal
             * (`c == 'A'`). The other operand must be byte-typed (a width-1 Var/Mem or a
             * `(char)`/`(unsigned char)` cast) so a real integer 0x41 is never turned into
             * a char. Value-identical (`'A'` == 0x41). */
            if (op == "==" || op == "!=" || op == "<" || op == "<=" || op == ">" || op == ">=") {
                auto byteish = [](const ExprP& x) -> bool {
                    if (!x || x->is_float) return false;
                    if (x->kind == EK::Cast && x->width == 1) return true;
                    ExprP c = x; int g = 0; while (c && c->kind == EK::Cast && g++ < 6) c = c->a;
                    return c && (c->kind == EK::Mem || c->kind == EK::Var) && c->width == 1 && !c->is_float;
                };
                for (int sw = 0; sw < 2; ++sw) {
                    ExprP& k   = sw ? e->b : e->a;
                    ExprP& sib = sw ? e->a : e->b;
                    if (k && k->kind == EK::Const && !k->is_float && !k->char_hint &&
                        k->cval >= 0x20 && k->cval <= 0x7e && byteish(sib)) {
                        auto c = std::make_shared<Expr>(*k); c->char_hint = true; k = c;
                    }
                }
            }
        }
        return e;
    }
    /* ----- stack-string recovery (annotation-only) -----
     * Obfuscators — and any code that builds a buffer from immediates — assemble a
     * string in a stack region with a run of constant stores to consecutive offsets
     * (`mov dword [rsp+0x20],0x3d79656b; mov word [rsp+0x24],0x3234; mov byte
     * [rsp+0x26],0`). Every store renders as an opaque hex write, so the string itself
     * is invisible. Reassemble the little-endian bytes and, when they form a printable
     * NUL-terminated run, note it on the REGION'S DECLARATION.
     *
     * Strictly a note: the stores are real writes and are left exactly as they are. The
     * note also cannot ride on the store site — SK::Comment is a tombstone that
     * block_stmts_empty/thread_empty treat as an empty block and thread away. */
    void recover_stack_strings() {
        static const bool off = std::getenv("DS_NO_STACKSTR") != nullptr;
        stack_str_found.clear();
        if (off) return;
        /* Splat each store's little-endian bytes over the offsets it covers. A byte that
         * two DIFFERENT instructions write with DIFFERENT values is ambiguous (branches,
         * or a later overwrite) -> POISON it rather than pick a value: a wrong string is
         * far worse than none. Re-exec of the same address is a no-op because the store
         * map is keyed by address. */
        struct Byte { uint8_t val; bool clean; };
        std::map<int64_t, Byte> mem;
        for (auto& kv : stack_str_stores) {
            const StrStore& ss = kv.second;
            for (int i = 0; i < ss.width; ++i) {
                uint8_t bv = ss.is_const ? (uint8_t)((ss.val >> (8 * i)) & 0xff) : 0;
                auto it = mem.find(ss.norm + i);
                if (it == mem.end()) { Byte nb; nb.val = bv; nb.clean = ss.is_const; mem[ss.norm + i] = nb; }
                else if (!ss.is_const || !it->second.clean || it->second.val != bv) it->second.clean = false;
            }
        }
        if (mem.empty()) return;
        /* candidate regions: the addressed aggregates (`char sN[]`) plus the indexed
         * stack arrays (`char bufN[]`) — the only stack objects rendered as a buffer
         * whose decl can carry the note. */
        struct Cand { std::string name; int64_t base, end; };
        std::vector<Cand> cands;
        for (auto& r : agg_regions) cands.push_back({r.name, r.base, r.end});
        for (auto& kv : stack_array_name)
            if (!agg_region_for(kv.first)) cands.push_back({kv.second, kv.first, kv.first + 256});
        for (auto& c : cands) {
            for (auto it = mem.lower_bound(c.base); it != mem.end() && it->first < c.end; ++it) {
                if (!it->second.clean || it->second.val == 0) continue;
                int64_t s = it->first;
                /* report MAXIMAL runs only: skip a start whose predecessor is a printable
                 * byte of the same run (it would just re-report a suffix). */
                auto pv = mem.find(s - 1);
                if (s - 1 >= c.base && pv != mem.end() && pv->second.clean && pv->second.val != 0) continue;
                std::string esc; int nbytes = 0; bool term = false;
                for (int64_t o = s; o < c.end && nbytes < 4096; ++o) {
                    auto b = mem.find(o);
                    if (b == mem.end() || !b->second.clean) break;   /* gap/poison -> not provably a string */
                    if (b->second.val == 0) { term = true; break; }
                    if (!cstr_escape_byte(b->second.val, esc)) break;
                    ++nbytes;
                }
                if (!term || nbytes < CSTR_MINLEN) continue;         /* must be NUL-terminated and long enough */
                stack_str_found[c.name][s - c.base] = comment_safe(esc);
            }
        }
    }
    /* `*` and `/` adjacent would CLOSE the block comment the note lives in and swallow
     * the rest of the function. read_cstring does not neutralize them because its other
     * callers emit string literals, where `*\/` is legal. */
    static std::string comment_safe(const std::string& s) {
        std::string o;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '/' && !o.empty() && o.back() == '*') o += '\\';
            o += s[i];
        }
        return o;
    }
    /* `  /` + `* s1 = "key=42" *` + `/` for a decl line, or "" if nothing was recovered.
     * The `+off` is ALWAYS rendered when the string does not start at the region base —
     * `s1 = "assword"` for a buffer whose first byte is dynamic would be a confident lie. */
    std::string stack_str_note(const std::string& name) {
        auto it = stack_str_found.find(name);
        if (it == stack_str_found.end() || it->second.empty()) return "";
        std::string o;
        for (auto& kv : it->second) {
            o += o.empty() ? "  /* " : ", ";
            o += name;
            if (kv.first) o += "+" + std::to_string((long long)kv.first);
            o += " = \"" + kv.second + "\"";
        }
        return o + " */";
    }
    void late_peephole() {
        if (std::getenv("DS_NO_PEEPHOLE")) return;
        auto go = [&](ExprP& e){ e = peephole_expr(e); };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) { go(s.lhs); go(s.rhs); }
            go(b.cond); go(b.ret_value); go(b.ret_raw); go(b.switch_var); go(b.tail_call);
        }
    }

    /* =================================================================== */
    /*  4. Phi resolution (cross-block register materialization)            */
    /* =================================================================== */

    /* entry_reg[blk][reg] = expression a register holds on entry to blk, when
     * uniquely defined; otherwise a temp variable name (materialized). */
    std::vector<std::array<ExprP, R_COUNT>> entry_reg;
    /* entry_reg_hi[blk][reg] = high 64-bit lane of an XMM on entry to blk, when
     * all live predecessors agree (loop-invariant broadcast). No phi temps. */
    std::vector<std::array<ExprP, R_COUNT>> entry_reg_hi;
    /* entry_xmm_f[blk][reg][lane] = the 4 packed-float lanes of an XMM on entry to
     * blk when all live predecessors agree (loop-invariant broadcast survives into
     * the loop). entry_xmm_f_real[blk][reg] carries the float-realness. */
    std::vector<std::array<std::array<ExprP, 4>, R_COUNT>> entry_xmm_f;
    std::vector<std::array<bool, R_COUNT>> entry_xmm_f_real;
    /* packed-INT analog of entry_xmm_f (the guard-block broadcast for a[i]*=k). */
    std::vector<std::array<std::array<ExprP, 4>, R_COUNT>> entry_xmm_i;
    std::vector<std::array<bool, R_COUNT>> entry_xmm_i_real;
    /* entry_vla[blk][reg] = address a wide (ymm/zmm) reg was loaded-from on entry
     * to blk, when all live predecessors agree — lets a jump-table-unrolled memcpy
     * (load and store in different blocks) still model as a real chunked copy. */
    std::vector<std::array<ExprP, R_COUNT>> entry_vla;
    /* entry_vfill[blk][reg] = broadcast/zero/ones fill value (+ element size) a wide
     * reg holds on entry to blk, when all preds agree — the jump-table-unrolled memset. */
    std::vector<std::array<ExprP, R_COUNT>> entry_vfill;
    std::vector<std::array<int, R_COUNT>> entry_vfill_esz;
    std::vector<std::array<bool, R_COUNT>> reg_live_in;
    /* x87 stack at each block's EXIT, so a successor can inherit it. regfile is reset
     * per block and re-seeded, so the FPU stack must be too — letting it flow in raw
     * walk order made a block read whatever stack the previously-WALKED block left,
     * not its predecessor's (a compare after an unrelated block's pops then read an
     * empty stack and compared 0.0 with 0.0). Mirrors block_flags_out. */
    std::vector<std::array<ExprP, 8>> block_fpu_out;
    std::vector<int>  block_fpu_top_out;
    std::vector<char> block_fpu_valid;

    void init_entry_regs() {
        entry_reg.assign(blocks.size(), {});
        entry_reg_hi.assign(blocks.size(), {});
        entry_xmm_f.assign(blocks.size(), {});
        entry_xmm_f_real.assign(blocks.size(), {});
        entry_xmm_i.assign(blocks.size(), {});
        entry_xmm_i_real.assign(blocks.size(), {});
        entry_vla.assign(blocks.size(), {});
        entry_vfill.assign(blocks.size(), {});
        entry_vfill_esz.assign(blocks.size(), {});
        block_flags_out.assign(blocks.size(), FlagSrc());
        block_fpu_out.assign(blocks.size(), {});
        block_fpu_top_out.assign(blocks.size(), 0);
        block_fpu_valid.assign(blocks.size(), 0);
        /* entry block: seed argument registers from params. 32-bit cdecl passes
         * args on the stack (recovered into param_home_off by detect_cdecl_params),
         * so there is nothing to seed in registers — and seeding ecx/edx there
         * would wrongly leak a param name into genuine scratch use. */
        int eb = entry_block();
        Reg argregs[4] = { R_RCX, R_RDX, R_R8, R_R9 };
        Reg xmmregs[4] = { R_XMM0, R_XMM1, R_XMM2, R_XMM3 };
        if (e->arch == DS_ARCH_X64 && eb >= 0 && eb < (int)blocks.size()) {
            for (int p = 0; p < num_params && p < 4; ++p) {
                std::string nm = "a" + std::to_string(p + 1);
                int w = var_width.count(nm) ? var_width[nm] : 8;
                int cw = w >= 8 ? 8 : 4;
                /* Seed BOTH the integer arg reg and the same-position XMM reg: a
                 * given parameter occupies exactly one of them depending on its
                 * type (float -> XMM, integer/pointer -> GPR). Seeding both lets
                 * the callee read whichever holds the value while keeping one
                 * consistent name; the unused seed is overwritten before use. */
                entry_reg[eb][argregs[p]] = mkVar(nm, cw);
                entry_reg[eb][xmmregs[p]] = mkVar(nm, cw);
            }
        }
    }

    /* Iterate: execute all blocks, then for each block with multiple preds whose
     * predecessor reg_out differ for a live register, introduce a temp at the
     * join and assign it in each predecessor. We do a single materialization
     * pass driven by liveness — sufficient for /Od where loop-carried values are
     * stack slots, not registers. */
    std::set<std::string> phi_temps;

    struct PhiNeed { int blk; Reg reg; std::string temp; };
    std::vector<PhiNeed> phi_needs;
    /* HIGH-lane (bits[127:64]) phis for a loop-carried 2x64 packed accumulator
     * (`xorps acc,acc; paddq acc,x` int64-sum reduction): the lo lane rides the
     * normal regfile phi; this carries the hi lane in lock-step so simd_src_lanes
     * sees both and the reduction is not dropped. */
    std::vector<PhiNeed> phi_needs_hi;
    /* Packed-INT lane phis (lanes 1,2,3) for a loop-carried 4x32 packed accumulator
     * (`xorps acc,acc; paddd acc,x` int32-sum reduction, isum): lane 0 rides the
     * normal regfile phi (phi_of[key]); these three carry lanes 1..3 in lock-step so
     * the 4-lane paddd is not dropped, then the psrldq/movd horizontal reduce sums
     * them. `lane` is 1, 2 or 3. */
    struct PhiNeedLane { int blk; Reg reg; int lane; std::string temp; };
    std::vector<PhiNeedLane> phi_needs_ilane;

    /* Decide which (join block, register) pairs require a materialized temp and
     * seed entry_reg accordingly. Statements are NOT injected here (they would be
     * wiped by the re-exec); inject_phis() appends them after the final exec. */
    void plan_phis() {
        compute_reg_liveness();
        phi_needs.clear();
        for (auto& b : blocks) {
            if (b.pred.size() < 2) continue;
            for (int r = R_RAX; r < R_RIP; ++r) {
                if (r == R_RSP || r == R_RBP || r == R_RIP) continue;
                if (!reg_live_in[b.id][(Reg)r]) continue;
                ExprP first = nullptr; bool diff = false, any = false;
                for (int p : b.pred) {
                    ExprP po = blocks[p].reg_out[r];
                    if (!po) { diff = true; continue; }
                    any = true;
                    if (!first) first = po;
                    else if (!exprEqual(first, po)) diff = true;
                }
                if (any && diff) {
                    std::string tn = "t" + std::to_string(++temp_seq);
                    phi_temps.insert(tn);
                    var_width[tn] = 8;
                    entry_reg[b.id][r] = mkVar(tn, 8);
                    phi_needs.push_back({b.id, (Reg)r, tn});
                } else if (any && first) {
                    /* all predecessors agree on the value of this live register:
                     * propagate it directly into the join block so the value is
                     * available there (e.g. a return value set in every arm).
                     * No temp is needed since there is no disagreement. */
                    entry_reg[b.id][r] = clone(first);
                }
            }
        }
    }

    /* After the final exec pass, append `temp = <pred reg_out>` to each pred.
     *
     * The copies destined for one predecessor are SIMULTANEOUS (SSA phi semantics).
     * Emitting them in arbitrary order corrupts a value another copy still needs:
     * the canonical victim is a loop latch carrying induction var i (`ti = i+1`) AND
     * an accumulator that reads i (`ta = f(a[i])`). Write ti first and ta then reads
     * the post-increment index — the off-by-one / wrong-element bug across every /O2
     * loop. So we (1) sequentialize per predecessor: a copy that READS another copy's
     * temp is emitted BEFORE that temp is overwritten (cycles broken with a save);
     * and (2) after emitting `temp = E`, rebind any occurrence of the exact
     * expression E in this block's terminator (the loop-exit test / returned value /
     * switch selector — all evaluated AFTER the copies) to `temp`, since E was built
     * from the pre-copy induction value and would otherwise re-read the just-bumped
     * variable (`i+1` after `i=i+1`). */
    struct PhiCopy { std::string temp; ExprP match; ExprP rhs; int w; };
    void inject_phis() {
        std::map<int, std::vector<PhiCopy>> per_pred;
        for (auto& nd : phi_needs) {
            int maxw = 4;
            for (int p : blocks[nd.blk].pred) {
                ExprP po = blocks[p].reg_out[nd.reg];
                if (po && po->width > maxw) maxw = po->width;
            }
            int tw = maxw >= 8 ? 8 : 4;
            if (maxw < 8) var_width[nd.temp] = 4;
            for (int p : blocks[nd.blk].pred) {
                ExprP po = blocks[p].reg_out[nd.reg];
                if (!po) continue;
                /* if predecessor already produces the temp (self-assign), skip */
                if (po->kind == EK::Var && po->name == nd.temp) continue;
                per_pred[p].push_back({nd.temp, clone(po), truncate(po, tw), tw});
            }
        }
        /* HI-lane phi copies (2x64 packed accumulator): same per-pred injection from
         * reg_out_hi, always 8-byte. Rides the same sequentialization/rebind as the
         * lo lane below (the accumulator is not in the loop terminator, so no snapshot
         * fires — a plain `hi = hi + x_hi` latch copy). */
        for (auto& nd : phi_needs_hi) {
            var_width[nd.temp] = 8;
            for (int p : blocks[nd.blk].pred) {
                ExprP po = blocks[p].reg_out_hi[nd.reg];
                if (!po) continue;
                if (po->kind == EK::Var && po->name == nd.temp) continue;
                per_pred[p].push_back({nd.temp, clone(po), truncate(po, 8), 8});
            }
        }
        /* INT-lane phi copies (lanes 1..3 of a 4x32 packed accumulator): per-pred
         * injection from reg_out_i[reg][lane], always 4-byte. The preheader copy
         * seeds `tL = 0` (xorps); the latch copy is `tL = tL + load_L`. */
        for (auto& nd : phi_needs_ilane) {
            var_width[nd.temp] = 4;
            for (int p : blocks[nd.blk].pred) {
                ExprP po = blocks[p].reg_out_i[nd.reg][nd.lane];
                if (!po) continue;
                if (po->kind == EK::Var && po->name == nd.temp) continue;
                per_pred[p].push_back({nd.temp, clone(po), truncate(po, 4), 4});
            }
        }
        /* Self-referential copies whose `match` must be rebound to `temp` — done in
         * a POST-PASS so it is order-independent: in NESTED loops an OUTER-loop phi
         * copy `t16 = t6 + last` is emitted into a block that is a single-pred
         * successor of the INNER latch (`t6 = t6 + last`); if the inner rebind runs
         * before the outer copy exists it misses it (box_blur_h double-counted the
         * row total). Collect all, apply after every copy is materialized. */
        struct Rebind { int p; ExprP match; ExprP tv; };
        std::vector<Rebind> rebinds;
        /* SAVE-then-ADVANCE-then-COMPARE snapshots (circular-list walk): {p, temp, t_old}. */
        std::vector<std::pair<int, std::pair<std::string, ExprP>>> snap_rebinds;
        for (auto& kv : per_pred) {
            int p = kv.first;
            std::vector<PhiCopy>& cps = kv.second;
            int n = (int)cps.size();
            std::vector<bool> done(n, false);
            for (int emitted = 0; emitted < n; ++emitted) {
                int pick = -1;
                for (int i = 0; i < n && pick < 0; ++i) {
                    if (done[i]) continue;
                    bool blocked = false;   /* some unemitted copy still needs cps[i].temp's old value */
                    for (int j = 0; j < n; ++j) {
                        if (j == i || done[j]) continue;
                        if (cps[j].temp != cps[i].temp && reads_named_var(cps[j].rhs, cps[i].temp)) { blocked = true; break; }
                    }
                    if (!blocked) pick = i;
                }
                if (pick < 0) {
                    /* genuine cycle (register swap): save one temp to a fresh local
                     * and redirect the others' reads of it, breaking the cycle. */
                    for (int i = 0; i < n; ++i) if (!done[i]) { pick = i; break; }
                    std::string sv = "t" + std::to_string(++temp_seq);
                    var_width[sv] = cps[pick].w;
                    Stmt s; s.kind = SK::Assign;
                    s.lhs = mkVar(sv, cps[pick].w);
                    s.rhs = mkVar(cps[pick].temp, cps[pick].w);
                    blocks[p].stmts.push_back(std::move(s));
                    ExprP svv = mkVar(sv, cps[pick].w);
                    for (int j = 0; j < n; ++j)
                        if (!done[j] && j != pick)
                            cps[j].rhs = subst_named_var(cps[j].rhs, cps[pick].temp, svv);
                }
                /* SAVE-then-ADVANCE-then-COMPARE (circular list walk `p = p->next`
                 * until `head == p`): `mov rax,r8; mov r8,[r8+off]; cmp rax,r8`. The
                 * terminator compares the PRE-advance value (bare `temp`, the saved
                 * `rax`) against `match` (the advanced value). Emitting `temp = match`
                 * then reading bare `temp` in the terminator reads the NEW value, and
                 * the induction-style `match -> temp` rebind collapses BOTH operands
                 * to `temp` (`t2 == t2`, so the walk runs exactly once). Detect a bare
                 * `temp` reference in the terminator (i.e. OUTSIDE every `match`
                 * subtree) and instead SNAPSHOT the old value into a fresh temp BEFORE
                 * the copy, rebinding every `temp` in the terminator to that snapshot. */
                bool self_ref = reads_named_var(cps[pick].match, cps[pick].temp);
                /* The snapshot is needed exactly when a terminator compares the OLD
                 * temp against the NEW value — i.e. it references BOTH bare `temp`
                 * (outside `match`) AND the `match` subtree. That distinguishes the
                 * `old != old->next` list-walk (snapshot) from a plain
                 * `do{p=p->next;}while(p)` (terminator has bare temp but NOT match, so
                 * it legitimately wants the advanced value — no snapshot). */
                bool snap_needed = false;
                {
                    const std::string& tn = cps[pick].temp;
                    ExprP mt = cps[pick].match;
                    auto needs = [&](const ExprP& e) -> bool {
                        if (!e) return false;
                        /* After removing the ADVANCED value (`match`) subtree, if the
                         * terminator STILL reads the bare temp it wants the PRE-advance
                         * value -> snapshot. This covers BOTH `old != old->next` (bare
                         * temp AND match present) AND `snapshot; advance; cmp snap, CONST`
                         * where the match subtree is ABSENT (count_bit: `mov r8,ecx; shr
                         * ecx; cmp r8,2` -> the exit test compares the pre-shift value to
                         * a constant). A terminator using the ADVANCED value renders AS
                         * the match subtree, so stripping removes the temp -> no snapshot
                         * (`do{p=p->next;}while(p)`, `do{i++;}while(i<n)`). */
                        ExprP stripped = subst_subtree(e, mt, mkConst(0, cps[pick].w));
                        return reads_named_var(stripped, tn);
                    };
                    if (needs(blocks[p].cond) || needs(blocks[p].ret_value)) snap_needed = true;
                    if (!snap_needed)
                        for (auto& sb : blocks)
                            if (sb.pred.size()==1 && sb.pred[0]==p &&
                                (needs(sb.cond) || needs(sb.ret_value))) { snap_needed = true; break; }
                    if (snap_needed) {
                        std::string sv = "t" + std::to_string(++temp_seq);
                        var_width[sv] = cps[pick].w;
                        Stmt s0; s0.kind = SK::Assign; s0.lhs = mkVar(sv, cps[pick].w);
                        s0.rhs = mkVar(cps[pick].temp, cps[pick].w);
                        blocks[p].stmts.push_back(std::move(s0));   /* t_old = temp (before the copy) */
                        snap_rebinds.push_back({p, {cps[pick].temp, mkVar(sv, cps[pick].w)}});
                    }
                }
                Stmt s; s.kind = SK::Assign;
                s.lhs = mkVar(cps[pick].temp, cps[pick].w);
                s.rhs = cps[pick].rhs;
                blocks[p].stmts.push_back(std::move(s));
                /* Only rebind the terminator when the back-edge value is SELF-
                 * referential (`temp = f(temp, ...)` — an induction step or a
                 * loop-carried accumulator). That is exactly when re-reading the
                 * just-overwritten variable corrupts the exit test / return value
                 * (`i+1` after `i=i+1`). A plain copy/merge has no such hazard, so
                 * leaving it untouched avoids misfiring on ordinary diamonds. */
                /* Only rebind when the back-edge value is SELF-referential
                 * (`temp = f(temp, ...)` — an induction step or loop-carried
                 * accumulator). That is exactly when re-reading the just-overwritten
                 * variable corrupts the exit test / return value / reduction tail. A
                 * plain copy/merge has no such hazard. Collect now; apply post-pass. */
                if (self_ref && !snap_needed)
                    rebinds.push_back({p, clone(cps[pick].match),
                                       mkVar(cps[pick].temp, cps[pick].w)});
                done[pick] = true;
            }
        }
        /* POST-PASS rebind (after every copy is emitted, so nested-loop outer copies
         * already exist in the single-pred successors). For each `temp = match`,
         * replace `match` with `temp` in p's terminator AND in any block whose SOLE
         * predecessor is p (the loop-EXIT / reduction-tail block): it inherited p's
         * PRE-copy reg_out value `match`, now live in `temp`. The phi target (loop
         * header) has >1 pred so it is excluded. Fixes vm_peephole `return w+1`,
         * convex_hull, and box_blur_h's reduction-tail double-count. */
        /* The stale `match` value propagates through a CHAIN of single-pred blocks
         * (loop-exit `cmp` -> `nop` -> phi-copies-into-the-remainder), so rebind the
         * whole transitive single-pred successor chain, not just p's DIRECT successor.
         * (arr_variance's unrolled sum: the remainder-loop phi copies live two blocks
         * past the loop, so `sum += a[i..i+3]; i+=4` was emitted a SECOND time there,
         * over-summing a whole group / reading out of bounds.) */
        auto single_pred_chain = [&](int p) -> std::vector<int> {
            std::vector<int> out; std::set<int> seen{p};
            for (bool grew = true; grew; ) {
                grew = false;
                for (auto& s : blocks)
                    if (!seen.count(s.id) && s.pred.size()==1 && seen.count(s.pred[0]))
                        { out.push_back(s.id); seen.insert(s.id); grew = true; }
            }
            return out;
        };
        for (auto& rb : rebinds) {
            int p = rb.p;
            blocks[p].cond       = subst_subtree(blocks[p].cond,       rb.match, rb.tv);
            blocks[p].ret_value  = subst_subtree(blocks[p].ret_value,  rb.match, rb.tv);
            blocks[p].switch_var = subst_subtree(blocks[p].switch_var, rb.match, rb.tv);
            for (int cid : single_pred_chain(p)) {
                Block& s = blocks[cid];
                s.cond       = subst_subtree(s.cond,       rb.match, rb.tv);
                s.ret_value  = subst_subtree(s.ret_value,  rb.match, rb.tv);
                s.switch_var = subst_subtree(s.switch_var, rb.match, rb.tv);
                for (auto& st : s.stmts) {
                    if (st.rhs) st.rhs = subst_subtree(st.rhs, rb.match, rb.tv);
                    if (st.lhs && st.lhs->kind == EK::Mem && st.lhs->a)
                        st.lhs->a = subst_subtree(st.lhs->a, rb.match, rb.tv);
                }
            }
        }
        /* SAVE-then-compare snapshots: replace EVERY `temp` in the terminator with the
         * pre-copy snapshot `t_old` — both the bare (saved) operand AND the one inside
         * `match` — so `t2 != *(t2+off)` becomes `t_old != *(t_old+off)`. */
        for (auto& sr : snap_rebinds) {
            int p = sr.first;
            const std::string& tn = sr.second.first;
            const ExprP& tv = sr.second.second;
            blocks[p].cond       = subst_named_var(blocks[p].cond,       tn, tv);
            blocks[p].ret_value  = subst_named_var(blocks[p].ret_value,  tn, tv);
            blocks[p].switch_var = subst_named_var(blocks[p].switch_var, tn, tv);
            for (int cid : single_pred_chain(p)) {
                Block& s = blocks[cid];
                s.cond       = subst_named_var(s.cond,       tn, tv);
                s.ret_value  = subst_named_var(s.ret_value,  tn, tv);
                s.switch_var = subst_named_var(s.switch_var, tn, tv);
            }
        }
    }

    /* Iterative cross-block register dataflow to a fixpoint.
     *
     * The old plan_phis() only touched MERGE blocks, so a value carried in a
     * register across a straight-line chain of single-predecessor blocks — a
     * this/context pointer in a callee-saved register, a loop induction variable,
     * a base pointer — was never propagated and collapsed to the `0` fallback in
     * reg_value(). That is THE dominant failure on real binaries (`[0 + 0xba8]`,
     * `t = 1; if (1 < N)`, `call f(0)`).
     *
     * Here we propagate each live register's value through EVERY block: a single
     * predecessor flows its exit value straight in; multiple predecessors that
     * disagree get a materialized phi-temp (this is also exactly how a loop
     * induction variable is recovered — the loop header is a merge of the forward
     * edge and the back edge). We iterate (Gauss-Seidel, in block/address order so
     * forward flow converges in ~1 pass) until entry_reg stops changing. */
    void compute_entry_regs_fixpoint() {
        static const bool no_loopvec = std::getenv("DS_NO_LOOPVEC") != nullptr;
        compute_reg_liveness();
        phi_temps.clear();
        phi_needs.clear();
        phi_needs_hi.clear();
        phi_needs_ilane.clear();
        std::map<long long, std::string> phi_of;    /* blk*64+reg -> lo-lane temp name */
        std::map<long long, std::string> phi_of_hi; /* blk*64+reg -> hi-lane temp name */
        std::map<long long, std::string> phi_of_ilane; /* (blk*64+reg)*4+lane -> int-lane temp */
        int eb = entry_block();
        /* PRE-SEED LOOP-HEADER PHIS. At a loop header a register that is live-in AND
         * modified in the loop body carries a different value on the back edge than
         * on entry, so it is loop-carried and needs a phi. Materializing it UP FRONT
         * (before the back-edge value first appears in the fixpoint) stops an
         * induction variable from UNROLLING into a `(0+4)+4+...` cascade: instead it
         * becomes a clean `t = seed; ... t = t + step;`. (Reducible loops only — what
         * find_loops detected; irreducible giants are still imperfect.) */
        for (auto& lp : loops) {
            int h = lp.header;
            if (h < 0 || h >= (int)entry_reg.size()) continue;
            for (int r = R_RAX; r < R_RIP; ++r) {
                if (r == R_RSP || r == R_RBP || r == R_RIP) continue;
                if (h < (int)reg_live_in.size() && !reg_live_in[h][(Reg)r]) continue;
                long long key = (long long)h * 64 + r;
                if (phi_of.count(key)) continue;
                bool modified = false;
                for (int blk : lp.body) {
                    if (blk < 0 || blk >= (int)blocks.size()) continue;
                    for (int ii : blocks[blk].insn_idx) {
                        const cs_x86& x = insns[ii].x86;
                        for (int o = 0; o < x.op_count && o < 4; ++o) {
                            if (x.operands[o].type == X86_OP_REG &&
                                (x.operands[o].access & CS_AC_WRITE)) {
                                Reg wr; int ww; map_reg(x.operands[o].reg, wr, ww);
                                if (wr == (Reg)r) { modified = true; break; }
                            }
                        }
                        if (modified) break;
                    }
                    if (modified) break;
                }
                if (!modified) continue;
                std::string tn = "t" + std::to_string(++temp_seq);
                phi_temps.insert(tn); var_width[tn] = 8;
                phi_of[key] = tn;
                phi_needs.push_back({h, (Reg)r, tn});
            }
        }
        /* Converges in O(loop-nesting-depth) iterations via Gauss-Seidel in
         * address order; the early-break handles the common case. The cap is a
         * backstop for pathological CFGs (kept low so huge functions stay fast). */
        for (int iter = 0; iter < 12; ++iter) {
            bool changed = false;
            for (auto& b : blocks) {
                if ((int)b.id != eb &&
                    b.id < (int)entry_reg.size()) {
                    for (int r = R_RAX; r < R_RIP; ++r) {
                        if (r == R_RSP || r == R_RIP) continue;
                        if (b.id < (int)reg_live_in.size() &&
                            !reg_live_in[b.id][(Reg)r]) continue;
                        long long key = (long long)b.id * 64 + r;
                        ExprP newval;
                        auto pit = phi_of.find(key);
                        if (pit != phi_of.end()) {
                            newval = mkVar(pit->second, 8);    /* keep existing phi */
                        } else if (b.pred.size() == 1) {
                            ExprP po = blocks[b.pred[0]].reg_out[r];
                            if (po) newval = clone(po);        /* propagate straight */
                        } else {
                            ExprP first = nullptr; bool diff = false, any = false;
                            for (int p : b.pred) {
                                ExprP po = blocks[p].reg_out[r];
                                /* skip edges with no tracked value AND edges that
                                 * carry only a lost-context `ctx_<reg>` placeholder:
                                 * a known concrete value on another edge is the real
                                 * one (a callee-saved const reloaded on each path),
                                 * so it should win the merge instead of being
                                 * tainted into a phi or a `ctx_` leak. */
                                if (!po || is_ctx_value(po)) continue;
                                any = true;
                                if (!first) first = po;
                                else if (!exprEqual(first, po)) diff = true;
                            }
                            if (any && diff) {
                                std::string tn = "t" + std::to_string(++temp_seq);
                                phi_temps.insert(tn); var_width[tn] = 8;
                                phi_of[key] = tn;
                                phi_needs.push_back({(int)b.id, (Reg)r, tn});
                                newval = mkVar(tn, 8);
                            } else if (any) {
                                newval = clone(first);
                            }
                        }
                        ExprP& cur = entry_reg[b.id][r];
                        bool same = ((bool)cur == (bool)newval) &&
                                    (!cur || exprEqual(cur, newval));
                        if (!same) { cur = newval; changed = true; }

                        /* High-lane (packed-SIMD) merge for XMM regs: propagate the
                         * lane only when all predecessors that have one agree (the
                         * loop-invariant broadcast case); no phi materialization. A
                         * disagreement or a write in the block leaves it unknown. */
                        if (is_xmm((Reg)r) && b.id < (int)entry_reg_hi.size()) {
                            ExprP hv = nullptr; bool hdiff = false, hany = false;
                            for (int p : b.pred) {
                                if (p < 0 || p >= (int)blocks.size()) continue;
                                ExprP po = blocks[p].reg_out_hi[r];
                                if (!po || expr_has_in_backstop(po)) continue;
                                hany = true;
                                if (!hv) hv = po;
                                else if (!exprEqual(hv, po)) hdiff = true;
                            }
                            ExprP nh;
                            auto hpit = phi_of_hi.find(key);
                            if (hpit != phi_of_hi.end()) {
                                nh = mkVar(hpit->second, 8);        /* keep existing hi phi */
                            } else if (hany && hdiff && phi_of.count(key)) {
                                /* loop-carried 2x64 packed accumulator (its LO lane is
                                 * already phi'd) whose HI lane disagrees across preds ->
                                 * materialize a hi-lane phi so both lanes ride the loop. */
                                std::string tn = "t" + std::to_string(++temp_seq);
                                phi_temps.insert(tn); var_width[tn] = 8;
                                phi_of_hi[key] = tn;
                                phi_needs_hi.push_back({(int)b.id, (Reg)r, tn});
                                nh = mkVar(tn, 8);
                            } else {
                                nh = (hany && !hdiff) ? clone(hv) : nullptr;
                            }
                            ExprP& curh = entry_reg_hi[b.id][r];
                            bool hsame = ((bool)curh == (bool)nh) &&
                                         (!curh || exprEqual(curh, nh));
                            if (!hsame) { curh = nh; changed = true; }
                        }

                        /* Vec-load-address merge for XMM regs (same agreement rule
                         * as the hi-lane): the "this wide reg was loaded from addr X"
                         * fact reaches a successor only when every predecessor that
                         * carries one agrees on the exact address. A disagreement, a
                         * backstop-tainted address, or any predecessor that lacks the
                         * fact (e.g. one that overwrote the reg -> reg_out_vla cleared)
                         * drops it, so a stale source can never leak into the store. */
                        if (is_xmm((Reg)r) && b.id < (int)entry_vla.size()) {
                            ExprP av = nullptr; bool adiff = false, aany = false;
                            for (int p : b.pred) {
                                if (p < 0 || p >= (int)blocks.size()) continue;
                                /* an UNREACHABLE dead block (no preds, not the entry) carries no
                                 * real dataflow -- capstone decoded it (alignment/dead tail) but
                                 * nothing reaches it, yet it lists a fall-through succ, so it
                                 * appears as a pred here. Skipping it (vs failing the strict
                                 * merge) lets a genuine cross-block vector fact survive. */
                                if (blocks[p].pred.empty() && p != eb) continue;
                                ExprP po = blocks[p].reg_out_vla[r];
                                if (!po) {
                                    /* OPTIMISTIC LOOP BOOTSTRAP: a back-edge pred (a loop
                                     * latch -- later in address order) has no reg_out on the
                                     * FIRST fixpoint pass because its block has not run yet.
                                     * Skip it so a loop-INVARIANT load set in the preheader can
                                     * seed the loop body; iter>=1 then REQUIRES it (a clobbering
                                     * loop's latch stays null -> the value is lowered), so the
                                     * converged state is sound. Without this, memcpy/memset only
                                     * ever fired on straight-line/unrolled code, never true
                                     * loops. DS_NO_LOOPVEC restores the old conservative merge. */
                                    if (iter == 0 && p > (int)b.id && !no_loopvec) continue;
                                    aany = false; break;
                                }
                                if (expr_has_in_backstop(po)) { aany = false; break; }
                                aany = true;
                                if (!av) av = po;
                                else if (!exprEqual(av, po)) adiff = true;
                            }
                            ExprP na = (aany && !adiff) ? clone(av) : nullptr;
                            ExprP& cura = entry_vla[b.id][r];
                            bool asame = ((bool)cura == (bool)na) &&
                                         (!cura || exprEqual(cura, na));
                            if (!asame) { cura = na; changed = true; }
                        }

                        /* Vec-FILL merge for XMM regs (same all-preds-agree rule as vla,
                         * but on both value and element size): the "this wide reg is a
                         * broadcast/zero of value V, element size E" fact reaches a
                         * successor only when every predecessor carrying one agrees on
                         * both. Any disagreement or a predecessor lacking it drops it. */
                        if (is_xmm((Reg)r) && b.id < (int)entry_vfill.size()) {
                            ExprP fvv = nullptr; int fesz = 0;
                            bool fdiff2 = false, fany2 = false;
                            for (int p : b.pred) {
                                if (p < 0 || p >= (int)blocks.size()) continue;
                                if (blocks[p].pred.empty() && p != eb) continue;   /* skip dead pred */
                                ExprP po = blocks[p].reg_out_vfill[r];
                                int pe = blocks[p].reg_out_vfill_esz[r];
                                if (!po || pe == 0) {
                                    /* optimistic loop bootstrap (see the vla merge): skip a
                                     * not-yet-run back-edge latch on iter 0 so a loop-invariant
                                     * FILL set before the loop seeds the store loop body. */
                                    if (iter == 0 && p > (int)b.id && !no_loopvec) continue;
                                    fany2 = false; break;
                                }
                                if (expr_has_in_backstop(po)) { fany2 = false; break; }
                                fany2 = true;
                                if (!fvv) { fvv = po; fesz = pe; }
                                else if (!exprEqual(fvv, po) || fesz != pe) fdiff2 = true;
                            }
                            ExprP nf = (fany2 && !fdiff2) ? clone(fvv) : nullptr;
                            int   ne = (fany2 && !fdiff2) ? fesz : 0;
                            ExprP& curf = entry_vfill[b.id][r];
                            int&   cure = entry_vfill_esz[b.id][r];
                            bool fsame = ((bool)curf == (bool)nf) &&
                                         (!curf || (exprEqual(curf, nf) && cure == ne));
                            if (!fsame) { curf = nf; cure = ne; changed = true; }
                        }

                        /* Packed-FLOAT 4-lane merge for XMM regs: same agreement
                         * rule — a loop-invariant broadcast (`shufps xmm,xmm,0` in a
                         * preheader) reaches the loop body only if every predecessor
                         * carrying lanes agrees on all four. Any disagreement or a
                         * lane-less predecessor drops it (the block recomputes). */
                        if (is_xmm((Reg)r) && b.id < (int)entry_xmm_f.size()) {
                            ExprP fv[4] = {nullptr,nullptr,nullptr,nullptr};
                            bool fdiff = false, fany = false, freal = false;
                            for (int p : b.pred) {
                                if (p < 0 || p >= (int)blocks.size()) continue;
                                const Block& pb = blocks[p];
                                if (!pb.reg_out_f[r][0]) continue;   /* no lanes */
                                bool bad = false;
                                for (int L = 0; L < 4; ++L)
                                    if (!pb.reg_out_f[r][L] || expr_has_in_backstop(pb.reg_out_f[r][L])) { bad = true; break; }
                                if (bad) continue;
                                if (!fany) {
                                    for (int L = 0; L < 4; ++L) fv[L] = pb.reg_out_f[r][L];
                                    freal = pb.reg_out_f_real[r];
                                    fany = true;
                                } else {
                                    for (int L = 0; L < 4; ++L)
                                        if (!exprEqual(fv[L], pb.reg_out_f[r][L])) { fdiff = true; break; }
                                    if (pb.reg_out_f_real[r] != freal) fdiff = true;
                                }
                            }
                            bool keep = fany && !fdiff;
                            auto& cf = entry_xmm_f[b.id][r];
                            bool fsame = ((bool)cf[0] == (bool)(keep ? fv[0] : nullptr));
                            if (fsame && keep)
                                for (int L = 0; L < 4; ++L)
                                    if (((bool)cf[L] != (bool)fv[L]) || (cf[L] && !exprEqual(cf[L], fv[L]))) { fsame = false; break; }
                            if (!fsame) {
                                for (int L = 0; L < 4; ++L) cf[L] = keep && fv[L] ? clone(fv[L]) : nullptr;
                                entry_xmm_f_real[b.id][r] = keep && freal;
                                changed = true;
                            }
                        }
                        /* Packed-INT 4-lane merge (same agreement rule) — the guard-block
                         * broadcast reaches the SSE body when every predecessor agrees. */
                        if (is_xmm((Reg)r) && b.id < (int)entry_xmm_i.size()) {
                            ExprP iv[4] = {nullptr,nullptr,nullptr,nullptr};
                            bool idiff = false, iany = false, ireal = false;
                            for (int p : b.pred) {
                                if (p < 0 || p >= (int)blocks.size()) continue;
                                const Block& pb = blocks[p];
                                if (!pb.reg_out_i[r][0]) continue;
                                bool bad = false;
                                for (int L = 0; L < 4; ++L)
                                    if (!pb.reg_out_i[r][L] || expr_has_in_backstop(pb.reg_out_i[r][L])) { bad = true; break; }
                                if (bad) continue;
                                if (!iany) {
                                    for (int L = 0; L < 4; ++L) iv[L] = pb.reg_out_i[r][L];
                                    ireal = pb.reg_out_i_real[r]; iany = true;
                                } else {
                                    for (int L = 0; L < 4; ++L)
                                        if (!exprEqual(iv[L], pb.reg_out_i[r][L])) { idiff = true; break; }
                                    if (pb.reg_out_i_real[r] != ireal) idiff = true;
                                }
                            }
                            auto& ci = entry_xmm_i[b.id][r];
                            /* loop-carried 4x32 packed accumulator (`xorps acc,acc;
                             * paddd acc,x` int-sum reduction, isum) whose lanes disagree
                             * across preds and whose LANE 0 already rides the scalar
                             * regfile phi -> phi lanes 1..3 in lock-step (lane 0 reuses
                             * phi_of[key]) so the 4-lane paddd is not dropped. */
                            bool ihavephi = (phi_of_ilane.count(((long long)key)*4+1) != 0);
                            if (iany && (idiff || ihavephi) && phi_of.count(key)) {
                                ExprP nl[4];
                                nl[0] = mkVar(phi_of[key], 4);
                                for (int L = 1; L < 4; ++L) {
                                    long long lk = ((long long)key)*4 + L;
                                    auto it = phi_of_ilane.find(lk);
                                    std::string tn;
                                    if (it != phi_of_ilane.end()) tn = it->second;
                                    else {
                                        tn = "t" + std::to_string(++temp_seq);
                                        phi_temps.insert(tn); var_width[tn] = 4;
                                        phi_of_ilane[lk] = tn;
                                        phi_needs_ilane.push_back({(int)b.id, (Reg)r, L, tn});
                                    }
                                    nl[L] = mkVar(tn, 4);
                                }
                                bool psame = true;
                                for (int L = 0; L < 4; ++L)
                                    if (((bool)ci[L] != (bool)nl[L]) || (ci[L] && !exprEqual(ci[L], nl[L]))) { psame = false; break; }
                                if (!psame) {
                                    for (int L = 0; L < 4; ++L) ci[L] = nl[L];
                                    entry_xmm_i_real[b.id][r] = true;
                                    changed = true;
                                }
                            } else {
                                bool keepi = iany && !idiff;
                                bool isame = ((bool)ci[0] == (bool)(keepi ? iv[0] : nullptr));
                                if (isame && keepi)
                                    for (int L = 0; L < 4; ++L)
                                        if (((bool)ci[L] != (bool)iv[L]) || (ci[L] && !exprEqual(ci[L], iv[L]))) { isame = false; break; }
                                if (!isame) {
                                    for (int L = 0; L < 4; ++L) ci[L] = keepi && iv[L] ? clone(iv[L]) : nullptr;
                                    entry_xmm_i_real[b.id][r] = keepi && ireal;
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                b.stmts.clear();
                exec_block(b);
            }
            if (!changed) break;
        }
    }

    void compute_reg_liveness(bool include_call_arg_uses = true) {
        size_t n = blocks.size();
        reg_live_in.assign(n, {});
        std::vector<std::array<bool, R_COUNT>> use(n), def(n), out(n);
        for (size_t i = 0; i < n; ++i) { use[i]={}; def[i]={}; out[i]={}; }
        for (auto& b : blocks) {
            std::array<bool, R_COUNT> defined{};
            auto useReg = [&](Reg r){ if (r>R_NONE && r<R_COUNT && !defined[r]) use[b.id][r]=true; };
            for (size_t k = 0; k < b.insn_idx.size(); ++k) {
                const Insn& in = insns[b.insn_idx[k]];
                /* a dropped stack-cookie call neither uses nor defines anything in
                 * the recovered C — counting its implicit rax-def would suppress
                 * the return-value phi at the epilogue merge. */
                if (cookie_call_addrs.count(in.addr)) continue;
                if (chkstk_call_addrs.count(in.addr)) continue;
                /* approximate: reads then writes per instruction operands */
                const cs_x86& x = in.x86;
                /* self-zeroing idiom (`xor r,r` / `sub r,r`) is a pure DEFINE to
                 * 0 — its operand[1] "read" is not a use of the incoming value.
                 * Counting it makes a zeroed scratch reg upward-exposed, which
                 * both leaks an in_<REG> backstop and (via finalize_params'
                 * entry-liveness) invents a phantom parameter on /O2 loops. */
                bool self_zero = (in.id==X86_INS_XOR || in.id==X86_INS_SUB) &&
                                 x.op_count==2 && x.operands[0].type==X86_OP_REG &&
                                 x.operands[1].type==X86_OP_REG &&
                                 x.operands[0].reg==x.operands[1].reg;
                for (int o = 0; o < x.op_count && o < 8; ++o) {
                    const cs_x86_op& op = x.operands[o];
                    if (op.type == X86_OP_REG) {
                        Reg r; int w; map_reg(op.reg, r, w);
                        /* Capstone leaves op.access == 0 (UNCLASSIFIED) on some
                         * read operands — notably the register operand of
                         * `test r/m, al` / `cmp` in this build, where AL is
                         * genuinely READ but no CS_AC_READ is set. A missed use
                         * kept a sub-register constant (`mov al,2`) from being
                         * carried across the block boundary, so a later
                         * `test [mem], al` read the entry-value backstop
                         * (`in_RAX`) instead of 2. The exec/lift path reads every
                         * operand regardless of access flags, so liveness must
                         * agree: an UNCLASSIFIED operand is a READ (over-
                         * approximating a use is liveness-safe — it only keeps a
                         * value live, never drops a real one). A true write-only
                         * operand always carries CS_AC_WRITE (nonzero), so it is
                         * unaffected. */
                        bool op_reads = (op.access & CS_AC_READ) || op.access == 0;
                        if (op_reads && !self_zero) useReg(r);
                    } else if (op.type == X86_OP_MEM) {
                        Reg bb=R_NONE, ix=R_NONE; int t;
                        if (op.mem.base!=X86_REG_INVALID) map_reg(op.mem.base,bb,t);
                        if (op.mem.index!=X86_REG_INVALID) map_reg(op.mem.index,ix,t);
                        useReg(bb); useReg(ix);
                    }
                }
                /* a cmovcc conditionally KEEPS its destination, so the dest's
                 * incoming value stays live (the lifter models it as the `else`
                 * arm of a ternary). capstone often reports the dest write-only,
                 * which would wrongly kill the value before the merge -> ctx_ leak. */
                if (cmovcc_of(in.id) != CC::NONE && x.op_count >= 1 &&
                    x.operands[0].type == X86_OP_REG) {
                    Reg r; int w; map_reg(x.operands[0].reg, r, w);
                    useReg(r);
                }
                /* implicit-READ opcodes: capstone lists NO operand for the rdx:rax
                 * dividend of div/idiv, the rax multiplicand of a 1-operand mul/imul,
                 * or the eax(leaf)/ecx(subleaf) inputs of cpuid/xgetbv. Those
                 * upward-exposed reads were invisible to liveness, so a value set in a
                 * PREDECESSOR block (`mov eax,0x24; ...; cpuid`, a magic-division
                 * `mul`, an `idiv` dividend) was never carried across the boundary and
                 * leaked as `in_RAX`. Mirrors the implicit-DEF switch below. */
                switch (in.id) {
                    case X86_INS_DIV: case X86_INS_IDIV:
                        useReg(R_RAX);
                        if (x.op_count >= 1 && x.operands[0].size > 1) useReg(R_RDX);
                        break;
                    case X86_INS_MUL: case X86_INS_IMUL:
                        if (x.op_count <= 1) useReg(R_RAX);
                        break;
                    case X86_INS_CPUID:  useReg(R_RAX); useReg(R_RCX); break;
                    case X86_INS_XGETBV: useReg(R_RCX); break;
                    default: break;
                }
                for (int o = 0; o < x.op_count && o < 8; ++o) {
                    const cs_x86_op& op = x.operands[o];
                    if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE)) {
                        Reg r; int w; map_reg(op.reg, r, w);
                        if (r>R_NONE && r<R_COUNT) { defined[r]=true; def[b.id][r]=true; }
                    }
                }
                /* implicit-def opcodes: cdq/cqo/cwd sign-extend rax INTO rdx, and
                 * the 1-operand mul/div leave the result in rdx:rax. capstone lists
                 * no rdx operand, so without recording the def the following idiv's
                 * implicit rdx read (or `sub rax,rdx` of the signed-/2 idiom) looks
                 * upward-exposed and finalize_params invents a phantom rdx param
                 * (half_ll's bogus `long long a2`). Mirrors detect_reg_params. */
                switch (in.id) {
                    case X86_INS_CDQ: case X86_INS_CQO: case X86_INS_CWD:
                        defined[R_RDX]=true; def[b.id][R_RDX]=true; break;
                    case X86_INS_DIV:  case X86_INS_IDIV:
                    case X86_INS_MUL:  case X86_INS_IMUL:
                        if (x.op_count <= 1) { defined[R_RDX]=true; def[b.id][R_RDX]=true; }
                        break;
                    default: break;
                }
                if (in.is_call) {
                    /* A call CONSUMES its first `pc` integer-argument registers
                     * (rcx,rdx,r8,r9). capstone reports `call` with no register
                     * operands, so without marking these as upward-exposed USES the
                     * arg registers are never live-in to the call's block — and the
                     * cross-block fixpoint (gated on liveness) then refuses to carry
                     * an argument value defined in a PREDECESSOR block across the
                     * boundary. The classic victim: `mov rcx,[rbx+0x28]; test rcx,rcx;
                     * je .skip` (ends the block) then `call free` (separate block) —
                     * rcx collapsed to the `0` fallback -> free(0)/memcmp(0,0,n).
                     * Freshly-loaded args (`mov rcx,rbx; call`) survived only because
                     * the def was local to the call's own block. Use the SAME arity
                     * lift_call renders (sigtab param_count, else 4) so liveness and
                     * the emitted arg list agree exactly. */
                    int apc = 4;
                    if (in.has_branch_target && sigtab &&
                        sigtab->count(in.branch_target))
                        apc = sigtab->at(in.branch_target).param_count;
                    if (apc < 0) apc = 0;
                    if (apc > 4) apc = 4;
                    static const Reg aregs[4] = { R_RCX, R_RDX, R_R8, R_R9 };
                    /* The synthetic arg-use is for cross-block value propagation
                     * (free/memcmp). It must NOT feed parameter detection — an
                     * indirect call's pc=4 default would make r8/r9 look live-in
                     * and invent phantom params. finalize_params passes false. */
                    if (include_call_arg_uses)
                        for (int ai = 0; ai < apc; ++ai) useReg(aregs[ai]);
                    defined[R_RAX]=true; def[b.id][R_RAX]=true;
                }
            }
            if (b.ends_ret && used_return) {
                Reg rr = ret_is_float ? R_XMM0 : R_RAX;
                if (!defined[rr]) use[b.id][rr]=true;
            }
        }
        bool changed = true; int guard = 0;
        while (changed && guard++ < (int)(blocks.size()+4)) {
            changed = false;
            for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
                Block& b = *it;
                std::array<bool,R_COUNT> no{};
                for (int s : b.succ) for (int r=0;r<R_COUNT;++r) if (reg_live_in[s][r]) no[r]=true;
                if (b.ends_ret && used_return) no[ret_is_float ? R_XMM0 : R_RAX]=true;
                out[b.id]=no;
                for (int r=0;r<R_COUNT;++r) {
                    bool ni = use[b.id][r] || (no[r] && !def[b.id][r]);
                    if (reg_live_in[b.id][r]!=ni){reg_live_in[b.id][r]=ni;changed=true;}
                }
            }
        }
    }

    /* =================================================================== */
    /*  Rendering expressions to C text (precedence-aware, minimal parens)  */
    /* =================================================================== */

    /* A `(char*)` cast wrapping a +/- whose LEADING operand is already `(char*)` is a no-op:
     * pointer arithmetic on a char* is already char*. Such a cast renders transparently (its
     * inner Binary), so both prec() and render() must defer to the inner. Very common from
     * nested address building (`(char*)((char*)a1 + N)` -> `(char*)a1 + N`, ~1000+ on NullWare).
     * DS_NO_CASTCLEAN restores the redundant cast. */
    bool redundant_charptr_cast(const ExprP& e) {
        static const bool off = std::getenv("DS_NO_CASTCLEAN") != nullptr;
        if (off || !e || e->kind != EK::Cast || e->op != "(char*)" || !e->a) return false;
        if (e->a->kind != EK::Binary || (e->a->op != "+" && e->a->op != "-")) return false;
        ExprP lead = e->a->a; int g = 0;
        while (lead && lead->kind == EK::Binary &&
               (lead->op == "+" || lead->op == "-") && g++ < 64) lead = lead->a;
        return lead && lead->kind == EK::Cast && lead->op == "(char*)";
    }

    int prec(const ExprP& e) {
        if (!e) return 99;
        switch (e->kind) {
            case EK::Const: case EK::Var: case EK::Str: case EK::Call: return 99;
            case EK::Mem: return 16;       /* unary deref */
            case EK::AddrOf: return 15;
            case EK::Cast: return redundant_charptr_cast(e) ? prec(e->a) : 14;
            case EK::Unary: return 14;
            case EK::Ternary: return is_minmax(e) ? 99 : 2;   /* __min/__max render as a call */
            case EK::Reg: return 99;
            case EK::Binary: {
                const std::string& op = e->op;
                if (op=="*"||op=="/"||op=="%") return 13;
                if (op=="+"||op=="-") return 12;
                if (op=="<<"||op==">>") return 11;
                if (op=="<"||op=="<="||op==">"||op==">=") return 10;
                if (op=="=="||op=="!=") return 9;
                if (op=="&") return 8;
                if (op=="^") return 7;
                if (op=="|") return 6;
                if (op=="&&") return 5;
                if (op=="||") return 4;
                return 1;
            }
        }
        return 1;
    }

    /* render `e` as an operand inside a parent of precedence `pp`, on `right`. */
    std::string rsub(const ExprP& e, int pp, bool right = false) {
        std::string s = render(e);
        int ep = prec(e);
        bool need = ep < pp || (ep == pp && right);
        /* associativity: + and * are associative so equal-prec left doesn't need
         * parens; for simplicity we only add parens when strictly lower, or when
         * equal-prec on the right of a non-associative op. */
        if (ep < pp) need = true;
        else if (ep == pp && right) {
            /* for - and / and % and << >> and comparisons, right side needs parens
             * if same precedence */
            need = true;
        } else need = false;
        if (need) return "(" + s + ")";
        return s;
    }

    /* Shortest decimal that round-trips back to the exact float/double bits, with
     * a guaranteed decimal point and `f` suffix for 32-bit. 0x40800000 -> "4.0f",
     * 0x3e4ccccd -> "0.2f", 0x3fb999999999999a -> "0.1". */
    std::string fmt_float_lit(int64_t bits, bool is32) {
        char buf[64];
        if (is32) {
            uint32_t u = (uint32_t)bits; float f; std::memcpy(&f, &u, 4);
            if (std::isnan(f) || std::isinf(f)) { std::snprintf(buf,sizeof buf,"0x%08x/*f*/",u); return buf; }
            double v = (double)f;
            for (int p = 6; p <= 9; ++p) {
                std::snprintf(buf, sizeof buf, "%.*g", p, v);
                float rt = std::strtof(buf, nullptr); uint32_t b2; std::memcpy(&b2,&rt,4);
                if (b2 == u) break;
            }
        } else {
            uint64_t u = (uint64_t)bits; double d; std::memcpy(&d, &u, 8);
            if (std::isnan(d) || std::isinf(d)) { std::snprintf(buf,sizeof buf,"0x%llx/*d*/",(unsigned long long)u); return buf; }
            for (int p = 15; p <= 17; ++p) {
                std::snprintf(buf, sizeof buf, "%.*g", p, d);
                double rt = std::strtod(buf, nullptr); uint64_t b2; std::memcpy(&b2,&rt,8);
                if (b2 == u) break;
            }
        }
        std::string s = buf;
        if (s.find('.')==std::string::npos && s.find('e')==std::string::npos &&
            s.find("inf")==std::string::npos && s.find("nan")==std::string::npos)
            s += ".0";
        if (is32) s += "f";
        return s;
    }

    /* string-literal recovery for a constant KNOWN to be used as a pointer (call arg,
     * pointer-typed store). Returns `"..."` if it addresses a read-only C string, else
     * empty. NOT applied to bare constants — an arithmetic/bitwise constant that merely
     * happens to point at read-only text must stay numeric (else `x & CONST` breaks and
     * checksums corrupt). */
    std::string try_string_lit(const ExprP& e) {
        if (!e || e->kind != EK::Const || e->is_float) return "";
        if ((uint64_t)e->cval < 0x1000) return "";
        std::string s;
        if (read_cstring((uint64_t)e->cval, s)) return "\"" + s + "\"";
        return "";
    }

    /* std::min/std::max recovered from a select ternary: `C ? T : F` where C
     * compares the SAME two side-effect-free operands that are the arms. Emits
     * `__min(X,Y)` / `__max(X,Y)`. Strict exprEqual so the compared and selected
     * values are identical (signedness included) => the macro is exact; has_call
     * guard so the double-evaluating macro is safe. DS_NO_MINMAX. */
    /* PURE shape test (no side effects) — also used by prec() so a recovered
     * `__min(a,b)` is treated as a call (no parens), not a low-precedence ternary. */
    bool is_minmax(const ExprP& e, ExprP* px = nullptr, ExprP* py = nullptr, bool* pmin = nullptr) const {
        if (std::getenv("DS_NO_MINMAX")) return false;
        if (!e || e->kind != EK::Ternary || !e->a || !e->b || !e->c) return false;
        const ExprP& c = e->a;
        if (c->kind != EK::Binary || !c->a || !c->b) return false;
        bool lt = (c->op == "<" || c->op == "<="), gt = (c->op == ">" || c->op == ">=");
        if (!lt && !gt) return false;
        ExprP X = c->a, Y = c->b, T = e->b, F = e->c;
        if (has_call(X) || has_call(Y)) return false;   /* macro double-evals -> must be pure */
        bool isMin;
        if (exprEqual(T, X) && exprEqual(F, Y)) isMin = lt;        /* X<Y?X:Y=min, X>Y?X:Y=max */
        else if (exprEqual(T, Y) && exprEqual(F, X)) isMin = gt;   /* X<Y?Y:X=max, X>Y?Y:X=min */
        else return false;
        if (px) *px = X; if (py) *py = Y; if (pmin) *pmin = isMin;
        return true;
    }
    bool try_minmax(const ExprP& e, std::string& out) {
        ExprP X, Y; bool isMin = false;
        if (!is_minmax(e, &X, &Y, &isMin)) return false;
        if (isMin) used_min = true; else used_max = true;
        out = std::string(isMin ? "__min(" : "__max(") + render(X) + ", " + render(Y) + ")";
        return true;
    }

    /* APIs whose integer args are plain counts/millisecond delays and so read
     * better in decimal than hex (`Sleep(500)` not `Sleep(0x1f4)`). */
    static bool api_prefers_decimal_args(const std::string& c) {
        return c == "Sleep" || c == "SleepEx" || c == "j_Sleep" || c == "j_SleepEx";
    }
    /* Render one call argument. For a decimal-preferred API, a small non-negative
     * integer constant (peeling any widening cast) is emitted in decimal; anything
     * else falls back to the normal string-literal / expression rendering. */
    std::string call_arg_text(const ExprP& arg, bool dec_api) {
        /* A subnormal "float" const in call-argument (VALUE) position is a
         * misclassified small integer that flowed into a float-typed param slot —
         * pass its integer value (`1`), not the bit-reinterpret `1.4013e-45f`. Safe
         * here because a call arg is never a bit-reinterpret store target. */
        if (is_subnormal_float_const(arg)) {
            char b[24]; std::snprintf(b, sizeof b, "%lld", (long long)arg->cval);
            return b;
        }
        if (dec_api && arg) {
            ExprP c = arg;
            while (c && c->kind == EK::Cast && c->a) c = c->a;   /* peel widening casts */
            if (c && c->kind == EK::Const && !c->is_float &&
                c->cval >= 0 && c->cval <= 3600000) {            /* plausible ms; skip INFINITE etc. */
                char b[24]; std::snprintf(b, sizeof b, "%lld", (long long)c->cval);
                return b;
            }
        }
        /* Drop a redundant width-preserving integer cast on an argument already of
         * that width: `f((unsigned int)a2)` -> `f(a2)` when a2 is a 32-bit var. In
         * call-arg position the value is passed by bits and the callee reads its own
         * width, so a signedness-only `(int)`/`(unsigned int)` cast on an already-
         * 32-bit value is pure noise (no truncation happens — w<=4 gate). This is
         * the majority of the (unsigned int)/(int) cast clutter. DS_NO_ARGCASTCLEAN. */
        ExprP a = arg;
        if (a && a->kind == EK::Cast && a->a && a->a->kind == EK::Var &&
            (a->op == "(unsigned int)" || a->op == "(int)") &&
            !getenv("DS_NO_ARGCASTCLEAN")) {
            auto it = var_width.find(a->a->name);
            int w = (it != var_width.end()) ? it->second : 4;
            if (w > 0 && w <= 4) a = a->a;
        }
        /* Same for a CONSTANT argument: the literal already IS the value, so the cast is
         * pure noise (`__fastfail((unsigned int)5)` -> `__fastfail(5)`).
         * NON-NEGATIVE only, and this is not pedantry: dropping `(unsigned int)` from a
         * NEGATIVE literal changes what a WIDER parameter receives —
         * `f((unsigned int)-1)` passes 0x00000000FFFFFFFF while `f(-1)` sign-extends to
         * 0xFFFFFFFFFFFFFFFF. */
        if (a && a->kind == EK::Cast && a->a && a->a->kind == EK::Const &&
            (a->op == "(unsigned int)" || a->op == "(int)") &&
            !a->a->is_float && !a->a->char_hint && !a->a->null_hint &&
            a->a->cval >= 0 && a->a->cval <= 0x7fffffff &&
            !getenv("DS_NO_ARGCASTCLEAN")) {
            a = a->a;
        }
        std::string sl = try_string_lit(a);
        return sl.empty() ? render(a) : sl;
    }
    /* True if `e` is a "float" const whose bit pattern is a SUBNORMAL (biased
     * exponent 0, mantissa != 0). Real code never uses float subnormals, so such a
     * const is a misclassified small INTEGER that flowed into a float-typed slot
     * (`mov [slot],1` passed to a float param renders 0x1 as `1.4013e-45f`). Only
     * safe to re-render as the integer in a VALUE context (a call arg), NOT in a
     * bit-reinterpret store `*(double*)&x = <bits>` where the bits are the payload. */
    bool is_subnormal_float_const(const ExprP& e) const {
        if (!e || e->kind != EK::Const || !e->is_float) return false;
        if (e->width < 8) { uint32_t b = (uint32_t)e->cval; return ((b >> 23) & 0xff) == 0 && (b & 0x7fffff) != 0; }
        uint64_t b = (uint64_t)e->cval; return ((b >> 52) & 0x7ff) == 0 && (b & 0xfffffffffffffULL) != 0;
    }
    std::string render_const(const ExprP& e) {
        if (e->is_float) return fmt_float_lit(e->cval, e->width < 8);
        int64_t v = e->cval;
        /* A 0 proven to be a pointer value (mark_null_consts) reads as NULL. The
         * <stddef.h> include is flagged HERE rather than where the hint is set: a hinted
         * const can still be folded away afterwards (`p == 0` becomes `!p`), and flagging
         * at hint-time pulled the header into functions that never print NULL. */
        if (e->null_hint) { used_null = true; return "NULL"; }
        /* RTTI: a constant that is a recovered type_info object address (MSVC TypeDescriptor+8
         * / g++ &_ZTI, seeded by the RTTI scanner) is a `typeid(T)` operand -> render
         * `&<Class>__type_info`. A named-global #define keeps the exact address (`&`/`*`
         * cancel), so it is behavior-neutral AND C-compile-clean /TC. Gated DS_NO_TYPEID. */
        if (!e->is_float && (uint64_t)v > 0x1000 && !std::getenv("DS_NO_TYPEID")) {
            std::string tc = rtti_type_class_for_addr((uint64_t)v);
            if (!tc.empty()) {
                std::string nm = tc + "__type_info";
                char def[96]; std::snprintf(def, sizeof def, "(*(int8_t*)0x%llx)",
                                            (unsigned long long)v);
                named_globals[nm] = def;
                return "&" + nm;
            }
        }
        /* A constant that IS a static-data address, passed in a proven pointer position
         * (addr_hint, stamped at the call-arg site from the callee's ptr_param_mask), is the
         * address of a global: render `&byte_<addr>` reusing the existing named_globals #define.
         * `&byte_X` expands via the #define to `&(*(int8_t*)0xADDR)` -- the `&` and `*` cancel
         * to exactly 0xADDR, so this is purely cosmetic. Only fires on positive pointer
         * evidence + in_data_rva, so a plain integer is never mislabeled a pointer. */
        if (e->addr_hint && !e->is_float && (uint64_t)v > 0x1000 && in_data_rva((uint64_t)v)) {
            char nm[40], def[96];
            std::snprintf(nm,  sizeof nm,  "byte_%llx", (unsigned long long)v);
            std::snprintf(def, sizeof def, "(*(int8_t*)0x%llx)", (unsigned long long)v);
            named_globals[nm] = def;
            return "&" + std::string(nm);
        }
        /* H4: a printable-ASCII constant compared against a byte value reads as a char
         * literal in Hex-Rays (`c == 'A'` not `c == 0x41`). char_hint is set only for a
         * printable value in a byte comparison, so it never mis-renders a real number. */
        if (e->char_hint && v >= 0x20 && v <= 0x7e) {
            char b[8];
            if (v == '\\' || v == '\'') { b[0]='\''; b[1]='\\'; b[2]=(char)v; b[3]='\''; b[4]=0; }
            else { b[0]='\''; b[1]=(char)v; b[2]='\''; b[3]=0; }
            return b;
        }
        /* A recovered magic-number DIVISOR reads as a decimal count (`x / 10`), never
         * `x / 0xa` — it is an arithmetic quantity, not a bitmask. */
        if (e->dec_hint && !e->is_float) {
            char b[24];
            std::snprintf(b, sizeof b, e->is_unsigned ? "%llu" : "%lld",
                          e->is_unsigned ? (unsigned long long)v : (long long)v);
            return b;
        }
        /* A bitmask/magic in a bitwise op reads far better in hex (Hex-Rays style):
         * `& 0x8000000000000000uLL`, `& 0x7FFFFFFF` — signedness is irrelevant to the
         * bitwise result so the unsigned suffix is safe. Set by late_peephole only for
         * `& | ^` operands, so a signed comparison literal is never affected. */
        if (e->hex_hint && !e->is_float) {
            if (e->width >= 8 && (v > 0x7fffffffLL || v < -0x80000000LL))
                return hex((uint64_t)v) + "uLL";
            return hex((uint64_t)(uint32_t)v);
        }
        if (e->width >= 8 && (v > 0x7fffffffLL || v < -0x80000000LL)) {
            if (v < 0) {
                char b[32]; std::snprintf(b,sizeof(b),"%lldLL",(long long)v); return b;
            }
            return hex((uint64_t)v) + "LL";
        }
        if (v < 0) {
            /* A negative literal whose magnitude is >= 2^31 (INT_MIN and beyond)
             * MUST carry an LL suffix. Written bare, `-2147483648` parses in C as
             * `-(2147483648)` where the too-big-for-int magnitude is UNSIGNED, so
             * a comparison like `x >= -2147483648` silently becomes unsigned and
             * flips — the classic INT_MIN-literal bug. */
            if (v <= -0x80000000LL) {
                char b[32]; std::snprintf(b, sizeof(b), "%lldLL", (long long)v); return b;
            }
            return std::to_string((long long)v);
        }
        if (v < 10) return std::to_string((long long)v);
        return hex((uint64_t)(uint32_t)v);
    }

    std::string render(const ExprP& e) {
        if (!e) return "0";
        switch (e->kind) {
            case EK::Const: return render_const(e);
            case EK::Var:   return disp(e->name);
            case EK::Reg:   return reg_value_fallback(e->reg, e->width);
            case EK::Str:   return e->text;
            case EK::Mem: {
                std::string sub;
                if (try_struct_field(e, sub)) return sub;
                if (try_array_subscript(e, sub)) return sub;
                std::string t = e->is_float ? (e->width >= 8 ? "double" : "float")
                                            : typ_str(e->width, e->is_unsigned, false);
                /* a load/store through a bare CONSTANT data address is a global
                 * variable — name it Hex-Rays style (`qword_174148`) instead of the
                 * noisy `*(long long*)0x174148` repeated dozens of times. A `#define`
                 * (emitted once) keeps the exact semantics (still derefs the address),
                 * so this is a pure readability win, not a behavior change. */
                const ExprP& a = e->a;
                if (a && a->kind == EK::Const && a->cval > 0x1000 &&
                    in_data_rva((uint64_t)a->cval)) {
                    /* Name by the TYPE the deref actually uses, not by width alone: a
                     * float global was rendering `#define dword_173004 (*(float*)0x173004)`
                     * — a name that says dword over a float load. Hex-Rays spells these
                     * flt_/dbl_, and the name is the only type cue at the use site.
                     * A `flt_`/`dbl_` name can never reach the `substr(6)` prefix-stripping
                     * sites: those are all gated on is_global_struct_name(), which matches
                     * only the 6-char qword_/dword_, and a struct base is required to be
                     * !is_float anyway. If one address is touched as both float and int it
                     * simply gets two names, each with its own correct #define. */
                    const char* pfx = e->is_float ? ((e->width >= 8) ? "dbl" : "flt")
                                     : (e->width >= 8) ? "qword" : (e->width == 4) ? "dword"
                                     : (e->width == 2) ? "word" : "byte";
                    char nm[40];
                    /* TLS INDEX: a dword global used as the index into the thread's TLS array
                     * (`__readgsqword(0x58) + G*8`) is the compiler's `_tls_index`. tls_index_addr
                     * is recorded by detect_tls_index() from that exact pattern -- decidable, one
                     * global. Naming it says "this is thread-local storage" at a glance. */
                    if (!e->is_float && tls_index_addr && (uint64_t)a->cval == tls_index_addr) {
                        char d2[96]; std::snprintf(d2, sizeof d2, "(*(unsigned long*)0x%llx)",
                                                   (unsigned long long)a->cval);
                        named_globals["_tls_index"] = d2;
                        return "_tls_index";
                    }
                    std::snprintf(nm, sizeof nm, "%s_%llx", pfx, (unsigned long long)a->cval);
                    char def[96];
                    std::snprintf(def, sizeof def, "(*(%s*)0x%llx)", t.c_str(),
                                  (unsigned long long)a->cval);
                    named_globals[nm] = def;
                    return nm;
                }
                /* a bare Var/param address needs no wrapping parens after the cast:
                 * `*(int*)a1` reads cleaner than `*(int*)(a1)`. Anything with an
                 * operator (base+off, a deref) keeps them for precedence clarity. */
                bool bare = a && a->kind == EK::Var;
                if (bare) return "*(" + t + "*)" + render_addr(a);
                return "*(" + t + "*)(" + render_addr(a) + ")";
            }
            case EK::AddrOf: return "&" + rsub(e->a, 15);
            case EK::Unary:  return e->op + rsub(e->a, 14, true);
            case EK::Cast: {
                /* redundant `(char*)` over an already-char* pointer sum: render the inner
                 * directly (prec() defers too, so parenthesization stays correct). */
                if (redundant_charptr_cast(e)) return render(e->a);
                /* `(char*)0xADDR` / `(int8_t*)0xADDR` pointing at a valid read-only
                 * C string reads as the string literal, like the sibling paths that
                 * already emit "<Unknown>" — not a bare rodata address. read_cstring
                 * validates it, so a genuine numeric pointer is left untouched. */
                if (e->a && e->a->kind == EK::Const &&
                    (e->op == "(char*)" || e->op == "(int8_t*)" || e->op == "(uint8_t*)" ||
                     e->op == "(const char*)" || e->op == "(unsigned char*)")) {
                    std::string sl = try_string_lit(e->a);
                    if (!sl.empty()) return sl;
                }
                return e->op + rsub(e->a, 14, true);
            }
            case EK::Ternary: {
                /* std::min / std::max: a select whose condition compares the SAME two
                 * (side-effect-free) operands that are the two arms — `X<Y?X:Y` etc.
                 * The strict exprEqual match means the compared and selected values are
                 * identical (incl. signedness), so the `__min`/`__max` macro is exact.
                 * DS_NO_MINMAX. */
                std::string mm;
                if (try_minmax(e, mm)) return mm;
                /* When the two arms differ in pointer-ness (`cond ? 0x16 : ptr`, a
                 * capacity/max on a mis-typed pointer, or a genuine ptr/int select),
                 * the `:` is C4047. Coerce the pointer arm to (long long) so both arms
                 * are integral — value-preserving on x64, and any pointer USE re-casts
                 * at its own site. */
                bool bp = renders_as_pointer(e->b), cp = renders_as_pointer(e->c);
                std::string bs = rsub(e->b, 3), cs = rsub(e->c, 2, true);
                if (bp && !cp) bs = "(long long)(" + bs + ")";
                else if (cp && !bp) cs = "(long long)(" + cs + ")";
                else if (bp && cp) {   /* both pointers, possibly DIFFERENT types (C4133):
                                        * make both integral; any pointer use re-casts. */
                    bs = "(long long)(" + bs + ")"; cs = "(long long)(" + cs + ")";
                }
                return rsub(e->a, 3) + " ? " + bs + " : " + cs;
            }
            case EK::Binary: {
                int pp = prec(e);
                const std::string& op = e->op;
                /* address-of a recognized struct field: `(char*)p + K` -> `&p->field_K` */
                {
                    std::string sfa;
                    if (try_struct_field_addr(e, sfa)) return sfa;
                }
                /* character-constant recovery: a small int constant compared against a
                 * char-typed value (a byte load, or an explicit `(signed char)` cast)
                 * is a character — render '\n' / ';' / '[' instead of 0xa / 0x3b / 0x5b.
                 * Value-identical; the reader sees intent (newline, separator, bracket)
                 * instead of memorizing ASCII codes. Only fires when the *other* operand
                 * is provably char-width, so shift amounts / flags stay numeric. */
                if (op=="=="||op=="!="||op=="<"||op==">"||op=="<="||op==">=") {
                    auto char_lit = [](int64_t v)->std::string {
                        if (v=='\t') return "'\\t'";
                        if (v=='\n') return "'\\n'";
                        if (v=='\r') return "'\\r'";
                        if (v=='\\') return "'\\\\'";
                        if (v=='\'') return "'\\''";
                        if (v>=0x20 && v<=0x7e) { std::string s="'"; s+=(char)v; s+="'"; return s; }
                        return "";   /* NUL and other control codes stay numeric */
                    };
                    auto is_char_ctx = [&](const ExprP& x)->bool {
                        if (!x || x->kind==EK::Const) return false;
                        if (x->kind==EK::Cast && x->op.find("char")!=std::string::npos) return true;
                        return x->width==1;   /* byte Mem / subscript / char Var */
                    };
                    auto isc = [&](const ExprP& x){ return x && x->kind==EK::Const &&
                                   !x->is_float && x->cval>=0 && x->cval<=0x7f; };
                    if (isc(e->a) && is_char_ctx(e->b)) {
                        std::string cl = char_lit(e->a->cval);
                        if (!cl.empty()) return cl + " " + op + " " + rsub(e->b, pp);
                    }
                    if (isc(e->b) && is_char_ctx(e->a)) {
                        std::string cl = char_lit(e->b->cval);
                        if (!cl.empty()) return rsub(e->a, pp) + " " + op + " " + cl;
                    }
                }
                /* UNIVERSAL pointer-comparison coercion — runs FIRST so no later
                 * special-case path (short-circuit merge, bitop, e->is_unsigned, the
                 * C4018 fix) can swallow it. ANY comparison with a pointer operand
                 * (ptr vs int = C4047; ptr vs a different ptr type = C4133) is made
                 * integral by casting each pointer side to (long long). Skips FP
                 * operands (the fp-compare block handles those) and `p == 0`. */
                if (op=="=="||op=="!="||op=="<"||op==">"||op=="<="||op==">=") {
                    auto isflt = [&](const ExprP& x){ return x && (x->is_float ||
                        (x->kind==EK::Var && var_is_float.count(x->name) && var_is_float[x->name])); };
                    auto isnull = [](const ExprP& x){ return x && x->kind==EK::Const && x->cval==0 && !x->is_float; };
                    bool pa = renders_as_pointer(e->a), pb = renders_as_pointer(e->b);
                    if ((pa || pb) && !isflt(e->a) && !isflt(e->b) &&
                        !(pa && isnull(e->b)) && !(pb && isnull(e->a)) &&
                        !isnull(e->a) && !isnull(e->b)) {
                        /* cast BOTH operands to ONE integral type so there is neither a
                         * ptr/int mismatch (C4047/C4133) nor a signed/unsigned one
                         * (C4018). The signedness follows the instruction (e->is_unsigned
                         * = the binary did `jb`/`ja`), so behavior is preserved. */
                        std::string ct = e->is_unsigned ? "(unsigned long long)(" : "(long long)(";
                        /* a bare constant operand needs no cast — C promotes it to the
                         * (width-8) cast type of the other side value-identically, so
                         * `(long long)(p) < 5` reads cleaner than `... < (long long)(5)`. */
                        auto side = [&](const ExprP& x){
                            return (x && x->kind == EK::Const && !x->is_float)
                                   ? rsub(x, 3) : ct + rsub(x, 3) + ")";
                        };
                        return side(e->a) + " " + op + " " + side(e->b);
                    }
                }
                /* Bitwise / shift / modulo require INTEGER operands: a pointer operand
                 * (e.g. an aligned+tagged stack-array address `(s1+0x10) & -256 | 1`,
                 * from `lea; and; or`) is illegal in C (C2296). Cast each pointer side
                 * to an integer of the op's signedness — value-preserving, and the only
                 * way these ops are ever well-typed on an address. */
                if (op=="&"||op=="|"||op=="^"||op=="<<"||op==">>"||op=="%") {
                    bool pa = renders_as_pointer(e->a), pb = renders_as_pointer(e->b);
                    if (pa || pb) {
                        std::string ct = e->is_unsigned ? "(unsigned long long)(" : "(long long)(";
                        std::string ls = pa ? ct + rsub(e->a, 3) + ")" : rsub(e->a, pp);
                        std::string rs = pb ? ct + rsub(e->b, 3) + ")" : rsub(e->b, pp);
                        return ls + " " + op + " " + rs;
                    }
                }
                /* high-multiply intrinsics (RDX of one-op `imul`/`mul`). */
                if (op == "mulh")  return "__mulh((long long)(" + render(e->a) + "), (long long)(" + render(e->b) + "))";
                if (op == "umulh") return "__umulh((unsigned long long)(" + render(e->a) + "), (unsigned long long)(" + render(e->b) + "))";
                /* Byte-accurate pointer arithmetic safety: if a typed pointer
                 * (`int*` etc., element width > 1) appears as the base of a bare
                 * +/- (i.e. an address computed outside a subscript/deref, e.g.
                 * from `lea`), the operand is a byte displacement, so cast the
                 * base to char* to keep the result byte-addressed instead of
                 * scaling by the element size. char* bases need no cast. */
                /* renders_as_ptr: the expr PRINTS with a pointer type — a typed
                 * pointer Var or an explicit (T*)-cast. `expr_is_pointer` looks
                 * THROUGH a cast to its integer source, so it alone misses a
                 * `(char*)(int)`; check the cast text too. Used to keep pointer
                 * arithmetic and bitwise ops well-typed (no C2110 / C2296). */
                auto rptr = [&](const ExprP& x) -> bool {
                    if (!x) return false;
                    /* A KNOWN-FLOAT var/param is NEVER a pointer base. A float param
                     * declared `float`/`double` that also carries a stray var_pointer
                     * flag (a mis-fired pointer propagation) would otherwise be treated
                     * as a pointer in +,-,bitwise, and DIVISION contexts: `a2 + const`
                     * rendered a bit-reinterpret of the float lvalue, and a float `/ a2`
                     * cast the divisor to a truncating integer -- both WRONG C. The
                     * declared float type wins (renders_as_pointer already declines it,
                     * keying off decl_type), so this only realigns expr_is_pointer's
                     * stale var_pointer flag with the declared float type. */
                    if (x->kind == EK::Var && var_is_float.count(x->name) &&
                        var_is_float[x->name]) return false;
                    if (x->kind == EK::Cast && x->op.find('*') != std::string::npos)
                        return true;
                    if (is_struct_ptr_field(x)) return true;   /* a retyped `struct T*` field */
                    return expr_is_pointer(x);
                };
                if ((op == "+" || op == "-")) {
                    /* is x a POINTER/ARRAY base (a pointer value or a stack array
                     * that decays to one)? Only these take a byte-offset addend. */
                    auto ptr_base = [&](const ExprP& x) -> bool {
                        if (!x) return false;
                        if (rptr(x)) return true;
                        return x->kind == EK::Var && array_locals.count(x->name);
                    };
                    /* A float CONSTANT added to a POINTER/ARRAY base is a mis-tagged
                     * integer byte offset: `s7 + 1.68156e-44f` is really `s7 + 12`
                     * (the float literal's raw bits ARE the offset). `ptr + floatconst`
                     * is C2111; render the integer bits (e->cval holds them). Gated to
                     * a pointer base so a genuine `float + floatconst` is untouched. */
                    if (e->b && e->b->kind == EK::Const && e->b->is_float && ptr_base(e->a)) {
                        /* Only a SUBNORMAL "float" const is a genuine mis-tagged small
                         * integer byte offset (every offset < 2^23 has float-bit exponent
                         * 0), so its raw bits ARE the offset. A NORMAL float const on a
                         * pointer base is a real scalar-float add whose base was mis-typed
                         * as a pointer -- e.g. a param-home slot reused as float scratch
                         * after an out-param call wrote a float through &slot (`addss
                         * xmm,[home]; addss xmm,[flt_const]`). Emitting the const's raw
                         * bit pattern as an int addend (`a7 + 1065353048`) is flat wrong.
                         * Keep the add in the float domain: reinterpret the base's low 4
                         * bytes as float (bit-identical, and value-preserving even if the
                         * base is really a float var) so the const prints as its true
                         * value. Needs a plain lvalue Var base for `&base` to be well-formed. */
                        /* peel a pointer cast (`(char*)a7`) so the underlying lvalue Var is
                         * reachable for `&base`; without this a cast-wrapped base fell through
                         * to the pointer-arith path and emitted `(char*)a7 + 0.99999f` = C2111. */
                        ExprP fb = e->a; while (fb && fb->kind == EK::Cast && fb->a) fb = fb->a;
                        if (!is_subnormal_float_const(e->b) && fb && fb->kind == EK::Var)
                            return "*(float*)&" + rsub(fb, 15) + " " + op + " " + render_const(e->b);
                        return (is_struct_ptr_field(e->a) ? "(char*)" + rsub(e->a, 14) : rsub(e->a, pp))
                               + " " + op + " " + std::to_string((long long)e->b->cval);
                    }
                    if (op == "+" && e->a && e->a->kind == EK::Const && e->a->is_float && ptr_base(e->b)) {
                        ExprP fb = e->b; while (fb && fb->kind == EK::Cast && fb->a) fb = fb->a;
                        if (!is_subnormal_float_const(e->a) && fb && fb->kind == EK::Var)
                            return "*(float*)&" + rsub(fb, 15) + " + " + render_const(e->a);
                        return (is_struct_ptr_field(e->b) ? "(char*)" + rsub(e->b, 14) : rsub(e->b, pp))
                               + " + " + std::to_string((long long)e->a->cval);
                    }
                    auto typed_ptr = [&](const ExprP& x) -> bool {
                        if (is_struct_ptr_field(x)) return true;   /* void* field: byte-cast for arithmetic */
                        if (!x || x->kind != EK::Var) return false;
                        auto it = ptr_elem_width.find(x->name);
                        if (it != ptr_elem_width.end() && it->second > 1) return true;
                        /* A STRUCT-typed pointer var (a recovered struct param/local base —
                         * `struct T*`) scales a byte offset by sizeof(struct) unless char-cast.
                         * ptr_elem_width is NOT set for these (their type comes from
                         * param_structs), so the byte-offset arithmetic `a1 + 0x28` was
                         * rendered raw and computed a1 + 0x28*sizeof(T) — a wrong address that
                         * compiles clean (the disasm is a plain `lea rcx,[rbx+0x28]`). Catch
                         * them by decl type; char and void bases add bytes directly (no cast). */
                        std::string dt = decl_type(x->name);
                        if (dt.size() >= 2 && dt.back() == '*') {
                            bool ischar = dt.size() >= 5 && dt.compare(dt.size()-5, 5, "char*") == 0;
                            bool isvoid = dt.size() >= 5 && dt.compare(dt.size()-5, 5, "void*") == 0;
                            if (!ischar && !isvoid) return true;
                        }
                        return false;
                    };
                    /* the OFFSET of pointer arithmetic must be an INTEGER byte count,
                     * never a pointer — `ptr + ptr` is C2110. A spurious `(char*)`
                     * cast wrapping an integer offset (`[rdx+rcx]` where the address
                     * renderer cast the offset instead of the base) is dropped; a
                     * genuine pointer offset is cast to (long long). */
                    auto off_of = [&](const ExprP& x, int p) -> std::string {
                        if (x && x->kind == EK::Cast &&
                            x->op.find('*') != std::string::npos && !expr_is_pointer(x->a))
                            return rsub(x->a, p, true);
                        if (rptr(x)) return "(long long)" + rsub(x, 14, true);
                        return rsub(x, p, true);
                    };
                    /* pointer MINUS pointer = an integer byte difference: cast BOTH to
                     * char* so the result is a ptrdiff (not a pointer), letting an outer
                     * `/elemsize` (element-count from `(end-begin)/size`) compile. Fires only
                     * when a retyped struct-ptr field meets ANOTHER address-like operand (a
                     * pointer or a width-8 memory field) — NOT a small int offset — so plain
                     * `(char*)field - index` byte addressing is unchanged. */
                    auto addr_like = [&](const ExprP& x) -> bool {
                        return rptr(x) || (x && x->kind == EK::Mem && x->width == 8 && !x->is_float);
                    };
                    /* Flatten a chained byte displacement: `(p + c1) + c2` on a pointer base
                     * (a temp `rsi = a1 + 8` then a store `[rsi + 8]`) otherwise renders as the
                     * nested `(char*)((char*)a1 + 8) + 8`. Fold the constants so it reads
                     * `(char*)a1 + 0x10`. Only when the inner base is itself a pointer, so this is
                     * byte arithmetic (never `int + int`), and the inner op is `+` (a ptrdiff
                     * `p - q` never matches). */
                    if (op == "+" && e->b && e->b->kind == EK::Const && !e->b->is_float &&
                        e->a && e->a->kind == EK::Binary && e->a->op == "+" &&
                        e->a->b && e->a->b->kind == EK::Const && !e->a->b->is_float && e->a->a &&
                        (rptr(e->a->a) || typed_ptr(e->a->a) || is_struct_ptr_field(e->a->a))) {
                        ExprP folded = mkBinary("+", clone(e->a->a),
                                                mkConst(e->a->b->cval + e->b->cval, 8), 8);
                        return render(folded);
                    }
                    if (op == "-" && (is_struct_ptr_field(e->a) || is_struct_ptr_field(e->b)) &&
                        addr_like(e->a) && addr_like(e->b))
                        return "(char*)" + rsub(e->a, 14) + " - (char*)" + rsub(e->b, 14);
                    /* `&p->field + K`: try_struct_field_addr renders the base as a TYPED
                     * pointer to the field (`<fieldtype>*`), so a residual byte offset K —
                     * a 16-byte SIMD store split into &field / &field+8, or any displacement
                     * past the last declared field — would be scaled by sizeof(field)
                     * (`&field_10 + 8` steps 8*8=64 bytes, not 8, overflowing the object).
                     * Cast the field-address to char* so K stays a byte count. Runs only
                     * after the whole-node try_struct_field_addr above already declined
                     * (i.e. e is NOT itself an exact field), mirroring the typed_ptr Var
                     * handling below. */
                    {
                        std::string sfa_dummy;
                        if (try_struct_field_addr(e->a, sfa_dummy))
                            return "(char*)" + rsub(e->a, 14) + " " + op + " " + off_of(e->b, 12);
                        if (op == "+" && try_struct_field_addr(e->b, sfa_dummy))
                            return "(char*)" + rsub(e->b, 14) + " + " + off_of(e->a, 12);
                    }
                    /* A FLOAT const can never be a pointer byte-offset (`(char*)a7 + 0.99999f`
                     * = C2111). The base is a param-home slot reused as float scratch; reinterpret
                     * its bytes as float so it reads `*(float*)&base + 0.99999f`. Catches the case
                     * the ptr_base block above misses when only typed_ptr (not ptr_base) holds. */
                    {
                        ExprP pc = nullptr, fc = nullptr;
                        if (e->b && e->b->kind == EK::Const && e->b->is_float) { pc = e->a; fc = e->b; }
                        else if (op == "+" && e->a && e->a->kind == EK::Const && e->a->is_float) { pc = e->b; fc = e->a; }
                        if (pc && fc && !is_subnormal_float_const(fc)) {
                            ExprP fb = pc; while (fb && fb->kind == EK::Cast && fb->a) fb = fb->a;
                            if (fb && fb->kind == EK::Var)
                                return "*(float*)&" + rsub(fb, 15) + " " + op + " " + render_const(fc);
                        }
                    }
                    if (typed_ptr(e->a))
                        return "(char*)" + rsub(e->a, 14) + " " + op + " " + off_of(e->b, 12);
                    if (op == "+" && typed_ptr(e->b))
                        return "(char*)" + rsub(e->b, 14) + " + " + off_of(e->a, 12);
                    /* neither is a typed (elem>1) pointer, but if BOTH still render
                     * as pointers (a char* base + a (char*)-cast integer offset),
                     * keep the left as base and force the right to an integer. */
                    if (rptr(e->a) && rptr(e->b))
                        return rsub(e->a, pp) + " " + op + " " + off_of(e->b, pp);
                    /* `int - ptr` is C2113 (a pointer may only be subtracted FROM a
                     * pointer). The result is a byte/pointer difference — cast the
                     * pointer subtrahend to an integer so `t56 - t55` (t55 a pointer
                     * begin, t56 an integer end) compiles as the byte span. */
                    if (op == "-" && rptr(e->b) && !rptr(e->a))
                        return rsub(e->a, pp) + " - (long long)" + rsub(e->b, 14, true);
                }
                if (e->is_unsigned &&
                    (op=="<"||op=="<="||op==">"||op==">="||op==">>"||op=="/"||op=="%")) {
                    std::string c = cast_str(e->width >= 8 ? 8 : 4, true);
                    /* A CONSTANT operand of an unsigned compare/div/mod needs no explicit
                     * unsigned cast: C promotes it to the unsigned type of the OTHER (cast)
                     * operand, value-identically (even a negative literal promotes the same
                     * way `(unsigned)K` would). Dropping it removes the bulk of the
                     * `(unsigned int)(K)` double-cast noise. NOT for `>>` (its result type
                     * follows the left operand, so a bare signed constant value would switch
                     * to an arithmetic shift). */
                    bool lean = !std::getenv("DS_NO_LEANCAST") && op != ">>";
                    /* only drop the cast on a constant that FITS the compare width — the
                     * cast truncates (`(unsigned int)0x100000000`==0); a bare wide literal
                     * would instead WIDEN the comparison, changing the result. */
                    auto fits = [&](const ExprP& k) -> bool {
                        if (e->width >= 8) return true;
                        return k->cval >= -0x80000000LL && k->cval <= 0xFFFFFFFFLL;
                    };
                    bool aconst = isConst(e->a) && !e->a->is_float && fits(e->a);
                    bool bconst = isConst(e->b) && !e->b->is_float && fits(e->b);
                    /* Skip the `(unsigned int)`/`(unsigned long long)` wrap when the
                     * operand ALREADY renders as an unsigned expr of the SAME width —
                     * re-casting an unsigned value to the same unsigned type is a no-op
                     * and just produces `(unsigned int)((unsigned int)x)` noise. */
                    int cw = e->width >= 8 ? 8 : 4;
                    auto uframe = [&](const ExprP& x) -> std::string {
                        if (x && x->is_unsigned && !x->is_float && x->width == cw)
                            return render(x);
                        return c + "(" + render(x) + ")";
                    };
                    std::string l = (lean && aconst && !bconst) ? render(e->a) : uframe(e->a);
                    /* The shift COUNT of `>>` is not part of the unsigned value;
                     * it must not be cast to unsigned (`x >> (unsigned)(1)` is
                     * ugly and pointless). Only the shifted value needs the cast. */
                    if (op == ">>") {
                        std::string r = rsub(e->b, prec(e), true);
                        return l + " >> " + r;
                    }
                    std::string r = (lean && bconst && !aconst) ? render(e->b) : uframe(e->b);
                    return l + " " + op + " " + r;
                }
                /* mixed-sign relational compare that is NOT flagged unsigned (`(int)x >=
                 * (unsigned)y`): C promotes both to unsigned (C4018) which can INVERT the
                 * signed `cmp` the binary actually did. We reach here only when the op is
                 * signed, so cast the unsigned operand back to SIGNED to keep the
                 * comparison signed — matches the instruction and silences C4018. */
                if (op=="<"||op=="<="||op==">"||op==">=") {
                    int sa = expr_signedness(e->a), sb = expr_signedness(e->b);
                    if ((sa > 0) != (sb > 0)) {
                        std::string sc = cast_str(e->width >= 8 ? 8 : 4, false);
                        std::string l = (sa > 0) ? sc + "(" + render(e->a) + ")" : rsub(e->a, pp);
                        std::string r = (sb > 0) ? sc + "(" + render(e->b) + ")" : rsub(e->b, pp, true);
                        return l + " " + op + " " + r;
                    }
                }
                /* `x / 0.0` — a literal floating divide-by-zero — is the HUGE_VAL/±inf
                 * idiom (`errno = ERANGE; return copysign(HUGE_VAL, s)` lowers to
                 * `divsd xmm, xorps-zeroed`). MSVC folds the constant division into a
                 * compile-time C2124. Route the zero divisor through a `volatile`
                 * static so the fold is defeated: at runtime IEEE `x / 0.0` is ±inf,
                 * exactly the intended value. */
                if (op == "/" && e->b && e->b->kind == EK::Const &&
                    e->b->is_float && e->b->cval == 0) {
                    used_fdiv0 = true;
                    return rsub(e->a, pp) + " / __ds_fzero";
                }
                /* A POINTER as an operand of a bitwise / shift / mul / div / mod op
                 * is a hard error (C2296/C2297: `p & 7`, `p * 4`). Alignment checks
                 * (`(uintptr)p & 7`), pointer hashing, and an index still typed as a
                 * pointer (`t1 * 4`) lower to exactly this — only `+ - < > == etc.`
                 * are legal on a pointer. Cast the pointer operand(s) to an integer;
                 * for a shift only the VALUE needs it, not the count. (Unsigned
                 * `>>`/`/`/`%` already went through the cast path above.) */
                if (op=="&" || op=="|" || op=="^" || op=="<<" || op==">>" ||
                    op=="*" || op=="/" || op=="%") {
                    /* a FLOAT value in a bitwise/shift op (`a1[0x14] & 1` where a1 is
                     * a float* struct base whose 0x14 field is really an int flags
                     * word) is C2296 too. The BITS are wanted, so REINTERPRET the
                     * float lvalue as an int (`*(int*)&x` / `*(int*)(addr)`) — bit-
                     * exact, unlike a value cast. */
                    bool bitop = (op=="&"||op=="|"||op=="^"||op=="<<"||op==">>");
                    /* the base pointer var of a memory address (`a1 + 0x14*4` -> a1),
                     * preferring a float-typed pointer — so a bare float* subscript
                     * (`a1[0x14]`, whose Mem is_float flag is not set) is recognized. */
                    std::function<std::string(const ExprP&)> mem_base = [&](const ExprP& a) -> std::string {
                        if (!a) return "";
                        if (a->kind == EK::Var) return a->name;
                        if (a->kind == EK::Cast) return mem_base(a->a);
                        if (a->kind == EK::Binary && (a->op=="+"||a->op=="-")) {
                            std::string l = mem_base(a->a), r = mem_base(a->b);
                            if (!l.empty() && ptr_elem_float.count(l)) return l;
                            if (!r.empty() && ptr_elem_float.count(r)) return r;
                            return l.empty() ? r : l;
                        }
                        return "";
                    };
                    auto is_fv = [&](const ExprP& x) -> bool {
                        if (!x || !bitop) return false;
                        if (x->is_float) return true;
                        if (x->kind==EK::Var && var_is_float.count(x->name) && var_is_float[x->name])
                            return true;
                        if (x->kind==EK::Mem && x->a) {
                            std::string b = mem_base(x->a);
                            if (!b.empty() && ptr_elem_float.count(b) && ptr_elem_float[b]) return true;
                        }
                        return false;
                    };
                    auto ibits = [&](const ExprP& x) -> std::string {
                        /* pick the reinterpret width from the operand: an 8-byte DOUBLE
                         * masked with a 64-bit constant (`d2u(x) & 0x8000000000000000`
                         * sign test) must read all 8 bytes — `*(int*)` truncated it to
                         * bit 31, testing the WRONG bit. Mirrors tobits below. */
                        if (x->kind == EK::Mem && x->a) {
                            const char* ty = (x->width >= 8) ? "long long" : "int";
                            return std::string("*(") + ty + "*)(" + render_addr(x->a) + ")";
                        }
                        if (x->kind == EK::Var) {
                            const char* ty = (var_width.count(x->name) && var_width[x->name] >= 8)
                                             ? "long long" : "int";
                            return std::string("*(") + ty + "*)&" + rsub(x, 14);  /* lvalue only */
                        }
                        return "(long long)" + rsub(x, 14, true);   /* non-lvalue: value cast */
                    };
                    /* a stack ARRAY (`char buf[N]`) in a bitwise op is its decayed
                     * address being masked (`(uintptr)buf & -32` alignment) — C2296/
                     * C2297. Cast to an integer like a pointer. */
                    auto is_arr = [&](const ExprP& x) {
                        return x && x->kind == EK::Var && array_locals.count(x->name);
                    };
                    bool la = rptr(e->a) || is_arr(e->a), laf = is_fv(e->a);
                    bool notcnt = (op != "<<" && op != ">>");
                    bool rb = notcnt && (rptr(e->b) || is_arr(e->b)), rbf = notcnt && is_fv(e->b);
                    if (la || laf || rb || rbf) {
                        std::string l = la  ? "(long long)" + rsub(e->a, 14, true)
                                      : laf ? ibits(e->a) : rsub(e->a, pp);
                        std::string r = rb  ? "(long long)" + rsub(e->b, 14, true)
                                      : rbf ? ibits(e->b) : rsub(e->b, pp, true);
                        return l + " " + op + " " + r;
                    }
                }
                /* A comparison between a FLOAT value and a POINTER (`t8 == a1+a2`
                 * where t8 is a mis-merged float holding a pointer) is C2440. Bridge
                 * both to `long long`: reinterpret the float lvalue's bits, value-cast
                 * the pointer, so they are comparable and compile. */
                if (op=="=="||op=="!="||op=="<"||op==">"||op=="<="||op==">=") {
                    std::function<bool(const ExprP&)> isf = [&](const ExprP& x) -> bool {
                        if (!x) return false;
                        if (x->is_float) return true;
                        if (x->kind==EK::Var) return var_is_float.count(x->name) && var_is_float[x->name];
                        /* a float leaks through +,-,*,/ arithmetic (`a1 + a2`, a2 float) */
                        if (x->kind==EK::Binary &&
                            (x->op=="+"||x->op=="-"||x->op=="*"||x->op=="/"))
                            return isf(x->a) || isf(x->b);
                        return false;
                    };
                    auto tobits = [&](const ExprP& x) -> std::string {
                        if (x->kind == EK::Var) return "(long long)*(" +
                            std::string(var_width.count(x->name)&&var_width[x->name]>=8?"long long":"int") +
                            "*)&" + rsub(x, 14);
                        return "(long long)" + rsub(x, 14, true);
                    };
                    bool af = isf(e->a), bf = isf(e->b), ap = rptr(e->a), bp = rptr(e->b);
                    if ((af && bp) || (ap && bf)) {
                        std::string l = af ? tobits(e->a) : (ap ? "(long long)" + rsub(e->a,14,true) : rsub(e->a,pp));
                        std::string r = bf ? tobits(e->b) : (bp ? "(long long)" + rsub(e->b,14,true) : rsub(e->b,pp,true));
                        return l + " " + op + " " + r;
                    }
                    /* pointer <=> integer compare (`t7 == *(long long*)..`, `ptr != n`,
                     * `t33 == (cond ? p : q)`) is C4047 unless the int side is a null
                     * literal (a valid ptr==0). Use renders_as_pointer (handles ternary
                     * arms + nested) so no site slips through; cast the pointer side. */
                    bool ap2 = renders_as_pointer(e->a), bp2 = renders_as_pointer(e->b);
                    auto isnull = [](const ExprP& x){ return x && x->kind==EK::Const && x->cval==0 && !x->is_float; };
                    /* ANY comparison involving a pointer (ptr vs int = C4047, OR ptr vs
                     * a DIFFERENT pointer type = C4133) is made purely integral by
                     * casting each pointer side to (long long). A pointer-vs-null
                     * (`p == 0`) is valid C and left alone. */
                    /* MEASURED AND REVERTED (2026-07-17): folding `(long long)p == (long long)q`
                     * to `p == q` when BOTH sides render as the SAME pointer type. Correct, and
                     * it fires ZERO times -- whole-binary A/B: 0 of 1497 files differ, chars
                     * byte-identical. Do not re-add it without first fixing the CAUSE.
                     *
                     * THE CAUSE IS WORTH MORE THAN THE FEATURE. recover_struct_layouts tags each
                     * recovered struct PER VARIABLE (s_<fn>_v54, s_<fn>_v2), so two pointers to
                     * the SAME real struct carry DIFFERENT type names:
                     *     struct s_fun_00009550_v54*v54;
                     *     struct s_fun_00009550_v2 *v2;
                     *     while ((int64_t)(v54) != (int64_t)(v2))   <- cast genuinely REQUIRED
                     * Every struct-pointer comparison therefore looks like a real C4133 type
                     * mismatch, and the cast below is right. The 825 casts are a SYMPTOM of the
                     * per-variable tagging, not of the cast rule. The actual fix is STRUCT
                     * UNIFICATION: two variables with the same recovered layout, compared to or
                     * assigned from each other, are one type and should share one tag. That also
                     * collapses the duplicate struct definitions in every dump. */
                    if ((ap2 || bp2) && !(ap2 && isnull(e->b)) && !(bp2 && isnull(e->a)) &&
                        !(isnull(e->a) || isnull(e->b))) {
                        std::string l = ap2 ? "(long long)(" + rsub(e->a,3) + ")" : rsub(e->a,pp);
                        std::string r = bp2 ? "(long long)(" + rsub(e->b,3) + ")" : rsub(e->b,pp,true);
                        return l + " " + op + " " + r;
                    }
                }
                /* clarity parens: a shift/bitwise operand that is itself an
                 * arithmetic (+,-) or shift expression reads ambiguously, so wrap
                 * it explicitly even though C precedence makes it unnecessary. */
                bool clar = (op=="<<"||op==">>"||op=="&"||op=="^"||op=="|");
                auto operand = [&](const ExprP& x, bool right) -> std::string {
                    std::string s = render(x);
                    bool wrap = prec(x) < pp || (prec(x) == pp && right);
                    if (clar && x && x->kind == EK::Binary) {
                        const std::string& xo = x->op;
                        if (xo=="+"||xo=="-"||xo=="<<"||xo==">>"||
                            xo=="&"||xo=="^"||xo=="|") wrap = true;
                    }
                    return wrap ? "(" + s + ")" : s;
                };
                return operand(e->a, false) + " " + op + " " + operand(e->b, true);
            }
            case EK::Call: {
                /* dynamic_cast recovery: MSVC __RTDynamicCast(p, VfDelta, &srcTD, &dstTD, isRef)
                 * (5 args, dst=arg[3]) / g++ __dynamic_cast(p, &srcTI, &dstTI, hint) (4 args,
                 * dst=arg[2]). When BOTH the dst and its preceding src arg are recovered RTTI
                 * type_info addresses, render `dynamic_cast<Class*>(p)`. Two adjacent
                 * TypeDescriptor pointers are unique to these runtime casts, so no false match.
                 * Gated DS_NO_DYNCAST. */
                if (!e->indirect && !std::getenv("DS_NO_DYNCAST")) {
                    int di = (int)e->args.size() == 5 ? 3 : (int)e->args.size() == 4 ? 2 : -1;
                    auto cst = [](const ExprP& x, uint64_t& o) {
                        if (!x || x->kind != EK::Const || x->is_float) return false;
                        o = (uint64_t)x->cval; return true; };
                    uint64_t drva = 0, srva = 0;
                    if (di >= 1 && cst(e->args[di], drva) && cst(e->args[di - 1], srva) &&
                        !rtti_type_class_for_addr(srva).empty()) {
                        std::string dc = rtti_type_class_for_addr(drva);
                        if (!dc.empty())
                            return "dynamic_cast<" + dc + "*>(" + render(e->args[0]) + ")";
                    }
                }
                /* Indirect call: render the target from the live child so the text
                 * reflects any copy-prop/inlining done after lift (the callee string
                 * is a stale snapshot from construction time). */
                bool vc_rec = false; int64_t vc_off = 0; std::string vc_tag;
                std::string vm = (e->indirect && e->a)
                    ? resolve_virtual_call(e->a, &vc_rec, &vc_off, &vc_tag) : "";
                std::string head = !vm.empty() ? vm
                    : (e->indirect && e->a)
                    ? "((long long(*)())(" + render(e->a) + "))"
                    : e->callee;
                std::string s = head + "(";
                /* A recursive call to THIS function sees its own definition's
                 * prototype, so the call-site arg count MUST equal num_params — a
                 * mis-detected outgoing-arg over/under-count is a hard C2197/C2198
                 * (unlike K&R `()` callees, which accept any arity). Clamp: drop
                 * phantom extra args, pad a short count with 0. */
                if (!e->indirect && !self_fname.empty() && e->callee == self_fname) {
                    for (int i = 0; i < num_params; ++i) {
                        if (i) s += ", ";
                        if (i >= (int)e->args.size()) { s += "0"; continue; }
                        std::string arg = render(e->args[i]);
                        /* cast a recursive-call arg to THIS function's own param type
                         * when they'd mismatch (the proto is known, so C4024/C4047 fire
                         * otherwise): a pointer param fed a non-pointer value (or vice
                         * versa) gets the param-type cast; a bare-matching arg is left. */
                        std::string pt = decl_type("a" + std::to_string(i + 1));
                        bool pt_ptr = !pt.empty() && pt.back() == '*';
                        bool arg_ptr = renders_as_pointer(e->args[i]);
                        bool argIsParam = e->args[i] && e->args[i]->kind == EK::Var &&
                                          e->args[i]->name == "a" + std::to_string(i + 1);
                        if (!pt.empty() && !argIsParam && (pt_ptr != arg_ptr || pt_ptr))
                            arg = "(" + pt + ")(" + arg + ")";
                        s += arg;
                    }
                    s += ")";
                    return s;
                }
                /* A callee with a FIXED-ARITY typed proto (float params) enforces its
                 * exact arg count. Call-site arg recovery is per-site (a float arg in
                 * xmm1 not visibly set at THIS site yields a short count); clamp to the
                 * proto arity — pad missing trailing args with 0, drop phantom extras —
                 * exactly as the self-call clamp does, so the typed proto stays
                 * compile-clean (fixes C2197/C2198 across the float-signature callees). */
                bool dec_api = !e->indirect && api_prefers_decimal_args(e->callee);
                int tp_pc = 0;
                if (!e->indirect && callee_typed_proto_arity(e->callee, tp_pc)) {
                    for (int i = 0; i < tp_pc; ++i) {
                        if (i) s += ", ";
                        if (i >= (int)e->args.size()) { s += "0"; continue; }
                        s += call_arg_text(e->args[i], dec_api);
                    }
                    s += ")";
                    return s;
                }
                for (size_t i = 0; i < e->args.size(); ++i) {
                    if (i) s += ", ";
                    s += call_arg_text(e->args[i], dec_api);   /* call arg = pointer context */
                }
                s += ")";
                /* UNRESOLVED virtual dispatch: the shape was a `*(*obj + off)` vtable call but
                 * no method name was recovered (class unknown, or the slot target is unnamed).
                 * Annotate the slot so the reader sees it IS a virtual dispatch and which slot:
                 * `Class::vfunc_N` when the class is known, else `vtable slot +0xNN`. Comment-only.
                 * DS_NO_VSLOT. */
                if (vm.empty() && vc_rec && !std::getenv("DS_NO_VSLOT")) {
                    int ptrsz = (this->e && this->e->arch == DS_ARCH_X64) ? 8 : 4;
                    if (!vc_tag.empty())
                        s += " /* " + vc_tag + "::vfunc_" + std::to_string(vc_off / ptrsz) + " */";
                    else
                        s += " /* vtable slot +" + hex((uint64_t)vc_off) + " */";
                }
                return s;
            }
        }
        return "0";
    }

