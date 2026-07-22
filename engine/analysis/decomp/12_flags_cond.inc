/* 12_flags_cond.inc -- flag/condition recovery, cc_to_expr, negate
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    ExprP cc_to_expr(CC cc, const FlagSrc& fs) {
        if (!fs.valid) return mkConst(1, 4);
        /* EXPLICIT carry: a shift recorded its shifted-out bit, so the carry codes read
         * it directly. Only CC::B (jc/jb, taken on CF==1) and CC::AE (jnc/jae, CF==0) are
         * determined by CF alone; every other code needs ZF/SF, which the is_arith result
         * below still supplies -- so fall through for those. */
        if (fs.cf && (cc == CC::B || cc == CC::AE)) {
            const char* rel = (cc == CC::B) ? "!=" : "==";
            return fold(mkBinary(rel, clone(fs.cf), mkConst(0, fs.width ? fs.width : 4),
                                 fs.width ? fs.width : 4));
        }
        /* bit test: `bt x,n; jc/jb` => bit set; `jnc/jae` => bit clear. CF holds
         * the tested bit (fs.a already = `(x >> n) & 1`). */
        if (fs.is_bt) {
            bool set = (cc == CC::B);    /* jb/jc taken when CF==1 (bit set) */
            return fold(mkBinary(set ? "!=" : "==", clone(fs.a), mkConst(0, fs.width), fs.width));
        }
        /* float compare: comiss/ucomiss set CF/ZF so the UNSIGNED conditional
         * jumps express the ordering. Emit plain float relops (no unsigned cast). */
        if (fs.is_fcmp) {
            /* comiss/ucomiss set CF/ZF so UNSIGNED jcc express the FP ordering, but
             * the "below"/"below-equal"/unordered-inclusive branches (jb/jbe, taken
             * on CF=1 which the CPU also sets for an UNORDERED/NaN compare) do NOT
             * match C's `<`/`<=` (both false for NaN). Rendering jb as `a < b` drops
             * the NaN case — e.g. arr_abs's `comiss 0,a[i]; jbe skip` (skip when
             * `!(a[i] < 0)` INCLUDING NaN) became `a[i] >= 0` (excludes NaN), so a
             * NaN element got wrongly negated. Emit the unordered-inclusive branches
             * as the negation of their ORDERED complement — `jb => !(a >= b)`,
             * `jbe => !(a > b)` — which is bit-correct for every input, NaN included.
             * ja/jae are ordered (false on NaN) and render directly. */
            std::string fop; bool neg_unord = false;
            switch (cc) {
                case CC::E:  fop = "=="; break;
                case CC::NE: fop = "!="; break;
                case CC::A:  fop = ">";  break;
                case CC::AE: fop = ">="; break;
                case CC::B:  fop = ">="; neg_unord = true; break;  /* jb  = !(a>=b) */
                case CC::BE: fop = ">";  neg_unord = true; break;  /* jbe = !(a>b)  */
                default:     fop = "!="; break;
            }
            ExprP la = clone(fs.a), ra = clone(fs.b);
            /* Canonicalise `const OP var` -> `var FLIP const` so a comiss with the
             * zero/constant in the first operand reads as `a2 < 0.0f`, not the
             * algebraically-equal but jarring `0.0f > a2`. */
            if (la->kind == EK::Const && ra->kind != EK::Const) {
                std::swap(la, ra);
                if (fop == ">") fop = "<"; else if (fop == "<") fop = ">";
                else if (fop == ">=") fop = "<="; else if (fop == "<=") fop = ">=";
            }
            /* a float relation: any bare 0 operand should print as a float zero. */
            if (la->kind == EK::Const) la->is_float = true, la->width = fs.width;
            if (ra->kind == EK::Const) ra->is_float = true, ra->width = fs.width;
            ExprP rel = fold(mkBinary(fop, la, ra, fs.width));
            if (neg_unord) rel = mkUnary("!", rel, 4);
            return rel;
        }
        ExprP L, R;
        bool uns = false;
        std::string op;
        /* An arithmetic SUBTRACTION result feeding a conditional carries exactly
         * the flags of `cmp A, B` (CF/SF/ZF/OF all reflect A - B). Modeling it as
         * `(A - B) OP 0` breaks the CARRY-based unsigned codes — `sub x,k; jae` is
         * `x >= k`, NOT the always-true `(x - k) >= 0u` — and is loose for signed
         * codes too (overflow). Decompose so every condition code is exact. */
        ExprP dA, dB; bool decomposed = false;
        if (fs.is_arith && !fs.is_cmp && !fs.is_test && fs.a &&
            fs.a->kind == EK::Binary && fs.a->op == "-" && fs.a->a && fs.a->b) {
            dA = fs.a->a; dB = fs.a->b; decomposed = true;
        }
        if (fs.is_cmp) { L = clone(fs.a); R = clone(fs.b); }
        else if (fs.is_test) {
            ExprP a = clone(fs.a), bb = clone(fs.b);
            if (exprEqual(fs.a, fs.b)) L = a;
            else L = mkBinary("&", a, bb, fs.width);
            R = mkConst(0, fs.width);
        } else if (decomposed) { L = clone(dA); R = clone(dB); }
        else { L = clone(fs.a); R = mkConst(0, fs.width); }

        switch (cc) {
            /* For a DESTRUCTIVE arithmetic (`sub eax,1; jne` countdown), the ZF
             * reflects the RESULT, so the exit test is `(A-B) == 0`, NOT the
             * operand form `A == B`. Critically, the destination register is
             * OVERWRITTEN by the sub and reused as the loop-carried counter, so the
             * operand form would re-read the just-decremented variable (rendering
             * `t1 == 1` where t1 is already post-decrement => one iteration short).
             * Emitting the result form `(A-B) == 0` lets inject_phis' terminator
             * rebind retarget the back-edge value `A-B` to the post-copy temp,
             * yielding the correct `t1 == 0`. Equality codes only — carry/borrow
             * codes still need the decomposed operands. */
            case CC::E:  op = "=="; if (decomposed) { L = clone(fs.a); R = mkConst(0, fs.width); } break;
            case CC::NE: op = "!="; if (decomposed) { L = clone(fs.a); R = mkConst(0, fs.width); } break;
            case CC::L:  op = "<";  break;
            case CC::LE: op = "<="; break;
            case CC::G:  op = ">";  break;
            case CC::GE: op = ">="; break;
            case CC::B:  op = "<";  uns = true; break;
            case CC::BE: op = "<="; uns = true; break;
            case CC::A:  op = ">";  uns = true; break;
            case CC::AE: op = ">="; uns = true; break;
            /* Sign flag after a COMPARE reflects sign(A - B), not sign(A): a
             * `cmp A,B; cmovns/setns` selects on `A - B >= 0`. Dropping B (forcing
             * the RHS to 0 while keeping L=A) silently loses an operand — e.g. a
             * 2D cross product `a*b - c*d` lowered to `imul; imul; cmp; cmovns`
             * collapsed to `a*b >= 0`, dropping the subtracted second product. For
             * a non-compare source (test / single arithmetic result) SF is the sign
             * of that one value, so L stays as-is. */
            case CC::S:
                op = "<";
                if (fs.is_cmp) L = fold(mkBinary("-", clone(fs.a), clone(fs.b), fs.width));
                else if (decomposed) L = clone(fs.a);   /* fs.a IS A - B */
                R = mkConst(0, fs.width); break;
            case CC::NS:
                op = ">=";
                if (fs.is_cmp) L = fold(mkBinary("-", clone(fs.a), clone(fs.b), fs.width));
                else if (decomposed) L = clone(fs.a);
                R = mkConst(0, fs.width); break;
            /* PARITY on an INTEGER test. A float compare's jp/jnp is the unordered
             * (NaN) test and is handled on the is_fcmp path above, which returns before
             * this switch — so reaching here means the x87 compare idiom
             * `fnstsw ax; test ah, <mask>; jp`, whose mask selects the C0/C2 status
             * bits. PF is the EVEN parity of the result byte: with C2 clear (operands
             * ordered) at most one selected bit can be set, so jp is taken exactly when
             * the masked result is ZERO. The `!=` default was the precise INVERSE of
             * that, silently flipping every x87 comparison's sense. */
            case CC::P:  op = "=="; break;
            case CC::NP: op = "!="; break;
            default:     op = "!="; break;
        }
        /* A sub-word cmp operand is zero-extended by `movzx` but rvalue()/truncate()
         * wraps it in a SIGNED narrowing cast (`(signed char)`). For an UNSIGNED code
         * (jb/jae/ja/jbe) or an EQUALITY (je/jne) that inverts the meaning: with a byte
         * b>=0x80, `(signed char)b == 0xED` is a tautology and `(unsigned)((signed
         * char)b) < 0xE0` sign-extends — both silently miscompile UTF-8 / byte-class
         * tests. Flip the narrowing cast to unsigned. Signed codes (jl/jg) and the
         * sign test (js/jns) are left signed, which is what they need. */
        if ((uns || cc == CC::E || cc == CC::NE) && fs.width < 4) {
            L = flip_trunc_unsigned(L);
            R = flip_trunc_unsigned(R);
        }
        return fold(mkBinary(op, L, R, fs.width, uns));
    }

    /* Flip a SIGNED narrowing cast (`(signed char)`/`(short)`) to its unsigned form so
     * a movzx'd operand compares as the unsigned byte/word the hardware used. */
    ExprP flip_trunc_unsigned(ExprP e) {
        if (!e || e->kind != EK::Cast) return e;
        if (e->op == "(signed char)" || e->op == "(char)")
            return mkCast("(unsigned char)", e->a, e->width, true);
        if (e->op == "(short)")
            return mkCast("(unsigned short)", e->a, e->width, true);
        return e;
    }

