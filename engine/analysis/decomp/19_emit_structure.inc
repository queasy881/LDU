/* 19_emit_structure.inc -- statement/label emission, structuring
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Does this statement CALL something that never returns? Everything after it in the block
     * is then unreachable, and printing it asserts the program does things it cannot:
     *     __fastfail(5);          <- int 0x29, the process is gone
     *     fun_0005d820();         <- dead
     *     a1->field_0 = NULL;     <- dead
     * Three sources, all facts rather than guesses: the fail-fast intrinsic; an IMPORT the SDK
     * really marks DECLSPEC_NORETURN; and a LOCAL that build_sig_table proved has no `ret` and
     * ends in a trap. DS_NO_NORETURN. */
    bool stmt_calls_noreturn(const Stmt& s) {
        if (std::getenv("DS_NO_NORETURN")) return false;
        if (s.kind != SK::Call || !s.rhs || s.rhs->kind != EK::Call) return false;
        const std::string& c = s.rhs->callee;
        if (c == "__fastfail") return true;
        static const char* NR[] = {"ExitProcess","ExitThread","FreeLibraryAndExitThread",
                                   "RaiseFailFastException","abort","exit","_exit","_Exit",
                                   "quick_exit","longjmp","_invoke_watson","RtlRaiseStatus",
                                   "TerminateProcess", nullptr};
        for (int i = 0; NR[i]; ++i) if (c == NR[i]) return true;
        uint64_t crva = 0;
        if (sigtab && callee_rva_of(c, crva)) {
            auto it = sigtab->find(crva);
            if (it != sigtab->end() && it->second.is_noreturn) return true;
        }
        return false;
    }
    void emit_stmts(int id, std::string& dst) {
        if (iv_suppressed_stmts.empty()) {
            for (auto& s : blocks[id].stmts) {
                emit_stmt(s, dst);
                if (stmt_calls_noreturn(s)) return;   /* the rest of this block is unreachable */
            }
            return;
        }
        for (size_t i = 0; i < blocks[id].stmts.size(); ++i) {
            if (iv_suppressed_stmts.count({id, (int)i})) continue;   /* for-loop init/incr */
            emit_stmt(blocks[id].stmts[i], dst);
            if (stmt_calls_noreturn(blocks[id].stmts[i])) return;
        }
    }

    /* A pointer-typed destination (`dt` ends in `*`) assigned a value that does not
     * already render as that exact pointer type needs an explicit cast — otherwise
     * the output has a silent int<->ptr / mismatched-ptr conversion (C4047/C4133,
     * which Hex-Rays writes as `p = (int *)a1[1];`). The cast is a pure reinterpret
     * on x64 (all pointers/longs are 64-bit), so it never changes the value. */
    /* The pointer type the RENDERER actually emits for `base` (mirrors the render of a
     * Binary +/- base). A TYPED pointer var (ptr_elem_width>1) is byte-cast to
     * `(char*)base + off` -> renders as char-ptr, NOT its declared element type; a
     * char-ptr / void-ptr var (elem<=1) or a bare var renders as its declared type; a
     * `(T*)x` cast renders as that T-ptr. Empty = unknown (force a cast). This makes
     * the assignment-cast decision match reality: `long long* t = a1 + 0x140` renders
     * `(char*)a1 + 0x140` (char*) and so DOES need the `(long long*)` cast. */
    std::string rendered_ptr_type(const ExprP& b) {
        if (!b) return "";
        if (b->kind == EK::Cast && b->op.size() >= 3 && b->op.front() == '(' &&
            b->op.back() == ')' && b->op.find('*') != std::string::npos)
            return b->op.substr(1, b->op.size() - 2);          /* "(T*)" -> "T*" */
        if (b->kind == EK::Var) {
            if (array_locals.count(b->name)) return "char*";   /* array decays to char* */
            auto it = ptr_elem_width.find(b->name);
            if (it != ptr_elem_width.end() && it->second > 1) return "char*"; /* byte-cast */
            return decl_type(b->name);
        }
        return "";
    }
    bool ptr_assign_needs_cast(const ExprP& r, const std::string& dt) {
        if (!r) return false;
        switch (r->kind) {
            case EK::Const:  return !(r->cval == 0 && !r->is_float);  /* null needs none */
            case EK::Var:    return decl_type(r->name) != dt;
            case EK::Cast:   return r->op != "(" + dt + ")";          /* already this cast? */
            case EK::AddrOf:  /* `&x` has x's-type* — cast when the dest differs (`int* t
                               * = &a2` where a2 is long long is C4133). Over-cast of a
                               * matching type is harmless. */
                             return true;
            case EK::Binary:
                if (r->op == "+" || r->op == "-") {
                    /* `ptr + ptr` is C2110, so the renderer integer-casts BOTH operands
                     * -> the rendered result is a `long long`, never the pointer type,
                     * so a pointer dest always needs the cast (t381 = t380 + a2). */
                    if (r->op == "+" && renders_as_pointer(r->a) && renders_as_pointer(r->b))
                        return true;
                    /* else the pointer operand is the base: r->a for `-`; for `+` the
                     * side that renders as a pointer. Cast unless its RENDERED type == dt. */
                    const ExprP& base = (r->op == "-")
                        ? r->a
                        : (!rendered_ptr_type(r->a).empty() ? r->a : r->b);
                    std::string rt = rendered_ptr_type(base);
                    if (!rt.empty() && rt == dt) return false;
                }
                return true;
            default:         return true;   /* Mem load, Call, Ternary, ... -> cast */
        }
    }

    /* Does `e` RENDER as a pointer type? Mirrors the renderer (not expr_is_pointer,
     * which conflates value-flow): a cast's pointer-ness is its cast op (`(long long)p`
     * is NOT a pointer, `(T*)x` IS); a var by var_pointer; `ptr ± i` if either side is. */
    bool renders_as_pointer(const ExprP& e) {
        if (!e) return false;
        switch (e->kind) {
            case EK::Cast:   return e->op.find('*') != std::string::npos;
            case EK::AddrOf: return true;
            case EK::Var: {  /* authoritative: the DECLARED type (covers pointer params
                              * whose var_pointer flag is not set), an array (char*), OR a
                              * ptr_elem_width>1 var — the renderer byte-casts THAT to
                              * `(char*)v` in arithmetic even when it's declared long long
                              * (`long long t3; ... (char*)t3 + 0x10`), so it renders as a
                              * pointer and must be treated as one. */
                if (array_locals.count(e->name)) return true;
                std::string dt = decl_type(e->name);
                if (!dt.empty() && dt.back() == '*') return true;
                auto it = ptr_elem_width.find(e->name);
                return it != ptr_elem_width.end() && it->second > 1;
            }
            case EK::Mem:    return is_struct_ptr_field(e);   /* `a1->field_8` where field_8 is void* */
            case EK::Binary: return (e->op == "+" || e->op == "-") &&
                                    (renders_as_pointer(e->a) || renders_as_pointer(e->b));
            case EK::Ternary: /* after arm coercion, a ternary is a pointer iff BOTH arms are */
                             return renders_as_pointer(e->b) && renders_as_pointer(e->c);
            default:         return false;
        }
    }
    void emit_stmt(const Stmt& s, std::string& dst) {
        size_t emit_start = dst.size();
        switch (s.kind) {
            case SK::Assign: {
                std::string l = render(s.lhs);
                /* Strip a redundant same-width integer cast on the RHS: a store to
                 * an integer variable truncates the value to the variable's width,
                 * so `v = (unsigned int)X;` is bit-identical to `v = X;` when v is a
                 * 32-bit int and X is an integer. Only fires for a plain integer
                 * dest of EXACTLY the cast width and an integer source (never a
                 * ptr/float reinterpret) — precisely the case where none of the
                 * pointer/float reconciliation below applies. DS_NO_ASGNCASTCLEAN. */
                ExprP arhs = s.rhs;
                if (arhs && arhs->kind == EK::Cast && arhs->a &&
                    !arhs->is_float && !arhs->a->is_float &&
                    s.lhs && s.lhs->kind == EK::Var && !std::getenv("DS_NO_ASGNCASTCLEAN") &&
                    (arhs->op == "(int)" || arhs->op == "(unsigned int)" ||
                     arhs->op == "(short)" || arhs->op == "(unsigned short)" ||
                     arhs->op == "(char)" || arhs->op == "(unsigned char)" ||
                     arhs->op == "(signed char)" ||
                     arhs->op == "(long long)" || arhs->op == "(unsigned long long)")) {
                    std::string dt = decl_type(s.lhs->name);
                    auto wit = var_width.find(s.lhs->name);
                    int lw = (wit != var_width.end()) ? wit->second : 0;
                    bool lhs_int = !dt.empty() && dt.back() != '*' && dt != "float" && dt != "double";
                    if (lhs_int && lw > 0 && lw == arhs->width && !renders_as_pointer(arhs->a))
                        arhs = arhs->a;
                }
                std::string r = render(arhs);
                if (l == r) break;     /* drop self-assign */
                /* The UNRECONCILED renderings. Everything below may wrap `l` or `r` in a cast
                 * to make the assignment legal C; the compound fold at the bottom re-renders
                 * from the AST and would silently DROP that cast. Keeping the originals lets it
                 * detect "a cast was added here" and decline. */
                const std::string l_plain = l, r_plain = r;
                if (s.lhs && s.rhs) {
                    auto wrapstr = [&](const std::string& x) {
                        return (s.rhs->kind == EK::Binary || s.rhs->kind == EK::Ternary)
                               ? "(" + x + ")" : x;
                    };
                    bool rhs_ptr = renders_as_pointer(s.rhs);
                    /* A resolved string literal (`lea rcx,[rodata]`) is a `char*`. Assigned
                     * to an INTEGER lvalue (a struct field / spill the recovery typed
                     * int64_t) it is C4047 without a cast — `field_40 = "(null)"` must read
                     * `field_40 = (long long)"(null)"`, exactly as an integer dest <- pointer
                     * value already does below. Only affects integer dests; a real char*
                     * dest is handled by the pointer-dest arm and stays cast-free. */
                    bool rhs_str = s.rhs && s.rhs->kind == EK::Str;
                    if (s.lhs->kind == EK::Var) {
                        std::string dt = decl_type(s.lhs->name);
                        if (!dt.empty() && dt.back() == '*') {
                            /* ptr dest <- other. Cast when ptr_assign_needs_cast says so,
                             * when the RHS does not RENDER as a pointer, OR when the
                             * RENDERED string shows the renderer integerized the operands
                             * (`(int)x + (long long)y`): the AST predicates look THROUGH
                             * casts (expr_is_pointer treats `(int)ptr` as a pointer) and
                             * disagree with the actual render, so the rendered text is the
                             * authority — a `(long long)`/`(int)` operand cast means the
                             * result is an integer and a pointer dest needs the cast. */
                            bool isnull = s.rhs->kind == EK::Const && s.rhs->cval == 0 && !s.rhs->is_float;
                            bool render_intized = (s.rhs->kind == EK::Binary) &&
                                (r.find("(long long)") != std::string::npos ||
                                 r.find("(int)") != std::string::npos) &&
                                r.compare(0, dt.size() + 1, "(" + dt) != 0;
                            if (!isnull && (ptr_assign_needs_cast(s.rhs, dt) || !rhs_ptr || render_intized))
                                r = "(" + dt + ")" + wrapstr(r);
                        } else if (rhs_ptr || rhs_str) {                  /* int dest <- ptr / string */
                            r = "(long long)" + wrapstr(r);
                        } else if (s.rhs->is_float && dt != "float" && dt != "double") {
                            /* a FLOAT value stored into an INTEGER-typed variable is a
                             * bit store (`movss/movsd [slot],xmm`), NOT a value cast: the
                             * var is a spill / outgoing-stack-arg cell that carries the
                             * float BITS (a later call reads them as a float arg). Without
                             * this, C converts `v3 = 1.5f` to `1` (truncation), corrupting
                             * the argument. Reinterpret the destination to keep the bits.
                             * A genuine float->int conversion carries an explicit (int)
                             * cast (rhs not is_float), so it is untouched. */
                            int fw = (s.rhs->width >= 8) ? 8 : 4;
                            /* A 4-byte "float" Const whose IEEE-754 bits are a SUBNORMAL
                             * (exponent field zero, mantissa non-zero) is almost never a
                             * real float literal -- it is a small integer FLAG mis-floated
                             * into a denormal (e.g. `mov dword[slot],0x40800`, an outgoing
                             * stack-arg cell reused by a neighbouring movss). Floating it
                             * prints garbage (`3.70212e-40f`); emit the integer bit store
                             * instead -- the SAME 4-byte pattern, read as the real flag.
                             * Normal patterns (1.0f=0x3f800000, -1.0f=0xbf800000,
                             * FLT_MAX=0x7f7fffff) carry a non-zero exponent and stay float. */
                            uint32_t fbits = (uint32_t)(uint64_t)s.rhs->cval;
                            if (fw == 4 && s.rhs->kind == EK::Const &&
                                ((fbits >> 23) & 0xff) == 0 && (fbits & 0x7fffff) != 0) {
                                char ibuf[32];
                                std::snprintf(ibuf, sizeof ibuf, "0x%x", (unsigned)fbits);
                                l = "*(int32_t*)&" + l;
                                r = ibuf;
                            } else {
                                l = std::string("*(") + (fw == 8 ? "double" : "float") + "*)&" + l;
                            }
                        }
                    } else if (s.lhs->kind == EK::Mem && !struct_ptr_field_tag(s.lhs).empty()) {
                        /* store into a retyped `struct T*` field: make the value's type
                         * explicit (an int address -> the struct ptr, or a different ptr ->
                         * this ptr) instead of an implicit int<->ptr conversion (C4047). */
                        std::string tag = struct_ptr_field_tag(s.lhs);
                        bool isnull = s.rhs->kind == EK::Const && s.rhs->cval == 0 && !s.rhs->is_float;
                        std::string want = "(struct " + tag + "*)";
                        if (!isnull && r.compare(0, want.size(), want) != 0)
                            r = want + wrapstr(r);
                    } else if (s.lhs->kind == EK::Mem && is_struct_ptr_field(s.lhs) && s.rhs->is_float) {
                        /* G4: a FLOAT value stored into a `void*` field is a bit store
                         * (`movss/movsd [field],xmm`), NOT a value cast (float->void* = C2440).
                         * collect_struct_access records `ff` from the FIRST access at an offset,
                         * so a pointer-use load seen before a same-offset float store leaves the
                         * field typed void* with a float store surviving. Reinterpret the field
                         * lvalue to keep the 8-byte pattern (mirrors the Var-dest idiom above). */
                        int fw = (s.rhs->width >= 8) ? 8 : 4;
                        l = std::string("*(") + (fw == 8 ? "double" : "float") + "*)&(" + l + ")";
                    } else if (s.lhs->kind == EK::Mem && is_struct_ptr_field(s.lhs) &&
                               s.rhs->kind == EK::Cast && s.rhs->a && renders_as_pointer(s.rhs->a) &&
                               (s.rhs->op == "(int64_t)" || s.rhs->op == "(long long)" ||
                                s.rhs->op == "(uint64_t)" || s.rhs->op == "(unsigned long long)")) {
                        /* `void* field = (int64_t)ptr` — the recovery boxed a pointer value in
                         * an integer cast to match the 8-byte store width, but the field itself
                         * is a pointer. Drop the int cast: `field = ptr` (a struct-ptr or char-ptr
                         * to void-ptr is a valid implicit conversion) reads clean and is C4047-free,
                         * where `field = (int64_t)ptr` warned and obscured that a pointer is stored. */
                        r = render(s.rhs->a);
                    } else if (s.lhs->kind == EK::Mem && (rhs_ptr || rhs_str) && !s.lhs->is_float) {
                        /* a pointer value stored into a scalar memory slot: make the
                         * ptr->int reinterpret explicit (else C4047). A width-8 slot is
                         * clean (long long); a width-4 `*(int*)` slot narrows (that
                         * residual C4244 is a genuine truncation, in the left-alone set). */
                        r = "(long long)" + wrapstr(r);
                    }
                }
                /* VTABLE POINTER STORE: a constructor storing a known vtable into a class's
                 * __vftable (field_0) — resolve the raw address to the seeded symbol so it reads
                 * `obj->__vftable = &<Class>__vftable;` instead of a magic number. Scoped to an
                 * is_class field_0 store so it never misfires on a coincidental constant. */
                {
                    ExprP rc = s.rhs; while (rc && rc->kind == EK::Cast) rc = rc->a;
                    std::string bp; int64_t boff;
                    if (rc && rc->kind == EK::Const && s.lhs && s.lhs->kind == EK::Mem && s.lhs->a &&
                        struct_base_offset(s.lhs->a, bp, boff) && boff == 0 &&
                        param_structs.count(bp) && param_structs[bp].is_class) {
                        std::string vraw = class_for_vtable((uint64_t)rc->cval);
                        if (!vraw.empty()) {
                            std::string sym = sani(vraw) + "__vftable";
                            r = "&" + sym; referenced_vtables.insert(sym);
                        }
                    }
                }
                /* COMPOUND ASSIGNMENT / INCREMENT. `v1 = v1 + *v2` is what the machine does;
                 * `v1 += *v2` is what the source said, and every loop body in the binary is
                 * full of the long form (measured: 1031 `v = v <op> x` and 827 `v = v + 1`).
                 *
                 * Done on the FINAL RENDERED TEXT, deliberately. Everything above this point
                 * reconciles pointer/float/struct types and may have wrapped either side in a
                 * cast; folding earlier would have to re-derive all of that. Here the only
                 * question left is whether the destination text is repeated verbatim as the
                 * first operand -- if it is, `l op= rest` is the same statement by definition,
                 * for any l, including `a1->field_8` and `*(int*)(x)`.
                 *
                 * REQUIRES the RHS to be a top-level Binary whose left operand rendered to
                 * EXACTLY the destination string. `l` must have no side effects to be written
                 * once instead of twice -- it is an lvalue we just rendered, so it cannot, but
                 * a CALL inside it could, hence the has_call guard.
                 * Only the operators where `x op= y` is identical to `x = x op y` in C: the
                 * shift/arith/bitwise set. NOT `-` with a pointer dest (`p = p - n` is fine as
                 * `p -= n`, but the renderer may have integerized it, so the text test decides).
                 * DS_NO_COMPOUND. */
                if (!std::getenv("DS_NO_COMPOUND") && s.rhs && s.rhs->kind == EK::Binary &&
                    s.rhs->a && s.rhs->b && !has_call(s.rhs->a) &&
                    /* A CAST WAS ADDED ABOVE -> do not fold, it would be dropped. Measured:
                     *     v21 = (int32_t*)(v21 & 0x7f)      <- the cast is what makes it legal
                     *     v21 &= 0x7f                       <- C2296 on fn_00084b90
                     * The reconciliation above knows things the AST does not (it compares
                     * RENDERED pointer-ness), so if it decided a cast was needed, the long form
                     * is the only correct output. */
                    l == l_plain && r == r_plain) {
                    static const char* OPS[] = {"+","-","*","/","%","&","|","^","<<",">>",nullptr};
                    bool ok = false;
                    for (int i = 0; OPS[i]; ++i) if (s.rhs->op == OPS[i]) { ok = true; break; }
                    /* A POINTER destination only accepts += and -=. `p &= m` / `p |= m` /
                     * `p *= n` are C2296 regardless of any cast: C has no such operator for a
                     * pointer. The long form survives because the renderer casts the whole RHS
                     * back to the pointer type. */
                    if (ok && renders_as_pointer(s.lhs) && s.rhs->op != "+" && s.rhs->op != "-")
                        ok = false;
                    if (ok) {
                        std::string la = render(s.rhs->a);
                        if (la == l) {
                            std::string rb = render(s.rhs->b);
                            /* `x = x + 1` -> `++x`; `x = x - 1` -> `--x`. Only for a plain
                             * integer destination: `p = p + 1` on a TYPED pointer advances by
                             * sizeof(*p), which is what the C already says, so ++ is equally
                             * correct there -- but a float `f = f + 1` is not an increment
                             * idiom a reader expects, so it keeps the long form. */
                            bool int_dst = !(s.lhs->kind == EK::Var &&
                                             (decl_type(s.lhs->name) == "float" ||
                                              decl_type(s.lhs->name) == "double"));
                            if (int_dst && rb == "1" && (s.rhs->op == "+" || s.rhs->op == "-")) {
                                dst += ind() + (s.rhs->op == "+" ? "++" : "--") + l + ";\n";
                                break;
                            }
                            dst += ind() + l + " " + s.rhs->op + "= " + rb + ";\n";
                            break;
                        }
                    }
                }
                dst += ind() + l + " = " + r + ";\n";
                break;
            }
            case SK::Call:
                dst += ind() + render(s.rhs) + ";\n";
                break;
            case SK::Return:
                if (s.ret_void || !s.rhs) dst += ind() + "return;\n";
                else dst += ind() + "return " + render_return_expr(s.rhs) + ";\n";
                break;
            case SK::Goto:
                dst += ind() + "goto " + s.label + ";\n";
                break;
            case SK::Label:
                dst += s.label + ":;\n";
                break;
            case SK::Comment:
                dst += ind() + "/* " + s.label + " */\n";
                break;
        }
        /* Frontend line<->address sync: tag real statements with their source
         * instruction address as a trailing marker comment. Gated on DS_LINE_ADDR
         * so the gates / corpus / batch dumper (which call decompile() directly)
         * never see it -- only the interactive get_pseudocode path sets it. Only
         * Assign/Call/Return get a marker: Label/Goto/Comment lines are matched by
         * exact text in later passes and must stay pristine. */
        if (s.addr && dst.size() > emit_start && dst.back() == '\n' &&
            (s.kind == SK::Assign || s.kind == SK::Call || s.kind == SK::Return) &&
            std::getenv("DS_LINE_ADDR")) {
            char buf[32];
            std::snprintf(buf, sizeof buf, "/*@%llx*/", (unsigned long long)s.addr);
            dst.insert(dst.size() - 1, buf);
        }
    }

    /* a switch selector must be INTEGRAL; a float-typed selector (mis-inferred) is
     * C2050. Reinterpret its bits (lvalue) or value-cast so it compiles. */
    std::string switch_sel(const ExprP& e) {
        if (!e) return "0";
        bool fl = e->is_float;
        if (e->kind == EK::Var) {
            std::string dt = decl_type(e->name);   /* catches force_float too */
            if (dt == "float" || dt == "double") fl = true;
        }
        if (fl) {
            if (e->kind == EK::Var) return "*(int*)&" + rsub(e, 14);
            if (e->kind == EK::Mem && e->a) return "*(int*)(" + render_addr(e->a) + ")";
            return "(int)(" + render(e) + ")";
        }
        /* A pointer-typed selector is not integral (C2050); a switch on it means the
         * value is really a small integer sharing that register. Cast to `long long`. */
        if (e->kind == EK::Var) {
            std::string dt = decl_type(e->name);
            if (!dt.empty() && dt.back() == '*') return "(long long)" + rsub(e, 14);
        }
        /* The Var check above misses a pointer-valued EXPRESSION, e.g. `switch (a2 - 0x100)`
         * when a2 is a pointer param: `a2 - 0x100` is still a pointer (C2050). expr_is_pointer
         * walks binary +/-, casts and addr-of, so it catches the composite selector. A ptr-ptr
         * difference is already integral, and wrapping it in a redundant (long long) is harmless. */
        if (expr_is_pointer(e)) return "(long long)(" + render(e) + ")";
        return render(e);
    }

    /* Render a return value with a ptr<->int coercion so the `return` is not C4047:
     * an int-returning fn returning a pointer value gets `(long long)`; a pointer-
     * returning fn returning a non-pointer/mismatched value gets the return ptr cast. */
    /* E4: `(X & K) | Y` where K clears the low byte (K & 0xFF == 0) — the high bytes are
     * stale caller-preserved bits and only the low byte (Y) is the real value. Returns Y
     * (recursing). Used ONLY when the return type is a single byte, so this is provably
     * observable-bits-neutral (the caller reads only AL). */
    ExprP strip_ret_byte_mask(const ExprP& e) {
        if (!e || e->kind != EK::Binary || e->op != "|" || !e->a || !e->b) return e;
        auto low_masked = [](const ExprP& s)->bool {
            return s && s->kind == EK::Binary && s->op == "&" && s->b &&
                   s->b->kind == EK::Const && ((uint64_t)s->b->cval & 0xFFu) == 0;
        };
        if (low_masked(e->a)) return strip_ret_byte_mask(e->b);
        if (low_masked(e->b)) return strip_ret_byte_mask(e->a);
        return e;
    }
    std::string render_return_expr(const ExprP& rhs) {
        /* E4: a byte (bool/char) return keeps only AL meaningful, so a stale-high-byte
         * merge `(v3 & -256) | 1` is just `1`. Strip it BEFORE rendering. Gated on the
         * single-byte return type => the dropped high bytes are unobservable. */
        if (rhs && !ret_is_float && !ret_is_pointer && (ret_small_w == 1 || ret_byte_return)) {
            ExprP s = strip_ret_byte_mask(rhs);
            if (s != rhs) return render_return_expr(s);
        }
        std::string rv = render(rhs);
        if (!rhs) return rv;
        bool wrap = rhs->kind == EK::Binary || rhs->kind == EK::Ternary;
        auto wr = [&](const std::string& c){ return c + (wrap ? "(" + rv + ")" : rv); };
        /* the function returns FLOAT/DOUBLE (xmm0) but the return value is an
         * INTEGER-typed lvalue holding the float BITS — a `v.u &= mask; return v.d`
         * union idiom where the modified integer slot IS the returned double
         * (d_fabs). Reinterpret the bits, don't value-convert (`(double)(long long)`
         * would turn 0x3fc0000000000000 into 4.6e18). A genuine `(float)n` conversion
         * carries an explicit Cast (is_float), so a bare int lvalue here is always a
         * bit return. */
        if (ret_is_float && !ret_is_pointer) {
            const char* ft = (ret_width >= 8) ? "double" : "float";
            /* the DECLARED type is the authority: a var declared `long long` (because
             * it was bit-mutated `a1 = *(long long*)&a1 & mask`) but read back by a
             * final `movsd xmm0,[slot]` carries an is_float NODE flag that disagrees
             * with its integer decl — reinterpret its bits so `return a1` is
             * `*(double*)&a1`, not the value-converting `(double)a1`. */
            if (rhs->kind == EK::Var) {
                std::string dt = decl_type(rhs->name);
                if (dt != "float" && dt != "double" && !(dt.size() && dt.back() == '*'))
                    return std::string("*(") + ft + "*)&" + rv;
            } else if (rhs->kind == EK::Mem && rhs->a && !rhs->is_float) {
                return std::string("*(") + ft + "*)(" + render_addr(rhs->a) + ")";
            }
        }
        if (!ret_is_pointer) {
            /* cast a pointer value (or a call whose result may be a pointer — ret_kind
             * 2 is `long long` OR pointer, indistinguishable) to (long long) so a
             * non-pointer-returning fn's `return ptr` / `return fun_x()` is not C4047. */
            if (renders_as_pointer(rhs) || (rhs->kind == EK::Call && rhs->ret_kind == 2))
                rv = wr("(long long)");
        } else {
            /* pointer return: cast the value to the EXACT return pointer type unless it
             * is already a cast to that type (covers both a non-pointer value AND a
             * DIFFERENT pointer type — `return a1` where a1 is float* but ret is int* is
             * C4133). An explicit `(T*)` reinterpret never warns; a bare-matching return
             * is over-cast harmlessly. Null stays null. */
            std::string rt = render_return_type_str();
            bool isnull = rhs->kind == EK::Const && rhs->cval == 0 && !rhs->is_float;
            bool already = rhs->kind == EK::Cast && rhs->op == "(" + rt + ")";
            /* A variable ALREADY declared at the return type needs no cast: once the return
             * type follows the returned struct pointer (ret_struct_type), `return (struct
             * Vec3*)a1` where a1 IS a `struct Vec3*` is pure noise. Only skip the cast when
             * the declared type matches exactly, so every reinterpreting return keeps its
             * cast and its C4133-silence. */
            bool same_ty = rhs->kind == EK::Var && decl_type(rhs->name) == rt;
            if (!isnull && !already && !same_ty) rv = wr("(" + rt + ")");
        }
        return rv;
    }
    std::string render_return_type_str() {
        if (!ret_is_pointer) return "long long";
        if (!ret_struct_ty().empty()) return ret_struct_ty();
        std::string base = ret_ptr_elem_float ? (ret_ptr_elem_w >= 8 ? "double" : "float")
                         : typ_str(ret_ptr_elem_w ? ret_ptr_elem_w : 1, ret_ptr_elem_uns, false);
        return base + "*";
    }
    std::string ret_text(int id) {
        Block& B = blocks[id];
        if (B.tail_call) {
            /* tail call: return the callee result (or just call it for void) */
            if (!used_return) return render(B.tail_call) + ";\n    return;";
            return "return " + render_return_expr(B.tail_call) + ";";
        }
        if (!used_return) return "return;";
        if (B.has_ret_value)
            return "return " + render_return_expr(B.ret_value) + ";";
        return "return 0;";
    }

    /* ---------- recursive structurer ---------- */
    /* We structure a reducible CFG by recursive descent over the dominator tree
     * combined with the natural-loop and immediate-post-dominator info. The
     * algorithm follows the practical scheme:
     *   - a loop header => emit while/do-while/for over the loop body, recursing
     *     on the body up to the back-edge.
     *   - a 2-way branch whose arms rejoin at the immediate post-dominator =>
     *     if/else, recursing on each arm, then continuing at the join.
     *   - a switch dispatch => switch{} with case bodies recursing to the join.
     *   - otherwise a straight-line block followed by its single successor.
     * Anything that does not fit (irreducible, computed fallthrough we cannot
     * prove) degrades to a goto to the target, with that target emitted as a
     * labeled region elsewhere. We guard recursion depth and a visited set so we
     * always terminate. */

    std::set<int> structured;   /* blocks already emitted structurally */
    std::set<int> threaded;     /* empty goto-landing blocks absorbed into a
                                   break/continue — re-thread, never goto them */
    int struct_guard = 0;
    bool struct_bailed = false;  /* set when struct_guard trips: the structured body
                                  * is INCOMPLETE (a region was dropped), so the whole
                                  * function must fall back to the complete goto-CFG. */

    bool reaches_only_via(int from, int stop) { (void)from; (void)stop; return true; }

    /* Follow a chain of empty (statement-free) unconditional-jump blocks to the
     * real target. /Od + our block splitting create tiny "L_x: goto L_y" landing
     * blocks; threading through them lets break/continue/return detection see the
     * actual loop header / follow / epilogue instead of an intermediate label. */
    int thread_target(int b) {
        std::set<int> seen;
        while (b >= 0 && !seen.count(b)) {
            seen.insert(b);
            Block& B = blocks[b];
            /* Stop at a real emitted block, but walk THROUGH blocks already
             * absorbed into a break/continue (threaded) — a later reference to
             * such a landing block must resolve to the same loop edge, not a
             * goto to a label that was never written. */
            if (structured.count(b) && !threaded.count(b)) break;
            bool empty = true;
            for (auto& s : B.stmts) if (s.kind != SK::Comment) { empty = false; break; }
            if (empty && B.ends_jmp && !B.ends_jcc && B.taken >= 0) { b = B.taken; continue; }
            break;
        }
        return b;
    }

    /* When an arm is converted to break/continue, the empty goto-only landing
     * blocks we threaded over become unreachable in the structured form. Mark
     * them `structured` so the leftover-block pass doesn't re-emit them (which
     * would create a dangling goto and revert the whole function). */
    void mark_threaded(int b) {
        std::set<int> seen;
        while (b >= 0 && !seen.count(b)) {
            seen.insert(b);
            Block& B = blocks[b];
            if (structured.count(b) && !threaded.count(b)) break;
            bool empty = true;
            for (auto& s : B.stmts) if (s.kind != SK::Comment) { empty = false; break; }
            if (empty && B.ends_jmp && !B.ends_jcc && B.taken >= 0) {
                structured.insert(b);
                threaded.insert(b);
                b = B.taken;
                continue;
            }
            break;
        }
    }

    static bool expr_has_call(const ExprP& e) {
        if (!e) return false;
        if (e->kind == EK::Call) return true;
        if (expr_has_call(e->a) || expr_has_call(e->b) || expr_has_call(e->c)) return true;
        for (auto& x : e->args) if (expr_has_call(x)) return true;
        return false;
    }
    /* A block whose statements are side-effect free (only Var assignments with no
     * embedded call; no memory stores, no calls) — safe to duplicate. */
    bool block_dup_safe(int id) {
        for (auto& s : blocks[id].stmts) {
            if (s.kind == SK::Comment) continue;
            if (s.kind == SK::Assign && s.lhs && s.lhs->kind != EK::Mem && !expr_has_call(s.rhs))
                continue;
            return false;
        }
        return true;
    }
    /* If `b` begins a short, branch-free, side-effect-free region that ends in a
     * return, emit it INLINE (duplicate) and return true. Return regions are
     * duplicate-safe, so duplicating a shared `set result; return` landing avoids
     * a dangling goto (which would revert the whole function to a goto-CFG). This
     * is exactly what Hex-Rays does with shared return epilogues. */
    bool try_emit_return_dup(int b, std::string& dst) {
        std::vector<int> chain;
        std::set<int> seen;
        int cur = b;
        while (cur >= 0 && !seen.count(cur) && chain.size() < 12) {
            seen.insert(cur);
            Block& C = blocks[cur];
            if (C.ends_jcc || C.is_switch) return false;
            /* A STRAIGHT-LINE return tail is reached once per path, so duplicating it
             * — including its memory stores / calls (e.g. `out[len]=0; return len`, a
             * shared epilogue of an inlined memcpy) — is semantically safe; only the
             * no-branch/no-loop SHAPE matters, not side-effect freedom. Bounded by
             * dup_budget so the duplication can't blow up. (The old block_dup_safe
             * gate rejected any store, forcing the whole /O2 function to a state
             * machine over one shared `out[len]=0; return`.) */
            chain.push_back(cur);
            /* Terminal tail = a block with NO in-function successor: an explicit
             * `ret`, OR a noreturn-call/`int3` error block (`fun_x(); int3` — fall
             * is -1), OR a tail-call `jmp` (taken is -1). All three render via
             * ret_text and are reached once per path, so duplicating them at each
             * goto site is behavior-safe and eliminates the goto. Previously ONLY
             * `ends_ret` counted, so a shared noreturn error block (fun_00074590();
             * int3, reached from 3 sites) forced the whole function to a state
             * machine over two `goto`s (fn_00060380 and many like it). */
            int nxt = C.ends_jmp ? C.taken : (C.ends_ret ? -1 : C.fall);
            if (C.ends_ret || nxt < 0) {
                for (int id : chain) { emit_stmts(id, dst); structured.insert(id); }
                dst += ind() + ret_text(chain.back()) + "\n";
                return true;
            }
            cur = nxt;
        }
        return false;
    }

    int dup_budget = 0;   /* per-function block-duplication budget (caps blowup) */

    /* Bounded TAIL DUPLICATION: emit a NON-LOOP region from `b` up to `stop` (the
     * join) entirely INLINE — handling straight-line, returns, and if/else
     * (recursively duplicating both arms). Duplication is always semantically
     * correct (each runtime path executes its own copy exactly once); it is how
     * the structurer recovers a shared body / shared conditional block reached
     * from two places (seg_intersect's `(d1>0)!=(d2>0)` chains) instead of a goto.
     * `dup_budget` caps total duplicated blocks per function so it never blows up;
     * a loop header / switch / budget-exhaustion makes it fail (caller falls back). */
    bool emit_dup_region(int b, int stop, std::string& dst, int loop_header) {
        bool DBG = std::getenv("DS_DBG_DUP") && f && f->rva == 0x24b0;
        int local_guard = 0;
        while (b >= 0 && b != stop) {
            if (--dup_budget < 0 || ++local_guard > 200) { if (DBG) fprintf(stderr, "DUP fail budget/guard blk=%d budget=%d\n", b, dup_budget); return false; }
            Block& B = blocks[b];
            int tb = thread_target(b);
            if (cur_loop_follow >= 0 && tb == cur_loop_follow) { dst += ind() + "break;\n"; return true; }
            if (cur_loop_header >= 0 && tb == cur_loop_header) { dst += ind() + "continue;\n"; return true; }
            if (loop_of_header.count(b) || B.is_switch) { if (DBG) fprintf(stderr, "DUP fail loop/switch blk=%d loophdr=%d switch=%d\n", b, (int)loop_of_header.count(b), (int)B.is_switch); return false; }
            emit_stmts(b, dst);
            if (B.ends_ret) { dst += ind() + ret_text(b) + "\n"; return true; }
            if (B.ends_jcc && B.taken >= 0 && B.fall >= 0) {
                ExprP cond = B.cond ? B.cond : mkConst(1, 4);
                std::string tbody, fbody;
                indent_lvl++; bool ok1 = emit_dup_region(B.taken, stop, tbody, loop_header); indent_lvl--;
                if (!ok1) { if (DBG) fprintf(stderr, "DUP fail taken-arm blk=%d taken=%d\n", b, B.taken); return false; }
                indent_lvl++; bool ok2 = emit_dup_region(B.fall, stop, fbody, loop_header); indent_lvl--;
                if (!ok2) { if (DBG) fprintf(stderr, "DUP fail fall-arm blk=%d fall=%d\n", b, B.fall); return false; }
                if (is_blank(fbody))
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + tbody + ind() + "}\n";
                else if (is_blank(tbody))
                    dst += ind() + "if (" + render_cond(negate_expr(cond)) + ") {\n" + fbody + ind() + "}\n";
                else
                    dst += ind() + "if (" + render_cond(cond) + ") {\n" + tbody + ind() + "} else {\n" + fbody + ind() + "}\n";
                return true;
            }
            int nxt = B.ends_jmp ? B.taken : B.fall;
            if (nxt < 0) { dst += ind() + ret_text(b) + "\n"; return true; }
            b = nxt;
        }
        return true;   /* reached stop */
    }

    /* Emit region starting at `b`, stopping (exclusive) when we reach `stop`
     * (a follow/join block) or a block already emitted. */
    void emit_region(int b, int stop, std::string& dst, int loop_header) {
        while (b >= 0 && b != stop) {
            if (++struct_guard > 300000) { struct_bailed = true; dst += ind() + "/* structurer bailout */\n"; return; }
            /* A jump to the innermost loop's follow is a `break`; a jump to its
             * header (the continue point) is a `continue`. Converting these here
             * keeps nested / early-exit loops structured instead of leaving a
             * dangling goto that reverts the whole function to a goto-CFG. Only
             * the innermost loop is targeted, which matches /Od break/continue. */
            int _tb = thread_target(b);
            /* Compare against the THREADED loop follow/header too: a nested loop whose
             * exit edge lands on an empty block that jumps to the outer loop's
             * continue point (op-20 count-words: the skip-word loop's exit-on-space
             * threads through the outer back-edge block to the outer header) leaves
             * `cur_loop_follow` as the raw landing block while `_tb` is threaded past
             * it. Without threading both, that single edge stayed a dangling `goto`
             * that reverted the WHOLE function to a state machine. */
            int _tf = (cur_loop_follow >= 0) ? thread_target(cur_loop_follow) : -1;
            int _th = (cur_loop_header >= 0) ? thread_target(cur_loop_header) : -1;
            if (cur_loop_follow >= 0 && (_tb == cur_loop_follow || _tb == _tf) && b != stop) { mark_threaded(b); dst += ind() + "break;\n"; return; }
            if (cur_loop_header >= 0 && (_tb == cur_loop_header || _tb == _th) && b != stop) { mark_threaded(b); dst += ind() + "continue;\n"; return; }
            /* forward-sink: a T=-1 pure-convergence join is emitted ONCE after its
             * region; every internal reach FALLS THROUGH here (it post-dominates the
             * region, so no divergent code is skipped). Toggled to -1 for the single
             * bottom emission so the sink block itself is not self-suppressed. */
            if (cur_fwd_sink >= 0 && b == cur_fwd_sink && b != stop) return;
            if (!active_loop_sinks.empty() && active_loop_sinks.count(b) && b != stop) return;  /* loop-fwd-sink chain */
            if (structured.count(b)) {
                /* High-fan-in reconvergence: a non-trivial tail reached from >=3
                 * paths (a shared append / return / field-store landing) is the
                 * "same tail duplicated 3-6x" the analysis flagged across
                 * fun_0001c930 / 00013490 / 00020530. Emit it ONCE (labeled) + goto
                 * rather than copying it into every arm — the Hex-Rays shared-epilogue
                 * form. A tiny 1-stmt landing (a bare `return 0;`) still duplicates:
                 * a goto to it would be noisier than the copy. Tunable via
                 * DS_FANIN_GOTO. */
                /* Only force goto for a tail that TAIL-MERGE just collapsed from N
                 * duplicate copies: without this, the structurer's return-dup would
                 * re-duplicate the freshly-merged block back into every arm, undoing
                 * the merge. A general pred-count heuristic is NOT used here — it
                 * pushes ordinary 2-pred diamonds into a state machine (worse). */
                /* STALE RATIONALE (2026-07-17): state machines no longer exist — the
                 * `while(1) switch(__state)` fallback was deleted. "pushes it into a state
                 * machine (worse)" can no longer happen, so the reason not to use a general
                 * pred-count heuristic here is gone, and the same applies to the cap=30
                 * tuning below (chosen to minimise state machines). Both now trade
                 * duplication against gotos with nothing else on the scale. Re-measure
                 * before trusting either number; do NOT read the old comments as current
                 * evidence. */
                bool hi_fanin = tail_merge_targets.count(b) &&
                                blocks[b].stmts.size() >= 2;
                if (!hi_fanin) {
                /* Prefer duplicating a shared side-effect-free return region over
                 * a goto to an already-inlined block (which would dangle). */
                if (try_emit_return_dup(b, dst)) return;
                /* Or duplicate the (non-loop) region up to this region's join — a
                 * shared body / shared conditional block reached from two paths.
                 * At the top level (stop<0) it duplicates through to the returns. */
                {
                    std::string db; int saved = dup_budget;
                    if (emit_dup_region(b, stop, db, loop_header)) {
                        /* Cap tail duplication by SIZE. Duplicating a SMALL shared tail
                         * (a bare return, a 1-2 line landing) reads cleaner than a goto,
                         * but copying a LARGE multi-statement tail into every path is the
                         * "return-block explosion" the analysis flagged across
                         * fun_00013490 / 00014040 / 00016260 / 00020530 (the same 4-6 line
                         * append / recurse / field-store tail duplicated 3-6x). For a
                         * large tail, discard the copy and emit ONE labeled block + goto
                         * instead — exactly what Hex-Rays does here. Tunable via DS_DUP_MAX. */
                        int dl = 0; for (char c : db) if (c == '\n') ++dl;
                        /* HISTORICAL, NO LONGER EVIDENCE (see the stale-rationale note
                         * above): cap=30 was measured best on the full 1443 by STATE-MACHINE
                         * count -- "fewest state machines (15 vs 18 baseline / 19 at cap=12)
                         * ... State-machine count is the readability metric that matters
                         * most, so we keep the broader dup". State machines were deleted on
                         * 2026-07-17, so that objective no longer exists and this number is
                         * optimising for nothing. It now purely trades DUPLICATED CODE
                         * against gotos. Re-A/B it (chars + the long-line histogram, never
                         * line count) before changing it in either direction. */
                        static int cap = [](){ const char* e = getenv("DS_DUP_MAX"); return e ? atoi(e) : 30; }();
                        /* MEASURED AND REJECTED (2026-07-17): raising the cap for a fan-in-2
                         * target (the "one-goto cross join" — reached from the path that
                         * already emitted it plus exactly ONE other edge, so a copy removes
                         * that goto and appears exactly twice). Whole-binary A/B at cap 30->60
                         * for fan-in 2: gotos 568 -> 542 (-26) for +229KB (+2.2% chars) across
                         * 852 duplicated regions. -26 gotos is a measured near-zero and the
                         * size cost is real, so the cap stays. Do not retry without new
                         * evidence; the census (DS_GOTO_WHY) says 287 of 508 surviving gotos
                         * have fan-in 2, which LOOKS like headroom and is not — most of those
                         * regions already duplicate at cap=30 or exceed 60 lines. */
                        if (dl <= cap) {
                            dst += db;
                            if (stop >= 0) { b = stop; continue; }
                            return;   /* region duplicated to its terminators */
                        }
                    }
                    dup_budget = saved;
                }
                }   /* end if(!hi_fanin) */
                /* already emitted elsewhere (or a high-fan-in shared tail) — jump to it */
                need_label.insert(b);
                dst += ind() + "goto " + block_label(b) + ";\n";
                if (std::getenv("DS_GOTO_WHY")) {
                    /* Classify WHY this reconvergence goto survived structuring, for the
                     * census that drives structural fixes. Hard CFG facts, not text. */
                    int fanin = (int)blocks[b].pred.size();
                    /* is b some (non-innermost) loop's follow? -> multi-level break */
                    int obreak = 0, ocont = 0;
                    for (auto& kv : loop_of_header) {
                        if (loop_follow(kv.first) == b && kv.first != cur_loop_header) obreak = 1;
                        if (kv.first == b && kv.first != cur_loop_header) ocont = 1;
                    }
                    /* does b post-dominate its own immediate dominator? (hoistable merge) */
                    int pdom = (idom[b] >= 0 && idom[b] < (int)ipdom.size() && ipdom[idom[b]] == b) ? 1 : 0;
                    int inloop = (cur_loop_header >= 0) ? 1 : 0;
                    dst.insert(dst.size() - 1, " /*WHY fanin=" + std::to_string(fanin) +
                               " obreak=" + std::to_string(obreak) + " ocont=" + std::to_string(ocont) +
                               " pdom=" + std::to_string(pdom) + " inloop=" + std::to_string(inloop) + "*/");
                }
                return;
            }

            /* loop header? */
            int lh = loop_of_header.count(b) ? loop_of_header[b] : -1;
            if (lh >= 0 && b != loop_header) {
                emit_loop(b, stop, dst);
                /* after the loop, continue at the loop follow */
                int follow = loop_follow(b);
                b = follow;
                continue;
            }

            structured.insert(b);
            if (need_label.count(b)) dst += block_label(b) + ":;\n";

            Block& B = blocks[b];

            /* switch guard: `cmp idx,K; ja default` falling into a switch block.
             * Emit the guard's own statements then descend straight into the
             * switch (which now carries the default). */
            if (B.is_switch_guard && B.guard_switch_blk >= 0 &&
                blocks[B.guard_switch_blk].is_switch &&
                blocks[B.guard_switch_blk].switch_var &&
                !structured.count(B.guard_switch_blk)) {
                emit_stmts(b, dst);
                b = B.guard_switch_blk;
                continue;
            }

            /* switch dispatch */
            if (B.is_switch && B.switch_var) {
                emit_stmts(b, dst);
                emit_switch(b, stop, dst, loop_header);
                return;
            }

            /* two-way conditional */
            if (B.ends_jcc && B.taken >= 0 && B.fall >= 0) {
                emit_stmts(b, dst);
                emit_if_else(b, stop, dst, loop_header);
                return;
            }

            /* straight line / unconditional */
            emit_stmts(b, dst);
            if (B.ends_ret) {
                dst += ind() + ret_text(b) + "\n";
                return;
            }
            if (B.is_switch) { /* switch with no var: fallthrough as goto */
                return;
            }
            int nxt = -1;
            if (B.ends_jmp) {
                if (B.taken >= 0) nxt = B.taken;
                else { dst += ind() + ret_text(b) + "\n"; return; }   /* tail/extern jmp */
            } else {
                nxt = B.fall;
            }
            if (nxt < 0) { dst += ind() + ret_text(b) + "\n"; return; }
            /* continue (tail-call into the loop) */
            b = nxt;
        }
    }

    /* The follow block of a loop = a successor of the body that is outside it. */
    int loop_follow(int header) {
        int lh = loop_of_header[header];
        const Loop& lp = loops[lh];
        /* An exit block that IMMEDIATELY returns is an early-exit guard clause
         * (mismatch/error path), NOT the loop's continuation. Treating it as the
         * follow nests the REAL continuation inside the loop, so any other edge
         * into that continuation becomes a goto -> state machine (fn_000856a0:
         * memcmp's byte loop exits to a `return` on mismatch and to the qword loop
         * on alignment; the qword loop is the true follow). */
        auto terminal = [&](int s){
            return s >= 0 && s < (int)blocks.size() && blocks[s].ends_ret &&
                   !blocks[s].is_switch;
        };
        /* A pre-test loop exits through the header's OWN conditional edge: that
         * out-of-loop successor is the canonical follow — UNLESS it just returns
         * while a non-terminal continuation exit also exists (handled below). */
        int hdr_exit = -1;
        if (blocks[header].ends_jcc)
            for (int s : blocks[header].succ)
                if (!lp.body.count(s)) { hdr_exit = s; break; }
        if (hdr_exit >= 0 && !terminal(hdr_exit)) return hdr_exit;
        std::map<int,int> cnt;
        for (int u : lp.body)
            for (int s : blocks[u].succ)
                if (!lp.body.count(s)) cnt[s]++;
        /* prefer the most common NON-terminal exit (the real continuation) */
        int best = -1, bc = -1;
        for (auto& kv : cnt) {
            if (terminal(kv.first)) continue;
            if (kv.second > bc) { bc = kv.second; best = kv.first; }
        }
        if (best >= 0) return best;
        if (hdr_exit >= 0) return hdr_exit;      /* all exits terminal: header's */
        /* fall back to the most common exit of any kind */
        for (auto& kv : cnt) if (kv.second > bc) { bc = kv.second; best = kv.first; }
        return best;
    }

    std::map<int,int> eff_join_cache;
    /* The join a conditional's arms reconverge at, IGNORING sibling paths that
     * return early. The strict post-dominator (ipdom) is the virtual exit when ANY
     * path returns before the real join, so a shared continuation reached from
     * several guards is neither recognized nor emitted once — it gets duplicated
     * into every guard (bloat + dup-budget exhaustion) or gotoed (state machine).
     * Here: if ipdom exists, use it; else return the earliest-RPO block reachable
     * from BOTH arms (the point where the non-returning paths meet). */
    int effective_join(int b) {
        if (b < 0 || (size_t)b >= blocks.size()) return -1;
        if ((size_t)b < ipdom.size() && ipdom[b] >= 0) return ipdom[b];
        auto it = eff_join_cache.find(b);
        if (it != eff_join_cache.end()) return it->second;
        const Block& B = blocks[b];
        if (!B.ends_jcc || B.taken < 0 || B.fall < 0) { eff_join_cache[b] = -1; return -1; }
        int n = (int)blocks.size();
        auto reach = [&](int start, std::vector<char>& vis){
            std::vector<int> wl{start};
            while (!wl.empty()) {
                int c = wl.back(); wl.pop_back();
                if (c < 0 || c == b || c >= n || vis[c]) continue;
                vis[c] = 1;
                for (int s : blocks[c].succ) wl.push_back(s);
            }
        };
        std::vector<char> vt(n, 0), vf(n, 0);
        reach(B.taken, vt); reach(B.fall, vf);
        int best = -1, bestrpo = 0x7fffffff;
        for (int c = 0; c < n; ++c) {
            if (c == b || !vt[c] || !vf[c]) continue;
            int r = (c < (int)rpo_num.size()) ? rpo_num[c] : -1;
            if (r >= 0 && r < bestrpo) { bestrpo = r; best = c; }
        }
        eff_join_cache[b] = best;
        return best;
    }

    void emit_loop(int header, int outer_stop, std::string& dst) {
        int lh = loop_of_header[header];
        Loop lp = loops[lh];
        int follow = loop_follow(header);
        Block& H = blocks[header];

        structured.insert(header);
        if (need_label.count(header)) dst += block_label(header) + ":;\n";

        /* for/while: header is the test. Determine if header is a pre-test loop:
         * header ends in jcc and one edge leaves the loop (== follow). */
        bool pretest = H.ends_jcc && (H.taken == follow || H.fall == follow);
        if (pretest && H.cond) {
            int body_entry = (H.fall == follow) ? H.taken : H.fall;
            bool cond_is_taken = (H.fall == follow); /* stay-in-loop on taken */
            /* If we leave the loop on the taken edge, the loop continues on fall;
             * the C condition to STAY is the negation of the branch when taken
             * leaves. cond selects taken. */
            ExprP stay = cond_is_taken ? H.cond : negate_expr(H.cond);
            /* emit header non-terminator statements before the while as part of
             * the condition recomputation is hard; under /Od the header is just
             * the compare, so its stmts are empty. Emit them once is unsafe for a
             * loop, so require header has no side-effecting stmts. */
            bool header_clean = true;
            for (auto& s : blocks[header].stmts)
                if (s.kind != SK::Comment) { header_clean = false; break; }
            if (header_clean) {
                auto itf = for_of_header.find(header);
                if (itf != for_of_header.end() && itf->second.ok) {
                    const ForInfo& fi = itf->second;
                    std::string init_text = (fi.init_blk >= 0)
                        ? render_stmt_inline(blocks[fi.init_blk].stmts[fi.init_idx]) : "";
                    std::string incr_text = build_incr(disp(fi.iv), fi.op, fi.step);
                    dst += ind() + "for (" + init_text + "; " + render_cond(stay) + "; " + incr_text + ") {\n";
                } else
                    dst += ind() + "while (" + render_cond(stay) + ") {\n";
                indent_lvl++;
                int saved_loop = cur_loop_header; cur_loop_header = header;
                int saved_follow = cur_loop_follow; cur_loop_follow = follow;
                int saved_latch = cur_loop_latch; cur_loop_latch = unique_latch(lh, header, follow);
                emit_loop_region(body_entry, cur_loop_latch >= 0 ? cur_loop_latch : header, header, dst);
                emit_shared_latch(header, dst);
                cur_loop_header = saved_loop; cur_loop_follow = saved_follow; cur_loop_latch = saved_latch;
                indent_lvl--;
                dst += ind() + "}\n";
                return;
            }
        }

        /* post-test single-exit loop -> do { body } while (cond); */
        int dw_latch = -1;
        if (is_dowhile(header, follow, lh, dw_latch)) {
            Block& Lb = blocks[dw_latch];
            dst += ind() + "do {\n";
            indent_lvl++;
            int saved_loop = cur_loop_header; cur_loop_header = header;
            int saved_follow = cur_loop_follow; cur_loop_follow = follow;
            int saved_latch = cur_loop_latch; cur_loop_latch = dw_latch;   /* body_stop = L */
            /* emit header + body down to L (exclusive); suppress the sink so L renders
             * as the while-tail rather than being emitted inside the body. */
            emit_loop_body(header, follow, dst, /*emit_latch=*/false);
            /* L's own statements (the loop-carried update, e.g. i++), then the test. */
            structured.insert(dw_latch);
            if (need_label.count(dw_latch)) dst += block_label(dw_latch) + ":;\n";
            emit_stmts(dw_latch, dst);
            cur_loop_header = saved_loop; cur_loop_follow = saved_follow; cur_loop_latch = saved_latch;
            indent_lvl--;
            /* condition to STAY (take the back-edge to header). */
            ExprP stay = (Lb.taken == header) ? Lb.cond : negate_expr(Lb.cond);
            dst += ind() + "} while (" + render_cond(stay) + ");\n";
            return;
        }

        /* generic loop: while(true){ body; if(!cond) break; } via region emission */
        used_while_true = true;
        dst += ind() + "while (true) {\n";
        indent_lvl++;
        int saved_loop = cur_loop_header; cur_loop_header = header;
        int saved_follow = cur_loop_follow; cur_loop_follow = follow;
        int saved_latch = cur_loop_latch; cur_loop_latch = unique_latch(lh, header, follow);
        /* emit the header block's own statements + structure starting at header's
         * successors, but we already inserted header into structured; emit its
         * terminator handling via emit_body_from. */
        emit_loop_body(header, follow, dst);
        cur_loop_header = saved_loop; cur_loop_follow = saved_follow; cur_loop_latch = saved_latch;
        indent_lvl--;
        dst += ind() + "}\n";
        (void)outer_stop;
    }

    int cur_loop_header = -1;
    int cur_loop_follow = -1;
    int cur_loop_latch  = -1;
    std::set<int> fwd_sinks;   /* T=-1 pure-convergence joins: emit ONCE after the region */
    int cur_fwd_sink = -1;
    std::map<int,std::map<int,int>> loop_pd;   /* loop-header -> (block -> loop-local ipdom), lazy */
    std::map<int,std::set<int>> loop_fwd_sink; /* loop-header -> in-loop convergence joins (chain), each emitted once */
    std::set<int> active_loop_sinks;           /* currently-active in-loop sinks: a reach falls through */

    /* The loop's UNIQUE latch (single block whose back-edge closes the loop),
     * when it is a distinct block from the header/follow. Emitting the body with
     * the latch as its stop-sink, then the latch ONCE at the bottom, makes every
     * internal path FALL THROUGH to the shared loop-carried update instead of the
     * first reach emitting it inline and every other reach `goto`-ing back to it
     * (the dominant residual-goto source in dense loops — CRC/scan/min-max latches
     * reached from several internal branches). A single latch post-dominates the
     * whole body, so this is behavior-preserving. */
    int unique_latch(int lh, int header, int follow) {
        if (std::getenv("DS_NO_LATCH")) return -1;
        Loop& lp = loops[lh];
        if (lp.latches.size() != 1) return -1;
        int L = *lp.latches.begin();
        if (L == header || L == follow || L < 0) return -1;
        return L;
    }

    /* A single-exit POST-TEST loop: the exit condition lives at the UNIQUE latch's
     * conditional back-edge (not at the header), and the ONLY way out of the loop is
     * that latch test. Such loops read cleanest as `do { body } while (cond);` rather
     * than `while (true) { body; if (!cond) break; }`. Returns the latch block in Lout.
     * Conservative: any second exit (stray break / side-jump to follow) or a pretest
     * header falls back to the generic while(true) form (never a wrong do-while). */
    bool is_dowhile(int header, int follow, int lh, int& Lout) {
        if (std::getenv("DS_NO_DOWHILE")) return false;   /* default-on; DS_NO_DOWHILE to disable */
        Loop& lp = loops[lh];
        Block& H = blocks[header];
        /* (1) header must NOT be a pretest (its jcc, if any, doesn't leave to follow). */
        if (H.ends_jcc && (H.taken == follow || H.fall == follow)) return false;
        /* (2) exactly one latch, distinct from header/follow. */
        if (lp.latches.size() != 1) return false;
        int L = *lp.latches.begin();
        if (L == header || L == follow || L < 0 || (size_t)L >= blocks.size()) return false;
        /* (3) latch terminator is the conditional back-edge {header, follow}. */
        Block& Lb = blocks[L];
        if (!Lb.ends_jcc || !Lb.cond || Lb.taken < 0 || Lb.fall < 0) return false;
        bool clean = (Lb.taken == header && Lb.fall == follow) ||
                     (Lb.taken == follow && Lb.fall == header);
        if (!clean) return false;
        /* (4) SINGLE-EXIT: the only body edge leaving the loop is L->follow. Any other
         *     block that jumps out (a second break / merged side-exit) disqualifies. */
        for (int u : lp.body)
            for (int s : blocks[u].succ)
                if (!lp.body.count(s) && !(u == L && s == follow)) return false;
        /* (5) header entered only from outside + the latch (defensive; implied by (2)). */
        for (int p : blocks[header].pred)
            if (lp.body.count(p) && p != L) return false;
        Lout = L;
        return true;
    }

    /* the loop's in-loop forward-sink joins, sorted into a fall-through chain (J1 reaches J2). */
    std::vector<int> loop_sinks_for(int header, int body_stop) {
        std::vector<int> sinks;
        auto sit = loop_fwd_sink.find(header);
        if (sit != loop_fwd_sink.end())
            for (int Ji : sit->second)
                if (!structured.count(Ji) && Ji != body_stop && Ji != header && Ji != cur_loop_follow)
                    sinks.push_back(Ji);
        /* forward-flow order == address order for a reducible loop body (J1's tail falls to J2). */
        std::sort(sinks.begin(), sinks.end(), [&](int a, int b){ return blocks[a].addr < blocks[b].addr; });
        return sinks;
    }
