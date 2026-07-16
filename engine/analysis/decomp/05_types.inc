/* 05_types.inc -- type naming, decl_type, widths, bool inference
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    /* Declared C type for a recovered variable. A pointer whose element width is
     * known (because it was dereferenced with a typed/scaled access) is declared
     * as `T*` so `base[i]` subscripts compile; otherwise pointers fall back to
     * the 64-bit-int model (`long long`). */
    std::string decl_type(const std::string& nm) {
        /* a flag local whose every assignment is 0/1 (compute_bool_vars) */
        if (bool_vars.count(nm)) return "bool";
        /* a recovered struct param renders `struct s_aN* aN` (or `class <Class>* aN` for an
         * RTTI class type, matching its `class`/`struct` definition keyword). */
        { auto si = param_structs.find(nm);
          if (si != param_structs.end())
              return std::string(si->second.is_class && !si->second.cls_kw_struct ? "class " : "struct ")
                     + si->second.tag + "*"; }
        /* A GP var holding a packed 2-float struct (Vec2 by value) is the raw 8-byte
         * bit pattern; the lanes are read via `*(float*)&v`, so it must stay a plain
         * `long long` — never a float or pointer type (its lane reinterprets would
         * otherwise mis-infer one). */
        if (packed_gp_vars.count(nm)) return "long long";
        /* a pointer-mistyped temp that also receives a float value (mis-merged gp
         * pointer + xmm float register): the raw 8-byte register — makes both the
         * float and pointer assignments compile as conversions instead of C2440. */
        if (conflict_raw_vars.count(nm)) return "long long";
        if (force_float_vars.count(nm)) return (var_width.count(nm) && var_width[nm] >= 8) ? "double" : "float";
        bool ptr = var_pointer.count(nm) && var_pointer[nm];
        bool ll  = var_is_ll.count(nm) && var_is_ll[nm];
        int w = var_width.count(nm) ? var_width[nm] : 8;
        /* A var PROVEN SIGNED by a `x < 0` / `x >= 0` sign-test cannot be a pointer
         * (an unsigned pointer is never < 0). mark_ptr_in_addr sometimes mis-picks a
         * signed index/return as the pointer base of a `Var + field` address; if the
         * signedness pass proved it signed, veto the pointer type and fall through to
         * the integer path so `if (t678 < 0)` stays a real signed test (not the
         * always-false pointer<0 that silently deletes an error path). Address uses
         * already carry explicit (long long) casts, so arithmetic is unchanged. */
        if (ptr && zero_signed_vars.count(nm) && !ptr_elem_float.count(nm)) ptr = false;
        /* float/double params (and locals proven float) — gated strictly on the
         * XMM-read detection so integer code is never affected. Float WINS over a
         * conflicting pointer inference: a variable that is ASSIGNED a float value
         * cannot be a pointer, and `int* v = <float>` is a hard error (C2440) that
         * — unlike int<->ptr — has NO valid cast. The mis-typed side is always the
         * pointer here (float-ness comes from an unambiguous XMM/scalar-FP read),
         * so a value carrying float coordinates through pointer-typed temps
         * (fn_00011470's min/max point search: t10/t11/t2/t3) declares as float. */
        if (var_is_float.count(nm) && var_is_float[nm] && !ptr_elem_float.count(nm))
            return (w >= 8) ? "double" : "float";
        if (ptr) {
            if (ptr_elem_float.count(nm) && ptr_elem_float[nm]) {
                /* prefer the MIN-wins float width (a movss single-precision access
                 * makes it `float*` even if a packed movsd also wrote 8 bytes). */
                int ew = ptr_elem_float_w.count(nm) ? ptr_elem_float_w[nm]
                       : (ptr_elem_width.count(nm) ? ptr_elem_width[nm] : 4);
                return (ew >= 8 ? "double" : "float") + std::string("*");
            }
            auto it = ptr_elem_width.find(nm);
            if (it != ptr_elem_width.end()) {
                bool eu = ptr_elem_uns.count(nm) && ptr_elem_uns[nm];
                return typ_str(it->second, eu, false) + "*";
            }
            return "long long";
        }
        bool uns = var_unsigned.count(nm) && var_unsigned[nm];
        if (ll || w >= 8) return uns ? "unsigned long long" : "long long";
        return typ_str(w ? w : 4, uns, false);
    }

    /* =================================================================== */
    /*  3. Symbolic execution per block                                     */
    /* =================================================================== */

    /* register file: current symbolic value of each canonical register */
    ExprP regfile[R_COUNT];

    /* ---- x87 FPU stack --------------------------------------------------------
     * x87 is a STACK machine: ST(0) is the top, FLD pushes, FSTP pops, and the
     * arithmetic ops read/write ST(0) implicitly. NONE of it was modeled, so in a
     * 32-bit /arch:IA32 binary — where x87 IS the entire float unit — every float
     * function decompiled to an empty `void f(void) { return; }`: parameters,
     * arithmetic and return value all silently dropped.
     *
     * Values are modeled as `double`. x87 computes in extended precision and rounds
     * only on store, so widening at the load and rounding at the store is the
     * faithful shape (and matches what the source-level `float` code meant).
     *
     * Compiler-generated x87 keeps the stack balanced within an expression and
     * spills to memory across branches, so the stack simply flows with the block
     * walk exactly as regfile does. `fpu_top` is the PHYSICAL index of ST(0). */
