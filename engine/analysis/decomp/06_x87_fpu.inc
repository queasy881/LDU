/* 06_x87_fpu.inc -- the x87 FPU stack model
 *
 * Section of the Decompiler class body, #included by decompiler.cpp inside the class.
 * This is a pure text partition of a 14.4k-line class: the preprocessor reassembles
 * the identical translation unit, so it is behaviour-neutral by construction.
 */
    ExprP fpu[8];
    int   fpu_top = 0;
    /* operands of the most recent LEGACY compare (FCOM/FUCOM family), pending an
     * `fnstsw ax` that reads the resulting condition bits back out */
    ExprP fcom_a, fcom_b;
    ExprP& fpu_slot(int i) { return fpu[(fpu_top + i) & 7]; }
    void   fpu_push(ExprP v) { fpu_top = (fpu_top + 7) & 7; fpu[fpu_top] = v; }
    ExprP  fpu_pop() {
        ExprP v = fpu[fpu_top];
        fpu[fpu_top] = nullptr;
        fpu_top = (fpu_top + 1) & 7;
        return v;
    }
    /* ST(i) as an rvalue; an empty slot means we lost track (unbalanced stack across
     * a branch) — yield 0.0 rather than a null that would silently drop the use. */
    ExprP fpu_get(int i) {
        ExprP v = fpu_slot(i);
        return v ? clone(v) : fpu_const(0.0);
    }
    ExprP fpu_const(double d) {
        uint64_t bits; std::memcpy(&bits, &d, sizeof bits);
        ExprP c = mkConst((int64_t)bits, 8);
        c->is_float = true; c->width = 8;
        return c;
    }
    /* Round an extended-precision stack value to the storage type. Must produce an
     * expr whose width already MATCHES the store, because do_dst's truncate() would
     * otherwise apply an INTEGER narrowing `(int)v` to a double. */
    ExprP fpu_round(ExprP v, int sz) {
        if (!v) return nullptr;
        if (sz == 4) { ExprP c = mkCast("(float)", v, 4); c->is_float = true; return c; }
        if (v->width != 8) { ExprP c = mkCast("(double)", v, 8); c->is_float = true; return c; }
        return v;
    }
    static int st_index(unsigned cr) {
        return (cr >= X86_REG_ST0 && cr <= X86_REG_ST7) ? (int)(cr - X86_REG_ST0) : -1;
    }

    /* High 64-bit lane (bits[127:64]) of each XMM register, for modeling packed
     * 64-bit-element SIMD (auto-vectorized element-wise maps: a[i]*=c, a[i]+=b[i],
     * abs, clamp). regfile[r] holds lane 0 (bits[63:0]); regfile_hi[r] holds lane 1.
     * Non-null ONLY immediately after a packed op that produced a known 2-lane
     * value; any scalar write to an xmm (set_reg) clears it. A 128-bit store only
     * splits into two clean 8-byte lane stores when BOTH lanes are tracked and
     * backstop-free — otherwise it falls back to the prior scalar behavior, so the
     * model never fabricates a half-known vector. */
    ExprP regfile_hi[R_COUNT];

    /* Packed 32-bit FLOAT lanes (4 per xmm): the scalar 2x64 model above cannot
     * express element-wise float vector math (mulps/addps/shufps on {x,y,z,w}).
     * xmm_f[r][0..3] hold the four float lanes when tracked; xmm_f_real[r] is set
     * once a definite float OP (arith/shuffle) produced them (so a 128-bit store
     * commits four `*(float*)` lanes). Block-LOCAL (cleared at each block entry and
     * on any scalar/integer write); consumed only by the packed-float handlers, so
     * integer code and the corpus (no floats) are entirely unaffected. */
    ExprP xmm_f[R_COUNT][4];
    bool  xmm_f_real[R_COUNT] = {false};

    /* Packed 32-bit INTEGER lanes (4 per xmm): the analog of xmm_f for auto-
     * vectorized element-wise INT maps (`a[i] *= k` -> movdqu/pmulld/movdqu,
     * `a[i] += b[i]` -> paddd). xmm_i[r][0..3] hold the four int lanes; xmm_i_real
     * is set once a definite packed-INT op (pmulld/paddd/psubd/pshufd) produced them
     * (so a 128-bit store commits four `*(int*)` lanes). Block-LOCAL, cleared with
     * xmm_f. Consumed only by the packed-int handlers -> float/scalar code and the
     * corpus are unaffected. */
    ExprP xmm_i[R_COUNT][4];
    bool  xmm_i_real[R_COUNT] = {false};

    /* Packed 2-float struct (Vec2) passed/returned BY VALUE in a GP register — MSVC
     * packs {float x, y} into one 8-byte int reg, `movq xmm,reg` reinterprets it,
     * and the high lane .y is extracted via a stack spill + `[slot+4]` reload. We
     * track which xmm/stack-slot currently holds such a packed value so the two
     * lanes render as `*(float*)&v` / `*(float*)((char*)&v + 4)` instead of integer
     * ops on the bit pattern (vec2_add/len/make). Cleared per block. */
    std::map<Reg, std::string> xmm_packed_var;      /* xmm holds packed bytes of GP var */
    std::map<int64_t, std::string> stack_packed_var; /* stack slot (norm) holds packed bytes of GP var */
    std::map<int64_t, int> float_slots;              /* stack slot (norm) last written by movss/movsd -> float width (bit-reinterpret on int read) */
    std::map<int64_t, int> int_slots;                /* stack slot (norm) last written by a GP integer store -> width (bit-reinterpret on movss/movsd load = int->float, the u2f/u2d direction) */
    /* Every GP store to a stack slot, for stack-string recovery (recover_stack_strings).
     * Keyed by INSN ADDR, not by slot: exec_block is re-run under the entry-reg fixpoint
     * (`b.stmts.clear(); exec_block(b)`), so an accumulator would double-count — re-exec
     * of the same address must be idempotent. For the same reason this is deliberately
     * NOT in exec_block's per-block clear, unlike int_slots. */
    struct StrStore { int64_t norm; int width; uint64_t val; bool is_const; };
    std::map<uint64_t, StrStore> stack_str_stores;
    /* region name -> start offset -> C-escaped string, filled by recover_stack_strings. */
    std::map<std::string, std::map<int64_t, std::string>> stack_str_found;
    /* normalized stack-slot offset of a memory operand, or false if not a plain [rbp/rsp+disp]. */
    bool op_slot_norm(const cs_x86_op& op, int64_t& norm) {
        if (op.type != X86_OP_MEM) return false;
        const x86_op_mem& m = op.mem;
        if (m.index != X86_REG_INVALID || m.base == X86_REG_INVALID) return false;
        Reg mb = R_NONE; int mt; map_reg(m.base, mb, mt);
        return normalise_slot(mb, m.disp, norm);
    }

    /* `*(float*)&v` (off==0) or `*(float*)((char*)&v + off)`: reinterpret the 32-bit
     * half at byte `off` of GP-var `v` as a single float. */
    std::set<std::string> packed_gp_vars;   /* GP vars holding a packed 2-float struct: force `long long` */
    /* Read a scalar-float source operand, forwarding a spilled Vec2 lane when the
     * source is a stack slot that a packed spill recorded (`addss xmm,[slot+4]`). */
    ExprP fp_src(const cs_x86_op& op, int w) {
        if (op.type == X86_OP_MEM && !stack_packed_var.empty()) {
            const x86_op_mem& m = op.mem;
            Reg mb = R_NONE; int mt; if (m.base != X86_REG_INVALID) map_reg(m.base, mb, mt);
            int64_t norm;
            if (m.index == X86_REG_INVALID && normalise_slot(mb, m.disp, norm))
                for (auto& kv : stack_packed_var) {
                    int64_t off = norm - kv.first;
                    if (off == 0 || off == 4) return packed_flane(kv.second, (int)off);
                }
        }
        return as_float(rvalue(op), w);
    }
    /* Pack two scalar float lanes back into a GP register (the `unpcklps; movq rax,
     * xmm` return of a Vec2 by value): `((long long)*(unsigned int*)&hi << 32) |
     * *(unsigned int*)&lo`. Non-lvalue lanes are first materialized into a float
     * temp so their bit pattern can be taken by address. */
    std::set<std::string> force_float_vars;   /* address-reinterpreted lanes: keep `float` */
    std::set<std::string> bool_vars;          /* every assignment is 0/1 -> declare `bool` */

    /* BOOL INFERENCE: a local whose EVERY assignment is provably 0/1 (a comparison,
     * `!x`, or the constants 0/1) is a `bool`, not an `int32_t` — `int v3; v3 = 1;
     * ... if (!v3)` is how a flag reads today. Excluded: params (their ABI type is
     * fixed), pointers/floats, and ADDRESS-TAKEN vars — a bool is 1 byte, so
     * `*(int*)&v` on a retyped var would read past it. bool arithmetic promotes to
     * int, and the value is already 0/1, so no expression changes meaning.
     * DS_NO_BOOLVAR. */
    void compute_bool_vars() {
        if (std::getenv("DS_NO_BOOLVAR")) return;
        /* A param-HOME alias local receives its initial value IMPLICITLY, through its
         * DECLARATION (`int v2 = a4;` — v2 shares a4's home slot). There is no SK::Assign
         * carrying it, so the 0/1 scan below never sees that arbitrary incoming param
         * value and would wrongly type the variable `bool` — silently TRUNCATING the
         * parameter to 0/1 (this broke heap_size_after / ident_length / range_sum_skip).
         * Mirror the emitter's reuse_local_init construction and refuse every var it
         * would initialise from a parameter. Same root cause as the invariant-inliner's
         * param-home misidentification: an implicit init is invisible to a def scan. */
        std::set<std::string> param_init;
        for (auto& kv : home_reuse_local)
            if (!kv.second.empty() && param_home_off.count(kv.first)) param_init.insert(kv.second);
        for (auto& kv : stack_slot_name)
            if (slot_init_param.count(kv.first)) param_init.insert(kv.second);
        std::set<std::string> taken;
        std::function<void(const ExprP&)> scan = [&](const ExprP& e) {
            if (!e) return;
            if (e->kind == EK::AddrOf && e->a && e->a->kind == EK::Var) taken.insert(e->a->name);
            scan(e->a); scan(e->b); scan(e->c);
            for (auto& ar : e->args) scan(ar);
        };
        std::map<std::string, bool> cand;
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                scan(s.lhs); scan(s.rhs);
                if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
                const std::string& n = s.lhs->name;
                /* A FLOAT-typed value assigned to an integer-typed var is BIT-REINTERPRETED
                 * by the emitter (`*(float*)&v = <float>`, the emit_stmt int-dest branch) —
                 * a float-register compare result is exactly this shape. That store is 4/8
                 * bytes wide, so the variable's storage must stay full width: a 1-byte
                 * `bool` would be written through a `float*` lvalue and corrupt the frame
                 * (arr_normalize01's v11). The reinterpret is applied at EMIT time, so the
                 * statement here still looks like a plain 0/1 assignment — mirror the
                 * emitter's condition rather than trusting the tree's shape. */
                bool bv = is_bool_value(s.rhs) && !(s.rhs && s.rhs->is_float);
                auto it = cand.find(n);
                if (it == cand.end()) cand[n] = bv; else it->second = it->second && bv;
            }
            scan(b.cond); scan(b.ret_value); scan(b.ret_raw); scan(b.switch_var); scan(b.tail_call);
        }
        for (auto& kv : cand) {
            if (!kv.second) continue;
            const std::string& n = kv.first;
            if (taken.count(n)) continue;                       /* &v needs real storage */
            if (param_init.count(n)) continue;                  /* implicit `vN = aN` init */
            if (is_ptr_param_name(n)) continue;                 /* param ABI type is fixed */
            if (!n.empty() && n[0] == 'a' && n.size() >= 2 && n[1] >= '0' && n[1] <= '9') continue;
            if (var_pointer.count(n) && var_pointer[n]) continue;
            if (var_is_float.count(n) && var_is_float[n]) continue;
            if (force_float_vars.count(n) || packed_gp_vars.count(n) ||
                conflict_raw_vars.count(n) || array_locals.count(n) || struct_var.count(n)) continue;
            if (param_structs.count(n)) continue;
            int w = var_width.count(n) ? var_width[n] : 0;
            if (w <= 0 || w > 4) continue;
            bool_vars.insert(n);
        }
        if (!bool_vars.empty()) used_while_true = true;         /* pulls in <stdbool.h> */
    }
    /* A pointer tested or assigned against literal `0` is a NULL check. Hex-Rays spells
     * it `if (p == NULL)`; the bare `0` hides that the value is a pointer at all, which
     * is exactly the distinction a reader is scanning for. Runs after the pointer- and
     * bool-type inference so decl_type is final. Purely cosmetic: NULL is `((void*)0)`,
     * so the emitted C is identical either way. DS_NO_NULLPTR. */
    void mark_null_consts() {
        if (std::getenv("DS_NO_NULLPTR")) return;
        auto take = [&](const ExprP& c, const ExprP& p) {
            if (!c || !p) return;
            if (c->kind != EK::Const || c->cval != 0 || c->is_float) return;
            /* renders_as_pointer is the RENDERER's own predicate, so `NULL` can never
             * disagree with the type actually printed. Exclude Binary: `p + i` renders
             * as a pointer but `p - q` is a ptrdiff, and neither is a null test. */
            if (!p || p->kind == EK::Binary || !renders_as_pointer(p)) return;
            c->null_hint = true;      /* used_null is set when it actually renders */
        };
        std::function<void(const ExprP&)> walk = [&](const ExprP& e) {
            if (!e) return;
            walk(e->a); walk(e->b); walk(e->c);
            for (auto& ar : e->args) walk(ar);
            if (e->kind == EK::Binary && (e->op == "==" || e->op == "!=") && e->a && e->b) {
                take(e->b, e->a);          /* p == 0 */
                take(e->a, e->b);          /* 0 == p */
            }
        };
        for (auto& b : blocks) {
            for (auto& s : b.stmts) {
                walk(s.lhs); walk(s.rhs);
                if (s.kind == SK::Assign) take(s.rhs, s.lhs);      /* p = 0 -> p = NULL */
            }
            walk(b.cond); walk(b.ret_value); walk(b.ret_raw);
            walk(b.switch_var); walk(b.tail_call);
        }
    }
