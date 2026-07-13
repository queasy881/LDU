# 10-DLL audit: 77 confirmed defects → root causes (by impact × tractability)

## TIER 1 — high value, low risk (do first)
- **F. Param width long long→int** (23 findings, most common). Narrow integer params to widest sub-register actually read (ecx/edx 32-bit → `int`); drop `(int)` casts. Type-only, no semantics. Affects nearly every function.
- **BSWAP not modeled** (reverse_bits): drops byte-swap → WRONG result. Add IR handler. CORRECTNESS, localized.
- **setcc `& 0xff` mask** (state_machine, week_days, validate_packet): `(ull)(cond) & 0xff` — drop mask, setcc already 0/1.
- **dead `& 0xffffff00`/`& -256` upper-bits merge term** (is_ascii_ident, week_days): `zext_byte(x) & ~0xff → 0`.
- **X & X → X** (fmt_into, from `test r,r`). Trivial fold.
- **x + x*2 → x*3** lea idiom (call_with_six).
- **btr mask 64→32 width** (checksum `& -2147483649LL` → `& 0x7fffffff`).

## TIER 2 — high value, medium/hard (correctness)
- **B. Loop-exit off-by-one** (sum_variadic, max_variadic, avg_variadic, fold_ops, reduce_with, checksum, validate_packet, state_machine; mod_pow re-shifts). `inc edx; cmp edx,ecx; jl` → `t=t+1; if(t+1>=n)` double-counts. Exits one early. CORRECTNESS.
- **A. Induction increment-before-use** (sum_array, dot_strided, accumulate_window, count_runs, list_sum, checksum, tokenize, validate_packet, state_machine). IV step hoisted above body loads → loads use post-increment index → wrong elements. Plus duplicate accumulator phi (t2/t3). CORRECTNESS, deep loop-SSA.
- **C. Indirect-call phantom args** (apply_op, fold_ops, reduce_with, run_handler). `call [tbl+i*8]`/`call rax` passes full RCX/RDX/R8/R9 + address-calc regs instead of reaching-def args.
- **E. void-vs-return both directions**: false-VOID drops return (sum_variadic, fmt_into, reduce_with — `mov eax,reg; ret` not traced); false-RETURN (mat_mul_vec, scale_array, list_push, ring_init — incidental rax/xmm0). Leaf funcs fundamentally ambiguous.
- **G/H. XMM type inference**: float-vs-double scalar params/returns (mix_scalars, avg_variadic); integer-SIMD tagged float (sum_array, accumulate_window — paddq/pmovsxdq i64 shown float).
- **CSE / temp materialization**: multi-use SSA inlined → quadratic/exponential blowup (vec_length 395KB!, popcount32, next_pow2, mix_scalars). Bind multi-use/self-ref values to named temps.

## TIER 3 — SIMD-heavy / specialized
- **D. Packed-FP arithmetic** addps/mulps/subps/divps dropped (vec_add, scale_array).
- **Packed-integer SIMD** paddd/paddq/pcmpeqd/pmovsxdq (count_with_flag, sum_array).
- **2-level jump table** RIP-relative byte+dword tables (classify_char).
- **signed mod-by-pow2 idiom** `(x & 0x8000003f)` + fixup → `% 64` (ring_push/pop).
- **stack array coalescing** rsp-relative accesses → one `stack[64]` (eval_rpn_digit).
- **sub-ladder switch** `sub edx,k; je` chain → switch(c) (eval_rpn_digit).
- **sret 16-byte struct return** (vec_add Vec4-by-value).
