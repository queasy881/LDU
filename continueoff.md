# CONTINUE-OFF — IDA-parity sweep (work AFTER the survey agents found the issues)

Context: a 12-agent survey workflow (`_qa/ida_parity_survey.js`) read our real decompiled NullWare
output and ranked, across 12 dimensions, where it reads worse than Hex-Rays. The findings were
distilled into a backlog: **`_qa/ida_parity_backlog.md`** (45 items, A1..J). Since then I've been
implementing that backlog, **gating every change** against three hard gates before moving on.

## THE GATES (must stay green — run after every change)
- **corpus 616 / 0** — behavioral oracle. `cargo test --release -p disasmstudio --test decompile_dump -- --nocapture` (writes `_qa/decomp/*.c`), then `python _qa/harness.py` (compiles + runs each decompiled fn vs the original DLL over 50k random+edge inputs; SUMMARY line = `N PASS / M FAIL`).
- **NullWare 1445 / 1445 compile-clean** + **GOTO_TOTAL <= 300**: `bash _qa/fast_gate.sh` (dumps all 1445 NullWare fns via dump_pairs, greps goto count, then `_qa/verify_fast.sh` compiles all 1445 with `cl /w /TC`). Current GOTO = 291.

BUILD ENV (critical): `touch crates/bridge/build.rs` before every rebuild or it silent-stales.
`export PATH="/c/Users/User/.cargo/bin:/c/Program Files/NASM:$PATH"`,
`export LIBCLANG_PATH="C:\Users\User\AppData\Local\disasmstudio-tools\LLVM\bin"` (NOT Program Files\LLVM).
Rebuild: `cargo test --release -p disasmstudio --test dump_pairs --test decompile_dump --no-run`.
NullWare DLL: `DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll"`.
All parity features are env-gated for A/B bisect: `DS_NO_{PEEPHOLE,ELSEIF,ANDGUARD,BOOLCOND,BOOLDIAMOND,RETFOLD,RENUM,CONTBREAK,NARROW}`.

STANDING RULE from the user: **fix EVERY backlog item, none skipped/half-done; on a regression FIX the root cause, never revert.** Everything lives in one file: `engine/analysis/decompiler.cpp`.

## DONE + GATED (each verified corpus 616/0 + 1445/1445)
- **A1** `x + -K`->`x - K`; **A3/A4** render-time nested unsigned-cast dedup; **A5** identical nested cast; **A6/A7** negative bitmasks->hex (Expr.hex_hint); **A8** widening cast `(int)((char)x)`->`(char)x`; **A9** drop const-cast in ptr compares.
- **B1** `else if` chains (was 0 in output -> 766; `collapse_else_if` string post-pass); **B2** `X!=0`->`X`,`X==0`->`!X` (`bool_simplify`+`render_cond` at ~41 sites); **B3** `(a-b)==0`->`a==b`; **B5** `if(A){if(B){}}`->`if(A&&B)` (`collapse_and_guards`).
- **C1**+`fold_return_temps` `v=e;return v;`->`return e;`; **C2** `if(C)continue;break;`->`if(!C)break;` (emit_region, uses loop's own header/follow ids so never mis-targets an inner switch); **C3** boolean diamond `if(c)x=1;else x=0;`->`x=c;` (`fold_boolean_diamonds` CFG pass).
- **F1** signed div 3/6 (magic 0x2aaaaaab/0x55555556, s==0); **F2** modulo `x-(x/d)*d`->`x%d` incl. doubled `(x/d*k)+(x/d*k)` form; **F3** = NON-ISSUE (the 0xcccccccd cases are 32-bit truncated hash multiplies, not divisions).
- **G1** const byte-offset `*(int*)((char*)p+0x10)`->`p[4]` (try_array_subscript).
- **H1** contiguous `v1,v2,..` renumber (`compute_display_renumber`, display-only via `autoname`); `t#` eliminated.
- **BONUS CORRECTNESS BUGS found while doing the above (not parity items):** (1) `negate_expr` NaN root-fix — `!(a>b)` was being inverted to `a<=b`, WRONG for floats (NaN unordered); found via a B2/arr_clamp regression. (2) **block-field-coverage bug class** — 9 passes (collect_addr_taken, total_reads, coalesce liveness x3+rename, global_dead_store_elim addr-scan+liveness x2, trim_phantom, mark x2) scanned only SOME of the 6 block expr fields {stmts.lhs/rhs, cond, ret_value, ret_raw, switch_var, tail_call} -> a var live/addr-taken ONLY in a tail-call/raw-return was invisible -> miscompile. LESSON: any block-iterating pass MUST cover all 6.

## IN FLIGHT AT SESSION END — D1 (temp-width narrowing)
**D1 = the biggest remaining lever (6642 `(int)tN` casts).** Implemented `narrow_temp_widths()` (just before `compute_display_renumber`): a VALUE-RANGE FIXPOINT — narrow a `long long` temp to `int` (keeping signedness) iff its VALUE provably fits 32 bits (`fits32(e)` monotone fixpoint over the temp's defs: Cast w<=4 / Binary,Unary w<=4 / &|^ w8 both fit / >> w8 fits(a) / Mem w<=4 / Const in [-2^31,2^31-1] / int-return Call). Sets the Var node widths to 4; added a `peephole_expr` rule to drop the now-redundant same-width `(int)v` cast (fold has it but runs pre-narrowing). Excludes ptr/float/addr-taken/array/struct-ptr/conflict-raw.
- **RESULT: `(int)tN` casts 382->77 in cap-150 (~80% removed).**
- **corpus PASSED 616/0** (the hard signal — 50k large/edge inputs would expose a bad truncation).
- **The NullWare compile gate (`fast_gate.sh`) was RUNNING when the session ended — its CLEAN=1445 result was NOT captured.** TODO ON RESUME: rebuild + run `bash _qa/fast_gate.sh`, confirm CLEAN=1445/1445 and GOTO<=300 and corpus still 616/0. If a compile error surfaces (e.g. a narrowed temp used where 64-bit is needed), FIX `fits32` (tighten), don't revert. If clean, D1 is done.

## REMAINING BACKLOG (implement ALL, high-risk included; see _qa/ida_parity_backlog.md)
- **D2/D3** single-use call-result temp inline into cond/assign/return (443+420) — the call_temp is dual-bound to RAX so total_reads>1 blocks copy_propagate; needs de-dup of the phantom RAX read.
- **E1** K&R `fun_xxxx()` -> typed prototypes (1232) [RISKY: arity mismatch -> C2197/8; there is a `callee_typed_proto_arity` clamp helper from an earlier milestone; run the FULL 1445 gate after ANY proto change]. **E2** API arity table (dropped 5th+ stack args). **E3** stale-register phantom trailing args on printf wrappers (167). **E4** AL-only bool return typed char, drop `(x&-256)|1` (229).
- **G2** one variable index disqualifies whole param struct (22 fns). **G3** pad-hole/`&field+delta` raw (372). **G4** pointer-valued qword fields typed as pointers (376) [HIGH RISK, reverted before — see decompiler-known-gaps memory]. **G5** missed `p[i]` on typed/global bases (102).
- **H2** struct tags embed raw temp id -> renumbered/stable (376). **H3** API/type-derived local name stems. **H4** char-literal rendering.
- **I1** boolean flag cascades -> `&&`/`||` chains. **I2** state-machine explosion (11 fns, up to 761 arms) -> labeled gotos.
- **A2** `(char*)((char*)p+a)+b` double-cast fold (930). **A10** redundant `(char*)` on integer _QWORD base (22). **C4** `result` idiom when return split (43). **F4** magic-div duplicated-subexpr temp (45).

## KEY FILES
- `engine/analysis/decompiler.cpp` — the whole decompiler (single file, ~15k lines). All parity work is here.
- `_qa/ida_parity_backlog.md` — the checklist (source of truth for what's left).
- `_qa/fast_gate.sh` / `_qa/verify_fast.sh` / `_qa/harness.py` — the gate scripts.
- `_qa/corpus/*.cpp` — 22 behavioral test files (the 616-fn oracle).
- `_qa/ida_parity_survey.js` — the survey workflow that produced the backlog (re-runnable).
- Full history + the info-recovery roadmap + the .NET-decompiler idea are in the auto-memory (`~/.claude/.../memory/`), esp. `decompiler-known-gaps.md` MILESTONE 26.
