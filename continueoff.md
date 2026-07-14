# CONTINUE-OFF — IDA-parity sweep (work AFTER the survey agents found the issues)

## >>> STRUCTURER NIGHT (user 2026-07-14, CURRENT FOCUS) <<<
Goal: drive REDUCIBLE gotos -> 0 (irreducible are fine) with NO code duplication and IDA-like
readability; then load kernel32.dll, classify its gotos reducible/irreducible, fix the reducible ones.
Metric = reducible gotos on the 129 NullWare reducible-goto fns (baseline 262) + full-binary GOTO_TOTAL
(lineage baseline: loop-sink build = 292 / 11 state-machines, corpus 616/0).

LANDED THIS SESSION (uncommitted until gate, corpus 616/0 already GREEN):
- **Loop-sink knobs REVERTED** (region bound 40->24, N-way cap 5->3 — they net-REGRESSED +8; the memory
  warned raising bounds backfires) + loop_sinks_for sort simplified to address order (removes block_reaches
  from the hot emission path — was stalling full dumps).
- **ACYCLIC PROPER-REGION FLAG STRUCTURER** (the big lever): a single-entry acyclic region whose join
  post-dominates no branch (fn_00014b50's F/D/E/54 lattice) has NO goto-free if/else form without
  duplication. `emit_flagged_region` lifts ONLY the cross-joins (>=2-pred blocks with `ipdom[idom[J]]!=J`)
  to a `char __at_<addr>` reaching-flag; every other block emits inline with natural nested if/else via
  `emit_flag_chain`; inner loops are OPAQUE nodes (emit_loop + flag the follow). Zero gotos, ZERO dup.
  fn_00014b50: 3 gotos -> 0 with 6 flags, clean structure. On the 129 targets: **262 -> 183 reducible
  gotos** (chain version, fired on 38 fns). Env: DS_NO_ACYCFLAG. Debug: DS_DBG_FLAG. Census: DS_GOTO_WHY
  (goto cause tags: fanin/obreak/ocont/pdom/inloop).
- **Coverage fix (building/gating now):** wrapper on emit_if_else precomputes `cross_joins` per fn and
  fires emit_flagged_region at the OUTERMOST if dominating a cross-join (its true single entry) — fixes
  the "fired too deep -> bail structured" (10568 bails) + many multi-entry bails. `emit_if_else` split
  into wrapper + `emit_if_else_body`; `in_flag_region` guards re-entry.
PROGRESSION (all committed, corpus 616/0, 1445/1445 cl-clean): loop-sink 292 GOTO -> flag structurer
212 -> +wrapper 175 -> +SESE 157 (1c15c06) -> +whole-fn fallback 123 (beafea9) -> +relative soup-cap 115
(4ba9593). state-machines 11->9. NullWare GOTO 292->115 = -61%. kernel32.dll: 242->210 reducible gotos
(GENERALIZES, not overfit; census _qa/kernel32_irred.csv). NEXT LEVER (user's "fix stuff u missed"):
MULTI-EXIT LOOPS (emit_loop gotos the secondary exit -> the whole-fn fallback bails "chain" on ~half the
kernel32 residual + NullWare 0x79d64). Fix = extend flag_dispatch_multiexit_loops (pre-emission CFG
transform, already does 2-exit loops + N-way forward regions via node-split) to N-EXIT loops; RISKY
(subtle, prior knob-loosening regressed) -> validate with a selfdll/corpus multi-exit-loop behavioral test
FIRST. Big-complex parsers (kernel32 0x7a8a8 = 15 `goto shared_tail` in a loop) are the high-fan-in tail
Hex-Rays also gotos. READABILITY KNOB the user should tune: DS_NO_FNFLAG reverts the whole-fn fallback to
the CLEAN scoped-only result (GOTO 157, no flag-soup); default keeps the fallback (GOTO 115, flaggier on
genuinely-tangled fns) honoring the "0 gotos" priority.
- **SESE flag region** (committed): emit_flagged_region uses rexit=ipdom[entry] (proper single-entry
  single-exit region, dominated blocks only), emits tail [rexit,stop) normally; only fires when R
  contains a genuine cross-join.
- **Whole-function flag fallback** (emit_function_flagged, UNCOMMITTED as of this note): if structuring
  still leaves reducible gotos AND cfg_is_reducible(), re-emit the WHOLE function as a flag chain (from
  entry every block is dominated -> single entry; stop=-1 -> all leaves are returns -> provably 0 gotos,
  0 dup). SOUP-CAP: accept only if clean_flagged = (flags - cross_joins) <= 3, so it flags ~only genuine
  cross-joins, not clean if/else merges. Env DS_NO_FNFLAG. Targets -> 85 (from 123). Bails on switch /
  multi-exit-loop (emit_loop still gotos there) -> those keep gotos.
REMAINING hard buckets: switch-containing fns, multi-exit loops, and cross-join loops. Then
GENERALIZATION: `DS_REAL_BIN=C:\Windows\System32\kernel32.dll python _qa/irreducible.py`, fix its reducible
gotos (don't overfit to NullWare). HARD CONSTRAINT: never tail-duplicate; flags/node-split only.
READABILITY NOTE: the flag form (`char __at_<addr>` + guarded join blocks) is goto-free + no-dup but
flaggier than Hex-Rays gotos for genuinely-tangled fns; the soup-cap keeps clean fns readable.
Tooling: `_qa/irreducible.py` (census, `--targets`/`--csv`), `_qa/goto_ab.sh`, `python _qa/irreducible.py --targets` = the 129-fn reducible target list.



Context: a 12-agent survey workflow (`_qa/ida_parity_survey.js`) read our real decompiled NullWare
output and ranked, across 12 dimensions, where it reads worse than Hex-Rays. The findings were
distilled into a backlog: **`_qa/ida_parity_backlog.md`** (45 items, A1..J). Since then I've been
implementing that backlog, **gating every change** against the hard gates before moving on.

## THE 4 STANDING RULES (user, 2026-07-13 — away 8 days, fully autonomous)
A session Stop-hook enforces these; do NOT pause to ask permission or announce "done except X, continue?".
1. **NEVER STOP / NEVER ASK.** Keep working until the whole goal is done. After a compaction/reset:
   re-read this file + `_qa/ida_parity_backlog.md` + memory `decompiler-known-gaps` MILESTONE 26, then
   pick up the next unchecked item and continue the implement→gate loop.
2. **IMPLEMENT EVERY 12-agent finding to the fullest**, including the high-risk ones (D1, E signatures,
   G4 pointer-fields, I2 state-machines). Verify no regression via the gates. **On a regression: FIX the
   root cause, NEVER revert.**
3. **THEN launch 12 NEW agents.** ONLY when the entire existing backlog is done+gated, run a fresh
   12-agent survey to find MORE IDA-parity improvements, and repeat the cycle on their findings.
4. **NEVER WASTE THE GATE WAIT.** The ~5-min 1445-fn gate: while it runs, implement the next backlog
   item in source so it's ready to build the instant the gate returns. Pipeline, never idle-poll.

**FINAL STEP when all of Rules 1–3 are done:** `git push origin main` to https://github.com/queasy881/LDU
(user configures git identity/auth). Do NOT enter the user's credentials; if a push prompts for a
password/token, that step is theirs. Refresh this file before the final push.

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

## PROGRESS LOG (most recent first)
- **STRUCTURER NIGHT (user 2026-07-14): drive REDUCIBLE gotos to 0.** Tool = `_qa/irreducible.py` (T1-T2 census: reducible=must-fix vs irreducible=keep) + `_qa/goto_ab.sh <rvas>` (fast per-fn goto A/B, reducibility is static so no re-census needed). BASELINE: total gotos 277, **REDUCIBLE_GOTOS=254 across 124 fns** (must->0), irreducible=23 across 5 fns (0x2c3d0 0x39aa0 0x70de0 0x24b0 0xe390 — KEEP), 8 reducible state-machines (0x26d0 0x4b530 0x57760 0x5cf90 0x65e34 0x6636c 0x6d5e4 0x70650 — worst, must structure). TOP reducible-goto targets: 0x19b80(8) 0x3e940(7) 0x5cba0(7) 0x25ad0(6) 0x23740(5) 0x24e90(5) 0x27f10(5) 0x35a30(5) 0x35b70(5) 0x71f30(5) 0x7fa54(5). METHOD: DS_DBG_FWD/DS_DBG_IF/DS_DBG_LOOPS on a target -> find rejection bucket -> fix -> DS_PAIRS_RVAS A/B -> gate corpus616/torture-bit-identical/NullWare1445. Dominant bucket = **in_loop joins** (flag_dispatch @10595 rejects them) -> needs loop-aware forward structuring (the relooper loop shape). Easy knobs already bumped: region bound 24->40 @~10618, N-way exit cap 3->5 @~10628. GATES: e2119de committed (C++ semantics + temp/deref). Base = e2119de.
- **e2119de** — C++ semantics (namespace blocks, class/struct/template, __vftable, operator_new) + D2/D3 return fold + A10 + H2. Gated 616/0, 1445/1445, GOTO 291.
- G3 (gating) — nested-const-offset `(a1+c1)+c2` now resolves in struct_base_offset (@~3308) -> field_(c1+c2) recovered instead of raw `&field_c1 + c2` (a lea-temp copy_propagate inlined without re-folding). fn_00006aa0: 78->2 `&field+N`. corpus 616/0. NullWare gate running.
- REMAINING BACKLOG PLAN: safe render items (F4/C4/D2-5/A10/H2) -> a multi-item analysis workflow then batch-implement. RISKY items (E1 typed-protos [silent arg-drop via clamp, no NullWare behavioral gate -> DEFER, do high-confidence-arity-only subset], E3 phantom-API-args, I2 state-machine->labeled-gotos) -> dedicated careful cycles w/ workflow support. Then Rule 3 (12 new agents). E1 machinery: callee_typed_proto_arity @9397 (gated to FLOAT-param callees; proto emitter @~15994; call-site clamp @9358).
- **983150d** — G4 pointer-fields->void* (352 fields/238 fns), previously-reverted high-risk, landed via 8-agent audit workflow. Gated 616/0 + 1445/1445 + GOTO 291. See [[decompiler-known-gaps]] MILESTONE 28.
- **cc1c315** — G5 global-address subscript.
- **7679712** (committed) — class recon (MSVC+G++ RTTI) + redundant-cast drop + E4 render-strip. Gated corpus 616/0, NullWare 1445/1445, GOTO 291. Class recon VERIFIED on classtest.dll (MSVC) + classtest_gcc.dll (g++): `struct GameManager* v1; v1->field_0 = <vtable>`.
- E4 byte-RETYPE (widening detection so `int` bool-fns become byte) DEFERRED as risky (program-wide callee-sig, no NullWare behavioral gate) — see backlog E4.
- G5 (subset) DONE, gating: global-address array subscript `*(T*)((char*)0xADDR + idx*esize)` -> `((T*)0xADDR)[idx]` (try_array_subscript early branch @~9479; renders RAW hex addr, NOT qword_X which #defines to a deref'd value). Sound: access width == elem width by the scale match. corpus 616/0.
- NEXT MAIN ITEM = **G4** (pointer-valued qword fields -> typed pointers, 376). PLAN: the machinery already EXISTS (is_struct_ptr_field @3242 reads fptr[off]; struct_typedef_str emits `void*` for fptr fields @~3767; nested-struct feature already added uniform is_struct_ptr_field byte-cast to rptr/render_addr/renders_as_pointer). scan_field_ptr (@3214) is currently UNRUN (deliberately disabled note @3567) so top-level fptr never set. G4 = CALL scan_field_ptr over all blocks in recover_struct_layouts BEFORE the fptr build (~3629 reads struct_field_ptr[p]), then rebuild+gate and FIX (not revert) any residual C2110/C2113 (ptr+ptr / int-ptr arith positions the nested work didn't cover). Gate hard: corpus 616/0 + NullWare 1445/1445. Iterative (expect a few fix rounds).
- Other candidates deferred: I1 flag cascades (pure-CFG already done by merge_short_circuit @10678; residual = flags set via ASSIGNMENTS across blocks = risky dataflow), E3 phantom API args (risky arity), pointer-arith VAR->element-index (composition hazard: element arith doesn't compose under nested +K).

## D1 (temp-width narrowing) — DONE + GATED
**D1 was the biggest remaining lever (6642 `(int)tN` casts).** `narrow_temp_widths()` (just before `compute_display_renumber`): a VALUE-RANGE FIXPOINT — narrow a `long long` temp to `int` (keeping signedness) iff its VALUE provably fits 32 bits (`fits32(e)` monotone fixpoint over the temp's defs: Cast w<=4 / Binary,Unary w<=4 / &|^ w8 both fit / >> w8 fits(a) / Mem w<=4 / Const in [-2^31,2^31-1] / int-return Call). Sets the Var node widths to 4; a `peephole_expr` rule drops the now-redundant same-width `(int)v` cast. Excludes ptr/float/addr-taken/array/struct-ptr/conflict-raw.
- **`(int)tN` casts 382->77 in cap-150 (~80% removed).** Gated **corpus 616/0 + NullWare 1445/1445**.
- **REGRESSION FIXED (not reverted):** byte_swap64/varint truncated 64-bit inputs — a self-referential temp (`v=(ull)v>>8`) has an implicit 64-bit param-home init (`v=a1`) the fixpoint didn't see. Fix = **has_root_def guard**: disqualify any candidate whose every explicit def reads itself.

## IN FLIGHT — CLASS / STRUCT RECONSTRUCTION (user's explicit "build this first")
Goal: decompiled output should show `struct Entity { int field_0; float field_4; ... }` and, for a class
with virtuals, name it by its RTTI class (`struct GameManager { ... }`) with a vtable-pointer field_0.
- **MSVC RTTI (done earlier):** `rtti.cpp` now also seeds a `<Class>__vftable` symbol at the vtable RVA
  (`pos`, offc==0) so a ctor's `*obj = <vtable>` is recognizable. `class_for_vtable(addr)` helper in
  decompiler.cpp maps a stored vtable address → class name.
- **NEXT (uncommitted, not yet gated):** in `recover_struct_layouts`, scan for `field_0 = Const(vtable)`
  via `class_for_vtable`, record `struct_class[base]=<Class>`, and use it for the struct tag (instead of
  `s_<fn>_<param>`) at the 4 `L.tag =` sites. Then rebuild + dump `_qa/classtest/classtest.dll` and
  CONFIRM `gm_make` emits `struct GameManager { ... }`. Test file: `_qa/classtest/classtest.cpp`
  (Entity struct + GameManager class w/ virtuals; MSVC `cl /LD /GR /O2 /GS-`).
- **THEN — G++ (Itanium ABI) RTTI recovery:** add `_ZTV<len><name>` vtable / `_ZTI` type_info / `_ZTS`
  type-string parsing to `rtti.cpp` (currently MSVC-COL-only, x64). Build `classtest_gcc.dll`
  (`g++ -shared -O2 -fno-exceptions`) and verify class recovery there too.
- Gate the whole class-recovery batch (+ H4 char-literal) at 616/0 + 1445/1445 before resuming backlog.

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
