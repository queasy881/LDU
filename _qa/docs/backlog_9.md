# THE 9 — user-mandated, ALL must be implemented (2026-07-16)

Order: the 13-feature run (wf_9fbea18b-0be) lands + is gated FIRST. Then ALL 9 of these.
NOT a subset. NOT "the tractable ones". ALL. Each gets: env kill-switch, real evidence on a
live binary, adversarial verify, then the full gate (NullWare 1497/1497 cl-clean + GOTO<=119,
corpus 629 PASS / 1 FAIL) before commit.

Grep-verified as NOT already present (2026-07-16) — do not re-litigate whether they exist.

---

## 1. UNWIND_INFO prolog opcodes -> authoritative frame layout   [HIGHEST VALUE]
`grep UWOP_ = 0`. .xdata is parsed for EH scopes ONLY. The prolog opcodes encode the frame
EXACTLY: UWOP_SET_FPREG (which reg is the frame ptr + offset), UWOP_ALLOC_LARGE/SMALL (frame
size), UWOP_PUSH_NONVOL (each push). `scan_prologue()` @1885 currently PATTERN-MATCHES
instructions to guess all of it.
WHY: fixes KNOWN, twice-deferred correctness bugs the memory documents —
  "P2 FRAME-ALIAS PARAM-HOME (NULL-deref, ~tens of fns)"
  "P6 rbp-from-alias OFF-BY-frame_size: DEFERRED (correct offset REGRESSED a compile)"
Win64 REQUIRES this data (no unwind without it), so it is ground truth, not a heuristic.
Anchors: compute_pe_tables()/pe_data_dir() already reach .pdata->UNWIND_INFO rva; PeTables
holds the pdata entries. scan_prologue @1885 is what it replaces/validates.
RISK: must fall back to the current scan when unwind data is absent (32-bit, leaf fns).

## 2. reloc64 -> global POINTER CLASSIFICATION   [CHEAPEST BIG WIN — data already parsed]
`petab->reloc64` (IMAGE_REL_BASED_DIR64 RVAs) is built @506 but has exactly ONE use site
(@3690, inlining a reloc-typed string). It is a DECIDABLE ORACLE: an 8-byte slot whose RVA is
in reloc64 IS a pointer (the loader rebases it); one that is NOT cannot be.
WHY: types real global pointers AND — more valuable — DISPROVES false pointer inference. The
engine guesses via mark_ptr_in_addr today; `zero_signed_vars` exists purely to veto a bad
guess (see decl_type @2911). The info-recovery roadmap already calls relocations top-ROI.

## 3. RTTI BaseClassArray -> real inheritance
`grep ClassHierarchy|BaseClassArray|mdisp = 0`. rtti.cpp reads COL -> TypeDescriptor for the
NAME and stops. Follow COL -> RTTIClassHierarchyDescriptor -> RTTIBaseClassArray: gives every
base class AND each base's offset (PMD.mdisp).
WHY: flat `struct GameManager { field_0; field_8; }` becomes `struct GameManager : Entity`
with the base subobject at its true offset; explains MI adjustor thunks (`offc>0` is already
read but unused for this). Verify on _qa/classtest/classtest.dll + classtest_gcc.dll.

## 4. Real CF tracking   [unlocks 3 things I had to decline]
set_flags_arith @~8300 stores ONLY the result value (flags.a = res, is_arith), so CF after
add/shr/mul is unrecoverable and cc_to_expr(CC::B) FABRICATES one.
WHY: this single root cause forced me to decline RCL/RCR, leave ADC opaque, and skip
ADCX/ADOX — all in one session. Model CF explicitly per setter:
  add -> (a+b) <u a      sub/cmp -> a <u b      shr n -> (x >> (n-1)) & 1
  shl n -> (x >> (w-n)) & 1                     mul -> high != 0
Then ADC/SBB/RCR/RCL/ADCX/SHRD carry chains all become EXACT. Bignum/crypto is opaque today
ONLY because of this.
RISK: touches every flag consumer — full gate is mandatory. Do it as its own cycle.

## 5. catch (Type&) from the EH typeinfo
eh_annotation() already parses the C++ FuncInfo magic (0x1993052x) and finds handlers; the
handler record points at a TypeDescriptor. ONE more hop gives the CAUGHT TYPE.
WHY: `__except` / bare try annotations become `catch (std::exception&)`.

## 6. FLIRT signatures for the CRT
`flirt_match` (symbols.cpp:74) has TWO signatures (__security_check_cookie, _RTC_CheckEsp).
fn_00084b90 IS memcpy — called by 107+ fns, body unrecoverable (66 YMM ops, 256-bit, and the
engine models 128-bit xmm).
WHY: names 107+ call sites AND tells the reader the unrecoverable body does not matter.
Extend the table: memcpy/memset/memmove/strlen/strcmp/malloc/free + the MSVC CRT init stubs.
Every assignment MUST be uniqueness-guarded (name_taken()) and only upgrade `fun_` placeholders.

## 7. Stale-flag invalidation   [the audit's systemic finding]
An unmodeled FLAG-WRITING instruction leaves `flags` holding an EARLIER, unrelated compare, so
the next jcc renders a CONFIDENTLY WRONG condition (or `if(1)` via cc_to_expr's !fs.valid path
@5427). Verified real on ntdll RtlCompareMemory by the instruction audit.
Capstone exposes per-instruction eflags (cs_x86.eflags) — invalidate `flags` when the op
writes them and we did not model the write.
NOTE: `if(1)` is also wrong — weigh honestly vs a plausible lie, and MEASURE on NullWare.

## 8. Cross-function type propagation
Each function is typed in ISOLATION today. A callee's recovered param types constrain every
caller's args, and a caller's arg types constrain the callee. Iterate to a fixpoint over the
call graph (sigtab already holds per-fn param_count/float_mask/ret_kind).
WHY: the roadmap lists whole-program type-prop as untapped. DANGER: mutating the program-wide
sig table has no NullWare behavioural gate — the corpus is the only net (see milestone 22's 14
C2197/C2198). Land it hard-gated, on its own.

## 9. Self-referential struct -> linked lists
A void* field whose LOADED VALUE is used as a base of THE SAME struct is `struct Node* next`.
The G4 machinery (scan_field_ptr/fptr/fptr_tag) already proves the field is a pointer and
already supports a typed `struct X* field` (nested-struct retyping) — this just closes the
loop back onto the parent tag. Verify on _qa/corpus/linklist.dll.

---

# ALSO OWED (not part of "the 9" — these fell out of the earlier 18)

## R1. range-for over std::vector          [of the 8 recovery]
Its agent never produced a worktree in wf_9fbea18b-0be. detect_stl_vectors() already finds the
_Myfirst/_Mylast/_Myend idiom; detect_for_loops() (DS_NO_FORLOOP) is the precedent for a pure
RE-RENDER that is goto-neutral by construction. Emit the ITERATOR form (always correct); only
claim the range-for sugar when the body's sole use of the iterator is a dereference.

## R2. type-library / typed Win32 prototypes   [general #8]
The agent's work EXISTS and is good — 56-entry table + api_type_backing() + api_param_types(),
saved at scratchpad/typelib_block.txt. Its patch is against a stale base (pre-split), so apply
MANUALLY: table -> engine/analysis/decomp/14_lift_support.inc next to known_api(); wiring ->
decompiler.cpp at seen_proto(:4937), known_api-in-proto-emitter(:4987), build_xref_comment(:5009).
SAFETY (the agent got this right — preserve it): arity is NEVER taken from this table;
known_api()'s argc is the sole authority and a length mismatch REJECTS the types, so a typo
cannot desync a proto from its call site (the C2197/C2198 class). Typedefs are INTEGER-backed
so no call site needs a new cast.

## R3. OLLVM unflattening — DETECTOR ONLY   [general #4]
Recon: NullWare has ZERO flattened functions (5 layers of evidence), so a CFG rewrite cannot be
validated and must NOT be built. Build only the detector: report how many fns match the
dispatcher/state-variable shape. cfg_is_reducible() + DS_IRRED_REPORT are the precedents.

## R4. whole-program recompilable export   [general #10 — I DROPPED THIS from the 13, do not
##     drop it again]
The flagship per [[recompilable-decompilation-feature]]: decompile every function, combine into
one TU, recompile. The closed-program version already WORKS (difftest.sh). Remaining per the
memory: global-data reconstruction (build FIRST), IAT, signature reconcile, CRT/EH glue.
Known blocker: a whole-program recompile hits C2040/C2371 signature-reconcile errors (this is
why rtti_test was moved OUT of _qa/corpus) — NullWare fns compile INDIVIDUALLY so they dodge it.
