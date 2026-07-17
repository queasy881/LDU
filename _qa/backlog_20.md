# THE 20 — overnight run (2026-07-17)

These are ON TOP of the 13 already owed (`_qa/backlog_9.md` = the 9 + R1-R4).
TOTAL OWED = 33. ALL of them. Not a subset.

---
# SCORECARD (updated live; recon workflow wf_7dff84c8-72c, 20 agents + adversarial verify)
# I wrote this list from MEMORY. Recon against the real binary corrected it substantially:
# a third of it was already implemented or has zero sites. Recording that honestly rather
# than "implementing" things that exist — which this project has already paid for twice
# (magic division, symbolic emulation).
#
#  ALREADY IMPLEMENTED (verified, cited):    4  shrd/shld · 7 bt/bts/btr/btc · 8 cpuid+
#      rdtsc+xgetbv (__cpuid_eax/ebx/ecx/edx @13_lift_insn.inc:2245) · 12 packed-float
#      bitwise · 3 stringops is ~done (movs/stos/scas all present; only `cmps` missing and
#      it has ZERO sites) · 11 SSE packed shifts present (psrldq 62 sites), only VEX missing
#  ZERO SITES / CANNOT REPRESENT:            10 AES (0 sites; and Expr width is 1/2/4/8 so
#      there is no 128-bit value to hold a result — building it would be a new lie)
#      · 4 shrd (0 sites) · 16 bitfields (LOW; layout risk unjustified)
#  REAL AND DONE THIS RUN:                   9 atomics (lock xadd -> _InterlockedExchangeAdd)
#      · 19a return-struct-type · 1 ymm256 (the width guard — see below)
#  REAL AND OUTSTANDING:                     2 lanes16 (HIGH) · 6 bswap · 11 VEX pshifts
#      · 17 varargs (11 fns) · 14/15/18/20 pending recon
#
# BIGGEST FIND OF THE NIGHT (item 1, ymm256) — a CONFIDENT LIE, gate-blind:
#   The VEX->SSE normalization had NO operand-width guard, so it remapped 32-byte ymm ops
#   onto SSE handlers that hardcode 16 bytes. Measured on _qa/ymm/ymmtest.c:
#       truth:  void ymm_copy32(char* dst, const char* src)   // dst[0..31] = src[0..31]
#       ours:   void ymm_copy32(int32_t*a1) { *a1 = 0; }      // src param DELETED
#   A 32-byte copy reported as a 4-byte zero, compiling clean — 1497/1497 saw nothing.
#   Controls prove the remap is fine at 128-bit (vex_scalar -> `a1 / a2 + a1 * a2`), so the
#   guard is narrow. Both recon agents independently said DO NOT build a lane model: nothing
#   reads byte lanes, and a symbolic 16-lane pmovmskb is a 400-char expression. They were
#   right — the value was in finding the lie, not in modeling the vectors.
#
#   MEASURED ON THE REAL BINARY (the two most-called functions in NullWare):
#     fn_00084b90 = the CRT AVX2 memcpy, called by 109 fns. Recon's words: "catastrophic, it
#       writes zeros instead of copying", plus ~30 phantom 0x20-stride structs invented by the
#       struct reconstructor from the unmodeled ymm strides.
#       AFTER: 0 fabricated `= 0` stores, 5 phantom structs, "confidence: LOW - 102 unmodeled
#       ops (__vmovntdq, __vmovdqu, __vmovdqa)".
#     fn_00085240 = the CRT AVX2 memset. `vmovdqa ymmword [rcx], ymm0` rendered as
#       `*(int32_t*)(..) = 0` — wrong on BOTH axes: a 4-byte access for a 32-byte store AND a
#       constant 0 instead of the broadcast fill, so `memset(p, 0xAB, n)` decompiled as writing
#       ZEROS. AFTER: 0 fabricated stores, 1 phantom struct, "confidence: LOW - 68 unmodeled ops".
#   Mechanism of the 4-byte access, for the record: store_lvalue sets width = op.size = 32; 32 is
#   not a C scalar width, so cast_str's `default: return "(int)"` silently renders it as int32_t.
---

Same bar as always: env kill-switch · real evidence from a live binary · adversarial verify ·
full gate (NullWare 1497/1497 cl-clean + GOTO<=119; corpus 629 PASS / 1 FAIL) before commit.
Never ship plausible-but-wrong C to close an item.

---

## GROUP A — the unmodeled-instruction families (all adversarially VERIFIED absent)
The systemic damage: an unmodeled instruction both DROPS its math AND leaves stale flags, so
the next jcc renders a confidently-wrong condition. Every one of these is a real hole.

1.  **YMM / 256-bit AVX register model** — THE architectural gap. `fn_00084b90` IS the CRT's
    AVX2 memcpy (66 YMM ops) and is called by 107+ fns; the engine models 128-bit xmm only, so
    the body is unrecoverable. vmovdqu/vmovntdq(x30)/vpxor/vpcmpeqb/vzeroupper.
2.  **16-byte lane model** — pcmpeqb/pmovmskb/pshufb/pslldq/psrldq. This is the SSE2 strlen/
    strchr/memchr idiom; without lanes those fns are opaque.
3.  **String ops** — `repe cmpsb`->memcmp, `repne scasb`->strlen, `rep stosq`->memset.
    (`rep movs`->__movsb already landed; these are its missing siblings.)
4.  **SHRD / SHLD** — double-precision shift = 128-bit shifts + bignum.
5.  **BMI1/BMI2** — ANDN, BEXTR, BLSI, BLSR, BLSMSK, TZCNT, LZCNT, MULX.
6.  **BSWAP** -> `_byteswap_ushort/_ulong/_uint64` (and the htons/htonl reading).
7.  **BT / BTS / BTR / BTC** -> `_bittest` / `_bittestandset` / `_bittestandreset` /
    `_bittestandcomplement`. Currently the bit index math is emitted raw or dropped.
8.  **CPUID / XGETBV / RDTSC / RDTSCP** -> `__cpuid` / `__xgetbv` / `__rdtsc`. Every CRT init
    and every anti-debug check starts here.
9.  **LOCK atomics** -> `_InterlockedExchangeAdd` / `_InterlockedCompareExchange` /
    `_InterlockedExchange` / `Increment` / `Decrement` / `And` / `Or` / `Xor`, + CMPXCHG16B.
    Today a `lock xadd` refcount looks like a plain add — that is a SILENT correctness lie.
10. **AES-NI** -> `_mm_aesenc_si128` etc. Names the crypto instead of dropping it.
11. **Packed integer shifts** — PSRAD/PSRLD/PSLLD/PSRAW/PSRLW/PSLLW/PSRLQ/PSLLQ.
12. **Packed float bitwise** — ORPS/ANDPS/XORPS/ANDNPS + the `andps mask`->fabs and
    `xorps signbit`->fneg idioms (these two render as garbage today).
13. **Saturating packs / unpacks** — PACKSSDW/PACKUSWB/PACKSSWB/PUNPCKL*/PUNPCKH*.

## GROUP B — type & structure recovery (IDA-parity readability)
14. **Enum recovery** — a var compared/switched against a closed constant set becomes a named
    enum; switch cases get symbolic labels.
15. **Union detection** — one struct offset loaded at two incompatible types = a union member,
    not a bad guess to be silently overwritten.
16. **Bitfield recovery** — `(x >> k) & mask` on a struct field -> `unsigned f : n;`.
17. **Varargs detection** — the va_start home-spill idiom -> `f(const char*, ...)`.
18. **noreturn detection** — a callee that never returns (call not followed by an epilogue;
    ends in int29/__fastfail/ExitProcess) -> `__declspec(noreturn)`; lets the caller drop its
    unreachable tail, which kills gotos for free.
19. **sret / struct-return-by-hidden-pointer** — the >8-byte return ABI. Today the hidden RCX
    pointer masquerades as param 1, so EVERY such fn has a phantom first arg and a wrong return
    type. This is a real, systematic signature bug.
    ### RESOLVED 2026-07-17 — split in two by the evidence. Fixture: `_qa/sret/srettest.c`.
    **19a WRONG RETURN TYPE — FIXED (universal, sound, landed).** `ret_struct_ty()` in
    decompiler.cpp: when every return path hands back the same recovered-struct pointer, the
    return type IS that struct pointer. Before/after on the fixture:
      `float* sret_make_vec(struct Vec3*a1, ...) { ...; return (float*)a1; }`
      `struct Vec3* sret_make_vec(struct Vec3*a1, ...) { ...; return a1; }`
    The old type was field 0's SCALAR width; the declared type contradicted the returned
    expression and only the inserted cast kept it compiling. Kill switch DS_NO_RETSTRUCT.
    NOTE it is computed LAZILY at render time on purpose: param_structs does not exist until
    recover_struct_layouts() (:4224), which runs ~50 lines AFTER recover_return_type() (:4176),
    so a pass at the natural-looking spot reads an empty map and silently never fires. The
    first cut did exactly that.
    **19b PHANTOM FIRST ARG — UNDECIDABLE HERE. Deliberately NOT built.** sret IS "an implicit
    pointer first param": these two are ABI-identical, same machine code, and differ only in
    source-level intent —
      `Vec3  make(float,float,float)`      -> RCX=out, XMM1..3 = args
      `Vec3* fill(Vec3*, float,float,float)` -> RCX=arg0, XMM1..3 = args
    The fixture proves it: `notsret_fill` has EXACTLY the naive sret signature (returns its own
    RCX, stores through it, never reads it). Any behavioural detector fires there and SILENTLY
    DELETES A LIVE PARAMETER. `Vec3 v = make(..)` and `Vec3 v; fill(&v,..)` are the same code —
    this is an identity, not a weakness of the analysis.
    Both possible type oracles were checked and are EMPTY on every binary here:
      - mangled names: NullWare has NO EXPORT TABLE; classtest/showcase/srettest export 0
        mangled names (all undecorated). demangle_msvc() also passes UNDNAME_NAME_ONLY (0x1000),
        which discards the return type — flags=0 would give the full signature IF a name existed.
      - PDB: engine/analysis/pdb.cpp recovers NAMES ONLY (no TPI/type stream), and no .pdb
        exists next to any test binary.
    Same precedent as R3/OLLVM: zero coverage means it cannot be validated, so it must not be
    built. REOPEN THIS the day a mangled-name or PDB-type oracle has real coverage — the fixture
    and the analysis are already here.
20. **Devirtualization** — a vtable slot load whose class is RTTI-known -> `obj->Method()` by
    NAME. The RTTI + vtable machinery from MILESTONE 23 already recovers both halves; this
    joins them at the call site.

---

# 21. THE R_NONE ZERO BACKSTOP  [FOUND 2026-07-17 by the ymm256 adversarial verifier —
#     probably the single biggest confident lie left in the engine. NOT YET FIXED.]
#
#   07_nullconst_backstop.inc, rvalue():
#       Reg r; int w; map_reg(op.reg, r, w);
#       if (r == R_NONE) return mkConst(0, w ? w : 8);     <-- fabricates a ZERO
#
#   EVERY register class the engine does not model reads back as the literal constant 0:
#   ymm/zmm, mmx, segment, control, debug. It is not a "missing value" marker — it is a
#   specific false claim, and it PROPAGATES: constant-folding believes it, so it reaches
#   conditions. Verified live in the NullWare dump (fn_00084848, the SSE2/AVX2 strlen):
#       if (__vpmovmskb(0)) break;                       (3 sites)
#       if (__vpmovmskb(0)) { ... }                      (4 sites)
#       v12 = ((1 << v1) - 1) & __vpmovmskb(0);
#       return (uint32_t)__tzcnt(__vpmovmskb(0)) + v5;
#   The scanned string data is replaced by 0 and the result GATES THE LOOP EXITS. It
#   compiles clean (`int32_t __vpmovmskb();` is old-style, so any arity passes cl), so the
#   1497/1497 gate is blind — same blindness that hid the ymm `*a1 = 0` store.
#
#   FIX: an unmapped register must read as a NAMED PLACEHOLDER, not 0 — mirror the existing
#   `in_<REG>` phantom-live-in machinery (unknown_reg_name), which the confidence header
#   ALREADY counts ("N phantom live-ins"). Then `__vpmovmskb(in_YMM1)` is honest and the
#   banner discloses it.
#   DANGER — DO THIS AS ITS OWN CYCLE WITH ITS OWN GATE: rvalue() is the hottest path in the
#   lifter and this touches EVERY unmodeled-register read at once. Expect large output churn
#   (a placeholder does not fold where 0 did). Measure CHARS + the long-line histogram, not
#   line count. Kill switch DS_NO_REGPLACEHOLDER.

# 22. PASS ORDERING IS THE RECURRING TRAP — read this before adding a pass (3 hits in one night)
#
# A pass placed where its call site READS WELL, rather than where its INPUTS ARE FILLED, sees
# empty maps. An empty map answers "no" to every question, so the pass either silently never
# fires or — worse — its safety guard passes everything.
#   1. ret_struct_ty : read param_structs, which recover_struct_layouts() fills ~50 lines LATER.
#      Silently never fired. Fixed by computing it LAZILY at render time instead of as a pass.
#   2. detect_stl_vectors' 2nd signature : looked like the same bug; was actually a stale binary.
#   3. propagate_api_types : read var_pointer / ptr_elem_width to refuse overriding a proven
#      pointer, but sat BEFORE collect_var_info + propagate_pointer_types. The guard therefore
#      passed everything and typed `int8_t* j` as LPCRITICAL_SECTION -> `j[0x38]` -> C2109 on
#      fn_0007f17c. The cl gate caught it; nothing else would have.
# RULE: before inserting a pass, grep where each map it reads is WRITTEN, and put the pass after
# the LAST writer. If that is awkward, compute lazily at render time — by then everything is final.
#
# 24. COMMIT `git add -f <dir>/*` SWEEPS IN WORK THE MESSAGE DOES NOT MENTION
# 3e681f3 ("Win32 types on variables, wide literals, _byteswap_*, std_vector, format arity")
# ALSO contains the locked-RMW family (try_interlocked_rmw: lock or/and/inc/dec ->
# _InterlockedOr/And/ExchangeAdd, 6 -> 89 sites) because the staging line was
# `git add -f engine/analysis/decomp/*.inc` and that work was already in the tree. The commit
# is correct and gated; its MESSAGE is incomplete, which is worse than it sounds — the message
# is what the next reader bisects against. Stage the FILES a change touches, not a glob.
#
# 23. STALE-BINARY / BAD-GREP DISCIPLINE (cost several cycles this night)
#   - `cargo ... | grep -c "error C"` must be CHECKED, not printed: a failing build leaves the
#     OLD exe in place and its output reads exactly like a working feature. Gate commands are
#     now `E=$(...); [ "$E" = "0" ] && <run>`.
#   - AND `error C` DOES NOT CATCH LINKER FAILURES. Building while a gate is running gives
#     `LINK : fatal error LNK1104: cannot open file dump_pairs-<hash>.exe` -- the exe is locked
#     by the running dump -- and `grep -c "error C"` reports 0. The C++ compiles, the .lib
#     updates, the EXE DOES NOT, and the next run silently uses the old binary. Grep
#     `error C[0-9]{4}|LNK[0-9]{4}|^error` and never build while a gate holds the exe.
#     (Confirmed 2026-07-17: exe mtime 17 minutes stale while "BUILD_ERRORS=0".)
#   - Anchor greps. `grep '\bgoto '` also matches the confidence header ("1 residual goto") and
#     inflated a whole-binary count 568 -> 637. `grep WSTR` matches LPCWSTR and faked a stale
#     binary. Count `goto [A-Za-z0-9_]*;` with the semicolon.
#   - Do NOT build C++ string literals through a python heredoc: `\n` arrived as a real newline
#     twice (C2001), both times leaving a stale exe behind. Use the Edit tool.

# STRETCH (do after the 20 if the night holds)
thunk collapsing (jmp trampolines) · __security_cookie prolog/epilog hiding · wide L"" strings ·
delay-load imports · TLS callbacks · .CRT$XCU static ctors · export forwarders · import-by-
ordinal naming · __purecall detection.

# MERGE DISCIPLINE (learned the hard way)
Group A items are mostly ADDITIVE switch arms in `decomp/13_lift_insn.inc` and DO compose.
Group B items touch shared inference and DO NOT — apply one at a time, build between each,
gate before commit. Never `git checkout` a conflicted stack: it reverts the good patches too.
