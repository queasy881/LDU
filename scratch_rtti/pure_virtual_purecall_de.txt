### FEATURE
Pure-virtual / __purecall detection: recognize a vtable slot that points at the shared abstract-call trap (MSVC `_purecall`, g++ `__cxa_pure_virtual`, or a NULL g++ slot) and annotate it as a pure/abstract slot instead of naming the shared trap as an ordinary class method.

### TRACTABILITY
medium

### CURRENT_HANDLING
engine/analysis/rtti.cpp:412-417 (MSVC vtable-slot naming loop). Today it does `if(!already_seeded(e,fn)){ snprintf(nm,"%s__vftbl_%d",cls,i); ds_engine_add_symbol(e,fn,nm);}` for EVERY exec slot, including the shared `_purecall` thunk -> emits `Shape__vftbl_0` for the CRT abstract-call trap (WRONG: names a shared runtime thunk as a per-class method), and the second pure slot is silently dropped by the already_seeded guard (line 412) -> `Shape__vftbl_1` absent (opaque). g++/Itanium: rtti.cpp:317-326 same, and rtti.cpp:306 + :319 outright REJECT/BREAK on a NULL pure slot (rejects the whole abstract vtable). Pure/abstract detection: NONE anywhere (`grep -rE 'purecall|pure_virtual|__cxa_pure' engine/` = 0 matches).

### GAP
The CRT/STL pure-virtual trap that every abstract class shares is presented as a normal recovered method of whichever abstract class the address-ordered scan reaches first (here `Shape__vftbl_0`); a class with >=2 pure virtuals loses its later pure slots to first-writer-wins (`Shape__vftbl_1` vanishes); nothing marks the class or its slots as abstract; and a devirtualized call landing on the trap reads as an ordinary method call rather than an abstract-call trap. g++ abstract classes with NULL pure slots are dropped from RTTI recovery entirely.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "anonymous namespace, just before `extern \"C\" void ds_engine_scan_rtti` (~line 333)",
  "change": "Add free helper `std::set<uint64_t> collect_purecall_rvas(ds_engine* e)`: re-run the exact COL-vtable recognition (sig==1, pSelf, ptd mapped-nonexec) already used at lines 344-359, and for every recognized vtable record target_rva -> set<slot_index>. Return the set of rvas occupying >=2 DISTINCT slot-indices (the shared abstract-call thunk). Proven: oracle->{0x1f60}, NullWare->{}."
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "top of ds_engine_scan_rtti, after the `if (off || ...) return;` guard (~line 337)",
  "change": "`static const bool no_pure = std::getenv(\"DS_NO_PUREVIRT\")!=nullptr; std::set<uint64_t> purecall = no_pure ? std::set<uint64_t>{} : collect_purecall_rvas(e);`"
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "MSVC slot-naming loop body, lines 412-417 (the `if(!already_seeded(e,fn))` __vftbl_i block)",
  "change": "Before the existing __vftbl_i naming, insert: `if (purecall.count(fn)) { if(!already_seeded(e,fn)) ds_engine_add_symbol(e,fn,\"_purecall\"); char pk[112]; snprintf(pk,sizeof pk,\"%s__vftbl_%d_pure\",cls.c_str(),i); if(!already_seeded(e,pos+8*(uint64_t)i)) ds_engine_add_symbol(e,pos+8*(uint64_t)i,pk); continue; }` \u2014 names the trap canonically ONCE and seeds a per-(class,slot) pure marker at the slot's data address (unique; matched by name like the existing `__extends__` marker)."
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "Itanium scan_rtti_itanium slot loop 317-326 and the reject at 306",
  "change": "Add the same purecall branch keyed on NULL slot (`v==0`) OR name==`__cxa_pure_virtual` OR purecall.count(fn); name the trap `__cxa_pure_virtual`, seed `<cls>__vftbl_<i>_pure` marker. Change line 306/319 so a leading NULL (pure) slot no longer rejects/aborts the vtable \u2014 accept the vtable via its _ZTI back-link and skip null slots as pure (stop only on a non-null non-exec value). Secondary path; MSVC is the proven-firing one."
 },
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "resolve_virtual_call, after `std::string nm = name_for_rva(mr);` (~line 103)",
  "change": "`if (nm==\"_purecall\"||nm==\"__cxa_pure_virtual\") { abstract_call_sites.insert(cur_call_id); }` and have the EK::Call render (16_globals_phis.inc ~2505 / 17_render.inc) prepend `/* pure virtual (abstract call) */` when the callee is that name \u2014 so a devirt'd dispatch onto a pure slot reads as an abstract-call trap. Optional polish; the `_purecall` naming alone already fixes the mislabel."
 },
 {
  "file": "engine/analysis/decomp/09_structs.inc",
  "anchor": "class reconstruction / struct header emit (mktag ~487, struct-class scan ~454-470)",
  "change": "OPTIONAL: when a reconstructed class tag has any `<Class>__vftbl_*_pure` marker, emit `/* abstract; pure virtual slot(s): N,M */` on the struct header. Low surface (abstract bases are rarely reconstructed as structs since they have no operator_new ctor)."
 }
]

### CODE_SKETCH
// engine/analysis/rtti.cpp — anonymous namespace, before ds_engine_scan_rtti.
// The pure-virtual trap is the ONE code address MSVC/g++ store into >=2 vtable slots
// at DISTINCT indices; a real (even inherited) method sits at ONE index across
// base+derived vtables. Proven: oracle -> {0x1f60 @ idx{0,1}}, NullWare -> {}.
std::set<uint64_t> collect_purecall_rvas(ds_engine* e) {
    std::map<uint64_t, std::set<int>> idx;
    for (size_t si = 0; si < e->segment_len; ++si) {
        const ds_segment& s = e->segments[si];
        if (!(s.flags & DS_FLAG_R) || (s.flags & DS_FLAG_X)) continue;
        uint64_t start = (s.rva + 7) & ~7ull, end = s.rva + s.size;
        if (end > e->image_size) end = e->image_size;
        for (uint64_t pos = start + 8; pos + 8 <= end; pos += 8) {
            uint64_t metaVA;                                   // same COL test as lines 344-359
            if (!read_u64(e, pos - 8, metaVA) || metaVA < e->base) continue;
            uint64_t col = metaVA - e->base;
            const ds_segment* cs = ds_seg_for_rva(e, col);
            if (!cs || (cs->flags & DS_FLAG_X)) continue;
            uint32_t sig, self, ptd;
            if (!read_u32(e, col+0x00, sig)  || sig != 1)                          continue;
            if (!read_u32(e, col+0x14, self) || self != (uint32_t)col)             continue;
            if (!read_u32(e, col+0x0C, ptd)  || !ds_rva_is_mapped(e, ptd) ||
                ds_rva_is_exec(e, ptd))                                            continue;
            for (int i = 0; i < 4096; ++i) {
                uint64_t v;
                if (!read_u64(e, pos + 8*(uint64_t)i, v) || v < e->base) break;
                uint64_t fn = v - e->base;
                if (!ds_rva_is_exec(e, fn)) break;
                idx[fn].insert(i);
            }
        }
    }
    std::set<uint64_t> pure;
    for (auto& kv : idx) if (kv.second.size() >= 2) pure.insert(kv.first);
    return pure;
}

// ds_engine_scan_rtti, top:
static const bool no_pure = std::getenv("DS_NO_PUREVIRT") != nullptr;
std::set<uint64_t> purecall = no_pure ? std::set<uint64_t>{} : collect_purecall_rvas(e);

// MSVC slot loop (replaces the body at 412-417):
if (purecall.count(fn)) {
    if (!already_seeded(e, fn)) ds_engine_add_symbol(e, fn, "_purecall");
    char pk[112]; std::snprintf(pk, sizeof pk, "%s__vftbl_%d_pure", cls.c_str(), i);
    if (!already_seeded(e, pos + 8*(uint64_t)i))
        ds_engine_add_symbol(e, pos + 8*(uint64_t)i, pk);
    continue;                                   // do NOT name the shared trap <Class>__vftbl_i
}
if (!already_seeded(e, fn)) { /* ...existing __vftbl_i naming, unchanged... */ }

### SOUNDNESS
The ">=2 distinct slot-indices" rule is proven not to flag legitimately-shared methods: an inherited method occupies the SAME index in base+derived vtables (oracle `name` 0x1080 at Shape[2]+Circle[2] -> 1 distinct index -> not flagged) and NullWare's whole std::exception family shares its two methods at fixed indices {0},{1} -> {} candidates. The change is NAME/COMMENT-only: it never alters emitted C semantics, so it cannot break compilation or behavior. Sole theoretical false-positive: MSVC /OPT:ICF folding two DISTINCT trivial methods that happen to land at different slot indices -> a harmless name/comment mislabel of one folded stub as `_purecall`. Optional hardening: additionally require the flagged target to be noreturn/trap-like (its recovered body ends in int3 padding / tail-calls a known abort-terminate) — `_purecall`'s body qualifies; a folded `return 0` stub does not. Everything gated by env `DS_NO_PUREVIRT` (reverts to exact current `<Class>__vftbl_i` naming). g++ NULL-slot handling must stop only on a non-null non-exec qword so it does not walk past the true end of a vtable.

### ORACLE
Source `_qa/classtest/puretest.cpp` (already written): `struct Shape { virtual double area() const = 0; virtual int sides() const = 0; virtual const char* name() const; virtual ~Shape(); int tag; };` with `Shape::name`/`~Shape` defined OUT-OF-LINE (forces the abstract vtable to be emitted with `_purecall` in the pure slots), plus `struct Circle : Shape` overriding both, and exported `make_circle`/`use_area`/`use_name`. Compile MSVC: `cl /LD /GR /O2 /GS- /Fe:puretest.dll puretest.cpp` (via `_qa/classtest/build_pure_msvc.bat` which calls vcvars64). g++ twin: `g++ -shared -O2 -o puretest_gcc.dll puretest.cpp`. ASSERT after fix, in the decompiled pairs: (1) fn @ 0x1f60 header is `_purecall` (NOT `Shape__vftbl_0`); (2) a `Shape__vftbl_0_pure` and `Shape__vftbl_1_pure` marker exists for the two pure slots; (3) `grep -c 'Shape__vftbl_0(' ` no longer shows the trap presented as a Shape method. BEFORE (current, for regression contrast): fn @ 0x1f60 = `Shape__vftbl_0`, no `Shape__vftbl_1`, no `_purecall`/`_pure` anywhere. Detector cross-check: the Python sim in scratchpad/sim_purecall.py prints `PURECALL candidates: [0x1f60]` for the oracle and `[]` for NullWare.

### GATE_RISK
Very low. The detector returns {} on NullWare.dll (proven by the sim over its 8 recognized vtables — all std::exception-family/type_info, each method at a single slot index), so scan_rtti renames NOTHING there and the fast_gate dump is byte-identical -> 1497/1497 compile-clean, GOTO_TOTAL and INVENTED_FLAGS/STATE_MACHINES unchanged. The corpus (629/1) is behavioral C with essentially no MSVC RTTI vtables, and a symbol-name/comment change cannot alter runtime behavior, so 629/1 holds. Keep both green by: (a) gating everything behind DS_NO_PUREVIRT; (b) keeping the >=2-distinct-index rule (never flags same-index inherited methods); (c) not touching any code-emission path — only ds_engine_add_symbol names + optional comments. Verify with a full `python _qa/harness.py 2>&1 | tee _qa/round_harness.log | grep -E 'SUMMARY|FAIL'` and a fast_gate run, plus the puretest oracle as the feature's own proof.

### FIRES
ORACLE (MSVC, primary): `_qa/classtest/puretest.cpp` -> `cmd //c _qa/classtest/build_pure_msvc.bat` (`cl /LD /GR /O2 /GS- puretest.cpp`) -> puretest.dll. Decompile: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN=".../puretest.dll" DS_PAIRS_DIR=/tmp/pm "$EXE"`.
Raw Shape vtable @ RVA 0xf2e8 = slots [0x1f60, 0x1f60, 0x1080, 0x1030] (objdump -s: `601f0080 01000000 601f0080 01000000 80100080...`). Slots 0(area) and 1(sides) BOTH point at 0x1f60.
Current opaque output: `grep -l Shape__vftbl_0 /tmp/pm/fn_*.txt` -> fn_00001f60.txt, whose body IS `_purecall` (reads the purecall-handler global qword_19bf0, calls it or aborts via fun_00005734=abort, tail padded int3) but is HEADER-NAMED `Shape__vftbl_0`. `grep -rho 'Shape__vftbl_[0-9]' /tmp/pm | sort -u` -> {0,2,3}; **Shape__vftbl_1 is ABSENT** (slot 1 shares 0x1f60, swallowed by already_seeded first-writer-wins).
DETECTOR PROOF (Python sim of the ">=2 distinct slot-indices" rule using rtti.cpp's exact COL-recognition predicate, run on both binaries): oracle -> **{0x1f60 occupies indices [0,1]}** (fires; correctly does NOT flag inherited `name` 0x1080 which sits at Shape[2]+Circle[2] = same index 2); NullWare.dll (the 1497-fn fast_gate binary) -> **{} zero candidates** across its 8 recognized vtables (std::exception family + type_info, each method at a single index). g++ oracle (puretest_gcc.dll, `g++ -shared -O2`) confirms the g++ variant: abstract Shape's vtable emits NULL pure slots (mingw leaves __cxa_pure_virtual an unresolved weak), which the current Itanium scan rejects entirely at rtti.cpp:306.

