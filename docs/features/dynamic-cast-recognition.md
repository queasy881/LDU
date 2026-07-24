### FEATURE
Recognize dynamic_cast: rewrite the opaque MSVC __RTDynamicCast / g++ __dynamic_cast runtime call into `dynamic_cast<Dst*>(p)` by resolving the destination TypeDescriptor / type_info argument to its recovered class name.

### TRACTABILITY
medium

### CURRENT_HANDLING
NONE. `grep -rniE "RTDynamicCast|dynamic_cast|__dynamic_cast"` over engine/ = 0 matches. The call falls through the generic `case EK::Call:` at engine/analysis/decomp/16_globals_phis.inc:2560, rendering the opaque `fun_00002560(a1, 0, 0x19a60, 0x19a80, 0)` (MSVC) / `j___dynamic_cast()` (g++). rtti.cpp seeds vtables/__extends__/vtbl slots but never seeds the TypeDescriptor (ptd, rtti.cpp:354) or the Itanium type_info (ti_rva, rtti.cpp:289) RVA, so the decompiler has no TD->class map.

### GAP
The two RTTI-cast runtime calls stay as raw opaque calls with numeric type_info pointers — the reader sees `fun_00002560(a1, 0, 0x19a60, 0x19a80, 0)` instead of `dynamic_cast<Derived*>(a1)`, losing the cast intent and the target class that IDA/Hex-Rays recover. The destination class IS recoverable: the dst arg is exactly the TypeDescriptor RVA (MSVC ptd) / type_info RVA (g++ _ZTI) that the rtti.cpp scanner already visits and demangles, but nothing bridges that RVA to a name at the call site.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "COL scan, right after `std::string cls = c_safe(cls_raw);` (line ~364), inside the `if (!read_u32... offc)` region where `ptd` (TypeDescriptor RVA, read at line 354) is in scope",
  "change": "Seed `<Class>__typedesc` at ptd so the decompiler can map a &TypeDescriptor arg back to the class. Guarded by DS_NO_DYNCAST + already_seeded(e,ptd) (ptd is shared by a class's primary+secondary COLs -> first-writer dedups). Unconditional on offc (not offc==0-gated) since the TD is the same object for every subobject vtable."
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "scan_rtti_itanium, inside the validated `vt_ti_slots` loop (line ~313, beside the `<Class>__vftable` naming) where `ti_rva` and `cls_raw` are in scope",
  "change": "Seed `<Class>__typeinfo` at ti_rva (the _ZTI object the g++ __dynamic_cast dst arg points to). Same DS_NO_DYNCAST + already_seeded guard."
 },
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "after vtable_rva_for_tag() (ends line 64), mirroring class_for_vtable's dual raw/RVA symbol scan",
  "change": "Add `std::string class_for_typedescriptor(uint64_t addr)`: scan e->symbols for a name at addr (or addr-e->base) ending in `__typedesc` or `__typeinfo`, return the RAW class-name prefix (keeps ::/<> like class_for_vtable), else \"\"."
 },
 {
  "file": "engine/analysis/decomp/16_globals_phis.inc",
  "anchor": "top of `case EK::Call: {` at line 2560, before the `std::string vm = ...` / head computation",
  "change": "Recognize the RTTI-cast shape and early-return `dynamic_cast<Class*>(render(args[0]))`. Gated DS_NO_DYNCAST; falls through to the existing opaque render when the class does not resolve."
 }
]

### CODE_SKETCH
// --- engine/analysis/rtti.cpp, MSVC COL scan, after `std::string cls = c_safe(cls_raw);` ---
if (!std::getenv("DS_NO_DYNCAST") && !already_seeded(e, ptd)) {
    char td[192];
    std::snprintf(td, sizeof td, "%s__typedesc", cls_raw.c_str());   // raw name keeps ns/tpl
    ds_engine_add_symbol(e, ptd, td);                                 // ptd = the &TypeDescriptor arg
}

// --- engine/analysis/rtti.cpp, scan_rtti_itanium, inside the validated vt_ti_slots loop ---
if (!std::getenv("DS_NO_DYNCAST") && !already_seeded(e, ti_rva)) {
    char ti[192];
    std::snprintf(ti, sizeof ti, "%s__typeinfo", cls_raw.c_str());
    ds_engine_add_symbol(e, ti_rva, ti);                             // ti_rva = _ZTI (g++ dst arg)
}

// --- engine/analysis/decomp/02_rtti_vtable.inc, after vtable_rva_for_tag() ---
std::string class_for_typedescriptor(uint64_t addr) {
    if (!e) return "";
    static const std::string s1 = "__typedesc", s2 = "__typeinfo";
    for (uint64_t r : { addr, (addr >= e->base ? addr - e->base : addr) }) {
        for (size_t i = 0; i < e->symbol_len; ++i) {
            if (e->symbols[i].rva != r || !e->symbols[i].name[0]) continue;
            std::string n = e->symbols[i].name;
            for (const std::string& suf : { s1, s2 })
                if (n.size() > suf.size() &&
                    n.compare(n.size() - suf.size(), suf.size(), suf) == 0)
                    return n.substr(0, n.size() - suf.size());   // RAW class name, e.g. "game::Entity"
        }
    }
    return "";
}

// --- engine/analysis/decomp/16_globals_phis.inc, top of `case EK::Call:` (line 2560) ---
if (!e->indirect && !std::getenv("DS_NO_DYNCAST")) {
    // MSVC __RTDynamicCast(p, VfDelta, &srcTD, &dstTD, isRef) : dst=arg[3], 5 args
    // g++   __dynamic_cast(p, &srcTI, &dstTI, hint)           : dst=arg[2], 4 args
    int di = e->args.size() == 5 ? 3 : e->args.size() == 4 ? 2 : -1;
    auto cst = [&](const ExprP& x, uint64_t& v) {
        if (!x || x->kind != EK::Const) return false; v = (uint64_t)x->cval; return true; };
    uint64_t drva = 0, srva = 0;
    if (di >= 0 && cst(e->args[di], drva) && cst(e->args[di - 1], srva)) {   // require BOTH TD ptrs
        std::string cls = class_for_typedescriptor(drva);
        if (!cls.empty())                                    // dst resolves to a recovered class
            return "dynamic_cast<" + cls + "*>(" + render(e->args[0]) + ")";
    }
}
// ... existing vm/head/args rendering unchanged ...

### SOUNDNESS
Correctness risks + mitigations: (1) False positive on an unrelated 5/4-arg call. Mitigated by requiring BOTH the dst arg AND its preceding (src) arg to be constants and the dst to resolve to a `__typedesc`/`__typeinfo` symbol — those symbols exist only for real polymorphic classes with a full COL/_ZTI, and passing two adjacent TypeDescriptor pointers is unique to __RTDynamicCast/__dynamic_cast; coincidence is effectively impossible. (2) Dropping VfDelta/isRef (MSVC) and hint (g++) args: these are ABI plumbing; even for a cast to a non-primary base (VfDelta!=0) the runtime folds the this-adjustment, so `dynamic_cast<Dst*>(p)` remains exactly the source-level semantics — sound. (3) If the dst class was not scanned (class_for_typedescriptor=="") the code falls through to the unchanged opaque render — no regression, pure improvement-or-nothing. (4) The seeds reuse rtti.cpp's existing, already-validated MSVC demangle()/itanium_demangle(), so namespace/template names match the rest of the class-recovery output. Single env gate DS_NO_DYNCAST disables BOTH the seed and the render for a clean bisect/revert.

### ORACLE
Oracle already written and compiled: _qa/classtest/dyncast.cpp
```
#include <cstdint>
struct Base    { int tag;   virtual int who(){return tag;}          virtual ~Base(){} };
struct Derived : Base { int extra; virtual int who(){return tag+extra;} int only_derived(){return extra*2;} };
extern "C" __declspec(dllexport) int try_cast(Base* p){
    Derived* d = dynamic_cast<Derived*>(p);
    if (d) return d->only_derived();
    return -1;
}
extern "C" __declspec(dllexport) Base*    make_base()   { return new Base(); }
extern "C" __declspec(dllexport) Derived* make_derived(){ return new Derived(); }
```
Compile: MSVC `cl /LD /GR /O2 /GS- dyncast.cpp` (vcvars64 from VS18 Community); g++ `g++ -shared -O2 -o dyncast_gcc.dll dyncast.cpp`.
Decompile: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN=$PWD/_qa/classtest/dyncast.dll DS_PAIRS_DIR=/tmp/dc_ms "$EXE" >/dev/null 2>&1`.
ASSERT (MSVC, /tmp/dc_ms/fn_000010f0.txt, try_cast): before = line contains `fun_00002560(a1, 0, 0x19a60, 0x19a80, 0)`; after = line contains `dynamic_cast<Derived*>(a1)` and no longer contains `fun_00002560(a1, 0, 0x19a60`. A/B via `DS_NO_DYNCAST=1` must reproduce the opaque form byte-for-byte.
ASSERT (rtti seed): dump e->symbols (or grep the seeded-symbol debug) for `Derived__typedesc` at RVA 0x19a80 and `Base__typedesc` at 0x19a60.
g++ (secondary, /tmp/dc_gcc/fn_00001310.txt): today `j___dynamic_cast()` (args dropped upstream); fires once the IAT-thunk call recovers its 4 args, then asserts `dynamic_cast<Derived*>(a1)` with 0x42f0->_ZTI7Derived.

### GATE_RISK
fast_gate (NullWare 1497/1497): NEUTRAL — verified 0 __RTDynamicCast call sites in NullWare's 401 decompiled fns (`grep -rEc "\(.*, 0, 0x[0-9a-f]+, 0x[0-9a-f]+, 0\)" /tmp/nw` = 0); its 8 RTTI TDs are all std:: EH types (bad_alloc/exception/out_of_range/...), never dynamic_cast'd, so the render never fires. The new `<std::x>__typedesc` seeds land at those std:: TD RVAs but are inert: TypeDescriptor RVAs are DATA, never call/jmp/fnptr targets, so name_for_rva never returns them; and the &TD constants that DO appear in EH code render via the Const path (raw hex, confirmed `0x19a60`) which does not consult e->symbols. Output stays byte-identical. corpus 629/1: NEUTRAL — the 24 corpus DLLs are C (each has only ~3 std:: TDs, no user polymorphic COL class, no dynamic_cast), so no `__typedesc`/`__typeinfo` for a user class and no matching call -> never fires. To keep both green: after landing, re-run `_qa/fast_gate.sh` (assert 1497/1497 + GOTO unchanged) and `_qa/harness.py` (assert 629/1) once WITH and once with DS_NO_DYNCAST=1 and diff — they must be identical. DS_NO_DYNCAST is the instant revert if any diff appears.

### FIRES
Built two oracles from _qa/classtest/dyncast.cpp (polymorphic struct Base + struct Derived, `Derived* d = dynamic_cast<Derived*>(p)` in exported try_cast).
MSVC: `cl /LD /GR /O2 /GS- dyncast.cpp` (via VS18 vcvars64) -> dyncast.dll (108032 B, statically links the CRT: only KERNEL32 imported, dumpbin //IMPORTS shows no RTDynamicCast).
g++: `g++ -shared -O2 -o dyncast_gcc.dll dyncast.cpp` -> dyncast_gcc.dll.
Decompiled: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN=$PWD/_qa/classtest/dyncast.dll DS_PAIRS_DIR=/tmp/dc_ms "$EXE"` (and dyncast_gcc.dll -> /tmp/dc_gcc).
MSVC OPAQUE (1 site, /tmp/dc_ms/fn_000010f0.txt = try_cast): `v1 = (int32_t*)fun_00002560(a1, 0, 0x19a60, 0x19a80, 0);` with forward-decl `int32_t fun_00002560();`. fun_00002560 is the 352-byte CRT __RTDynamicCast. The dst arg 0x19a80 is a TypeDescriptor whose +0x10 name = `.?AUDerived@@` (Derived); src arg 0x19a60 +0x10 = `.?AUBase@@` (pefile-confirmed). Desired: `v1 = (int32_t*)dynamic_cast<Derived*>(a1);`.
g++ OPAQUE (1 site, /tmp/dc_gcc/fn_00001310.txt): `v1 = (int32_t*)j___dynamic_cast();` (thunk to imported __dynamic_cast; args dropped by pre-existing IAT-thunk arg recovery). type_info args: 0x42f0=_ZTI7Derived (dst), 0x42e0=_ZTI4Base (pefile-confirmed via _ZTI[+8]->_ZTS string).
MSVC is the fully-firing path (all 5 args recovered, dst resolvable). g++ is structurally identical but blocked upstream by the thunk arg-drop.

