### FEATURE
Recognize typeid: resolve a type_info object's address to its class and render RTTI type_info operands as `&<Class>__type_info` (a C-compile-clean `typeid(<Class>)` stand-in) instead of a bare rodata address. Core = static typeid operand resolution (MSVC TypeDescriptor+8 / g++ &_ZTI). Optional secondary = name the MSVC `__RTtypeid` dynamic-typeid helper so `typeid(*obj)` can form.

### TRACTABILITY
easy

### CURRENT_HANDLING
NONE for the type_info object. engine/analysis/rtti.cpp reads the TypeDescriptor (`ptd` = col+0x0C, MSVC) and the _ZTI (`ti_rva` = ns-8, g++) but never seeds a symbol for the type_info object itself — it only seeds `<Class>__vftable`/`__vfstruct` (rtti.cpp:370-373, :313-316) and `<Class>__vftbl_N`. So no address->type_info mapping exists. At render time, engine/analysis/decomp/16_globals_phis.inc render_const (:1915) has no type_info branch: a width-8 unsigned data-address const with no addr_hint falls straight through null_hint(:1922)/addr_hint(:1929)/char/dec/hex to the terminal `return hex((uint64_t)(uint32_t)v);` at :1980 — emitting the bare `0x39a88`.

### GAP
The RTTI scanner already computes every class's type_info address but discards it, so a typeid operand (the operator== / .name() argument, MSVC &TypeDescriptor._Data == TD+8; g++ &_ZTI) decompiles to an opaque rodata hex constant with no indication it is `typeid(<Class>)`. Need: (1) seed the type_info address -> class in e->symbols, and (2) a render_const branch that resolves such a const to `&<Class>__type_info`.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "ds_engine_scan_rtti, MSVC COL loop, immediately after `std::string cls = c_safe(cls_raw);` (line 364), before the `if (offc == 0 ...)` vtable-naming block. `ptd` (TypeDescriptor RVA, from col+0x0C, already validated mapped & non-exec at :354) is in scope.",
  "change": "Seed `<Class>__type_info` at ptd+8 (the &_Data / __std_type_info_data* address the compiler actually references for typeid). Guard with `!std::getenv(\"DS_NO_TYPEID\")` and `already_seeded(e, ptd+8)`. Fires per-class (independent of offc), which is correct since the TypeDescriptor is per-class."
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "scan_rtti_itanium, immediately after `if (!read_u64(e, ti_rva, tivt) || tivt == 0) continue;` (line 294). `ti_rva` (=_ZTI RVA) and `cls` (=c_safe(cls_raw), computed :284) in scope.",
  "change": "Seed `<Class>__type_info` at ti_rva (the &_ZTI address a g++ static typeid references). Same DS_NO_TYPEID + already_seeded guards."
 },
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "immediately after class_for_vtable's closing brace (line 26), alongside the other RTTI symbol resolvers.",
  "change": "Add `std::string type_info_class_for_addr(uint64_t addr)` mirroring class_for_vtable: scan e->symbols for a name ending `__type_info` at rva `addr` (try `addr` and its RVA form `addr-e->base`), return the class identifier (suffix stripped). Returns \"\" under DS_NO_TYPEID. EXACT match only (no +-8 tolerance) so it never false-matches a non-type_info const."
 },
 {
  "file": "engine/analysis/decomp/16_globals_phis.inc",
  "anchor": "render_const, right after `if (e->null_hint) { used_null = true; return \"NULL\"; }` (line 1922), before the addr_hint branch (:1929).",
  "change": "If `!e->is_float && (uint64_t)v > 0x1000` and `type_info_class_for_addr(v)` is non-empty, register a named_global `#define <cls>__type_info (*(int8_t*)0xADDR)` and `return \"&\" + cls + \"__type_info\";`. The `&`/`*` cancel to exactly the address, so it is behavior-preserving AND C-compile-clean /TC."
 }
]

### CODE_SKETCH
// ---- engine/analysis/rtti.cpp, MSVC COL loop (after `std::string cls = c_safe(cls_raw);`) ----
/* TYPEID: seed the type_info object so a `typeid(T)` operand (a reference to
 * &TypeDescriptor._Data == ptd+8) resolves to the class instead of a raw address. */
if (!std::getenv("DS_NO_TYPEID") && !already_seeded(e, ptd + 8)) {
    char ti[176]; std::snprintf(ti, sizeof ti, "%s__type_info", cls.c_str());
    ds_engine_add_symbol(e, ptd + 8, ti);
}

// ---- engine/analysis/rtti.cpp, scan_rtti_itanium (after the tivt read `continue;`) ----
if (!std::getenv("DS_NO_TYPEID") && !already_seeded(e, ti_rva)) {
    char ti[176]; std::snprintf(ti, sizeof ti, "%s__type_info", cls.c_str());
    ds_engine_add_symbol(e, ti_rva, ti);          /* &_ZTI (Itanium type_info) */
}

// ---- engine/analysis/decomp/02_rtti_vtable.inc (after class_for_vtable) ----
/* typeid(T)/&T::typeinfo recovery: the RTTI scanner seeds `<Class>__type_info`
 * at the type_info object (MSVC TypeDescriptor+8; g++ &_ZTI). Map that address
 * (RVA or VA) back to the class identifier; "" if it is not a type_info object. */
std::string type_info_class_for_addr(uint64_t addr) {
    if (!e || std::getenv("DS_NO_TYPEID")) return "";
    static const std::string suf = "__type_info";
    for (uint64_t r : { addr, (addr >= e->base ? addr - e->base : addr) })
        for (size_t i = 0; i < e->symbol_len; ++i) {
            if (e->symbols[i].rva != r || !e->symbols[i].name[0]) continue;
            std::string n = e->symbols[i].name;
            if (n.size() > suf.size() &&
                n.compare(n.size()-suf.size(), suf.size(), suf) == 0)
                return n.substr(0, n.size()-suf.size());   /* already a C identifier (c_safe) */
        }
    return "";
}

// ---- engine/analysis/decomp/16_globals_phis.inc, render_const (after the null_hint return) ----
/* A constant that is a recovered RTTI type_info object address renders as the
 * class's typeinfo: `&<Class>__type_info`. A named-global #define keeps the exact
 * address (`&`/`*` cancel), so it is behavior-neutral AND C-compile-clean /TC.
 * Reveals `typeid(T)` operands (operator== / .name() args). Gated DS_NO_TYPEID. */
if (!e->is_float && (uint64_t)v > 0x1000) {
    std::string cls = type_info_class_for_addr((uint64_t)v);
    if (!cls.empty()) {
        std::string nm = cls + "__type_info";
        char def[96];
        std::snprintf(def, sizeof def, "(*(int8_t*)0x%llx)", (unsigned long long)v);
        named_globals[nm] = def;
        return "&" + nm;              /* == typeid(<cls>) ; e.g. &Animal__type_info */
    }
}
// After: animal_is_dog_static -> fun_00001ef0(&Animal__type_info, &Dog__type_info) == 0
//        animal_type_name     -> fun_00001f60(&Animal__type_info, 0x39c60)
//        NullWare fn_000638cc -> fun_000607b8(v3 + 8, &std__bad_exception__type_info)

### SOUNDNESS
Correctness risks are minimal and contained. (1) The resolver returns non-empty ONLY for addresses the RTTI scanner positively identified as a TypeDescriptor (sig==1 COL, pSelf self-ref) or _ZTI (string<-ti<-vtable triple back-link) — the exact validation gating today's vtable naming. No other code has a reason to reference a TD+8/_ZTI address, so there are zero false positives; EXACT-match resolution (no +-8 fuzz) rules out matching a neighbouring const. (2) The render is behavior-preserving: `&<Class>__type_info` expands via the named_global #define to `&(*(int8_t*)0xADDR)` == `(int8_t*)0xADDR` == the original pointer value — identical to the existing `byte_X` addr_hint path (16_globals_phis.inc:1929-1934) already trusted in the gate. (3) It is C-compile-clean /TC (a real identifier + a numeric-address #define), unlike `typeid(T)`/`&T::typeinfo` which are C++-only — this is what makes it safe even when it fires inside NullWare's CRT exception matcher. Gate env: DS_NO_TYPEID disables BOTH the seeding (rtti.cpp) and the resolver/render (returns "" -> raw hex), giving a clean A/B kill-switch. Known scope limits (not unsound, just gaps): MSVC seeds only the polymorphic (COL-backed) classes' TDs, so `typeid` of a non-polymorphic type is not covered; g++ static compares hide the resolved operand because the `_ZNKSt9type_infoeqERKS_` thunk drops args (a separate proto-arity fix).

### ORACLE
Oracle already built and committed at _qa/classtest/typeidtest.cpp (+ typeidtest.dll MSVC, typeidtest_gcc.dll g++). Source: Animal/Dog polymorphic structs with four exports exercising static typeid, dynamic typeid, and typeid comparison.
Compile (MSVC, RTTI on): `cl /LD /GR /O2 /GS- typeidtest.cpp`  (g++: `g++ -shared -O2 -o typeidtest_gcc.dll typeidtest.cpp`).
Decompile: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN="$PWD/_qa/classtest/typeidtest.dll" DS_PAIRS_DIR=/tmp/tid "$EXE" >/dev/null 2>&1`.
Assert (post-fix) in /tmp/tid/fn_00001000.txt (animal_is_dog_static): body contains `&Animal__type_info` AND `&Dog__type_info`, and contains NO bare `0x39a88`/`0x39aa8`. In fn_00001030.txt (animal_type_name): `&Animal__type_info`. A/B: re-run with `DS_NO_TYPEID=1` and assert the bare `0x39a88`/`0x39aa8` return (proves the gate + isolates the change). Firing count today (must go to 0 post-fix): `grep -rhoE '0x39a88|0x39aa8' /tmp/tid/fn_*.txt | wc -l` == 8.

### GATE_RISK
Low and characterized. fast_gate (NullWare 1497/1497 cl /TC /w): exactly ONE function changes — fn_000638cc's `fun_000607b8(v3 + 8, 0x173f20)` becomes `fun_000607b8(v3 + 8, &std__bad_exception__type_info)` (0x173f20 = std::bad_exception TypeDescriptor 0x173f18 +8, confirmed by PE parse + a pairs grep that found this as the sole NullWare ref of the 8 std TDs). It stays compile-clean because the render is a C identifier + a numeric #define (the whole reason to render `&<Class>__type_info` rather than C++ `typeid(...)`). No CFG/statement change, so GOTO_TOTAL (568), INVENTED_FLAGS (0), STATE_MACHINES (0) are all untouched. corpus (629/1): those DLLs are C with no typeid/RTTI TDs, so nothing seeds and nothing renders differently -> 629/1 unchanged. The RTTI oracles (classtest/showcase/etc.) gain unused `<Class>__type_info` symbols but reference no type_info in code, so their output is unchanged; they are gate-neutral anyway. To keep both green: verify fast_gate SUMMARY still 1497/1497 after landing, and spot-check that fn_000638cc still compiles. DS_NO_TYPEID is the revert lever if any surprise appears.

### FIRES
PROVEN opaque on a purpose-built oracle. Wrote `_qa/classtest/typeidtest.cpp` (Animal/Dog polymorphic; animal_type_name=typeid(Animal).name(), obj_type_name=typeid(*a).name(), is_a_dog=typeid(*a)==typeid(Dog), animal_is_dog_static=typeid(Animal)==typeid(Dog)).
Build: MSVC `cl /LD /GR /O2 /GS- typeidtest.cpp` -> typeidtest.dll (240640 B); g++ `g++ -shared -O2 -o typeidtest_gcc.dll typeidtest.cpp` -> 42061 B. Both exit 0.
Decompile: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN="$PWD/_qa/classtest/typeidtest.dll" DS_PAIRS_DIR=/tmp/tid_msvc "$EXE"`.
MSVC opaque output (current engine):
 - animal_is_dog_static: `return fun_00001ef0(0x39a88, 0x39aa8) == 0;`
 - animal_type_name:     `return (int64_t)fun_00001f60(0x39a88, 0x39c60);`
 - is_a_dog:             `return fun_00001ef0(fun_00001e30() + 8, 0x39aa8) == 0;`
 - obj_type_name:        `fun_00001f60(fun_00001e30() + 8, 0x39c60);`
Bare type_info addresses counted: 8 occurrences of 0x39a88/0x39aa8 across the dump; 4 in DECOMPILED bodies (fn_1000 x2, fn_1030, fn_1050). PE-parse (pe_rtti.py) confirms 0x39a88 = TypeDescriptor(.?AUAnimal@@) base 0x39a80 +8, 0x39aa8 = Dog TD 0x39aa0 +8; helpers fun_1e30=__RTtypeid (contains "Attempted a typeid of nullptr pointer!"), fun_1ef0=type_info::operator== (name compare), fun_1f60=type_info::name() (calls __unDName). 0x39c60=__type_info_root_node (correctly stays raw).
g++: operator==/__cxa_bad_typeid already demangled/named; static `_ZTI` consts 0x4300(Animal)/0x42e0(Dog) proven via pe_itanium.py but hidden because the `j__ZNKSt9type_infoeqERKS_` thunk has arity 0 (args dropped) — so g++ firing is secondary; MSVC is the primary decompiler-visible firing.
Also fires (and must stay clean) in NullWare: fn_000638cc passes `0x173f20` (= std::bad_exception TD 0x173f18 +8) to `fun_000607b8(v3 + 8, 0x173f20)` — a CRT type_info compare — the only NullWare ref of any of the 8 std TDs.

