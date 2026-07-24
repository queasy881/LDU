### FEATURE
Type a recovered virtual method's `this` (a1) as its RTTI class, so field accesses render through the recovered class layout (`class game__Entity* a1` + `a1->field_8`) instead of a raw pointer with `a1[2]`.

### TRACTABILITY
easy

### CURRENT_HANDLING
engine/analysis/decomp/09_structs.inc:454-470 — `struct_class[base]` (base var -> class tag) is populated ONLY by the constructor scan (`scan_vt`: a `*obj = &<Class>__vftable` store). A vmethod's a1 only READS fields, never stores the vtable, so it never enters struct_class; it falls through decl_type (05_types.inc:58+, the plain pointer path) to `int32_t*`/`int64_t*`. Additionally the layout-build gate 09_structs.inc:535 `if (L.fw.size() >= 2)` blocks take_damage's a1 (it touches only health at +8 = 1 field) from becoming a struct at all. Emits the opaque `int32_t*a1`/`a1[2]` shown above. NONE of the vmethod-this typing is done anywhere (grep for `__vftbl_` outside rtti.cpp finds only resolve_virtual_call, 02_rtti_vtable.inc:88-95, which already assumes a1-of-a-vftbl-fn IS its class — the precedent this reuses).

### GAP
The RTTI scanner knows a1 is the class (it named the function `<Class>__vftbl_N`), but the receiver is never typed, so field accesses stay raw `a1[k]`/`*(int*)(a1+off)` instead of arrow access through the recovered class layout, and the signature hides that a1 is a class pointer.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "immediately after vtable_rva_for_tag() (ends ~line 64, before the resolve_virtual_call comment)",
  "change": "Add a helper class_qual_for_tag(tag, qual_raw, is_struct_kw): the inverse of class_for_vtable \u2014 scan e->symbols for a name ending in `__vftable`/`__vfstruct` whose sani(prefix)==tag; on match return prefix as the RAW qualified name and set is_struct_kw from the suffix. Mirrors vtable_rva_for_tag exactly."
 },
 {
  "file": "engine/analysis/decomp/09_structs.inc",
  "anchor": "between line 470 (closing `}` of the scan_vt constructor-detection block) and line 471 (the `/* Vec2/Vec3/Vec4 ... */` comment / is_vec_layout lambda)",
  "change": "When self_fname matches `<Class>__vftbl_N` (primary vtable, reject an `_off<digits>` MI-subobject suffix) and class_qual_for_tag(tag,...) succeeds and struct_class has no `a1` yet: set struct_class[\"a1\"]=tag, struct_class_qual[\"a1\"]=qual, struct_class_kw[\"a1\"]=is_struct, and seed the vtable field `if(!fw[\"a1\"].count(0)){fw[\"a1\"][0]=8;fu[\"a1\"][0]=false;ff[\"a1\"][0]=false;}` so the class layout has field_0 and a1 clears the >=2-field gate at line 535. Gated DS_NO_VMTHIS."
 }
]

### CODE_SKETCH
// --- 02_rtti_vtable.inc, after vtable_rva_for_tag() ---
/* RAW qualified name + kw for a class TAG (sani'd) — inverse of class_for_vtable,
 * from the `<raw>__vftable`/`__vfstruct` symbol rtti.cpp seeded. */
bool class_qual_for_tag(const std::string& tag, std::string& qual_raw, bool& is_struct_kw) {
    if (!e || tag.empty()) return false;
    static const struct { const char* suf; bool st; } S[] = {{"__vftable",false},{"__vfstruct",true}};
    for (size_t i = 0; i < e->symbol_len; ++i) {
        const char* nm = e->symbols[i].name;
        if (!nm || !nm[0]) continue;
        std::string n = nm;
        for (auto& s : S) {
            size_t sl = std::strlen(s.suf);
            if (n.size() > sl && n.compare(n.size()-sl, sl, s.suf) == 0) {
                std::string raw = n.substr(0, n.size()-sl);
                if (sani(raw) == tag) { qual_raw = raw; is_struct_kw = s.st; return true; }
            }
        }
    }
    return false;
}

// --- 09_structs.inc, inserted after line 470 (the scan_vt block) ---
/* VIRTUAL-METHOD `this` TYPING (DS_NO_VMTHIS): a recovered vmethod `<Class>__vftbl_N`
 * has a1 == this == <Class> (the exact assumption resolve_virtual_call already trusts).
 * The RTTI scanner named the fn but never typed the receiver, so a1 renders int*/int64_t*
 * with a1[k]. Tag a1 as the class so accesses arrow through the recovered layout. */
if (!std::getenv("DS_NO_VMTHIS") && !struct_class.count("a1")) {
    size_t vp = self_fname.find("__vftbl_");
    if (vp != std::string::npos && vp > 0) {
        std::string ctag = self_fname.substr(0, vp);
        bool mi = false;                      /* reject `<Class>_off<digits>` MI subobject */
        size_t op = ctag.rfind("_off");
        if (op != std::string::npos && op + 4 < ctag.size()) {
            mi = true;
            for (size_t k = op + 4; k < ctag.size(); ++k)
                if (!isdigit((unsigned char)ctag[k])) { mi = false; break; }
        }
        std::string qual; bool isst = false;
        if (!mi && class_qual_for_tag(ctag, qual, isst)) {
            struct_class["a1"] = ctag;
            struct_class_qual["a1"] = qual;
            struct_class_kw["a1"] = isst;
            if (!fw["a1"].count(0)) { fw["a1"][0] = 8; fu["a1"][0] = false; ff["a1"][0] = false; }
        }
    }
}
// -> build loop @535 now sees fw["a1"]={0:8, 8:4} (take_damage), mktag@487 finds
//    struct_class["a1"] -> is_class, tag "game__Entity", qual "game::Entity".
//    decl_type (05_types.inc:23-26) renders `class game__Entity* a1`; struct_typedef_str
//    renders field_0 as `void* __vftable`; a1[2] -> a1->field_8. Matches make_entity.

### SOUNDNESS
Sound: a virtual method's receiver IS its own class by definition — the identical assumption resolve_virtual_call (02_rtti_vtable.inc:87-95) already ships and calls "sound". The change is render-only: `a1->field_8` addresses the same bytes as `a1[2]`/`*(int*)(a1+8)` under #pragma pack(1) with the 8-byte vtable at offset 0, so behavior is unchanged. Risks + guards: (1) MI subobject methods — MSVC names them `<Class>_off<u>__vftbl_N`; the `_off<digits>` reject skips them (their this is a sub-object ptr, not the class base). (2) g++/Itanium MI secondary-vtable methods are named `<Class>__vftbl_N` with NO _off suffix, so a g++ multiple-inheritance secondary method could be mis-labeled the full class — cosmetic only (offsets used are the method's own accesses, output still compiles); single-inheritance (the oracle + dominant case) is exact. (3) never fires without a matching seeded `__vftable`/`__vfstruct` symbol (class_qual_for_tag gate) — so only genuine RTTI classes qualify. (4) an array-indexed a1 is already excluded by struct_excluded_params before the build loop, so a1[i] is never wrongly structified. (5) offset-0 access at width!=8 is left untouched (`if(!fw["a1"].count(0))`). Gate: DS_NO_VMTHIS reverts instantly.

### ORACLE
Oracle already exists: _qa/classtest/showcase.cpp -> showcase.dll (MSVC) + showcase_gcc.dll (g++), both built with RTTI. Rebuild if needed: `cl /LD /GR /O2 /GS- showcase.cpp` / `g++ -shared -O2 -o showcase_gcc.dll showcase.cpp`. The relevant class: `namespace game { class Entity { int health; /*+8*/ int level; Entity* target; virtual int take_damage(int d){health-=d;return health;} ... }; }`. Decompile: `DS_REAL_BIN=$PWD/_qa/classtest/showcase.dll DS_PAIRS_DIR=<out> "$EXE"`; the fn whose header is `game__Entity__vftbl_0` (currently fn_00001110.txt). ASSERT (before, current): signature contains `int32_t*a1` and body contains `a1[2] -= a2` / `return a1[2]`. ASSERT (after fix): signature contains `class game__Entity*a1`, a `class game__Entity { void* __vftable; ... int32_t field_8; }` definition is emitted, and the body reads `a1->field_8 -= a2; return a1->field_8;` — matching the constructor-recovered class already emitted by make_entity (fn_00001160). Also assert `DS_NO_VMTHIS=1` restores the `int32_t*a1`/`a1[2]` form (gate A/B).

### GATE_RISK
Low blast radius. fast_gate (NullWare 1497/1497 cl /TC): only 3 vmethods exist. std__exception__vftbl_1 (`return a1[1]!=0?a1[1]:"Unknown exception"`) gains field_0 -> 2 fields -> becomes `class std__exception*` with `a1->field_8` (same int64_t-vs-char* ternary that already compiles clean today, so still /TC-clean). std__exception__vftbl_0 and type_info__vftbl_0 access ONLY offset 0 (`*a1=<vtable>`) -> stay 1 field -> blocked by the >=2 gate -> byte-identical output, no risk. GOTO/INVENTED_FLAGS/STATE_MACHINES untouched (no control-flow change). corpus 629/1: render-only (a1->field == a1[k] same address), semantics unchanged, so behavioral difftests are unaffected. The class-struct machinery reused is the exact one make_entity already compiles 1497/1497-clean. Keep green by running fast_gate + harness.py after landing; DS_NO_VMTHIS is the instant revert.

### FIRES
PROVEN on the existing MSVC oracle showcase.dll (built `cl /LD /GR /O2`). Decompile: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN="$PWD/_qa/classtest/showcase.dll" DS_PAIRS_DIR=<out> "$EXE"`. The named oracle Entity::take_damage lands in fn_00001110.txt as:
`int32_t game__Entity__vftbl_0(int32_t*a1, int32_t a2) { a1[2] -= a2; return a1[2]; }`
— `this` is `int32_t*`, health(+8) renders `a1[2]`, even though the RTTI scanner named the fn `game__Entity__vftbl_0`.
Count of the gap: ALL 12 recovered vmethods in showcase are untyped — `grep -rhE "__vftbl_[0-9]+\(.*\{$" <out>/fn_*.txt` shows every one is either `int32_t*a1`/`int64_t*a1` (opaque, e.g. take_damage, level_up, dtors) or a per-fn generic `struct s_game__Pool_int___vftbl_0_a1*` (Pool::alloc fn_000010c0, Body::momentum) — NONE is `class/struct <Class>*`. The g++/Itanium build showcase_gcc.dll names the same `game__Entity__vftbl_0` etc., so the fix fires on both compilers. On NullWare (full cap: `DS_PAIRS_CAP=1500 ... "$EXE" --nocapture`, 1497 fns) exactly 3 vmethods exist (std__exception__vftbl_0/1, type_info__vftbl_0), all untyped today.
That the fixed layout is recoverable is proven on the SAME dll: the Entity constructor make_entity (fn_00001160) already emits `class game::Entity { void* __vftable; int64_t field_8; ... }` with `p->field_8` arrows and `extern void* game__Entity__vftable;` — proving the `game::Entity__vftable` symbol is seeded and `sani("game::Entity")=="game__Entity"` matches the vmethod tag; and Pool::alloc proves a1-in-param_structs renders `a1->field_8` arrows.

