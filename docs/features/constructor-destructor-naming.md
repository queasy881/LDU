### FEATURE
C++ constructor / destructor identification + naming: a function that stores a recovered vtable address to [this+0] is named `<Class>__ctor` (if it is not itself a vtable slot) or `<Class>__dtor` (if it IS a vtable slot — the scalar-deleting destructor), replacing the opaque `fun_XXXX` / `<Class>__vftbl_N` name at the definition and every call site.

### TRACTABILITY
medium

### CURRENT_HANDLING
NONE for constructor identity. The ctor gets the generic fallback name at engine/analysis/symbols.cpp:400-404 (`fun_%08llx`), which name_for_rva (01_naming_reads.inc:235-250) then echoes at the definition (via seeded_symbol at symbols.cpp:369) and at every call site. Its a1 IS already typed as the class by the existing struct_class recovery (09_structs.inc:432-470) when the ctor writes >=2 fields (confirmed: `class std__bad_alloc*a1`), so ONLY the function name is missing. For destructors: rtti.cpp:412-417 seeds `<Class>__vftbl_%d` — an opaque slot index, never "dtor". And a 1-field destructor (e.g. GameManager) never reaches struct_class's `L.fw.size() >= 2` gate (09_structs.inc:535), so a1 stays `int64_t*` and its vtable store renders as the magic constant `*a1 = 0xf2e8;` instead of `a1->__vftable = &GameManager__vftable`.

### GAP
The single most identity-bearing fact about these functions — "this is Class's constructor / destructor" — is dropped. A reader sees `fun_00001510(...)` and an out-of-line `GameManager__vftbl_2(this, flags)` instead of `std__bad_alloc__ctor(...)` / `GameManager__dtor(this, flags)`, even though the engine already recovered the class, the vtable, and (for ctors) the typed `this`. All the inputs to name them are present and unused.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/cfg.cpp",
  "anchor": "the final `return 0;` of `ds_engine_build_cfg` (~line 383), immediately after the e->funcs sort/dedupe block",
  "change": "call `ds_engine_scan_ctor_dtor(e);` here \u2014 e->funcs is final and sorted, e->insns is the full listing, scan_rtti's vtable symbols are seeded (line 162), and resolve_symbols has not yet run, so a seeded ctor symbol / an in-place dtor rename is consumed by seeded_symbol at both definition and call sites"
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "end of the anonymous namespace + after `scan_rtti_itanium` / the `ds_engine_scan_rtti` body (line 425-426)",
  "change": "add the new pass `extern \"C\" void ds_engine_scan_ctor_dtor(ds_engine* e)` plus file-local helpers (class_for_vtable_va, a vtbl-slot-symbol lookup, name_in_use). Reuse the existing `c_safe`, `already_seeded`, `ds_rva_is_exec`, and the public `ds_engine_add_symbol`. Gate on `DS_NO_CTORDTOR`."
 },
 {
  "file": "engine/include/disasm.h",
  "anchor": "right after the `void ds_engine_scan_rtti(ds_engine* e);` declaration (line 122) and its comment",
  "change": "declare `void ds_engine_scan_ctor_dtor(ds_engine* e);`"
 },
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "resolve_virtual_call branch (b), lines 87-95, which derives the receiver class from `self_fname.find(\"__vftbl_\")`",
  "change": "OPTIONAL (preserve devirt after a dtor slot is renamed): also recover the class when self_fname ends with `__dtor`/`__ctor` (strip the suffix) so a virtual call on `this` inside a renamed destructor still devirtualizes"
 },
 {
  "file": "engine/analysis/decomp/09_structs.inc",
  "anchor": "the struct_class / scan_vt / mktag area (lines 432-470) and the `L.fw.size() >= 2` gate at line 535",
  "change": "OPTIONAL (delivers the task's `type a1 as <Class>*` for the 1-field destructor case): when self_fname matches `<Class>__ctor`/`<Class>__dtor`, force param_structs[\"a1\"] to that class (is_class=true) even with a single field, so GameManager__dtor's `*a1 = 0xf2e8;` becomes `a1->__vftable = &GameManager__vftable;`"
 }
]

### CODE_SKETCH
/* --- in rtti.cpp anonymous namespace --- */
/* c_safe class tag for the vtable at VA `va`, from the <Class>__vftable/__vfstruct
 * symbol scan_rtti seeded; "" if `va` is not a recovered vtable. */
static std::string class_for_vtable_va(const ds_engine* e, uint64_t va) {
    for (uint64_t r : { va, (va >= e->base ? va - e->base : va) })
        for (size_t i = 0; i < e->symbol_len; ++i) {
            if (e->symbols[i].rva != r || !e->symbols[i].name[0]) continue;
            std::string n = e->symbols[i].name;
            for (const char* suf : { "__vftable", "__vfstruct" }) {
                size_t sl = std::strlen(suf);
                if (n.size() > sl && n.compare(n.size()-sl, sl, suf) == 0)
                    return c_safe(n.substr(0, n.size()-sl));   /* raw class -> identifier */
            }
        }
    return "";
}
/* index of the __vftbl_N slot symbol at func rva `r`, or SIZE_MAX (= not a vtable slot) */
static size_t vtbl_slot_sym(const ds_engine* e, uint64_t r) {
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].rva == r && e->symbols[i].name[0] &&
            std::strstr(e->symbols[i].name, "__vftbl_")) return i;
    return SIZE_MAX;
}
static bool name_in_use(const ds_engine* e, const char* nm) {
    for (size_t i = 0; i < e->symbol_len; ++i)
        if (e->symbols[i].name[0] && !std::strcmp(e->symbols[i].name, nm)) return true;
    return false;
}
/* tiny operand-string parsers over capstone Intel syntax (as in e->insns.operands):
 *   reg_dst("rbx, rcx")               -> "rbx"       reg_src(..) -> "rcx"  (reg,reg)
 *   store_base0("qword ptr [rbx], rax", base,src) -> base="rbx" src="rax", only when the
 *       mem operand is [reg] with NO '+'/disp (rejects "[rbx + 8]") */
} // namespace

extern "C" void ds_engine_scan_ctor_dtor(ds_engine* e) {
    if (std::getenv("DS_NO_CTORDTOR")) return;
    if (!e || e->arch != DS_ARCH_X64 || !e->image || !e->func_len || !e->insn_len) return;
    for (size_t fi = 0; fi < e->func_len; ++fi) {
        ds_func* f = &e->funcs[fi];
        size_t lo = 0, hi = e->insn_len;                         /* first insn of f */
        while (lo < hi) { size_t m=(lo+hi)/2; if (e->insns[m].rva < f->rva) lo=m+1; else hi=m; }
        uint64_t fend = f->rva + (f->size ? f->size : 0);
        std::set<std::string> thisreg = { "rcx" };               /* this + copies of it  */
        std::map<std::string,uint64_t> vtreg;                    /* reg -> vtable VA      */
        uint64_t stored_vt = 0;                                  /* last vtable -> [this] */
        for (size_t k = lo; k < e->insn_len && e->insns[k].rva < fend; ++k) {
            const ds_insn* in = &e->insns[k];
            std::string d, s, base;
            if (!std::strcmp(in->mnemonic,"lea") && in->ref_type==DS_REF_DATA && in->ref_target) {
                d = reg_dst(in->operands);                       /* a def: reg no longer 'this' */
                thisreg.erase(d);
                if (!d.empty() && !class_for_vtable_va(e, in->ref_target).empty()) vtreg[d]=in->ref_target;
                else vtreg.erase(d);
            } else if (!std::strcmp(in->mnemonic,"mov") && reg_reg(in->operands, d, s)) {
                if (thisreg.count(s)) thisreg.insert(d);          /* mov rbx,rcx : rbx aliases this */
                else { thisreg.erase(d); vtreg.erase(d); }
            } else if (!std::strcmp(in->mnemonic,"mov") && store_base0(in->operands, base, s)) {
                if (thisreg.count(base) && vtreg.count(s)) stored_vt = vtreg[s];  /* last wins */
            }
        }
        if (!stored_vt) continue;
        std::string cls = class_for_vtable_va(e, stored_vt);
        if (cls.empty()) continue;
        size_t slot = vtbl_slot_sym(e, f->rva);
        char nm[96];
        std::snprintf(nm, sizeof nm, "%s__%s", cls.c_str(), slot!=SIZE_MAX ? "dtor" : "ctor");
        if (name_in_use(e, nm))                                  /* 2 ctors/dtors of one class */
            std::snprintf(nm, sizeof nm, "%s__%s_%llx", cls.c_str(),
                          slot!=SIZE_MAX ? "dtor":"ctor", (unsigned long long)f->rva);
        if (slot != SIZE_MAX)                                    /* DTOR: win over __vftbl_N in place */
            std::snprintf(e->symbols[slot].name, sizeof(e->symbols[slot].name), "%s", nm);
        else if (!already_seeded(e, f->rva))                     /* CTOR: fun_ has no symbol -> add */
            ds_engine_add_symbol(e, f->rva, nm);
    }
}

### SOUNDNESS
Soundness rests on: among vtable-slot functions only a destructor rewrites [this+0] with the class's own vtable (draw/update/get_score never touch offset 0), and a non-slot function storing a recovered vtable to [this+0] is by definition constructing a Class there — the same rule the existing struct_class ctor-recovery already trusts (09_structs.inc:454-470). It is a naming hint, not a semantic transform, so a rare mislabel (a reset/placement-init helper) is low-harm and matches Hex-Rays. Risks + mitigations: (1) `this` may be clobbered mid-body (ct fn_00001510 does `lea rcx,[vtable]` after `mov rbx,rcx`) — the sketch erases any register from `thisreg` when it is redefined, and only offset-0 stores with NO displacement count, so the secondary `[rcx+0x10]` MI store is ignored and the primary `[this]` store selects the most-derived class (last-wins). (2) A store of a NON-vtable value to [this+0] never matches (src must be a reg holding a lea of an addr that carries a `__vftable`/`__vfstruct` symbol). (3) Multiple ctors/dtors of one class collide — uniquified with an `_<rva>` suffix and a global name_in_use check (verified needed: classtest has two std__bad_alloc ctors, two bad_array_new_length, two bad_exception). (4) Never shadow an export/PDB name — ctor path guards on `!already_seeded`. Gate: `DS_NO_CTORDTOR` disables the whole pass for A/B bisect.

### ORACLE
The existing oracles already fire; no new DLL required. Re-run and assert on the dumped pairs:
EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1)
DS_REAL_BIN=$PWD/_qa/classtest/mitest.dll   DS_PAIRS_DIR=/tmp/mi "$EXE" >/dev/null 2>&1
DS_REAL_BIN=$PWD/_qa/classtest/classtest.dll DS_PAIRS_DIR=/tmp/ct "$EXE" >/dev/null 2>&1
Assert (all currently FAIL — the opaque names — and must PASS after the change):
 - CTOR: `grep -l 'std__bad_alloc__ctor(' /tmp/mi/*.txt` non-empty (was `fun_00001510`/`fun_000015d0`); the def header line becomes `/* std__bad_alloc__ctor @ 0x1510 ... */` and its signature `... std__bad_alloc__ctor(class std__bad_alloc*a1, int64_t a2)`.
 - DTOR: `grep -l 'Drawable__dtor\|Sprite__dtor\|Updatable__dtor' /tmp/mi/*.txt` non-empty (was `Drawable__vftbl_1` etc.).
 - DTOR (classtest): fn_00001000 header becomes `/* GameManager__dtor @ 0x1000 ... */` (was `GameManager__vftbl_2`); with the optional 09_structs.inc typing, its body reads `a1->__vftable = &GameManager__vftable;` instead of `*a1 = 0xf2e8;`.
 - Call-site propagation: any devirtualized `delete`/dispatch that previously printed `GameManager__vftbl_2(` now prints `GameManager__dtor(`.
Optional purpose-built ctor oracle (forces a standalone USER-class ctor, defeating /O2 inlining via array-new): _qa/classtest/ctortest.cpp:
  struct W { long long a,b; virtual int f(){return (int)a;} virtual ~W(){} W():a(1),b(2){} };
  extern "C" __declspec(dllexport) W* mk(int n){ return new W[n]; }
  cl /LD /GR /O2 /GS- ctortest.cpp   (array-new emits an out-of-line W::W() called by the vector-ctor-iterator)
then assert `W__ctor(` appears in the dump.

### GATE_RISK
The RTTI oracles are in neither gate, so the naming is gate-neutral there; the risk is only that renaming NullWare's (C++/RTTI) ctors/dtors perturbs a fast_gate (1497/1497) or corpus (629/1) compile. Mitigations already in the design: names are globally consistent (one rva -> one name at def and all call sites), globally unique (name_in_use + `_<rva>` suffix), and valid C identifiers (c_safe). fast_gate compiles each function as its own /TC TU, so cross-TU name choices never collide within a TU and the existing extern_callees/`callee_typed_proto_arity` machinery emits a matching `extern` for a renamed dtor call site exactly as it does today for `__vftbl_N`. The one behavioral seam is dropping `__vftbl_` from a renamed dtor's self-name, handled by insertion point 4 so resolve_virtual_call still devirtualizes. Verification protocol after implementing: `python _qa/harness.py 2>&1 | tee _qa/round_harness.log | grep -E "SUMMARY|FAIL"` (expect 629/1) and the fast_gate 1497/1497; if either regresses, `DS_NO_CTORDTOR=1` must restore it exactly, isolating the cause. Re-run the RTTI oracle asserts above to confirm the win.

### FIRES
MSVC RTTI fires on NullWare and on every class oracle. Built nothing new — ran the existing engine on the existing oracle DLLs:
EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); for d in classtest mitest dyncast showcase; do DS_REAL_BIN=$PWD/_qa/classtest/$d.dll DS_PAIRS_DIR=/tmp/$d "$EXE" >/dev/null 2>&1; done
Grepping the DECOMPILED bodies for a vtable store into `this`:
 - CONSTRUCTORS (body does `a1->__vftable = &X__vftable`, name is a bare `fun_XXXX`, NOT a vtable slot): 33 across the 4 oracles. Concrete: mitest fn_00001510/`fun_00001510` is `std::bad_alloc::bad_alloc` — currently `class std__bad_alloc* fun_00001510(class std__bad_alloc*a1,int64_t a2){ a1->__vftable=&std__exception__vftable; ...; a1->__vftable=&std__bad_alloc__vftable; return a1; }` → would be `std__bad_alloc__ctor`. Also fun_000015d0/1640/1590/1600 etc.
 - DESTRUCTORS (scalar deleting, a vtable slot that re-stores its own vtable to [this+0] then `test dl,1`/`operator delete`/`return this`): 17. Concrete: classtest fn_00001000 currently `GameManager__vftbl_2` (renders the store as raw `*a1 = 0xf2e8;`), mitest fn_00001010/1040/1080 = `Drawable__vftbl_1`/`Sprite__vftbl_1`/`Updatable__vftbl_2` → would be `Drawable__dtor`/`Sprite__dtor`/`Updatable__dtor`.
classtest's gm_make ctor is INLINED at /O2 (fn_00001090 = gm_make itself contains the vtable store, stored to [operator_new result], not [rcx]) so it is correctly NOT flagged; the firing GameManager case is its standalone scalar-deleting destructor fn_00001000.

