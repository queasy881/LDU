### FEATURE
Annotate UNRESOLVED virtual calls with their vtable slot offset (class unknown) or Class::vfunc_N (class known but slot target unnamed), as a trailing /* ... */ comment on the opaque indirect-call render.

### TRACTABILITY
easy

### CURRENT_HANDLING
engine/analysis/decomp/16_globals_phis.inc:2564-2568 — EK::Call render: `vm = resolve_virtual_call(e->a)`; when vm=="" and e->indirect, head becomes `"((long long(*)())(" + render(e->a) + "))"` (line 2566-2567). Args appended, `s += ")"`, `return s;` at 2618. Emits the OPAQUE `((int64_t(*)())(*(int64_t*)(*a1 + 0x8)))(a1)` with no indication it is a virtual dispatch or which slot. The slot offset is present in the expression but buried; the reader gets no class, no slot index, no "this is a vtable call" signal.

### GAP
The offset (and, on the class-known path, the class tag) is already computed inside resolve_virtual_call but discarded on every "" return. When devirt fails, all recovered structure is thrown away and the render is a raw double-indirection cast. IDA/Hex-Rays annotate these as `(*(off_18)(this))` style slot references; we emit nothing.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "resolve_virtual_call signature at line 71 and its shape-recognition body (lines 74-96)",
  "change": "Add three defaulted out-params `bool* out_recognized=nullptr, int64_t* out_off=nullptr, std::string* out_tag=nullptr`. After line 81 (`if (!obj || obj->kind != EK::Var) return \"\";`) \u2014 the point where the `*(*Var + off)` vtable-dispatch shape is confirmed \u2014 set `if(out_recognized)*out_recognized=true; if(out_off)*out_off=off;`. Right before line 96 (`if (tag.empty()) return \"\";`) set `if(out_tag)*out_tag=tag;`. All existing behaviour/return values unchanged (defaults keep the 3 nullptr); the existing callsite at 16_globals_phis.inc:2564 keeps working."
 },
 {
  "file": "engine/analysis/decomp/16_globals_phis.inc",
  "anchor": "EK::Call case, the `std::string vm = ... resolve_virtual_call(e->a) ...` at line 2564, and the final `s += \")\"; return s;` at lines 2617-2618",
  "change": "Capture the out-params at line 2564: `bool vc_rec=false; int64_t vc_off=0; std::string vc_tag; std::string vm = (e->indirect && e->a) ? resolve_virtual_call(e->a,&vc_rec,&vc_off,&vc_tag) : \"\";`. Before the final `return s;` (2618), append the annotation when the dispatch was recognized but not named. Both early `return s` paths (self-call clamp @2575, typed-proto @2604) are `!e->indirect`-guarded, so every indirect call reaches this final return."
 }
]

### CODE_SKETCH
// --- 02_rtti_vtable.inc : resolve_virtual_call ---
std::string resolve_virtual_call(const ExprP& target,
                                 bool* out_recognized = nullptr,
                                 int64_t* out_off = nullptr,
                                 std::string* out_tag = nullptr) {
    if (std::getenv("DS_NO_VCALL")) return "";
    if (!target || target->kind != EK::Mem || !target->a) return "";
    ExprP inner = target->a; int64_t off = 0;
    if (inner->kind == EK::Binary && inner->op == "+" && inner->b &&
        inner->b->kind == EK::Const) { off = inner->b->cval; inner = inner->a; }
    while (inner && inner->kind == EK::Cast) inner = inner->a;
    if (!inner || inner->kind != EK::Mem || !inner->a) return "";
    ExprP obj = inner->a;
    while (obj && obj->kind == EK::Cast) obj = obj->a;
    if (!obj || obj->kind != EK::Var) return "";
    if (out_recognized) *out_recognized = true;   /* NEW: vtable-dispatch shape confirmed */
    if (out_off)        *out_off = off;            /* NEW: slot byte offset (bytes, as used at read_i64(vt+off)) */
    std::string tag;
    auto it = param_structs.find(obj->name);
    if (it != param_structs.end() && it->second.is_class) tag = it->second.tag;
    else if (obj->name == "a1" && !self_fname.empty()) {
        size_t p = self_fname.find("__vftbl_");
        if (p != std::string::npos && p > 0) tag = self_fname.substr(0, p);
    }
    if (out_tag) *out_tag = tag;                    /* NEW: class when known (may be "") */
    if (tag.empty()) return "";
    /* ... unchanged: vtable_rva_for_tag / read_i64 / ds_rva_is_exec / name_for_rva ... */
}

// --- 16_globals_phis.inc : case EK::Call ---
case EK::Call: {
    bool vc_rec = false; int64_t vc_off = 0; std::string vc_tag;
    std::string vm = (e->indirect && e->a)
        ? resolve_virtual_call(e->a, &vc_rec, &vc_off, &vc_tag) : "";
    std::string head = !vm.empty() ? vm
        : (e->indirect && e->a) ? "((long long(*)())(" + render(e->a) + "))"
        : e->callee;
    std::string s = head + "(";
    /* ... unchanged self-call / typed-proto (both !e->indirect) + general arg loop ... */
    s += ")";
    if (vm.empty() && vc_rec && !std::getenv("DS_NO_VSLOT")) {   /* NEW */
        if (!vc_tag.empty())
            s += " /* " + vc_tag + "::vfunc_" +
                 std::to_string(vc_off / (e->arch == DS_ARCH_X64 ? 8 : 4)) + " */";
        else
            s += " /* vtable slot +" + hex((uint64_t)vc_off) + " */";
    }
    return s;
}
// gm_score  -> return (int64_t)((int64_t(*)())(*(int64_t*)(*a1 + 8)))(a1) /* vtable slot +0x8 */;
// w_finalize-> ... (*a1 + 0x18)))(a1) /* vtable slot +0x18 */;

### SOUNDNESS
Comment-only: never changes emitted C semantics. Soundness of the CLAIM rests on reusing resolve_virtual_call's exact shape parser (lines 73-81) as the single source of truth: the annotation fires iff that parser confirmed the `*(*Var + const)` double-indirection dispatch (the C++ thiscall vtable ABI) AND could not produce a method name (vm==""). Plain fnptr calls `(*fp)(x)` (single indirection, target=Var, rejected @73), dispatch-table calls `tbl[i](x)` (variable index, inner not Mem-of-Var, rejected @78), and cast-wrapped indirect targets are all excluded — verified: 0 of the ~40 non-vtable indirect calls in the test dumps match. off is treated as BYTES exactly as resolve_virtual_call already uses it at read_i64(vt+off), so vfunc_N = off/ptr_size is consistent. Comment text cannot contain `*/` (hex() yields 0x.. digits; vc_tag is a sani'd class tag = alnum/underscore). Null-safe (all derefs guarded by the existing shape checks). Optional extra hardening (NOT required): also require the call to pass obj as arg0 (true thiscall) — keeps all 6 MSVC sites, only suppresses the g++ this-arg-elided form. Gate: DS_NO_VSLOT disables the annotation independently of DS_NO_VCALL.

### ORACLE
Oracle file (already written + built): _qa/classtest/vslottest.cpp
  struct Widget { int state;
    virtual void tick(){state++;}        // slot 0 (+0x0)
    virtual int  read(){return state;}   // slot 1 (+0x8)
    virtual int  measure(){return state*2;}   // slot 2 (+0x10)
    virtual int  finalize(){return state-1;}  // slot 3 (+0x18)
    virtual ~Widget(){} };
  extern "C" __declspec(dllexport) Widget* w_make(){return new Widget();}
  extern "C" __declspec(dllexport) void w_tick(Widget* w){w->tick();}
  extern "C" __declspec(dllexport) int  w_read(Widget* w){return w->read();}
  extern "C" __declspec(dllexport) int  w_measure(Widget* w){return w->measure();}
  extern "C" __declspec(dllexport) int  w_finalize(Widget* w){return w->finalize();}
Compile: cl /nologo /LD /GR /O2 /GS- vslottest.cpp   (vcvars64 shim); g++ -shared -O2 -fno-exceptions -o vslottest_gcc.dll vslottest.cpp
Decompile: DS_REAL_BIN=.../vslottest.dll DS_PAIRS_DIR=/tmp/vs $(ls -t target/release/deps/dump_pairs-*.exe|head -1) >/dev/null 2>&1
ASSERT after fix (grep /tmp/vs/*.txt): w_read contains "*a1 + 8)))(a1) /* vtable slot +0x8 */"; w_measure "+0x10 */"; w_finalize "+0x18 */"; w_tick "*(int64_t*)(*a1)))(a1) /* vtable slot +0x0 */". BEFORE fix (verified now): those exact lines end at ")(a1);" with NO comment. Also assert with DS_NO_VSLOT set the comments vanish (A/B).

### GATE_RISK
Gate-neutral. fast_gate (NullWare 1497/1497 cl /TC): the annotation is a C block comment = whitespace to the compiler, cannot break /TC compilation of any of the 1497 fns. It introduces none of the tokens fast_gate counts — no `goto `, no `switch(__state`, no `__at_`/invented flags, no `in_<REG>` — the strings are only "vtable slot"/"vfunc_", so GOTO<=700 fence + INVENTED_FLAGS/STATE_MACHINES/IN_REG=0 are untouched. corpus/harness.py 629 is behavioral (runtime) — comments have no runtime effect. To keep both green: A/B with DS_NO_VSLOT — the on/off char delta must be exactly the appended comments (verify `grep -c "vtable slot"` before/after) and CLEAN must stay 1497/1497. New DS_NO_VSLOT gate lets the change be reverted to a byte-identical baseline instantly. The oracles are in neither gate, so the feature is proven solely by its own decompile grep.

### FIRES
Built two MSVC oracles and decompiled them; 6 opaque virtual-dispatch sites fire, all currently emitting the bare cast with ZERO slot annotation.

Commands:
  # fresh oracle, 4 distinct slot offsets
  cl /nologo /LD /GR /O2 /GS- _qa/classtest/vslottest.cpp   (via vcvars64.bat)
  EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1)
  DS_REAL_BIN="$PWD/_qa/classtest/vslottest.dll" DS_PAIRS_DIR=/tmp/vs "$EXE" >/dev/null 2>&1
  grep -rE "int64_t\(\*\)\)\(\*\(int64_t\*\)\(\*a1" /tmp/vs/*.txt

Output (verbatim, all opaque, NO comment):
  w_tick     0x10d0: return (int64_t)((int64_t(*)())(*(int64_t*)(*a1)))(a1);          // slot +0x0
  w_read     0x10c0: return (int64_t)((int64_t(*)())(*(int64_t*)(*a1 + 8)))(a1);      // slot +0x8
  w_measure  0x10b0: return (int64_t)((int64_t(*)())(*(int64_t*)(*a1 + 0x10)))(a1);   // slot +0x10
  w_finalize 0x1070: return (int64_t)((int64_t(*)())(*(int64_t*)(*a1 + 0x18)))(a1);   // slot +0x18
Plus the existing classtest.dll: gm_score (slot +0x8), gm_tick (slot +0x0) — same opaque shape. 6/6 MSVC sites currently unannotated; each would gain "/* vtable slot +0xN */".

Why resolve_virtual_call returns "" here: a1 is typed int64_t* (the thunk `mov rax,[rcx]; jmp [rax+8]` reveals no class), so param_structs[a1].is_class is false (source a) and self is not a __vftbl_ method (source b) -> tag empty -> line 96 `if (tag.empty()) return ""`. The vtable-dispatch SHAPE (Mem(Mem(Var))) is fully recognized (obj==a1 Var confirmed at line 81); only the class is missing.

False-positive check: every OTHER indirect call in the same dumps — ((int64_t(*)())(a2))(...), (...)(v11), (...)(a4), (...)(qword_1d018), subscript-through-cast ((uint32_t)((int32_t*)0x16a18)[...]) — has a Var/Cast target, rejected by resolve_virtual_call's `target->kind != EK::Mem` (line 73) / inner-not-Mem (line 78). Only the two GameManager/Widget forwarders match. g++ variant (vslottest_gcc.dll) uses a typed-field vptr `*(int64_t*)(a1->field_0)` for slot 0 (obj still resolves to Var a1 -> would also annotate +0x0) and subscript `((int64_t*)a1->field_0)[N]` for higher slots.

