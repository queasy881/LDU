### FEATURE
Devirtualize virtual calls made on a class-typed LOCAL (a copy of an operator-new'd / factory class object), not just on `this` in a vmethod or a directly-is_class base.

### TRACTABILITY
easy

### CURRENT_HANDLING
engine/analysis/decomp/02_rtti_vtable.inc:71-112 resolve_virtual_call. Only two tag sources: (a) :84-86 `param_structs[obj->name].is_class`; (b) :87-95 obj=="a1" inside a `<Class>__vftbl_N` self_fname. :96 `if (tag.empty()) return "";` bails for a copy-local. Fallback render at engine/analysis/decomp/16_globals_phis.inc:2564-2567 emits the opaque `((long long(*)())(render(e->a)))(...)`. So a virtual call on a class-object COPY (`v1 = (cast)p`) is emitted as an opaque computed-pointer call.

### GAP
No class-tag propagation across a pointer copy: when a class-typed base (p, is_class via the inlined vtable store) is copied/cast into another local (v1 = (struct ...*)p — the operator_new null-check merge, or a plain alias), v1's param_structs entry is a plain non-class struct, so resolve_virtual_call cannot find v1's class and every `v1->vmethod()` stays an opaque indirect call. Naive fix (retag v1 as Widget) is UNSOUND for rendering — v1's recovered fields differ from Widget's (field_8 vs field_c) -> C2039 in the class typedef gate. So the class identity must flow through a SIDE CHANNEL used only for call-target naming, leaving v1's struct layout/field renders untouched.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "immediately after the source-(b) block, at line 96 `if (tag.empty()) return \"\";` inside resolve_virtual_call",
  "change": "Add source (c): `if (tag.empty()) { auto ct = var_class_tag.find(obj->name); if (ct != var_class_tag.end()) tag = ct->second; }` \u2014 placed BEFORE the tag.empty bail. Everything downstream (vtable_rva_for_tag + read_i64 + ds_rva_is_exec + name_for_rva) already fail-closes, so a mis-propagated tag yields \"\" (unchanged output), never a wrong name."
 },
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "next to `std::set<std::string> virtual_callees;` at line 113, and a new method near resolve_virtual_call",
  "change": "Declare member `std::map<std::string,std::string> var_class_tag;` and add the new pass `propagate_local_class_tags()` (body in code_sketch). Keyed on canonical Expr::name; display renumber (autoname/disp, 01_naming_reads.inc:37) is a pure alias so keys stay valid."
 },
 {
  "file": "engine/analysis/decompiler.cpp",
  "anchor": "run(), right after `assign_global_struct_locals();` at line 4906 (param_structs + is_class are final at recover_struct_layouts():4897; the phi-copy v1 has two defs so it survives coalesce_locals/inline/fold \u2014 placement here or after fold_dead_block_temps:4913 are both correct)",
  "change": "Insert `propagate_local_class_tags();`"
 }
]

### CODE_SKETCH
// --- member (02_rtti_vtable.inc, by virtual_callees) ---
std::map<std::string,std::string> var_class_tag; // local var -> class tag of the value it copies

// --- new pass (02_rtti_vtable.inc); call from run() after assign_global_struct_locals() ---
void propagate_local_class_tags() {
    if (std::getenv("DS_NO_VCALL_LOCAL")) return;
    std::set<std::string> ambig;
    auto tag_of = [&](const std::string& v) -> std::string {
        auto it = param_structs.find(v);
        if (it != param_structs.end() && it->second.is_class) return it->second.tag;
        auto ct = var_class_tag.find(v);
        return (ct != var_class_tag.end()) ? ct->second : std::string();
    };
    for (int iter = 0; iter < 4; ++iter) {          // fixpoint over copy chains v1=(cast)p; w=v1
        bool changed = false;
        for (auto& b : blocks) for (auto& s : b.stmts) {
            if (s.kind != SK::Assign || !s.lhs || s.lhs->kind != EK::Var || !s.rhs) continue;
            ExprP r = s.rhs; while (r && r->kind == EK::Cast) r = r->a;   // strip (struct ...*) cast
            if (!r || r->kind != EK::Var) continue;
            const std::string& dst = s.lhs->name;
            if (ambig.count(dst)) continue;
            std::string tag = tag_of(r->name);
            if (tag.empty() || !vtable_rva_for_tag(tag)) continue;        // real vtable-backed class only
            auto ex = var_class_tag.find(dst);
            if (ex == var_class_tag.end())      { var_class_tag[dst] = tag; changed = true; }
            else if (ex->second != tag)         { var_class_tag.erase(ex); ambig.insert(dst); changed = true; }
        }
        if (!changed) break;
    }
}

// --- resolve_virtual_call, at 02_rtti_vtable.inc:96 (before `if (tag.empty()) return "";`) ---
if (tag.empty()) {
    auto ct = var_class_tag.find(obj->name);   // (c) obj is a (possibly cast) copy of a class-typed value
    if (ct != var_class_tag.end()) tag = ct->second;
}

### SOUNDNESS
Sound because the propagated tag is used ONLY to pick which vtable RVA to read; resolve_virtual_call then reads the concrete slot (read_i64 at :100), requires ds_rva_is_exec (:102) and a non-empty name_for_rva (:103-104), so a wrong tag fails closed to \"\" (no devirt), never a wrong callee. It never mutates v1's param_structs layout/tag, so no field render or typedef changes (avoids the C2039 hazard of retagging). Copy is a true value copy (v1 = (cast)p): the non-null path is exactly p's class, so naming the dispatch Class__vftbl_N matches the machine. Guards: only classes with a recovered vtable (vtable_rva_for_tag != 0) propagate; conflicting sources for one dst are dropped (ambig set). Pre-existing is_class ambiguity (p reused for two `new` of different classes) is not worsened — param_structs[p] already carries a single tag. Env gate: DS_NO_VCALL_LOCAL (reverts to today's output for A/B bisect).

### ORACLE
ORACLE ALREADY BUILT: _qa/classtest/devlocal.cpp + devlocal.dll (MSVC) and devlocal_gcc.dll. Source: `struct Widget { int state; virtual int compute(){return state*3;} virtual int refresh(){return state+5;} virtual ~Widget(){} };` with exports widget_make (factory), make_and_compute (new + w->compute() same body), factory_and_compute (w=widget_make(); w->compute()+w->refresh()), param_compute (Widget* param). Compile: `cl /nologo /LD /GR /O2 /GS- devlocal.cpp` (vcvars64 shim) and `g++ -shared -O2 -o devlocal_gcc.dll devlocal.cpp`.
ASSERT on the MSVC decompile (/tmp/dl fn_000010e0.txt = make_and_compute, fn_00001050.txt = factory_and_compute):
  BEFORE (proven now): `grep -c '((int64_t(\*)())' fn_000010e0.txt fn_00001050.txt` => 1 and 2 (opaque heads); `grep -hoE 'Widget__vftbl_[0-9]+\([^)]' ...` => NONE (no named call-head; only `Widget__vftbl_0();` decls).
  AFTER (fix): those 3 opaque heads become named call-heads `Widget__vftbl_0(v1)` / `Widget__vftbl_1(v1)` — assert `grep -E 'Widget__vftbl_[01]\((v1|a1)' ` matches >=3 and the `((int64_t(*)())(*(int64_t*)(v1->field_0` opaque form drops to 0. The `Widget__vftbl_N` extern protos are already emitted (from the guard-compare operand), so no new C2197/C2198.
This oracle is NOT in fast_gate/corpus, so it is the standalone proof.

### GATE_RISK
Low. The change only converts an opaque indirect call into a named `Class__vftbl_N(...)` head + registers that name in virtual_callees (extern proto) — byte-for-byte the same transformation source (a)/(b) already perform and that fast_gate 1497/1497 + corpus 629/1 already accept. Self-verifying slot read means any mis-propagation reverts to today's output (net-zero on functions with no class-copy). To keep both green: (1) require vtable_rva_for_tag(tag)!=0 in the pass; (2) drop conflicting-source locals (ambig); (3) named vftbl callees use the K&R `int64_t X();` proto so any recovered arg count compiles. Run `python _qa/harness.py 2>&1 | tee _qa/round_harness.log | grep -E \"SUMMARY|FAIL\"` and `_qa/fast_gate.sh`; if any regression, DS_NO_VCALL_LOCAL reverts. Corpus DLLs with MSVC-devirt-guarded copies are the only functions whose text changes, and only from opaque->named.

### FIRES
ORACLE BUILT + DECOMPILED (proves the gap): _qa/classtest/devlocal.cpp (Widget with 2 virtuals + dtor; make_and_compute constructs+calls a virtual same-body, factory_and_compute, param_compute). Built MSVC: `cl /nologo /LD /GR /O2 /GS- devlocal.cpp` (via vswhere+vcvars64 at "C:\Program Files\Microsoft Visual Studio\18\Community"). Decompiled: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN="$PWD/_qa/classtest/devlocal.dll" DS_PAIRS_DIR=/tmp/dl "$EXE" >/dev/null 2>&1`.
FIRING COUNTS (/tmp/dl): opaque virtual-dispatch heads `((int64_t(*)())(*(int64_t*)(v1->field_0)))(...)` = 3 (make_and_compute fn_000010e0 x1, factory_and_compute fn_00001050 x2). Named call-heads `Widget__vftbl_N(...)` today = 0 (`grep -hoE "Widget__vftbl_[0-9]+\([^)]"` -> NONE; the only `Widget__vftbl_0(` lines are `int64_t Widget__vftbl_0();` forward-decls).
ROOT CAUSE proven in the same output: the operator-new'd object IS class-typed — `struct Widget*p;` (is_class) with `p->__vftable = &Widget__vftable;` — but MSVC /O2 routes it through the alloc null-check merge into a FRESH local `v1 = (struct s_make_and_compute_v1*)p;` whose struct s_..._v1 is NOT is_class, and EVERY virtual call is made on `v1` (`*(int64_t*)(v1->field_0)`), so resolve_virtual_call source (a) `param_structs[v1].is_class` is false -> no devirt. The engine even resolves the guard operand (`!= Widget__vftbl_0`) yet leaves the paired indirect CALL opaque. Cross-check: the pre-existing classtest.dll gm_tick/gm_score (virtual call on a class PARAM a1, no in-body vtable store) are likewise fully opaque (`(*(int64_t*)(*a1))(a1)`). g++ -O2 exact-type-devirts A/B away but param_compute keeps the same opaque guarded fallback. So source(a)-for-locals is effectively dead under /O2 whenever the class is only knowable via the copy.

