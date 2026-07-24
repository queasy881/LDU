### FEATURE
Multiple inheritance (MSVC x64 RTTI): recognize/annotate this-adjustor thunks + surface the secondary-vtable base subobject. Two-base oracle `_qa/classtest/mitest.cpp` -> `struct Sprite : Drawable, Updatable` yields a PRIMARY vtable (Drawable subobject at +0) and a SECONDARY vtable (Updatable subobject at +16, COL offset=16), plus a this-adjustor thunk `sub rcx,0x10; jmp Sprite::~dtor` in the secondary destructor slot.

### TRACTABILITY
medium

### CURRENT_HANDLING
engine/analysis/rtti.cpp:380-399 (inside `if (offc==0 && !already_seeded(pos))`): reads ONLY base[1] (`read_u32(e, pba + 4, bd1)` at line 386) and seeds a single `<Class>__extends__<Base>` marker at the CHD rva — so exactly one base is ever recorded, and secondary bases (mdisp>0) are never mapped. engine/analysis/decomp/09_structs.inc:906: `class_base_of(L.tag)` returns that one base -> `struct Sprite /* : Drawable */` (incomplete for MI). engine/analysis/decomp/02_rtti_vtable.inc:32 `class_base_of` returns first match only. The thunk itself: rtti.cpp names it `Sprite_off16__vftbl_2` (secondary-vtable slot, offc branch at line 414) and the ordinary tail-call lifter renders `Sprite__vftbl_1(a1 - 0x10)` — there is NO this-adjustor-thunk detector or annotation anywhere (grep `thunk_annotation`/`adjustor` in engine = 0 hits; existing "thunk" refs are import/lock/tail-call wrappers only).

### GAP
(1) The secondary-vtable this-adjustor thunk (`sub/add rcx,N; jmp method`) is emitted opaquely as `method(a1 - N)` with no note that N is a base-subobject `this` adjustment nor which base it re-bases to. (2) With multiple inheritance the inheritance clause drops every base after the first: `struct Sprite /* : Drawable */` instead of `/* : Drawable, Updatable */`. (3) The `off16` in the secondary-vtable slot names surfaces the displacement but is never tied to the concrete base (Updatable) sitting at that displacement.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "the base-seed block at lines 385-397 (`read_u32(e, pba + 4, bd1)` ... single `%s__extends__%s` snprintf), inside `if (offc==0 && !already_seeded(e,pos))` and `!getenv(DS_NO_RTTIBASE)`",
  "change": "Replace the single base[1] read with a numContainedBases-aware DFS walk over the whole BaseClassArray: base[0] is the class itself; a DIRECT base is the next entry after skipping the previous direct base's `numContainedBases` (BCD+0x04) descendants. For each DIRECT base seed `<Class>__extends__<Base>` (at the base's BCD rva, unique), and when its PMD.mdisp (BCD+0x08) > 0 also seed `<Class>__baseoff_<mdisp>__<Base>` (at BCD rva+4). Bounded by nbase<64; break on any unmapped read."
 },
 {
  "file": "engine/analysis/decomp/02_rtti_vtable.inc",
  "anchor": "immediately after `class_base_of` (ends line 44) and near `build_confidence_comment`",
  "change": "Add `class_bases_of(tag)` = comma-joined list of every `<tag>__extends__<Base>` marker (dedup, seed order); add `base_at_offset(tag, off)` = the `<Base>` from a `<tag>__baseoff_<off>__<Base>` marker; add `thunk_annotation()` that detects the 2-insn this-adjustor idiom and returns a header comment. Keep `class_base_of` unchanged (still used for catch-type first-base)."
 },
 {
  "file": "engine/analysis/decomp/09_structs.inc",
  "anchor": "line 906 `std::string bb = class_base_of(L.tag);`",
  "change": "Swap `class_base_of` -> `class_bases_of` so the struct/class header comment lists ALL direct bases: `struct Sprite /* : Drawable, Updatable */`."
 },
 {
  "file": "engine/analysis/decompiler.cpp",
  "anchor": "line 5825 `full += build_confidence_comment(body, referenced);` in the header-assembly of the emit routine",
  "change": "Add `full += thunk_annotation();` so the this-adjustor note prints just under the `/* name @ rva size */` + confidence header, before the signature."
 }
]

### CODE_SKETCH
// --- engine/analysis/decomp/02_rtti_vtable.inc (new helpers) ---
std::string class_bases_of(const std::string& tag){
  if(!e||tag.empty()||std::getenv("DS_NO_RTTIBASE")) return "";
  static const char* MK="__extends__"; std::vector<std::string> bs;
  for(size_t i=0;i<e->symbol_len;++i){ const char* nm=e->symbols[i].name; if(!nm||!nm[0])continue;
    std::string n=nm; size_t p=n.find(MK); if(p==std::string::npos)continue;
    if(sani(n.substr(0,p))!=tag)continue; std::string b=n.substr(p+std::strlen(MK));
    if(std::find(bs.begin(),bs.end(),b)==bs.end()) bs.push_back(b); }
  std::string o; for(size_t i=0;i<bs.size();++i){ if(i)o+=", "; o+=bs[i]; } return o;
}
std::string base_at_offset(const std::string& tag,int64_t off){
  if(!e||tag.empty()||off<=0) return "";
  char pfx[64]; std::snprintf(pfx,sizeof pfx,"__baseoff_%lld__",(long long)off);
  for(size_t i=0;i<e->symbol_len;++i){ const char* nm=e->symbols[i].name; if(!nm||!nm[0])continue;
    std::string n=nm; size_t p=n.find(pfx); if(p==std::string::npos)continue;
    if(sani(n.substr(0,p))!=tag)continue; return n.substr(p+std::strlen(pfx)); }
  return "";
}
std::string thunk_annotation(){                       // comment-only; DS_NO_THUNKANNOT
  static const bool off=std::getenv("DS_NO_THUNKANNOT")!=nullptr;
  if(off||!e||insns.size()!=2) return "";
  const Insn& a=insns[0]; const Insn& j=insns[1];
  if(!(a.id==X86_INS_SUB||a.id==X86_INS_ADD)) return "";
  if(a.x86.op_count!=2||a.x86.operands[0].type!=X86_OP_REG||a.x86.operands[1].type!=X86_OP_IMM) return "";
  Reg r; int w; map_reg(a.x86.operands[0].reg,r,w); if(r!=R_RCX) return "";   // x64 `this`
  if(!j.is_jmp||!j.has_branch_target||!ds_rva_is_exec(e,j.branch_target)) return "";
  std::string tn=name_for_rva(j.branch_target); if(tn.empty()) return "";
  int64_t adj=(a.id==X86_INS_SUB)? -a.x86.operands[1].imm : a.x86.operands[1].imm;
  std::string tag=self_fname; size_t p;
  if((p=tag.find("__vftbl_"))!=std::string::npos) tag=tag.substr(0,p);
  if((p=tag.find("_off"))!=std::string::npos)     tag=tag.substr(0,p);
  std::string b=base_at_offset(tag,-adj), note = b.empty()?"":(" ("+b+" base subobject)");
  char buf[224]; std::snprintf(buf,sizeof buf,
    "/* this-adjustor thunk: this %s 0x%llx%s; tail-call %s */\n",
    adj<0?"-=":"+=",(unsigned long long)(adj<0?-adj:adj),note.c_str(),tn.c_str());
  return buf;
}
// --- engine/analysis/rtti.cpp (replace lines 385-397 single-base read) ---
for(uint32_t k=1;k<nbase;){
  uint32_t bcd=0,btd=0,ncont=0,md=0;
  if(!read_u32(e,pba+4*k,bcd)||!ds_rva_is_mapped(e,bcd)) break;
  read_u32(e,bcd+0x04,ncont); read_u32(e,bcd+0x00,btd); read_u32(e,bcd+0x08,md);
  if(ds_rva_is_mapped(e,btd)){
    std::string bdec=read_rtti_name(e,btd+0x10);
    if(bdec.rfind(".?A",0)==0){ std::string br=demangle(bdec,nullptr);
      if(!br.empty()&&br!=cls_raw){ char mk[224];
        std::snprintf(mk,sizeof mk,"%s__extends__%s",c_safe(cls_raw).c_str(),c_safe(br).c_str());
        ds_engine_add_symbol(e,bcd,mk);
        if((int32_t)md>0){ std::snprintf(mk,sizeof mk,"%s__baseoff_%d__%s",
              c_safe(cls_raw).c_str(),(int)md,c_safe(br).c_str());
          ds_engine_add_symbol(e,bcd+4,mk); } } } }
  k+=1+ncont;   // skip this direct base's descendants (indirect bases are not `: Base`)
}
// --- 09_structs.inc:906 --- std::string bb = class_bases_of(L.tag);
// --- decompiler.cpp:5825 --- full += thunk_annotation();

### SOUNDNESS
All reads are the existing bounds-checked read_u32/ds_rva_is_mapped/ds_rva_is_exec helpers; the base walk is bounded (nbase<64) and terminates for any garbage numContainedBases (k advances >=1 each step and stops past nbase or on an unmapped BCD), so no infinite loop / OOB. The numContainedBases DFS is the correct MSVC rule for DIRECT vs indirect bases (verified: for std::bad_array_new_length the walk yields only bad_alloc, not the indirect exception) so it will never over-report `: Base`. thunk_annotation is deliberately narrow (exactly 2 insns; op0 = SUB/ADD RCX,imm; op1 = direct jmp to in-image EXEC): the import-thunk (`jmp [IAT]`, indirect) and vcall-thunk (`mov rax,[rcx]; jmp [rax]`, op0=MOV) shapes are excluded, and even a false positive only prints a comment. RENDER IS COMMENT-ONLY (no emitted C token changes, no rename of the thunk fn -> call sites unchanged). Extra symbols are seeded at .rdata BCD rvas that no code references (RTTI structures are reached only from other RTTI data), so name_for_rva output for real code/data is unchanged; this matches the pre-existing `__extends__`-at-CHD seeding that already ships clean. Gates: new render behind DS_NO_THUNKANNOT (kill-switch -> byte-identical output); multi-base seeding reuses the existing DS_NO_RTTIBASE (already reverts to single/no base). Keep class_base_of intact for the catch-type consumer.

### ORACLE
Oracle already written+built: `_qa/classtest/mitest.cpp` (struct Drawable{virtual draw}; struct Updatable{virtual update,speak}; struct Sprite:Drawable,Updatable overriding all + dtor; exports spr_make/spr_update/spr_speak/spr_draw). Compile: PowerShell vcvars shim -> `cl /nologo /LD /GR /O2 /GS- mitest.cpp` (and `g++ -shared -O2 -o mitest_gcc.dll mitest.cpp`). RTTI cross-check tool `_qa/classtest/parse_rtti.py` confirms base[2]=Updatable mdisp=16. AFTER implementing, decompile mitest.dll (DS_REAL_BIN=.../mitest.dll DS_PAIRS_DIR=/tmp/mi_ms dump_pairs) and assert: (1) /tmp/mi_ms/fn_00001000.txt contains `this-adjustor thunk: this -= 0x10 (Updatable base subobject); tail-call Sprite__vftbl_1` (today: absent — only `Sprite__vftbl_1(a1 - 0x10)`); (2) the Sprite struct render contains `struct Sprite /* : Drawable, Updatable */` (today: `/* : Drawable */`); (3) DS_NO_THUNKANNOT + DS_NO_RTTIBASE revert both to today's output byte-for-byte. Negative control: single-inheritance oracles classtest.dll/showcase.dll still emit exactly one `: Base`.

### GATE_RISK
Low. The whole change is comment-only at render time plus additional .rdata-anchored RTTI marker symbols, so no function body, signature, name, or call site changes token-wise -> fast_gate stays 1497/1497 cl-clean and corpus stays 629/1 behavioral (comments are stripped by cl /TC; no new gotos, so GOTO_TOTAL and INVENTED_FLAGS/STATE_MACHINES fences are untouched). To keep both green: (a) do NOT rename the thunk function (annotate only); (b) seed the extra markers at unique BCD rvas (not shared CHD) so no already_seeded interaction and no accidental name_for_rva hit on real code; (c) leave class_base_of (first-base, used for catch types) intact and add class_bases_of separately. Run `python _qa/harness.py 2>&1 | tee _qa/round_harness.log | grep -E "SUMMARY|FAIL"` and `bash _qa/fast_gate.sh` after the edit; if any NullWare fn happens to match the 2-insn `sub rcx,N; jmp` shape the only effect is an added comment. mitest is not in either gate, so its own decompile is the proof of fire.

### FIRES
Built oracle: `cl /LD /GR /O2 /GS- mitest.cpp` (vcvars: VS18\Community\...\vcvars64.bat) -> mitest.dll (105472 B); also `g++ -shared -O2 -o mitest_gcc.dll`. Decompiled: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN="$PWD/_qa/classtest/mitest.dll" DS_PAIRS_DIR=/tmp/mi_ms "$EXE"` (390 fns).
EVIDENCE 1 (thunk, opaque today): exactly ONE 2-insn adjustor thunk in the DLL — fn_00001000.txt DISASM `0x1000: sub rcx,0x10 / 0x1004: jmp 0x1040`, rendered `int64_t Sprite_off16__vftbl_2(int64_t a1){ return Sprite__vftbl_1(a1 - 0x10); }` — no adjustor annotation; `a1 - 0x10` reads as arbitrary ptr math. Target 0x1040 = `Sprite__vftbl_1` (the ~Sprite deleting dtor).
EVIDENCE 2 (MI base dropped): fn_00001110.txt line 29 emits `struct Sprite /* : Drawable */ {` — shows only base[1] (Drawable), MISSES base[2] (Updatable, the second base).
EVIDENCE 3 (data is recoverable): `python _qa/classtest/parse_rtti.py mitest.dll` shows Sprite COL@0x16c70 (offset=0) and a SECOND COL@0x16d20 (offset=16), both -> CHD@0x16c98 numBases=3: base[0]=Sprite mdisp=0 numContained=2, base[1]=Drawable mdisp=0, base[2]=Updatable mdisp=16. So COL.offset(16) == thunk adj(0x10) == base[2].PMD.mdisp(16) all agree — the base name for the +16 subobject is directly recoverable. (g++ -O2 variant recovered only `Sprite__vftbl` and emitted no 2-insn `sub rcx` thunk, so this plan targets the MSVC path; the render-side thunk detector is compiler-agnostic and will also catch g++ `_ZThn` thunks when present.)

