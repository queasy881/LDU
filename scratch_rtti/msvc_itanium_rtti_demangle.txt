### FEATURE
MSVC + Itanium RTTI demangler: parse pointer / reference / cv-qualified and non-type (integer) template arguments, instead of declining on them. Today the template-arg parsers only accept plain builtins and class-refs; ANY other arg shape (`int*`, `char*`, `Fixed<5>`, `T&`) makes `type_arg()` set `ok=false`, which on MSVC discards the whole recursive parse and falls back to a flat `@`-split that promotes argument-encoding fragments into INVENTED namespace components, and on g++/Itanium drops the class entirely.

### TRACTABILITY
medium

### CURRENT_HANDLING
rtti.cpp:100-107 `MsvcName::type_arg()` accepts only `builtin()` and V/U/T/W class-refs; everything else `ok=false; return "?"`. That trips rtti.cpp:141 (`if (p.ok && !out.empty()) return out;`) so demangle() falls to the flat `@`-split fallback at rtti.cpp:143-155, which splits `?$Box@PEAH@app` on '@' and reverses -> emits `app::PEAH::Box` (arg code PEAH becomes a namespace). Itanium: rtti.cpp:225-231 `ItaniumName::type_arg()` accepts only builtin / N-nested / source-name; pointer 'P', ref 'R', literal 'L' -> `ok=false`, so itanium_demangle (rtti.cpp:245-250) returns "" at line 248, and scan_rtti_itanium drops the class at rtti.cpp:282-283 (`if (cls_raw.empty()) continue;`). Downstream render is untouched by the bug and needs no change: engine/analysis/decomp/02_rtti_vtable.inc:7 `class_for_vtable` returns the RAW seeded name and the caller sani()s it (09_structs.inc:460-464), so a corrected cls_raw flows straight through.

### GAP
Pointer (`P/Q/R/S`), reference (`A/B`), cv+`__ptr64` modifiers, and non-type integer args (`$0<num>`) are unhandled on MSVC; pointer (`P`), lvalue/rvalue ref (`R`/`O`), cv (`K`/`V`/`r`) prefixes and integer literals (`L<type><value>E`) are unhandled on Itanium. Result: common instantiations like `Box<int*>` / `Array<N>` either get a WRONG class name that fabricates a namespace (MSVC) or are silently not recovered at all (g++). Because the failure discards the ALREADY-correct namespace+template-name, the output is worse than a generic placeholder would be.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "MsvcName::type_arg() at lines 100-107 (and add a MsvcName::number() helper near builtin() at 80-99)",
  "change": "Peel leading pointer/reference layers (P/Q/R/S -> '*', A/B -> '&'), each optionally followed by 'E' (__ptr64) and one cv byte A-D; then handle '$' non-type args ('$0'<num> -> integer literal via number()); then fall through to the existing builtin()/qname() paths, appending the accumulated pointer/ref suffix. Only genuinely unknown leading codes keep ok=false."
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "ItaniumName::type_arg() at lines 225-231",
  "change": "Peel leading 'P'->'*', 'R'->'&', 'O'->'&&', and drop cv prefixes 'K'/'V'/'r'; handle 'L' <type> <value> 'E' integer literals (consume the type via builtin(), read the decimal digits, consume 'E'); then fall through to builtin()/nested()/source_name(), appending the pointer/ref suffix."
 },
 {
  "file": "engine/analysis/rtti.cpp",
  "anchor": "top of both new type_arg() bodies",
  "change": "Gate the new behavior behind `static const bool off = std::getenv(\"DS_NO_TMPLARG\") != nullptr; if (off) { <old immediate-decline body> }` so the change can be A/B bisected and reverted without a rebuild-flag."
 }
]

### CODE_SKETCH
// ---- MsvcName: new integer decoder (place near builtin(), ~line 99) ----
std::string number() {                 // MSVC int literal, already past "$0"
    bool neg = false; if (peek()=='?') { neg=true; ++i; }
    if (peek()>='0' && peek()<='9') {  // 1..10 encoded as '0'..'9'
        long v=(peek()-'0')+1; ++i; return (neg?"-":"")+std::to_string(v);
    }
    long v=0; bool any=false;          // >10: nibbles 'A'..'P', '@'-terminated
    while (peek()>='A' && peek()<='P') { v=v*16+(peek()-'A'); ++i; any=true; }
    if (peek()=='@') ++i;
    if (!any) { ok=false; return "?"; }
    return (neg?"-":"")+std::to_string(v);
}
// ---- MsvcName::type_arg() REPLACES lines 100-107 ----
std::string type_arg() {
    std::string suffix;
    for (;;) { char c=peek();
        if (c=='P'||c=='Q'||c=='R'||c=='S') { ++i; if(peek()=='E')++i; if(peek()>='A'&&peek()<='D')++i; suffix="*"+suffix; continue; }
        if (c=='A'||c=='B')               { ++i; if(peek()=='E')++i; if(peek()>='A'&&peek()<='D')++i; suffix="&"+suffix; continue; }
        break;
    }
    if (peek()=='$') { ++i; if (peek()=='0') { ++i; return number(); } ok=false; return "?"; }
    std::string b=builtin(); if (!b.empty()) return b+suffix;
    char c=peek();
    if (c=='V'||c=='U'||c=='T') { ++i; return qname()+suffix; }
    if (c=='W')                 { ++i; if(peek()=='4')++i; return qname()+suffix; }
    ok=false; return "?";
}
// ---- ItaniumName::type_arg() REPLACES lines 225-231 ----
std::string type_arg() {
    std::string suffix;
    for (;;) { char c=peek();
        if (c=='P') { ++i; suffix="*"+suffix;  continue; }
        if (c=='R') { ++i; suffix="&"+suffix;  continue; }
        if (c=='O') { ++i; suffix="&&"+suffix; continue; }
        if (c=='K'||c=='V'||c=='r') { ++i; continue; }   // cv/restrict, dropped
        break;
    }
    if (peek()=='L') {                                    // L <type> <value> E
        ++i; builtin();                                  // consume type code
        std::string num; if (peek()=='n'){num="-";++i;}
        while (peek()>='0'&&peek()<='9'){ num+=peek(); ++i; }
        if (peek()=='E') ++i; else ok=false;
        if (num.empty()||num=="-") { ok=false; return "?"; }
        return num;
    }
    std::string b=builtin(); if (!b.empty()) return b+suffix;
    if (peek()=='N') return nested()+suffix;
    if (peek()>='1'&&peek()<='9') return source_name()+suffix;
    ok=false; return "?";
}
// Effect: cls_raw becomes "app::Box<int*>" / "app::Fixed<5>"; c_safe -> "app__Box_int__" /
// "app__Fixed_5_"; the __vftable seed feeds class_for_vtable unchanged. No render edits.

### SOUNDNESS
Correctness hinges on consuming EXACTLY the arg's bytes so the parser stays in sync. The x64 RTTI encoding is well-covered: pointer = P/Q/R/S then optional 'E' (__ptr64, always present on x64) then one cv byte A-D then the pointee; the peel loop mirrors that grammar, and pointer-to-class/pointer-to-pointer nest correctly because the pointee is parsed by the same routine. At arg-start position P/Q/R/S/A/B are unambiguous (they are neither MSVC builtins C/D/E/F/G/H/I/J/K/M/N/O/X/_J.. nor class tags V/U/T/W), so the existing correct cases (classtest/tpltest/showcase/vcalltest have NO pointer/non-type args) are byte-for-byte unchanged. Residual exotic args (function pointers/member pointers `$$`, complex `$` forms) still set ok=false -> flat fallback, i.e. never worse than today. Defense-in-depth follow-on (note, not required for this fix): make demangle()'s fallback at rtti.cpp:143-155 strip `?$`/type-code fragments so it can never fabricate a namespace even for the residual shapes. Gate everything behind env `DS_NO_TMPLARG` (reverts both type_arg bodies to the old immediate-decline) for clean bisection.

### ORACLE
Oracle source already written: `_qa/classtest/tmplargs.cpp` (namespace app; Box<T>, Fixed<int N>, Wrap<T>, Widget; exports mk_boxpi/mk_boxpc/mk_fixed/mk_wrap/mk_widget). Build MSVC: run vcvars64 (`C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat`) then `cl /nologo /LD /GR /O2 /GS- tmplargs.cpp` -> tmplargs.dll (done). Build g++: `/c/ProgramData/mingw64/mingw64/bin/g++ -shared -O2 -o tmplargs_gcc.dll tmplargs.cpp` (done). Decompile each: `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN=$PWD/_qa/classtest/tmplargs.dll DS_PAIRS_DIR=/tmp/ta "$EXE"`. ASSERT after fix — MSVC: `grep -rl 'app::Box<int\*>' /tmp/ta` non-empty AND `grep -rho 'app__Box_int' /tmp/ta` present AND `grep -rl 'PEAH\|PEAD\|::\$04\|_04__' /tmp/ta` EMPTY (kills the fabricated namespaces). g++ (DS_REAL_BIN=tmplargs_gcc.dll): `grep -rho 'app__Box[A-Za-z0-9_]*__vftbl' /tmp/tag` and `grep -rho 'app__Fixed[A-Za-z0-9_]*__vftbl' /tmp/tag` non-empty (both are EMPTY today). Regression guard: re-run showcase.dll/tpltest.dll/classtest.dll and assert `game::Pool<int>`/`mytools::Box<int>`/`GameManager` names are byte-identical to pre-change.

### GATE_RISK
Gate-neutral by construction. RTTI-recovered names are NOT part of fast_gate (NullWare 1497/1497) or the corpus (629/1) per the RTTI map ("RTTI oracles are NOT in either gate"). The change alters only the CONTENT string of RTTI-seeded symbol names; it does NOT change which vtables/RVAs are detected or which functions are discovered, so GOTO/CLEAN counts and behavioral results are unaffected. It can only touch fast_gate if a corrected class name surfaces as a tag/comment inside a NullWare function's C — and the new names contain FEWER stray `$`/`?`/fabricated-identifier characters than today, so they are strictly safer to compile. To keep both green: (1) run `python _qa/harness.py 2>&1 | tee _qa/round_harness.log | grep -E "SUMMARY|FAIL"` (expect 629/1) and the full fast_gate (expect 1497/1497) after landing; (2) confirm showcase/tpltest/classtest/vcalltest RTTI names are unchanged (they have no pointer/non-type args, so they must be). DS_NO_TMPLARG gives an instant revert if anything moves.

### FIRES
Built oracle `_qa/classtest/tmplargs.cpp` (app::Box<int*>, Box<char*>, Fixed<5>, Wrap<app::Widget>, Widget). Compiled MSVC: `cmd //c` a bat that runs vcvars64 then `cl /nologo /LD /GR /O2 /GS- tmplargs.cpp` -> tmplargs.dll; g++: `/c/ProgramData/mingw64/mingw64/bin/g++ -shared -O2 -o tmplargs_gcc.dll tmplargs.cpp`. Mangled names present (verified via `strings`): `.?AV?$Box@PEAH@app@@`, `.?AV?$Box@PEAD@app@@`, `.?AV?$Fixed@$04@app@@`; Itanium `_ZTSN3app3BoxIPiEE`, `_ZTSN3app5FixedILi5EEE`. Decompiled with `EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN=.../tmplargs.dll DS_PAIRS_DIR=/tmp/ta "$EXE"`, then grep /tmp/ta/*.txt. MSVC output is WRONG (invents namespaces): Box<int*> -> `app::PEAH::Box__` / tag `app__PEAH____Box` (`__vftable`, `__vftbl_0`, `__vftbl_1` all so-named); Box<char*> -> `app::PEAD::Box__`; Fixed<5> -> `app::$04::Fixed__` / `app___04____Fixed`; 9 fn-files reference the fabricated PEAH/PEAD/$04 namespaces. g++ output DROPS them: only `app::Widget` recovers (`app__Widget__vftbl_0..2`); Box<int*>, Box<char*>, Fixed<5>, Wrap<Widget> get NO class name, NO vtable, NO virtual naming. Control: classtest.dll (GameManager), tpltest.dll (`mytools::Box<int>`->`mytools__Box_int_`), showcase.dll (`game::Entity`,`game::Pool<int>`) all demangle CORRECTLY today (no pointer/non-type args), so the change is scoped to the failing shapes.

