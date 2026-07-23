### FEATURE
MSVC C++ exception catch types via __CxxFrameHandler4 (FH4) compressed FuncInfo. The engine already parses v3 (__CxxFrameHandler3) FuncInfo to recover catch(<Type>&), but modern MSVC (/O2 default, VS 2026 on this box) emits __CxxFrameHandler4 whose FuncInfo has NO 4-byte magic and a variable-length-int compressed layout the current code explicitly skips ("v4 ... intentionally left for a later pass"). Add an FH4 decoder that walks the compressed FuncInfo -> TryBlockMap4 -> HandlerMap4, reads each HandlerType4.dispType (the caught TypeDescriptor RVA), and populates the SAME EHInfo.cpp/CppTry/CppCatch structures the existing v3 path and eh_annotation() renderer already use.

### TRACTABILITY
medium

### CURRENT_HANDLING
engine/analysis/decompiler.cpp:567-604 — compute_pe_tables() parses ONLY v3 FuncInfo: `if (pe_rd_u32(e,fi,magic) && (magic==0x19930520|21|22))`. On any FH4 FuncInfo the magic test fails and info.cpp stays empty, so no catch is recorded. Renderer engine/analysis/decompiler.cpp:5841-5867 eh_annotation() emits `/* C++ EH: try{...} catch(<type> @<rva>) */` from info.cpp but gets nothing for FH4 functions. Net: for guarded the entire try/catch and all three catch types are silently dropped (opaque output above).

### GAP
Every user try/catch compiled by modern MSVC (2019+; VS 2026 here, /O2 default = __CxxFrameHandler4) loses its catch types. The FH4 compressed FuncInfo (1-byte header + variable-length-int maps, no magic) is never decoded, so `catch (NetworkError&)`, `catch (MyError&)`, `catch (...)` are all invisible in the output despite the metadata being fully present and recoverable in .xdata.

### INSERTION_POINTS
[
 {
  "file": "engine/analysis/decompiler.cpp",
  "anchor": "after pe_rd_u32 (~line 476), alongside pe_rd_u8/u16/u32",
  "change": "Add static bool pe_rd_fh4uint(const ds_engine* e, uint64_t& rva, uint32_t& out): MSVC FH4 variable-length uint. Read 1 byte b; ((b&1)==0)->1 byte val=b>>1; ((b&2)==0)->u16>>2 (+2); ((b&4)==0)->3 bytes>>3 (+3); ((b&8)==0)->u32>>4 (+4); else return false (5-byte forms unneeded for catch metadata). Advances rva; every read bounds-checked."
 },
 {
  "file": "engine/analysis/decompiler.cpp",
  "anchor": "line 604, immediately after the v3 `if (info.seh.empty()){...}` block closes, still inside the `for (const auto& rf : t->pdata)` loop",
  "change": "Add FH4 branch (C): guarded by `if (info.seh.empty() && info.cpp.empty() && !std::getenv(\"DS_NO_EH4\"))`. fi=*(u32)data; require ds_rva_is_mapped(e,fi)&&!ds_rva_is_exec(e,fi). Read header byte, require !(hdr&0x80). Skip optional bbtFlags(hdr&0x04, fh4uint), dispUnwindMap(hdr&0x08, u32), read dispTryBlockMap(hdr&0x10, u32) + dispIPtoStateMap(u32). If TryBlockMap present+mapped: walk TryBlockMap4 (fh4uint count 1..64; per entry fh4uint tryLow/tryHigh/catchHigh + u32 dispHandlerArray); walk HandlerMap4 (fh4uint nCatch <=32; per Handler4 read header H then in order: if H&0x01 adj(fh4uint), if H&0x02 dispType(u32 RVA), if H&0x04 dispCatchObj(fh4uint), dispHandler(u32 always), if H&0x08 dispFrame(fh4uint), if H&0x10 cont0(fh4uint), if H&0x20 cont1(fh4uint)). dispType==0 -> catch(...); else require ds_rva_is_mapped(e,dispType), read name at dispType+16, REQUIRE nm starts \".?A\" (else bail), cc.type=pe_demangle_type(nm), cc.by_ref=(adj&0x08). All-or-nothing: on any inconsistency clear info.cpp so no partial/garbage table is ever emitted. Populate info.cpp (same struct the renderer already consumes)."
 },
 {
  "file": "engine/analysis/decompiler.cpp",
  "anchor": "line 434, struct CppCatch { std::string type; uint32_t handler = 0; };",
  "change": "(optional) add `bool by_ref = false;` so the annotation can print `catch (NetworkError &)` \u2014 the reference qualifier is available from FH4 adjectives bit 0x08 (v3 path leaves it default false)."
 },
 {
  "file": "engine/analysis/decompiler.cpp",
  "anchor": "line 5862 in eh_annotation(), the `c.type.empty()? \"...\" : c.type` render",
  "change": "(optional) append \" &\" when c.by_ref, i.e. `(c.type.empty()? std::string(\"...\") : c.type + (c.by_ref?\" &\":\"\"))`, so the comment reads `catch( NetworkError & @0x101b0 )`."
 }
]

### CODE_SKETCH
// (1) helper near pe_rd_u32
static bool pe_rd_fh4uint(const ds_engine* e, uint64_t& rva, uint32_t& out){
    uint8_t b; if(!pe_rd_u8(e,rva,b)) return false;
    if((b&1)==0){out=b>>1; rva+=1;}
    else if((b&2)==0){uint16_t w; if(!pe_rd_u16(e,rva,w))return false; out=w>>2; rva+=2;}
    else if((b&4)==0){uint32_t w=0; for(int i=0;i<3;i++){uint8_t x;if(!pe_rd_u8(e,rva+i,x))return false;w|=(uint32_t)x<<(8*i);} out=w>>3; rva+=3;}
    else if((b&8)==0){uint32_t w; if(!pe_rd_u32(e,rva,w))return false; out=w>>4; rva+=4;}
    else return false; return true;
}
// (2) after the v3 block (decompiler.cpp:604), inside the pdata loop:
if(info.seh.empty() && info.cpp.empty() && !std::getenv("DS_NO_EH4")){
    uint32_t fi;
    if(pe_rd_u32(e,data,fi) && fi && ds_rva_is_mapped(e,fi) && !ds_rva_is_exec(e,fi)){
        uint8_t hdr;
        if(pe_rd_u8(e,fi,hdr) && !(hdr&0x80)){
            uint64_t p=fi+1; uint32_t t; bool ok=true;
            if(hdr&0x04){ if(!pe_rd_fh4uint(e,p,t)) ok=false; }          // bbtFlags
            if(ok&&(hdr&0x08)){ p+=4; }                                  // dispUnwindMap
            uint32_t dispTry=0,dispIP=0;
            if(ok&&(hdr&0x10)){ if(!pe_rd_u32(e,p,dispTry)) ok=false; p+=4; }
            if(ok){ if(!pe_rd_u32(e,p,dispIP)) ok=false; p+=4; }
            if(ok && dispTry && ds_rva_is_mapped(e,dispTry)){
                uint64_t tp=dispTry; uint32_t nTry=0;
                if(pe_rd_fh4uint(e,tp,nTry) && nTry>=1 && nTry<=64){
                    for(uint32_t ti=0; ti<nTry && ok; ++ti){
                        uint32_t tl,th,ch,dha;
                        if(!pe_rd_fh4uint(e,tp,tl)||!pe_rd_fh4uint(e,tp,th)||
                           !pe_rd_fh4uint(e,tp,ch)||!pe_rd_u32(e,tp,dha)){ok=false;break;} tp+=4;
                        if(!ds_rva_is_mapped(e,dha)){ok=false;break;}
                        CppTry ct; ct.low=(int)tl; ct.high=(int)th;
                        uint64_t hp=dha; uint32_t nC=0;
                        if(!pe_rd_fh4uint(e,hp,nC)||nC>32){ok=false;break;}
                        for(uint32_t ci=0; ci<nC && ok; ++ci){
                            uint8_t H; if(!pe_rd_u8(e,hp,H)){ok=false;break;} hp+=1;
                            uint32_t adj=0,dispType=0,dc=0,dh=0,tmp;
                            if((H&0x01)&&!pe_rd_fh4uint(e,hp,adj)){ok=false;break;}
                            if(H&0x02){ if(!pe_rd_u32(e,hp,dispType)){ok=false;break;} hp+=4; }
                            if((H&0x04)&&!pe_rd_fh4uint(e,hp,dc)){ok=false;break;}
                            if(!pe_rd_u32(e,hp,dh)){ok=false;break;} hp+=4;   // dispOfHandler
                            if((H&0x08)&&!pe_rd_fh4uint(e,hp,tmp)){ok=false;break;} // dispFrame
                            if((H&0x10)&&!pe_rd_fh4uint(e,hp,tmp)){ok=false;break;} // cont0
                            if((H&0x20)&&!pe_rd_fh4uint(e,hp,tmp)){ok=false;break;} // cont1
                            CppCatch cc; cc.handler=dh;
                            if(dispType){
                                if(!ds_rva_is_mapped(e,dispType)){ok=false;break;}
                                std::string nm;
                                for(int j=0;j<512;++j){uint8_t x; if(!pe_rd_u8(e,(uint64_t)dispType+16+j,x)||!x)break; nm+=(char)x;}
                                if(nm.rfind(".?A",0)!=0){ok=false;break;}    // strong validator
                                cc.type=pe_demangle_type(nm); cc.by_ref=(adj&0x08)!=0;
                            }
                            ct.catches.push_back(std::move(cc));
                        }
                        if(ok) info.cpp.push_back(std::move(ct));
                    }
                    if(!ok) info.cpp.clear();   // never emit a partial/garbage table
                }
            }
        }
    }
}
// Result for guarded: /* C++ EH: try { ... } catch( NetworkError & @0x101b0 ) catch( MyError & @0x101e0 ) catch( ... @0x10210 ) */

### SOUNDNESS
Sound because the FH4 branch (a) runs ONLY after the v3 magic test fails, so v3 recovery is untouched; (b) every read goes through pe_rd_* which bounds-checks against image_size; (c) fi must be a mapped, non-exec (data-section) RVA and the header reserved bit (0x80) must be clear before any decode; (d) counts are hard-capped (nTry<=64, nCatch<=32) so a mis-decode can't loop or blow memory; (e) the decisive validator: a non-null dispType MUST point to a TypeDescriptor whose name begins ".?A" — random/misaligned data essentially never satisfies this, so __GSHandlerCheck (whose data is a small cookie offset, not a FuncInfo) and any non-EH bytes bail; (f) all-or-nothing — any single inconsistency clears info.cpp, so the engine emits either the correct full table or nothing, never a wrong catch type. Output is a comment only, so it cannot change emitted C semantics. Env gate: DS_NO_EH4.

### ORACLE
Oracle source already written: _qa/classtest/ehtest.cpp (struct MyError{int code; virtual int what();}; struct NetworkError:MyError{int sock; int fd();}; __declspec(noinline) static void may_throw(){throw NetworkError(...);} extern "C" __declspec(dllexport) int guarded(int,int){ try{may_throw();} catch(NetworkError& e){...} catch(MyError& e){...} catch(...){...} }). Compile (MSVC 18/VS2026 shim): call "C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat" then `cl /nologo /LD /EHsc /GR /O2 /GS- ehtest.cpp`. Decompile: DS_REAL_BIN=.../ehtest.dll DS_PAIRS_DIR=/tmp/eh2 dump_pairs. ASSERT-BEFORE: `grep -c "C++ EH" /tmp/eh2/fn_000010b0.txt` == 0 (opaque guarded). ASSERT-AFTER (fix in): fn_000010b0.txt contains a line matching `C\+\+ EH:.*catch\( NetworkError` AND `catch\( MyError` AND `catch\( \.\.\.`. Independent ground truth: `python _qa/classtest/fh4probe.py ehtest.dll 0x19230` prints catch[0]=NetworkError catch[1]=MyError catch[2]=catch(...), so the decompiler output must match those three types in order. Also re-run on ehtest_gs.dll (default /GS) to confirm the same annotation.

### GATE_RISK
Low. fast_gate (1497/1497 NullWare, cl /TC /w) and corpus (629 behavioral) are both blind to comments, and the FH4 output is a comment-only block gated by DS_NO_EHANNOT (render) + DS_NO_EH4 (parse). The branch runs only when the v3 magic is absent, so no v3-annotated function changes. Only conceivable regression is a false-positive FH4 decode adding a bogus comment to a non-EH NullWare function — neutralized by the ".?A"-TypeDescriptor validator + mapped/non-exec fi gate + all-or-nothing bail. Keep both green by: (1) after landing, diff the full corpus/NullWare emitted C with vs without the change and confirm ONLY added `/* C++ EH: ... */` comment lines differ (no code lines change); run `python _qa/harness.py 2>&1 | tee _qa/round_harness.log | grep -E "SUMMARY|FAIL"` and the fast_gate; (2) keep DS_NO_EH4 so any surprise is one-env-var bisectable; (3) the ehtest.dll/ehtest_gs.dll oracle is the feature's own proof (not in either gate, so it's gate-neutral there).

### FIRES
Built a purpose oracle _qa/classtest/ehtest.cpp: guarded() has try/catch(NetworkError&)/catch(MyError&)/catch(...), throwing via a noinline C++-linkage helper so /O2 can't delete the EH (the extern-C-nothrow C4297 trap was hit on the first build and killed the catch machinery — fixed). Compile: cl /LD /EHsc /GR /O2 /GS- ehtest.cpp (and default /GS -> ehtest_gs.dll; both identical for this fn). CURRENT (opaque) output: EXE=$(ls -t target/release/deps/dump_pairs-*.exe|head -1); DS_REAL_BIN="$PWD/_qa/classtest/ehtest.dll" DS_PAIRS_DIR=/tmp/eh2 "$EXE" -> /tmp/eh2/fn_000010b0.txt (guarded) is `int32_t guarded(int64_t a1,int64_t a2){int32_t result=0; fun_00001070(a1,a2); return result;}` with NO try/catch and NO catch types. `grep -rl "C++ EH" /tmp/eh2 | wc -l` = 0 across all 388 functions (the v3 path never fires here: the statically-linked v3 CRT funcs all have nTryBlocks=0, and every USER catch is FH4). guarded's pdata entry 0x10b0..0x10c5 uses handler 0x2b40 with FuncInfo@rva 0x19230 whose first bytes are 38 3d 92 01 (header 0x38, NOT 0x1993052x). FIX-FIRES proof (fh4probe.py): FuncInfo@0x19230 decodes to nTryBlocks=1, dispHandlerArray@0x19248, nCatches=3 -> catch[0] dispType=0x1ba60=".?AUNetworkError@@" adj=8(by-ref) funclet 0x101b0; catch[1] dispType=0x1ba88=".?AUMyError@@" adj=8 funclet 0x101e0; catch[2] dispType=0 adj=64(ellipsis)=catch(...) funclet 0x10210. The two dispType RVAs equal the TypeDescriptor RVAs of the ".?AUNetworkError@@"/".?AUMyError@@" strings (name at TD+0x10), and the handler cursor lands exactly at the array boundary — a fully validated decode. Oracles + both probe scripts saved under _qa/classtest/.

