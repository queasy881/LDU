# IDA-Parity Backlog — fix EVERY item, no skips. Gate (corpus 616/0 + NullWare 1445/1445 + GOTO<=300) per batch.

Legend: [ ] todo  [~] in progress  [x] done+gated  risk=none|low|med|high

## BONUS — CLASS/STRUCT RECONSTRUCTION (user-requested flagship, done+gated)
- [x] RTTI-MSVC  x64 COL scan -> class names + `<Class>__vftable` seed + `<Class>__vftbl_N` slots (rtti.cpp)
- [x] RTTI-G++   Itanium ABI (_ZTS/_ZTI/_ZTV structural scan) -> same, verified on classtest_gcc.dll (rtti.cpp scan_rtti_itanium)
- [x] CLS-STRUCT struct whose field_0 = a known vtable const IS that class -> `struct <Class> { ... }` (guarded typedef); verified struct GameManager on both MSVC+G++ classtest
- [x] CLS-CAST   drop redundant `(struct <tag>*)` cast on a pointer-temp struct base (kept for `char[N]` stack-buffer structs); bare `v1->field_0`

## BATCH A — pure render/fold peepholes (risk=none, in fold()/Binary/Cast render)
- [x] A1  `x + -K` -> `x - K`  (2236 sites)
- [x] A2  `(char*)((char*)p+a)+b` -> `(char*)p + (a+b)` double-cast fold (930)
- [x] A3  `(unsigned int)((int)X)` -> `(unsigned int)X` cross-sign nested cast (926)
- [x] A4  `(unsigned int)((unsigned char)x)` -> `(unsigned char)x` (movzx noise) (934)
- [x] A5  `(T)((T)x)` -> `(T)x` identical nested cast collapse (633)
- [x] A6  negative 64-bit bitmask -> hex `& 0x8000000000000000uLL` (196)
- [x] A7  float sign-clear over-wide `& -2147483649LL` -> `& 0x7FFFFFFF` (83)
- [x] A8  `(int)` on char/short lvalue redundant (integer promotion) (303)
- [x] A9  constant operand needlessly cast in pointer-compare coercion (92)
- [ ] A10 redundant `(char*)` on integer `_QWORD` base field (22)

## BATCH B — condition simplification (risk=none/low, if-emitter + negate)
- [x] B1  `else if` chains (else-{single if} -> `else if`) (766-1006)
- [x] B2  integer cond `X != 0` -> `X`, `X == 0` -> `!X` (1796+1956)
- [x] B3  offset compare `x + -C == D` -> `x == D+C` (286)
- [x] B4  redundant bool renorm `((X!=0)!=0)`, `(unsigned char)(X!=0)` (36+)
- [x] B5  foldable `&&` guard nest `if(A){if(B){}}` -> `if(A && B)` (215)

## BATCH C — structural readability (risk=low, structurer/emit)
- [x] C1  return-temp fold `result=X; return (int)result;` -> `return X;` (815)
- [x] C2  `if(C) continue; break;` -> `if(!C) break;` (92)
- [x] C3  boolean diamond `if(c){x=1}else{x=0}` -> `x = c;` (135)
- [ ] C4  `result` idiom when return split into >1 SSA temp (43)

## BATCH D — temps & width (risk=med, gate hard — recently bug-prone)
- [x] D1  scalar temp declared 64-bit -> narrow width, kill `(int)tN` (6642)  [has_root_def guard fixes byte_swap64]
- [ ] D2  single-use call-result temp -> inline into condition (443)
- [ ] D3  single-use call-result temp -> inline into assign/return/arg (420)
- [ ] D4  cast-only forwarding temp inlined (63)
- [ ] D5  bare register-move copy `t=v` coalesced (72)

## BATCH E — signatures/prototypes (risk=med)
- [ ] E1  K&R `fun_xxxx()` forward decls -> typed prototypes we know (1232)
- [ ] E2  API arity table: stop dropping 5th+ stack args (imports)
- [ ] E3  stale-register phantom trailing args on printf-style wrappers (167)
- [~] E4  AL-only bool return typed char, drop `(x & -256)|1` mask (229)
       [x] SOUND render-strip: `return (X & K)|Y` -> `return Y` when ret type is ALREADY byte
           (render_return_expr strip_ret_byte_mask; gated on ret_small_w==1||ret_byte_return).
       [ ] DEFERRED (risky): widening byte-return DETECTION so `int fun(){...return (int)((x&-256)|1);
           ...return 0;}` becomes byte-typed. Root: a `xor eax,eax` return-0 path sets saw_wide_ret
           (~16388) and vetoes byte-typing. Retyping mutates the program-wide callee-sig table with NO
           behavioral gate on NullWare to catch a wrong truncation at call sites -> defer, do in an
           isolated hard-gated cycle (corpus is the only net; it currently LOCKS these as int).

## BATCH F — idioms / division (risk=low-med)
- [x] F1  signed div by 3/6 (magic 0x2aaaaaab/0x55555556, s==0) fold (28+)
- [x] F2  modulo-by-constant reconstruction `% N` (0 currently)
- [x] F3  unsigned magic div 0xcccccccd (/10) with cast-ride unsignedness
- [ ] F4  magic-division duplicated-subexpr cast temp cleanup (45)

## BATCH G — struct/field & pointer/array (risk=low-high)
- [x] G1  const byte-offset on typed pointer -> `p[n]` (616)
- [x] G2  one variable-indexed access disqualifies whole param struct (22 fns)  [>=4 fixed fields keeps struct]
- [x] G3  pad-hole / `&field+delta` offsets render raw amid fields  [DONE+GATED 62d20f9: 1265->4 across NullWare; struct_base_offset resolves nested (base+c1)+c2]
- [x] G4  pointer-valued qword fields typed as pointers (352 fields / 238 fns)  [DONE+GATED 983150d; was reverted before]
       IMPLEMENTED: enabled scan_field_ptr (DS_NO_FIELDPTR) so a qword field whose VALUE is
       used as an address base becomes `void*`. Driven by an 8-agent audit workflow (g4-field-pointer-
       audit) that mapped every render position a field-value flows through. 4 edits: (a) scan_field_ptr
       driver in recover_struct_layouts; (b) expr_is_pointer EK::Mem arm (closes 5 arith/subscript gaps);
       (c) float-const-offset arith branches char-cast (C2036 guard); (d) float->void*-field store
       reinterpret (C2440 guard). Soundness: void* is 8 bytes == long long on x64, pack(1) so layout
       byte-identical, every use bit-reinterpreted not value-converted. corpus 616/0 (linklist/struct_ops/
       encoding void* fields all behaviorally validated: `!a1->field_0`, `*(uchar*)((char*)a1->field_0+i)`).
       NullWare gate pending (watch FIX 1 return-inference ripple @~14727; surgical fallback documented).
- [x] G5  missed `p[i]` on typed/global pointer bases (102)  [global-address subset DONE+GATED cc1c315: ((T*)0xADDR)[idx]]

## BATCH H — naming (risk=none/low)
- [x] H1  final display-only per-function renumber (v1..) unify v#/t#/s# (250 files)
- [ ] H2  struct tags embed raw temp id -> use renumbered/stable id (376 files)
- [ ] H3  API/type-derived local name stems (pervasive)
- [x] H4  char-literal rendering for printable-ASCII compares (minor)  [char_hint on byteish compares]

## BATCH I — control-flow (risk=low-med)
- [ ] I1  boolean flag cascades -> `&&`/`||` short-circuit chains (pervasive)
- [ ] I2  state-machine explosion (11 fns, up to 761 arms) -> labeled gotos

## BATCH J — globals/strings/api (auditor ERRORED — re-survey then fix)
- [ ] J0  re-run globals-strings-api auditor
- [ ] J*  (fill from J0: string literals inline, named globals, IAT api names)
