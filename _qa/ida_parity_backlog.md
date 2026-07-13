# IDA-Parity Backlog — fix EVERY item, no skips. Gate (corpus 616/0 + NullWare 1445/1445 + GOTO<=300) per batch.

Legend: [ ] todo  [~] in progress  [x] done+gated  risk=none|low|med|high

## BATCH A — pure render/fold peepholes (risk=none, in fold()/Binary/Cast render)
- [x] A1  `x + -K` -> `x - K`  (2236 sites)
- [ ] A2  `(char*)((char*)p+a)+b` -> `(char*)p + (a+b)` double-cast fold (930)
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
- [ ] D1  scalar temp declared 64-bit -> narrow width, kill `(int)tN` (6642)
- [ ] D2  single-use call-result temp -> inline into condition (443)
- [ ] D3  single-use call-result temp -> inline into assign/return/arg (420)
- [ ] D4  cast-only forwarding temp inlined (63)
- [ ] D5  bare register-move copy `t=v` coalesced (72)

## BATCH E — signatures/prototypes (risk=med)
- [ ] E1  K&R `fun_xxxx()` forward decls -> typed prototypes we know (1232)
- [ ] E2  API arity table: stop dropping 5th+ stack args (imports)
- [ ] E3  stale-register phantom trailing args on printf-style wrappers (167)
- [ ] E4  AL-only bool return typed char, drop `(x & -256)|1` mask (229)

## BATCH F — idioms / division (risk=low-med)
- [x] F1  signed div by 3/6 (magic 0x2aaaaaab/0x55555556, s==0) fold (28+)
- [x] F2  modulo-by-constant reconstruction `% N` (0 currently)
- [x] F3  unsigned magic div 0xcccccccd (/10) with cast-ride unsignedness
- [ ] F4  magic-division duplicated-subexpr cast temp cleanup (45)

## BATCH G — struct/field & pointer/array (risk=low-high)
- [x] G1  const byte-offset on typed pointer -> `p[n]` (616)
- [ ] G2  one variable-indexed access disqualifies whole param struct (22 fns)
- [ ] G3  pad-hole / `&field+delta` offsets render raw amid fields (372)
- [ ] G4  pointer-valued qword fields typed as pointers (376)  [high risk - was reverted before]
- [ ] G5  missed `p[i]` on typed/global pointer bases (102)

## BATCH H — naming (risk=none/low)
- [x] H1  final display-only per-function renumber (v1..) unify v#/t#/s# (250 files)
- [ ] H2  struct tags embed raw temp id -> use renumbered/stable id (376 files)
- [ ] H3  API/type-derived local name stems (pervasive)
- [ ] H4  char-literal rendering for printable-ASCII compares (minor)

## BATCH I — control-flow (risk=low-med)
- [ ] I1  boolean flag cascades -> `&&`/`||` short-circuit chains (pervasive)
- [ ] I2  state-machine explosion (11 fns, up to 761 arms) -> labeled gotos

## BATCH J — globals/strings/api (auditor ERRORED — re-survey then fix)
- [ ] J0  re-run globals-strings-api auditor
- [ ] J*  (fill from J0: string literals inline, named globals, IAT api names)
