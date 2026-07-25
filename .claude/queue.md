# Work queue

The Stop hook refuses to let the session end while any `- [ ]` remains here.
Tick an item ONLY when it is committed and verified. Add new items to the end.

DO NOT write a status report between items. Finish one, tick it, start the next.
The user reads the commits; a summary is only wanted when the whole queue is empty.

- [x] SIG-3: rename params a1 -> arg1 (signature, body uses, derived names)
- [x] SIG-1 residual: void returns -- BLOCKED/measured. Both cases are exported LEAVES with zero
      xrefs, so caller-side evidence does not exist. Two callee-side rules tried and recorded in
      the code: the path-mix rule fires on nothing; tightening the xmm0 fallback costs RET
      677->664. Needs a genuinely new signal, not a tweak.
- [ ] SIG-1 residual: sret / Vector1-4 struct returns. HALF DONE.
      DONE: oracle _qa/fixtures/corpus/sretcall.cpp; caller-side signal recorded as
      FuncSig::sret_hint (lea rcx,[rsp/rbp+d]; call T) in build_sig_table's 2nd pass.
      MEASURED TOO LOOSE ALONE: marks 201/2590 kernel32 fns (passing &local is ordinary).
      NEXT, and it is specific: compute the callee-side conjunct 'returns its own arg0'
      (rax == incoming rcx at EVERY ret) in the main loop, require BOTH, then consume it
      (struct return type + drop the hidden param + `struct T __ret; T* a1 = &__ret;`).
      Nothing consumes sret_hint today, so output is unaffected until that lands.
- [ ] Vector function naming (vec2_/vec3_/vec4_ shapes -> named vector ops)
- [ ] GOTO-1 residual: 2879 reducible gotos (structurer re-emission efficiency)
- [ ] IDA-3: ARM64 lifting (BLOCKED: capstone AArch64 backend not vendored - user decision)
- [ ] UI-1: adopt the Hexstrand Workbench mockup as the real UI
      source: "C:\Users\User\Downloads\Hexstrand Workbench (1).zip" (Claude design mockup,
      knows nothing about our backend). Rewire EVERYTHING to real engine data and DELETE
      every mock/placeholder. Specifics from the user:
        * the mockup's frontend only has Functions / Imports / Strings panes. EXPORTS and
          MEMORY SEGMENTS are NOT dropped - they simply are not in the mockup and must be
          ADDED. Backend already answers get_exports and get_segments.
        * KEEP the stack-frame pane the mockup introduced -> wire to real frame recovery
        * add the graph, offsets, and the rest of the real views
        * the mockup's Problems counter must be wired to a real backend problem list
        * EVERY button must actually work - no dead controls
