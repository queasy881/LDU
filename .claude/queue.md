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
- [ ] SIG-1 residual: sret / Vector1-4 struct returns. ORACLE NOW EXISTS:
      _qa/fixtures/corpus/sretcall.cpp (makers are static + called by exported wrappers, so the
      xrefs the rest of the corpus lacks are present; also plants an 8-byte Vec2 returned in RAX
      and copy_bytes, a real writes-through-arg0-and-returns-it function a naive detector breaks).
      DECISIVE PATTERN, seen in our own output for sum3: caller passes &<its own local> as arg0,
      then bulk-copies N bytes FROM the returned pointer. Belongs in build_sig_table (cross-fn).
      BONUS BUG pinned by the same fixture: sum3 recovers as int32_t returning (int32_t)(s1+0x10)
      instead of a float sum.
- [ ] Vector function naming (vec2_/vec3_/vec4_ shapes -> named vector ops)
- [ ] GOTO-1 residual: 2879 reducible gotos (structurer re-emission efficiency)
- [ ] IDA-3: ARM64 lifting (BLOCKED: capstone AArch64 backend not vendored - user decision)
- [ ] UI-1: adopt the Hexstrand Workbench mockup as the real UI
      source: "C:\Users\User\Downloads\Hexstrand Workbench (1).zip" (Claude design mockup,
      knows nothing about our backend). Rewire EVERYTHING to real engine data and DELETE
      every mock/placeholder. Specifics from the user:
        * Functions / Imports / Strings panes are real; there are NO exports (drop that idea)
        * KEEP the stack-frame pane the mockup introduced -> wire to real frame recovery
        * add the graph, offsets, and the rest of the real views
        * the mockup's Problems counter must be wired to a real backend problem list
        * EVERY button must actually work - no dead controls
