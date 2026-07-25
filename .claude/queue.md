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
      source zip is a .dc.html DESIGN-CANVAS file (<sc-for>/{{ }} bindings + support.js),
      NOT plain HTML - the design must be reimplemented against the real frontend.
      DONE (5ada37b, 78c66a8):
        * backend get_problems + get_stack_frame / ds_decompile_frame (the frame comes from
          the SAME decompiler run as the pseudocode, so the panes cannot disagree)
        * mock host in frontend/js/ipc.js DELETED (139 -> 65 lines); off-host now rejects
        * Stack frame inspector tab + Problems panel and activity-rail badge, both wired
        * both on the script surface (`frame`, `problems`) so they verify headlessly
          (kernel32: 12 real unresolved-indirect problems)
      ALSO DONE (ea53d75, this commit): action strip (Reanalyze/Xrefs/Strings/Problems/
        Sync views) all wired; `reanalyze` IPC clears the decomp cache + cancels the
        in-flight run; Sync views scrolls the pseudocode by data-addrs lookup.
        Audited: 17 buttons, 0 dead.
      REMAINING - mostly cosmetic now:
        * apply the mockup's VISUAL design: menu bar, toolbar (Reanalyze/Xrefs/Strings/
          Problems/Sync views/Script), left nav tab strip, main tab strip (IDA View-A /
          Hex View-1 / Call tree), right side tabs, bottom console (Output/Problems/Python),
          segment dropdown, EA box
        * Script button (needs a GUI script console; --script is headless-only)
        * call-tree view does not exist yet (derivable from xrefs)
        * exports + memory segments ALREADY exist in the real frontend and stay; they are
          only absent from the mockup. get_exports/get_segments already answer.
