# Work queue

The Stop hook refuses to let the session end while any `- [ ]` remains here.
Tick an item ONLY when it is committed and verified. Add new items to the end.

DO NOT write a status report between items. Finish one, tick it, start the next.
The user reads the commits; a summary is only wanted when the whole queue is empty.

- [ ] SIG-3: rename params a1 -> arg1 (signature, body uses, derived names)
- [ ] SIG-1 residual: void returns forced by caller-side evidence (no caller reads the result)
- [ ] SIG-1 residual: sret / Vector1-4 struct returns via caller-side evidence
- [ ] Vector function naming (vec2_/vec3_/vec4_ shapes -> named vector ops)
- [ ] GOTO-1 residual: 2879 reducible gotos (structurer re-emission efficiency)
- [ ] IDA-3: ARM64 lifting (BLOCKED: capstone AArch64 backend not vendored - user decision)
