/*
 * decompiler.h — pseudo-C decompiler for the DisasmStudio engine.
 *
 * Lifts a recovered function (ds_func) into compilable, behaviorally-equivalent
 * pseudo-C by disassembling it with capstone, building a CFG, lifting each
 * instruction to a small expression/statement IR, forward-substituting register
 * temporaries, structuring control flow (if/else, while, do-while, for) and
 * falling back to label+goto for anything that does not structure cleanly.
 *
 * This declares only the flat C ABI; all C++ lives inside decompiler.cpp.
 */
#ifndef DS_DECOMPILER_H
#define DS_DECOMPILER_H

#include "disasm.h"   /* ds_engine, ds_func, ds_insn, fixed-width types */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decompile the function whose entry RVA is `func_rva`.
 *
 * Returns a malloc'd, NUL-terminated C string containing the pseudo-C source of
 * that one function, or NULL when `func_rva` is not a known function start (or on
 * allocation failure). The caller owns the string and must release it with
 * ds_free_string. This function never throws or aborts across the boundary; on
 * internal trouble it returns a best-effort string (possibly a stub function with
 * a plausible signature and a "decompilation failed" body).
 */
char* ds_decompile(ds_engine* e, uint64_t func_rva);

/* Free a string returned by ds_decompile. Safe to call with NULL. */
void ds_free_string(char* s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DS_DECOMPILER_H */
