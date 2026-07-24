# Architecture

## Layers

```
frontend/            HTML + JS, embedded in the exe, talks JSON over wry IPC
   │
crates/shell/        windows, IPC dispatch, Session (analysis driver)
   │
crates/bridge/       safe Rust wrapper  ──bindgen──▶  engine/include/disasm.h
   │
engine/src/          C core:   sweep, decoder, engine lifecycle
engine/analysis/     C++:      cfg, symbols, xrefs, rtti, pdb, decompiler
```

`crates/binary-parser` sits beside the shell: it turns a file on disk into a flat
RVA-addressed image plus segment/import/export tables, which the shell feeds to
the engine. `crates/flirt` names statically-linked library code from signature
databases.

## The FFI boundary

[`engine/include/disasm.h`](../engine/include/disasm.h) is the single source of
truth. Its rules:

- Plain C, fixed-width types, `extern "C"`. No C++ type crosses the boundary.
- The engine **never owns the image memory** — the Rust side keeps the `Vec<u8>`
  alive for the whole engine lifetime.
- No function may abort or throw across the boundary; errors are `int` codes.

`crates/bridge/build.rs` drives CMake to build the engine as a static lib and
runs bindgen over the header.

## Analysis pipeline

Four stages, in order (`ds_engine_analyze`):

1. **Sweep** — [`engine/src/sweep.c`](../engine/src/sweep.c)
   Linear sweep over executable segments, plus recursive descent from every
   seed (entry point, exports, TLS callbacks, discovered call targets). On x64,
   `.pdata` `RUNTIME_FUNCTION.BeginAddress` entries are authoritative function
   starts — chained (`UNW_FLAG_CHAININFO`) entries are fragments and are skipped.

2. **CFG** — [`engine/analysis/cfg.cpp`](../engine/analysis/cfg.cpp)
   Function starts = seeds ∪ call targets ∪ prologue detection. Prologue hits
   only count at a real boundary (previous instruction is `ret`/`jmp`/`int3`/
   `ud2`/`hlt`, or non-contiguous), otherwise a mid-prologue frame setup splits a
   function in half. Register-indirect `jmp` dispatches are resolved by reading
   the actual `.rdata` jump table, giving a precise extent instead of guessing.

3. **Symbols** — [`engine/analysis/symbols.cpp`](../engine/analysis/symbols.cpp)
   Priority chain, first hit wins: PDB/export seed → entry point → import thunk
   (`j_<import>`) → built-in signature → `fun_<rva>`. Then two upgrade passes
   that only ever replace the `fun_` fallback, both uniqueness-guarded so they
   can never introduce a duplicate C symbol.

4. **Xrefs** — [`engine/analysis/xref.cpp`](../engine/analysis/xref.cpp)
   Dedupe edges, re-derive per-function call counts.

Naming passes that need the full function list run between stages 2 and 3:
`load_pdb` → `scan_rtti` → `scan_ctor_dtor` → `scan_format_fns` →
`scan_string_names`.

## The decompiler

[`engine/analysis/decompiler.cpp`](../engine/analysis/decompiler.cpp) plus twenty
`#include`d sections under [`decomp/`](../engine/analysis/decomp) that together
form one `Decompiler` class body. The split is a pure text partition — the
preprocessor reassembles an identical translation unit — done because the class
is ~14k lines.

Pipeline:

1. **Disassemble** — capstone over `[rva, rva+size)` with detail on.
2. **CFG** — leaders → blocks → succ/pred, plus jump-table recovery.
3. **Symbolic execution** — per-block forward execution over `reg → Expr` and
   `stackslot → Expr`. Register writes only update the map; a statement is
   emitted only on a write to a recovered variable, a call, or a return. This is
   what folds `mov eax,[a]; add eax,[b]; mov [c],eax` into `c = a + b;` with no
   register anywhere in the output.
4. **Phi / temps** — registers live across a join with differing values get a
   materialized temp, minimized by liveness.
5. **Dominators** — Cooper-Harvey-Kennedy, plus post-dominators and natural-loop
   detection.
6. **Structuring** — if/else, while, do-while, for, switch.
7. **Emit** — C precedence with minimal parens/casts, recovered typed locals.

**Correctness over prettiness.** Widths, comparison signedness, branch directions
and access sizes are preserved exactly. When a structuring transform cannot be
proven correct, a `goto` is emitted for that region only — never wrong structure,
never a raw register name. `cfg_is_reducible()` (Hecht-Ullman T1-T2 interval
reduction) is ground truth for whether a residual `goto` is inherent to the CFG
or a structurer limitation.

## Concurrency

`bridge::Engine` is `Send + Sync`. `ds_decompile(e, rva)` builds a *fresh*
`Decompiler` per call, reads a const engine, and shares only mutex-guarded
per-engine caches (signature table, PE tables, demangle map), so many threads may
hold `&Engine` and decompile at once. Only `&self` methods are safe concurrently;
the `&mut self` builders are excluded by the borrow checker.

The shell exploits this in `session.rs`: after analysis, every function is
decompiled eagerly across worker threads so opening one in the UI is instant.

Two caches matter for load time:

- **Per-engine signature table.** `build_sig_table` scans every function, so
  calling it per-decompile made a whole-DLL dump quadratic. It is a pure function
  of the (unchanging) function set, so it is computed once per engine.
- **On-disk decompilation cache**, invalidated by the binary's size+mtime *and*
  the app executable's mtime, so output from an older engine is never replayed.

## User annotations

Renames and comments are keyed by a hash of the function's **masked instruction
stream**, not its RVA — call displacements and RIP-relative references are masked
out, so an annotation survives a rebuild that moves code. An ambiguous hash
(two identical thunks) deliberately declines rather than renaming an arbitrary
one. See [`annotations.cpp`](../engine/analysis/annotations.cpp).

## Feature specs

[`docs/features/`](features) holds the design docs behind the RTTI/C++ recovery
work — each states the gap, the current handling, and the exact insertion points.
