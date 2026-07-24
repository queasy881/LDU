# DisasmStudio

A native reverse-engineering IDE: it parses a PE/ELF binary, disassembles it,
recovers functions, symbols and C++ class structure, and **decompiles x86-64 to
readable, compilable pseudo-C**.

Rust shell (`tao` + `wry` webview) over a C/C++ analysis engine, with an embedded
HTML/JS frontend. Nothing is read from disk at runtime — the whole UI is compiled
into the executable.

## Build

Requires the MSVC toolchain, CMake, and LLVM (bindgen needs `libclang.dll`).

```bash
compile.bat
```

That builds release + debug into `target/`. If `libclang.dll` is not at
`C:\Program Files\LLVM\bin`, edit `LIBCLANG_PATH` at the top of the script.

Or directly:

```bash
cargo build --release -p disasmstudio
```

## Run

```bash
target\release\disasmstudio.exe
```

Optionally pass a binary path to open it immediately:

```bash
target\release\disasmstudio.exe C:\path\to\target.dll
```

The launcher window manages projects (`.dsproj`); each opened binary gets its own
window, and analysis starts automatically.

## Layout

| Path | What |
|---|---|
| [`crates/shell`](crates/shell) | Multi-window host, IPC dispatch, analysis session driver, `.dsproj` model |
| [`crates/binary-parser`](crates/binary-parser) | PE/ELF parser — std-only, zero deps, fully bounds-checked |
| [`crates/bridge`](crates/bridge) | Safe Rust wrapper over the engine's C ABI (bindgen + CMake driver) |
| [`crates/flirt`](crates/flirt) | Library-function signature matching, from scratch |
| [`engine/include/disasm.h`](engine/include/disasm.h) | **The FFI contract** — plain C, the single source of truth |
| [`engine/src`](engine/src) | C core: lifecycle, instruction sweep, decoder |
| [`engine/analysis`](engine/analysis) | C++ passes: CFG, symbols, xrefs, RTTI, PDB, annotations, decompiler |
| [`frontend`](frontend) | Launcher / project / disasm pages (embedded via `include_str!`) |
| [`flirt/sigs`](flirt/sigs) | Prebuilt signature databases (`.fdb`) |
| [`docs`](docs) | Architecture notes and feature design specs |
| [`_qa`](_qa) | Quality harness: fixtures, gate scripts, metrics — see [`_qa/README.md`](_qa/README.md) |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit together.

## Tests

```bash
cargo test -p disasmstudio -- --nocapture
```

Tests that need a real binary read `DS_REAL_BIN`, falling back to a corpus DLL
(build one with `_qa/fixtures/corpus/compile_all.bat`). They skip with a clear
message rather than failing when neither is present.
