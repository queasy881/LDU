#!/bin/bash
# env.sh — shared preamble for every _qa script. Source it, never run it:
#
#     . "$(dirname "$0")/env.sh"
#
# Resolves the repo root from THIS FILE's own location, so a script works from
# any working directory and in any git worktree. Previously each script did
# `cd /c/Users/User/Downloads/sd` and exported a hardcoded LIBCLANG_PATH, which
# meant none of them ran on any machine but the original author's.
#
# Everything below is overridable from the environment: set the variable before
# calling and this file leaves it alone.

# ---- repo root -------------------------------------------------------------
# env.sh lives at <root>/_qa/scripts/env.sh, so the root is two levels up.
QA_SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$QA_SCRIPTS/../.." && pwd)"
QA="$ROOT/_qa"
FIXTURES="$QA/fixtures"
CORPUS="$FIXTURES/corpus"
# All generated output goes under _qa/out (gitignored) — never next to sources.
OUT="${DS_QA_OUT:-$QA/out}"
PAIRS="${DS_PAIRS_DIR:-$OUT/pairs}"
export ROOT QA FIXTURES CORPUS OUT PAIRS
mkdir -p "$OUT"
cd "$ROOT" || { echo "[env] cannot cd to repo root $ROOT" >&2; exit 1; }

# ---- toolchain -------------------------------------------------------------
# cargo: honour an existing install, else the standard rustup location.
[ -x "$(command -v cargo)" ] || export PATH="$HOME/.cargo/bin:$PATH"

# libclang, needed by bindgen in crates/bridge/build.rs. Probe the usual homes
# instead of hardcoding one; first hit wins. Override with LIBCLANG_PATH.
if [ -z "$LIBCLANG_PATH" ]; then
  for c in \
    "/c/Program Files/LLVM/bin" \
    "$LOCALAPPDATA/disasmstudio-tools/LLVM/bin" \
    "/c/Users/$USERNAME/AppData/Local/disasmstudio-tools/LLVM/bin" \
    "/c/Program Files (x86)/LLVM/bin"
  do
    if [ -f "$c/libclang.dll" ]; then export LIBCLANG_PATH="$c"; break; fi
  done
fi
[ -n "$LIBCLANG_PATH" ] || echo "[env] warning: libclang not found; set LIBCLANG_PATH" >&2

# NASM is only needed if the engine ever ships .asm sources (see CMakeLists).
for c in "/c/Program Files/NASM" "$LOCALAPPDATA/disasmstudio-tools/nasm"; do
  [ -d "$c" ] && export PATH="$c:$PATH"
done

# ---- the binary under test -------------------------------------------------
# DS_REAL_BIN wins; otherwise fall back to a corpus DLL this repo can actually
# build (_qa/fixtures/corpus/compile_all.bat), rather than a personal path.
if [ -z "$DS_REAL_BIN" ]; then
  for c in board.dll torture.dll math_ops.dll; do
    if [ -f "$CORPUS/$c" ]; then
      DS_REAL_BIN="$(cygpath -w "$CORPUS/$c" 2>/dev/null || echo "$CORPUS/$c")"
      export DS_REAL_BIN
      break
    fi
  done
fi

# ---- the dump_pairs harness binary ----------------------------------------
# Resolve lazily: callers that do not dump should not fail because it is absent.
qa_dump_exe() {
  ls -t "$ROOT"/target/release/deps/dump_pairs-*.exe 2>/dev/null | head -1
}

qa_require_bin() {
  if [ -z "$DS_REAL_BIN" ] || [ ! -f "$(cygpath -u "$DS_REAL_BIN" 2>/dev/null || echo "$DS_REAL_BIN")" ]; then
    echo "[env] no test binary. Set DS_REAL_BIN=<path>, or build the corpus:" >&2
    echo "      _qa/fixtures/corpus/compile_all.bat" >&2
    return 1
  fi
}
