#!/bin/bash
# Build engine/tools/dumptool.cpp -> _qa/out/dumptool.exe, linking the engine +
# capstone static libs the cargo build already produced. Run a `cargo build`
# (or the normal gate rebuild) FIRST so disasmengine.lib reflects current source.
set -e
# Repo root resolved from this script's own location (engine/tools/), so it works
# in any checkout or git worktree rather than one hardcoded machine path.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# pick the NEWEST disasmengine.lib (by lib mtime = current engine), then capstone
# from the SAME bridge/out tree (compatible build).
ENG=$(find target/release/build -name disasmengine.lib -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)
[ -z "$ENG" ] && { echo "disasmengine.lib not found — run: cargo test --release -p disasmstudio --test dump_pairs --no-run"; exit 1; }
OUTDIR=$(echo "$ENG" | sed -E 's|(.*/out)/.*|\1|')
CAP=$(find "$OUTDIR" -name capstone.lib 2>/dev/null | head -1)
[ -z "$CAP" ] && { echo "capstone.lib not found under $OUTDIR"; exit 1; }
win() { echo "$1" | sed 's|^/\([a-z]\)/|\U\1:\\|; s|/|\\|g'; }
ENGW=$(win "$ENG"); CAPW=$(win "$CAP")
echo "engine:   $ENGW"
echo "capstone: $CAPW"

# emit a .bat (avoids nested-quote hell across bash->powershell->cmd).
# ROOTW is baked in rather than using %~dp0 so the .bat can live under _qa/out.
OUTDIR_QA="$PWD/_qa/out"; mkdir -p "$OUTDIR_QA"
BATF="$OUTDIR_QA/_build_dumptool.bat"
ROOTW=$(win "$PWD")
VCVARS_BAT="${VCVARS:-C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat}"
cat > "$BATF" <<BAT
@echo off
call "$VCVARS_BAT" >nul 2>&1
cd /d "$ROOTW"
cl /nologo /O2 /MD /std:c++17 /EHsc /Iengine\include engine\tools\dumptool.cpp "$ENGW" "$CAPW" /Fe:_qa\out\dumptool.exe /link /INCREMENTAL:NO /STACK:67108864
BAT
rm -f _qa/out/dumptool.exe
cmd //c "$(win "$BATF")" 2>&1 | grep -iE 'error|fatal|LNK[0-9]|dumptool\.(cpp|exe)|\.obj' | head -25
[ -f _qa/out/dumptool.exe ] && echo "OK: _qa/out/dumptool.exe built" || echo "FAILED"
