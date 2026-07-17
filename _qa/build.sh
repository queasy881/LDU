#!/bin/bash
# Build the engine + test binaries, and FAIL LOUDLY. Exists because two different silent
# failures cost real time on 2026-07-17, both of which left the OLD exe in place while the
# output read exactly like a working feature:
#   1. `grep -c "error C"` printed but never CHECKED  -> a failed compile looked like success.
#   2. `error C` DOES NOT MATCH LINKER ERRORS. Building while a gate is running gives
#      `LINK : fatal error LNK1104: cannot open file dump_pairs-<hash>.exe` (the running dump
#      holds the exe) -- the C++ compiles, the .lib updates, the EXE DOES NOT, and the next
#      run silently uses a binary that is minutes stale.
# Usage:  bash _qa/build.sh   ->  exit 0 only if a FRESH exe exists.
set -u
cd "$(dirname "$0")/.."
export PATH="/c/Users/User/.cargo/bin:/c/Program Files/NASM:$PATH"
export LIBCLANG_PATH="C:\\Users\\User\\AppData\\Local\\disasmstudio-tools\\LLVM\\bin"

if ls _qa/pairs/fn_*.txt >/dev/null 2>&1 && pgrep -f dump_pairs >/dev/null 2>&1; then
    echo "BUILD REFUSED: a dump_pairs run holds the exe (a gate is in flight)."
    echo "               Linking now would fail LNK1104 and leave a stale binary."
    exit 2
fi

touch crates/bridge/build.rs
OUT=$(cargo test --release -p disasmstudio --test dump_pairs --test decompile_dump --no-run 2>&1)
BAD=$(printf '%s' "$OUT" | grep -cE "error C[0-9]{4}|LNK[0-9]{4}|^error(\[|:)")
if [ "$BAD" != "0" ]; then
    echo "BUILD FAILED ($BAD):"
    printf '%s' "$OUT" | grep -E "error C[0-9]{4}|LNK[0-9]{4}|^error(\[|:)" | head -6
    exit 1
fi
EXE=$(ls -t target/release/deps/dump_pairs-*.exe 2>/dev/null | head -1)
[ -n "$EXE" ] || { echo "BUILD FAILED: no dump_pairs exe"; exit 1; }
echo "BUILD OK  $(basename "$EXE")  mtime=$(date -r "$EXE" +%H:%M:%S)  now=$(date +%H:%M:%S)"
