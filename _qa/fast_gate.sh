#!/bin/bash
# Lean NullWare gate: dump + GOTO_TOTAL (single grep) + parallel compile.
# Skips full_gate2.sh's per-file TOP-15 awk loop (1445 spawns = slow on Git Bash).
export PATH="/c/Users/User/.cargo/bin:/c/Users/User/AppData/Local/disasmstudio-tools/nasm/nasm-2.16.03:/c/Program Files/NASM:$PATH"
export LIBCLANG_PATH="/c/Users/User/AppData/Local/disasmstudio-tools/LLVM/bin"
cd /c/Users/User/Downloads/sd
export DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll"
export DS_PAIRS_CAP=1500
EXE=$(ls -t target/release/deps/dump_pairs-*.exe | head -1)
rm -f _qa/pairs/fn_*.txt
"$EXE" --nocapture >/dev/null 2>&1
echo "DUMPED $(ls _qa/pairs/fn_*.txt 2>/dev/null | wc -l)"
echo "GOTO_TOTAL $(grep -rho 'goto [A-Za-z0-9_]*;' _qa/pairs/fn_*.txt 2>/dev/null | wc -l)   (<=300 gate; baseline 296)"
echo "STATE_MACHINES $(grep -l 'switch (__state)' _qa/pairs/fn_*.txt 2>/dev/null | wc -l)"
bash _qa/verify_fast.sh 2>&1 | tail -1
