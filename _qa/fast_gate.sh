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
# GOTO_TOTAL is a READABILITY PROXY, not a correctness oracle -- and on 2026-07-17 the proxy
# and the goal were shown to disagree. The reaching-flag structurer and the switch(__state)
# machine bought a low goto count by INVENTING control flow: `char __at_1f80 = 0; ...
# __at_1f80 = 1; ... if (__at_1f80)`, and whole functions re-encoded as a dispatch loop.
# Neither exists in the binary. Hex-Rays -- the parity target -- emits a real goto instead.
# Removing both took gotos 142 -> 568 across 53 -> 154 of 1497 fns at +0.4% chars, and every
# one of those gotos is an edge that IS in the machine code.
# The threshold below is therefore a REGRESSION FENCE around the honest number, not a target
# to optimise: driving it back down means printing flags instead of edges. Do not "improve" it.
# NB count with the SEMICOLON anchor as below. A bare `goto ` also matches the confidence
# header ("... 1 residual goto"), which inflates the count by one per affected function --
# it briefly told me 637.
echo "GOTO_TOTAL $(grep -rho 'goto [A-Za-z0-9_]*;' _qa/pairs/fn_*.txt 2>/dev/null | wc -l)   (<=700 fence; honest baseline 568; was 142 w/ invented flags)"
echo "INVENTED_FLAGS $(grep -l '__at_[0-9a-f]' _qa/pairs/fn_*.txt 2>/dev/null | wc -l)   (must stay 0)"
echo "STATE_MACHINES $(grep -l 'switch (__state)' _qa/pairs/fn_*.txt 2>/dev/null | wc -l)   (must stay 0)"
bash _qa/verify_fast.sh 2>&1 | tail -1
