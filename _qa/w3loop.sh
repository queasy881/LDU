#!/bin/bash
export PATH="/c/Users/User/.cargo/bin:/c/Users/User/AppData/Local/disasmstudio-tools/nasm/nasm-2.16.03:$PATH"
export LIBCLANG_PATH="/c/Users/User/AppData/Local/disasmstudio-tools/LLVM/bin"
cd /c/Users/User/Downloads/sd
bash _qa/rb_check.sh 2>&1 | grep -E 'CARGO_EXIT|BUILD|error C' | tail -3
[ "$(grep -c 'BUILD OK' <(bash _qa/rb_check.sh 2>&1))" ] 
powershell.exe -NoProfile -ExecutionPolicy Bypass -File _qa/measure.ps1 >/dev/null 2>&1
echo "CORPUS: $(grep -E 'SUMMARY:' _qa/round_harness.log | tail -1)"
bash _qa/redump_par.sh 2>&1 | tail -1
bash _qa/w3check.sh 2>&1 | grep -E 'C4047/C4133|warning C4047' | head -10
