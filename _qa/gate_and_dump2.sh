#!/bin/bash
cd /c/Users/User/Downloads/sd
echo "=== corpus gate (harness truth) ==="
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\User\Downloads\sd\_qa\measure.ps1" 2>&1 | grep -E 'BUILD_OK|COMPILE_FAIL|BUILD_ERRORS' 
grep -E 'SUMMARY:' _qa/round_harness.log | tail -1
echo "=== re-dump full 1443 ==="
DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll" DS_PAIRS_CAP=1500 cargo test --release -p disasmstudio --test dump_pairs -- --nocapture >/dev/null 2>&1
echo "=== dump done: $(ls _qa/pairs/fn_*.txt|wc -l) pairs ==="
