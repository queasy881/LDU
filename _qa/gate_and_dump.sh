#!/bin/bash
cd /c/Users/User/Downloads/sd
echo "=== corpus gate ==="
powershell.exe -ExecutionPolicy Bypass -File "C:\Users\User\Downloads\sd\_qa\measure.ps1" 2>&1 | grep -E 'ORACLE_PASS|ORACLE_FAIL|BUILD_OK|COMPILE_FAIL|BUILD_ERRORS'
echo "=== re-dump full 1443 ==="
DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll" DS_PAIRS_CAP=1500 cargo test --release -p disasmstudio --test dump_pairs -- --nocapture 2>&1 | grep -iE 're-dumped|pairs=|wrote' | tail -3
echo "=== dump done: $(ls _qa/pairs/fn_*.txt|wc -l) pairs ==="
