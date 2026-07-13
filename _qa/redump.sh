#!/bin/bash
export PATH="/c/Users/User/.cargo/bin:/c/Users/User/AppData/Local/disasmstudio-tools/nasm/nasm-2.16.03:$PATH"
export LIBCLANG_PATH="/c/Users/User/AppData/Local/disasmstudio-tools/LLVM/bin"
export DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll"
export DS_PAIRS_CAP=1500
cd /c/Users/User/Downloads/sd
cargo test --release -p disasmstudio --test dump_pairs -- --nocapture > /tmp/redump.log 2>&1
echo "REDUMP_EXIT=$?"
grep -iE 're-dumped|pairs written|wrote [0-9]' /tmp/redump.log | tail -3
echo "pairs on disk: $(ls _qa/pairs/fn_*.txt|wc -l)"
