#!/bin/bash
export PATH="/c/Users/User/.cargo/bin:/c/Users/User/AppData/Local/disasmstudio-tools/nasm/nasm-2.16.03:$PATH"
export LIBCLANG_PATH="/c/Users/User/AppData/Local/disasmstudio-tools/LLVM/bin"
cd /c/Users/User/Downloads/sd
command -v cargo >/dev/null || { echo "FATAL: cargo not found"; exit 99; }
powershell.exe -Command "Get-Process disasmstudio -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue" >/dev/null 2>&1
cargo test --release -p disasmstudio --test dump_pairs --no-run > /tmp/build_dp.log 2>&1
rc=$?
echo "CARGO_EXIT=$rc"
if [ $rc -ne 0 ]; then
  echo "--- errors ---"
  grep -iE ': error C[0-9]|: fatal error|LNK[0-9]|panicked|failed to run custom' /tmp/build_dp.log | head -15
else
  echo "BUILD OK"
fi
