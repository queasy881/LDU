#!/usr/bin/env bash
# Rebuild the engine AND relink the shell (disasmstudio) test binaries.
# CRITICAL: `cargo build -p bridge` rebuilds the engine lib but does NOT relink
# the dump_pairs / decompile_dump test exes (they live in crate `disasmstudio`).
# Always use this so tests run against the freshly-built engine.
set -u
export PATH="$PATH:/c/Users/User/.cargo/bin"
export LIBCLANG_PATH="C:\\Users\\User\\AppData\\Local\\disasmstudio-tools\\LLVM\\bin"
cd /c/Users/User/Downloads/sd
for i in 1 2 3 4 5; do
  cargo test --release --no-run -p disasmstudio --test dump_pairs --test decompile_dump \
    2>_qa/rebuild.err 1>_qa/rebuild.out
  rc=$?
  if grep -qiE "os error 5|Access is denied|being used by another process" _qa/rebuild.err; then
    echo "rebuild retry $i (locked test exe)"
    taskkill //F //IM dump_pairs-2fa953706409b00b.exe 2>/dev/null >/dev/null
    taskkill //F //IM decompile_dump-edcc4c200037ef39.exe 2>/dev/null >/dev/null
    sleep 2; continue
  fi
  break
done
if grep -qiE "error\[|error:" _qa/rebuild.err; then
  echo "BUILD FAILED"; grep -iE "error\[|error:" _qa/rebuild.err | head -20; exit 1
fi
echo "BUILD OK (exit=$rc)"; tail -2 _qa/rebuild.err
