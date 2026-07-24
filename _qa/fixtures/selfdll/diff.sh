#!/bin/bash
# Behavioural diff: build the driver against the SOURCE impl vs the DECOMPILED impl,
# run both with identical inputs, diff stdout. Any difference = a semantic bug.
# Resolved from this script's own location so it runs in any checkout/worktree.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$HERE"
PAIRS="${DS_PAIRS_DIR:-$ROOT/_qa/out/pairs}"
mkdir -p "$PAIRS"

# my exported function names (the decompiler recovers these from the export table)
# the function name is the identifier right before the first '(' on each API line
# (robust to multi-word / pointer return types like `const int *find_max`).
NAMES=$(grep -E '^API ' mine.c | sed -E 's/\(.*//' | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*$' | sort -u | tr '\n' ' ')

# 1. source impl (strip dllexport + main; keep the plain functions)
sed -e 's/__declspec(dllexport) //' -e 's/#define API .*/#define API/' \
    -e '/^int main(void)/d' mine.c > impl_src.c

# 2. decompiled impl: only MY functions (real names).
INCF=""
for f in "$PAIRS"/fn_*.txt; do
  nm=$(sed -n 's:.*/\* \([a-zA-Z_][a-zA-Z0-9_]*\) @.*:\1:p' "$f" | head -1)
  case " $NAMES " in *" $nm "*) INCF="$INCF $f";; esac
done
inc=$(echo $INCF | wc -w)
: > impl_dec.c
echo '#include <stdbool.h>' >> impl_dec.c
# /O2 vectorized loops read CRT CPU-feature globals (__isa_available) at absolute
# addresses; standalone that memory is unmapped -> crash. Emit each referenced
# global ONCE as a static: int guards =2 (SSE2 present -> the vectorized path runs,
# matching the reference's real CPU flag), qword data =0. Value-neutral (the sum is
# identical on either path). Deduped across functions so no redefinition.
grep -hoE 'dword_[0-9a-f]+' $INCF 2>/dev/null | sort -u | while read g; do echo "static int $g = 2;" >> impl_dec.c; done
grep -hoE 'qword_[0-9a-f]+' $INCF 2>/dev/null | sort -u | while read g; do echo "static long long $g = 0;" >> impl_dec.c; done
# bodies: drop K&R callee protos, #include, and the per-function #define globals.
for f in $INCF; do
  awk '/--- DECOMPILED ---/{p=1;next}
       p && !/^[a-z0-9_ ]+ [a-z0-9_]+\(\);$/ && !/^#include/ && !/^#define (dword|qword)_/ { print }' "$f" >> impl_dec.c
  echo "" >> impl_dec.c
done
# /O2 COMDAT-folds identical bodies (my_add == fwd_add); re-provide any folded export.
grep -qE '\bmy_add\(' impl_dec.c || echo 'int my_add(int a,int b){return fwd_add(a,b);}' >> impl_dec.c
echo "included $inc of my functions (of $(echo "$NAMES" | wc -w) exports)"

# 3. build + run both
rm -f ref.exe dec.exe ref.out dec.out
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
$vc = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vc`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match "^([^=]+)=(.*)$") { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] } }
Set-Location "$(cygpath -w "$HERE")"
cmd /c "cl /nologo /O2 /w driver.c impl_src.c /Fe:ref.exe 2>&1" | Out-Null
cmd /c "cl /nologo /O2 /w /TC driver.c impl_dec.c /Fe:dec.exe 2>&1" | Set-Content declog.txt -Encoding ascii
if (Test-Path ref.exe) { cmd /c ".\ref.exe > ref.out 2>&1" } else { "REF BUILD FAIL" }
if (Test-Path dec.exe) { cmd /c ".\dec.exe > dec.out 2>&1" } else { "DEC BUILD FAIL:"; Get-Content declog.txt | Select-String "error C" | Select-Object -First 10 | ForEach-Object { $_.Line.Trim() } }
'
echo "=== DIFF (source vs decompiled behaviour) ==="
if [ -f ref.out ] && [ -f dec.out ] && diff -q ref.out dec.out >/dev/null 2>&1; then
  echo "*** IDENTICAL — $(wc -l < ref.out) test lines match ***"
else
  echo "MISMATCHES (source | decompiled):"; diff ref.out dec.out 2>&1 | head -40
fi
