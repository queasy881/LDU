#!/bin/bash
# Generalized behavioural differential test for a self-authored DLL.
#   difftest.sh <name>   uses <name>.c (source) + <name>_driver.c (driver).
set +e
NAME="$1"; [ -z "$NAME" ] && { echo "usage: difftest.sh <name>"; exit 2; }
export DLLNAME="$NAME"
# Resolved from this script's own location so it runs in any checkout/worktree.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$HERE"
PAIRS="${DS_PAIRS_DIR:-$ROOT/_qa/out/pairs}"
mkdir -p "$PAIRS"
EXE=$(ls -t "$ROOT"/target/release/deps/dump_pairs-*.exe | head -1)

# 1. build the DLL (/O2)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
$vc = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vc`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match "^([^=]+)=(.*)$") { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] } }
Set-Location "$(cygpath -w "$HERE")"
$n = $env:DLLNAME
cmd /c "cl /nologo /O2 /LD $n.c /link /OUT:$n.dll /EXPORT:main 2>&1" | Out-Null
"built $n.dll = $(Test-Path ""$n.dll"")"
'
# decompile it fresh
rm -f "$PAIRS"/fn_*.txt
DS_REAL_BIN="$(cygpath -w "$HERE")\\${NAME}.dll" DS_PAIRS_CAP=400 "$EXE" --nocapture >/dev/null 2>&1

# 2. exported names + source impl
NAMES=$(grep -E '^API ' "$NAME.c" | sed -E 's/\(.*//' | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*$' | sort -u | tr '\n' ' ')
sed -e 's/__declspec(dllexport) //' -e 's/#define API .*/#define API/' -e '/^int main(void)/d' "$NAME.c" > "impl_${NAME}_src.c"

# 3. decompiled impl
INCF=""
for f in "$PAIRS"/fn_*.txt; do
  nm=$(sed -n 's:.*/\* \([a-zA-Z_][a-zA-Z0-9_]*\) @.*:\1:p' "$f" | head -1)
  case " $NAMES " in *" $nm "*) INCF="$INCF $f";; esac
done
DEC="impl_${NAME}_dec.c"
: > "$DEC"; echo '#include <stdbool.h>' >> "$DEC"
grep -hoE 'dword_[0-9a-f]+' $INCF 2>/dev/null | sort -u | while read g; do echo "static int $g = 0;" >> "$DEC"; done
grep -hoE 'qword_[0-9a-f]+' $INCF 2>/dev/null | sort -u | while read g; do echo "static long long $g = 0;" >> "$DEC"; done
for f in $INCF; do
  awk '/--- DECOMPILED ---/{p=1;next}
       p && !/^[a-z0-9_ ]+ [a-z0-9_]+\(\);$/ && !/^#include/ && !/^#define (dword|qword)_/ {print}' "$f" >> "$DEC"
  echo "" >> "$DEC"
done
MISS=""; for n in $NAMES; do grep -qE "[ *]$n[[:space:]]*\(" "$DEC" || MISS="$MISS $n"; done
echo "[$NAME] included $(echo $INCF|wc -w) fns of $(echo $NAMES|wc -w); missing:${MISS:- none}"

# 4. build both + run
rm -f "ref_$NAME.exe" "dec_$NAME.exe" "ref_$NAME.out" "dec_$NAME.out"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
$vc = "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vc`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match "^([^=]+)=(.*)$") { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] } }
Set-Location "$(cygpath -w "$HERE")"
$n = $env:DLLNAME
cmd /c "cl /nologo /O2 /w ${n}_driver.c impl_${n}_src.c /Fe:ref_$n.exe 2>&1" | Out-Null
cmd /c "cl /nologo /O2 /w /TC ${n}_driver.c impl_${n}_dec.c /Fe:dec_$n.exe 2>&1" | Set-Content ${n}_declog.txt -Encoding ascii
if (Test-Path "ref_$n.exe") { cmd /c ".\ref_$n.exe > ref_$n.out 2>&1" } else { "REF BUILD FAIL" }
if (Test-Path "dec_$n.exe") { cmd /c ".\dec_$n.exe > dec_$n.out 2>&1" } else { "DEC BUILD FAIL:"; Get-Content "${n}_declog.txt" | Select-String "error C|error LNK" | Select-Object -First 12 | ForEach-Object { $_.Line.Trim() } }
'
echo "=== [$NAME] DIFF (source vs decompiled) ==="
if [ -f "ref_$NAME.out" ] && [ -f "dec_$NAME.out" ] && diff -q "ref_$NAME.out" "dec_$NAME.out" >/dev/null 2>&1; then
  echo "*** [$NAME] IDENTICAL — $(wc -l < ref_$NAME.out) test lines match ***"
else
  echo "[$NAME] MISMATCHES:"; diff "ref_$NAME.out" "dec_$NAME.out" 2>&1 | head -30
fi
