#!/bin/bash
cd /c/Users/User/Downloads/sd
rm -rf _qa/w3; mkdir -p _qa/w3
n=0
for f in _qa/pairs/fn_*.txt; do
  nm=$(sed -n 's:.*/\* \([a-zA-Z_][a-zA-Z0-9_]*\) @.*:\1:p' "$f" | head -1)
  [ -z "$nm" ] && continue
  awk '/--- DECOMPILED ---/{p=1;next} p' "$f" > "_qa/w3/$nm.c"
  n=$((n+1))
done
echo "extracted $n bodies"
ls _qa/w3/*.c | sed 's#.*/##' > _qa/w3/files.rsp
powershell.exe -NoProfile -Command '
$vc="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vc`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match "^([^=]+)=(.*)$") { Set-Item "Env:$($matches[1])" $matches[2] } }
Set-Location C:\Users\User\Downloads\sd\_qa\w3
cmd /c "cl /nologo /c /W3 /MP16 /TC @files.rsp 2>&1" | Set-Content w3.log -Encoding ascii
' 2>/dev/null
# tally
grep -oE '[a-zA-Z0-9_]+\.c\([0-9]+\): warning (C4047|C4133)' _qa/w3/w3.log 2>/dev/null > _qa/w3/hits.txt
tot=$(wc -l < _qa/w3/hits.txt)
fns=$(grep -oE '^[a-zA-Z0-9_]+\.c' _qa/w3/hits.txt | sort -u | wc -l)
errs=$(grep -cE 'error C' _qa/w3/w3.log)
echo "==== C4047/C4133 warnings: $tot across $fns functions | compile errors: $errs ===="
echo "--- warning-operator histogram (what render site) ---"
grep -oE "warning C40..: '[^']*'" _qa/w3/w3.log 2>/dev/null | sort | uniq -c | sort -rn | head -12
