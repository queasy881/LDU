#!/bin/bash
cd /c/Users/User/Downloads/sd
rm -rf _qa/w3; mkdir -p _qa/w3
awk 'FNR==1{ if(out)close(out); b=FILENAME; sub(/.*\//,"",b); sub(/\.txt$/,"",b); out="_qa/w3/" b ".c"; p=0 }
     /--- DECOMPILED ---/{ p=1; next }
     p{ print > out }' _qa/pairs/fn_*.txt
ls _qa/w3/*.c | sed 's#.*/##' > _qa/w3/files.rsp
powershell.exe -NoProfile -Command '
$vc="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmd /c "`"$vc`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match "^([^=]+)=(.*)$") { Set-Item "Env:$($matches[1])" $matches[2] } }
Set-Location C:\Users\User\Downloads\sd\_qa\w3
cmd /c "cl /nologo /c /W3 /MP16 /TC @files.rsp 2>&1" | Set-Content w3.log -Encoding ascii
' 2>/dev/null
echo "fns=$(ls _qa/w3/*.c|wc -l) errors=$(grep -cE 'error C' _qa/w3/w3.log)"
grep -oE 'warning C[0-9]+' _qa/w3/w3.log | sort | uniq -c | sort -rn | head -14
