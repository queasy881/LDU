#!/bin/bash
# Fast compile-verification of all decompiled pair files.
#  1. one awk pass extracts every `--- DECOMPILED ---` body to verify/fn_*.c
#  2. ONE `cl /MP16 /c @rsp` invocation compiles all 1443 as separate TUs across
#     16 parallel compiler processes (vs 1443 serial cl spawns).
# Prints CLEAN=n/total and lists the failing functions with their error codes.
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
VDIR="$OUT/verify"
rm -rf "$VDIR"; mkdir -p "$VDIR"

# single awk process: split each pair's decompiled body into its own .c
awk 'FNR==1{ if(out) close(out); base=FILENAME; sub(/.*\//,"",base); sub(/\.txt$/,"",base); out="'"$VDIR"'/" base ".c"; p=0 }
     /--- DECOMPILED ---/{ p=1; next }
     p{ print > out }' "$PAIRS"/fn_*.txt

ls "$VDIR"/*.c | sed 's|.*/||' > "$VDIR/files.rsp"
TOTAL=$(wc -l < "$VDIR/files.rsp")

# compile all TUs in one parallel cl invocation via a PowerShell shim (needs vcvars).
# VDIR/VCVARS cross the boundary as ENVIRONMENT variables: the script below is
# single-quoted (so bash does not expand it), which means a $(...) inside it would
# be passed to PowerShell literally rather than substituted.
DS_VDIR_W="$(cygpath -w "$VDIR")"; export DS_VDIR_W
DS_VCVARS="${VCVARS:-C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat}"
export DS_VCVARS
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
$vc = $env:DS_VCVARS
if (-not (Test-Path $vc)) { Write-Error "vcvars64.bat not found at $vc; set VCVARS"; exit 2 }
cmd /c "`"$vc`" >nul 2>&1 && set" | ForEach-Object { if ($_ -match "^([^=]+)=(.*)$") { Set-Item -Path "Env:$($matches[1])" -Value $matches[2] } }
Set-Location $env:DS_VDIR_W
$out = cmd /c "cl /nologo /c /w /MP16 /TC @files.rsp 2>&1"
$out | Set-Content _cl.log -Encoding ascii
$errfiles = @{}
foreach ($l in $out) {
  if ($l -match "^([A-Za-z0-9_]+\.c)\((\d+)\): error (C[0-9]+)") {
    $fn = $matches[1]; $code = $matches[3]
    if (-not $errfiles.ContainsKey($fn)) { $errfiles[$fn] = @{} }
    $errfiles[$fn][$code] = $true
  }
}
$lines = $errfiles.GetEnumerator() | Sort-Object Name | ForEach-Object {
  "{0} [{1}]" -f $_.Key, (($_.Value.Keys | Sort-Object) -join ",")
}
Set-Content _errs.txt -Value ([string[]]$lines) -Encoding ascii
'
ERRFUNCS=$(grep -cE '\.c \[' "$VDIR/_errs.txt" 2>/dev/null); ERRFUNCS=${ERRFUNCS:-0}
CLEAN=$(( TOTAL - ERRFUNCS ))
echo "CLEAN=$CLEAN / $TOTAL   ($(awk "BEGIN{printf \"%.2f\", 100*$CLEAN/$TOTAL}")%)"
[ "$ERRFUNCS" -gt 0 ] && { echo "--- failing functions ---"; cat "$VDIR/_errs.txt"; }
