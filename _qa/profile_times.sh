#!/bin/bash
# One-time timing profile: run the parallel dump with DS_TIMING, aggregate the
# per-function decompile times into _qa/fn_times.txt (rva_hex  ms) for LPT balancing.
cd /c/Users/User/Downloads/sd
export DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll"
export DS_TIMING=1
N=14
EXE=$(ls -t target/release/deps/dump_pairs-*.exe | head -1)
mapfile -t SORTED < <(
  awk 'FNR==1{ b=0; if(match($0,/blocks=[0-9]+/)) b=substr($0,RSTART+7,RLENGTH-7);
               r=FILENAME; sub(/.*\/fn_/,"",r); sub(/\.txt$/,"",r); print b, r }' \
      _qa/pairs/fn_*.txt | sort -rn | awk '{print $2}')
TOTAL=${#SORTED[@]}
declare -a LIST
for ((i=0;i<TOTAL;i++)); do c=$((i%N)); LIST[$c]="${LIST[$c]}${LIST[$c]:+,}0x${SORTED[$i]}"; done
pids=()
for ((c=0;c<N;c++)); do
  [ -z "${LIST[$c]}" ] && continue
  DS_PAIRS_RVAS="${LIST[$c]}" "$EXE" --nocapture > "/tmp/prof_w$c.log" 2>&1 &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
grep -hoE 'DSTIME 0x[0-9a-f]+ [0-9]+' /tmp/prof_w*.log | awk '{print $2, $3}' | sort -u > _qa/fn_times.txt
echo "PROFILE_DONE lines=$(wc -l < _qa/fn_times.txt)"
echo "=== top 15 slowest (contention-inflated) ==="
sort -k2 -rn _qa/fn_times.txt | head -15
