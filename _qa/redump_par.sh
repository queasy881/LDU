#!/bin/bash
# Parallel full re-dump of all NullWare functions, load-balanced by block count
# (decompile-time proxy). Splits work so the few monster functions land on DISTINCT
# workers instead of clustering (which made a straggler dominate). Each worker runs
# the already-built dump_pairs test exe directly (no cargo lock, no rebuild).
# ~10min serial -> ~1min on 16 cores (floored by the single slowest function, ~40s).
# Usage: bash _qa/redump_par.sh [N]   (N workers, default 14)
cd /c/Users/User/Downloads/sd
export DS_REAL_BIN="C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll"
N=${1:-14}
EXE=$(ls -t target/release/deps/dump_pairs-*.exe 2>/dev/null | head -1)
[ -z "$EXE" ] && { echo "FATAL: no dump_pairs exe (build first)"; exit 1; }

# (block_count, rva) for every function, sorted by block count DESC so the biggest
# go first; then assign sorted-index i to worker (i % N) — the top N monsters land
# on N distinct workers, the next N tier fills the same workers, etc. (balanced).
mapfile -t SORTED < <(
  awk 'FNR==1{ b=0; if(match($0,/blocks=[0-9]+/)) b=substr($0,RSTART+7,RLENGTH-7);
               r=FILENAME; sub(/.*\/fn_/,"",r); sub(/\.txt$/,"",r); print b, r }' \
      _qa/pairs/fn_*.txt | sort -rn | awk '{print $2}')
TOTAL=${#SORTED[@]}
[ "$TOTAL" -eq 0 ] && { echo "FATAL: no pair files to derive RVA list"; exit 1; }

declare -a LIST
for ((i=0; i<TOTAL; i++)); do
  c=$(( i % N ))
  LIST[$c]="${LIST[$c]}${LIST[$c]:+,}0x${SORTED[$i]}"
done

pids=()
for ((c=0; c<N; c++)); do
  [ -z "${LIST[$c]}" ] && continue
  DS_PAIRS_RVAS="${LIST[$c]}" "$EXE" --nocapture > "/tmp/dump_w$c.log" 2>&1 &
  pids+=($!)
done
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
echo "PAR_REDUMP_EXIT=$fail  workers=$N  pairs=$(ls _qa/pairs/fn_*.txt | wc -l)/$TOTAL"
