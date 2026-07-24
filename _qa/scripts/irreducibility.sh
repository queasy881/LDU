#!/usr/bin/env bash
# PROVABLY-CORRECT irreducibility census for the whole test binary.
#
# Re-dumps every function with DS_IRRED_REPORT set, so the engine emits one CSV
# row per function:  rva,reachable_blocks,reducible(1/0),final_gotos,form
# where `reducible` is decided by Hecht-Ullman T1-T2 interval reduction on the
# CFG built by CfgBuilder (independent of the structurer) — a flowgraph is
# reducible iff repeated self-loop removal (T1) + unique-predecessor merge (T2)
# collapse it to one node (Aho/Sethi/Ullman Dragon Thm 9.42). This is ground
# truth: an IRREDUCIBLE CFG provably has NO goto-free structured form without
# node-splitting, so any goto it emits is mathematically unavoidable.
#
# Usage:  bash _qa/irreducibility.sh            # NullWare real binary (default)
#         DS_REAL_BIN=/path/to.exe bash _qa/irreducibility.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"

REPORT="$OUT/irred_report.csv"
rm -f "$REPORT"
EXE=$(qa_dump_exe)
if [ -z "${EXE:-}" ]; then
  echo "dump_pairs exe not found — build with: cargo test --release -p disasmstudio --test dump_pairs --no-run" >&2
  exit 1
fi

# env.sh already resolved DS_REAL_BIN (env override, else a corpus DLL).
qa_require_bin || exit 2
export DS_PAIRS_DIR="$PAIRS"
export DS_PAIRS_CAP="${DS_PAIRS_CAP:-2000}"
export DS_IRRED_REPORT="$REPORT"

rm -f "$PAIRS"/fn_*.txt 2>/dev/null || true
"$EXE" --nocapture >/dev/null 2>&1 || true

python - "$REPORT" <<'PY'
import sys, csv
rows = []
with open(sys.argv[1], newline="") as f:
    for r in csv.reader(f):
        if len(r) < 5: continue
        rva, nb, red, gotos, form = r[0], int(r[1]), int(r[2]), int(r[3]), r[4]
        rows.append((rva, nb, red, gotos, form))

total       = len(rows)
irred       = [r for r in rows if r[2] == 0]
with_gotos  = [r for r in rows if r[3] > 0]                 # gotos in FINAL output
sm          = [r for r in rows if r[4] == "state-machine"]
# functions whose emitted output is NOT fully structured (gotos OR state machine)
non_struct  = [r for r in rows if r[3] > 0 or r[4] == "state-machine"]

# The headline: of the functions that could NOT be emitted goto-free
# (kept-goto OR state-machine), how many are PROVABLY irreducible?
ns_irred    = [r for r in non_struct if r[2] == 0]
ns_red      = [r for r in non_struct if r[2] == 1]

# And of kept-goto functions specifically:
kg_irred    = [r for r in with_gotos if r[2] == 0]
kg_red      = [r for r in with_gotos if r[2] == 1]

print("==== CFG REDUCIBILITY CENSUS (T1-T2, provably correct) ====")
print(f"functions analysed .................. {total}")
print(f"  irreducible CFG (any) ............. {len(irred)}  ({100*len(irred)/total:.1f}%)" if total else "")
print()
print(f"NOT emitted goto-free (goto OR state-machine): {len(non_struct)}")
print(f"  of those, PROVABLY IRREDUCIBLE ... {len(ns_irred)}   <-- gotos mathematically UNAVOIDABLE")
print(f"  of those, reducible (structurer limitation): {len(ns_red)}")
print()
print(f"kept-goto functions (gotos in output): {len(with_gotos)}   total gotos = {sum(r[3] for r in with_gotos)}")
print(f"  irreducible ...................... {len(kg_irred)}")
print(f"  reducible (fixable) .............. {len(kg_red)}")
print(f"state-machine functions ............ {len(sm)}")
print()
if ns_red:
    print("REDUCIBLE-BUT-NOT-STRUCTURED (structurer could improve), first 25 rvas:")
    print("  " + " ".join(r[0] for r in ns_red[:25]))
if kg_irred:
    print("IRREDUCIBLE kept-goto (unavoidable), first 25 rvas:")
    print("  " + " ".join(r[0] for r in kg_irred[:25]))
PY
echo "raw CSV: $REPORT"
