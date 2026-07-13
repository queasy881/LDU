#!/usr/bin/env python3
"""
irreducible.py — the goto census + structurer target list.

Runs the NullWare dump with DS_IRRED_REPORT so the engine emits one CSV row per
function:  rva,reachable_blocks,reducible(1/0),final_gotos,form
where `reducible` is decided by Hecht-Ullman T1-T2 interval reduction on the CFG
(independent of the structurer) = ground truth. An IRREDUCIBLE CFG provably has NO
goto-free structured form, so its gotos are mathematically unavoidable. Everything
REDUCIBLE that still emits a goto is a STRUCTURER LIMITATION and MUST be fixed.

GOAL (the whole night): drive REDUCIBLE_GOTOS to 0. The only gotos left must be in
provably-irreducible functions.

Usage:
  python _qa/irreducible.py                 # full re-dump + census (slow, ~1-15 min)
  python _qa/irreducible.py --csv PATH      # parse an existing report CSV (fast)
  python _qa/irreducible.py --targets       # (after a run) just the reducible-goto RVAs, space-separated
  python _qa/irreducible.py --targets-cap N # top-N reducible-goto RVAs by goto count
"""
import os, sys, csv, subprocess, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(ROOT, "_qa", "irred_report.csv")
NULLWARE = r"C:\Users\User\Downloads\NullWare\NullWare\NullWare\build\bin\Release\NullWare.dll"


def run_dump():
    """Re-dump every NullWare function with DS_IRRED_REPORT set."""
    exes = sorted(glob.glob(os.path.join(ROOT, "target", "release", "deps", "dump_pairs-*.exe")),
                  key=os.path.getmtime, reverse=True)
    if not exes:
        sys.exit("dump_pairs exe not found — build: cargo test --release -p disasmstudio --test dump_pairs --no-run")
    env = dict(os.environ)
    env["PATH"] = r"C:\Users\User\.cargo\bin;C:\Program Files\NASM;" + env.get("PATH", "")
    env["LIBCLANG_PATH"] = r"C:\Users\User\AppData\Local\disasmstudio-tools\LLVM\bin"
    env["DS_REAL_BIN"] = env.get("DS_REAL_BIN", NULLWARE)
    env["DS_PAIRS_CAP"] = env.get("DS_PAIRS_CAP", "2000")
    env["DS_IRRED_REPORT"] = REPORT
    if os.path.exists(REPORT):
        os.remove(REPORT)
    subprocess.run([exes[0], "--nocapture"], env=env, cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def load(path):
    rows = []
    with open(path, newline="") as f:
        for r in csv.reader(f):
            if len(r) < 5:
                continue
            try:
                rows.append((r[0], int(r[1]), int(r[2]), int(r[3]), r[4]))
            except ValueError:
                continue
    return rows


def main():
    args = sys.argv[1:]
    csv_path = REPORT
    if "--csv" in args:
        csv_path = args[args.index("--csv") + 1]
    elif "--targets" not in args and "--targets-cap" not in args:
        run_dump()

    if not os.path.exists(csv_path):
        sys.exit(f"no report at {csv_path} — run `python _qa/irreducible.py` first")
    rows = load(csv_path)

    with_gotos = [r for r in rows if r[3] > 0]
    kg_red   = sorted([r for r in with_gotos if r[2] == 1], key=lambda r: -r[3])   # REDUCIBLE  -> MUST fix
    kg_irred = sorted([r for r in with_gotos if r[2] == 0], key=lambda r: -r[3])   # irreducible -> ignore
    sm       = [r for r in rows if r[4] == "state-machine"]
    sm_red   = [r for r in sm if r[2] == 1]

    if "--targets" in args:
        print(" ".join("0x" + r[0] for r in kg_red))
        return
    if "--targets-cap" in args:
        n = int(args[args.index("--targets-cap") + 1])
        print(" ".join("0x" + r[0] for r in kg_red[:n]))
        return

    total_gotos     = sum(r[3] for r in with_gotos)
    red_gotos       = sum(r[3] for r in kg_red)
    irred_gotos     = sum(r[3] for r in kg_irred)

    print("==== GOTO / IRREDUCIBILITY CENSUS (T1-T2 provable) ====")
    print(f"functions analysed .................. {len(rows)}")
    print(f"total gotos in output .............. {total_gotos}   across {len(with_gotos)} functions")
    print(f"state-machine functions ............ {len(sm)}   (reducible: {len(sm_red)})")
    print()
    print(f">>> REDUCIBLE_GOTOS = {red_gotos}  across {len(kg_red)} functions   <-- MUST become 0 (structurer limitation)")
    print(f"    irreducible gotos = {irred_gotos}  across {len(kg_irred)} functions   <-- OK, mathematically unavoidable")
    print()
    if sm_red:
        print(f"REDUCIBLE STATE-MACHINES ({len(sm_red)}) — worst readability, MUST be structured:")
        print("  " + " ".join("0x" + r[0] for r in sm_red[:30]))
        print()
    if kg_red:
        print(f"REDUCIBLE goto-functions (MUST FIX), by goto count:")
        for r in kg_red[:30]:
            print(f"  0x{r[0]:<8} gotos={r[3]:<3} blocks={r[1]:<4} form={r[4]}")
    print()
    print(f"IRREDUCIBLE goto-functions (ignore) : {len(kg_irred)}")
    if kg_irred:
        print("  " + " ".join("0x" + r[0] for r in kg_irred[:20]))
    print()
    if red_gotos == 0 and not sm_red:
        print("*** DONE: every reducible CFG is fully structured. Only irreducible gotos remain. ***")
    else:
        print(f"*** {red_gotos} reducible gotos + {len(sm_red)} reducible state-machines left to eliminate. ***")


if __name__ == "__main__":
    main()
