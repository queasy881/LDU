#!/usr/bin/env python3
"""Precise offender census across all _qa/pairs/fn_*.txt decompiled output.

Counts, per the user's three hard targets, ONLY inside the --- DECOMPILED --- section:
  1. ctx leaks       : leaked callee-saved entry-value placeholders  ctx_<reg>
  2. null-base       : dereference/arith off a literal null pointer base
  3. folded-if       : constant-folded conditionals  if (0 == 0) / if (1) / etc.

Prints grand totals + a per-RVA breakdown of every offending function, and
dumps concrete example lines so each hit can be traced to real code.
"""
import os, re, sys, glob, collections

from qapaths import PAIRS

# --- ctx leak: ctx_rax/ctx_rdi/ctx_r12/ctx_xmm6 ... -------------------------
RE_CTX = re.compile(r"\bctx_[a-z][a-z0-9]*\b")

# --- null-base: a pointer cast of a literal 0 (then used as a base) ----------
#   (char*)(0)   (int *)0   *(double*)(0 + x)   *(_QWORD*)(0)
RE_NULLBASE = re.compile(
    r"\(\s*[A-Za-z_][\w ]*\*+\s*\)\s*\(?\s*0\s*\)"      # (char*)(0) / (int *)0
    r"|\*\s*\(\s*[A-Za-z_][\w ]*\*+\s*\)\s*\(\s*0\b"     # *(int*)(0 + ...)
)

# --- folded-if: constant condition -----------------------------------------
RE_FOLDED = re.compile(
    r"\bif\s*\(\s*"
    r"(?:0\s*==\s*0|1\s*==\s*1|0\s*!=\s*0|1\s*!=\s*1|1|0|"
    r"0\s*==\s*1|1\s*==\s*0|true|false)\s*\)"
)

def decompiled_section(path):
    lines = []
    inside = False
    with open(path, "r", errors="replace") as f:
        for ln in f:
            if ln.startswith("--- DECOMPILED"):
                inside = True
                continue
            if ln.startswith("--- DISASM"):
                inside = False
                continue
            if inside:
                lines.append(ln.rstrip("\n"))
    return lines

def main():
    files = sorted(glob.glob(os.path.join(PAIRS, "fn_*.txt")))
    tot = collections.Counter()
    per_rva = collections.defaultdict(lambda: collections.Counter())
    examples = {"ctx": [], "nullbase": [], "folded": []}
    for path in files:
        rva = os.path.basename(path)[3:-4]   # fn_XXXX.txt -> XXXX
        for ln in decompiled_section(path):
            for m in RE_CTX.finditer(ln):
                tot["ctx"] += 1; per_rva[rva]["ctx"] += 1
                if len(examples["ctx"]) < 25: examples["ctx"].append(f"{rva}: {ln.strip()}")
            for m in RE_NULLBASE.finditer(ln):
                tot["nullbase"] += 1; per_rva[rva]["nullbase"] += 1
                if len(examples["nullbase"]) < 25: examples["nullbase"].append(f"{rva}: {ln.strip()}")
            for m in RE_FOLDED.finditer(ln):
                tot["folded"] += 1; per_rva[rva]["folded"] += 1
                if len(examples["folded"]) < 25: examples["folded"].append(f"{rva}: {ln.strip()}")

    print(f"==== CENSUS over {len(files)} functions ====")
    print(f"  ctx leaks  : {tot['ctx']}")
    print(f"  null-base  : {tot['nullbase']}")
    print(f"  folded-if  : {tot['folded']}")
    print(f"  GRAND TOTAL: {tot['ctx']+tot['nullbase']+tot['folded']}")
    print()
    # per-RVA, worst first
    def worst(key):
        items = [(rva, c[key]) for rva, c in per_rva.items() if c[key] > 0]
        items.sort(key=lambda x: -x[1])
        return items
    for key, label in (("ctx","CTX LEAKS"),("nullbase","NULL-BASE"),("folded","FOLDED-IF")):
        w = worst(key)
        print(f"--- {label}: {len(w)} functions affected ---")
        for rva, c in w[:40]:
            print(f"    0x{rva}={c}")
        print()
    if "-v" in sys.argv:
        for key in ("ctx","nullbase","folded"):
            print(f"==== examples: {key} ====")
            for e in examples[key]:
                print("   ", e)
            print()

if __name__ == "__main__":
    main()
