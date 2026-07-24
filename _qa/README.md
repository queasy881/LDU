# QA

The quality loop for the decompiler. Nothing here ships in the app.

```
_qa/
├── docs/       findings and backlogs (read these first)
├── fixtures/   test SOURCES — committed, compiled on demand
├── scripts/    build + gate shell scripts
├── metrics/    Python census / oracle / scanners
├── workflows/  multi-agent audit scripts
└── out/        ALL generated output — gitignored, safe to delete
```

Every script resolves the repo root from its own location, so they work from any
directory and in any git worktree. Shell scripts source
[`scripts/env.sh`](scripts/env.sh); Python imports
[`metrics/qapaths.py`](metrics/qapaths.py).

## Picking a target binary

`DS_REAL_BIN` wins everywhere. With it unset, everything falls back to a corpus
DLL — build those first:

```bash
_qa/fixtures/corpus/compile_all.bat
```

## The gate

```bash
bash _qa/scripts/rebuild.sh      # engine + relink the test exes (do this first)
bash _qa/scripts/fast_gate.sh    # dump, count gotos, compile-verify every body
```

`fast_gate.sh` reports four numbers:

- `GOTO_TOTAL` — a **regression fence**, not a target. Driving it down by
  inventing control flow (reaching flags, `switch(__state)` dispatch loops) is
  how it was gamed before; every goto counted here is an edge that genuinely
  exists in the machine code. See the comment in the script.
- `INVENTED_FLAGS` and `STATE_MACHINES` — must stay 0.
- `CLEAN=n/total` — from `verify_fast.sh`, which compiles every decompiled body
  as its own TU in one parallel `cl` invocation.

## Behavioral equivalence

The real oracle. For each corpus DLL it compiles the decompiled C, then calls
every export in both the original and the decompiled build with identical random
and edge inputs, comparing returns and out-parameters:

```bash
python _qa/metrics/harness.py
```

"Perfect" = every function passes on every input.

`fixtures/selfdll/` is the same idea for hand-written single-file DLLs —
`difftest.sh <name>` builds `<name>.c`, decompiles it, and diffs the two runs'
stdout. Any difference is a semantic bug.

## Other metrics

| Script | Measures |
|---|---|
| `metrics/census.py` | Offender census over dumped pairs (register leaks, etc.) |
| `metrics/typescan.py` | Recovered signature vs. corpus ground truth |
| `metrics/irreducible.py` | Goto census + which are genuinely irreducible |
| `metrics/parity_scan.py` | Readability gap vs. Hex-Rays (not correctness) |
| `metrics/count_temps.py` | Temp/local declaration counts |
| `scripts/irreducibility.sh` | Provable T1-T2 reducibility report per function |
