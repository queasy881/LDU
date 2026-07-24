#!/usr/bin/env python3
# IDA-parity anti-pattern census over the decompiled NullWare bodies in _qa/verify/*.c.
# Measures the readability gap vs Hex-Rays — NOT correctness (the harness/gate own that).
#
# Anti-patterns (each is a place our output reads worse than IDA would):
#   CASCADE    a temp assigned once and read exactly once whose RHS is side-effect-free
#              (no call, no memory read) -> IDA inlines it; a surviving one is pure noise.
#   LOADONCE   a temp assigned once from a single memory load and read exactly once
#              -> IDA usually inlines when no aliasing store/call intervenes.
#   COPY       a bare rename `tN = vM;` (or vN = tM) -> should have coalesced away.
#   DBLCAST    redundant nested casts e.g. (int)(unsigned int)x, (unsigned int)(int).
#   ADDRNOISE  `*(T*)&name` reinterprets that are necessary (kept as a baseline count).
#   RETSPLIT   >1 distinct `return <expr>;` with a non-trivial expr (IDA unifies to result).
import glob, os, re, collections

VER = os.path.join(os.path.dirname(__file__), "verify")
TMP = re.compile(r'\b([vt][0-9]+)\b')
ASSIGN = re.compile(r'^\s*([vt][0-9]+)\s*=\s*(.*?);\s*$')
DECL = re.compile(r'^\s*(?:unsigned\s+|signed\s+)?(?:long\s+long|long|int|char|short|float|double|void|__int64|struct\s+\w+)\s*\**\s*([vt][0-9]+)\s*(?:=|;)')
COPY = re.compile(r'^\s*([vt][0-9]+)\s*=\s*([vt][0-9]+)\s*;\s*$')
DBLCAST = re.compile(r'\((?:unsigned |signed )?(?:int|char|short|long|long long)\)\s*\((?:unsigned |signed )?(?:int|char|short|long|long long)\)')
RET = re.compile(r'^\s*return\s+(.*?);\s*$')

def bodies(path):
    """yield (name, [lines]) per function in a verify .c file (they hold one fn each)."""
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    yield os.path.basename(path), lines

tot = collections.Counter()
fn_with = collections.Counter()
worst = collections.Counter()   # per-function cascade+loadonce+copy count -> rank offenders

for f in glob.glob(os.path.join(VER, "fn_*.c")):
    for name, lines in bodies(f):
        text = "\n".join(lines)
        counts = collections.Counter(TMP.findall(text))
        local = collections.Counter()
        # per-temp classification
        assigned = {}
        for ln in lines:
            m = ASSIGN.match(ln)
            if m:
                assigned.setdefault(m.group(1), []).append(m.group(2))
        for t, rhs_list in assigned.items():
            if len(rhs_list) != 1:      # multi-def = genuine phi/mutable; skip (irreducible)
                continue
            uses = counts[t] - 1        # total occurrences minus the def LHS
            if uses != 1:
                continue
            rhs = rhs_list[0]
            has_call = re.search(r'\b(fun_|sub_)[0-9a-fA-F]+\s*\(', rhs) or re.search(r'\)\s*\(', rhs)
            reads_mem = '*(' in rhs or '->' in rhs or '[' in rhs
            if COPY.match("  " + t + " = " + rhs + ";"):
                local['COPY'] += 1
            elif has_call:
                pass                    # single-use call temp — often must stay (side effects/order)
            elif reads_mem:
                local['LOADONCE'] += 1
            else:
                local['CASCADE'] += 1
        # textual anti-patterns
        local['DBLCAST'] += len(DBLCAST.findall(text))
        local['ADDRNOISE'] += len(re.findall(r'\*\([^)]*\*\)\s*\(?&', text))
        rets = [r for r in (RET.match(l) for l in lines) if r]
        nontrivial = set(r.group(1) for r in rets if not re.fullmatch(r'[0-9x-]+|result|0|a[0-9]+', r.group(1)))
        if len(nontrivial) > 1:
            local['RETSPLIT'] += 1
        for k, v in local.items():
            tot[k] += v
            if v: fn_with[k] += 1
        worst[name] = local['CASCADE'] + local['LOADONCE'] + local['COPY']

print("==== IDA-PARITY ANTI-PATTERN CENSUS (1445 NullWare fns) ====")
for k in ['CASCADE', 'LOADONCE', 'COPY', 'DBLCAST', 'RETSPLIT', 'ADDRNOISE']:
    print(f"  {k:10s} total={tot[k]:6d}   in {fn_with[k]:4d} functions")
print("\n  worst 20 functions by (cascade+loadonce+copy):")
for name, n in worst.most_common(20):
    if n: print(f"    {n:4d}  {name}")
