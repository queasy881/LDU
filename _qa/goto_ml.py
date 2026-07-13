import re, glob, collections, sys

PAIRS = r"C:\Users\User\Downloads\sd\_qa\pairs"
cat = collections.Counter()
per_fn_gotos = {}
examples = collections.defaultdict(list)

# For each function, parse the DECOMPILED C. Track brace stack, tagging each
# open brace as LOOP (while/for/do) or OTHER. For each `goto L_x`, find the
# label line and classify by the loop-nesting relationship:
#   - source loop-depth vs the loop-depth at the label
#   - whether the label sits at an ENCLOSING loop header (continue-outer) or
#     just after an enclosing loop close (break-outer) or elsewhere.
for f in sorted(glob.glob(PAIRS + r"\fn_*.txt")):
    txt = open(f, encoding="utf-8", errors="replace").read()
    if "--- DECOMPILED ---" not in txt: continue
    dec = txt.split("--- DECOMPILED ---", 1)[1]
    lines = dec.split("\n")
    if "goto L_" not in dec: continue
    fn = f.split("\\")[-1]

    # first pass: label line index + loop-depth at each line
    label_line = {}
    # compute per-line loop-depth by scanning braces
    loopdepth_at = [0]*len(lines)
    depth = 0
    stack = []  # list of 'L' or 'O'
    for i, ln in enumerate(lines):
        s = ln.strip()
        # record label defs
        m = re.match(r'(L_[0-9a-fA-F]+)\s*:', s)
        if m: label_line[m.group(1)] = i
        # loop-depth BEFORE processing this line's braces
        loopdepth_at[i] = sum(1 for x in stack if x == 'L')
        # process braces on this line (rough: a line opening a loop ends with '{')
        opens = s.count('{'); closes = s.count('}')
        is_loop_open = bool(re.search(r'\b(while|for)\b', s)) and '{' in s
        # handle closes first then opens (approx)
        for _ in range(closes):
            if stack: stack.pop()
        for k in range(opens):
            stack.append('L' if (is_loop_open and k == opens-1) else 'O')

    n_goto = 0
    for i, ln in enumerate(lines):
        m = re.search(r'goto\s+(L_[0-9a-fA-F]+)\s*;', ln)
        if not m: continue
        n_goto += 1
        lab = m.group(1)
        tgt = label_line.get(lab)
        if tgt is None:
            cat['DANGLING']+= 1; continue
        sd = loopdepth_at[i]     # loop-depth at the goto
        td = loopdepth_at[tgt]   # loop-depth at the label
        back = tgt < i
        # what's right after the label?
        nxt = lines[tgt+1].strip() if tgt+1 < len(lines) else ""
        nxt2 = lines[tgt+2].strip() if tgt+2 < len(lines) else ""
        near_loop = nxt.startswith(("while","for")) or nxt2.startswith(("while","for"))
        if back and sd > td:
            cat['BACK: source deeper -> continue/break OUTER loop (Core-B target)']+=1
            examples['MLBC'].append((fn, lab, f"sd{sd}>td{td}"))
        elif back and sd == td and near_loop:
            cat['BACK: same depth, label at loop header (continue innermost — should already be handled)']+=1
        elif back:
            cat['BACK: other (irreducible back-edge)']+=1
            examples['BACK_OTHER'].append((fn,lab,f"sd{sd},td{td}"))
        elif sd > td:
            cat['FWD: source deeper -> break OUTER loop (Core-B target)']+=1
            examples['MLBC'].append((fn, lab, f"fwd sd{sd}>td{td}"))
        elif td > sd:
            cat['FWD: into deeper loop (irreducible / entry into loop)']+=1
            examples['FWD_IN'].append((fn,lab,f"sd{sd}<td{td}"))
        else:
            cat['FWD: same depth (join/guard)']+=1
            examples['FWD_JOIN'].append((fn,lab,f"sd{sd}"))
    per_fn_gotos[fn] = n_goto

sm_fns = len(per_fn_gotos)
one_goto = sum(1 for v in per_fn_gotos.values() if v <= 2)
total = sum(cat.values())
print(f"would-be-SM functions: {sm_fns}  (<=2 gotos: {one_goto})")
print(f"total residual gotos: {total}\n")
print("=== goto shape distribution ===")
for k,v in cat.most_common():
    print(f"  {v:5d}  {k}")
print("\n=== sample Core-B (multi-level break/continue) targets ===")
for e in examples['MLBC'][:12]: print("  ", e)
print("=== sample FWD join/guard ===")
for e in examples['FWD_JOIN'][:6]: print("  ", e)
print("=== sample BACK other (irreducible) ===")
for e in examples['BACK_OTHER'][:6]: print("  ", e)
