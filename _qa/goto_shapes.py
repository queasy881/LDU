import re, glob, collections, sys

PAIRS = r"C:\Users\User\Downloads\sd\_qa\pairs"
cat = collections.Counter()
per_fn = collections.Counter()
examples = collections.defaultdict(list)

for f in sorted(glob.glob(PAIRS + r"\fn_*.txt")):
    txt = open(f, encoding="utf-8", errors="replace").read()
    if "--- DECOMPILED ---" not in txt: continue
    dec = txt.split("--- DECOMPILED ---", 1)[1]
    lines = dec.split("\n")
    # map label -> line index where "L_xxxx:" is defined
    label_line = {}
    for i, ln in enumerate(lines):
        m = re.match(r'\s*(L_[0-9a-fA-F]+)\s*:', ln)
        if m: label_line[m.group(1)] = i
    # for each goto, classify
    fn_has_goto = False
    for i, ln in enumerate(lines):
        m = re.search(r'goto\s+(L_[0-9a-fA-F]+)\s*;', ln)
        if not m: continue
        fn_has_goto = True
        lab = m.group(1)
        tgt = label_line.get(lab, None)
        if tgt is None:
            cat['DANGLING'] += 1; continue
        # is the target label immediately followed by a 'while' (loop header)?
        nxt = lines[tgt+1].strip() if tgt+1 < len(lines) else ""
        nxt2 = lines[tgt+2].strip() if tgt+2 < len(lines) else ""
        is_loop_hdr = nxt.startswith("while") or nxt.startswith("for") or nxt2.startswith("while")
        if tgt < i:  # back edge (target defined earlier)
            if is_loop_hdr: cat['BACK_to_loop_header (continue)'] += 1
            else: cat['BACK_to_nonloop (loop-not-recognized)'] += 1
            examples['BACK'].append((f.split("\\")[-1], lab))
        else:  # forward edge
            if is_loop_hdr: cat['FWD_to_loop_header (loop-placement)'] += 1
            else: cat['FWD_to_nonloop (join/guard)'] += 1
            examples['FWD'].append((f.split("\\")[-1], lab))
    if fn_has_goto: per_fn[f.split("\\")[-1]] += 1

total_gotos = sum(cat.values())
print("would-be-SM functions:", len(per_fn))
print("total residual gotos:", total_gotos)
print("\n=== goto shape distribution ===")
for k, v in cat.most_common():
    print(f"  {v:5d}  {k}")
print("\n=== sample forward-to-nonloop (join/guard) funcs ===")
for e in examples['FWD'][:8]: print("  ", e)
print("=== sample back-edge funcs ===")
for e in examples['BACK'][:8]: print("  ", e)
