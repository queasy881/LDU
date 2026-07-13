import re, glob, collections

PAIRS = r"C:\Users\User\Downloads\sd\_qa\pairs"

def classify(lines, i, tgt, label_line, loopdepth_at):
    sd = loopdepth_at[i]; td = loopdepth_at[tgt]
    back = tgt < i
    nxt = lines[tgt+1].strip() if tgt+1 < len(lines) else ""
    nxt2 = lines[tgt+2].strip() if tgt+2 < len(lines) else ""
    near_loop = nxt.startswith(("while","for")) or nxt2.startswith(("while","for"))
    # what does the label line itself + next look like
    labln = lines[tgt].strip()
    after = (lines[tgt+1].strip() if tgt+1<len(lines) else "")
    if back and sd > td:  return "ML: continue/break OUTER (Core-B)"
    if back and near_loop and sd==td: return "BACK: innermost continue"
    if back:              return "BACK: irreducible back-edge"
    if sd > td:           return "ML: break OUTER (fwd)"
    if td > sd:           return "FWD: into deeper loop"
    # forward same depth: refine by what the target is
    if re.match(r'return\b', after) or re.match(r'return\b', labln): return "FWD join: shared RETURN/epilogue"
    if sd>0:              return "FWD join: inside loop (shared continuation)"
    return "FWD join: top-level shared block"

buckets = collections.defaultdict(collections.Counter)   # gotocount-bucket -> shape counter
gating_fns = collections.defaultdict(list)               # shape -> [fn]
per_fn = {}

for f in sorted(glob.glob(PAIRS + r"\fn_*.txt")):
    txt = open(f, encoding="utf-8", errors="replace").read()
    if "--- DECOMPILED ---" not in txt: continue
    dec = txt.split("--- DECOMPILED ---", 1)[1]
    if "goto L_" not in dec: continue
    lines = dec.split("\n"); fn=f.split("\\")[-1]
    label_line={}; loopdepth_at=[0]*len(lines); stack=[]
    for i,ln in enumerate(lines):
        s=ln.strip()
        m=re.match(r'(L_[0-9a-fA-F]+)\s*:',s)
        if m: label_line[m.group(1)]=i
        loopdepth_at[i]=sum(1 for x in stack if x=='L')
        opens=s.count('{'); closes=s.count('}')
        is_loop=bool(re.search(r'\b(while|for)\b',s)) and '{' in s
        for _ in range(closes):
            if stack: stack.pop()
        for k in range(opens):
            stack.append('L' if (is_loop and k==opens-1) else 'O')
    shapes=[]
    for i,ln in enumerate(lines):
        m=re.search(r'goto\s+(L_[0-9a-fA-F]+)\s*;',ln)
        if not m: continue
        tgt=label_line.get(m.group(1))
        if tgt is None: shapes.append("DANGLING"); continue
        shapes.append(classify(lines,i,tgt,label_line,loopdepth_at))
    per_fn[fn]=shapes
    ng=len(shapes)
    bucket = "1 goto" if ng==1 else ("2 gotos" if ng==2 else ("3-5" if ng<=5 else "6+"))
    for sh in shapes: buckets[bucket][sh]+=1
    # a function's DISTINCT gating shapes
    for sh in set(shapes): gating_fns[sh].append(fn)

print("=== goto shapes by per-function goto-count bucket ===")
for b in ["1 goto","2 gotos","3-5","6+"]:
    tot=sum(buckets[b].values())
    nf=sum(1 for fn,s in per_fn.items() if (len(s)==1 and b=="1 goto") or (len(s)==2 and b=="2 gotos") or (3<=len(s)<=5 and b=="3-5") or (len(s)>=6 and b=="6+"))
    print(f"\n[{b}]  {nf} functions, {tot} gotos:")
    for sh,c in buckets[b].most_common(): print(f"   {c:4d}  {sh}")

print("\n=== # of SM functions that would be FULLY FREED if we handle each shape ===")
# a function is freed only if ALL its goto shapes are in the handled set
from itertools import combinations
shape_universe = set()
for s in per_fn.values(): shape_universe.update(s)
def freed_if(handled):
    return sum(1 for s in per_fn.values() if set(s) <= handled)
for sh in sorted(shape_universe):
    print(f"   handle only [{sh}]: frees {freed_if({sh})} fns")
print(f"\n   total SM fns: {len(per_fn)}")
# greedy: which single shape frees the most, then two, etc.
best1=max(shape_universe, key=lambda s: freed_if({s}))
print(f"   best single shape: {best1} -> {freed_if({best1})}")
for s2 in sorted(shape_universe):
    if s2==best1: continue
    print(f"   +{s2}: frees {freed_if({best1,s2})}")
