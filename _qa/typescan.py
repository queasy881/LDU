#!/usr/bin/env python3
# Signature-accuracy scan: compare each decompiled export's signature against
# the ground-truth corpus source. Flags wrong return-type class, wrong param
# count (phantom / missing args), and goto/label presence. Corpus-only (we have
# source truth here).
import os, re, glob, collections

QA = r"C:\Users\User\Downloads\sd\_qa"
CORPUS = os.path.join(QA, "corpus")
DECOMP = os.path.join(QA, "decomp")

SIG = re.compile(
    r'(?:EXPORT\b|extern\s+"C"\s+__declspec\(dllexport\))\s+'
    r'([A-Za-z_][\w\s\*]*?)\s*\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.S)

def ret_class(r):
    r = r.strip()
    r = re.sub(r'\b(EXPORT|extern|__declspec\(dllexport\)|static|const)\b','',r).strip()
    if r == "void": return "void"
    if "*" in r: return "ptr"
    if "double" in r or "float" in r: return "fp"
    if "int64" in r or "long long" in r or ("long" in r and "unsigned long" not in r) or "size_t" in r: return "i64"
    if any(t in r for t in ("char","bool","int8","short","int16")): return "small"
    return "int"

def nparams(p):
    p = p.strip()
    if p in ("","void"): return 0
    return len([x for x in p.split(",") if x.strip()])

def src_sigs(dll):
    src = open(os.path.join(CORPUS, dll+".cpp"),encoding="utf-8",errors="replace").read()
    d={}
    for m in SIG.finditer(src):
        d[m.group(2)] = (ret_class(m.group(1)), nparams(m.group(3)))
    return d

# parse decompiled: "/* ==== name @ 0x... ==== */" then next line has the sig
DEC_HDR = re.compile(r'/\*\s*====\s*(\w+)\s*@')
def dec_sigs(dll):
    path = os.path.join(DECOMP, dll+".c")
    if not os.path.exists(path): return {}
    txt = open(path,encoding="utf-8",errors="replace").read()
    d={}
    parts = txt.split("/* ==== ")
    for ch in parts[1:]:
        m = re.match(r'(\w+)\s*@', ch)
        if not m: continue
        name = m.group(1)
        # find the function definition line: first line matching  <ret> name(
        mdef = re.search(r'\n([A-Za-z_][\w\s\*]*?\b'+re.escape(name)+r')\s*\(([^)]*)\)\s*\{', ch)
        if not mdef: continue
        rettoks = mdef.group(1)[:mdef.group(1).rfind(name)]
        d[name] = (ret_class(rettoks), nparams(mdef.group(2)), ch)
    return d

def main():
    tot_fn=0; ret_bad=0; parm_bad=0; goto_fn=0
    ret_detail=collections.Counter(); rows=[]
    for cf in sorted(glob.glob(os.path.join(CORPUS,"*.cpp"))):
        dll = os.path.splitext(os.path.basename(cf))[0]
        if not os.path.exists(os.path.join(DECOMP,dll+".c")): continue
        S=src_sigs(dll); D=dec_sigs(dll)
        for name,(sret,sn) in S.items():
            if name not in D: continue
            dret,dn,body = D[name]
            tot_fn+=1
            rb = sret!=dret
            # tolerate int<->small (both 32-bit-ish) only when NOT the named case
            pb = sn!=dn
            gt = "goto " in body
            if rb: ret_bad+=1; ret_detail["%s->%s"%(dret,sret)]+=1
            if pb: parm_bad+=1
            if gt: goto_fn+=1
            if rb or pb or gt:
                rows.append("%-16s %-28s ret dec=%-5s src=%-5s | parm dec=%d src=%d%s"%(
                    dll,name,dret,sret,dn,sn," GOTO" if gt else ""))
    print("functions compared:",tot_fn)
    print("wrong return-type class:",ret_bad)
    print("wrong param count     :",parm_bad)
    print("functions with goto   :",goto_fn)
    print("\nreturn mismatch (dec->src):")
    for k,v in ret_detail.most_common(): print("  %-16s %d"%(k,v))
    print("\n---- offenders ----")
    for r in rows: print(r)

if __name__=="__main__": main()
