import json,html,io,re
p=r"C:\Users\User\AppData\Local\Temp\claude\C--Users-User-Downloads-sd\91017ac6-5602-4ef6-91fb-8cd68d533ce7\tasks\w6ybu7g3k.output"
data=json.loads(open(p,encoding='utf-8',errors='replace').read())["result"]
def U(s): return html.unescape(s or "")
flat=[(r["rva"],f) for r in data["with_real_bugs"] for f in r["findings"]]
fk=re.compile(r'float|xmm|double|andps|sqrt|movss|movsd|comis|cvt|packed|simd|nan|ucomis',re.I)
out=io.open(r"C:\Users\User\Downloads\sd\_qa\auditB_float_ptr.txt","w",encoding="utf-8")
nf=npt=0
for rva,f in flat:
    if f["severity"]=="cosmetic": continue
    blob=f["category"]+" "+f["description"]+" "+f["evidence"]
    isf=bool(fk.search(blob)); isp=("ptr" in f["category"] or "pointer" in f["category"])
    if isf or isp:
        out.write(f'\n[{rva}] {f["severity"].upper()} {f["category"]} {"(FLOAT)" if isf else "(PTR)"}\n')
        out.write("  D: "+U(f["description"])[:280]+"\n")
        out.write("  E: "+U(f["evidence"])[:380]+"\n")
        if isf: nf+=1
        else: npt+=1
out.close(); print("float-related:",nf,"ptr:",npt)
