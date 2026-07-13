import json,html
p=r"C:\Users\User\AppData\Local\Temp\claude\C--Users-User-Downloads-sd\91017ac6-5602-4ef6-91fb-8cd68d533ce7\tasks\wqr53512o.output"
data=json.loads(open(p,encoding='utf-8',errors='replace').read())["result"]
def U(s): return html.unescape(s or "")
cats={"dropped-body","dropped_return_value","missing-return-value","missing-return-flow","register_tracking_dropped","missing-call","missing-xor-operand","wrong-control-structure","wrong-control-flow","duplicated-code","missing-condition"}
for r in data["with_real_bugs"]:
    for f in r["findings"]:
        if f["category"] in cats:
            print(f'\n[{r["rva"]}] {f["severity"]} {f["category"]}')
            print(" D:",U(f["description"])[:200])
            print(" E:",U(f["evidence"])[:280])
