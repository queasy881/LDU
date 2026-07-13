import json,html,io
p=r"C:\Users\User\AppData\Local\Temp\claude\C--Users-User-Downloads-sd\91017ac6-5602-4ef6-91fb-8cd68d533ce7\tasks\w6ybu7g3k.output"
data=json.loads(open(p,encoding='utf-8',errors='replace').read())["result"]
def U(s): return html.unescape(s or "")
print("LOGS:",data.get("category_clusters") and "ok")
print("audited:",data["audited"],"with_real_bugs:",len(data["with_real_bugs"]))
print("\n=== CATEGORY CLUSTERS ===")
for c in data["category_clusters"]:
    sev=c["severities"]
    print(f'{c["count"]:3d}  {c["category"]:26s} crit={sev.count("critical")} maj={sev.count("major")}')
