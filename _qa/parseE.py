import json,html
p=r"C:\Users\User\AppData\Local\Temp\claude\C--Users-User-Downloads-sd\91017ac6-5602-4ef6-91fb-8cd68d533ce7\tasks\wii3yf2d9.output"
data=json.loads(open(p,encoding='utf-8',errors='replace').read())["result"]
print("audited:",data["audited"],"with_real_bugs:",len(data["with_real_bugs"]))
print("=== CLUSTERS ===")
for c in data["category_clusters"][:18]:
    s=c["severities"]; print(f'{c["count"]:3d} {c["category"]:26s} crit={s.count("critical")} maj={s.count("major")}')
