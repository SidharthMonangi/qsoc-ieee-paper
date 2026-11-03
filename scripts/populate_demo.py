import httpx, json, sys
B="http://localhost:8000"; pw=open("/tmp/qsoc_demo_pw").read().strip()
c=httpx.Client(base_url=B,timeout=120)
t=c.post("/api/auth/login",json={"email":"admin@q-soc.demo","password":pw}).json()["access_token"]
h={"Authorization":f"Bearer {t}"}
sc=c.get("/api/simulator/scenarios",headers=h).json()
print("scenarios:",len(sc))
res=[]
for s in sc:
    r=c.post("/api/simulator/run",json={"scenario_id":s["scenario_id"]},headers=h)
    j=r.json() if r.status_code<300 else {"err":r.text[:200]}
    print(s["scenario_id"],r.status_code,j.get("status"),j.get("events_generated"),j.get("detection_confirmed"),j.get("err",""))
al=c.get("/api/alerts",headers=h,params={"limit":200}).json()
print("alerts",len(al))
sev={"critical":0}
top=[a for a in al if a["severity"] in("critical","high")][:3]
if top:
    r=c.post("/api/incidents",headers=h,json={"title":"Credential attack followed by successful login","description":"Investigation opened from correlated authentication alerts.","severity":top[0]["severity"],"alert_ids":[a["id"] for a in top]})
    print("incident",r.status_code)
    iid=r.json()["id"]
    c.patch(f"/api/incidents/{iid}",headers=h,json={"status":"INVESTIGATING","note":"Analyst reviewing source IP and account activity."})
inv=[("RSA-2048","TLS certificate","api.example.internal","Server authentication","production"),
("ECDSA-P256","Code signing","build-01","Release signing","production"),
("RSA-3072","VPN gateway","vpn.example.internal","Remote access","production"),
("ECDH-P256","TLS key exchange","web-01","Session key agreement","production"),
("AES-256","Disk encryption","db-01","Data at rest","production"),
("AES-128","Backup encryption","backup-01","Backups","staging"),
("SHA-256","Integrity","ci-01","Artifact hashing","production"),
("SHA-1","Legacy checksum","legacy-01","Legacy integrity","production"),
("3DES","Legacy payment link","pay-gw","Legacy protocol","production"),
("ML-DSA-65","Report signing","q-soc","Signed exports","production")]
algs=[a["algorithm"] if isinstance(a,dict) else a for a in c.get("/api/quantum/algorithms",headers=h).json()]
print("catalog",algs)
for alg,sysn,host,purp,env in inv:
    r=c.post("/api/quantum/inventory",headers=h,json={"algorithm":alg,"system":sysn,"purpose":purp,"hostname":host,"environment":env,"owner":"Platform Security"})
    if r.status_code>=300: print("inv fail",alg,r.status_code,r.text[:150]); continue
    aid=r.json()["id"]
    r2=c.post("/api/quantum/assess",headers=h,json={"algorithm":alg,"crypto_asset_id":aid})
    print("assess",alg,r2.status_code,r2.json().get("risk_classification") if r2.status_code<300 else r2.text[:120])
print("grover",c.get("/api/quantum/grover",headers=h,params={"target":"11","shots":1024}).status_code)
print("shor",c.get("/api/quantum/shor",headers=h,params={"shots":1024}).status_code)
r=c.get("/api/quantum/readiness",headers=h); print("readiness",r.status_code,json.dumps(r.json())[:400])
print(json.dumps(c.get("/api/dashboard/summary",headers=h).json())[:600])
