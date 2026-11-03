"""Builds the demonstration-run figures and tables from data exported by the running Q-SOC API
(data/demo_data.json: dashboard summary, alerts, scenarios, inventory, assessments, experiments)."""
import json, collections
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
d=json.load(open("data/demo_data.json"))
plt.rcParams.update({"font.family":"serif","font.size":8,"axes.spines.top":False,"axes.spines.right":False,"axes.linewidth":0.6,"pdf.fonttype":42})
G="#4C72B0"; R="#C44E52"; O="#DD8452"; P="#8172B3"; K="#55A868"; Y="#937860"
def bars(ax,labels,vals,colors,title,rot=0,horizontal=False):
    if horizontal:
        ax.barh(labels,vals,color=colors,edgecolor="black",linewidth=0.4); ax.invert_yaxis()
        for i,v in enumerate(vals): ax.text(v+0.15,i,str(v),va="center",fontsize=7)
        ax.set_xlim(0,max(vals)*1.18)
    else:
        ax.bar(labels,vals,color=colors,edgecolor="black",linewidth=0.4)
        for i,v in enumerate(vals): ax.text(i,v+max(vals)*0.02,str(v),ha="center",fontsize=7)
        ax.set_ylim(0,max(vals)*1.18); plt.setp(ax.get_xticklabels(),rotation=rot,ha="right" if rot else "center")
    ax.set_title(title,fontsize=8)
# ---- Fig: demonstration overview (3 panels)
al=d["alerts"]; sev=collections.Counter(a["severity"] for a in al)
cat=collections.Counter(a["rule_id"].split(".")[0] for a in al)
order=["critical","high","medium"]
fig,ax=plt.subplots(1,3,figsize=(7.0,2.1))
bars(ax[0],order,[sev[s] for s in order],[P,R,O],"(a) Alerts by severity"); ax[0].set_ylabel("alerts")
cl=["auth","endpoint","network","web","threat_intel"]
bars(ax[1],["auth","endpoint","network","web","TI"],[cat[c] for c in cl],[G]*5,"(b) Alerts by rule category",rot=30)
th=d["summary"]["top_hosts"]
bars(ax[2],[h["host"] for h in th],[h["count"] for h in th],[K]*len(th),"(c) Events by host (top 5)",rot=30); ax[2].set_ylabel("events")
fig.tight_layout(); fig.savefig("figures/fig_demo_overview.pdf"); plt.close()
# ---- Fig: quantum readiness demonstration (3 panels)
s=d["summary"]; inv=d["inventory"]; asm=d["assessments"]
rs=collections.Counter(i["readiness_status"] for i in inv)
rc=collections.Counter(a["risk_classification"] for a in asm)
fig,ax=plt.subplots(1,3,figsize=(7.0,2.2))
comp=["Crypto\nreadiness","Migration\nprep.","Quantum\nexposure"]; score=[60,40,60]; w=[0.4,0.3,0.3]
x=range(3); ax[0].bar([i-0.2 for i in x],score,0.4,label="component score",color=G,edgecolor="black",linewidth=0.4)
ax[0].bar([i+0.2 for i in x],[sc*wi for sc,wi in zip(score,w)],0.4,label="weighted contribution",color=O,edgecolor="black",linewidth=0.4,hatch="//")
ax[0].set_xticks(list(x)); ax[0].set_xticklabels(comp,fontsize=7); ax[0].set_ylim(0,85); ax[0].legend(fontsize=6,frameon=False,loc="upper right")
ax[0].set_title("(a) QRI = %.0f"%s["quantum_readiness_index"],fontsize=8)
for i,(sc,wi) in enumerate(zip(score,w)):
    ax[0].text(i-0.2,sc+1.5,str(sc),ha="center",fontsize=6.5); ax[0].text(i+0.2,sc*wi+1.5,"%g"%(sc*wi),ha="center",fontsize=6.5)
st=["LEGACY","AT_RISK","PARTIALLY_READY","PQC_READY","UNKNOWN","NOT_ASSESSED"]; lab=["Legacy","At risk","Partly ready","PQC ready","Unknown","Not assessed"]
bars(ax[1],lab,[rs[k] for k in st],[R,O,Y,K,"#999999","#CCCCCC"],"(b) Readiness status (12 assets)",rot=35); plt.setp(ax[1].get_xticklabels(),fontsize=6.5)
ck=["HIGH","REVIEW","LOWER","UNKNOWN"]
bars(ax[2],ck,[rc[k] for k in ck],[R,O,K,"#999999"],"(c) Risk classification (10 assessed)"); plt.setp(ax[2].get_xticklabels(),fontsize=6.5)
fig.tight_layout(); fig.savefig("figures/fig_demo_quantum.pdf"); plt.close()
# ---- Fig: Qiskit measurement counts
ex={e["algorithm"]:e for e in d["experiments"]}
fig,ax=plt.subplots(1,2,figsize=(3.4,1.9))
g=ex["grover"]["measurement_counts"]; sh=ex["shor"]["measurement_counts"]
ax[0].bar(list(g),list(g.values()),color=G,edgecolor="black",linewidth=0.4); ax[0].set_title("(a) Grover, 1024 shots",fontsize=7); ax[0].set_ylim(0,1250)
for i,(k,v) in enumerate(g.items()): ax[0].text(i,v+25,str(v),ha="center",fontsize=6.5)
ks=sorted(sh); ax[1].bar(ks,[sh[k] for k in ks],color=P,edgecolor="black",linewidth=0.4); ax[1].set_title("(b) Shor $N{=}15$, 1024 shots",fontsize=7); ax[1].set_ylim(0,330)
for i,k in enumerate(ks): ax[1].text(i,sh[k]+6,str(sh[k]),ha="center",fontsize=6.5)
for a in ax: a.tick_params(labelsize=6.5)
ax[0].set_ylabel("counts",fontsize=7); fig.tight_layout(); fig.savefig("figures/fig_demo_qiskit.pdf"); plt.close()
# ---- Tables
evs={"auth_failure_burst":12,"repeated_login_attempts":6,"successful_login_after_failures":5,"synthetic_port_scan":12,"suspicious_web_request":1,
"privilege_escalation_indicator":1,"suspicious_process_event":1,"persistence_indicator":1,"data_access_anomaly":1,"ransomware_like_file_activity":6,"ioc_test_indicator_match":1}
amap={a["rule_id"]:a for a in al}
def tx(s): return s.replace("_","\\_")
rows=[]
for sc in d["scenarios"]:
    a=amap.get(sc["expected_detection_rule_id"]); ok=a is not None and a["severity"]==sc["expected_severity"] and (a["mitre_technique"]==sc["expected_mitre"])
    rows.append("%s & \\texttt{%s} & %s & %s & %s & %d & %s \\\\"%(tx(sc["scenario_id"]),tx(sc["expected_detection_rule_id"]),sc["expected_severity"],"%.2f"%a["confidence"] if a else "--",sc["expected_mitre"] or "none",evs[sc["scenario_id"]],"PASS" if ok else "FAIL"))
assert sum(evs.values())==s["total_events"], (sum(evs.values()),s["total_events"])
open("tables/scenario_rows.tex","w").write("\n".join(rows)+"\n\\bottomrule\n"); print("\n".join(rows)); print("allpass:",all("PASS" in r for r in rows))
inv_rows=[]
am={a["algorithm"].upper().replace("ECDH-P256","ECDH").replace("ECDSA-P256","ECDSA"):a for a in asm}
for i in inv:
    a=am.get(i["algorithm"].upper().replace("ECDH-P256","ECDH").replace("ECDSA-P256","ECDSA"))
    na=i["readiness_status"]=="NOT_ASSESSED"
    host=i["hostname"] or "seeded demo asset"
    inv_rows.append("%s & %s & %s & %s \\\\"%(i["algorithm"],tx(host),"not assessed" if (na or not a) else a["risk_classification"],tx(i["readiness_status"])))
open("tables/inventory_rows.tex","w").write("\n".join(inv_rows)+"\n\\bottomrule\n"); print("\n".join(inv_rows))
kp=[("Total events",s["total_events"]),("Alerts (critical / high / medium)","%d (%d / %d / %d)"%(s["total_alerts"],sev["critical"],sev["high"],sev["medium"])),
("Active incidents",s["active_incidents"]),("Validation runs passed / failed",f'{s["validation_runs"]["passed"]} / {s["validation_runs"]["failed"]}'),
("Threat-intel indicators (active / test)",f'{s["ioc_counts"]["active"]} / {s["ioc_counts"]["test"]}'),("Threat-intel matches",s["ioc_matches"]),
("Crypto inventory assets / assessments",f'{s["crypto_inventory_count"]} / {s["assessments_count"]}'),("Quantum-vulnerable algorithms (assessed)",s["quantum_vulnerable_algorithms"]),
("Quantum Readiness Index",f'{s["quantum_readiness_index"]:.0f}'),("Migration readiness",s["migration_readiness"].replace("%","\\%")),("Qiskit experiments run",s["experiments_count"])]
open("tables/kpi_rows.tex","w").write("\n".join("%s & %s \\\\"%(a,b) for a,b in kp)+"\n\\bottomrule\n")
print(open("tables/kpi_rows.tex").read())
