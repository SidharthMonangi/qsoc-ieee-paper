import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, numpy as np
plt.rcParams.update({"font.size":8,"font.family":"serif","axes.spines.top":False,"axes.spines.right":False})
sc=["auth_failure_burst","repeated_login_attempts","successful_login_after_failures","synthetic_port_scan","suspicious_web_request","privilege_escalation_indicator","suspicious_process_event","persistence_indicator","data_access_anomaly","ransomware_like_file_activity","ioc_test_indicator_match"]
med=[36.2,28.7,25.0,31.6,20.2,19.6,20.2,23.4,23.3,28.1,32.0]
p95=[51.0,55.0,35.5,43.6,30.4,39.4,39.8,51.5,52.1,55.4,70.9]
x=np.arange(len(sc)); fig,ax=plt.subplots(figsize=(3.5,2.6))
ax.bar(x-0.2,med,0.4,label="median",color="#2b6cb0"); ax.bar(x+0.2,p95,0.4,label="p95",color="#9fb8d9")
ax.set_xticks(x); ax.set_xticklabels([s.replace("_"," ") for s in sc],rotation=70,ha="right",fontsize=5.5)
ax.set_ylabel("in-process latency (ms)"); ax.legend(frameon=False,fontsize=7); fig.tight_layout(); fig.savefig("figures/fig12_e2_latency.pdf")
fig,ax=plt.subplots(figsize=(3.5,2.2))
names=["health","alerts list","events list\n(limit 100)","dashboard\nsummary","dashboard\ntimeline"]
m=[1.25,3.68,7.42,29.0,269.6]; p=[1.84,5.13,11.18,31.04,293.4]
x=np.arange(5); ax.bar(x-0.2,m,0.4,label="median",color="#2b6cb0"); ax.bar(x+0.2,p,0.4,label="p95",color="#9fb8d9")
ax.set_yscale("log"); ax.set_xticks(x); ax.set_xticklabels(names,fontsize=6); ax.set_ylabel("read latency (ms, log)")
ax.legend(frameon=False,fontsize=7); fig.tight_layout(); fig.savefig("figures/fig13_reads.pdf")
# throughput + latency per batch size
B=[1,10,100,500]
fig,ax=plt.subplots(figsize=(3.5,2.3))
for lab,v,c in [("heartbeat",[34.8,97.3,741.5,1525.5],"#2b6cb0"),("auth success",[25.7,104.8,797.5,1218.2],"#c05621"),("auth failure (distinct src)",[48.9,343.1,785.2,939.8],"#2f855a")]:
    ax.plot(B,v,marker="o",label=lab,color=c)
ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("batch size B"); ax.set_ylabel("median events/s"); ax.legend(frameon=False,fontsize=6)
fig.tight_layout(); fig.savefig("figures/fig14_throughput_types.pdf")
