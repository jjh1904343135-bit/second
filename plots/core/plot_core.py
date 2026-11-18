"""Plot measured core results only; missing/partial points stay explicitly missing."""
import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/"results/core"
plt.rcParams.update({"font.family":"serif","font.serif":["Times New Roman","DejaVu Serif"],"font.size":9,"axes.labelsize":9.5,"xtick.labelsize":8,"ytick.labelsize":8,"axes.linewidth":.8,"pdf.fonttype":42,"ps.fonttype":42})
COLORS=["#007a5e","#4e79a7","#e18727","#949ea8","#a46b9b"]
def load(p,default):
    return json.loads(p.read_text()) if p.exists() else default
def clean(ax):
    ax.spines[["top","right"]].set_visible(False)
    ax.yaxis.grid(True,ls="--",lw=.5,alpha=.4,zorder=0)
    ax.set_axisbelow(True)
def save(fig,folder,name):
    folder.mkdir(parents=True,exist_ok=True)
    fig.tight_layout()
    for ext in ["png","pdf","svg"]:
        fig.savefig(folder/f"{name}.{ext}",dpi=300,bbox_inches="tight")
    plt.close(fig)
def empty(ax,text):
    ax.text(.5,.5,text,ha="center",va="center",transform=ax.transAxes,color="#5b6470",fontsize=9)
def quartiles(values):
    values=np.asarray(values,dtype=float)
    return np.median(values),np.quantile(values,.25),np.quantile(values,.75)
def latest_frontier_result():
    candidates=[]
    for p in (OUT/"experiment2-frontier-cache").glob("*/results.json"):
        data=load(p,{})
        if data.get("status")=="COMPLETE":candidates.append((p,data))
    return sorted(candidates,key=lambda x:str(x[0]))[-1][1] if candidates else {}
def security():
    rows=load(OUT/"experiment1/summary.json",[])
    profiles=["FULL","NO_QUERY","NO_VALIDITY","NO_LINEAGE","NO_BINDING"]
    labels=["Full protocol","No complete query","No current validity","No lineage","No interface binding"]
    cats=["omission","invalid_reuse","lineage","substitution","reason"]
    fig,ax=plt.subplots(figsize=(8,3.1));clean(ax)
    observed=False
    for i,(p,label) in enumerate(zip(profiles,labels)):
        rs=[next((r for r in rows if r["profile"]==p and r["family"]==c),{}) for c in cats]
        vals=[r.get("interception_rate") for r in rs]
        x=np.arange(5)+(i-2)*.15
        for j,v in enumerate(vals):
            if v is None:continue
            observed=True
            ax.bar(x[j],100*v,width=.13,color=COLORS[i],edgecolor="#20262c",lw=.6,hatch=["","//","..","\\\\","xx"][i],label=label if j==next(k for k,vv in enumerate(vals) if vv is not None) else None,zorder=3)
            if v==0:ax.plot(x[j],0,marker="_",ms=5,color=COLORS[i],clip_on=False)
    if not observed:empty(ax,"No completed attack observations")
    else:ax.legend(ncol=3,frameon=False,fontsize=8,loc="upper center",bbox_to_anchor=(.5,1.26))
    ax.set(ylim=(0,110),ylabel="Attack interception (%)",xticks=np.arange(5),xticklabels=["Selective\nomission","Invalid evidence\nreuse","Lineage /\nduplication","Cross-proof\nsubstitution","Reason-code\nmasquerade"])
    save(fig,OUT/"experiment1","security_ablation")
def performance():
    """Plot only completed repeated measurements, never the timed-out sweep."""
    main_raw=OUT/"experiment2-main/capacity-3-16-16/raw.jsonl"
    samples=[]
    if main_raw.exists():
        samples=[json.loads(line) for line in main_raw.read_text().splitlines() if line.strip()]
        samples=[r for r in samples if r.get("stage")=="sample" and isinstance(r.get("rep"),int)]
    frontier=latest_frontier_result()
    fig,axes=plt.subplots(1,3,figsize=(10.4,3.05))
    for ax in axes:clean(ax)
    # (a) Complete main configuration: ten fresh proofs per arm.
    if samples:
        arms=["reuse","rebuild"]
        stages=[("state_online_ms","\u03a8 state",COLORS[0]),("wtns_ms","Joint witness",COLORS[1]),("joint_prove_ms","Joint proof",COLORS[2]),("B_verify_ms","B verification",COLORS[3])]
        x=np.arange(len(arms));bottom=np.zeros(len(arms));totals=[];iqrs=[]
        for key,label,color in stages:
            vals=[]
            for arm in arms:
                values=[s["stages"][0].get(key,0)/1000 for s in samples if s["arm"]==arm]
                vals.append(np.median(values))
            axes[0].bar(x,vals,bottom=bottom,width=.6,color=color,edgecolor="#20262c",lw=.55,label=label,zorder=3)
            bottom+=np.asarray(vals)
        for arm in arms:
            values=[s["wall_ms"]/1000 for s in samples if s["arm"]==arm]
            med,q1,q3=quartiles(values);totals.append(med);iqrs.append((med-q1,q3-med))
        axes[0].errorbar(x,totals,yerr=np.asarray(iqrs).T,fmt="none",ecolor="#20262c",capsize=3,lw=.8,zorder=4)
        for i,total in enumerate(totals):axes[0].text(i,total+18,f"{total:.0f}s",ha="center",va="bottom",fontsize=8,fontweight="bold")
        speedup=totals[1]/totals[0]
        axes[0].annotate(f"{speedup:.1f}\u00d7",xy=(1,totals[1]),xytext=(.52,max(totals)*.62),ha="center",fontsize=9,fontweight="bold",color="#00664e",arrowprops={"arrowstyle":"-","color":"#00664e","lw":.9})
        axes[0].legend(frameon=False,fontsize=7,ncol=2,loc="upper left",bbox_to_anchor=(.01,.98))
        axes[0].set_xticks(x,["\u03a8 reused","Genesis rebuild"])
        axes[0].set_ylim(0,max(totals)*1.22)
    else:empty(axes[0],"No complete 10-repeat\nmain configuration")
    axes[0].set(ylabel="Online task cost (s)",title="(a) Main configuration (n = 10 / arm)")
    # (b) New paired frontier-cache experiment: update readiness at two lags.
    summary=frontier.get("summary",[])
    if summary:
        deltas=[r["delta"] for r in summary]
        for arm,color,label in [("incremental",COLORS[0],"Incremental \u03a8"),("rebuild",COLORS[2],"Genesis rebuild")]:
            meds=[];lower=[];upper=[]
            for row in summary:
                stat=row["arms"][arm]["state_ready_ms"];meds.append(stat["median"]/1000);lower.append((stat["median"]-stat["q1"])/1000);upper.append((stat["q3"]-stat["median"])/1000)
            axes[1].errorbar(deltas,meds,yerr=[lower,upper],fmt="o-",lw=1.5,capsize=3,color=color,label=label)
        for row in summary:
            s=row["paired_speedup"]["state_ready_ms"]["median"]
            a=row["arms"]["incremental"]["state_ready_ms"]["median"]/1000
            b=row["arms"]["rebuild"]["state_ready_ms"]["median"]/1000
            axes[1].text(row["delta"],(a+b)/2,f"{s:.2f}\u00d7",ha="center",fontsize=8,fontweight="bold",color="#00664e",bbox={"facecolor":"white","edgecolor":"none","pad":.4,"alpha":.85})
        axes[1].legend(frameon=False,fontsize=7,loc="upper left")
        axes[1].set_xticks(deltas,[f"\u0394={d}" for d in deltas])
    else:empty(axes[1],"No completed paired\nfrontier experiment")
    axes[1].set(ylabel="State ready time (s)",xlabel="New events",title="(b) Cached frontier update (n = 3 pairs)")
    # (c) End-to-end improvement remains after including joint proofs.
    if summary:
        labels=["First task\nwith update","Mean of 3 tasks\nwith update"]
        metrics=["first_task_with_update_ms","avg_task_including_update_ms"]
        x=np.arange(len(summary));width=.32
        for j,(label,metric) in enumerate(zip(labels,metrics)):
            values=[row["paired_speedup"][metric]["median"] for row in summary]
            axes[2].bar(x+(j-.5)*width,values,width=width,color=[COLORS[1],COLORS[0]][j],edgecolor="#20262c",lw=.6,hatch=["//",""][j],label=label,zorder=3)
            for i,value in enumerate(values):axes[2].text(x[i]+(j-.5)*width,value+.012,f"{value:.2f}\u00d7",ha="center",fontsize=7.3)
        axes[2].axhline(1,color="#59636e",lw=.8,ls="--")
        axes[2].legend(frameon=False,fontsize=7,loc="upper left")
        axes[2].set_xticks(x,[f"\u0394={row['delta']}" for row in summary])
        axes[2].set_ylim(.9,max(max(row["paired_speedup"][m]["median"] for row in summary) for m in metrics)+.14)
    else:empty(axes[2],"No paired end-to-end\nfrontier measurements")
    axes[2].set(ylabel="Rebuild / incremental (\u00d7)",xlabel="New events",title="(c) End-to-end amortized gain")
    save(fig,OUT/"experiment2","cost_scaling_increment")
def agents():
    p=OUT/"experiment3/raw.jsonl";rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []
    fig,axes=plt.subplots(1,2,figsize=(8,2.9))
    for ax in axes:clean(ax)
    names=["normal","adverse_update","stale_memory","source_timeout"]
    for i,arm in enumerate(["RCPEH","PLAIN_COMPLETE"]):
        rs=[next((r for r in rows if r["scenario"]==n and r["arm"]==arm),None) for n in names]
        for ax,key,scale in [(axes[0],"task_wall_ms",1000),(axes[1],"handoff_bytes",1024)]:
            for j,r in enumerate(rs):
                if r:ax.bar(j+(i-.5)*.3,r[key]/scale,width=.27,color=COLORS[i],label=arm if j==0 else None,edgecolor="#20262c",lw=.6)
    for ax in axes:
        if not rows:empty(ax,"No completed agent replays")
        else:ax.legend(frameon=False,fontsize=8)
        ax.set_xticks(range(4),["Normal","Adverse\nupdate","Stale\nmemory","Source\ntimeout"])
    axes[0].set(ylabel="Frozen-trajectory replay (s)",title="(a) End-to-end cost (model separate)")
    axes[1].set(ylabel="B handoff (KiB)",title="(b) Actual structured communication")
    save(fig,OUT/"experiment3","agent_cost_disclosure")
security();performance();agents()
print("Generated core PNG / PDF / SVG from observed rows only")
