import numpy as np, pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import roc_auc_score
df=pd.read_pickle('/tmp/phase1/df.pkl')
d=np.load('/tmp/phase1/hs_ckpt.npz')
H_last,H_mean=d['last'],d['mean']
assert len(H_last)==len(df), f"{len(H_last)} vs {len(df)}"
N,L,dim=H_last.shape
print(f'{N} samples x {L} layers x {dim} dims')
# equal-length pair subset (length gives no signal there)
eqlen=set()
for cve,g in df.groupby('cve'):
    if set(g.label)=={0,1}:
        lv=len(g.loc[g.label==1,'code'].iloc[0]); lf=len(g.loc[g.label==0,'code'].iloc[0])
        if abs(lv-lf)<=20: eqlen.add(cve)
print(f'near-equal-length pairs (|delta|<=20 chars): {len(eqlen)}')
def pairwise(s,subset=None):
    a=n=0
    for cve,g in df.assign(s=s).groupby('cve'):
        if subset is not None and cve not in subset: continue
        if set(g.label)=={0,1}:
            sv=g.loc[g.label==1,'s'].iloc[0]; sf=g.loc[g.label==0,'s'].iloc[0]
            a+= 1.0 if sv>sf else (0.5 if sv==sf else 0.0); n+=1
    return a/n if n else float('nan')
def probe(H,l):
    X=H[:,l,:]; s=np.zeros(N)
    for tr,te in GroupKFold(5).split(X,df.label,groups=df.cve):
        p=make_pipeline(StandardScaler(),LogisticRegression(max_iter=3000,C=0.5))
        p.fit(X[tr],df.label.iloc[tr]); s[te]=p.predict_proba(X[te])[:,1]
    return s
rows=[]
for name,H in [('last',H_last),('mean',H_mean)]:
    for l in range(L):
        s=probe(H,l)
        rows.append(dict(pool=name,layer=l,auc=roc_auc_score(df.label,s),
                         pw=pairwise(s),pw_eqlen=pairwise(s,eqlen)))
        r=rows[-1]; print(f"{name:5s} L{l:2d}  AUC {r['auc']:.3f}  pairwise {r['pw']:.3f}  eq-len {r['pw_eqlen']:.3f}",flush=True)
res=pd.DataFrame(rows); res.to_csv('/tmp/phase1/pilot_results.csv',index=False)
b=res.loc[res.pw.idxmax()]
print(f"\nBEST overall pairwise: {b.pw:.3f} ({b.pool} L{int(b.layer)})  [floor 0.807]")
b2=res.loc[res.pw_eqlen.idxmax()]
print(f"BEST eq-length pairwise: {b2.pw_eqlen:.3f} ({b2.pool} L{int(b2.layer)})  [floor 0.5]")
b3=res.loc[res.auc.idxmax()]
print(f"BEST AUC: {b3.auc:.3f} ({b3.pool} L{int(b3.layer)})  [tfidf floor 0.563]")
