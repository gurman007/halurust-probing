import glob, os, re, numpy as np, pandas as pd
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import roc_auc_score

meta = pd.read_csv('/tmp/out/halurust_metadata.csv')
meta['date'] = meta[['advisory_date','commit_date']].fillna('').max(axis=1)
flagged = set(meta.loc[~meta.audit_verdict.eq('OK'),'cve'])
cve2 = meta.set_index('cve').to_dict('index')

def parse(fp):
    m = re.match(r'(CVE-\d{4}-\d+)', os.path.basename(fp)); return m.group(1) if m else None
neg = {parse(f): f for f in glob.glob('Negative/*.rs')}
rows=[]
skipped=[]
for f in sorted(glob.glob('Positive/*.rs')):
    cve = parse(f)
    if cve in flagged: skipped.append(cve); continue
    if cve not in neg: continue
    for path,label in [(f,1),(neg[cve],0)]:
        code=open(path,encoding='utf-8',errors='replace').read()
        rows.append(dict(cve=cve,label=label,code=code,date=str(cve2.get(cve,{}).get('date',''))))
df=pd.DataFrame(rows)
print(f'pairs kept: {df.cve.nunique()}  samples: {len(df)}  excluded by audit: {len(set(skipped))}')
print(f'post-2024 pairs: {df[df.date>="2024"].cve.nunique()}')

def pairwise(scores):
    a=n=0
    for cve,g in df.assign(s=scores).groupby('cve'):
        if set(g.label)=={0,1}:
            sv=g.loc[g.label==1,'s'].iloc[0]; sf=g.loc[g.label==0,'s'].iloc[0]
            a += 1.0 if sv>sf else (0.5 if sv==sf else 0.0); n+=1
    return a/n
def cv(X):
    s=np.zeros(len(df))
    for tr,te in GroupKFold(5).split(X,df.label,groups=df.cve):
        m=LogisticRegression(max_iter=2000).fit(X[tr],df.label.iloc[tr]); s[te]=m.predict_proba(X[te])[:,1]
    return s

res={}
res['length']       = df.code.str.len().values.astype(float)
res['line count']   = df.code.str.count('\n').values.astype(float)
res['unsafe count'] = df.code.str.count(r'\bunsafe\b').values.astype(float)
X=TfidfVectorizer(max_features=5000,token_pattern=r'\S+').fit_transform(df.code).toarray()
res['tfidf (grouped CV)']=cv(X)
print(f"\n{'floor':22s}{'AUC':>7s}{'pairwise':>10s}")
for k,s in res.items():
    print(f"{k:22s}{roc_auc_score(df.label,s):7.3f}{pairwise(s):10.3f}")
# random-split exhibit
from sklearn.model_selection import KFold
s=np.zeros(len(df))
for tr,te in KFold(5,shuffle=True,random_state=0).split(X):
    m=LogisticRegression(max_iter=2000).fit(X[tr],df.label.iloc[tr]); s[te]=m.predict_proba(X[te])[:,1]
print(f"\nrandom-split tfidf AUC (leakage exhibit): {roc_auc_score(df.label,s):.3f}")
df.to_pickle('/tmp/phase1/df.pkl')
