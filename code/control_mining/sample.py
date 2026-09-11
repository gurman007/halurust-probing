"""Select a delta-matched control set: match the CVE pairs' (fixed - vuln) char-delta
distribution with control (after - before) deltas, cap per-repo, prefer non-fix commits."""
import csv,os,json,random,collections,numpy as np,zipfile,shutil
random.seed(7); rng=np.random.default_rng(7)
P='/tmp/phase1/Positive';N='/tmp/phase1/Negative'
meta=list(csv.DictReader(open('/tmp/out/halurust_metadata.csv')))
ok={r['cve'] for r in meta if r['audit_verdict']=='OK'}
cve_delta=[]
for f in os.listdir(P):
    cve=f.split('_')[0]
    if cve not in ok: continue
    a=len(open(os.path.join(P,f),errors='ignore').read()); b=len(open(os.path.join(N,f),errors='ignore').read())
    cve_delta.append((b-a,a))
cve_delta=np.array(cve_delta)
print('CVE pairs used',len(cve_delta),'frac fixed longer',np.mean(cve_delta[:,0]>0))
BINS=[-1e9,-300,-50,0,50,200,600,1500,4000,1e9]
def binof(d): return int(np.digitize([d],BINS)[0])
target=collections.Counter(binof(d) for d,_ in cve_delta)
TARGET_N=len(cve_delta)  # same size as CVE set
ctrl=list(csv.DictReader(open('/tmp/ctrl/pairs/control_meta.csv')))
for r in ctrl: r['delta']=int(r['delta']); r['before_chars']=int(r['before_chars']); r['bin']=binof(r['delta'])
random.shuffle(ctrl)
ctrl.sort(key=lambda r:0 if r['cat']=='nonfix' else 1)
by_bin=collections.defaultdict(list)
for r in ctrl: by_bin[r['bin']].append(r)
chosen=[]; per_repo=collections.Counter()
for b,cnt in target.items():
    pool=by_bin.get(b,[])
    for r in pool:
        if cnt<=0: break
        if per_repo[r['repo']]>=5: continue
        chosen.append(r); per_repo[r['repo']]+=1; cnt-=1
    if cnt>0: print(f'bin {b} ({BINS[b-1]:.0f}..{BINS[b]:.0f}) short by {cnt}')
# fill remainder from any bin, keeping frac-after-longer close
have=len(chosen)
if have<TARGET_N:
    rest=[r for r in ctrl if r not in chosen and per_repo[r['repo']]<5]
    for r in rest[:TARGET_N-have]: chosen.append(r); per_repo[r['repo']]+=1
# secondary stratum: non-security *bug-fix* commits (does the probe detect 'bugginess' in general?)
bug=[r for r in ctrl if r['cat']=='bugfix' and r not in chosen]
random.shuffle(bug); bug.sort(key=lambda r:0 if r['delta']>0 else 1)  # keep mostly after-longer like CVE set
# take ~80% after-longer, 20% not
pos=[r for r in bug if r['delta']>0]; neg=[r for r in bug if r['delta']<=0]
bugpick=[]; prc=collections.Counter()
for r in pos:
    if len(bugpick)>=48: break
    if prc[r['repo']]>=3: continue
    bugpick.append(r); prc[r['repo']]+=1
for r in neg:
    if len(bugpick)>=60: break
    if prc[r['repo']]>=3: continue
    bugpick.append(r); prc[r['repo']]+=1
print('bugfix stratum',len(bugpick),'frac after longer',np.mean([r['delta']>0 for r in bugpick]))
chosen+=bugpick
cd=np.array([r['delta'] for r in chosen if r['cat']=='nonfix'])
print('control chosen',len(chosen),'frac after longer',np.mean(cd>0),'repos',len(per_repo),'nonfix',sum(r['cat']=='nonfix' for r in chosen))
print('CVE delta pct',np.percentile(cve_delta[:,0],[10,25,50,75,90]).round(0))
print('CTL delta pct',np.percentile(cd,[10,25,50,75,90]).round(0))
print('CVE vuln chars median',np.median(cve_delta[:,1]),'CTL before chars median',np.median([r['before_chars'] for r in chosen]))
out='/tmp/ctrl/control_set'; shutil.rmtree(out,ignore_errors=True); os.makedirs(f'{out}/Before'); os.makedirs(f'{out}/After')
for r in chosen:
    shutil.copy(f"/tmp/ctrl/pairs/Before/{r['id']}.rs",f"{out}/Before/"); shutil.copy(f"/tmp/ctrl/pairs/After/{r['id']}.rs",f"{out}/After/")
with open(f'{out}/control_meta.csv','w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=[k for k in chosen[0] if k!='bin']); w.writeheader()
    for r in chosen: w.writerow({k:v for k,v in r.items() if k!='bin'})
with zipfile.ZipFile('/tmp/ctrl/control.zip','w',zipfile.ZIP_DEFLATED) as z:
    for root,_,files in os.walk(out):
        for fn in files: z.write(os.path.join(root,fn),os.path.relpath(os.path.join(root,fn),out))
print('zip bytes',os.path.getsize('/tmp/ctrl/control.zip'))
