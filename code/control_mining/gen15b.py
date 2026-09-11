import json, base64, ast, os
src=open('/tmp/nb2/gen.py').read()
ns={}; exec(src[:src.index("zb = open(")], ns)
C_INSTALL=ns['C_INSTALL']; C_LOAD=ns['C_LOAD']; C_FLOORS=ns['C_FLOORS']

C_TITLE = """# Phase 1.5b — Controls: is the probe reading *security* or *patch shape*?

Phase 1/1.5 found a layer-24 linear probe separates vulnerable from fixed Rust twins (~0.80 pairwise) while the
model's own answers sit at chance. But "fixed twin is longer" alone scores 0.807. This notebook runs the controls:

* **Test 1 — Transfer to non-security patches.** about 245 before/after function pairs from ordinary commits in the *same*
  repositories (no advisory, no security keywords, not adjacent to a fix), delta-matched to the CVE pairs.
  The CVE-trained probe is asked "which twin is vulnerable?". Chance (about 0.5) ⇒ security signal; about 0.8 ⇒ patch-shape.
* **Test 2 — Vulnerability-specific discrimination.** CVE-vulnerable vs control-before (both are "old versions"):
  AUC above the domain baseline (CVE-fixed vs control-after) ⇒ signal specific to vulnerability.
* **Test 3 — Length-residualised probe** on the CVE pairs (regress length out of every hidden dimension).
* **Test 4 — Length-only perturbation.** Pad the vulnerable twin with comment lines until it is the longer one;
  count how often the probe flips its choice.

Self-contained (data embedded). Runtime: T4. ~75 min."""

C_CONFIG = """#@title 2. Config
MODEL_BASE   = "Qwen/Qwen2.5-Coder-7B"
MAX_TOKENS   = 3000
CACHE_CVE    = "hs_cve.npz"
CACHE_CTL    = "hs_ctl.npz"
CACHE_PAD    = "hs_pad.npz"
SEED = 0
np.random.seed(SEED); torch.manual_seed(SEED)"""

C_LOADCTL = """#@title 3b. Load control (non-security) pairs
with zipfile.ZipFile("control.zip") as z: z.extractall("ctl")
cmeta = pd.read_csv("ctl/control_meta.csv")
rows=[]
for _,r in cmeta.iterrows():
    for sub,label in [("Before",1),("After",0)]:   # label 1 = "before" (plays the role of 'vulnerable' twin)
        rows.append(dict(cve=r["id"], cwe="", label=label, code=open(f"ctl/{sub}/{r['id']}.rs",encoding="utf-8",errors="replace").read(),
                         date=str(r["date"]), never_patched=False, repo=r["repo"], cat=r["cat"]))
dfc = pd.DataFrame(rows)
ctl_eqlen=set()
for pid,g in dfc.groupby("cve"):
    lb=len(g.loc[g.label==1,"code"].iloc[0]); la=len(g.loc[g.label==0,"code"].iloc[0])
    if abs(lb-la)<=20: ctl_eqlen.add(pid)
print(f"control pairs: {dfc.cve.nunique()}  samples: {len(dfc)}  repos: {dfc.repo.nunique()}  non-fix commits: {(cmeta['cat']=='nonfix').sum()}  eq-len: {len(ctl_eqlen)}")
print("CVE   frac fixed-longer :", np.mean([len(g.loc[g.label==0,'code'].iloc[0])>len(g.loc[g.label==1,'code'].iloc[0]) for c,g in df.groupby('cve') if set(g.label)=={0,1}]).round(3))
print("CTL   frac after-longer :", np.mean([len(g.loc[g.label==0,'code'].iloc[0])>len(g.loc[g.label==1,'code'].iloc[0]) for c,g in dfc.groupby('cve')]).round(3))

def pair_outcomes_df(d, scores, subset=None):
    out={}
    for k,g in d.assign(s=scores).groupby("cve"):
        if subset is not None and k not in subset: continue
        if set(g.label)=={0,1}:
            sv=g.loc[g.label==1,"s"].iloc[0]; sf=g.loc[g.label==0,"s"].iloc[0]
            out[k]= 1.0 if sv>sf else (0.5 if sv==sf else 0.0)
    return out
def pw(d, scores, subset=None):
    o=pair_outcomes_df(d,scores,subset); return sum(o.values())/len(o) if o else float("nan")
rng = np.random.default_rng(0)
def boot_ci(outcomes, iters=5000):
    vals=np.array(list(outcomes.values())); n=len(vals)
    bs=np.array([vals[rng.integers(0,n,n)].mean() for _ in range(iters)])
    return vals.mean(), np.percentile(bs,2.5), np.percentile(bs,97.5), n
# length floor on control: 'shorter twin is before'
ctl_len_scores = -dfc.code.str.len().values.astype(float)
print(f"control length rule ('shorter is before'): non-fix {pw(dfc, ctl_len_scores, set(dfc[dfc['cat']=='nonfix'].cve)):.3f}   bug-fix {pw(dfc, ctl_len_scores, set(dfc[dfc['cat']=='bugfix'].cve)):.3f}")"""

C_EXTRACT = """#@title 5. Extract mean-pooled hidden states: CVE set + control set (~50 min)
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
tok = AutoTokenizer.from_pretrained(MODEL_BASE)
model = AutoModelForCausalLM.from_pretrained(MODEL_BASE, device_map="auto", torch_dtype=torch.float16,
    quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16))
model.eval()
def extract(codes, cache):
    if os.path.exists(cache): return np.load(cache)["mean"]
    out=[]
    with torch.no_grad():
        for i,c in enumerate(codes):
            enc=tok(c, return_tensors="pt", truncation=True, max_length=MAX_TOKENS).to(model.device)
            hs=model(**enc, output_hidden_states=True).hidden_states
            out.append(torch.stack([h[0].mean(0) for h in hs]).float().cpu().numpy())
            if i%100==0: print(f"{cache} {i}/{len(codes)}")
    H=np.stack(out); np.savez_compressed(cache, mean=H); return H
H_cve = extract(list(df.code), CACHE_CVE)
H_ctl = extract(list(dfc.code), CACHE_CTL)
N,L1,d = H_cve.shape; print("CVE",H_cve.shape,"CTL",H_ctl.shape)"""

C_PROBE = """#@title 6. CVE probes per layer (grouped 5-fold CV) -> best layer
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import roc_auc_score
def mk(): return make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=0.5))
def cv_scores(H, d_, l):
    X=H[:,l,:]; s=np.zeros(len(d_))
    for tr,te in GroupKFold(5).split(X, d_.label, groups=d_.cve):
        s[te]=mk().fit(X[tr], d_.label.iloc[tr]).predict_proba(X[te])[:,1]
    return s
layer_scores={l:cv_scores(H_cve, df, l) for l in range(L1)}
for l in range(L1): print(f"L{l:2d}: pairwise {pw(df,layer_scores[l]):.3f}  eq-len {pw(df,layer_scores[l],eqlen):.3f}  AUC {roc_auc_score(df.label,layer_scores[l]):.3f}")
best_layer = max(layer_scores, key=lambda l: pw(df,layer_scores[l]))
probe_scores = layer_scores[best_layer]
cve_out = pair_outcomes_df(df, probe_scores)
m,lo,hi,n = boot_ci(cve_out)
print(f"BEST L{best_layer}: CVE pairwise {m:.3f} CI[{lo:.3f},{hi:.3f}] n={n}  AUC {roc_auc_score(df.label,probe_scores):.3f}")"""

C_TEST1 = """#@title 7. TEST 1 — Transfer: CVE-trained probe applied to non-security patches
results={}
transfer_curve={}
for l in range(L1):
    p=mk().fit(H_cve[:,l,:], df.label)
    transfer_curve[l]=pw(dfc, p.predict_proba(H_ctl[:,l,:])[:,1], set(dfc[dfc["cat"]=="nonfix"].cve))
probe_full = mk().fit(H_cve[:,best_layer,:], df.label)
ctl_scores = probe_full.predict_proba(H_ctl[:,best_layer,:])[:,1]
ctl_out = pair_outcomes_df(dfc, ctl_scores)
cat_of = dfc.drop_duplicates("cve").set_index("cve")["cat"].to_dict()
ctl_nonfix = {k:v for k,v in ctl_out.items() if cat_of[k]=="nonfix"}
ctl_bugfix = {k:v for k,v in ctl_out.items() if cat_of[k]=="bugfix"}
mc,loc,hic,nc = boot_ci(ctl_nonfix)            # HEADLINE control = non-security, non-fix commits (delta-matched)
mall,loall,hiall,nall = boot_ci(ctl_out)
mnf,lonf,hinf,nnf = mc,loc,hic,nc
mbf,lobf,hibf,nbf = boot_ci(ctl_bugfix) if ctl_bugfix else (float('nan'),)*3+(0,)
nonfix_ids=set(ctl_nonfix)
# also: how often does the probe agree with the length rule on control pairs?
ctl_len_out = pair_outcomes_df(dfc, ctl_len_scores)
agree = np.mean([ctl_out[k]==ctl_len_out[k] for k in ctl_nonfix])
print(f"CVE pairs   : probe picks vulnerable twin  {m:.3f}  CI[{lo:.3f},{hi:.3f}]  n={n}")
print(f"CONTROL (non-security, non-fix commits): probe picks 'before' twin  {mc:.3f}  CI[{loc:.3f},{hic:.3f}]  n={nc}   (length rule on these: {pw(dfc,ctl_len_scores,nonfix_ids):.3f}; agreement with length rule {agree:.3f})")
print(f"  secondary stratum, non-security BUG-FIX commits: {mbf:.3f} CI[{lobf:.3f},{hibf:.3f}] n={nbf}   |   all control pairs: {mall:.3f} n={nall}")
print("transfer curve (control 'before' rate by layer):", {l:round(v,3) for l,v in transfer_curve.items()})
gap = m - mc
print(f"GAP (CVE - control) = {gap:.3f}   -> interpretation: ~0 => patch-shape; large => security-specific")
results["test1"]=dict(cve=[m,lo,hi,n], control=[mc,loc,hic,nc], all_control=[mall,loall,hiall,nall], bugfix=[mbf,lobf,hibf,nbf], ctl_len_rule=pw(dfc,ctl_len_scores,nonfix_ids), agree_len=float(agree), curve=transfer_curve)"""

C_TEST2 = """#@title 8. TEST 2 — Vulnerability-specific discrimination (old-vs-old, new-vs-new)
def disc_auc(Xa, Xb, ga, gb):
    X=np.vstack([Xa,Xb]); y=np.r_[np.ones(len(Xa)),np.zeros(len(Xb))]; groups=np.r_[ga,gb]; s=np.zeros(len(y))
    for tr,te in GroupKFold(5).split(X,y,groups): s[te]=mk().fit(X[tr],y[tr]).predict_proba(X[te])[:,1]
    return roc_auc_score(y,s)
l=best_layer
vul = H_cve[df.label.values==1, l, :]; fix = H_cve[df.label.values==0, l, :]
bef = H_ctl[dfc.label.values==1, l, :]; aft = H_ctl[dfc.label.values==0, l, :]
g_v=df.cve.values[df.label.values==1]; g_f=df.cve.values[df.label.values==0]
g_b=dfc.cve.values[dfc.label.values==1]; g_a=dfc.cve.values[dfc.label.values==0]
auc_old = disc_auc(vul,bef,g_v,g_b)   # CVE-vulnerable vs control-before
auc_new = disc_auc(fix,aft,g_f,g_a)   # CVE-fixed vs control-after  (domain baseline)
# paired-difference version: (vuln - fixed) vs (before - after) direction vectors
dv = np.stack([H_cve[(df.cve==c)&(df.label==1),l,:][0]-H_cve[(df.cve==c)&(df.label==0),l,:][0] for c in pair_cves])
dc = np.stack([H_ctl[(dfc.cve==c)&(dfc.label==1),l,:][0]-H_ctl[(dfc.cve==c)&(dfc.label==0),l,:][0] for c in sorted(dfc.cve.unique())])
auc_diff = disc_auc(dv, dc, np.array(pair_cves), np.array(sorted(dfc.cve.unique())))
print(f"AUC  CVE-vulnerable vs control-before (old vs old) : {auc_old:.3f}")
print(f"AUC  CVE-fixed      vs control-after  (new vs new) : {auc_new:.3f}   <- domain/dataset baseline")
print(f"AUC  security-patch direction vs ordinary-patch direction (pair differences): {auc_diff:.3f}")
print(f"vulnerability-specific margin (old-vs-old minus new-vs-new): {auc_old-auc_new:+.3f}")
results["test2"]=dict(auc_old=auc_old, auc_new=auc_new, auc_diff=auc_diff)"""

C_TEST3 = """#@title 9. TEST 3 — Length-residualised probe on CVE pairs
from sklearn.linear_model import LinearRegression
def resid_cv(H, d_, l):
    X=H[:,l,:]; z=np.log1p(d_.code.str.len().values)[:,None]; s=np.zeros(len(d_))
    for tr,te in GroupKFold(5).split(X, d_.label, groups=d_.cve):
        reg=LinearRegression().fit(z[tr], X[tr])
        Rtr=X[tr]-reg.predict(z[tr]); Rte=X[te]-reg.predict(z[te])
        s[te]=mk().fit(Rtr, d_.label.iloc[tr]).predict_proba(Rte)[:,1]
    return s
res_scores = resid_cv(H_cve, df, best_layer)
res_out = pair_outcomes_df(df, res_scores); mr,lor,hir,nr = boot_ci(res_out)
res_auc = roc_auc_score(df.label, res_scores)
# residualised probe transferred to control (train on all CVE, apply to control after same residualisation)
z=np.log1p(df.code.str.len().values)[:,None]; zc=np.log1p(dfc.code.str.len().values)[:,None]
reg=LinearRegression().fit(z, H_cve[:,best_layer,:])
pr=mk().fit(H_cve[:,best_layer,:]-reg.predict(z), df.label)
res_ctl = pw(dfc, pr.predict_proba(H_ctl[:,best_layer,:]-reg.predict(zc))[:,1], nonfix_ids)
print(f"residualised probe L{best_layer}: CVE pairwise {mr:.3f} CI[{lor:.3f},{hir:.3f}]  AUC {res_auc:.3f}  eq-len {pw(df,res_scores,eqlen):.3f}")
print(f"residualised probe on control ('before' rate): {res_ctl:.3f}")
results["test3"]=dict(cve=[mr,lor,hir,nr], auc=res_auc, eqlen=pw(df,res_scores,eqlen), control=res_ctl)"""

C_TEST4 = """#@title 10. TEST 4 — Length-only perturbation: pad the vulnerable twin so it becomes the longer one (~10 min)
pad_targets=[]   # (cve, padded vulnerable code)
for c in pair_cves:
    g=df[df.cve==c]; v=g.loc[g.label==1,"code"].iloc[0]; f=g.loc[g.label==0,"code"].iloc[0]
    if len(f)>len(v)+20:
        need=(len(f)-len(v))*2   # make vulnerable longer by the same margin it was shorter
        line="// note: see documentation for details on this implementation.\\n"
        pad_targets.append((c, v.rstrip("\\n")+"\\n"+line*(need//len(line)+1)))
codes=[p[1] for p in pad_targets]
H_pad = extract(codes, CACHE_PAD)
# score padded vulnerable twin with the fold model that did NOT see this CVE (reuse CV folds)
X=H_cve[:,best_layer,:]; fold_of={}
folds=list(GroupKFold(5).split(X, df.label, groups=df.cve))
for fi,(tr,te) in enumerate(folds):
    for c in set(df.cve.iloc[te]): fold_of[c]=fi
fold_models={fi:mk().fit(X[tr], df.label.iloc[tr]) for fi,(tr,te) in enumerate(folds)}
flips=0; still=0; padded_out={}
for (c,_),h in zip(pad_targets, H_pad[:,best_layer,:]):
    fm=fold_models[fold_of[c]]
    sv_pad=fm.predict_proba(h[None])[0,1]
    sf=probe_scores[(df.cve==c)&(df.label==0)][0]
    before=cve_out[c]; after=1.0 if sv_pad>sf else 0.0
    padded_out[c]=after
    if before!=after: flips+=1
    else: still+=1
pad_rate=sum(padded_out.values())/len(padded_out)
orig_rate=sum(cve_out[c] for c in padded_out)/len(padded_out)
print(f"pairs where fixed twin was longer: {len(pad_targets)}")
print(f"probe picks vulnerable twin: original {orig_rate:.3f} -> after padding vulnerable twin to be longer {pad_rate:.3f}   (flipped {flips}, unchanged {still})")
print("interpretation: pure length detector -> rate collapses toward 0; code-reading probe -> rate roughly preserved")
results["test4"]=dict(n=len(pad_targets), orig=orig_rate, padded=pad_rate, flips=flips)"""

C_FINAL = """#@title 11. Final verdict table + results JSON
t1=results["test1"]; t2=results["test2"]; t3=results["test3"]; t4=results["test4"]
print("="*78)
print(f"{'TEST':50s}{'value':>10s}{'95% CI':>18s}")
print(f"{'CVE pairs: probe picks vulnerable (L'+str(best_layer)+')':50s}{t1['cve'][0]:10.3f}   [{t1['cve'][1]:.3f},{t1['cve'][2]:.3f}]")
print(f"{'CONTROL: probe picks before (should be ~0.5)':50s}{t1['control'][0]:10.3f}   [{t1['control'][1]:.3f},{t1['control'][2]:.3f}]")
print(f"{'   control length rule (shorter=before)':50s}{t1['ctl_len_rule']:10.3f}")
print(f"{'   non-security BUG-FIX commits (secondary)':50s}{t1['bugfix'][0]:10.3f}   [{t1['bugfix'][1]:.3f},{t1['bugfix'][2]:.3f}]")
print(f"{'AUC vuln vs control-before (old vs old)':50s}{t2['auc_old']:10.3f}")
print(f"{'AUC fixed vs control-after (domain baseline)':50s}{t2['auc_new']:10.3f}")
print(f"{'AUC patch-direction: security vs ordinary':50s}{t2['auc_diff']:10.3f}")
print(f"{'Length-residualised probe, CVE pairwise':50s}{t3['cve'][0]:10.3f}   [{t3['cve'][1]:.3f},{t3['cve'][2]:.3f}]")
print(f"{'   residualised AUC / eq-len / on control':50s}{t3['auc']:10.3f}   eq-len {t3['eqlen']:.3f}  control {t3['control']:.3f}")
print(f"{'Padding placebo: vuln-pick rate orig -> padded':50s}{t4['orig']:10.3f} -> {t4['padded']:.3f}  (n={t4['n']}, flips={t4['flips']})")
print("="*78)
verdict = "SECURITY-SPECIFIC" if (t1['control'][2] < t1['cve'][1]) else ("PATCH-SHAPE (probe transfers to ordinary patches)" if t1['control'][1] > 0.65 else "INCONCLUSIVE")
print("VERDICT:", verdict)
results["best_layer"]=int(best_layer); results["verdict"]=verdict
print("===RESULTS_JSON==="); print(json.dumps(results, default=float)); print("===END_JSON===")"""

zb = open('/mnt/user-data/outputs/dataset.zip','rb').read()
mb = open('/mnt/user-data/outputs/halurust_metadata.csv','rb').read()
cb = open('/tmp/ctrl/control.zip','rb').read()
C_DATA = ("#@title 2b. Materialize embedded data (CVE pairs + metadata)\nimport base64, os\n"
 + "_DZ='''" + base64.encodebytes(zb).decode() + "'''\n"
 + "_MD='''" + base64.encodebytes(mb).decode() + "'''\n"
 + "open('dataset.zip','wb').write(base64.b64decode(_DZ))\n"
 + "open('halurust_metadata.csv','wb').write(base64.b64decode(_MD))\n"
 + "del _DZ, _MD\n"
 + "print('materialized', os.path.getsize('dataset.zip'), os.path.getsize('halurust_metadata.csv'))")
C_DATA2 = ("#@title 2c. Materialize embedded control pairs\nimport base64, os\n"
 + "_CZ='''" + base64.encodebytes(cb).decode() + "'''\n"
 + "open('control.zip','wb').write(base64.b64decode(_CZ))\n"
 + "del _CZ\n"
 + "print('materialized', os.path.getsize('control.zip'))")

cells=[]
def md(s): cells.append({"cell_type":"markdown","metadata":{},"source":s})
def code(s):
    body='\n'.join(l for l in s.splitlines() if not l.strip().startswith('!'))
    ast.parse(body)
    cells.append({"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],"source":s})
md(C_TITLE); code(C_INSTALL); code(C_CONFIG); code(C_DATA); code(C_DATA2); code(C_LOAD); code(C_LOADCTL); code(C_FLOORS)
code(C_EXTRACT); code(C_PROBE); code(C_TEST1); code(C_TEST2); code(C_TEST3); code(C_TEST4); code(C_FINAL)
nb={"cells":cells,"metadata":{"colab":{"provenance":[],"gpuType":"T4"},"kernelspec":{"name":"python3","display_name":"Python 3"},"accelerator":"GPU"},"nbformat":4,"nbformat_minor":0}
json.dump(nb, open('/mnt/user-data/outputs/phase15b_controls_v2.ipynb','w'), indent=1)
print("OK all cells parse; size:", os.path.getsize('/mnt/user-data/outputs/phase15b_controls_v2.ipynb'))
