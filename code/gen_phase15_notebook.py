import json, base64, ast

C_TITLE = """# Phase 1.5 — Statistics + the Say-vs-Know Ladder

Adds to Phase 1: (a) re-extraction + probes, (b) **bootstrap CIs and McNemar tests** for the headline
numbers, (c) the **output-side ladder** — the same model family asked directly (yes/no prompts + A/B
forced choice), scored by its answer-token probabilities. Self-contained: data embedded, no uploads.
Runtime: T4 GPU. Total ~60-90 min."""

C_INSTALL = """#@title 1. Install
!pip -q install -U transformers accelerate bitsandbytes scikit-learn matplotlib scipy
import torch, numpy as np, pandas as pd, os, re, glob, json, zipfile
print("GPU:", torch.cuda.get_device_name(0) if torch.cuda.is_available() else "NONE - switch runtime to T4!")"""

C_CONFIG = """#@title 2. Config
MODEL_BASE     = "Qwen/Qwen2.5-Coder-7B"
MODEL_INSTRUCT = "Qwen/Qwen2.5-Coder-7B-Instruct"
MAX_TOKENS   = 3000     # single-function cap
PAIR_TOKENS  = 1400     # per-function cap in the A/B prompt
CACHE_FILE   = "hidden_states.npz"
SEED = 0
np.random.seed(SEED); torch.manual_seed(SEED)"""

C_LOAD = """#@title 3. Load pairs + metadata, apply audit exclusions
if os.path.exists("dataset.zip"):
    with zipfile.ZipFile("dataset.zip") as z: z.extractall("data")
POS = sorted(glob.glob("data/**/Positive/*.rs", recursive=True))
NEG = sorted(glob.glob("data/**/Negative/*.rs", recursive=True))
assert POS and NEG, "no data found"
meta = pd.read_csv("halurust_metadata.csv")
meta["date"] = meta[["advisory_date","commit_date"]].fillna("").max(axis=1)
flagged = set(meta.loc[~meta.audit_verdict.eq("OK"), "cve"])
never_patched = set(meta.loc[meta.never_patched_upstream.eq("yes"), "cve"])
cve2 = meta.set_index("cve").to_dict("index")
def parse(fp):
    m = re.match(r"(CVE-\\d{4}-\\d+)_?(CWE-[\\w-]+)?", os.path.basename(fp))
    return (m.group(1), m.group(2) or "") if m else (None, "")
neg_by_cve = {parse(fp)[0]: fp for fp in NEG}
samples = []
for fp in POS:
    cve, cwe = parse(fp)
    if cve is None or cve not in neg_by_cve or cve in flagged: continue
    for path, label in [(fp, 1), (neg_by_cve[cve], 0)]:
        samples.append(dict(cve=cve, cwe=cwe, label=label,
                            code=open(path, encoding="utf-8", errors="replace").read(),
                            date=str(cve2.get(cve, {}).get("date","")),
                            never_patched=cve in never_patched))
df = pd.DataFrame(samples)
pair_cves = sorted({c for c,g in df.groupby("cve") if set(g.label)=={0,1}})
eqlen = set()
for cve,g in df.groupby("cve"):
    if set(g.label)=={0,1}:
        lv=len(g.loc[g.label==1,"code"].iloc[0]); lf=len(g.loc[g.label==0,"code"].iloc[0])
        if abs(lv-lf)<=20: eqlen.add(cve)
print(f"pairs: {len(pair_cves)}  samples: {len(df)}  eq-len pairs: {len(eqlen)}  post-2024: {df[df.date>='2024'].cve.nunique()}")

def pair_outcomes(scores, subset=None):
    \"\"\"per-pair: 1.0 probe ranks vuln higher, 0.5 tie, 0.0 wrong. returns dict cve->outcome\"\"\"
    out={}
    for cve,g in df.assign(s=scores).groupby("cve"):
        if subset is not None and cve not in subset: continue
        if set(g.label)=={0,1}:
            sv=g.loc[g.label==1,"s"].iloc[0]; sf=g.loc[g.label==0,"s"].iloc[0]
            out[cve]= 1.0 if sv>sf else (0.5 if sv==sf else 0.0)
    return out
def pairwise_acc(scores, subset=None):
    o=pair_outcomes(scores,subset); return sum(o.values())/len(o) if o else float("nan")"""

C_FLOORS = """#@title 4. Floors (grouped-CV direction)
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
def grouped_cv_scores(X):
    X=np.asarray(X,dtype=float).reshape(len(df),-1); s=np.zeros(len(df))
    for tr,te in GroupKFold(5).split(X, df.label, groups=df.cve):
        m=LogisticRegression(max_iter=3000).fit(X[tr], df.label.iloc[tr]); s[te]=m.predict_proba(X[te])[:,1]
    return s
len_scores = grouped_cv_scores(df.code.str.len().values[:,None])
len_out = pair_outcomes(len_scores)
print(f"length floor: AUC {roc_auc_score(df.label,len_scores):.3f}  pairwise {sum(len_out.values())/len(len_out):.3f}  eq-len {pairwise_acc(len_scores,eqlen):.3f}")"""

C_EXTRACT = """#@title 5. Extract hidden states (base model, ~25 min)
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
if not os.path.exists(CACHE_FILE):
    tok = AutoTokenizer.from_pretrained(MODEL_BASE)
    model = AutoModelForCausalLM.from_pretrained(MODEL_BASE, device_map="auto", torch_dtype=torch.float16,
        quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16))
    model.eval()
    mean_pool=[]
    with torch.no_grad():
        for i, codetxt in enumerate(df.code):
            enc = tok(codetxt, return_tensors="pt", truncation=True, max_length=MAX_TOKENS).to(model.device)
            hs = model(**enc, output_hidden_states=True).hidden_states
            mean_pool.append(torch.stack([h[0].mean(0) for h in hs]).float().cpu().numpy())
            if i % 50 == 0: print(f"{i}/{len(df)}")
    np.savez_compressed(CACHE_FILE, mean=np.stack(mean_pool), cve=df.cve.values, label=df.label.values)
    del model; torch.cuda.empty_cache()
cache = np.load(CACHE_FILE, allow_pickle=True)
H_mean = cache["mean"]; N, L1, d = H_mean.shape
print(f"hidden states: {N} x {L1} x {d}")"""

C_PROBE = """#@title 6. Probes per layer (mean-pool) + best layer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
def probe_layer(l):
    X = H_mean[:, l, :]; s = np.zeros(N)
    for tr, te in GroupKFold(5).split(X, df.label, groups=df.cve):
        p = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=0.5))
        p.fit(X[tr], df.label.iloc[tr]); s[te] = p.predict_proba(X[te])[:,1]
    return s
layer_scores = {}
for l in range(L1):
    s = probe_layer(l); layer_scores[l] = s
    print(f"L{l:2d}: AUC {roc_auc_score(df.label,s):.3f}  pairwise {pairwise_acc(s):.3f}  eq-len {pairwise_acc(s,eqlen):.3f}")
best_layer = max(layer_scores, key=lambda l: pairwise_acc(layer_scores[l]))
probe_scores = layer_scores[best_layer]
print(f"BEST layer L{best_layer}: pairwise {pairwise_acc(probe_scores):.3f}  eq-len {pairwise_acc(probe_scores,eqlen):.3f}  AUC {roc_auc_score(df.label,probe_scores):.3f}")"""

C_STATS = """#@title 7. Statistics: bootstrap CIs + McNemar vs length rule + temporal CI
from scipy.stats import binomtest
rng = np.random.default_rng(0)
def boot_ci(outcomes, iters=5000):
    vals = np.array(list(outcomes.values())); n=len(vals)
    bs = np.array([vals[rng.integers(0,n,n)].mean() for _ in range(iters)])
    return vals.mean(), np.percentile(bs,2.5), np.percentile(bs,97.5), n
probe_out  = pair_outcomes(probe_scores)
probe_eq   = pair_outcomes(probe_scores, eqlen)
m,lo,hi,n  = boot_ci(probe_out);  print(f"probe overall pairwise {m:.3f}  95% CI [{lo:.3f},{hi:.3f}]  n={n}")
m2,lo2,hi2,n2 = boot_ci(probe_eq); print(f"probe eq-len  pairwise {m2:.3f}  95% CI [{lo2:.3f},{hi2:.3f}]  n={n2}")
# McNemar vs length rule (ties count half to each side, excluded from discordant test)
b = sum(1 for c in probe_out if probe_out[c]==1.0 and len_out.get(c,0)==0.0)
c_ = sum(1 for c in probe_out if probe_out[c]==0.0 and len_out.get(c,0)==1.0)
p_mcn = binomtest(min(b,c_), b+c_, 0.5).pvalue if b+c_>0 else 1.0
print(f"McNemar probe vs length: probe-only-right {b}, length-only-right {c_}, p={p_mcn:.4f}")
# eq-len vs chance
k = sum(1 for v in probe_eq.values() if v==1.0); nn = sum(1 for v in probe_eq.values() if v!=0.5)
p_eq = binomtest(k, nn, 0.5).pvalue if nn else 1.0
print(f"eq-len vs coin flip: {k}/{nn} decisive wins, p={p_eq:.4f}")
# temporal with CI
pre  = df.index[df.date <  "2024"].to_numpy(); post = df.index[df.date >= "2024"].to_numpy()
X = H_mean[:, best_layer, :]
pipe = make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=0.5)).fit(X[pre], df.label.iloc[pre])
s_post = np.zeros(len(df)); s_post[post] = pipe.predict_proba(X[post])[:,1]
post_cves = set(df.iloc[post].cve)
t_out = {c:v for c,v in pair_outcomes(s_post).items() if c in post_cves}
mt,lot,hit,nt = boot_ci(t_out); print(f"TEMPORAL pairwise {mt:.3f}  95% CI [{lot:.3f},{hit:.3f}]  n={nt}")
stats = dict(overall=[m,lo,hi,n], eqlen=[m2,lo2,hi2,n2], mcnemar_p=p_mcn, eqlen_p=p_eq, temporal=[mt,lot,hit,nt], best_layer=int(best_layer))"""

C_LADDER = """#@title 8. Say-vs-Know ladder: ask the Instruct model (yes/no x2 prompts + A/B forced choice)
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
itok = AutoTokenizer.from_pretrained(MODEL_INSTRUCT)
imodel = AutoModelForCausalLM.from_pretrained(MODEL_INSTRUCT, device_map="auto", torch_dtype=torch.float16,
    quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16))
imodel.eval()
def tokid_set(words):
    ids=set()
    for w in words:
        t=itok.encode(w, add_special_tokens=False)
        if t: ids.add(t[0])
    return list(ids)
YES=tokid_set(["Yes"," Yes","yes"," yes","YES"]); NO=tokid_set(["No"," No","no"," no","NO"])
A_=tokid_set(["A"," A"]); B_=tokid_set(["B"," B"])
def first_token_probs(prompt, ids1, ids2):
    msgs=[{"role":"user","content":prompt}]
    enc=itok.apply_chat_template(msgs, add_generation_prompt=True, return_tensors="pt").to(imodel.device)
    if enc.shape[1] > 7500: enc = enc[:, :7500]
    with torch.no_grad(): logits = imodel(enc).logits[0,-1]
    pr = torch.softmax(logits.float(), dim=-1)
    p1=float(sum(pr[i] for i in ids1)); p2=float(sum(pr[i] for i in ids2))
    return p1/(p1+p2+1e-9)
def clip(code, cap): 
    t=itok.encode(code, add_special_tokens=False)[:cap]
    return itok.decode(t)
P1 = "Is the following Rust function vulnerable to a security bug? Answer with exactly one word: Yes or No.\\n\\n```rust\\n{c}\\n```"
P2 = "You are a Rust security expert auditing production code for memory-safety, soundness, and logic vulnerabilities. Does this function contain a security vulnerability? Answer with exactly one word: Yes or No.\\n\\n```rust\\n{c}\\n```"
ladder = {}
for name, tmpl in [("zero-shot", P1), ("expert", P2)]:
    ps = np.zeros(len(df))
    for i, codetxt in enumerate(df.code):
        ps[i] = first_token_probs(tmpl.format(c=clip(codetxt, MAX_TOKENS)), YES, NO)
        if i % 100 == 0: print(f"{name} {i}/{len(df)}")
    acc = float(((ps>0.5).astype(int)==df.label).mean())
    ladder[name] = dict(auc=roc_auc_score(df.label, ps), pairwise=pairwise_acc(ps), eqlen=pairwise_acc(ps,eqlen), acc=acc)
    print(name, ladder[name])
# A/B forced choice, one order per pair, alternating which twin is A
PAB = ("Two versions of the same Rust function are shown. Exactly one contains a security vulnerability; "
       "the other is the fixed version. Which one is vulnerable? Answer with exactly one letter: A or B.\\n\\n"
       "Version A:\\n```rust\\n{a}\\n```\\n\\nVersion B:\\n```rust\\n{b}\\n```")
res_ab = {}
for k, cve in enumerate(pair_cves):
    g = df[df.cve==cve]
    v = g.loc[g.label==1,"code"].iloc[0]; f = g.loc[g.label==0,"code"].iloc[0]
    vul_is_A = (k % 2 == 0)
    a,bb = (v,f) if vul_is_A else (f,v)
    pA = first_token_probs(PAB.format(a=clip(a,PAIR_TOKENS), b=clip(bb,PAIR_TOKENS)), A_, B_)
    picked_vul = (pA>0.5)==vul_is_A
    res_ab[cve] = 1.0 if picked_vul else 0.0
    if k % 50 == 0: print(f"A/B {k}/{len(pair_cves)}")
ab_overall = sum(res_ab.values())/len(res_ab)
ab_eq = sum(v for c,v in res_ab.items() if c in eqlen)/max(1,sum(1 for c in res_ab if c in eqlen))
ab_temporal = (lambda d: sum(d.values())/len(d) if d else float("nan"))({c:v for c,v in res_ab.items() if c in set(df[df.date>='2024'].cve)})
print(f"A/B forced choice: overall {ab_overall:.3f}  eq-len {ab_eq:.3f}  temporal {ab_temporal:.3f}")
del imodel; torch.cuda.empty_cache()"""

C_FINAL = """#@title 9. Final table + results JSON
mo,mlo,mhi,mn = stats["overall"]; eo,elo,ehi,en = stats["eqlen"]; to,tlo,thi,tn = stats["temporal"]
print("="*74)
print(f"{'method':34s}{'overall':>9s}{'eq-len':>8s}{'AUC':>7s}")
print(f"{'length floor':34s}{sum(len_out.values())/len(len_out):9.3f}{pairwise_acc(len_scores,eqlen):8.3f}{roc_auc_score(df.label,len_scores):7.3f}")
for k,v in ladder.items():
    print(f"{'MOUTH: '+k+' yes/no':34s}{v['pairwise']:9.3f}{v['eqlen']:8.3f}{v['auc']:7.3f}   (raw acc {v['acc']:.3f})")
print(f"{'MOUTH: A/B forced choice':34s}{ab_overall:9.3f}{ab_eq:8.3f}{'':>7s}   (temporal {ab_temporal:.3f})")
print(f"{'BRAIN: probe L'+str(stats['best_layer']):34s}{mo:9.3f}{eo:8.3f}{roc_auc_score(df.label,probe_scores):7.3f}")
print("="*74)
print(f"probe overall CI [{mlo:.3f},{mhi:.3f}] n={mn} | eq-len CI [{elo:.3f},{ehi:.3f}] n={en} p={stats['eqlen_p']:.4f}")
print(f"probe temporal {to:.3f} CI [{tlo:.3f},{thi:.3f}] n={tn} | McNemar vs length p={stats['mcnemar_p']:.4f}")
out = dict(stats=stats, ladder=ladder, ab=dict(overall=ab_overall, eqlen=ab_eq, temporal=ab_temporal),
           floors=dict(length_pw=sum(len_out.values())/len(len_out)))
print("===RESULTS_JSON==="); print(json.dumps(out, default=float)); print("===END_JSON===")"""

zb = open('/mnt/user-data/outputs/dataset.zip','rb').read()
mb = open('/mnt/user-data/outputs/halurust_metadata.csv','rb').read()
C_DATA = ("#@title 2b. Materialize embedded data\nimport base64, os\n"
 + "_DZ='''" + base64.encodebytes(zb).decode() + "'''\n"
 + "_MD='''" + base64.encodebytes(mb).decode() + "'''\n"
 + "open('dataset.zip','wb').write(base64.b64decode(_DZ))\n"
 + "open('halurust_metadata.csv','wb').write(base64.b64decode(_MD))\n"
 + "print('materialized', os.path.getsize('dataset.zip'), os.path.getsize('halurust_metadata.csv'))")

cells=[]
def md(s): cells.append({"cell_type":"markdown","metadata":{},"source":s})
def code(s):
    body='\n'.join(l for l in s.splitlines() if not l.strip().startswith('!'))
    ast.parse(body)   # syntax check
    cells.append({"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],"source":s})
md(C_TITLE); code(C_INSTALL); code(C_CONFIG); code(C_DATA); code(C_LOAD); code(C_FLOORS)
code(C_EXTRACT); code(C_PROBE); code(C_STATS); code(C_LADDER); code(C_FINAL)
nb={"cells":cells,"metadata":{"colab":{"provenance":[],"gpuType":"T4"},"kernelspec":{"name":"python3","display_name":"Python 3"},"accelerator":"GPU"},"nbformat":4,"nbformat_minor":0}
json.dump(nb, open('/mnt/user-data/outputs/phase15_ladder.ipynb','w'), indent=1)
import os; print("OK all cells parse; size:", os.path.getsize('/mnt/user-data/outputs/phase15_ladder.ipynb'))
