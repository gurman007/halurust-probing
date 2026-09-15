import json, base64, ast, os, sys
src15b=open('/tmp/ctrl/gen15b.py').read()
ns={}; exec(src15b[:src15b.rindex("zb = open(")], ns)
C_LOAD=ns['C_LOAD']; C_FLOORS=ns['C_FLOORS']; C_LOADCTL=ns['C_LOADCTL']; C_PROBE=ns['C_PROBE']
src=open('/tmp/nb2/gen.py').read(); ns2={}; exec(src[:src.index("zb = open(")], ns2)

MODELS = {
 "codellama7b": dict(base="codellama/CodeLlama-7b-hf", instruct="codellama/CodeLlama-7b-Instruct-hf", tag="CodeLlama-7B", eager=False),
 "llama31_8b":  dict(base="meta-llama/Llama-3.1-8B", instruct="meta-llama/Llama-3.1-8B-Instruct", tag="Llama-3.1-8B", eager=False),
 "gemma2_9b":   dict(base="google/gemma-2-9b", instruct="google/gemma-2-9b-it", tag="Gemma-2-9B", eager=True),
 "mistral24b":  dict(base="mistralai/Mistral-Small-24B-Base-2501", instruct="mistralai/Mistral-Small-24B-Instruct-2501", tag="Mistral-Small-24B", eager=False, big=True),
}

def build(key):
    M=MODELS[key]
    C_TITLE = f"""# Cross-model replication — {M['tag']}

Same three measurements as the Qwen2.5-Coder-7B study, on a different model family:
**brain** (linear probe on frozen base-model hidden states, CVE-grouped CV, temporal split),
**control** (same probe transferred to 226 length-matched non-security patches; length-residualised probe),
**mouth** (Instruct sibling asked directly: yes/no, expert yes/no, A/B forced choice; answer-token probabilities).
Self-contained (data embedded). Runtime: {"an L4 (24 GB) or A100 — this model does not fit the free T4; ~2–3 h on an L4" if M.get('big') else "Colab T4, ~60–90 min"}. Run cells one at a time (Colab's *Run all* has restarted the runtime after the pip step)."""

    C_INSTALL = """#@title 1. Install
!pip -q install -U transformers accelerate bitsandbytes scikit-learn scipy
import torch, numpy as np, pandas as pd, os, re, glob, json, zipfile
print("GPU:", torch.cuda.get_device_name(0) if torch.cuda.is_available() else "NONE - switch to a GPU runtime!")
if torch.cuda.is_available(): print("VRAM GB:", round(torch.cuda.get_device_properties(0).total_memory/1e9,1))"""

    C_CONFIG = f"""#@title 2. Config + Hugging Face token (from Colab Secrets)
MODEL_BASE     = "{M['base']}"
MODEL_INSTRUCT = "{M['instruct']}"
MODEL_TAG      = "{M['tag']}"
ATTN_EAGER     = {M['eager']}
MAX_TOKENS   = 3000
PAIR_TOKENS  = 1400
CACHE_CVE, CACHE_CTL = "hs_cve.npz", "hs_ctl.npz"
SEED = 0
np.random.seed(SEED); torch.manual_seed(SEED)
HF_TOKEN = None
try:
    from google.colab import userdata
    HF_TOKEN = userdata.get('HF_TOKEN')
    from huggingface_hub import login
    login(token=HF_TOKEN, add_to_git_credential=False)
    print("HF login OK")
except Exception as e:
    print("No HF_TOKEN secret (fine for ungated models):", type(e).__name__)"""

    C_EXTRACT = """#@title 5. Extract mean-pooled hidden states from the BASE model: CVE set + control set
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
kw = dict(device_map="auto", torch_dtype=torch.float16,
          quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16), token=HF_TOKEN)
if ATTN_EAGER: kw["attn_implementation"] = "eager"
tok = AutoTokenizer.from_pretrained(MODEL_BASE, token=HF_TOKEN)
model = AutoModelForCausalLM.from_pretrained(MODEL_BASE, **kw); model.eval()
print(MODEL_BASE, "layers:", model.config.num_hidden_layers, "hidden:", model.config.hidden_size)
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
N,L1,d = H_cve.shape; print("CVE",H_cve.shape,"CTL",H_ctl.shape)
del model; torch.cuda.empty_cache()
import shutil, glob as _g  # free the base model's disk cache before the Instruct download (two large models may not fit the disk)
for _p in _g.glob(os.path.expanduser('~/.cache/huggingface/hub/models--'+MODEL_BASE.replace('/','--'))): shutil.rmtree(_p, ignore_errors=True)"""

    C_STATS = """#@title 7. Temporal split + control transfer + length-residualised probe
from sklearn.linear_model import LinearRegression
results = dict(model=MODEL_TAG, base=MODEL_BASE, instruct=MODEL_INSTRUCT, layers=int(L1-1), best_layer=int(best_layer))
results["probe"] = dict(pairwise=[m,lo,hi,n], auc=float(roc_auc_score(df.label, probe_scores)), eqlen=pw(df,probe_scores,eqlen))
# temporal
pre  = df.index[df.date <  "2024"].to_numpy(); post = df.index[df.date >= "2024"].to_numpy()
X = H_cve[:, best_layer, :]
pipe = mk().fit(X[pre], df.label.iloc[pre]); s_post = np.zeros(len(df)); s_post[post] = pipe.predict_proba(X[post])[:,1]
post_cves = set(df.iloc[post].cve); t_out = {c:v for c,v in pair_outcomes_df(df, s_post).items() if c in post_cves}
mt,lot,hit,nt = boot_ci(t_out); results["temporal"]=[mt,lot,hit,nt]
print(f"TEMPORAL (train <2024, test 2024+): {mt:.3f} CI[{lot:.3f},{hit:.3f}] n={nt}")
# control transfer
probe_full = mk().fit(H_cve[:,best_layer,:], df.label)
ctl_scores = probe_full.predict_proba(H_ctl[:,best_layer,:])[:,1]
ctl_out = pair_outcomes_df(dfc, ctl_scores)
cat_of = dfc.drop_duplicates("cve").set_index("cve")["cat"].to_dict()
ctl_nonfix = {k:v for k,v in ctl_out.items() if cat_of[k]=="nonfix"}; ctl_bugfix = {k:v for k,v in ctl_out.items() if cat_of[k]=="bugfix"}
mc,loc,hic,nc = boot_ci(ctl_nonfix); mbf,lobf,hibf,nbf = boot_ci(ctl_bugfix)
nonfix_ids=set(ctl_nonfix)
print(f"CONTROL non-security patches: probe picks 'before' {mc:.3f} CI[{loc:.3f},{hic:.3f}] n={nc}  (length rule {pw(dfc,ctl_len_scores,nonfix_ids):.3f})")
print(f"CONTROL bug-fix commits: {mbf:.3f} CI[{lobf:.3f},{hibf:.3f}] n={nbf}")
results["control"]=dict(nonfix=[mc,loc,hic,nc], bugfix=[mbf,lobf,hibf,nbf], len_rule=pw(dfc,ctl_len_scores,nonfix_ids), gap=m-mc)
# residualised
def resid_cv(H, d_, l):
    Xl=H[:,l,:]; z=np.log1p(d_.code.str.len().values)[:,None]; s=np.zeros(len(d_))
    for tr,te in GroupKFold(5).split(Xl, d_.label, groups=d_.cve):
        reg=LinearRegression().fit(z[tr], Xl[tr]); s[te]=mk().fit(Xl[tr]-reg.predict(z[tr]), d_.label.iloc[tr]).predict_proba(Xl[te]-reg.predict(z[te]))[:,1]
    return s
res_scores = resid_cv(H_cve, df, best_layer); mr,lor,hir,nr = boot_ci(pair_outcomes_df(df,res_scores))
print(f"RESIDUALISED probe: {mr:.3f} CI[{lor:.3f},{hir:.3f}]  AUC {roc_auc_score(df.label,res_scores):.3f}")
results["residualised"]=[mr,lor,hir,nr]
results["length_floor"]=dict(pairwise=sum(len_out.values())/len(len_out), eqlen=pairwise_acc(len_scores,eqlen))"""

    C_MOUTH = """#@title 8. MOUTH: ask the Instruct sibling directly (yes/no x2 + A/B forced choice)
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
itok = AutoTokenizer.from_pretrained(MODEL_INSTRUCT, token=HF_TOKEN)
ikw = dict(device_map="auto", torch_dtype=torch.float16,
           quantization_config=BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.float16), token=HF_TOKEN)
if ATTN_EAGER: ikw["attn_implementation"] = "eager"
imodel = AutoModelForCausalLM.from_pretrained(MODEL_INSTRUCT, **ikw); imodel.eval()
HAS_TMPL = bool(getattr(itok, "chat_template", None))
print("chat template:", HAS_TMPL)
def tokid_set(words):
    ids=set()
    for w in words:
        t=itok.encode(w, add_special_tokens=False)
        if t: ids.add(t[0])
    return list(ids)
YES=tokid_set(["Yes"," Yes","yes"," yes","YES"]); NO=tokid_set(["No"," No","no"," no","NO"])
A_=tokid_set(["A"," A"]); B_=tokid_set(["B"," B"])
def encode_prompt(prompt):
    if HAS_TMPL:
        enc=itok.apply_chat_template([{"role":"user","content":prompt}], add_generation_prompt=True, return_tensors="pt")
        if not torch.is_tensor(enc): enc=enc["input_ids"]
    else:
        enc=itok("[INST] "+prompt+" [/INST]", return_tensors="pt")["input_ids"]
    return enc
def first_token_probs(prompt, ids1, ids2):
    enc=encode_prompt(prompt).to(imodel.device)
    if enc.shape[1]>7500: enc=enc[:,:7500]
    with torch.no_grad():  # last-position logits only (full-vocab logits for all positions OOM on Gemma-2's 256k vocab)
        try: logits=imodel(enc, logits_to_keep=1).logits[0,-1]
        except TypeError: logits=imodel(enc, num_logits_to_keep=1).logits[0,-1]
    pr=torch.softmax(logits.float(), dim=-1)
    p1=float(sum(pr[i] for i in ids1)); p2=float(sum(pr[i] for i in ids2))
    return p1/(p1+p2+1e-9)
def clip(code, cap): return itok.decode(itok.encode(code, add_special_tokens=False)[:cap])
P1 = "Is the following Rust function vulnerable to a security bug? Answer with exactly one word: Yes or No.\\n\\n```rust\\n{c}\\n```"
P2 = "You are a Rust security expert auditing production code for memory-safety, soundness, and logic vulnerabilities. Does this function contain a security vulnerability? Answer with exactly one word: Yes or No.\\n\\n```rust\\n{c}\\n```"
ladder={}
for name,tmpl in [("zero-shot",P1),("expert",P2)]:
    ps=np.zeros(len(df))
    for i,codetxt in enumerate(df.code):
        ps[i]=first_token_probs(tmpl.format(c=clip(codetxt,MAX_TOKENS)), YES, NO)
        if i%100==0: print(name, i, len(df))
    ladder[name]=dict(auc=float(roc_auc_score(df.label,ps)), pairwise=pairwise_acc(ps), eqlen=pairwise_acc(ps,eqlen), acc=float(((ps>0.5).astype(int)==df.label).mean()))
    print(name, ladder[name])
PAB = ("Two versions of the same Rust function are shown. Exactly one contains a security vulnerability; the other is the fixed version. "
       "Which one is vulnerable? Answer with exactly one letter: A or B.\\n\\nVersion A:\\n```rust\\n{a}\\n```\\n\\nVersion B:\\n```rust\\n{b}\\n```")
res_ab={}
for k,cve in enumerate(pair_cves):
    g=df[df.cve==cve]; v=g.loc[g.label==1,"code"].iloc[0]; f=g.loc[g.label==0,"code"].iloc[0]
    vul_is_A=(k%2==0); a,bb=(v,f) if vul_is_A else (f,v)
    pA=first_token_probs(PAB.format(a=clip(a,PAIR_TOKENS), b=clip(bb,PAIR_TOKENS)), A_, B_)
    res_ab[cve]=1.0 if (pA>0.5)==vul_is_A else 0.0
    if k%50==0: print("A/B", k, len(pair_cves))
ab_overall=sum(res_ab.values())/len(res_ab)
mab,loab,hiab,nab = boot_ci(res_ab)
print(f"A/B forced choice: {ab_overall:.3f} CI[{loab:.3f},{hiab:.3f}]")
results["mouth"]=dict(ladder=ladder, ab=[mab,loab,hiab,nab])
del imodel; torch.cuda.empty_cache()"""

    C_FINAL = """#@title 9. Row for the cross-model table + JSON
p=results["probe"]["pairwise"]; c=results["control"]["nonfix"]; t=results["temporal"]; r=results["residualised"]; ab=results["mouth"]["ab"]; L=results["mouth"]["ladder"]
print("="*80)
print(f"MODEL: {MODEL_TAG}   (base {MODEL_BASE} / instruct {MODEL_INSTRUCT}; best layer {best_layer} of {L1-1})")
print(f"{'MOUTH zero-shot / expert / A-B':40s} {L['zero-shot']['pairwise']:.3f} / {L['expert']['pairwise']:.3f} / {ab[0]:.3f}  [A/B CI {ab[1]:.3f},{ab[2]:.3f}]")
print(f"{'length floor':40s} {results['length_floor']['pairwise']:.3f}")
print(f"{'BRAIN probe (CVE pairs)':40s} {p[0]:.3f}  [{p[1]:.3f},{p[2]:.3f}]  AUC {results['probe']['auc']:.3f}")
print(f"{'BRAIN temporal (2024+)':40s} {t[0]:.3f}  [{t[1]:.3f},{t[2]:.3f}]  n={t[3]}")
print(f"{'BRAIN residualised':40s} {r[0]:.3f}  [{r[1]:.3f},{r[2]:.3f}]")
print(f"{'CONTROL non-security patches':40s} {c[0]:.3f}  [{c[1]:.3f},{c[2]:.3f}]   length rule {results['control']['len_rule']:.3f}   gap {results['control']['gap']:.3f}")
print("="*80)
json.dump(results, open(f"results_{MODEL_TAG}.json","w"), default=float)
print("===RESULTS_JSON==="); print(json.dumps(results, default=float)); print("===END_JSON===")"""

    zb = open('/mnt/user-data/outputs/dataset.zip','rb').read()
    mb = open('/mnt/user-data/outputs/halurust_metadata.csv','rb').read()
    cb = open('/tmp/ctrl/control.zip','rb').read()
    C_DATA = ("#@title 2b. Materialize embedded data (CVE pairs + metadata)\nimport base64, os\n"
     + "_DZ='''" + base64.encodebytes(zb).decode() + "'''\n_MD='''" + base64.encodebytes(mb).decode() + "'''\n"
     + "open('dataset.zip','wb').write(base64.b64decode(_DZ))\nopen('halurust_metadata.csv','wb').write(base64.b64decode(_MD))\ndel _DZ,_MD\n"
     + "print('materialized', os.path.getsize('dataset.zip'), os.path.getsize('halurust_metadata.csv'))")
    C_DATA2 = ("#@title 2c. Materialize embedded control pairs\nimport base64, os\n_CZ='''" + base64.encodebytes(cb).decode() + "'''\n"
     + "open('control.zip','wb').write(base64.b64decode(_CZ))\ndel _CZ\nprint('materialized', os.path.getsize('control.zip'))")

    cells=[]
    def md(s): cells.append({"cell_type":"markdown","metadata":{},"source":s})
    def code(s):
        ast.parse('\n'.join(l for l in s.splitlines() if not l.strip().startswith('!')))
        cells.append({"cell_type":"code","metadata":{},"execution_count":None,"outputs":[],"source":s})
    md(C_TITLE); code(C_INSTALL); code(C_CONFIG); code(C_DATA); code(C_DATA2); code(C_LOAD); code(C_LOADCTL); code(C_FLOORS)
    code(C_EXTRACT); code(C_PROBE); code(C_STATS); code(C_MOUTH); code(C_FINAL)
    nb={"cells":cells,"metadata":{"colab":{"provenance":[],"gpuType":("L4" if M.get("big") else "T4")},"kernelspec":{"name":"python3","display_name":"Python 3"},"accelerator":"GPU"},"nbformat":4,"nbformat_minor":0}
    out=f'/mnt/user-data/outputs/xmodel_{key}.ipynb'
    json.dump(nb, open(out,'w'), indent=1); print(key, "OK", os.path.getsize(out))

for k in (sys.argv[1:] or MODELS): build(k)
