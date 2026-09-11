import torch, pandas as pd, numpy as np, time, os, sys
from transformers import AutoTokenizer, AutoModelForCausalLM
torch.set_num_threads(2)
MODEL="Qwen/Qwen2.5-Coder-0.5B"; MAXTOK=1024
df=pd.read_pickle('/tmp/phase1/df.pkl')
tok=AutoTokenizer.from_pretrained(MODEL)
model=AutoModelForCausalLM.from_pretrained(MODEL, torch_dtype=torch.float32)
model.eval()
CK='/tmp/phase1/hs_ckpt.npz'
done=0; last=[]; mean=[]
if os.path.exists(CK):
    d=np.load(CK); last=list(d['last']); mean=list(d['mean']); done=len(last)
    print(f'resuming at {done}',flush=True)
t0=time.time()
with torch.no_grad():
    for i in range(done,len(df)):
        enc=tok(df.code.iloc[i],return_tensors='pt',truncation=True,max_length=MAXTOK)
        out=model(**enc,output_hidden_states=True)
        hs=out.hidden_states
        last.append(torch.stack([h[0,-1] for h in hs]).numpy())
        mean.append(torch.stack([h[0].mean(0) for h in hs]).numpy())
        if (i+1)%20==0 or i==done:
            el=time.time()-t0; rate=(i+1-done)/el
            print(f'{i+1}/{len(df)}  {rate:.2f} samp/s  eta {(len(df)-i-1)/rate/60:.0f} min',flush=True)
            np.savez_compressed(CK,last=np.stack(last),mean=np.stack(mean))
np.savez_compressed(CK,last=np.stack(last),mean=np.stack(mean))
print('DONE',len(last),flush=True)
