import json,subprocess,tempfile,shutil,os
alts={
 31:['apache/arrow-rs','apache/arrow-rs-object-store'],
 175:['apache/teaclave-sgx-sdk','apache/incubator-teaclave-sgx-sdk'],
 20:['bytecodealliance/cap-std','bytecodealliance/wasmtime'],
 74:['time-rs/time','chronotope/chrono'],
 186:['hyperium/hyper'],
 240:['oberien/abox','Vurich/abox'],
 11:['ogham/rust-users','fnordpig/rust-users'],
 160:['paritytech/libsecp256k1','tari-labs/libsecp256k1-rs','sipa/secp256k1'],
}
rows={r['row']:r for r in json.load(open('/tmp/hr/rows.json'))}
os.makedirs('/tmp/gitwk',exist_ok=True)
res=json.load(open('/tmp/hr/gitinfo.json'))
for rn,cands in alts.items():
    r=rows[rn]; sha=r['sha']; found=False
    for repo in cands:
        d=tempfile.mkdtemp(dir='/tmp/gitwk')
        try:
            subprocess.run(['git','init','-q','.'],cwd=d)
            p=subprocess.run(['git','fetch','-q','--depth=2',f'https://github.com/{repo}',sha],cwd=d,capture_output=True,text=True,timeout=120,env={**os.environ,'GIT_TERMINAL_PROMPT':'0'})
            if p.returncode==0:
                m=subprocess.run(['git','log','-1','--format=%ci%x01%P%x01%s','FETCH_HEAD'],cwd=d,capture_output=True,text=True)
                date,par,subj=m.stdout.split('\x01')
                st=subprocess.run(['git','diff','--numstat','FETCH_HEAD^','FETCH_HEAD'],cwd=d,capture_output=True,text=True)
                files=[{'a':x.split('\t')[0],'d':x.split('\t')[1],'f':x.split('\t')[2]} for x in st.stdout.strip().splitlines() if len(x.split('\t'))==3]
                res[f'{repo}@{sha}']={'ok':True,'date':date,'parents':par.split(),'subject':subj,'body':'','files':files[:80],'nfiles':len(files)}
                print(rn,r['cve'],r['crate'],'FOUND in',repo,'|',subj[:80]); found=True
                r['repo']=repo
                break
            else:
                print(rn,repo,'->',p.stderr.strip()[:90])
        finally: shutil.rmtree(d,ignore_errors=True)
    if not found: print(rn,r['cve'],r['crate'],'NOT FOUND in any candidate')
json.dump(res,open('/tmp/hr/gitinfo.json','w'))
json.dump(list(rows.values()),open('/tmp/hr/rows.json','w'))
