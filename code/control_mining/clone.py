import csv,subprocess,os,sys,concurrent.futures as cf,json,time
rows=list(csv.DictReader(open('/tmp/out/halurust_metadata.csv')))
repos=sorted({r['repo'] for r in rows if r['repo'] and '/' in r['repo']})
def clone(repo):
    d=f"/tmp/ctrl/repos/{repo.replace('/','__')}.git"
    if os.path.isdir(d): return repo,'exists'
    t=time.time()
    p=subprocess.run(['git','clone','-q','--bare','--filter=blob:none','--depth=600','--single-branch',f'https://github.com/{repo}',d],capture_output=True,text=True,timeout=600)
    if p.returncode!=0:
        subprocess.run(['rm','-rf',d]); return repo,'FAIL '+p.stderr[:120].replace('\n',' ')
    return repo,f'ok {time.time()-t:.0f}s'
res={}
with cf.ThreadPoolExecutor(8) as ex:
    for r,s in ex.map(clone,repos):
        res[r]=s; print(r,s,flush=True)
json.dump(res,open('/tmp/ctrl/clone_status.json','w'),indent=1)
print('ok',sum(v.startswith('ok') or v=='exists' for v in res.values()),'fail',sum(v.startswith('FAIL') for v in res.values()))
