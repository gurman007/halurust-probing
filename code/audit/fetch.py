import json,os,subprocess,tempfile,shutil,concurrent.futures as cf,sys
rows=json.load(open('/tmp/hr/rows.json'))
res={}
if os.path.exists('/tmp/hr/gitinfo.json'): res=json.load(open('/tmp/hr/gitinfo.json'))
items=sorted({(r['repo'],r['sha']) for r in rows if r['repo']})
items=[i for i in items if f'{i[0]}@{i[1]}' not in res]
print('to fetch:',len(items)); sys.stdout.flush()
def run(cmd,cwd,t=90):
    return subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,timeout=t)
def work(it):
    repo,sha=it; key=f'{repo}@{sha}'
    d=tempfile.mkdtemp(dir='/tmp/gitwk')
    try:
        run(['git','init','-q','.'],d)
        p=run(['git','fetch','-q','--depth=2',f'https://github.com/{repo}',sha],d,120)
        if p.returncode!=0:
            return key,{'ok':False,'err':(p.stderr or '')[:300]}
        m=run(['git','log','-1','--format=%H%x01%ci%x01%P%x01%s%x01%b','FETCH_HEAD'],d)
        h,date,par,subj,body=(m.stdout.split('\x01')+['']*5)[:5]
        st=run(['git','diff','--numstat','FETCH_HEAD^','FETCH_HEAD'],d)
        files=[]
        for line in st.stdout.strip().splitlines():
            pp=line.split('\t')
            if len(pp)==3: files.append({'a':pp[0],'d':pp[1],'f':pp[2]})
        return key,{'ok':True,'sha':h,'date':date,'parents':par.split(),'subject':subj,'body':body[:800],'files':files[:80],'nfiles':len(files)}
    except Exception as e:
        return key,{'ok':False,'err':str(e)[:200]}
    finally:
        shutil.rmtree(d,ignore_errors=True)
os.makedirs('/tmp/gitwk',exist_ok=True)
with cf.ThreadPoolExecutor(12) as ex:
    for n,(k,v) in enumerate(ex.map(work,items)):
        res[k]=v
        if n%25==0:
            print(n,k,v.get('ok'),(v.get('subject') or v.get('err',''))[:70].replace('\n',' ')); sys.stdout.flush()
            json.dump(res,open('/tmp/hr/gitinfo.json','w'))
json.dump(res,open('/tmp/hr/gitinfo.json','w'))
print('done. ok:',sum(1 for v in res.values() if v['ok']),'fail:',sum(1 for v in res.values() if not v['ok']))
