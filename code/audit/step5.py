import json,os,time,urllib.request,urllib.error
rows=json.load(open('/tmp/hr/rows.json'))
TOK=os.environ.get('GH_TOKEN')
out={}
if os.path.exists('/tmp/hr/commits.json'): out=json.load(open('/tmp/hr/commits.json'))
def api(u):
    req=urllib.request.Request(u,headers={'Authorization':'Bearer '+TOK,'User-Agent':'halurust-audit','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=30) as f: return json.load(f)
todo=[r for r in rows if r['repo'] and f"{r['repo']}@{r['sha']}" not in out]
print('to fetch:',len(todo))
for n,r in enumerate(todo):
    key=f"{r['repo']}@{r['sha']}"
    try:
        d=api(f"https://api.github.com/repos/{r['repo']}/commits/{r['sha']}")
        files=[{'f':x['filename'],'a':x.get('additions',0),'d':x.get('deletions',0)} for x in d.get('files',[])]
        out[key]={'ok':True,'msg':d['commit']['message'],'date':d['commit']['committer']['date'],
                  'author_date':d['commit']['author']['date'],'parents':[p['sha'] for p in d['parents']],
                  'files':files[:60],'nfiles':len(d.get('files',[])),
                  'stats':d.get('stats',{})}
    except urllib.error.HTTPError as e:
        out[key]={'ok':False,'status':e.code,'body':e.read()[:200].decode('utf8','replace')}
    except Exception as e:
        out[key]={'ok':False,'status':'ERR','body':str(e)[:200]}
    if n%25==0:
        print(n,key,out[key].get('ok'),(out[key].get('msg','') or out[key].get('body',''))[:60].replace('\n',' '))
        json.dump(out,open('/tmp/hr/commits.json','w'))
json.dump(out,open('/tmp/hr/commits.json','w'))
bad=[k for k,v in out.items() if not v['ok']]
print('FAILED lookups:',len(bad))
for k in bad: print('  ',k,out[k].get('status'),out[k].get('body','')[:80].replace('\n',' '))
