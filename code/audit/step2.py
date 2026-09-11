import glob,re,json,os
idx={}   # CVE -> list of advisories
adv_by_id={}
for f in glob.glob('/tmp/advdb/crates/*/*.md')+glob.glob('/tmp/advdb/rust/*/*.md'):
    t=open(f,encoding='utf-8',errors='replace').read()
    m=re.search(r'```toml(.*?)```',t,re.S)
    if not m: continue
    toml=m.group(1); body=t[m.end():]
    def g(k):
        mm=re.search(rf'^{k}\s*=\s*"(.*?)"',toml,re.M); return mm.group(1) if mm else None
    def gl(k):
        mm=re.search(rf'^{k}\s*=\s*\[(.*?)\]',toml,re.S|re.M)
        return re.findall(r'"(.*?)"',mm.group(1)) if mm else []
    a=dict(file=f,id=g('id'),package=g('package'),date=g('date'),url=g('url'),
           aliases=gl('aliases'),related=gl('related'),patched=gl('patched'),
           categories=gl('categories'),body=body,toml=toml)
    adv_by_id[a['id']]=a
    for al in a['aliases']+a['related']+([a['id']] if a['id'] else []):
        idx.setdefault(al,[]).append(a['id'])
rows=json.load(open('/tmp/hr/rows.json'))
hit=0;miss=[]
for r in rows:
    ids=idx.get(r['cve'],[])
    r['adv_ids']=ids
    if ids: hit+=1
    else: miss.append(r)
print('rows matched to a RustSec advisory:',hit,'/',len(rows))
print('unmatched:',[(m['row'],m['cve'],m['crate']) for m in miss])
json.dump(rows,open('/tmp/hr/rows.json','w'))
json.dump({k:{kk:vv for kk,vv in v.items() if kk!='body'} for k,v in adv_by_id.items()},open('/tmp/hr/adv_meta.json','w'))
json.dump({k:v['body'] for k,v in adv_by_id.items()},open('/tmp/hr/adv_body.json','w'))
