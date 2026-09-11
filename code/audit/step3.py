import json,re,time,urllib.request
rows=json.load(open('/tmp/hr/rows.json'))
adv=json.load(open('/tmp/hr/adv_meta.json'))
pkgs=sorted({adv[i]['package'] for r in rows for i in r['adv_ids'] if adv.get(i)})
print('unique crates to resolve:',len(pkgs))
UA='halurust-audit/1.0 (academic dataset verification)'
cache={}
def get(u):
    req=urllib.request.Request(u,headers={'User-Agent':UA})
    with urllib.request.urlopen(req,timeout=25) as f: return json.load(f)
for i,p in enumerate(pkgs):
    for attempt in range(3):
        try:
            d=get(f'https://crates.io/api/v1/crates/{p}')
            c=d.get('crate',{})
            cache[p]={'repository':c.get('repository'),'homepage':c.get('homepage')}
            break
        except Exception as e:
            cache[p]={'error':str(e)}; time.sleep(1.5)
    time.sleep(0.35)
    if i%40==0: print(i,p,cache[p])
json.dump(cache,open('/tmp/hr/crates_repo.json','w'))
null=[p for p,v in cache.items() if not v.get('repository')]
print('no repository field:',len(null),null)
