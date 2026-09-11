import json,time,urllib.request,statistics
rows=json.load(open('rows.json')); adv=json.load(open('adv_meta.json'))
pkgs=sorted({adv[i]['package'] for r in rows for i in r['adv_ids'] if adv.get(i)})
UA='halurust-audit/1.0 (academic)'
out={}
for p in pkgs:
    try:
        req=urllib.request.Request(f'https://crates.io/api/v1/crates/{p}',headers={'User-Agent':UA})
        d=json.load(urllib.request.urlopen(req,timeout=20))['crate']
        out[p]={'downloads':d.get('downloads',0),'recent':d.get('recent_downloads',0),'created':d.get('created_at','')[:10]}
    except Exception as e: out[p]={'downloads':None}
    time.sleep(0.3)
json.dump(out,open('pop.json','w'))
d=[(v['downloads'],k) for k,v in out.items() if v.get('downloads')]
d.sort()
print('crates resolved:',len(d))
import math
buckets={'<10k':0,'10k-1M':0,'1M-100M':0,'>100M':0}
for n,k in d:
    if n<10_000: buckets['<10k']+=1
    elif n<1_000_000: buckets['10k-1M']+=1
    elif n<100_000_000: buckets['1M-100M']+=1
    else: buckets['>100M']+=1
print(buckets)
print('median downloads:',statistics.median([n for n,_ in d]))
print('bottom 8:',d[:8])
print('top 8:',d[-8:])
