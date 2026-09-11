import json,re
rows={r['row']:r for r in json.load(open('/tmp/hr/rows.json'))}
an=json.load(open('/tmp/hr/analysis.json'))
adv=json.load(open('/tmp/hr/adv_meta.json')); body=json.load(open('/tmp/hr/adv_body.json'))
def advinfo(r):
    for i in r['adv_ids']:
        a=adv.get(i)
        if not a: continue
        b=body.get(i,'')
        title=b.strip().splitlines()[0].lstrip('# ').strip() if b.strip() else ''
        txt=' '.join(b.split())[:300]
        return i,title,txt,a.get('url') or ''
    return '','','',''
# better fix-sha extraction: commit urls + hex near 'commit'
def advshas(r):
    s=set()
    for i in r['adv_ids']:
        a=adv.get(i); b=body.get(i,'')+' '+(a.get('url') or '') if a else ''
        s|=set(x.lower() for x in re.findall(r'commit[/s]?[:\s#]*([0-9a-f]{7,40})',b,re.I))
        s|=set(x.lower() for x in re.findall(r'/commit/([0-9a-f]{7,40})',b,re.I))
    return s
lines=[]
for o in an:
    r=rows[o['row']]
    aid,title,txt,url=advinfo(r)
    shas=advshas(r)
    m='ADV_SHA_OK' if any(o['sha'].startswith(s) for s in shas) else ('ADV_SHA_MISMATCH' if shas else '-')
    lines.append(f"{o['row']}\t{o['cve']}\t{o['crate']}\t{o.get('date','?')}\tadv:{o.get('adv_date')}\t{m}\tRS:{o.get('rs','?')}/{o.get('nfiles','?')}\tSUBJ: {o['subject'][:95]}\tADV: {title[:70]} :: {txt[:150]}")
open('/tmp/hr/table.tsv','w').write('\n'.join(lines))
print(len(lines))
import collections
print(collections.Counter(l.split('\t')[5] for l in lines))
