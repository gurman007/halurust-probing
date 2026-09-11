import json,re,datetime
rows=json.load(open('/tmp/hr/rows.json')); gi=json.load(open('/tmp/hr/gitinfo.json'))
adv=json.load(open('/tmp/hr/adv_meta.json')); body=json.load(open('/tmp/hr/adv_body.json'))
def advtext(r):
    t=''
    for i in r['adv_ids']:
        a=adv.get(i)
        if a: t+= (a.get('url') or '')+'\n'+a.get('toml','')+'\n'+body.get(i,'')
    return t
VERSION=re.compile(r'^\s*(v?\d+\.\d+(\.\d+)?|release|bump|prepare|publish|chore\(release\)|cargo:? ?bump)',re.I)
NOISE=re.compile(r'clippy|warning|rustfmt|fmt|typo|readme|changelog|doc(s|umentation)?\b|ci\b|lint|deprecat|edition|msrv|dependab|update deps|bump deps|test(s|ing)?\b',re.I)
out=[]
for r in rows:
    k=f"{r['repo']}@{r['sha']}" if r['repo'] else None
    g=gi.get(k) if k else None
    rec=dict(row=r['row'],cve=r['cve'],crate=r['crate'],cwe=r['cwe'],repo=r['repo'],sha=r['sha'])
    if not g or not g.get('ok'):
        rec['status']='UNRESOLVED'; rec['subject']=''; out.append(rec); continue
    subj=(g['subject'] or '').strip()
    rec['subject']=subj; rec['date']=g['date'][:10]; rec['nfiles']=g['nfiles']
    files=[f['f'] for f in g['files']]
    rec['rs']=sum(1 for f in files if f.endswith('.rs'))
    rec['merge']=len(g['parents'])>1
    at=advtext(r)
    shas=set(x.lower() for x in re.findall(r'\b([0-9a-f]{7,40})\b',at))
    matched=any(r['sha'].startswith(s) or s.startswith(r['sha'][:7]) for s in shas if len(s)>=7)
    rec['adv_names_sha']=bool(shas); rec['adv_sha_match']=matched
    # advisory date
    ad=None
    for i in r['adv_ids']:
        a=adv.get(i)
        if a and a.get('date'): ad=a['date']
    rec['adv_date']=ad
    flags=[]
    if matched: flags.append('MATCHES_ADVISORY_SHA')
    if VERSION.match(subj): flags.append('VERSION_BUMP')
    if NOISE.search(subj) and not re.search(r'security|vulnerab|unsound|overflow|UB\b|panic|leak|race|fix ',subj,re.I): flags.append('NOISE_SUBJECT')
    if rec['rs']==0: flags.append('NO_RS_FILES')
    if rec['merge']: flags.append('MERGE')
    if ad and rec['date']:
        d1=datetime.date.fromisoformat(rec['date']); d0=datetime.date.fromisoformat(ad)
        rec['days_after_adv']=(d1-d0).days
        if (d1-d0).days>90: flags.append('AFTER_ADVISORY_90d')
    rec['flags']=flags
    rec['status']='OK'
    out.append(rec)
json.dump(out,open('/tmp/hr/analysis.json','w'))
from collections import Counter
print('resolved:',sum(1 for o in out if o['status']=='OK'),'unresolved:',sum(1 for o in out if o['status']!='OK'))
c=Counter(f for o in out for f in o.get('flags',[]))
print(c)
print('\n-- MATCHES_ADVISORY_SHA count:',c['MATCHES_ADVISORY_SHA'])
print('rows whose advisory names some sha:',sum(1 for o in out if o.get('adv_names_sha')))
