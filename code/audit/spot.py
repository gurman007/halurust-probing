import json,subprocess,tempfile,shutil,os,random,re
rows={r['row']:r for r in json.load(open('rows.json'))}
adv=json.load(open('adv_meta.json')); body=json.load(open('adv_body.json')); gi=json.load(open('gitinfo.json'))
graded={2,50,87,133,159,213,216,220,237,249,250,11,175,186,240,115,162,207,209,212,168,100,37,53,54,253}
pool=[rn for rn in rows if rn not in graded and gi.get(f"{rows[rn]['repo']}@{rows[rn]['sha']}",{}).get('ok')]
random.seed(7)
sample=[74,22,184]+random.sample(pool,12)
os.makedirs('/tmp/gitwk',exist_ok=True)
for rn in sample:
    r=rows[rn]; g=gi[f"{r['repo']}@{r['sha']}"]
    a=adv.get(r['adv_ids'][0]) if r['adv_ids'] else None
    print('='*95); print(f"ROW {rn} {r['cve']} {r['crate']} | {r['repo']}@{r['sha'][:8]} | {g['date'][:10]} | {g['subject'][:70]}")
    if a: print('  ADV',a['id'],a['date'],'patched',a['patched'],'|',' '.join(body.get(a['id'],'').split())[:200])
    d=tempfile.mkdtemp(dir='/tmp/gitwk')
    subprocess.run(['git','init','-q','.'],cwd=d)
    subprocess.run(['git','fetch','-q','--depth=2',f"https://github.com/{r['repo']}",r['sha']],cwd=d,capture_output=True)
    out=subprocess.run(['git','diff','FETCH_HEAD^','FETCH_HEAD','--','*.rs'],cwd=d,capture_output=True,text=True).stdout
    keep=[l for l in out.splitlines() if l[:1] in '+-' and not l.startswith(('+++','---'))]
    print('  DIFF (first 18 changed lines of',len(keep),'):')
    for l in keep[:18]: print('   ',l[:110])
    shutil.rmtree(d,ignore_errors=True)
