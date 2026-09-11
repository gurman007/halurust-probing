import os,re,json,subprocess,random,csv,sys,collections
sys.path.insert(0,'/tmp/ctrl')
from rustitems import parse_items, enclosing_items, item_text
random.seed(1234)
REPOS='/tmp/ctrl/repos'
OUT='/tmp/ctrl/pairs'
os.makedirs(f'{OUT}/Before',exist_ok=True); os.makedirs(f'{OUT}/After',exist_ok=True)

gitinfo=json.load(open('/tmp/hr/gitinfo.json'))
fix_shas=set(); fix_parents=set()
for k,v in gitinfo.items():
    fix_shas.add(k.split('@')[1].lower())
    if v.get('ok') and v.get('sha'):
        fix_shas.add(v['sha']); fix_parents.update(v.get('parents',[]))
# also every SHA that appears in the user's sheet (even wrong ones)
rows=json.load(open('/tmp/hr/rows.json'))
for r in rows:
    if r.get('sha'): fix_shas.add(r['sha'].lower())

SEC=re.compile(r'(?i)(cve|rustsec|secur|vuln|unsound|soundness|\bub\b|undefined behavi|overflow|underflow|out[- ]of[- ]bound|\boob\b|use[- ]after[- ]free|\buaf\b|double[- ]free|dangling|memory safety|exploit|\bdos\b|denial|panic|\brace\b|data race|deadlock|leak|injection|saniti[sz]|escap|unchecked|bounds?[- ]check|integer|truncat|timing|side[- ]channel|constant[- ]time|audit|advisor|malicious|attack|crash|segfault|unsafe|poison|zeroiz|validate|validation|infinite loop|recursion|stack overflow|traversal|symlink|permission|privilege|spoof|forge|tamper|confus|mitigat|harden|assert)')
BUG=re.compile(r'(?i)\b(fix|fixes|fixed|bug|regression|incorrect|wrong|broken|issue|error|handle|edge case|corner case|off[- ]by[- ]one)\b')
SKIP=re.compile(r'(?i)(\bbump|release|\bversion\b|changelog|rustfmt|cargo fmt|\bfmt\b|clippy|typo|license|readme|\bci\b|revert|merge|dependabot|update deps|upgrade|msrv|edition|nightly|warning|lint|deprecat|no[- ]op|rename|move .* to|reorder|reformat|whitespace|comment|doc)')
TESTPATH=re.compile(r'(^|/)(tests?|benches|examples|fuzz|testing|test_data|testdata)(/|$)|_tests?\.rs$|/test_[^/]*\.rs$|/build\.rs$')

def git(d,*a,timeout=120):
    p=subprocess.run(['git','-C',d,*a],capture_output=True,text=True,timeout=timeout,errors='replace')
    return p.stdout if p.returncode==0 else None

def log_commits(d):
    out=git(d,'log','--no-merges','--format=%x02%H%x01%P%x01%ci%x01%s%x01%b','--name-only',timeout=600)
    if not out: return []
    commits=[]
    for chunk in out.split('\x02')[1:]:
        head,_,rest=chunk.partition('\n')
        parts=head.split('\x01')
        if len(parts)<5: continue
        sha,parents,date,subj,body=parts[0],parts[1].split(),parts[2],parts[3],parts[4]
        files=[]
        # body may contain newlines; numstat lines are "a\td\tpath"
        lines=[l for l in rest.split('\n') if l.strip()]
        # name-only: file paths are the trailing block of non-empty lines without spaces
        while lines and (' ' not in lines[-1]) and ('.' in lines[-1] or '/' in lines[-1]):
            files.append(('-','-',lines.pop()))
        files.reverse()
        if lines: body+='\n'+'\n'.join(lines)
        commits.append(dict(sha=sha,parents=parents,date=date[:10],subject=subj,msg=(subj+'\n'+body).strip(),files=files))
    return commits

def candidates(commits):
    fix_children=set()
    for c in commits:
        if any(p in fix_shas for p in c['parents']): fix_children.add(c['sha'])
    res=[]
    for c in commits:
        if len(c['parents'])!=1: continue
        if c['sha'] in fix_shas or c['sha'] in fix_parents or c['sha'] in fix_children: continue
        msg=c['msg']
        if SEC.search(msg) or SKIP.search(msg): continue
        rs=[f for f in c['files'] if f[2].endswith('.rs')]
        if not rs: continue
        if any(TESTPATH.search(f[2]) for f in rs): continue
        nonrs=[f for f in c['files'] if not f[2].endswith('.rs') and not f[2].endswith(('.md','.toml','.lock','.yml','.yaml','.txt'))]
        if nonrs: continue
        if len(rs)>4: continue
        cat='bugfix' if BUG.search(msg) else 'nonfix'
        res.append(dict(c,cat=cat,rs=[f[2] for f in rs],tot=-1))
    return res

def hunks(d,parent,sha,path):
    out=git(d,'diff','-U0',parent,sha,'--',path)
    if not out: return []
    hs=[]
    for m in re.finditer(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@',out,re.M):
        ol,oc,nl,nc=int(m.group(1)),int(m.group(2) or 1),int(m.group(3)),int(m.group(4) or 1)
        hs.append((ol,oc,nl,nc))
    return hs

def numstat(d,c):
    out=git(d,'diff','--numstat',c['parents'][0],c['sha'],'--',*c['rs'])
    if out is None: return None
    tot=0
    for line in out.splitlines():
        p=line.split('\t')
        if len(p)==3:
            if p[0]=='-' : return None
            tot+=int(p[0])+int(p[1])
    return tot

def build_pair(d,c):
    tot=numstat(d,c)
    if tot is None or tot<4 or tot>160: return None
    c['tot']=tot
    before_items=collections.OrderedDict(); after_items=collections.OrderedDict()
    for path in c['rs']:
        old=git(d,'show',f"{c['parents'][0]}:{path}"); new=git(d,'show',f"{c['sha']}:{path}")
        if old is None and new is None: return None
        old=old or ''; new=new or ''
        if old and not new or new and not old: return None  # file add/delete -> skip commit
        oi=parse_items(old); ni=parse_items(new)
        ol=old.split('\n'); nl=new.split('\n')
        for (a,ac,b,bc) in hunks(d,c['parents'][0],c['sha'],path):
            # ranges 0-based inclusive; for 0-count hunks use the neighbouring line
            olo=max(a-1,0); ohi=max(a-1+max(ac,1)-1,0)
            nlo=max(b-1,0); nhi=max(b-1+max(bc,1)-1,0)
            for it in enclosing_items(oi,olo,ohi):
                before_items[(path,it['kind'],it['name'])]=item_text(ol,it)
            for it in enclosing_items(ni,nlo,nhi):
                after_items[(path,it['kind'],it['name'])]=item_text(nl,it)
        # ensure the counterpart of every changed item is present in the other version
        by_key_o={(it['kind'],it['name']):it for it in oi}
        by_key_n={(it['kind'],it['name']):it for it in ni}
        for (p,k,n) in list(before_items):
            if p==path and (p,k,n) not in after_items and (k,n) in by_key_n:
                after_items[(p,k,n)]=item_text(nl,by_key_n[(k,n)])
        for (p,k,n) in list(after_items):
            if p==path and (p,k,n) not in before_items and (k,n) in by_key_o:
                before_items[(p,k,n)]=item_text(ol,by_key_o[(k,n)])
    if not before_items or not after_items: return None
    # drop whole-impl/mod blobs when fn-level items exist for the same path (keep it function-level)
    def drop_big(items):
        keys=list(items)
        fnpaths={p for (p,k,n) in keys if k=='fn'}
        return collections.OrderedDict((key,v) for key,v in items.items() if not (key[1] in ('impl','mod') and key[0] in fnpaths))
    before_items=drop_big(before_items); after_items=drop_big(after_items)
    bt='\n'.join(before_items.values()).strip('\n')+'\n'
    at='\n'.join(after_items.values()).strip('\n')+'\n'
    if bt.strip()==at.strip(): return None
    if not (150<=len(bt)<=9000 and 150<=len(at)<=10000): return None
    if bt.count('\n')>320 or at.count('\n')>320: return None
    return bt,at

def do_repo(rd):
    random.seed(hash(rd)%10**6)
    d=os.path.join(REPOS,rd); repo=rd[:-4].replace('__','/')
    meta=[]
    try:
        commits=log_commits(d)
        cands=candidates(commits)
        random.shuffle(cands)
        cands.sort(key=lambda c:0 if c['cat']=='nonfix' else 1)
        got=0
        for c in cands[:70]:
            if got>=8: break
            try: pr=build_pair(d,c)
            except Exception as e: pr=None
            if not pr: continue
            bt,at=pr
            pid=f"{repo.replace('/','__')}__{c['sha'][:8]}"
            open(f'{OUT}/Before/{pid}.rs','w').write(bt); open(f'{OUT}/After/{pid}.rs','w').write(at)
            meta.append(dict(id=pid,repo=repo,sha=c['sha'],date=c['date'],cat=c['cat'],subject=c['subject'][:120],files='|'.join(c['rs']),nfiles=len(c['rs']),diff_lines=c['tot'],before_chars=len(bt),after_chars=len(at),delta=len(at)-len(bt)))
            got+=1
        print(f'{repo}: commits={len(commits)} cands={len(cands)} pairs={got}',flush=True)
    except Exception as e:
        print(f'{repo}: ERROR {e}',flush=True)
    return meta

def main():
    import concurrent.futures as cf
    repos=sorted(os.listdir(REPOS)); meta=[]
    with cf.ProcessPoolExecutor(6) as ex:
        for m in ex.map(do_repo,repos): meta.extend(m)
    with open(f'{OUT}/control_meta.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(meta[0].keys())); w.writeheader(); w.writerows(meta)
    print('TOTAL pairs',len(meta),'repos with pairs',len({m['repo'] for m in meta}))
if __name__=='__main__': main()
