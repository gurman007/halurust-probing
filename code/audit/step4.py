import json,re,os,time,urllib.request
rows=json.load(open('/tmp/hr/rows.json')); adv=json.load(open('/tmp/hr/adv_meta.json'))
cr=json.load(open('/tmp/hr/crates_repo.json'))
FB={'abox':'https://github.com/oberien/abox','nano_arena':'https://github.com/bennetthardwick/nano-arena',
    'protobuf':'https://github.com/stepancheg/rust-protobuf','std':'https://github.com/rust-lang/rust'}
PROJ={'Frontier':'polkadot-evm/frontier','Solana rBPF':'solana-labs/rbpf','SWHKD':'waycrate/swhkd',
 'Cargo':'rust-lang/cargo','russh':'warp-tech/russh','Apollo Router':'apollographql/router',
 'rs-stellar-strkey':'stellar/rs-stellar-strkey','Rust EVM':'rust-ethereum/evm','evm':'rust-ethereum/evm',
 'evm crate':'rust-ethereum/evm','ClamAV':'Cisco-Talos/clamav','Parity Browser':'paritytech/parity-ethereum',
 'rustls crate':'rustls/rustls','Libra Core':'diem/diem','Apache Teaclave Rust SGX SDK':'apache/incubator-teaclave-sgx-sdk',
 'Skytable':'skytable/skytable','coreos-installer':'coreos/coreos-installer','Occlum':'occlum/occlum'}
def norm(u):
    if not u: return None
    m=re.search(r'github\.com/([^/\s]+)/([^/\s#?]+)',u)
    if not m: return None
    return m.group(1)+'/'+re.sub(r'\.git$','',m.group(2))
for r in rows:
    repo=None; src=None
    for i in r['adv_ids']:
        a=adv.get(i)
        if not a: continue
        p=a['package']
        repo=norm((cr.get(p) or {}).get('repository')) or norm(FB.get(p)) or norm(a.get('url'))
        if repo: src='crates.io/'+p; break
    if not repo:
        g=PROJ.get(r['crate'])
        if g: repo,src=g,'manual'
    r['repo']=repo; r['repo_src']=src
print('rows with repo:',sum(1 for r in rows if r['repo']),'/',len(rows))
print('no repo:',[(r['row'],r['cve'],r['crate']) for r in rows if not r['repo']])
json.dump(rows,open('/tmp/hr/rows.json','w'))
