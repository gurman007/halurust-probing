import json,subprocess,tempfile,shutil,os
rows={r['row']:r for r in json.load(open('rows.json'))}
want={207:'decoder.rs',216:'lib.rs',215:'lib.rs',221:'common.rs',250:'mpmc.rs'}
os.makedirs('/tmp/gitwk',exist_ok=True)
for rn,pat in want.items():
    r=rows[rn]; d=tempfile.mkdtemp(dir='/tmp/gitwk')
    subprocess.run(['git','init','-q','.'],cwd=d)
    p=subprocess.run(['git','fetch','-q','--depth=2',f"https://github.com/{r['repo']}",r['sha']],cwd=d,capture_output=True,text=True)
    out=subprocess.run(['git','diff','FETCH_HEAD^','FETCH_HEAD','--','*'+pat],cwd=d,capture_output=True,text=True).stdout
    print('='*90); print('ROW',rn,r['cve'],r['crate'],r['repo'])
    print(out[:2200])
    shutil.rmtree(d,ignore_errors=True)
