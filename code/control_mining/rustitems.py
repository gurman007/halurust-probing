"""Lightweight Rust item extractor: finds fn / impl / trait / struct / enum items
by brace matching (string- and comment-aware enough for our purpose) and
returns spans so we can pull the item(s) enclosing a changed line range."""
import re

ITEM_RE = re.compile(
    r'^\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?'
    r'(?:(?:default|async|unsafe|const|extern(?:\s+"[^"]*")?)\s+)*'
    r'(fn|impl|trait|struct|enum|union|mod)\b\s*(?:<[^{;]*?>)?\s*([A-Za-z_][A-Za-z0-9_]*)?')

def strip_noise(line):
    """Remove string literals and line comments so braces inside them don't count."""
    out=[];i=0;n=len(line)
    while i<n:
        c=line[i]
        if c=='/' and i+1<n and line[i+1]=='/':
            break
        if c=='"':
            j=i+1
            while j<n and line[j]!='"':
                j+= 2 if line[j]=='\\' else 1
            i=j+1; out.append('""'); continue
        if c=="'" and i+2<n and (line[i+2]=="'" or (line[i+1]=='\\' and i+3<n)):
            j=i+2 if line[i+1]!='\\' else i+3
            while j<n and line[j]!="'": j+=1
            i=j+1; continue
        out.append(c); i+=1
    return ''.join(out)

def parse_items(src):
    """Return list of dicts {kind,name,start,end,depth} with 0-based inclusive line spans."""
    lines=src.split('\n')
    items=[]; stack=[]; depth=0; in_block_comment=False
    pending=None  # item header seen, waiting for '{' or ';'
    for idx,raw in enumerate(lines):
        line=raw
        if in_block_comment:
            if '*/' in line:
                line=line.split('*/',1)[1]; in_block_comment=False
            else: continue
        # crude block comment handling (single-line or start)
        while '/*' in line:
            a=line.index('/*')
            if '*/' in line[a:]:
                b=line.index('*/',a); line=line[:a]+line[b+2:]
            else:
                line=line[:a]; in_block_comment=True; break
        s=strip_noise(line)
        if pending is None:
            m=ITEM_RE.match(s)
            if m and not s.strip().startswith('//'):
                kind=m.group(1); name=m.group(2) or ''
                if kind=='impl':
                    mm=re.search(r'impl(?:<[^>]*>)?\s+(?:[\w:]+(?:<[^>]*>)?\s+for\s+)?([\w:]+)',s)
                    name=mm.group(1) if mm else 'impl'
                pending={'kind':kind,'name':name,'start':idx,'depth':depth,'hdr':idx}
        opens=s.count('{'); closes=s.count('}')
        if pending is not None:
            if opens>0:
                pending['body_open']=depth  # depth before this line's braces
                stack.append(pending); pending=None
            elif ';' in s and opens==0:
                # declaration without body (trait fn sig, struct Foo;) -> item ends here
                it=pending; it['end']=idx; items.append(it); pending=None
            elif idx-pending['hdr']>12:
                pending=None  # gave up
        depth+=opens-closes
        # close items whose body_open depth we returned to
        while stack and depth<=stack[-1]['body_open'] and (opens or closes):
            it=stack.pop(); it['end']=idx; items.append(it)
    for it in stack:
        it['end']=len(lines)-1; items.append(it)
    items.sort(key=lambda x:(x['start'],-x['end']))
    return items

def enclosing_items(items, lo, hi, prefer_fn=True):
    """Items enclosing the [lo,hi] (0-based inclusive) line range.
    Returns the innermost fn if any, else the innermost item of any kind."""
    cands=[it for it in items if it['start']<=hi and it['end']>=lo]
    if not cands: return []
    fns=[it for it in cands if it['kind']=='fn']
    if fns and prefer_fn:
        # innermost fn(s) overlapping range: pick those not containing another candidate fn
        inner=[f for f in fns if not any(g is not f and g['start']>=f['start'] and g['end']<=f['end'] and g['start']<=hi and g['end']>=lo for g in fns)]
        return inner
    inner=[c for c in cands if not any(g is not c and g['start']>=c['start'] and g['end']<=c['end'] for g in cands)]
    return inner

def item_text(src_lines, it):
    return '\n'.join(src_lines[it['start']:it['end']+1])

if __name__=='__main__':
    t='''use foo;
pub struct A { x: u32 }
impl A {
    /// doc
    pub fn new(x: u32) -> Self { A { x } }
    fn helper(&self) -> u32 {
        let s = "}{";
        if self.x > 0 { 1 } else { 0 }
    }
}
fn free() {
    println!("{}", 1);
}
'''
    for it in parse_items(t): print(it)
    print(enclosing_items(parse_items(t),7,7))
