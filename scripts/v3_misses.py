# -*- coding: utf-8 -*-
"""按语料列出误报/漏报明细"""
import glob, json, os, sys
from collections import Counter
rd, corpus, kind = sys.argv[1], sys.argv[2], sys.argv[3]
names = {f[:-7] for f in os.listdir(corpus) if f.endswith('.tar.gz')}
rows, seen = [], set()
for fn in glob.glob(os.path.join(rd, '*.jsonl')):
    for line in open(fn, encoding='utf-8'):
        line = line.strip()
        if not line: continue
        try: r = json.loads(line)
        except Exception: continue
        n = (r.get('_input_name') or '').replace('.tar.gz','')
        if n not in names: continue
        k = (n, r.get('_ts'))
        if k in seen: continue
        seen.add(k); rows.append(r)
want = 'MALICIOUS' if kind == 'ben' else 'BENIGN'
bad = [r for r in rows if r.get('final_category') == want]
print(f"{kind} 完成 {len(rows)}，{want} {len(bad)}")
for r in bad:
    print(f"  {r.get('package_name','')[:36]:38s} "
          f"{(r.get('voting_summary') or '')[:70]}")
