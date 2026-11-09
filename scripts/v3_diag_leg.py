# -*- coding: utf-8 -*-
"""合法性通道的实际影响：它把多少包从 SUSPICIOUS 拉成了 BENIGN"""
import glob, json, os, sys
from collections import Counter

results_dir, mal_dir = sys.argv[1], sys.argv[2]
mal = {f[:-7] for f in os.listdir(mal_dir) if f.endswith('.tar.gz')}
rows, seen = [], set()
for fn in glob.glob(os.path.join(results_dir, '*.jsonl')):
    for line in open(fn, encoding='utf-8'):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        name = (r.get('_input_name') or '').replace('.tar.gz', '')
        if name not in mal:
            continue
        k = (name, r.get('_ts'))
        if k in seen:
            continue
        seen.add(k)
        rows.append(r)

ben_rows = [r for r in rows if r.get('final_category') == 'BENIGN']
leg = [r for r in rows if r.get('legitimacy')]
leg_allow = [r for r in leg if r['legitimacy'].get('allow_benign')]
print(f'恶意集已完成 {len(rows)}；BENIGN {len(ben_rows)}；'
      f'通道尝试 {len(leg)}，放行 {len(leg_allow)}')
print(f'  收分分布: ' + ', '.join(f'{k}={v}' for k, v in
      Counter(round((r["legitimacy"] or {}).get("score", 0), 1) for r in leg).most_common(8)))
print(f'  放行包最终判决: ' + str(Counter(r.get("final_category") for r in leg_allow)))
print('\n被放行的包（按分数降序）：')
for r in sorted(leg_allow, key=lambda x: -x['legitimacy'].get('score', 0))[:25]:
    li = r['legitimacy']
    print(f"  {li.get('score'):.2f}  {r.get('package_name','')[:34]:36s} "
          f"{(li.get('reasons') or [''])[0][:70]}")
print(f'\n从未进入通道的 BENIGN: {len([r for r in ben_rows if not r.get("legitimacy")])}')
for r in ben_rows:
    if not r.get('legitimacy'):
        print(f"  {r.get('package_name','')[:40]:42s} {(r.get('voting_summary') or '')[:60]}")
