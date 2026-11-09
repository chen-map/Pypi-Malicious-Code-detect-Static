# -*- coding: utf-8 -*-
"""漏报归因：BENIGN 的恶意包，判决是从哪来的？

三种状态：
  all_none   —— 子图全都没有判决（None）。聚合层却输出"均为良性"，
                这是"unknown 被当成 safe"，属于判决管道缺陷，不是图的缺陷。
  some_none  —— 部分子图无判决
  all_judged —— 每个子图都真判了良性（代码层面确实干净，或判据不足）

用法: python v3_verdict_state.py <results_dir> <corpus_dir>
"""
import glob
import json
import os
import sys
from collections import Counter


def verdict_state(r):
    sv = r.get('subgraph_verdicts') or []
    if not sv:
        return 'no_subgraph'
    vs = [v.get('verdict') for v in sv]
    if all(v is None for v in vs):
        return 'all_none'
    if any(v is None for v in vs):
        return 'some_none'
    return 'all_judged'


def main():
    results_dir, corpus = sys.argv[1], sys.argv[2]
    names = {f[:-7] for f in os.listdir(corpus) if f.endswith('.tar.gz')}
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
            n = (r.get('_input_name') or '').replace('.tar.gz', '')
            if n not in names:
                continue
            k = (n, r.get('_ts'))
            if k in seen:
                continue
            seen.add(k)
            rows.append(r)

    ben = [r for r in rows if r.get('final_category') == 'BENIGN']
    print(f'恶意集已完成 {len(rows)}，判 BENIGN {len(ben)}')
    print('\n判决来源：')
    for k, v in Counter(verdict_state(r) for r in ben).most_common():
        print(f'   {k}: {v}')

    withchain = [r for r in ben
                 if ((r.get('attack_chains') or {}).get('chain_count') or 0) > 0]
    print(f'\n有攻击链但仍判 BENIGN: {len(withchain)} 个')
    for r in withchain[:10]:
        ac = r['attack_chains']
        name = (r.get('package_name') or '')[:32]
        print(f'   {name:34s} chains={ac["chain_count"]} '
              f'state={verdict_state(r)}')

    # 反向核对：所有 all_none 的包，PyFlow 是否报过 Tier-1 能力
    tier1 = {'process_spawn', 'code_eval', 'credential_access', 'deserialize'}
    none_rows = [r for r in ben if verdict_state(r) in ('all_none', 'no_subgraph')]
    with_t1 = [r for r in none_rows
               if any(c in (r.get('capabilities') or {}) for c in tier1)]
    print(f'\n无判决的包里，PyFlow 报过 Tier-1 能力的: {len(with_t1)}/{len(none_rows)}')


if __name__ == '__main__':
    main()
