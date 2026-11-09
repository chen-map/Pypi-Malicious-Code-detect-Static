# -*- coding: utf-8 -*-
"""跑批进行中的实时快照（不依赖批次结束才写的结果文件）

用法（在代码目录下）:
    python scripts/v3_live.py /disk2/wch/chq/corpus_mal2000 \
        /disk2/wch/chq/corpus_ben2000 [output/results]

按 _input_name 判断每行属于哪个语料，所以多分片并行、结果还没合并时也能看。
重复行（同一包同一次完成）用 (name, _ts) 去重。
"""
import glob
import json
import os
import sys
from collections import Counter

CATS = ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'ANALYSIS_FAILED', 'OBFUSCATED')


def collect(results_dir, mal, ben):
    buf = {'mal': [], 'ben': [], 'unk': []}
    seen = set()
    for fn in glob.glob(os.path.join(results_dir, '*.jsonl')):
        try:
            fh = open(fn, encoding='utf-8')
        except OSError:
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                name = (r.get('_input_name') or r.get('package_name')
                        or '').replace('.tar.gz', '')
                key = (name, r.get('_ts'))
                if key in seen:
                    continue
                seen.add(key)
                k = 'mal' if name in mal else ('ben' if name in ben else 'unk')
                buf[k].append(r)
    return buf


def main():
    mal_dir, ben_dir = sys.argv[1], sys.argv[2]
    results_dir = sys.argv[3] if len(sys.argv) > 3 else 'output/results'
    mal = {f[:-7] for f in os.listdir(mal_dir) if f.endswith('.tar.gz')}
    ben = {f[:-7] for f in os.listdir(ben_dir) if f.endswith('.tar.gz')}
    buf = collect(results_dir, mal, ben)

    for k, total in (('mal', 1000), ('ben', 1000)):
        rows = buf[k]
        n = len(rows)
        if not n:
            print(f'[{k}] 0/{total}')
            continue
        c = Counter(r.get('final_category') for r in rows)
        parts = '  '.join(f'{x}={c[x]}' for x in CATS if c[x])
        hit = c['MALICIOUS']
        label = '召回' if k == 'mal' else '误报'
        print(f'[{k}] {n}/{total}  {parts}')
        print(f'      {label} {hit}/{n} = {hit / n:.1%}   '
              f'疑似 {c["SUSPICIOUS"]}/{n} = {c["SUSPICIOUS"] / n:.1%}')
        if c['ANALYSIS_FAILED']:
            bad = [r.get('package_name') for r in rows
                   if r.get('final_category') == 'ANALYSIS_FAILED']
            print(f'      失败 {len(bad)}: {", ".join(bad[:8])}')
    if buf['unk']:
        print(f'[unk] {len(buf["unk"])}（不属于任一语料，检查语料名）')

    # 通道触发（只在已完成的包里统计）
    rows = buf['mal'] + buf['ben']
    leg = [r for r in rows if r.get('legitimacy')]
    leg_allow = [r for r in leg if r['legitimacy'].get('allow_benign')]
    cov = [r for r in rows if r.get('coverage')]
    cov_block = [r for r in cov if not r['coverage'].get('allow_benign', True)]
    bs = [r for r in rows if r.get('block_scan')]
    bs_fire = [r for r in bs if r['block_scan'].get('verdict') == 'MALICIOUS'
               and r['block_scan'].get('valid_paths')]
    print(f'通道: 合法性尝试 {len(leg)} 放行 {len(leg_allow)}; '
          f'覆盖度拦截 {len(cov_block)}/{len(cov)}; '
          f'block_scan 出链 {len(bs_fire)}/{len(bs)}')
    if leg_allow:
        print('      放行: ' + ', '.join(r.get('package_name', '?')
                                     for r in leg_allow[:8]))


if __name__ == '__main__':
    main()
