# -*- coding: utf-8 -*-
"""A/B 评测汇总（100+100 对比用）

读取 batch_solution_b_v2 的产出（.json 列表或 .jsonl 逐行），
打印可粘贴的紧凑汇总：类别计数 / 召回 / 误报清单。

用法:
    python scripts/ab_summary.py <results.json|results.jsonl> \
        --label "C: all on" --kind mal
    python scripts/ab_summary.py <...> --kind ben
"""
import argparse
import json
from collections import Counter
from pathlib import Path

CATS = ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'UNKNOWN',
        'ANALYSIS_FAILED', 'OBFUSCATED')


def load_rows(path: Path):
    txt = path.read_text(encoding='utf-8').strip()
    if not txt:
        return []
    if path.suffix == '.jsonl' or txt.startswith('{'):
        rows = []
        for line in txt.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        return rows
    data = json.loads(txt)
    return data if isinstance(data, list) else []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('results')
    ap.add_argument('--label', default='')
    ap.add_argument('--kind', choices=['mal', 'ben', 'none'], default='none')
    args = ap.parse_args()

    rows = load_rows(Path(args.results))
    if not rows:
        print(f"[{args.label}] EMPTY  {args.results}")
        return

    cats = Counter(r.get('final_category', 'UNKNOWN') for r in rows)
    n = len(rows)
    mal = cats.get('MALICIOUS', 0)

    print(f"\n=== {args.label or Path(args.results).name} ({n} packages) ===")
    print("  " + '  '.join(f"{c}={cats.get(c, 0)}" for c in CATS if cats.get(c)))
    if args.kind == 'mal':
        print(f"  RECALL(MALICIOUS) = {mal}/{n} = {mal / n:.1%}")
        missed = [r.get('package_name', '?') for r in rows
                  if r.get('final_category') != 'MALICIOUS']
        print(f"  未判 MALICIOUS: {len(missed)}")
    elif args.kind == 'ben':
        fps = [r.get('package_name', '?') for r in rows
               if r.get('final_category') == 'MALICIOUS']
        print(f"  FALSE POSITIVES = {len(fps)}/{n} = {len(fps) / n:.1%}")
        for p in fps[:20]:
            print(f"    FP: {p}")

    # 包块划分使用情况（只有 config C 会有）
    bs = [r for r in rows if r.get('block_scan')]
    if bs:
        esc = [r for r in bs if (r['block_scan'].get('verdict') == 'MALICIOUS'
                                 and r['block_scan'].get('valid_paths'))]
        print(f"  block_scan fired on {len(bs)} packages, "
              f"{len(esc)} with verified chains")
    print()


if __name__ == '__main__':
    main()
