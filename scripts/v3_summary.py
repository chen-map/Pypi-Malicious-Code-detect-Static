# -*- coding: utf-8 -*-
"""v3 跑批汇总：判决分布 + 各通道实际触发率 + 近似吞吐

比 ab_summary.py 多回答三个问题：
  1. 合法性通道到底放行了多少（allow_benign 命中 / 尝试次数）
  2. 覆盖度门控是否在真实数据上生效（有多少包因覆盖不足被禁止 BENIGN）
  3. 两阶段管道里 block_scan / 簇投递 / IOC 目标感知各触发了多少包

用法:
    python scripts/v3_summary.py results_mal.json results_ben.json \
        [--jsonl-mal a.jsonl --jsonl-ben b.jsonl]

不带 jsonl 也能跑（只是没有逐包耗时）。
"""
import argparse
import json
from collections import Counter
from pathlib import Path

CATS = ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'UNKNOWN',
        'ANALYSIS_FAILED', 'OBFUSCATED')


def load_rows(path):
    p = Path(path)
    if not p.exists():
        return []
    txt = p.read_text(encoding='utf-8').strip()
    if not txt:
        return []
    if p.suffix == '.jsonl' or txt.startswith('{'):
        rows = []
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
        return rows
    data = json.loads(txt)
    return data if isinstance(data, list) else []


def _leg(row):
    return row.get('legitimacy') or {}


def _cov(row):
    return row.get('coverage') or {}


def report(label, rows, kind, jsonl_rows=None):
    n = len(rows)
    print(f"\n=== {label} ({n} packages) ===")
    if not n:
        print("  EMPTY")
        return {}
    cats = Counter(r.get('final_category', 'UNKNOWN') for r in rows)
    print("  " + '  '.join(f"{c}={cats.get(c, 0)}"
                           for c in CATS if cats.get(c)))

    if kind == 'mal':
        mal = cats.get('MALICIOUS', 0)
        sus = cats.get('SUSPICIOUS', 0)
        print(f"  RECALL  = {mal}/{n} = {mal / n:.1%}")
        print(f"  SUSP    = {sus}/{n} = {sus / n:.1%}")
        missed = [r.get('package_name', '?') for r in rows
                  if r.get('final_category') in ('BENIGN', 'ANALYSIS_FAILED',
                                                 'UNKNOWN')]
        if missed:
            print(f"  完全漏掉 {len(missed)}: {', '.join(missed[:15])}")
    else:
        fps = [r.get('package_name', '?') for r in rows
               if r.get('final_category') == 'MALICIOUS']
        sus = cats.get('SUSPICIOUS', 0)
        print(f"  FALSE POSITIVES = {len(fps)}/{n} = {len(fps) / n:.1%}")
        print(f"  SUSP            = {sus}/{n} = {sus / n:.1%}")
        for p in fps[:20]:
            print(f"    FP: {p}")

    # ---- 通道触发统计 ----
    leg_tried = [r for r in rows if _leg(r)]
    leg_allow = [r for r in leg_tried if _leg(r).get('allow_benign')]
    cov_gate = [r for r in rows
                if _cov(r) and not _cov(r).get('allow_benign', True)]
    bs = [r for r in rows if r.get('block_scan')]
    bs_fire = [r for r in bs if r['block_scan'].get('verdict') == 'MALICIOUS'
               and r['block_scan'].get('valid_paths')]
    chains = sum(len(r.get('attack_chains') or []) for r in rows)
    degraded = sum(1 for r in rows if r.get('analysis_degraded'))
    cov_missing = sum(1 for r in rows if not _cov(r))

    print(f"  legitimacy: 尝试 {len(leg_tried)}, 放行 {len(leg_allow)}"
          + (f"  ({', '.join(r.get('package_name', '?') for r in leg_allow[:6])})"
             if leg_allow else ""))
    print(f"  coverage gate: 阻止 BENIGN {len(cov_gate)}  (无覆盖数据 {cov_missing})")
    print(f"  block_scan: 触发 {len(bs_fire)}/{len(bs)} 有验证链")
    print(f"  attack_chains 总数: {chains}")
    print(f"  analysis_degraded: {degraded}")

    # ---- 近似吞吐（jsonl 的 _ts 是完成时间戳）----
    jr = jsonl_rows or []
    ts = [r['_ts'] for r in jr if r.get('_ts')]
    if len(ts) > 5:
        span = max(ts) - min(ts)
        gaps = sorted(b - a for a, b in zip(sorted(ts), sorted(ts)[1:]))
        med = gaps[len(gaps) // 2] if gaps else 0
        print(f"  吞吐: {span / 60:.1f} min / {len(ts)} 包"
              f"  (中位 {med:.1f}s/包)")

    return {'cats': dict(cats), 'n': n, 'leg_allow': len(leg_allow),
            'leg_tried': len(leg_tried), 'cov_gate': len(cov_gate),
            'chains': chains}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mal')
    ap.add_argument('ben')
    ap.add_argument('--jsonl-mal', default=None)
    ap.add_argument('--jsonl-ben', default=None)
    args = ap.parse_args()

    m = report('MALICIOUS 集', load_rows(args.mal), 'mal',
               load_rows(args.jsonl_mal) if args.jsonl_mal else None)
    b = report('BENIGN 集', load_rows(args.ben), 'ben',
               load_rows(args.jsonl_ben) if args.jsonl_ben else None)

    if m and b:
        print("\n=== 合并 ===")
        print(f"  恶意召回 {m['cats'].get('MALICIOUS', 0)}/{m['n']}"
              f"  良性误报 {b['cats'].get('MALICIOUS', 0)}/{b['n']}"
              f"  良性疑似 {b['cats'].get('SUSPICIOUS', 0)}/{b['n']}")
        print(f"  合法性通道放行 {b['leg_allow']}（尝试 {b['leg_tried']}）")
        print(f"  覆盖度门控拦截 {b['cov_gate']} 个良性被判 BENIGN 的机会")
        print(f"  验证链总数 恶意集 {m['chains']} / 良性集 {b['chains']}")


if __name__ == '__main__':
    main()
