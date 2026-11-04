# -*- coding: utf-8 -*-
"""SUSPICIOUS 离线重判（2026-11 升级机制部署）

对已完成批次结果中的 SUSPICIOUS 行应用与在线投票完全相同的升级门控
（src/taint_engine.escalation_gate），不重跑分析、不调用 LLM。

两级门控:
  Tier 1 同源门控（新数据）: subgraph_verdicts[].taint_categories
      —— 升级链与可疑子图来自同一函数，与在线投票口径完全一致
  Tier 2 包级门控（老数据回退）: 读 {extract_base}/{pkg}/.ddg_output/taint_chains.json
      —— 包内任意链满足门控 且 行内存在 LLM 可疑子图 → 升级
      （链与可疑子图可能来自不同函数，弱于 Tier 1，单独标记 package_level）

用法:
  python scripts/rejudge_suspicious.py <results.jsonl> \
      [--extract-base /path/to/packages] [-o rejudged.jsonl] [--apply]

默认 dry-run：只打印统计不写文件；--apply 才落盘。
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.taint_engine import escalation_gate  # noqa: E402


def gate_categories(cats):
    """对 taint_categories 简化结构（source_category/sink_category）跑门控"""
    for c in cats or []:
        src = c.get('source_category', '')
        sink = c.get('sink_category', '')
        if src or sink:
            reason = escalation_gate([{'source_category': src, 'sink_category': sink}])
            if reason:
                return reason
    return ''


def rejudge_row(row, extract_base=None):
    """对单行执行重判。返回 (new_row, action, reason)。
    action: 'keep' | 'escalate_same_source' | 'escalate_package_level' | 'chain_data_missing'
    """
    if row.get('final_category') != 'SUSPICIOUS':
        return row, 'keep', ''

    # 已有升级标记的不重复处理
    if row.get('escalation'):
        return row, 'keep', ''

    vs = row.get('subgraph_verdicts') or []
    susp_names = [v.get('subgraph_name', '?') for v in vs
                  if v.get('final_verdict') == 'SUSPICIOUS']
    if not susp_names:
        # 非子图判决来源的 SUSPICIOUS（如规则孤证降级），保持不动
        return row, 'keep', ''

    # ---- Tier 1: 同源门控（verdict 自带链类别）----
    for v in vs:
        if v.get('final_verdict') != 'SUSPICIOUS':
            continue
        cats = v.get('taint_categories')
        if cats is None:
            continue  # 老数据无此字段 → Tier 2
        reason = gate_categories(cats)
        if reason:
            new = dict(row)
            new['final_category'] = 'MALICIOUS'
            new['escalation'] = 'same_source'
            new['escalation_reason'] = (
                f"[离线重判] {v.get('subgraph_name', '?')}: {reason}")
            new['final_risk_score'] = max(row.get('final_risk_score', 0.5), 0.72)
            new['final_confidence'] = max(row.get('final_confidence', 0.5), 0.62)
            return new, 'escalate_same_source', reason

    # verdicts 带字段但都不满足门控 → 确认不升级（不是数据缺失）
    has_field = any(v.get('taint_categories') is not None for v in vs
                    if v.get('final_verdict') == 'SUSPICIOUS')
    if has_field:
        return row, 'keep', ''

    # ---- Tier 2: 包级门控（读全局 taint_chains.json）----
    if not extract_base:
        return row, 'chain_data_missing', ''
    chain_file = Path(extract_base) / row.get('package_name', '') / '.ddg_output' / 'taint_chains.json'
    if not chain_file.exists():
        return row, 'chain_data_missing', ''
    try:
        data = json.loads(chain_file.read_text(encoding='utf-8'))
    except Exception:
        return row, 'chain_data_missing', ''
    reason = escalation_gate(data.get('chains') or [])
    if reason:
        new = dict(row)
        new['final_category'] = 'MALICIOUS'
        new['escalation'] = 'package_level'
        new['escalation_reason'] = f"[离线重判-包级] {reason}"
        new['final_risk_score'] = max(row.get('final_risk_score', 0.5), 0.70)
        new['final_confidence'] = max(row.get('final_confidence', 0.5), 0.60)
        return new, 'escalate_package_level', reason
    return row, 'keep', ''


def main():
    ap = argparse.ArgumentParser(description='SUSPICIOUS 离线重判')
    ap.add_argument('results_jsonl')
    ap.add_argument('--extract-base', default=None, help='解压根目录（Tier 2 需要）')
    ap.add_argument('-o', '--output', default=None)
    ap.add_argument('--apply', action='store_true', help='实际写输出文件（默认 dry-run）')
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.results_jsonl, encoding='utf-8') if l.strip()]
    print(f"读取 {len(rows)} 行: {args.results_jsonl}")

    actions = Counter()
    escalated = []
    out_rows = []
    for row in rows:
        new_row, action, reason = rejudge_row(row, args.extract_base)
        actions[action] += 1
        if action.startswith('escalate'):
            escalated.append((row.get('package_name', '?'), action, reason))
        out_rows.append(new_row)

    # 统计
    before = Counter(r['final_category'] for r in rows)
    after = Counter(r['final_category'] for r in out_rows)
    n = len(rows)
    print(f"\n=== 分布变化 ===")
    for cat in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'OBFUSCATED', 'ANALYSIS_FAILED'):
        b, a = before.get(cat, 0), after.get(cat, 0)
        if b or a:
            print(f"  {cat:16s}: {b:5d} ({b*100//n:2d}%) → {a:5d} ({a*100//n:2d}%)")

    print(f"\n=== 动作统计 ===")
    for k, v in sorted(actions.items()):
        print(f"  {k:26s}: {v}")

    if escalated:
        print(f"\n=== 升级明细（前 15）===")
        for name, action, reason in escalated[:15]:
            print(f"  {name[:30]:30s} [{action}] {reason}")

    if args.apply and args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            for r in out_rows:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')
        print(f"\n[OK] 已写出 {len(out_rows)} 行 → {args.output}")
    elif not args.apply:
        print(f"\n[dry-run] 未写文件。加 --apply -o <out.jsonl> 落盘。")


if __name__ == '__main__':
    main()
