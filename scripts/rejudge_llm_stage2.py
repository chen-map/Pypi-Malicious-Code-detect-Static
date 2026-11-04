# -*- coding: utf-8 -*-
"""SUSPICIOUS 包级 LLM 离线重判 Stage 2（2026-11 bug②修复的价值兑现）

背景：Pass 1 运行时包级 LLM 聚合从未见过污点链（bug②：verdicts 不带链），
对全部 SUSPICIOUS 保守回声。本脚本对新 prompt（含显式判决判据 + 完整
链证据 + 函数摘要 + 增强信号）重跑包级判断。

输入: Stage 1 的 JSONL（rejudged_stage1.jsonl）
证据来源: {extract_base}/{pkg}/.ddg_output/（taint_chains.json /
          function_summaries.json / security_report.json）
输出: 只对 SUSPICIOUS 行调 LLM；升级/确认/降级都记录。

用法:
  python3 scripts/rejudge_llm_stage2.py <stage1.jsonl> \
      --extract-base <pass1_dir> --api-key <KEY> [--model glm-4-flashx] \
      [--workers 5] [--limit 50] -o stage2.jsonl
"""
import argparse
import json
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PROMPT_TMPL = """You are performing a FINAL package-level security assessment.
All individual analyses are complete. You must weigh ALL evidence together
and make a holistic judgment.

## Package: {name}

## All Detection Signals
{signals}

## Mechanical Voting Result
Category: SUSPICIOUS (the per-function classifier was conservative;
your job is to weigh the EVIDENCE, not echo this label)

## Decision Criteria (apply strictly)
- MALICIOUS - any ONE of:
  * A STRONG taint chain exists: source is network/socket/deserialization/
    decoded data, OR the sink is data-exfiltration - and no benign
    explanation covers it. These chain shapes are rare in benign software.
  * Code downloads/executes payloads, exfiltrates data, or backdoors
    installs, even across multiple functions/files (you verified this
    from the flagged code itself, not just from labels).
  * Install-time (setup.py) code execution or exfiltration.
  * Identity fraud: the distribution name does NOT exist on PyPI
    (verification status "not_found") while claiming to be a real package.
- SUSPICIOUS - dangerous-API usage with NO strong chain and a plausible
  benign explanation. IMPORTANT: environment/file_read/user_input ->
  exec/file_write chains are ROUTINE in build tools, plugin loaders and
  test-data generators - such weak-source chains alone stay SUSPICIOUS
  unless the flagged code itself shows malicious intent.
  Corporate-prefixed or internal fork names missing from PyPI are NOT
  identity fraud by themselves. Name-similarity (typosquat heuristics)
  at "high" level alone is NOT proof - require the not_found status or
  corroborating code evidence.
- BENIGN - no taint chains, dangerous APIs clearly used in benign context.

Do NOT default to SUSPICIOUS when a STRONG chain is present: a chain is
structural evidence from the graph kernel, independent of your confidence.
Do NOT upgrade to MALICIOUS on weak-source chains or name-similarity
signals alone - that is how false positives happen.

Output JSON:
```json
{{
  "final_category": "MALICIOUS|SUSPICIOUS|BENIGN",
  "risk_score": 0.0-1.0,
  "confidence": 0.0-1.0,
  "reasoning": "one paragraph weighing all evidence"
}}
```
"""


def load_signals(pkg_dir: Path, row: dict, verify_pypi=False, verifier=None) -> str:
    """从 .ddg_output 与行内字段汇总证据（与在线 _package_level_analysis 对齐）

    verify_pypi=True 时现场做名称核验（Pass 1 未开 --verify-pypi 时，
    仿名/404/版本跳变证据整条通道缺失——补齐后弱模型才有判断依据）。
    """
    signals = []
    ddg = pkg_dir / '.ddg_output'

    # 行内增强信号
    ed = row.get('enhanced_detection') or {}
    signals.append(f"Enhanced detection: {ed.get('threat_level', 'safe')} "
                   f"({ed.get('threats_found', 0)} threats)")

    # 离线名称核验（Pass 1 缺失的通道）
    if verify_pypi and verifier is not None:
        name = row.get('package_name', '')
        dist = name.rsplit('-', 1)[0] if '-' in name else name  # 去掉版本后缀
        try:
            vr = verifier(dist) or {}
            status = vr.get('status', 'unknown')
            signals.append(f"PyPI verification: {status}")
            if status == 'not_found':
                signals.append(f"  [!] {dist} does NOT exist on PyPI - fabricated/removed name")
            stats = vr.get('release_stats') or {}
            if stats.get('first_release_age_days') is not None:
                signals.append(f"  first release {stats['first_release_age_days']} days ago, "
                               f"{stats.get('versions_count', '?')} versions")
        except Exception as e:
            signals.append(f"PyPI verification: error ({type(e).__name__})")

    # 全局污点链（bug② 修复后包级 LLM 才能看到的核心证据）
    chain_file = ddg / 'taint_chains.json'
    if chain_file.exists():
        try:
            data = json.loads(chain_file.read_text(encoding='utf-8'))
            chains = data.get('chains') or []
            if chains:
                from src.taint_engine import format_for_prompt
                signals.append(f"Taint chains: {data.get('chain_count', len(chains))} total")
                signals.append(format_for_prompt(chains, max_chains=4))
        except Exception:
            pass
    else:
        signals.append("Taint chains: none found")

    # 函数摘要
    summ_file = ddg / 'function_summaries.json'
    if summ_file.exists():
        try:
            sdata = json.loads(summ_file.read_text(encoding='utf-8'))
            tf = [(k, s) for k, s in (sdata.get('summaries') or {}).items()
                  if s.get('taint_relevant')]
            if tf:
                signals.append(f"Taint-relevant functions: {len(tf)}")
                for k, s in tf[:5]:
                    signals.append(f"  {s.get('name', k)}: return_tainted="
                                   f"{s.get('return_tainted')} param_to_sink={s.get('param_to_sink')}")
        except Exception:
            pass

    # 攻击链摘要
    ac = row.get('attack_chains') or {}
    if ac.get('chain_count'):
        signals.append(f"Attack chains: {ac['chain_count']} "
                       f"(completeness={ac.get('completeness')} — "
                       f"below 0.5 means incomplete, NOT conclusive)")

    # 可疑子图名（来自投票）
    susp = [v.get('subgraph_name', '?') for v in (row.get('subgraph_verdicts') or [])
            if v.get('final_verdict') == 'SUSPICIOUS']
    if susp:
        signals.append(f"Suspicious subgraphs (per-function): {', '.join(susp[:8])}")

    # 2026-11 证据完整性:可疑子图的函数代码原文。
    # 只有判决标签时 LLM 只能回声;从 sub_ddgs 读代码它才能独立判断。
    # 预算:最多4个函数,每个1200字符。
    sub_root = ddg / 'sub_ddgs'
    code_shown = 0
    for name in susp[:4]:
        nodes_file = sub_root / name / 'nodes.json'
        if not nodes_file.exists():
            continue
        try:
            nodes_data = json.loads(nodes_file.read_text(encoding='utf-8'))
        except Exception:
            continue
        lines = sorted({(n.get('line', 0), n.get('code', ''))
                        for n in nodes_data if n.get('code')})
        buf, total = [], 0
        for _ln, code in lines:
            if total + len(code) > 1200:
                buf.append('  ...')
                break
            buf.append(f'  {code}')
            total += len(code)
        if buf:
            signals.append(f"Code of flagged subgraph '{name}':")
            signals.extend(buf)
            code_shown += 1
    if code_shown:
        signals.append(f"({code_shown} flagged subgraphs' code shown - judge from the code itself)")

    return '\n'.join(signals)


def judge_one(client, model, row, extract_base, verify_pypi=False, verifier=None):
    name = row.get('package_name', '')
    pkg_dir = Path(extract_base) / name
    signals = load_signals(pkg_dir, row, verify_pypi, verifier)
    prompt = PROMPT_TMPL.format(name=name, signals=signals[:8000])
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content":
                 "You are a senior malware analyst making a final determination "
                 "on a Python package. Weigh all evidence and give a definitive verdict."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1, max_tokens=600)
        text = resp.choices[0].message.content if resp.choices else ''
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if not m:
            return row, 'parse_error', ''
        data = json.loads(m.group())
        cat = data.get('final_category', '')
        if cat not in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN'):
            return row, 'invalid_cat', ''
        new = dict(row)
        old = row['final_category']
        new['final_category'] = cat
        new['final_risk_score'] = float(data.get('risk_score', 0.5))
        new['final_confidence'] = float(data.get('confidence', 0.5))
        new['package_llm_reasoning'] = (data.get('reasoning') or '')[:300]
        new['package_llm_rejudge'] = True
        action = f'{old}->{cat}'

        # 机械兜底（2026-11）：LLM 后仍 SUSPICIOUS + PyPI 404 → MALICIOUS。
        # 404 = PyPI 明确回答"没有这个名字"，是确定性证据；弱模型实测
        # 能读到 404 红旗却不敢拍板，此证据不该依赖概率模型。
        if cat == 'SUSPICIOUS' and verify_pypi and verifier is not None:
            dist = name.rsplit('-', 1)[0] if '-' in name else name
            try:
                vr = verifier(dist) or {}
                if vr.get('status') == 'not_found':
                    new['final_category'] = 'MALICIOUS'
                    new['final_risk_score'] = max(new['final_risk_score'], 0.72)
                    new['escalation_source'] = 'pypi_404'
                    new['package_llm_reasoning'] = (
                        '[pypi_404 兜底] ' + new['package_llm_reasoning'])
                    action = f'{old}->MALICIOUS(pypi_404)'
            except Exception:
                pass
        return new, action, (data.get('reasoning') or '')[:150]
    except Exception as e:
        return row, f'error:{type(e).__name__}', str(e)[:100]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('stage1_jsonl')
    ap.add_argument('--extract-base', required=True)
    ap.add_argument('--api-key', required=True)
    ap.add_argument('--model', default='glm-4-flashx')
    ap.add_argument('--workers', type=int, default=5)
    ap.add_argument('--limit', type=int, default=0, help='只处理前 N 个 SUSPICIOUS(调试)')
    ap.add_argument('--verify-pypi', action='store_true',
                    help='离线补做名称核验(Pass 1 未开时的证据补齐)')
    ap.add_argument('--carryover', default=None,
                    help='旧 stage2 结果:同名包已判决的直接搬运,不重复调 LLM'
                         '(用于 Pass 1 全量完成后补判新增行的场景)')
    ap.add_argument('-o', '--output', required=True)
    args = ap.parse_args()

    from zhipuai import ZhipuAI
    client = ZhipuAI(api_key=args.api_key)

    verifier = None
    if args.verify_pypi:
        from src.pypi_verifier import verify_distribution
        verifier = verify_distribution

    rows = [json.loads(l) for l in open(args.stage1_jsonl, encoding='utf-8') if l.strip()]
    # 搬运表: 同名且已做过包级重判的旧记录
    carried = {}
    if args.carryover:
        for l in open(args.carryover, encoding='utf-8'):
            if not l.strip():
                continue
            old = json.loads(l)
            if old.get('package_llm_rejudge'):
                carried[old.get('package_name')] = old
    susp = [r for r in rows if r['final_category'] == 'SUSPICIOUS']
    # 同名已判决的搬运(判决由同证据产生,无需重调 LLM)
    to_carry, to_llm = [], []
    for r in susp:
        old = carried.get(r.get('package_name'))
        if old is not None and old.get('final_category') != 'SUSPICIOUS':
            new = dict(r)
            new['final_category'] = old['final_category']
            new['final_risk_score'] = old.get('final_risk_score', 0.7)
            new['final_confidence'] = old.get('final_confidence', 0.6)
            new['package_llm_reasoning'] = old.get('package_llm_reasoning', '')
            new['package_llm_rejudge'] = True
            new['carried_over'] = True
            to_carry.append(new)
        else:
            to_llm.append(r)
    if args.limit:
        to_llm = to_llm[:args.limit]
    print(f"总 {len(rows)} 行, SUSPICIOUS: {len(susp)} "
          f"(搬运 {len(to_carry)}, 待 LLM {len(to_llm)})")

    actions = Counter()
    done = [0]

    def work(r):
        return judge_one(client, args.model, r, args.extract_base, args.verify_pypi, verifier)

    out_rows = list(to_carry)  # 搬运判决直接进输出
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(work, r): r for r in to_llm}
        for fut in as_completed(futs):
            new_row, action, reason = fut.result()
            actions[action] += 1
            out_rows.append(new_row)
            done[0] += 1
            if done[0] % 50 == 0:
                print(f"  进度 {done[0]}/{len(to_llm)}: {dict(actions)}")

    # 非 SUSPICIOUS 行原样保留
    non_susp = [r for r in rows if r['final_category'] != 'SUSPICIOUS']
    all_out = non_susp + out_rows

    before = Counter(r['final_category'] for r in rows)
    after = Counter(r['final_category'] for r in all_out)
    n = len(rows)
    print("\n=== Stage 2 分布变化 ===")
    for cat in ('MALICIOUS', 'SUSPICIOUS', 'BENIGN', 'OBFUSCATED', 'ANALYSIS_FAILED'):
        b, a = before.get(cat, 0), after.get(cat, 0)
        if b or a:
            print(f"  {cat:16s}: {b:5d} ({b*100//n:2d}%) -> {a:5d} ({a*100//n:2d}%)")
    print("\n=== LLM 动作 ===")
    for k, v in sorted(actions.items()):
        print(f"  {k:28s}: {v}")

    with open(args.output, 'w', encoding='utf-8') as f:
        for r in all_out:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    print(f"\n[OK] 写出 {len(all_out)} 行 -> {args.output}")


if __name__ == '__main__':
    main()
