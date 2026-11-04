# -*- coding: utf-8 -*-
"""SUSPICIOUS 升级机制 端到端测试（2026-11 两个 bug 的联合验证）

bug ①: 投票层无升级路径 —— SUSPICIOUS 是终点
bug ②: verdicts 从未携带 taint_chains —— 包级聚合对最强证据失明

本测试走真实 _v12_voting_classify_by_subgraphs 数据流:
  subgraph_json(带链) → _classify_one_high_priority 附加链到 verdict
  → 投票层 escalation_gate 判定 → 升级 MALICIOUS
仅 mock LLM 分类器的判决内容（模拟弱模型保守判 SUSPICIOUS 的真实场景），
规则评分器/优先级排序/投票逻辑全部真实运行。
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from batch_solution_b_v2 import BatchAnalyzerV20Voting
from v12_subgraph_classifier import V12SubgraphClassifier

PASS = 0
FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def chain(src, sink, cross_file=False):
    return {'source_category': src, 'sink_category': sink,
            'cross_file': cross_file, 'confidence': 0.9,
            'steps': [{'stage': 'source', 'code': 'requests.get(u)'},
                      {'stage': 'sink', 'code': 'exec(d)'}]}


def make_subgraph(name, chains):
    """构造高优先级子图（含危险 API 节点，确保进 LLM 复核通道）"""
    return {
        'subgraph_name': name,
        'nodes': [
            {'id': f'{name}_1', 'type': 'call', 'code': 'exec(payload)', 'line': 1},
            {'id': f'{name}_2', 'type': 'call', 'code': 'requests.get(url)', 'line': 2},
        ],
        'edges': [
            {'from_node': f'{name}_2', 'to_node': f'{name}_1',
             'kind': 'data', 'variable': 'payload'},
        ],
        'dangerous_nodes': [{'id': f'{name}_1', 'code': 'exec(payload)', 'line': 1}],
        'data_flow_paths': [],
        'functions': {},
        'taint_chains': chains,
        'function_name': name,
        'function_summary': None,
    }


def mock_llm_suspicious(self, subgraph_json, *a, **kw):
    """模拟弱模型:看到危险API但保守判 SUSPICIOUS（bug②修复前不带链也能测通）"""
    return {
        'subgraph_name': subgraph_json.get('subgraph_name', 'unknown'),
        'is_malicious': False,
        'final_verdict': 'SUSPICIOUS',
        'risk_score': 0.55,
        'confidence': 0.6,
        'reasoning': 'dangerous API usage, cannot fully confirm malice',
        'fallback': False,   # 非回退 → llm_used=True
        'attack_chain_type': 'Unknown',
    }


def run_voting(subgraphs, tmp):
    analyzer = BatchAnalyzerV20Voting(
        tarfile_dir=str(tmp), api_key='dummy', count=1,
        extract_base=str(tmp / 'extract'), use_llm_cache=False)
    return analyzer._v12_voting_classify_by_subgraphs(
        subgraphs, tmp, {}, {'overall_threat_level': 'safe'})


def main():
    tmp = Path(tempfile.mkdtemp())
    orig = V12SubgraphClassifier.classify_subgraph
    V12SubgraphClassifier.classify_subgraph = mock_llm_suspicious
    try:
        print("=== 场景1: 强链(network→exec) + LLM判可疑 → 升级 MALICIOUS ===")
        r = run_voting([make_subgraph('dropper', [chain('network_response', 'code_execution')])], tmp)
        check("包级升级为 MALICIOUS", r['final_category'] == 'MALICIOUS',
              detail=f"got {r['final_category']}")
        check("voting_summary 记录升级理由", '升级' in r.get('voting_summary', ''),
              detail=r.get('voting_summary', ''))
        esc = [v for v in r['subgraph_verdicts'] if v.get('escalated')]
        check("verdict 带 escalated 标记", len(esc) == 1)
        check("verdict 携带链计数(bug②修复证据)",
              esc and esc[0].get('taint_chain_count') == 1,
              detail=str([v.get('taint_chain_count') for v in r['subgraph_verdicts']]))

        print("=== 场景2: 弱链(environment→exec, 构建工具形态) → 不升级 ===")
        r2 = run_voting([make_subgraph('build_helper', [chain('environment', 'command_execution')])], tmp)
        check("保持 SUSPICIOUS", r2['final_category'] == 'SUSPICIOUS',
              detail=f"got {r2['final_category']}")
        check("无升级标记", not any(v.get('escalated') for v in r2['subgraph_verdicts']))

        print("=== 场景3: 83良性+1强链可疑 → 证据不被稀释, 仍升级 ===")
        subs = [make_subgraph(f'benign_{i}', []) for i in range(12)]
        subs.append(make_subgraph('payload_exec', [chain('decoded_data', 'code_execution')]))
        r3 = run_voting(subs, tmp)
        check("包级升级为 MALICIOUS", r3['final_category'] == 'MALICIOUS',
              detail=f"got {r3['final_category']}")

        print("=== 场景4: 外传链(任意源→exfil) → 升级 ===")
        r4 = run_voting([make_subgraph('stealer', [chain('file_read', 'data_exfiltration')])], tmp)
        check("包级升级为 MALICIOUS", r4['final_category'] == 'MALICIOUS',
              detail=f"got {r4['final_category']}")

        print("=== 场景5: 多个弱链可疑子图(无强链) → 不升级 ===")
        r5 = run_voting([
            make_subgraph('a', [chain('environment', 'code_execution')]),
            make_subgraph('b', [chain('file_read', 'command_execution')]),
        ], tmp)
        check("保持 SUSPICIOUS", r5['final_category'] == 'SUSPICIOUS',
              detail=f"got {r5['final_category']}")

        print("=== 场景6: 增强通道 critical 佐证 → 升级 ===")
        analyzer = BatchAnalyzerV20Voting(
            tarfile_dir=str(tmp), api_key='dummy', count=1,
            extract_base=str(tmp / 'extract2'), use_llm_cache=False)
        r6 = analyzer._v12_voting_classify_by_subgraphs(
            [make_subgraph('f', [chain('environment', 'code_execution')])],
            tmp, {}, {'overall_threat_level': 'critical'})
        check("包级升级为 MALICIOUS", r6['final_category'] == 'MALICIOUS',
              detail=f"got {r6['final_category']}")
        check("升级理由含增强通道", 'critical' in r6.get('voting_summary', ''),
              detail=r6.get('voting_summary', ''))
    finally:
        V12SubgraphClassifier.classify_subgraph = orig

    print(f"\n结果: {PASS} 通过, {FAIL} 失败")
    sys.exit(1 if FAIL else 0)


if __name__ == '__main__':
    main()
