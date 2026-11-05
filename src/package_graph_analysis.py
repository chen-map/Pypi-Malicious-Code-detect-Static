# -*- coding: utf-8 -*-
"""包级图细判（Graph-level adjudication）

架构定位（2026-11 重构）：
    粗筛（API 匹配/启发式）  →  只决定「先看哪里」，**不决定「哪里恶意」**
    细判（图 + LLM 读图）    →  真正的判定：整包图分块读，LLM 找链路

与旧流程的关键区别：
- 旧：pattern_matcher 标记危险节点 → 只把含危险节点的子图交给 LLM
       → 正则没命中的函数永远进不了细判（漏检天花板 = 正则召回率）
- 新：整包图按文件/函数分块，**每一块都读**，LLM 自己判断哪里有恶意
       → 粗筛只用于排序与预算，漏检不再由正则决定

成本控制：
- 小块（< BLOCK_NODES）一次读完
- 大文件按函数边界再切
- 总块数上限，超出时按「块内是否含外部交互 API」排序截断（仍不看恶意性）
"""
from typing import Dict, List, Tuple

from src.graph_digest import digest, verify_paths
from src.llm_graph_analyst import analyze as analyze_block

# 单块节点上限（超过则按函数再切）
BLOCK_NODES = 500
# 单包最多分析的块数（防止超大 monorepo 成本爆炸）
MAX_BLOCKS = 12


def _split_blocks(nodes: List[Dict], edges: List[Dict],
                  block_nodes: int = BLOCK_NODES,
                  max_blocks: int = MAX_BLOCKS) -> List[Tuple[str, List[Dict], List[Dict]]]:
    """把整包图切成若干块，每块可独立交给 LLM。

    切分顺序：文件 → 函数 → 贪心填充。
    返回 [(label, nodes, edges)]，边只保留两端在本块内的。
    """
    # 1) 按文件分组
    by_file: Dict[str, List[Dict]] = {}
    for n in nodes:
        by_file.setdefault(n.get('file') or '?', []).append(n)

    raw_blocks: List[Tuple[str, List[Dict]]] = []
    for f, f_nodes in sorted(by_file.items()):
        if len(f_nodes) <= block_nodes:
            raw_blocks.append((f, f_nodes))
            continue
        # 2) 文件过大 → 按函数再切
        by_func: Dict[str, List[Dict]] = {}
        for n in f_nodes:
            fn = n.get('function_name') or '<module>'
            by_func.setdefault(fn, []).append(n)
        for fn, fn_nodes in sorted(by_func.items()):
            if len(fn_nodes) <= block_nodes:
                raw_blocks.append((f'{f}::{fn}', fn_nodes))
                continue
            # 3) 单函数仍过大 → 顺序切片
            for i in range(0, len(fn_nodes), block_nodes):
                chunk = fn_nodes[i:i + block_nodes]
                raw_blocks.append((f'{f}::{fn}#{i // block_nodes + 1}', chunk))

    # 4) 块数上限：按「外部交互密度」排序（网络/文件/进程相关调用数），
    #    这只是**预算排序**，不代表恶意判断——不含任何危险/恶意语义。
    _EXTERNAL_HINTS = ('request', 'http', 'url', 'socket', 'urllib', 'subprocess',
                       'popen', 'system', 'exec', 'eval', 'open', 'read', 'write',
                       'loads', 'load', 'decode', 'connect', 'send', 'recv')

    def _external_density(blk_nodes):
        hits = 0
        for n in blk_nodes:
            code = (n.get('code') or '').lower()
            if any(h in code for h in _EXTERNAL_HINTS):
                hits += 1
        return hits

    if len(raw_blocks) > max_blocks:
        raw_blocks.sort(key=lambda b: _external_density(b[1]), reverse=True)
        raw_blocks = raw_blocks[:max_blocks]

    # 5) 每块挑出内部边
    out = []
    for label, blk_nodes in raw_blocks:
        ids = {n.get('node_id') for n in blk_nodes if n.get('node_id')}
        blk_edges = [e for e in edges
                     if e.get('from_node') in ids and e.get('to_node') in ids]
        out.append((label, blk_nodes, blk_edges))
    return out


def analyze_package_graph(nodes: List[Dict], edges: List[Dict], client, model: str,
                          samples: int = 1, block_nodes: int = BLOCK_NODES,
                          max_blocks: int = MAX_BLOCKS) -> Dict:
    """整包图细判：分块读图 → 汇总判决。

    聚合规则（保守但可解释）：
      - 任一块 MALICIOUS 且有**验证通过的路径** → 整包 MALICIOUS
      - 否则任一块 SUSPICIOUS → 整包 SUSPICIOUS
      - 否则 BENIGN
    路径永远来自 verify_paths（图验证），LLM 只负责指出。

    Returns:
        {
          'verdict', 'confidence', 'reasoning',
          'block_results': [...],      # 每块明细（可审计）
          'valid_paths': [...],        # 跨块合并、已验证
          'blocks_analyzed', 'nodes_total',
        }
    """
    if not nodes:
        return {'verdict': 'UNKNOWN', 'confidence': 0.0, 'reasoning': 'empty graph',
                'block_results': [], 'valid_paths': [],
                'blocks_analyzed': 0, 'nodes_total': 0}

    blocks = _split_blocks(nodes, edges, block_nodes=block_nodes,
                           max_blocks=max_blocks)
    block_results = []
    all_paths = []
    mal_blocks, sus_blocks = [], []

    for label, b_nodes, b_edges in blocks:
        r = analyze_block(b_nodes, b_edges, client, model, samples=samples)
        r['block'] = label
        r['block_nodes'] = len(b_nodes)
        block_results.append(r)
        v = r.get('verdict')
        if v == 'MALICIOUS' and r.get('valid_paths'):
            mal_blocks.append((label, r))
            all_paths.extend(r['valid_paths'])
        elif v in ('MALICIOUS', 'SUSPICIOUS'):
            sus_blocks.append((label, r))

    if mal_blocks:
        verdict = 'MALICIOUS'
        confidence = max(r.get('confidence', 0.0) for _, r in mal_blocks)
        reason = '; '.join(f"{lb}: {r.get('reasoning', '')[:80]}"
                           for lb, r in mal_blocks[:3])
    elif sus_blocks:
        verdict = 'SUSPICIOUS'
        confidence = max(r.get('confidence', 0.0) for _, r in sus_blocks)
        reason = '; '.join(f"{lb}: {r.get('reasoning', '')[:80]}"
                           for lb, r in sus_blocks[:3])
    elif any(r.get('verdict') == 'BENIGN' for r in block_results):
        verdict = 'BENIGN'
        confidence = 0.8
        reason = f'all {len(block_results)} blocks analyzed: no malicious path'
    else:
        verdict = 'UNKNOWN'
        confidence = 0.0
        reason = 'all blocks failed to produce a verdict'

    return {
        'verdict': verdict,
        'confidence': confidence,
        'reasoning': reason,
        'block_results': block_results,
        'valid_paths': all_paths,
        'blocks_analyzed': len(block_results),
        'nodes_total': len(nodes),
    }
