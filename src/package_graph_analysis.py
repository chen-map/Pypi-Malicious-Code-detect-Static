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
                  max_blocks: int = MAX_BLOCKS
                  ) -> List[Tuple[str, List[Dict], List[Dict], Dict]]:
    """把整包图切成若干块，每块可独立交给 LLM。

    切分顺序：文件 → 函数 → 贪心填充。
    返回 [(label, nodes, edges, boundary_edges)]：
      - edges 只保留两端在本块内的
      - boundary_edges 是**跨块边**（{'in': [...], 'out': [...]}），
        不把外部节点拉进块，只告诉 LLM 数据从哪进来、去哪了。
        （2026-11：诱导子图会切断跨函数/跨文件流，这里补旁路元数据）
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

    # 5) 每块挑出内部边 + 跨块边（跨块边单独作为旁路元数据）
    _BOUNDARY_KINDS = {'data', 'param', 'return', 'call'}
    _KIND_RANK = {'return': 0, 'data': 1, 'param': 2, 'call': 3}
    _MAX_PER_SIDE = 20

    node_block: Dict[str, int] = {}
    for bi, (_label, blk_nodes) in enumerate(raw_blocks):
        for n in blk_nodes:
            nid = n.get('node_id')
            if nid:
                node_block[nid] = bi

    by_id = {n.get('node_id'): n for n in nodes if n.get('node_id')}
    boundary: List[Dict[str, List[Dict]]] = [
        {'in': [], 'out': []} for _ in raw_blocks]

    for e in edges:
        a, b = e.get('from_node'), e.get('to_node')
        ba, bb = node_block.get(a), node_block.get(b)
        if ba is None or bb is None or ba == bb:
            continue
        kind = e.get('kind') or e.get('edge_kind') or 'data'
        if kind not in _BOUNDARY_KINDS:
            continue
        na, nb = by_id.get(a) or {}, by_id.get(b) or {}
        rec = {
            'from_node': a, 'to_node': b,
            'from_file': na.get('file', ''), 'from_line': na.get('line', 0),
            'to_file': nb.get('file', ''), 'to_line': nb.get('line', 0),
            'from_func': na.get('function_name') or '<module>',
            'to_func': nb.get('function_name') or '<module>',
            'kind': kind, 'variable': e.get('variable') or '',
        }
        boundary[ba]['out'].append(rec)
        boundary[bb]['in'].append(rec)

    def _key(rec):
        return (0 if rec['from_file'] != rec['to_file'] else 1,
                _KIND_RANK.get(rec['kind'], 9),
                rec['from_node'], rec['to_node'])

    out = []
    for (label, blk_nodes), bd in zip(raw_blocks, boundary):
        ids = {n.get('node_id') for n in blk_nodes if n.get('node_id')}
        blk_edges = [e for e in edges
                     if e.get('from_node') in ids and e.get('to_node') in ids]
        bounded = {
            'in': sorted(bd['in'], key=_key)[:_MAX_PER_SIDE],
            'out': sorted(bd['out'], key=_key)[:_MAX_PER_SIDE],
        }
        out.append((label, blk_nodes, blk_edges, bounded))
    return out


def analyze_package_graph(nodes: List[Dict], edges: List[Dict], client, model: str,
                          samples: int = 1, block_nodes: int = BLOCK_NODES,
                          max_blocks: int = MAX_BLOCKS,
                          time_budget_s: float = 0) -> Dict:
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
                'blocks_analyzed': 0, 'nodes_total': 0,
                'truncated_by_budget': False}

    blocks = _split_blocks(nodes, edges, block_nodes=block_nodes,
                           max_blocks=max_blocks)
    block_results = []
    all_paths = []
    mal_blocks, sus_blocks = [], []

    # 2026-11 时间预算：块数是预算，但大包的**单块**可能几千节点，
    # 光限块数挡不住（实测一个 9317 节点良性包，10 块读了 40 分钟）。
    # 超预算就停在当前块，用已读结果聚合。
    import time as _time
    _t0 = _time.time()
    _budget_hit = False

    for label, b_nodes, b_edges, b_boundary in blocks:
        if time_budget_s and (_time.time() - _t0) > time_budget_s:
            _budget_hit = True
            print(f"        [包块划分] 超出时间预算 {time_budget_s:.0f}s，"
                  f"停在 {len(block_results)}/{len(blocks)} 块")
            break
        r = analyze_block(b_nodes, b_edges, client, model, samples=samples,
                          boundary_edges=b_boundary)
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
        'truncated_by_budget': _budget_hit,
        'nodes_total': len(nodes),
    }
