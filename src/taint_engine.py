# -*- coding: utf-8 -*-
"""污点引擎 - 在 DDG 子图上做真实的 Source→Sink 反向追踪

动机（2026-10 图内核重构）：此前喂给 LLM 的"数据流路径"是每条边生成一个
二元组（from/to 各一带 code），中间节点丢失，LLM 看到的不是攻击链而是碎片。
本模块在子图的节点/边上做真正的反向 BFS：从 Sink 出发沿 def→use 边回溯，
到达 Source 即产出一条完整污点链。

设计约束：
- 输入是子图 JSON 的 nodes/edges（与 _read_subgraph_jsons 的产物同构），不依赖
  builder 内部结构，可独立测试。
- 正则匹配限长（节点 code 截 500 字符已足够），无灾难性回溯模式。
- 链与步数都有上限，大子图（百节点级）耗时毫秒级。
"""

import re
from collections import deque
from typing import Dict, List, Optional

# 数据进入点（不可信来源）
SOURCE_PATTERNS = [
    (r'\bos\.environ\b', 'environment'),
    (r'\bos\.getenv\s*\(', 'environment'),
    (r'\bsys\.argv\b', 'cli_args'),
    (r'(?<![\w.])input\s*\(', 'user_input'),
    (r'(?<![\w.])open\s*\([^)]*[\'"]r', 'file_read'),
    (r'\.read(text|lines|line|bytes)?\s*\(', 'file_read'),
    (r'requests\.(get|post|put|head)\s*\(', 'network_response'),
    (r'\burlopen\s*\(', 'network_response'),
    (r'httpx\.(get|post)\s*\(', 'network_response'),
    (r'\.recv\s*\(', 'socket_recv'),
    (r'\b(pickle|marshal)\.loads\s*\(', 'deserialization'),
    (r'yaml\.load\s*\(', 'deserialization'),
    (r'b64decode\s*\(', 'decoded_data'),
]

# 危险汇聚点
SINK_PATTERNS = [
    (r'(?<![\w.])exec\s*\(', 'code_execution'),
    (r'(?<![\w.])eval\s*\(', 'code_execution'),
    (r'(?<![\w.])compile\s*\(', 'code_execution'),
    (r'\bos\.system\s*\(', 'command_execution'),
    (r'\bos\.popen\s*\(', 'command_execution'),
    (r'\bsubprocess\.\w+\s*\(', 'command_execution'),
    (r'requests\.(post|put)\s*\(', 'data_exfiltration'),
    (r'\burlopen\s*\([^)]*,', 'data_exfiltration'),
    (r'socket\.(send|sendall|sendto)\s*\(', 'data_exfiltration'),
    (r'smtplib\.', 'data_exfiltration'),
    (r'(?<![\w.])open\s*\([^)]*[\'"]w', 'file_write'),
    (r'\.write\s*\(', 'file_write'),
]

# 主来源归因优先级(模块级常量):越靠前越是"真正的外部来源"。
# decoded_data/deserialization 是变换而非源头——若同一 sink 同时
# 可达 os.environ 与 b64decode，主来源应归因到环境变量。
# 2026-10 提升为模块级:函数摘要等外部消费者也需要。
SOURCE_PRIORITY = {cat: rank for rank, cat in enumerate([
    'environment', 'cli_args', 'user_input', 'network_response',
    'file_read', 'socket_recv', 'deserialization', 'decoded_data',
])}

_MAX_CHAIN_DEPTH = 12
_MAX_CHAINS = 5
_MATCH_CHARS = 500


def _match(patterns: List, code: str) -> Optional[str]:
    """返回命中的第一个类别名，无命中返回 None"""
    if not code:
        return None
    text = code[:_MATCH_CHARS]
    for pattern, category in patterns:
        if re.search(pattern, text):
            return category
    return None


def analyze(nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
    """在子图上做污点追踪

    Args:
        nodes: [{'node_id','code','line','file','type',...}]
        edges: [{'from_node','to_node',...}]（def→use 方向）

    Returns:
        [{'sink': {...}, 'sink_category': str, 'source': {...},
          'source_category': str, 'steps': [{'stage','node_id','code','file','line'}]}]
    """
    if not nodes or not edges:
        return []

    node_map = {n.get('node_id'): n for n in nodes if n.get('node_id')}

    # 2026-10 结构尸检：复合语句节点(if/for/def/class)携带完整 body 文本，
    # 一个节点会同时命中 Source 和 Sink（gequests 实测产出 1 步退化链）。
    # 匹配限定在语句/调用级节点上——复合节点只作为传播中间节点。
    _COMPOSITE_TYPES = {'function', 'class', 'if', 'for', 'while', 'try'}

    def _matchable(node: Dict) -> bool:
        return (node.get('type') or '') not in _COMPOSITE_TYPES

    # 正向邻接表 + 反向邻接表 + 边类型表
    # 2026-10 BFS 审计修复:污点传播只走数据类边(data/param/call/return),
    # **排除 control**(true_branch/loop_body/contains)——实测
    # `if flag: os.system('ls')`(sink 参数是字面量)曾产出假的
    # environment→command_execution 链:环境变量只控制"是否执行",
    # 没有任何污点数据到达 sink。控制依赖不是数据依赖。
    reverse_adj: Dict[str, List[str]] = {}
    edge_kind_map: Dict[tuple, str] = {}
    for e in edges:
        src, dst = e.get('from_node'), e.get('to_node')
        if src and dst:
            kind = e.get('kind') or e.get('edge_kind') or 'data'
            if kind == 'control':
                continue
            reverse_adj.setdefault(dst, []).append(src)
            edge_kind_map[(src, dst)] = kind

    # 找 Sink 节点（复合节点不参与匹配,同上）
    # 2026-10 词法天花板攻坚:**resolved_call 优先**——AST 解析出的真实
    # 调用目标(getattr 常量折叠/别名追踪产物)直接查表;正则回退保留。
    # 2026-11 摘要传播:**sink_expansion**——builder 标记的"调用污点
    # 相关函数"的调用点,通过摘要传播 sink-ness,不依赖正则。
    from src.call_resolver import match_resolved_sink, match_resolved_source
    sinks = []
    for n in nodes:
        if not _matchable(n):
            continue
        resolved = n.get('resolved_call')
        category = match_resolved_sink(resolved) if resolved else None
        if not category:
            category = _match(SINK_PATTERNS, n.get('code', '') or '')
        if not category and n.get('sink_expansion'):
            # 摘要传播:调用污点相关函数 → 使用摘要中的 sink 类别
            cats = n.get('taint_categories') or ['code_execution']
            category = cats[0]
        if category:
            sinks.append((n, category))

    chains = []
    seen_chains = set()

    def _is_source(node: Dict) -> Optional[str]:
        if not _matchable(node):
            return None
        resolved = node.get('resolved_call')
        if resolved:
            cat = match_resolved_source(resolved)
            if cat:
                return cat
        return _match(SOURCE_PATTERNS, node.get('code', '') or '')

    for sink_node, sink_cat in sinks:
        if len(chains) >= _MAX_CHAINS:
            break
        sink_id = sink_node.get('node_id')
        if not sink_id:
            continue

        # 反向 BFS（主来源归因）：收集全部可达 Source,按优先级取主来源,
        # 平手取路径最长——替代原先"第一个命中即停"的最近来源语义
        #（b64decode 会抢在 os.environ 前面,归因不完整）
        parents = {sink_id: None}
        found_sources = []  # [(source_id, source_cat, depth)]
        queue = deque([(sink_id, 0)])
        while queue:
            cur, depth = queue.popleft()
            cur_node = node_map.get(cur) or {}
            if cur != sink_id:
                cat = _is_source(cur_node)
                if cat:
                    found_sources.append((cur, cat, depth))
            for pred in reverse_adj.get(cur, []):
                if pred not in parents:
                    parents[pred] = cur
                    queue.append((pred, depth + 1))
            if len(parents) > 600:  # 单 sink 搜索上限
                break

        if not found_sources:
            continue

        # 主来源 = 优先级最高；平手取最深(链最长=证据最完整)
        best_source_id, source_cat, _ = max(
            found_sources,
            key=lambda t: (-SOURCE_PRIORITY.get(t[1], 99), t[2]))

        # 重建路径 source → sink（沿 parents 从 source 走到 sink，已是正序）
        path_ids = []
        cur = best_source_id
        while cur is not None:
            path_ids.append(cur)
            cur = parents[cur]

        source_node = node_map.get(best_source_id, {})

        # 去重：同 (source_id, sink_id) 的链只留一条
        key = (best_source_id, sink_id)
        if key in seen_chains:
            continue
        seen_chains.add(key)

        # 截断时保留两端：头部 source 步 + 尾部 sink 步
        if len(path_ids) > _MAX_CHAIN_DEPTH:
            path_ids = path_ids[:_MAX_CHAIN_DEPTH - 1] + [path_ids[-1]]

        steps = []
        path_kinds = set()
        for i, nid in enumerate(path_ids):
            n = node_map.get(nid) or {}
            if nid == sink_id:
                stage = 'sink'
            elif i == 0:
                stage = 'source'
            else:
                stage = 'propagate'
            # 本步的入边类型(2026-10:数据流/调用边区分,LLM 与复核可读)
            via = edge_kind_map.get((path_ids[i - 1], nid)) if i > 0 else None
            if via:
                path_kinds.add(via)
            steps.append({
                'stage': stage,
                'node_id': nid,
                'code': (n.get('code', '') or '')[:160],
                'file': n.get('file', ''),
                'line': n.get('line', 0),
                'via': via,
            })

        # 跨文件标志 + 置信度(纯 data 边=0.9,穿 call/param 边=0.75)
        step_files = {s.get('file', '') for s in steps if s.get('file')}
        cross_file = len(step_files) > 1
        confidence = 0.9 if path_kinds <= {'data', None} else 0.75

        chains.append({
            'sink': {'node_id': sink_id,
                     'code': (sink_node.get('code', '') or '')[:160],
                     'file': sink_node.get('file', ''),
                     'line': sink_node.get('line', 0)},
            'sink_category': sink_cat,
            'source': {'node_id': best_source_id,
                       'code': (source_node.get('code', '') or '')[:160],
                       'file': source_node.get('file', ''),
                       'line': source_node.get('line', 0)},
            'source_category': source_cat,
            'steps': steps,
            'cross_file': cross_file,
            'confidence': confidence,
        })

    return chains


def format_for_prompt(chains: List[Dict], max_chains: int = 4) -> str:
    """把污点链格式化为 LLM prompt 文本（2026-10 硬化：代码消毒后呈现）

    2026-10 结构重构:呈现主来源归因/边类型/跨文件标志/置信度。
    """
    from src.llm_sanitizer import sanitize_code
    if not chains:
        return "No complete taint chain found in this subgraph."
    lines = []
    for i, c in enumerate(chains[:max_chains], 1):
        flags = []
        if c.get('cross_file'):
            flags.append('CROSS-FILE')
        if c.get('confidence') is not None:
            flags.append(f"confidence={c['confidence']}")
        suffix = f" ({', '.join(flags)})" if flags else ''
        lines.append(
            f"Taint Chain {i} [Source: {c['source_category']} -> Sink: {c['sink_category']}]{suffix}:")
        for s in c['steps']:
            icon = {'source': '[SOURCE]', 'sink': '[SINK]', 'propagate': '  -->'}.get(s['stage'], '     ')
            via = f" --{s['via']}-->" if s.get('via') and s['via'] != 'data' else ''
            fname = s['file'].replace('\\', '/').rsplit('/', 1)[-1] if s['file'] else '?'
            code = sanitize_code(s['code'], marker=f"L{s['line']}")
            lines.append(f"  {icon} L{s['line']} in {fname}{via}: {code}")
    return "\n".join(lines)
