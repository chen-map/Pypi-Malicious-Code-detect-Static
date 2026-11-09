# -*- coding: utf-8 -*-
"""函数目录与 top-N 选择（2026-11，LLM 划分的耦合层）

问题：
    PyFlow 产出的全包图动辄上万节点，LLM 读不了。之前按"文件→函数→预算"
    切块，切分依据是随机的（外部调用密度），且切断跨函数关系。

做法：
    先把图压缩成**函数目录**（一个函数一行），再按多维信号打分选 top-N，
    交付小模型提取链路。

    目录规模实测（dist_meta 62 函数 → 1.2k tokens；requsets 457 函数 →
    10k tokens）。选 top-N 后只需展开 10-20 个函数，规模回到可读区间。

打分维度（全部可解释、可调）：
    能力等级   Tier-1 能力（执行/外传/提权/凭据）权重最高
    出入度     函数级 in/out degree——被调用多 = 枢纽，调用多 = 编排者
    执行时机   install/import 期执行是 PyPI 主战场
    敌意字面量 有解码载荷/矿池/回连 = 直接证据
    跨文件     与其他文件有边 = 攻击链跨度
    模块级     setup.py / __init__.py 顶层代码

设计约束：
    - 纯确定性打分，不调 LLM
    - 选出的函数必须"完整展开"（整函数体 + 边界边），不能切半
    - 目录本身可渲染给 LLM（Tier A/B/C 分层），供后续"LLM 参与划分"
"""
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# 能力权重（Tier-1 直接是攻击链要素）
_CAP_WEIGHT = {
    'process_spawn': 10, 'code_eval': 10, 'network_out': 9,
    'privilege': 10, 'credential_access': 10,
    'deserialize': 6, 'decode': 5, 'network_in': 5, 'file_write': 5,
    'env_access': 3, 'file_read': 2,
}

# 攻击链常见的关键词（节点代码里出现，说明这个函数"有攻击面"）
_SINK_HINT = re.compile(
    r'\b(exec|eval|compile|__import__|subprocess|os\.system|popen|'
    r'urlopen|urlretrieve|requests\.(get|post)|socket\.|pickle\.loads|'
    r'marshal\.loads|b64decode|ctypes|chmod|setuid)\b', re.IGNORECASE)

# 敌意字面量（有解码载荷时也算）
_HOSTILE_HINT = re.compile(
    r'(/dev/tcp|encodedcommand|supportxmr|stratum|oastify|pastebin|'
    r'webhook\.site|\.onion|wallet)', re.IGNORECASE)


def _fn_key(n: Dict) -> Tuple[str, str]:
    return (n.get('file') or '', n.get('function_name') or '<module>')


def build_catalog(nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
    """把图压缩成函数目录。

    Returns:
        [{'key','file','name','lines','n_stmt','caps','in','out','phase',
          'hostile','sink_hits','score','reasons'}]
    """
    by_fn: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for n in nodes:
        by_fn[_fn_key(n)].append(n)

    fn_of = {n['node_id']: _fn_key(n) for n in nodes if n.get('node_id')}
    ind: Dict[Tuple[str, str], int] = defaultdict(int)
    outd: Dict[Tuple[str, str], int] = defaultdict(int)
    cross: Dict[Tuple[str, str], int] = defaultdict(int)
    for e in edges:
        a = fn_of.get(e.get('from_node'))
        b = fn_of.get(e.get('to_node'))
        if not a or not b:
            continue
        if a != b:
            outd[a] += 1
            ind[b] += 1
            if a[0] != b[0]:
                cross[a] += 1
                cross[b] += 1

    catalog: List[Dict] = []
    for key, ns in by_fn.items():
        f, name = key
        caps = {n['capability'] for n in ns if n.get('capability')}
        phases = {n.get('phase') for n in ns if n.get('phase')}
        hostile = any(_HOSTILE_HINT.search(n.get('code') or '') for n in ns)
        sink_hits = sum(1 for n in ns if _SINK_HINT.search(n.get('code') or ''))
        lines = sorted({int(n.get('line') or 0) for n in ns})
        rec = {
            'key': key,
            'file': f,
            'name': name,
            'lines': (lines[0], lines[-1]) if lines else (0, 0),
            'n_stmt': len(ns),
            'caps': sorted(caps),
            'in': ind[key],
            'out': outd[key],
            'cross': cross[key],
            'phase': ('install' if 'install' in phases else
                      'import' if 'import' in phases else 'runtime'),
            'hostile': hostile,
            'sink_hits': sink_hits,
            'module_level': name == '<module>',
        }
        rec['score'], rec['reasons'] = _score(rec)
        catalog.append(rec)

    catalog.sort(key=lambda r: r['score'], reverse=True)
    return catalog


def _score(rec: Dict) -> Tuple[float, List[str]]:
    """确定性打分 + 可读理由（审计用）"""
    score = 0.0
    reasons: List[str] = []

    for c in rec['caps']:
        w = _CAP_WEIGHT.get(c, 0)
        if w:
            score += w
            reasons.append(c)

    # 出入度取对数，避免枢纽函数垄断
    if rec['out']:
        score += 3 * math.log1p(rec['out'])
    if rec['in']:
        score += 2 * math.log1p(rec['in'])
    if rec['out'] or rec['in']:
        reasons.append(f"in{rec['in']}/out{rec['out']}")

    if rec['phase'] in ('install', 'import'):
        score += 6
        reasons.append(f"{rec['phase']}-time")

    if rec['hostile']:
        score += 8
        reasons.append('hostile-literal')

    if rec['sink_hits']:
        score += min(rec['sink_hits'], 3) * 1.5
        reasons.append(f"sink×{rec['sink_hits']}")

    if rec['cross']:
        score += 2
        reasons.append(f"cross-file×{rec['cross']}")

    if rec['module_level']:
        score += 2
        reasons.append('module-level')

    # 测试/示例目录降权：恶意包常把正版 tests/ 整包复制，纯噪声
    try:
        from src.benign_context import is_fixture_path
        if is_fixture_path(rec['file']):
            score *= 0.25
            reasons.append('fixture×0.25')
    except Exception:
        pass

    return round(score, 2), reasons


def select_top(catalog: List[Dict], n: int = 12,
               min_score: float = 3.0) -> List[Dict]:
    """选 top-N 函数；分数太低的不入选（避免纯工具函数占位）。"""
    picked = [r for r in catalog if r['score'] >= min_score][:n]
    return picked


def expand_functions(nodes: List[Dict], edges: List[Dict],
                     selected: List[Dict]) -> List[Dict]:
    """把选中的函数展开成若干"块"（供 LLM 读），每块含：
        label / nodes / edges(块内) / boundary_edges(跨块)
    """
    keys: Set[Tuple[str, str]] = {tuple(r['key']) for r in selected}
    by_fn: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for n in nodes:
        by_fn[_fn_key(n)].append(n)

    node_block: Dict[str, int] = {}
    blocks = []
    for i, r in enumerate(selected):
        key = tuple(r['key'])
        ns = by_fn.get(key) or []
        ids = {n['node_id'] for n in ns if n.get('node_id')}
        for nid in ids:
            node_block[nid] = i
        blocks.append({
            'label': f"{Path(r['file']).name}::{r['name']}",
            'nodes': ns,
            'edges': [],
            'boundary_edges': {'in': [], 'out': []},
            'meta': r,
        })

    by_id = {n['node_id']: n for n in nodes if n.get('node_id')}
    for e in edges:
        a, b = e.get('from_node'), e.get('to_node')
        ba, bb = node_block.get(a), node_block.get(b)
        if ba is not None and ba == bb:
            blocks[ba]['edges'].append(e)
        elif ba is not None or bb is not None:
            rec = {
                'from_node': a, 'to_node': b,
                'from_file': (by_id.get(a) or {}).get('file', ''),
                'from_line': (by_id.get(a) or {}).get('line', 0),
                'to_file': (by_id.get(b) or {}).get('file', ''),
                'to_line': (by_id.get(b) or {}).get('line', 0),
                'from_func': (by_id.get(a) or {}).get('function_name') or '<module>',
                'to_func': (by_id.get(b) or {}).get('function_name') or '<module>',
                'kind': e.get('kind') or 'data',
                'variable': e.get('variable') or '',
            }
            if ba is not None:
                blocks[ba]['boundary_edges']['out'].append(rec)
            if bb is not None:
                blocks[bb]['boundary_edges']['in'].append(rec)
    return blocks


def render_catalog(catalog: List[Dict], top_n: int = 12,
                   max_chars: int = 6000) -> str:
    """渲染给 LLM 的目录（分层：有能力的 / 关联的 / 其余折叠）"""
    if not catalog:
        return '(empty)'
    lines = []
    picked = catalog[:top_n]
    picked_keys = {tuple(r['key']) for r in picked}

    lines.append(f"## FUNCTION CATALOG  ({len(catalog)} functions)")
    lines.append("### Selected for analysis (top by score)")
    for i, r in enumerate(picked, 1):
        caps = ','.join(r['caps']) or '-'
        lines.append(
            f"{i:2d}. {Path(r['file']).name}::{r['name']} "
            f"L{r['lines'][0]}-{r['lines'][1]} {r['n_stmt']}stmt "
            f"[{caps}] in{r['in']}/out{r['out']} {r['phase']} "
            f"score={r['score']} ({', '.join(r['reasons'][:4])})")

    rest = [r for r in catalog[top_n:] if r['caps'] or r['hostile']]
    if rest:
        lines.append(f"### Not selected but capability-bearing ({len(rest)})")
        for r in rest[:10]:
            lines.append(f"    {Path(r['file']).name}::{r['name']} "
                         f"[{','.join(r['caps'])}] score={r['score']}")

    plain = len(catalog) - len(picked) - len(rest)
    if plain > 0:
        lines.append(f"### Other functions: {plain} (no capability, low degree)")

    text = '\n'.join(lines)
    if len(text) > max_chars:
        text = text[:max_chars] + '\n... (catalog truncated)'
    return text
