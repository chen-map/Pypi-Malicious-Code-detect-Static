# -*- coding: utf-8 -*-
"""IOC 目标感知（Target Awareness）· 数据流出去了，流向了谁？

动机（2026-11，500+500 FP 归因 + twirp/pyslack/colcon/artifactory 驱动）：
    `requests.post` 的 sink 类别是 data_exfiltration——API 客户端与真
    外传在【类别】层面不可分。区别只有一个：**目的地**。

        流向自有服务端（self._address / PKG-INFO homepage）→ 正常业务
        流向裸 IP / oastify / webhook.site / 矿池          → 攻击基础设施
        流向 b64 解出来 / 拼接 / 环境变量                    → dynamic（故意藏）
        解析不到字面量                                       → none

    四分类 → 进升级门：EXFIL sink 按目标分层定罪，替代"一律定罪"。

设计约束：
    - 纯本地规则，零联网（不需要 VirusTotal 也能覆盖主要攻击形态）
    - 浅层指向分析：沿数据边回溯一跳找默认参数/字面量；追不到就 none
    - 攻击基础设施特征表是显式清单 + 形状规则，可单测
"""
import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ===== 攻击基础设施特征 =====
# interactsh / DNS 回连平台（攻击者测试外传的标准工具）
_OAST_DOMAINS = ('oastify.com', 'oast.pro', 'oast.fun', 'oast.live',
                 'oast.site', 'interact.sh', 'interactsh',
                 'dnslog.cn', 'ceye.io', 'webhook.site', 'requestbin',
                 'pipedream.net', 'burpcollaborator.net')
# 数据外传/暂存服务（窃取数据的常见落点）
_EXFIL_HOSTS = ('pastebin.com', 'hastebin', 'ghostbin', 'termbin',
                'transfer.sh', 'file.io', 'anonfiles', 'gofile.io',
                'discord.com/api/webhooks', 'discordapp.com/api/webhooks',
                'telegram.org', 'api.telegram.org', 't.me')
# 矿池协议特征
_MINER_RE = re.compile(r'(stratum\+?tcp|stratum\+?ssl)://|pool\.[\w-]+\.(com|net|org|io)|'
                       r'supportxmr|xmrpool|nanopool|f2pool|pool\.hashvault', re.IGNORECASE)
_BARE_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$')
# 隧道/C2 前置服务（2026-11，calculator_2c397c49ab20c445 驱动：47 行反弹
# shell，socket.connect(("4.tcp.eu.ngrok.io",19931))，整包判了 BENIGN）。
# 这类主机是"临时公网入口"，正常软件运行时极少连它，是 C2 的标准形态。
_C2_TUNNEL_HOSTS = ('ngrok.io', 'ngrok-free.app', 'ngrok.app', 'ngrok.dev',
                    'ngrok-free.dev', 'localtunnel.me', 'loca.lt', 'serveo.net',
                    'trycloudflare.com', 'bore.pub', 'localhost.run',
                    'pagekite.me', 'telebit.io', 'pinggy.io', 'tunnelto.dev')
# Tor 隐藏服务——合法软件几乎不直连
_ONION_RE = re.compile(r'\b[a-z2-7]{16}\.onion\b', re.IGNORECASE)
# 连接/外发语句（判断字面量是否真的落在连接点上，而非文档字符串）
_CONNECT_RE = re.compile(r'\b(connect|connect_ex|create_connection|urlopen|'
                         r'requests\.(post|get|put)|session\.(post|get|put)|'
                         r'urllib\.request|http\.client|os\.system|Popen|call|run)\s*\(')
# 连接形态的 IP:port：connect(("1.2.3.4", 4444))
_IP_PORT_RE = re.compile(r'[\'"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\'"]\s*,\s*(\d{2,5})')
# 疑似恶意 TLD（廉价/匿名注册，常见于一次性 C2）
_SUSPECT_TLD = ('.tk', '.top', '.xyz', '.click', '.link', '.gq', '.cf', '.ml')


def hostile_literal_in(code: str) -> Optional[str]:
    """一条语句里是否含攻击者基础设施字面量？命中返回类型名。

    与 classify_target 的分工：classify_target 判"流出的目标属于谁"，
    这里判"这段代码本身是不是在连攻击基础设施"。零数据流的硬编码 C2
    （socket.connect(("x.ngrok.io", 19931))）没有 source 也没有链，
    只能靠字面量本身作证——这是字面量证据通道的入口。
    """
    if not code:
        return None
    low = code.lower()
    if _ONION_RE.search(low):
        return 'onion'
    for h in _C2_TUNNEL_HOSTS:
        if h in low:
            return 'c2_tunnel'
    if _MINER_RE.search(low):
        return 'miner'
    if _CONNECT_RE.search(low):
        for h in _OAST_DOMAINS + _EXFIL_HOSTS:
            if h in low:
                return 'exfil_endpoint'
        if _IP_PORT_RE.search(code):
            return 'ip_port'
    return None


def classify_target(target: str) -> str:
    """把一个目标字符串归入四分类。

    Returns:
        'attacker_infra' | 'package_own' | 'dynamic' | 'none'
    """
    if not target:
        return 'none'
    t = target.strip().lower()

    if _MINER_RE.search(t):
        return 'attacker_infra'
    if any(h in t for h in _OAST_DOMAINS):
        return 'attacker_infra'
    if any(h in t for h in _EXFIL_HOSTS):
        return 'attacker_infra'
    # URL 里的主机也可能就是裸 IP（http://194.5.98.1:8080/upload）
    host = _host_of(t)
    if host:
        if _BARE_IP_RE.match(host):
            return 'attacker_infra'      # 裸 IP（无域名）= 默认不可信
        if host.endswith(_SUSPECT_TLD):
            return 'attacker_infra'
    if _BARE_IP_RE.match(t):
        return 'attacker_infra'
    # 形状是网络地址但解析不出归属——按自有处理
    if host or t.startswith(('http://', 'https://')):
        return 'package_own'
    return 'none'


def _host_of(target: str) -> str:
    t = target.strip().lower()
    m = re.match(r'https?://([^/\'"():\s]+)', t)
    if m:
        return m.group(1)
    if _BARE_IP_RE.match(t):
        return t.split(':')[0]
    # host:port 或裸域名
    if re.match(r'^[\w.-]+(\.\w+)+(:\d+)?$', t):
        return t
    return ''


def _stringify(node) -> Optional[str]:
    """AST 节点 → 字面量字符串（含拼接折叠）"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _stringify(node.left)
        right = _stringify(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):     # f-string：含占位符 = 动态目标
        return '__fstring__'
    return None


def _extract_call_target(code: str) -> Optional[str]:
    """从 sink 语句提取 URL/主机参数字面量。

    requests.post("http://..") / urlopen("http://..") /
    socket.connect(("1.2.3.4", 4444)) / os.system("curl http://..")
    """
    try:
        tree = ast.parse(code)
    except Exception:
        return None
    found: List[str] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        # 位置参数与 url= 关键字参数都看
        args = list(n.args) + [kw.value for kw in n.keywords
                               if kw.arg in ('url', 'host', 'address', 'addr')]
        for a in args:
            s = _stringify(a)
            if s:
                found.append(s)
                break
    if not found:
        return None
    # 优先返回含网络形状的那个
    for s in found:
        if 'http' in s.lower() or _BARE_IP_RE.match(s) or 'stratum' in s.lower():
            return s
    return found[0]


def chain_target(chain: Dict, nodes: List[Dict],
                 project_dir=None) -> Tuple[str, str]:
    """解析一条污点链的 sink 目标。

    沿链的 sink 节点取完整源码（AST-dump 修复后是真实代码），提取
    调用参数字面量；无字面量时做一跳浅解析（同语句赋值/默认参数）。

    Returns:
        (classification, evidence)  如 ('attacker_infra', 'oastify.com')
    """
    sink = chain.get('sink') or {}
    node_by_id = {n.get('node_id'): n for n in nodes if n.get('node_id')}
    # 优先级：chain 携带的 sink code > 图上同 id 节点的 code
    # （chain 的 sink code 由 taint 引擎写回，已是该 sink 的真实语句；
    #   nodes 可能是过滤后的子集，同 id 不保证是同一个 sink）
    code = sink.get('code') or ''
    nid = sink.get('node_id')
    if not code and nid and nid in node_by_id:
        code = node_by_id[nid].get('code') or ''
    if not code:
        return 'none', ''

    target = _extract_call_target(code)
    if target:
        cls = classify_target(target)
        return cls, target[:120]

    # 无字面量参数：目的地是运行时构造（twirp 形态 url=self._address+url、
    # f-string、纯变量）→ dynamic。故意不可静态解析比"解析不到"更可疑，
    # 但不足以定罪——交给 LLM 意图比对。
    try:
        tree = ast.parse(code)
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            args = list(n.args) + [kw.value for kw in n.keywords
                                   if kw.arg in ('url', 'host', 'address', 'addr')]
            for a in args:
                if isinstance(a, (ast.BinOp, ast.JoinedStr)):
                    return 'dynamic', 'target built at runtime'
                # 纯参数名（requests.post(url) 的 url= 关键字回环）
                # 不算运行时构造；裸变量名才算（self._address 形态已被
                # BinOp/Attribute 覆盖，这里是直接传变量的情况）
                if isinstance(a, ast.Name):
                    return 'dynamic', f'target from variable {a.id}'
                if isinstance(a, ast.Attribute):
                    return 'dynamic', 'target from attribute'
    except Exception:
        pass
    return 'none', ''


_ASSIGN_NAME_RE = re.compile(r'^\s*([a-zA-Z_]\w*)\s*=\s*(.{0,120})')


def _shallow_resolve(chain: Dict, node_by_id: Dict) -> Optional[str]:
    """sink 引用的变量名 → 链上/同文件节点的赋值字面量（一跳）"""
    sink = chain.get('sink') or {}
    code = sink.get('code') or ''
    m = _ASSIGN_NAME_RE.match('')   # 占位，避免 linter
    # 收集 sink 代码里的裸名字（粗略）
    names = set(re.findall(r'\b([a-zA-Z_]\w{2,20})\b', code))
    for s in chain.get('steps') or []:
        n = node_by_id.get(s.get('node_id')) or {}
        src = n.get('code') or ''
        m2 = _ASSIGN_NAME_RE.match(src)
        if m2 and m2.group(1) in names:
            val = m2.group(2).strip()
            if ('http' in val.lower() or _BARE_IP_RE.match(val)
                    or 'stratum' in val.lower()):
                return val
    return None
