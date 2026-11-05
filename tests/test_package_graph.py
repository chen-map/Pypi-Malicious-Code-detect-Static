# -*- coding: utf-8 -*-
"""包级图细判测试：分块 + 聚合 + 结构门控

验证的核心命题（架构重构）：
**粗筛只决定"先看哪里"，细判（图 + LLM）决定"哪里恶意"**。
因此即使正则完全没命中（所有节点 is_dangerous=False），
只要图里存在真实的数据流链，细判也应该抓出来。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.package_graph_analysis import _split_blocks, analyze_package_graph

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


print("=== 1. 分块 ===")
nodes = []
for i in range(30):
    nodes.append({'node_id': f'a{i}', 'code': 'x=1', 'line': i,
                  'file': 'small.py', 'function_name': 'f'})
for i in range(1200):
    nodes.append({'node_id': f'b{i}', 'code': 'y=2', 'line': i,
                  'file': 'big.py', 'function_name': f'g{i % 3}'})
blocks = _split_blocks(nodes, [], block_nodes=500, max_blocks=12)
check("按函数切分大文件", len(blocks) == 4, detail=str(len(blocks)))
check("单块不超预算", all(len(b[1]) <= 500 for b in blocks))
check("块标签含文件与函数", any('big.py::g' in b[0] for b in blocks))

print("=== 2. 聚合：任一块恶意且有路径 → 整包恶意 ===")


class FakeClient:
    """按块内容返回预设判决：包含 exec 的块判恶意"""
    def __init__(self):
        self.chat = self
        self.completions = self
        self.calls = 0

    def create(self, **kw):
        self.calls += 1
        content = kw['messages'][-1]['content']
        # 找出 digest 里的一个节点作为"路径"
        import re
        ids = re.findall(r'^(N\d+)  \[', content, re.MULTILINE)
        has_bad = 'exec(' in content
        if has_bad and len(ids) >= 2:
            body = ('{"paths": [{"nodes": ["%s", "%s"], "behavior": "x", '
                    '"why_malicious": "y"}], "verdict": "MALICIOUS", '
                    '"confidence": 0.9, "reasoning": "r"}' % (ids[0], ids[1]))
        else:
            body = ('{"paths": [], "verdict": "BENIGN", '
                    '"confidence": 0.8, "reasoning": "clean"}')

        class R:
            class C:
                message = type('M', (), {'content': body})
            choices = [C()]
        return R()


# 构造：一个小文件含 exec 流，另一个文件干净；全部节点不被正则标记
danger_nodes = [
    {'node_id': 's1', 'code': 'import requests', 'line': 1, 'file': 'evil.py',
     'type': 'import', 'function_name': '<module>'},
    {'node_id': 's2', 'code': 'd = requests.get(u).text', 'line': 2, 'file': 'evil.py',
     'type': 'assign', 'function_name': '<module>'},
    {'node_id': 's3', 'code': 'exec(d)', 'line': 3, 'file': 'evil.py',
     'type': 'call', 'function_name': '<module>'},
]
clean_nodes = [
    {'node_id': 'c1', 'code': 'v = 1', 'line': 1, 'file': 'ok.py',
     'type': 'assign', 'function_name': 'f'},
    {'node_id': 'c2', 'code': 'return v', 'line': 2, 'file': 'ok.py',
     'type': 'return', 'function_name': 'f'},
]
danger_edges = [
    {'from_node': 's1', 'to_node': 's2', 'kind': 'data', 'variable': 'requests'},
    {'from_node': 's2', 'to_node': 's3', 'kind': 'data', 'variable': 'd'},
]
r = analyze_package_graph(danger_nodes + clean_nodes, danger_edges, FakeClient(), 'fake')
check("含恶意流的块 → 整包 MALICIOUS", r['verdict'] == 'MALICIOUS', detail=r['verdict'])
check("路径来自图验证", len(r['valid_paths']) >= 1)
check("所有块都被分析（无粗筛过滤）", r['blocks_analyzed'] == 2,
      detail=str(r['blocks_analyzed']))
check("正则标记全为 False 也能检出",
      all(not n.get('is_dangerous') for n in danger_nodes + clean_nodes))

print("=== 3. 无路径的 MALICIOUS 不升级 ===")


class HallucClient:
    def __init__(self):
        self.chat = self
        self.completions = self

    def create(self, **kw):
        body = ('{"paths": [{"nodes": ["N1", "N999"], "behavior": "x", '
                '"why_malicious": "y"}], "verdict": "MALICIOUS", '
                '"confidence": 0.95, "reasoning": "r"}')

        class R:
            class C:
                message = type('M', (), {'content': body})
            choices = [C()]
        return R()


r2 = analyze_package_graph(clean_nodes, [], HallucClient(), 'fake')
check("幻觉路径导致降级", r2['verdict'] == 'SUSPICIOUS', detail=r2['verdict'])

print("=== 4. 空图安全 ===")
r3 = analyze_package_graph([], [], FakeClient(), 'fake')
check("空图返回 UNKNOWN", r3['verdict'] == 'UNKNOWN')

print(f"\n结果: {PASS} 通过, {FAIL} 失败")
sys.exit(1 if FAIL else 0)
