# -*- coding: utf-8 -*-
"""跨作用域证据测试（2026-11 划分越界修复）

覆盖三件事：
  1. taint_engine.distribute_chains / merge_chains —— 全图链按块分发
  2. _split_blocks 的跨块边（boundary_edges）—— 不把外部节点拉进块
  3. digest 的 ## BOUNDARY EDGES 渲染
  4. partition_by_function 的跨块边元数据

背景：函数级划分用 nx.subgraph()/块内边过滤，会切断 DDG 建图阶段
resolve_cross_file / CrossFileCallTracker 得到的跨函数、跨文件边。
跨块边作为**旁路元数据**随块落盘，只影响 prompt，不影响块内节点。
"""
import sys
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.taint_engine import distribute_chains, merge_chains
from src.package_graph_analysis import _split_blocks
from src.graph_digest import digest

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


# ==================== 1. distribute_chains / merge_chains ====================
def _chain(src, sink, step_ids, **kw):
    return {
        'source_category': src,
        'sink_category': sink,
        'steps': [{'stage': 'source' if i == 0 else 'sink',
                   'node_id': nid, 'code': f'code_{nid}',
                   'file': f'f{i}.py', 'line': i + 1}
                  for i, nid in enumerate(step_ids)],
        **kw,
    }


print("[1] distribute_chains / merge_chains")

C_CROSS = _chain('network_response', 'code_execution', ['s1', 'm1', 'k1'],
                 cross_file=True)
C_LOCAL = _chain('environment', 'command_execution', ['k1', 'k2'])
C_OTHER = _chain('user_input', 'file_write', ['z1', 'z2'])

# 跨块链：只有 k1 落在本块
hit = distribute_chains([C_CROSS, C_LOCAL, C_OTHER], {'k1', 'k2'})
check("按步骤节点交集分发", len(hit) == 2, detail=str(len(hit)))
check("命中跨块链", C_CROSS in hit)
check("未命中的链被排除", C_OTHER not in hit)

# min_hits=2 过滤掉只沾一步的链
hit2 = distribute_chains([C_CROSS, C_LOCAL], {'k1', 'k2'}, min_hits=2)
check("min_hits 生效", hit2 == [C_LOCAL], detail=str(len(hit2)))

check("空 node_ids 返回空", distribute_chains([C_CROSS], set()) == [])
check("空 chains 返回空", distribute_chains([], {'k1'}) == [])

merged = merge_chains([C_CROSS], [C_CROSS, C_LOCAL])
check("合并去重", len(merged) == 2, detail=str(len(merged)))
check("跨块链排前面", merged[0] is C_CROSS)

capped = merge_chains([C_CROSS, C_LOCAL, C_OTHER], [], max_chains=2)
check("合并后截断", len(capped) == 2, detail=str(len(capped)))


# ==================== 2. _split_blocks 跨块边 ====================
print("[2] _split_blocks boundary_edges")

nodes = [
    {'node_id': 'a1', 'file': 'a.py', 'function_name': 'f1',
     'code': 'payload = net.get()', 'line': 1},
    {'node_id': 'a2', 'file': 'a.py', 'function_name': 'f1',
     'code': 'data = parse(payload)', 'line': 2},
    {'node_id': 'a3', 'file': 'a.py', 'function_name': 'f1',
     'code': 'exec(data)', 'line': 3},
    {'node_id': 'b1', 'file': 'b.py', 'function_name': 'f2',
     'code': 'run(payload)', 'line': 10},
    {'node_id': 'b2', 'file': 'b.py', 'function_name': 'f2',
     'code': 'os.system(cmd)', 'line': 11},
]
edges = [
    {'from_node': 'a1', 'to_node': 'a2', 'kind': 'data', 'variable': 'payload'},
    {'from_node': 'a2', 'to_node': 'a3', 'kind': 'data', 'variable': 'data'},
    # 跨文件 → 跨块
    {'from_node': 'a3', 'to_node': 'b2', 'kind': 'return', 'variable': 'cmd'},
    # control 边不参与边界（函数间没有语句顺序关系）
    {'from_node': 'a1', 'to_node': 'b1', 'kind': 'control'},
]

blocks = _split_blocks(nodes, edges, block_nodes=10, max_blocks=10)
check("切成两块", len(blocks) == 2, detail=str(len(blocks)))
check("返回四元组", all(len(b) == 4 for b in blocks))

by_label = {b[0]: b for b in blocks}
blk_a = by_label.get('a.py')
blk_b = by_label.get('b.py')
check("两块都存在", blk_a and blk_b, detail=str(list(by_label)))

if blk_a and blk_b:
    check("块内边只含本块",
          {e['from_node'] for e in blk_a[2]} <= {'a1', 'a2', 'a3'})
    check("跨块边不在块内边里",
          not any(e.get('to_node') == 'b2' for e in blk_a[2]))
    check("OUT 侧记录跨块边",
          any(r['to_node'] == 'b2' for r in blk_a[3]['out']),
          detail=str(blk_a[3]))
    check("IN 侧记录跨块边",
          any(r['from_node'] == 'a3' for r in blk_b[3]['in']),
          detail=str(blk_b[3]))
    check("边界记录带函数与变量",
          blk_a[3]['out'][0]['to_func'] == 'f2'
          and blk_a[3]['out'][0]['variable'] == 'cmd')
    check("control 边不进边界",
          not any(r['kind'] == 'control'
                  for r in blk_a[3]['out'] + blk_b[3]['in']))
    check("块内节点数不变", len(blk_a[1]) == 3 and len(blk_b[1]) == 2)

# 同块内边不产生边界
blocks2 = _split_blocks(nodes[:3], edges[:2], block_nodes=10, max_blocks=10)
check("同块内边无边界记录",
      all(not b[3]['in'] and not b[3]['out'] for b in blocks2))

# 函数级切分路径（单文件超过 block_nodes → 按函数再切）
blocks_fn = _split_blocks(nodes, edges, block_nodes=2, max_blocks=10)
labels_fn = {b[0]: b for b in blocks_fn}
check("按函数切分标签", any('::f1' in lb for lb in labels_fn),
      detail=str(list(labels_fn)))
check("函数级切分也带边界",
      any(r['kind'] == 'return'
          for b in blocks_fn for r in b[3]['out'] + b[3]['in']))


# ==================== 3. digest 渲染 ====================
print("[3] digest BOUNDARY EDGES")

DIG_NODES = [
    {'node_id': 'n1', 'code': 'exec(data)', 'line': 8,
     'file': 'setup.py', 'type': 'call'},
    {'node_id': 'n2', 'code': 'setup(name="pkg")', 'line': 20,
     'file': 'setup.py', 'type': 'call'},
]
DIG_EDGES = [{'from_node': 'n1', 'to_node': 'n2', 'kind': 'call'}]

text, _ = digest(DIG_NODES, DIG_EDGES)
check("无边界参数时不输出该段", 'BOUNDARY EDGES' not in text)

boundary = {
    'in': [{'from_node': 'x1', 'to_node': 'n1', 'from_file': 'config.py',
            'from_line': 3, 'to_file': 'setup.py', 'to_line': 8,
            'from_func': 'load_config', 'to_func': '<module>',
            'kind': 'return', 'variable': 'payload'}],
    'out': [{'from_node': 'n2', 'to_node': 'x2', 'from_file': 'setup.py',
             'from_line': 20, 'to_file': 'shell.py', 'to_line': 88,
             'from_func': '<module>', 'to_func': 'run_shell',
             'kind': 'data', 'variable': 'cmd'}],
}
text_b, _ = digest(DIG_NODES, DIG_EDGES, boundary_edges=boundary)
check("输出 BOUNDARY EDGES 段", '## BOUNDARY EDGES' in text_b)
check("渲染 IN", 'IN   load_config' in text_b and '[config.py:3]' in text_b)
check("渲染 OUT", 'OUT  [THIS BLOCK]' in text_b and 'run_shell' in text_b)
check("带变量名", '[payload]' in text_b and '[cmd]' in text_b)
check("不影响节点/边段", '## NODES' in text_b and '## EDGES' in text_b)


# ==================== 4. partition_by_function 跨块边 ====================
print("[4] partition_by_function boundary_edges")

try:
    import networkx as nx
    from src.common import GraphPartitioner, PartitionConfig

    g = nx.DiGraph()
    g.add_node('a.py_1', file='a.py', line=1, type='call',
               source='payload = net.get()', function_name='f1')
    g.add_node('a.py_2', file='a.py', line=2, type='call',
               source='exec(payload)', function_name='f1')
    g.add_node('a.py_3', file='a.py', line=3, type='call',
               source='cmd = build(payload)', function_name='f2')
    g.add_node('a.py_4', file='a.py', line=4, type='call',
               source='eval(cmd)', function_name='f2')
    g.add_edge('a.py_2', 'a.py_3', edge_kind='return', variable='payload')

    p = GraphPartitioner(g, PartitionConfig(verbose=False))
    results = p.partition(method='function')
    check("两个函数块", len(results) == 2, detail=str(len(results)))

    f1 = next((r for r in results if r.get('function_name') == 'f1'), None)
    f2 = next((r for r in results if r.get('function_name') == 'f2'), None)
    check("f1/f2 都存在", f1 and f2)
    if f1 and f2:
        check("f1 OUT 有跨块边",
              any(r['to_node'] == 'a.py_3' for r in f1['boundary_edges']['out']),
              detail=str(f1['boundary_edges']))
        check("f2 IN 有跨块边",
              any(r['from_node'] == 'a.py_2' for r in f2['boundary_edges']['in']),
              detail=str(f2['boundary_edges']))
        check("跨块边不进诱导子图",
              'a.py_3' not in f1['subgraph'].nodes(),
              detail=str(list(f1['subgraph'].nodes())))
        check("边界记录带文件行号",
              f1['boundary_edges']['out'][0]['from_file'] == 'a.py'
              and f1['boundary_edges']['out'][0]['from_line'] == 2)
except ImportError as e:
    check("networkx 可用", False, detail=str(e))


print()
print(f"跨作用域证据: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
