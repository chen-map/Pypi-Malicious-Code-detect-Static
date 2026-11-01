# -*- coding: utf-8 -*-
"""回归测试:图分割(超限分量不丢弃/孤立危险节点保留/WCC严重度)"""
import sys
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

import networkx as nx
from src.common.graph_partitioner import GraphPartitioner, PartitionConfig


def chain_graph(n: int, danger_indices=None) -> nx.DiGraph:
    """n 节点链,指定下标的节点带 exec( 危险源码"""
    g = nx.DiGraph()
    danger = set(danger_indices or [n // 2])
    for i in range(n):
        src = "exec(payload)" if i in danger else f"value_{i} = compute({i})"
        g.add_node(f"mod.py_{i}", file="mod.py", line=i, type="call" if i in danger else "assignment",
                   source=src)
    for i in range(n - 1):
        g.add_edge(f"mod.py_{i}", f"mod.py_{i+1}", variable=f"v{i}")
    return g


def test_oversized_wcc_not_dropped():
    """核心验收:>1000 节点的连通分量在 hybrid 模式下不再被丢弃"""
    g = chain_graph(1500, danger_indices=[700])
    config = PartitionConfig(max_nodes=100, verbose=False)
    p = GraphPartitioner(g, config)
    results = p.partition(method='hybrid')
    assert results, f"超限分量(1500节点)被丢弃——巨型恶意连通团漏报回归: {len(results)}"

    # 纯 wcc 模式:超限分量被丢弃但应有警告(不崩溃)
    results_wcc = p.partition(method='wcc')
    assert results_wcc == [], "纯wcc模式超限分量应被丢弃(带警告)"
    print(f"[OK] 超限分量 hybrid 切分出 {len(results)} 个子图(不再丢弃), wcc模式警告丢弃")


def test_isolated_dangerous_node_kept():
    """修复回归:孤立的单个危险节点(min_wcc_size=1)不再被丢弃"""
    g = nx.DiGraph()
    g.add_node("solo.py_5", file="solo.py", line=5, type="call", source="eval(user_input)")
    config = PartitionConfig(verbose=False)
    p = GraphPartitioner(g, config)
    results = p.partition(method='hybrid')
    assert results, "孤立危险节点应产生子图(原先 min_wcc_size=2 直接丢弃)"
    print(f"[OK] 孤立危险节点保留: {len(results)} 个子图")


def test_wcc_max_severity():
    """修复回归:含 critical 节点的分量 severity 不再因迭代顺序标错"""
    g = nx.DiGraph()
    g.add_node("a.py_1", file="a.py", line=1, type="call", source="eval(x)")
    g.add_node("a.py_2", file="a.py", line=2, type="call", source="base64.b64decode(y)")
    g.add_edge("a.py_1", "a.py_2", variable="x")
    config = PartitionConfig(verbose=False)
    p = GraphPartitioner(g, config)
    results = p.partition(method='wcc')
    assert results, "应产生1个WCC"
    assert results[0]['severity'] == 'critical', \
        f"含eval的分量severity应为critical, 实际 {results[0]['severity']}"
    print("[OK] WCC severity 取最大等级")


if __name__ == '__main__':
    test_oversized_wcc_not_dropped()
    test_isolated_dangerous_node_kept()
    test_wcc_max_severity()
    print("\n===== test_partitioner 全部通过 =====")
