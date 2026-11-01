"""
子图优先级排序器 - 参考MALGUARD的图中心性 + Graph-Guided LLM的子图筛选

核心思想：
1. 图结构分析（中心性、关键节点）
2. 子图优先级排序（高风险子图优先LLM分析）
3. 优化LLM资源分配（聚焦关键区域）
"""

import re
import networkx as nx
from typing import Dict, List, Tuple
from collections import Counter


class SubgraphPrioritizer:
    """子图优先级排序器"""

    def __init__(self):
        # 带词界的 API 匹配模式（均衡模式 2026-10：原先 'default'/'open' 等
        # 裸子串会命中 default=/urlopen/opened 等海量良性代码）
        self.dangerous_api_weights = {
            # 最高优先级（直接代码执行）
            r'\beval\s*\(': 1.0,
            r'\bexec\s*\(': 1.0,
            r'\bcompile\s*\(': 1.0,
            r'__import__\s*\(': 1.0,

            # 高优先级（命令执行）
            r'os\.system\s*\(': 0.9,
            r'subprocess\.\w+\s*\(': 0.9,
            r'\bpopen\s*\(': 0.9,

            # 中优先级（网络操作）
            r'urllib\.request\.urlopen\s*\(': 0.7,
            r'requests\.(get|post|put)\s*\(': 0.7,
            r'socket\.connect\s*\(': 0.7,

            # 中优先级（文件操作）
            r'(?<![\w.])open\s*\(': 0.5,
            r'os\.remove\s*\(': 0.5,
            r'shutil\.rmtree\s*\(': 0.5,
        }

    def prioritize_subgraphs(
        self,
        subgraph_jsons: List[Dict],
        max_llm_calls: int = 20
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        子图优先级排序

        Args:
            subgraph_jsons: 所有子图
            max_llm_calls: 最大LLM调用次数（资源限制）

        Returns:
            (high_priority_subgraphs, low_priority_subgraphs)
        """
        print(f"        [Prioritizer] 分析 {len(subgraph_jsons)} 个子图...")

        # 1. 为每个子图计算优先级分数
        scored_subgraphs = []
        for idx, subgraph in enumerate(subgraph_jsons, 1):
            priority_score = self._calculate_priority_score(subgraph, idx)
            scored_subgraphs.append((priority_score, subgraph))

        # 2. 按优先级降序排序
        scored_subgraphs.sort(key=lambda x: x[0], reverse=True)

        # 3. 分为高优先级和低优先级
        high_priority = [sg for score, sg in scored_subgraphs[:max_llm_calls]]
        low_priority = [sg for score, sg in scored_subgraphs[max_llm_calls:]]

        print(f"        [Prioritizer] 高优先级子图: {len(high_priority)}")
        print(f"        [Prioritizer] 低优先级子图: {len(low_priority)}")

        # 打印Top 3高风险子图
        if high_priority:
            print(f"\n        [Top 3 高风险子图]:")
            for idx, (score, sg) in enumerate(scored_subgraphs[:3], 1):
                sg_name = sg.get('subgraph_name', 'unknown')
                print(f"          {idx}. {sg_name} (优先级: {score:.2f})")

        return high_priority, low_priority

    def _calculate_priority_score(self, subgraph: Dict, idx: int) -> float:
        """
        计算子图优先级分数

        参考MALGUARD的图中心性计算：
        - 危险API权重
        - 攻击链完整性
        - 节点中心性
        - 数据流复杂度
        """
        score = 0.0

        # 因子1：危险节点API权重（40%）
        dangerous_nodes = subgraph.get('dangerous_nodes', [])
        api_score = self._calculate_api_score(dangerous_nodes)
        score += api_score * 0.4

        # 因子2：攻击链完整性（30%）
        data_flow_paths = subgraph.get('data_flow_paths', [])
        chain_completeness = self._calculate_chain_completeness(data_flow_paths)
        score += chain_completeness * 0.3

        # 因子3：节点中心性（20%）- 参考MALGUARD
        centrality_score = self._calculate_centrality_score(subgraph)
        score += centrality_score * 0.2

        # 因子4：数据流复杂度（10%）- 参考Graph-Guided LLM
        complexity_score = self._calculate_complexity_score(subgraph)
        score += complexity_score * 0.1

        return score

    def _calculate_api_score(self, dangerous_nodes: List[Dict]) -> float:
        """
        计算危险API分数

        参考MALGUARD的API敏感度计算
        """
        if not dangerous_nodes:
            return 0.0

        # 统计每个危险API的出现次数
        api_counter = Counter()
        for node in dangerous_nodes:
            code = node.get('code', '').lower()
            for pattern, weight in self.dangerous_api_weights.items():
                if re.search(pattern, code):
                    api_counter[pattern] += weight

        # 加权求和（越危险的API权重越高）
        # 修复：原先双重 for 循环里内层重新绑定了外层变量 api，实际算出
        # (Σ计数)×(Σ全部匹配权重)，数值严重膨胀，命中 2 个 API 即饱和 1.0
        total_score = sum(count * self.dangerous_api_weights[pattern]
                          for pattern, count in api_counter.items())

        # 归一化到 [0, 1]
        max_possible = len(dangerous_nodes) * 1.0  # 假设所有节点都是最危险的API
        return min(total_score / max_possible, 1.0) if max_possible > 0 else 0.0

    def _calculate_chain_completeness(self, data_flow_paths: List[List]) -> float:
        """
        计算攻击链完整性

        参考Taint-Based Code Slicing的Source→Sink完整性
        """
        if not data_flow_paths:
            return 0.0

        complete_chains = 0
        total_chains = len(data_flow_paths)

        for path in data_flow_paths:
            # 检查路径是否有Source和Sink
            has_source = self._has_source_node(path)
            has_sink = self._has_dangerous_sink(path)

            if has_source and has_sink:
                complete_chains += 1

        # 完整攻击链比例
        completeness = complete_chains / total_chains if total_chains > 0 else 0.0

        return completeness

    def _has_source_node(self, path: List) -> bool:
        """检查路径是否有Source节点"""
        # 均衡模式扩充：PyPI 恶意包的真实数据源是环境变量/文件读取/
        # base64 解码，原先 5 个模式几乎覆盖不到，complete_chain 恒假
        source_patterns = [
            'request.', 'input(', 'args.', 'kwargs.', 'form.get',
            'os.environ', 'getenv', 'open(', '.read(', 'readlines',
            'b64decode', 'urlopen', 'fromhex', 'unhexlify',
        ]
        for node in path:
            if isinstance(node, dict):
                code = node.get('code', '')
                if any(pattern in code for pattern in source_patterns):
                    return True
        return False

    def _has_dangerous_sink(self, path: List) -> bool:
        """检查路径是否有危险Sink"""
        sink_patterns = ['eval(', 'exec(', 'compile(', 'os.system', 'subprocess.']
        for node in path:
            if isinstance(node, dict):
                code = node.get('code', '')
                if any(pattern in code for pattern in sink_patterns):
                    return True
        return False

    def _calculate_centrality_score(self, subgraph: Dict) -> float:
        """
        计算节点中心性分数

        参考MALGUARD的图中心性计算
        """
        dangerous_nodes = subgraph.get('dangerous_nodes', [])
        if not dangerous_nodes:
            return 0.0

        # 构建子图的局部图
        G = nx.DiGraph()
        for node in dangerous_nodes:
            node_id = node.get('node_id', f"node_{id(node)}")
            G.add_node(node_id, weight=1.0)

        # 添加边（从data_flow_paths）
        data_flow_paths = subgraph.get('data_flow_paths', [])
        for path in data_flow_paths:
            for i in range(len(path) - 1):
                if isinstance(path[i], dict) and isinstance(path[i+1], dict):
                    from_id = path[i].get('node_id', f"node_{i}")
                    to_id = path[i+1].get('node_id', f"node_{i+1}")
                    G.add_edge(from_id, to_id)

        if G.number_of_nodes() == 0:
            return 0.0

        # 计算度中心性
        centrality = nx.degree_centrality(G)

        # 平均中心性
        avg_centrality = sum(centrality.values()) / len(centrality) if centrality else 0.0

        return avg_centrality

    def _calculate_complexity_score(self, subgraph: Dict) -> float:
        """
        计算数据流复杂度

        参考Graph-Guided LLM的复杂度分析
        """
        dangerous_nodes = subgraph.get('dangerous_nodes', [])
        data_flow_paths = subgraph.get('data_flow_paths', [])
        functions = subgraph.get('functions', {})

        # 复杂度指标：
        # 1. 节点数量（越多越复杂）
        node_count = len(dangerous_nodes)

        # 2. 数据流路径数量（越多越复杂）
        path_count = len(data_flow_paths)

        # 3. 函数数量（越多越复杂）
        function_count = len(functions)

        # 归一化复杂度分数
        # 假设：10个节点、5条路径、3个函数 = 高复杂度
        complexity = (min(node_count, 10) / 10.0 +
                     min(path_count, 5) / 5.0 +
                     min(function_count, 3) / 3.0) / 3.0

        return complexity


def test_prioritizer():
    """测试优先级排序器"""
    import json

    # 模拟子图数据
    mock_subgraphs = [
        {
            'subgraph_name': 'subgraph_1',
            'dangerous_nodes': [
                {'code': 'eval(user_input)', 'node_id': 'n1'},
                {'code': 'decoded = base64.b64decode(data)', 'node_id': 'n2'},
            ],
            'data_flow_paths': [
                [{'code': 'user_input = request.form.get("data")', 'node_id': 'n3'},
                 {'code': 'eval(user_input)', 'node_id': 'n1'}]
            ],
            'functions': {'process': [{'node': {'code': 'def process():'}}]}
        },
        {
            'subgraph_name': 'subgraph_2',
            'dangerous_nodes': [
                {'code': 'print("hello")', 'node_id': 'n4'},
            ],
            'data_flow_paths': [],
            'functions': {}
        },
        {
            'subgraph_name': 'subgraph_3',
            'dangerous_nodes': [
                {'code': 'os.system("ls")', 'node_id': 'n5'},
                {'code': 'data = requests.get("http://example.com")', 'node_id': 'n6'},
            ],
            'data_flow_paths': [
                [{'code': 'cmd = "ls"', 'node_id': 'n7'},
                 {'code': 'os.system(cmd)', 'node_id': 'n5'}]
            ],
            'functions': {'execute': [{'node': {'code': 'def execute():'}}]}
        }
    ]

    prioritizer = SubgraphPrioritizer()
    high, low = prioritizer.prioritize_subgraphs(mock_subgraphs, max_llm_calls=2)

    print(f"\n高优先级子图数: {len(high)}")
    print(f"低优先级子图数: {len(low)}")

    print(f"\n高优先级子图:")
    for sg in high:
        print(f"  - {sg['subgraph_name']}")

    print(f"\n低优先级子图:")
    for sg in low:
        print(f"  - {sg['subgraph_name']}")


if __name__ == '__main__':
    test_prioritizer()
