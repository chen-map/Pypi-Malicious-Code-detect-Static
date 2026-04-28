"""
统一的图分割模块

整合自：
- graph_partitioner_v7.py: DataFlowExtractor, DOTParser
- visualizer_v7.py: _generate_sub_ddgs, _bidirectional_bfs

功能：
1. 从NetworkX图提取包含危险节点的子图
2. 支持WCC（弱连通分量）分割
3. 支持双向BFS数据流追踪
4. 输出标准化的nodes.json/edges.json
"""

import re
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field

import networkx as nx

from .pattern_matcher import DangerPatternLoader, SuspiciousNodeDetector


# ==================== 配置类 ====================

@dataclass
class PartitionConfig:
    """图分割配置"""

    # BFS限制
    max_nodes: int = 500
    max_depth: int = 10
    timeout: float = 30.0  # 秒
    max_iterations: int = 10000

    # WCC阈值
    min_wcc_size: int = 2
    max_wcc_size: int = 1000

    # 输出控制
    include_safe_nodes: bool = True  # 是否包含子图中的安全节点
    save_dot: bool = True
    save_json: bool = True

    # 调试
    verbose: bool = True


# ==================== DOT解析器 ====================

class DOTParser:
    """
    DOT文件解析器

    功能：
    1. 解析DOT格式文件为NetworkX图
    2. 提取节点属性（文件、行号、代码）
    3. 提取边属性（类型、变量名）
    """

    FILE_LINE_PATTERN = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)_py_(\d+)')

    def __init__(self, dot_file: str):
        self.dot_file = Path(dot_file)

    def parse(self) -> nx.DiGraph:
        """解析DOT文件为NetworkX有向图"""
        content = self.dot_file.read_text(encoding='utf-8', errors='ignore')
        graph = nx.DiGraph()

        # 解析节点
        node_pattern = r'"([^"]+)"\s*\[(.+?)\];'
        for match in re.finditer(node_pattern, content):
            node_id = match.group(1)
            attrs_str = match.group(2)
            attrs = self._parse_attrs(attrs_str)

            # 提取文件名和行号
            file_match = self.FILE_LINE_PATTERN.search(node_id)
            if file_match:
                attrs['_file'] = file_match.group(1)
                attrs['_line'] = int(file_match.group(2))
            else:
                attrs['_file'] = 'unknown'
                attrs['_line'] = 0

            graph.add_node(node_id, **attrs)

        # 解析边
        edge_pattern = r'"([^"]+)"\s*->\s*"([^"]+)"\s*\[(.+?)\];'
        for match in re.finditer(edge_pattern, content):
            from_node = match.group(1)
            to_node = match.group(2)
            attrs_str = match.group(3)
            attrs = self._parse_attrs(attrs_str)
            graph.add_edge(from_node, to_node, **attrs)

        return graph

    def _parse_attrs(self, attrs_str: str) -> Dict:
        """解析DOT属性字符串"""
        attrs = {}
        for match in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', attrs_str):
            key, value = match.groups()
            attrs[key] = value
        return attrs


# ==================== 双向BFS（带超时保护）====================

class BidirectionalBFS:
    """
    双向广度优先搜索（带多层保护）

    保护机制：
    1. 节点数限制 (max_nodes)
    2. 深度限制 (max_depth)
    3. 超时限制 (timeout)
    4. 迭代计数限制 (max_iterations)
    """

    def __init__(self, graph: nx.DiGraph, config: PartitionConfig):
        self.graph = graph
        self.config = config

    def search(self, start_node: str) -> Set[str]:
        """
        从起始节点开始双向BFS

        Args:
            start_node: 起始节点ID

        Returns:
            包含的节点集合
        """
        included = {start_node}
        queue = deque([(start_node, 0)])  # (node, depth)

        start_time = time.time()
        iterations = 0

        while queue and len(included) < self.config.max_nodes:
            # 超时检查
            if time.time() - start_time > self.config.timeout:
                if self.config.verbose:
                    print(f"    [BFS] Timeout after {self.config.timeout}s, {len(included)} nodes")
                break

            # 迭代计数检查
            iterations += 1
            if iterations > self.config.max_iterations:
                if self.config.verbose:
                    print(f"    [BFS] Max iterations reached: {self.config.max_iterations}")
                break

            current, depth = queue.popleft()

            # 深度限制检查
            if depth >= self.config.max_depth:
                continue

            # 向后追踪（数据来源）
            for pred in self.graph.predecessors(current):
                if pred not in included:
                    included.add(pred)
                    if len(included) < self.config.max_nodes:
                        queue.append((pred, depth + 1))

            # 向前追踪（数据去向）
            for succ in self.graph.successors(current):
                if succ not in included:
                    included.add(succ)
                    if len(included) < self.config.max_nodes:
                        queue.append((succ, depth + 1))

        return included


# ==================== WCC分割器 ====================

class WeaklyConnectedComponentsPartitioner:
    """
    基于弱连通分量的图分割器

    功能：
    1. 计算图的所有弱连通分量
    2. 过滤出包含危险节点的分量
    3. 按严重程度和大小排序
    """

    def __init__(self, graph: nx.DiGraph, suspicious_nodes: Dict[str, Dict],
                 config: PartitionConfig):
        self.graph = graph
        self.suspicious_nodes = suspicious_nodes
        self.config = config

    def partition(self) -> List[Dict]:
        """
        执行WCC分割

        Returns:
            分割结果列表，每个元素包含子图信息
        """
        # 构建危险节点集合
        dangerous_set = set(self.suspicious_nodes.keys())

        if not dangerous_set:
            if self.config.verbose:
                print("    [WCC] No dangerous nodes found")
            return []

        # 计算弱连通分量
        undirected = self.graph.to_undirected()
        all_wccs = list(nx.connected_components(undirected))

        # 只保留包含危险节点的分量
        dangerous_wccs = [
            wcc for wcc in all_wccs
            if any(node in dangerous_set for node in wcc)
        ]

        if self.config.verbose:
            print(f"    [WCC] Found {len(dangerous_wccs)} components with dangerous nodes")

        # 按严重程度和大小排序
        sorted_wccs = sorted(
            dangerous_wccs,
            key=lambda wcc: (
                self._get_max_severity(wcc),  # 严重程度
                -len(wcc)  # 大小（降序）
            )
        )

        # 构建结果
        results = []
        for i, wcc in enumerate(sorted_wccs, 1):
            if self.config.min_wcc_size <= len(wcc) <= self.config.max_wcc_size:
                results.append(self._build_wcc_result(wcc, i))

        return results

    def _get_max_severity(self, wcc: Set[str]) -> int:
        """获取WCC的最大严重程度（用于排序）"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}

        max_severity = 4  # 默认safe
        for node in wcc:
            if node in self.suspicious_nodes:
                sev = self.suspicious_nodes[node]['severity']
                max_severity = min(max_severity, severity_order.get(sev, 4))

        return max_severity

    def _build_wcc_result(self, wcc: Set[str], index: int) -> Dict:
        """构建单个WCC的结果"""
        subgraph = self.graph.subgraph(wcc).copy()

        # 统计危险节点
        dangerous_in_wcc = [n for n in wcc if n in self.suspicious_nodes]

        # 确定主要严重程度
        if dangerous_in_wcc:
            primary = self.suspicious_nodes[dangerous_in_wcc[0]]
            severity = primary['severity']
        else:
            severity = 'safe'

        return {
            'index': index,
            'nodes': wcc,
            'subgraph': subgraph,
            'dangerous_nodes': dangerous_in_wcc,
            'severity': severity,
            'size': len(wcc)
        }


# ==================== 数据流提取器 ====================

class DataFlowExtractor:
    """
    从危险节点提取数据流

    功能：
    1. 对每个危险节点执行双向BFS
    2. 提取完整的def-use链
    3. 避免重复处理（已处理节点标记）
    """

    FILE_LINE_PATTERN = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)_py_(\d+)')

    def __init__(self, graph: nx.DiGraph, suspicious_nodes: Dict[str, Dict],
                 config: PartitionConfig):
        self.graph = graph
        self.suspicious_nodes = suspicious_nodes
        self.config = config
        self.bfs = BidirectionalBFS(graph, config)

    def extract_all(self) -> List[Dict]:
        """
        提取所有危险节点的数据流

        Returns:
            数据流列表
        """
        if self.config.verbose:
            print(f"\n  [DataFlow] Extracting data flows for {len(self.suspicious_nodes)} suspicious nodes")

        data_flows = []
        processed = set()

        # 按严重程度排序
        sorted_nodes = sorted(
            self.suspicious_nodes.items(),
            key=lambda x: (x[1]['severity'] != 'critical', x[1]['severity'] != 'high')
        )

        for node_id, info in sorted_nodes:
            # 避免重复处理
            if node_id in processed:
                continue

            # 提取数据流
            flow = self._extract_single(node_id, info, processed)
            if flow:
                data_flows.append(flow)

        if self.config.verbose:
            print(f"  [DataFlow] Extracted {len(data_flows)} data flows")

        return data_flows

    def _extract_single(self, start_node: str, info: Dict, processed: Set[str]) -> Optional[Dict]:
        """提取单个数据流"""
        # 执行双向BFS
        nodes_to_keep = self.bfs.search(start_node)

        if len(nodes_to_keep) == 0:
            return None

        # 标记已处理
        processed.update(nodes_to_keep)

        # 提取子图
        subgraph = self.graph.subgraph(nodes_to_keep).copy()

        # 找出子图中的所有危险节点
        suspicious_in_subgraph = [
            n for n in nodes_to_keep
            if n in self.suspicious_nodes
        ]

        # 解析位置
        filename, line_no = self._parse_location(start_node)

        return {
            'name': f"{info['category']}_{filename}_{line_no}",
            'subgraph': subgraph,
            'nodes': list(nodes_to_keep),
            'edges': list(subgraph.edges(data=True)),
            'suspicious_nodes': suspicious_in_subgraph,
            'primary_node': start_node,
            'primary_severity': info['severity'],
            'primary_category': info['category'],
            'primary_reason': info['reason'],
            'size': len(nodes_to_keep),
            'edges_count': subgraph.number_of_edges()
        }

    def _parse_location(self, node_id: str) -> Tuple[str, str]:
        """解析节点位置"""
        match = self.FILE_LINE_PATTERN.search(node_id)
        if match:
            return match.group(1), match.group(2)
        return 'unknown', '0'


# ==================== 主分割器 ====================

class GraphPartitioner:
    """
    图分割器（统一入口）

    支持两种分割模式：
    1. WCC模式：基于弱连通分量
    2. BFS模式：基于双向BFS数据流追踪

    支持两种输入：
    1. NetworkX图（推荐）
    2. DOT文件路径
    """

    def __init__(self, graph_or_dotfile, config: Optional[PartitionConfig] = None,
                 patterns_file: Optional[str] = None):
        """
        初始化分割器

        Args:
            graph_or_dotfile: NetworkX图或DOT文件路径
            config: 分割配置
            patterns_file: 危险模式配置文件路径
        """
        self.config = config or PartitionConfig()

        # 加载图
        if isinstance(graph_or_dotfile, nx.DiGraph):
            self.graph = graph_or_dotfile
            self._input_type = 'networkx'
        elif isinstance(graph_or_dotfile, (str, Path)):
            parser = DOTParser(str(graph_or_dotfile))
            self.graph = parser.parse()
            self._input_type = 'dot'
        else:
            raise TypeError(f"Unsupported input type: {type(graph_or_dotfile)}")

        # 加载危险模式
        self.pattern_loader = DangerPatternLoader(patterns_file, verbose=self.config.verbose)
        self.node_detector = SuspiciousNodeDetector(self.pattern_loader)

        # 检测危险节点
        self.suspicious_nodes = self.node_detector.detect_all(self.graph)

        if self.config.verbose:
            print(f"  [Partitioner] Graph loaded: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
            print(f"  [Partitioner] Found {len(self.suspicious_nodes)} suspicious nodes")

    def partition_wcc(self) -> List[Dict]:
        """
        使用WCC方法分割图

        Returns:
            分割结果列表
        """
        partitioner = WeaklyConnectedComponentsPartitioner(
            self.graph, self.suspicious_nodes, self.config
        )
        return partitioner.partition()

    def partition_bfs(self) -> List[Dict]:
        """
        使用BFS方法分割图

        Returns:
            数据流列表
        """
        extractor = DataFlowExtractor(
            self.graph, self.suspicious_nodes, self.config
        )
        return extractor.extract_all()

    def partition_hybrid(self) -> List[Dict]:
        """
        使用WCC+BFS双重模式分割图

        策略：
        1. 先用WCC将图分割成弱连通分量
        2. 对每个超过max_nodes阈值的分量，再用BFS截断
        3. 保证所有子图大小都在可控范围内

        Returns:
            分割结果列表
        """
        if self.config.verbose:
            print(f"  [Hybrid] Starting WCC+BFS hybrid partitioning...")

        # 步骤1: 使用WCC分割
        wcc_partitioner = WeaklyConnectedComponentsPartitioner(
            self.graph, self.suspicious_nodes, self.config
        )
        wcc_results = wcc_partitioner.partition()

        if not wcc_results:
            return []

        # 步骤2: 检查每个WCC的大小，对过大的进行BFS截断
        final_results = []
        split_count = 0

        for wcc_result in wcc_results:
            wcc_size = wcc_result['size']

            # 如果WCC大小在阈值内，直接保留
            if wcc_size <= self.config.max_nodes:
                final_results.append(wcc_result)
                if self.config.verbose:
                    print(f"    [Hybrid] WCC {wcc_result['index']} size {wcc_size} <= {self.config.max_nodes}, keeping as-is")
            else:
                # WCC过大，使用BFS进一步分割
                if self.config.verbose:
                    print(f"    [Hybrid] WCC {wcc_result['index']} size {wcc_size} > {self.config.max_nodes}, applying BFS split")

                # 获取该WCC中的危险节点
                dangerous_nodes_in_wcc = wcc_result['dangerous_nodes']

                if not dangerous_nodes_in_wcc:
                    # 如果没有危险节点（理论上不应该发生），保留原WCC
                    final_results.append(wcc_result)
                    continue

                # 对每个危险节点执行BFS（但会去重）
                bfs_extractor = DataFlowExtractor(
                    self.graph,
                    {node: self.suspicious_nodes[node] for node in dangerous_nodes_in_wcc},
                    self.config
                )

                bfs_flows = bfs_extractor.extract_all()

                # 将BFS结果添加到最终结果中
                for flow in bfs_flows:
                    # 重命名index，避免冲突
                    flow['index'] = len(final_results) + 1
                    flow['wcc_origin'] = wcc_result['index']  # 记录来源WCC
                    final_results.append(flow)
                    split_count += 1

                if self.config.verbose:
                    print(f"    [Hybrid] Split large WCC into {len(bfs_flows)} BFS subgraphs")

        if self.config.verbose:
            print(f"  [Hybrid] Partitioning complete: {len(wcc_results)} WCCs -> {len(final_results)} final subgraphs")
            print(f"  [Hybrid] Split {split_count} oversized WCCs")

        # 按严重程度和大小排序
        final_results.sort(key=lambda x: (
            self._get_severity_order(x.get('primary_severity', x.get('severity', 'safe'))),
            -x.get('size', 0)
        ))

        # 重新编号
        for i, result in enumerate(final_results, 1):
            result['index'] = i

        return final_results

    def _get_severity_order(self, severity: str) -> int:
        """获取严重程度排序值"""
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}
        return order.get(severity, 5)

    def partition(self, method: str = 'auto') -> List[Dict]:
        """
        自动选择方法分割图

        Args:
            method: 'wcc', 'bfs', 'hybrid', 或 'auto'

        Returns:
            分割结果列表
        """
        if method == 'auto':
            # 根据图规模自动选择
            if self.graph.number_of_nodes() > 1000:
                method = 'hybrid'  # 大图使用hybrid模式
            else:
                method = 'bfs'     # 小图使用BFS

        if method == 'wcc':
            return self.partition_wcc()
        elif method == 'bfs':
            return self.partition_bfs()
        elif method == 'hybrid':
            return self.partition_hybrid()
        else:
            raise ValueError(f"Unknown method: {method}")

    def save_results(self, results: List[Dict], output_dir: Path,
                     method: str = 'bfs') -> List[Path]:
        """
        保存分割结果

        Args:
            results: 分割结果
            output_dir: 输出目录
            method: 分割方法（用于命名）

        Returns:
            保存的文件路径列表
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        saved_files = []

        for i, result in enumerate(results, 1):
            # 创建子目录
            severity = result.get('severity', 'unknown')
            size = result.get('size', 0)
            folder_name = f"{i:03d}_{severity}_{size}nodes_{method}"
            sub_dir = output_dir / folder_name
            sub_dir.mkdir(exist_ok=True)

            # 保存nodes.json
            if self.config.save_json:
                nodes_file = self._save_nodes(result, sub_dir)
                saved_files.append(nodes_file)

                # 保存edges.json
                edges_file = self._save_edges(result, sub_dir)
                saved_files.append(edges_file)

            # 保存DOT
            if self.config.save_dot:
                dot_file = self._save_dot(result, sub_dir)
                saved_files.append(dot_file)

        # 保存summary.json
        summary_file = self._save_summary(results, output_dir)
        saved_files.append(summary_file)

        return saved_files

    def _save_nodes(self, result: Dict, output_dir: Path) -> Path:
        """保存nodes.json"""
        subgraph = result['subgraph']
        # 兼容两种字段名：dangerous_nodes (WCC) 和 suspicious_nodes (BFS)
        dangerous_set = set(result.get('dangerous_nodes', result.get('suspicious_nodes', [])))

        nodes_list = []
        for node_id in subgraph.nodes():
            attrs = subgraph.nodes[node_id]
            # 优先使用 source 属性（DDG构建器的实际代码内容）
            # 回退到 label 属性（可视化器生成的标签）
            # 再回退到 _source 属性（DOT解析器的属性）
            code = attrs.get('source', '') or attrs.get('label', '') or attrs.get('_source', '')

            # 获取文件路径和行号（兼容DDG构建器和DOT解析器）
            file_attr = attrs.get('file', attrs.get('_file', 'unknown'))
            line_attr = attrs.get('line', attrs.get('_line', 0))

            nodes_list.append({
                'node_id': node_id,
                'file': file_attr,
                'line': line_attr,
                'code': code,
                'is_dangerous': node_id in dangerous_set,
                'severity': self.suspicious_nodes.get(node_id, {}).get('severity', 'safe'),
                'confidence': 0.9 if node_id in dangerous_set else 0.5,
                # ✅ 修复：保存函数和类信息（用于桩程序生成）
                'function_name': attrs.get('_function_name', attrs.get('function_name', None)),
                'class_name': attrs.get('_class_name', attrs.get('class_name', None))
            })

        output_file = output_dir / 'nodes.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(nodes_list, f, indent=2, ensure_ascii=False)

        return output_file

    def _save_edges(self, result: Dict, output_dir: Path) -> Path:
        """保存edges.json"""
        subgraph = result['subgraph']

        edges_list = []
        for from_node, to_node in subgraph.edges():
            from_file = subgraph.nodes[from_node].get('_file', 'unknown')
            to_file = subgraph.nodes[to_node].get('_file', 'unknown')
            edges_list.append({
                'from_node': from_node,
                'to_node': to_node,
                'from_file': from_file,
                'to_file': to_file,
                'is_cross_file': from_file != to_file
            })

        output_file = output_dir / 'edges.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(edges_list, f, indent=2, ensure_ascii=False)

        return output_file

    def _save_dot(self, result: Dict, output_dir: Path) -> Path:
        """保存DOT文件"""
        subgraph = result['subgraph']
        suspicious_set = set(result.get('suspicious_nodes', []))
        primary = result.get('primary_node', '')
        severity = result.get('primary_severity', 'unknown')

        # 颜色映射
        severity_colors = {
            'critical': '#B71C1C',
            'high': '#D32F2F',
            'medium': '#F57C00',
            'low': '#FBC02D',
            'safe': '#ECEFF1'
        }

        dot_lines = [
            'digraph SubDDG {',
            '  rankdir=TB;',
            '  splines=spline;',
            '  nodesep=0.4;',
            '  ranksep=0.6;',
            '  node [shape=box, style="filled,rounded", fontname="Consolas", fontsize=7];',
        ]

        # 添加节点
        for node_id in subgraph.nodes():
            attrs = subgraph.nodes[node_id]
            file_name = Path(attrs.get('_file', 'unknown')).name
            line = attrs.get('_line', 0)
            source = attrs.get('label', node_id)[:40]
            label = f"{file_name}:{line}\\n{source}"

            if node_id == primary:
                color = severity_colors.get(severity, '#D32F2F')
                dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="{color}", fontcolor="white", penwidth=2.5];')
            elif node_id in suspicious_set:
                sev = self.suspicious_nodes.get(node_id, {}).get('severity', 'low')
                color = severity_colors.get(sev, '#FBC02D')
                dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="{color}", penwidth=1.5];')
            else:
                dot_lines.append(f'  "{node_id}" [label="{label}", fillcolor="#E0E0E0", style="filled,dashed"];')

        # 添加边
        for from_node, to_node in subgraph.edges():
            from_file = subgraph.nodes[from_node].get('_file', '')
            to_file = subgraph.nodes[to_node].get('_file', '')
            is_cross = from_file != to_file
            color = '#4CAF50' if is_cross else '#616161'
            dot_lines.append(f'  "{from_node}" -> "{to_node}" [color="{color}", penwidth={2.0 if is_cross else 0.8}];')

        dot_lines.append('}')

        output_file = output_dir / 'sub_ddg.dot'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(dot_lines))

        return output_file

    def _save_summary(self, results: List[Dict], output_dir: Path) -> Path:
        """保存summary.json"""
        summary = {
            'total_components': len(results),
            'by_severity': defaultdict(int),
            'components': []
        }

        for r in results:
            severity = r.get('severity', 'unknown')
            summary['by_severity'][severity] += 1
            summary['components'].append({
                'index': r.get('index'),
                'severity': severity,
                'size': r.get('size'),
                'dangerous_count': len(r.get('dangerous_nodes', [])),
                'primary_reason': r.get('primary_reason', '')
            })

        output_file = output_dir / 'summary.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=dict)

        return output_file


# ==================== 便捷函数 ====================

def partition_graph(graph_or_dotfile, output_dir: Optional[Path] = None,
                    method: str = 'auto', patterns_file: Optional[str] = None,
                    max_nodes: int = 500, verbose: bool = True) -> List[Dict]:
    """
    便捷的图分割函数

    Args:
        graph_or_dotfile: NetworkX图或DOT文件路径
        output_dir: 输出目录（不保存则设为None）
        method: 分割方法 ('wcc', 'bfs', 'hybrid', 'auto')
        patterns_file: 危险模式配置文件
        max_nodes: 最大节点数
        verbose: 是否输出详细信息

    Returns:
        分割结果列表
    """
    config = PartitionConfig(max_nodes=max_nodes, verbose=verbose)
    partitioner = GraphPartitioner(graph_or_dotfile, config, patterns_file)
    results = partitioner.partition(method)

    if output_dir:
        partitioner.save_results(results, Path(output_dir), method)

    return results
