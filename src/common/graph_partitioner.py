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
    max_nodes: int = 100  # 🔧 修改：从500改为100，避免大子图
    max_depth: int = 10
    timeout: float = 30.0  # 秒
    max_iterations: int = 10000

    # WCC阈值（2026-10 大改）：min 从 2 改 1——孤立的单个危险节点原先
    # 被 WCC/hybrid 模式直接丢弃（漏报通道）；max_wcc_size 超限分量在
    # hybrid 模式下交由 BFS 切分而非丢弃，见 WeaklyConnectedComponentsPartitioner
    min_wcc_size: int = 1
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

            # 向后追踪（数据来源;2026-10 确定性:sorted 邻居顺序）
            for pred in sorted(self.graph.predecessors(current)):
                if pred not in included:
                    # 🔧 修复：先检查max_nodes，避免突然超过限制
                    if len(included) >= self.config.max_nodes:
                        break  # 达到限制，停止添加
                    included.add(pred)
                    queue.append((pred, depth + 1))

            # 向前追踪（数据去向;2026-10 确定性:sorted 邻居顺序）
            for succ in sorted(self.graph.successors(current)):
                if succ not in included:
                    # 🔧 修复：先检查max_nodes，避免突然超过限制
                    if len(included) >= self.config.max_nodes:
                        break  # 达到限制，停止添加
                    included.add(succ)
                    queue.append((succ, depth + 1))

        # 🔧 方案1：补全函数上下文
        included = self._complete_function_context(included)

        return included

    def _complete_function_context(self, included_nodes: Set[str]) -> Set[str]:
        """
        补全函数定义和参数节点（方案1）

        策略：
        1. 检查included_nodes中的每个节点
        2. 如果节点在函数体内，包含函数定义
        3. 包含函数参数到函数体的数据流边

        Args:
            included_nodes: BFS找到的节点集合

        Returns:
            补全后的节点集合
        """
        result = set(included_nodes)

        # 提取所有节点的行号(2026-10 确定性:sorted——set 迭代受
        # PYTHONHASHSEED 影响,会改变函数上下文补全的探索路径)
        node_lines = {}
        for node_id in sorted(included_nodes):
            line = self._extract_line_number(node_id)
            if line:
                node_lines[node_id] = line

        if not node_lines:
            return result

        # 在图中查找函数定义节点
        func_defs = self._find_function_definitions(node_lines)

        # 🔧 添加大小限制检查
        max_size = self.config.max_nodes

        # 添加函数定义节点（检查大小限制;2026-10 确定性:sorted(func_defs)）
        for func_node_id in sorted(func_defs):
            if func_node_id not in result:
                if len(result) >= max_size:
                    if self.config.verbose:
                        print(f"    [BFS+] Reached max_nodes ({max_size}), stopping function context completion")
                    break
                result.add(func_node_id)
                if self.config.verbose:
                    func_line = self._extract_line_number(func_node_id)
                    print(f"    [BFS+] Added function definition at line {func_line} (total: {len(result)})")

        # 添加函数参数相关的边和节点（检查大小限制）
        param_nodes = self._find_parameter_dependencies(func_defs, included_nodes)
        for param_node_id in sorted(param_nodes):
            if param_node_id not in result:
                if len(result) >= max_size:
                    if self.config.verbose:
                        print(f"    [BFS+] Reached max_nodes ({max_size}), skipping parameter nodes")
                    break
                result.add(param_node_id)

        return result

    def _extract_line_number(self, node_id: str) -> Optional[int]:
        """提取节点行号

        2026-10 图内核重构：优先读节点属性 line/_line（nx_graph 由 DDG 构建
        时已写入），正则仅对无属性的节点（DOT 手写夹具等）兜底——id 格式
        变化不再影响行号解析。
        """
        try:
            attrs = self.graph.nodes[node_id]
            line = attrs.get('line') or attrs.get('_line')
            if line:
                return int(line)
        except (KeyError, ValueError, TypeError):
            pass
        import re
        match = re.search(r'_(\d+)(?:_\d+)?$', node_id)
        if match:
            return int(match.group(1))
        return None

    def _find_function_definitions(self, node_lines: Dict[str, int]) -> Set[str]:
        """
        在图中查找函数定义节点

        策略：
        1. 遍历图中的所有节点
        2. 找到type='function'的节点
        3. 检查函数定义行是否小于included节点行
        4. 返回最近的函数定义

        Args:
            node_lines: {node_id: line} 映射

        Returns:
            函数定义节点ID集合
        """
        func_defs = set()

        # 遍历图中的所有节点，找函数定义
        for node_id in self.graph.nodes():
            node_attrs = self.graph.nodes[node_id]

            # 检查是否是函数定义
            # 注意：NetworkX图中，DOTParser解析的属性可能是'type'或其他名称
            if node_attrs.get('type') == 'function':
                func_line = self._extract_line_number(node_id)
                if not func_line:
                    continue

                func_file = self._node_file(node_id)

                # 检查是否有included节点在这个函数之后
                for included_id, included_line in node_lines.items():
                    # 简单判断：函数定义行 < 包含节点行
                    # 且不超过500行（假设单个函数不超过500行）
                    # 修复：原判断只比行号不比文件，多文件图里 A 文件的函数
                    # 会"包含"B 文件同区间的节点
                    if func_line < included_line <= func_line + 500:
                        included_file = self._node_file(included_id)
                        if func_file and included_file and func_file != included_file:
                            continue
                        func_defs.add(node_id)
                        break

        return func_defs

    def _node_file(self, node_id: str) -> Optional[str]:
        """获取节点所属文件（程序化图为 file 属性，DOT 解析为 _file）"""
        attrs = self.graph.nodes[node_id]
        return attrs.get('file') or attrs.get('_file')

    def _find_parameter_dependencies(self, func_def_nodes: Set[str],
                                     included_nodes: Set[str]) -> Set[str]:
        """
        查找函数参数相关的依赖节点

        修复（2026-10）：原先只把 succ in included_nodes 的后继加入结果——
        这些节点本来就在 included 里，返回值恒为 included 的子集，函数体
        现上完全没有效果（空操作）。现在返回流入函数定义的数据源节点
        （实参 def 点），真正补全参数数据流。

        Args:
            func_def_nodes: 函数定义节点ID集合
            included_nodes: 已包含的节点集合

        Returns:
            参数依赖节点ID集合
        """
        param_deps = set()

        for func_node in func_def_nodes:
            # 参数数据流：流入函数定义节点的数据源（实参定义点）
            try:
                for pred in self.graph.predecessors(func_node):
                    if pred not in included_nodes:
                        param_deps.add(pred)
            except Exception:
                continue

        return param_deps


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

        # 2026-10 确定性修复:字符串 set 的迭代顺序受 PYTHONHASHSEED 影响,
        # 同包跨进程构建会产生不同子图数。所有分量统一转为排序后的列表,
        # 下游(subgraph/BFS/落盘)的遍历顺序从此确定。
        all_wccs = [sorted(wcc) for wcc in all_wccs]

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
                -len(wcc),  # 大小（降序）
                wcc[0] if wcc else ''  # 确定性并列打破(首个节点名)
            )
        )

        # 构建结果（2026-10 大改：不再丢弃超限/孤立分量——
        # 超限分量标记 oversized=True，由 hybrid 的 BFS 阶段切分；
        # 原先 >max_wcc_size 的分量在此被整体丢弃，巨型恶意连通团系统性漏报）
        results = []
        for i, wcc in enumerate(sorted_wccs, 1):
            if len(wcc) >= self.config.min_wcc_size:
                results.append(self._build_wcc_result(wcc, i))
            elif self.config.verbose:
                print(f"    [WCC] Skipped empty component")

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

        # 确定主要严重程度（修复：原先取"第一个"危险节点的严重度，
        # 集合迭代顺序任意，含 critical 的分量可能被标成 medium）
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}
        if dangerous_in_wcc:
            severity = min(
                (self.suspicious_nodes[n]['severity'] for n in dangerous_in_wcc),
                key=lambda s: severity_order.get(s, 4)
            )
        else:
            severity = 'safe'

        return {
            'index': index,
            'nodes': wcc,
            'subgraph': subgraph,
            'dangerous_nodes': dangerous_in_wcc,
            'severity': severity,
            'oversized': len(wcc) > self.config.max_wcc_size,
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

        🔧 方案2：按函数分组，避免重复子图

        Returns:
            数据流列表
        """
        if self.config.verbose:
            print(f"\n  [DataFlow] Extracting data flows for {len(self.suspicious_nodes)} suspicious nodes")

        # 🔧 新增：按函数分组危险节点
        groups = self._group_by_function(self.suspicious_nodes)

        if self.config.verbose:
            print(f"  [DataFlow] Grouped into {len(groups)} functions/contexts")

        data_flows = []
        processed = set()

        # 按严重程度排序组
        sorted_groups = sorted(
            groups,
            key=lambda g: (g['primary_severity'] != 'critical', g['primary_severity'] != 'high')
        )

        for group in sorted_groups:
            # 提取整个组的数据流（每个组只BFS一次）
            flow = self._extract_group(group, processed)
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

    def _group_by_function(self, suspicious_nodes: Dict[str, Dict]) -> List[Dict]:
        """
        🔧 方案2：按函数分组危险节点

        策略：
        1. 查找每个危险节点所属的函数
        2. 同一函数的危险节点分为一组
        3. 模块级节点单独一组

        Args:
            suspicious_nodes: {node_id: info} 字典

        Returns:
            分组列表，每个组包含：
            {
                'primary': 主要危险节点ID,
                'nodes': [所有危险节点ID],
                'primary_severity': 主要严重程度,
                'primary_category': 主要类别,
                'function_node': 所属函数节点ID（如果有）
            }
        """
        groups = []
        processed = set()

        for node_id, info in suspicious_nodes.items():
            if node_id in processed:
                continue

            # 查找所属函数
            func_node_id = self._find_containing_function(node_id)

            if func_node_id:
                # 找到函数：收集该函数内的所有危险节点
                group_nodes = self._find_nodes_in_function(
                    func_node_id, suspicious_nodes
                )
                group_type = 'function'
            else:
                # 模块级：只包含当前节点
                group_nodes = [node_id]
                group_type = 'module'

            # 创建组
            groups.append({
                'primary': node_id,
                'nodes': group_nodes,
                'primary_severity': info.get('severity', 'unknown'),
                'primary_category': info.get('category', 'unknown'),
                'primary_reason': info.get('reason', ''),
                'function_node': func_node_id if func_node_id else None,
                'type': group_type
            })

            # 标记已处理
            processed.update(group_nodes)

        return groups

    def _find_containing_function(self, node_id: str) -> Optional[str]:
        """查找包含节点的函数定义

        2026-10 分层 CPG-lite ①:节点现携带 function_name 属性(构建器
        _tag_node_owners 写入)——直接按属性+文件匹配函数节点,**不再用
        500 行行号窗口猜归属**(旧启发式跨文件/相邻函数会错配)。
        """
        try:
            attrs = self.graph.nodes[node_id]
        except KeyError:
            return None
        fname = attrs.get('function_name')
        node_file = self._node_file(node_id)
        node_line = self._extract_line_number(node_id)
        if not fname or not node_file:
            return None  # 无归属信息(旧图/DOT)→ 模块级处理

        for graph_node_id in self.graph.nodes():
            node_attrs = self.graph.nodes[graph_node_id]
            if node_attrs.get('type') != 'function':
                continue
            if self._node_file(graph_node_id) != node_file:
                continue
            # 函数定义节点自身的归属就是它自己(function_name 同名)
            if node_attrs.get('function_name') == fname:
                fl = self._extract_line_number(graph_node_id)
                if fl is not None and (node_line is None or fl <= node_line):
                    return graph_node_id
            # 兜底:函数节点 source 首行匹配 "def fname("
            src = node_attrs.get('source', '') or ''
            if src.lstrip().startswith(f"def {fname}("):
                fl = self._extract_line_number(graph_node_id)
                if fl is not None and (node_line is None or fl <= node_line):
                    return graph_node_id
        return None

    def _node_file(self, node_id: str) -> Optional[str]:
        """获取节点所属文件（程序化图为 file 属性，DOT 解析为 _file）"""
        attrs = self.graph.nodes[node_id]
        return attrs.get('file') or attrs.get('_file')

    def _find_nodes_in_function(self, func_node_id: str,
                               suspicious_nodes: Dict[str, Dict]) -> List[str]:
        """查找函数内的所有危险节点

        2026-10 分层 CPG-lite ①:优先用节点的 function_name 属性匹配
        (图原生查询),行号窗口仅作无归属信息节点的兜底。
        """
        func_attrs = self.graph.nodes[func_node_id]
        func_fname = None
        src = func_attrs.get('source', '') or ''
        func_fname_attr = func_attrs.get('function_name')
        m = re.match(r'\s*(?:async\s+)?def\s+(\w+)\s*\(', src)
        func_fname = func_fname_attr or (m.group(1) if m else None)
        func_file = self._node_file(func_node_id)

        result = []
        for node_id in suspicious_nodes.keys():
            try:
                node_attrs = self.graph.nodes[node_id]
            except KeyError:
                continue
            if func_fname and func_file:
                if node_attrs.get('function_name') == func_fname \
                        and self._node_file(node_id) == func_file:
                    result.append(node_id)
                continue
            # 兜底:无归属信息时行号窗口
            func_line = self._extract_line_number(func_node_id)
            node_line = self._extract_line_number(node_id)
            if node_line and func_line and func_line < node_line <= func_line + 500:
                result.append(node_id)

        return result

    def _extract_line_number(self, node_id: str) -> Optional[int]:
        """提取节点行号（属性优先，正则兜底；同 EnhancedBFS 的同名方法）"""
        try:
            attrs = self.graph.nodes[node_id]
            line = attrs.get('line') or attrs.get('_line')
            if line:
                return int(line)
        except (KeyError, ValueError, TypeError):
            pass
        import re
        match = re.search(r'_(\d+)(?:_\d+)?$', node_id)
        if match:
            return int(match.group(1))
        return None

    def _extract_group(self, group: Dict, processed: Set[str]) -> Optional[Dict]:
        """
        提取整个组的数据流

        策略：
        1. 使用组的主节点作为BFS起点
        2. BFS会自动补全函数上下文（方案1的逻辑）
        3. 包含组内所有危险节点

        Args:
            group: 分组信息
            processed: 已处理节点集合

        Returns:
            数据流字典
        """
        start_node = group['primary']
        nodes_in_group = set(group['nodes'])

        # 执行BFS（会自动补全函数上下文）
        nodes_to_keep = self.bfs.search(start_node)

        if len(nodes_to_keep) == 0:
            return None

        # 确保包含组内所有危险节点
        # （BFS可能因为max_nodes限制没有包含所有节点）
        for node_id in nodes_in_group:
            if node_id in self.graph.nodes():
                nodes_to_keep.add(node_id)

        # 标记已处理
        processed.update(nodes_in_group)

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
            'name': f"{group['primary_category']}_{filename}_{line_no}",
            'subgraph': subgraph,
            'nodes': list(nodes_to_keep),
            'edges': list(subgraph.edges(data=True)),
            'suspicious_nodes': suspicious_in_subgraph,
            'primary_node': start_node,
            'primary_severity': group['primary_severity'],
            'primary_category': group['primary_category'],
            'primary_reason': group['primary_reason'],
            'size': len(nodes_to_keep),
            'edges_count': subgraph.number_of_edges(),
            'group_type': group.get('type', 'unknown'),
            'function_node': group.get('function_node')
        }


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
        results = partitioner.partition()

        # 纯 WCC 模式无法承载超限分量（整图做子图会超出 LLM 上下文），
        # 此处警告后丢弃；hybrid 模式会对超限分量做 BFS 切分，建议使用 hybrid
        kept = []
        for r in results:
            if r.get('oversized'):
                print(f"    [WCC] WARNING: component {r['index']} has {r['size']} nodes "
                      f"(> {self.config.max_wcc_size}), dropped in 'wcc' mode. "
                      f"Use method='hybrid' to split it via BFS.")
            else:
                kept.append(r)
        return kept

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

        # 步骤2: 对所有WCC（不管大小），都用BFS重新分割（应用方案2去重）
        final_results = []
        split_count = 0

        for wcc_result in wcc_results:
            wcc_size = wcc_result['size']

            if self.config.verbose:
                print(f"    [Hybrid] Processing WCC {wcc_result['index']} (size {wcc_size})...")

            # 获取该WCC中的危险节点
            dangerous_nodes_in_wcc = wcc_result['dangerous_nodes']

            if not dangerous_nodes_in_wcc:
                # 如果没有危险节点，保留原WCC（虽然不太可能）
                if self.config.verbose:
                    print(f"    [Hybrid] WCC {wcc_result['index']} has no dangerous nodes, keeping as-is")
                final_results.append(wcc_result)
                continue

            # 🔧 修改：所有WCC都用BFS分割（应用方案2的去重逻辑）
            if self.config.verbose:
                print(f"    [Hybrid] Applying BFS split with deduplication (Method 2)...")

            # 对每个危险节点执行BFS（会自动按函数分组去重）
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
                print(f"    [Hybrid] Split WCC into {len(bfs_flows)} BFS subgraphs (deduplicated)")

        if self.config.verbose:
            print(f"  [Hybrid] Partitioning complete: {len(wcc_results)} WCCs -> {len(final_results)} final subgraphs")
            print(f"  [Hybrid] Split {split_count} oversized WCCs")

        # 🔧 新增：全局去重（处理不同WCC包含相同危险节点的情况）
        final_results = self._deduplicate_subgraphs(final_results)

        if self.config.verbose:
            print(f"  [Hybrid] After deduplication: {len(final_results)} unique subgraphs")

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

    def _deduplicate_subgraphs(self, results: List[Dict]) -> List[Dict]:
        """
        去重子图（处理不同WCC包含相同危险节点导致的重复）

        策略：
        1. 计算每对子图的节点重叠度
        2. 如果重叠度 >= 90%，认为是重复
        3. 保留较大的子图

        Args:
            results: 子图列表

        Returns:
            去重后的子图列表
        """
        if self.config.verbose:
            print(f"    [Dedup] Checking {len(results)} subgraphs for duplicates...")

        unique_results = []
        skip_indices = set()

        for i, result1 in enumerate(results):
            if i in skip_indices:
                continue

            # 获取result1的节点集合
            nodes1 = self._get_subgraph_nodes(result1)

            # 假设result1是要保留的
            should_keep = True

            # 检查是否有其他子图与它重复
            for j, result2 in enumerate(results):
                if i == j or j in skip_indices:
                    continue

                nodes2 = self._get_subgraph_nodes(result2)

                # 计算重叠
                overlap = len(nodes1 & nodes2)
                if overlap > 0:
                    similarity = overlap / min(len(nodes1), len(nodes2)) * 100

                    if similarity >= 90:
                        # 发现重复，保留较大的
                        if self.config.verbose:
                            print(f"    [Dedup] Found duplicate: subgraph {i+1} <-> subgraph {j+1} ({similarity:.1f}% overlap)")

                        if len(nodes1) < len(nodes2):
                            # result2更大，应该保留result2，跳过result1
                            should_keep = False
                            # 标记j，因为result2会被保留
                            break
                        else:
                            # result1更大或相等，保留result1，跳过result2
                            skip_indices.add(j)

            if should_keep:
                unique_results.append(result1)

        removed = len(results) - len(unique_results)
        if self.config.verbose and removed > 0:
            print(f"    [Dedup] Removed {removed} duplicate subgraphs")

        return unique_results

    def _get_subgraph_nodes(self, result: Dict) -> Set[Tuple[str, int]]:
        """
        获取子图的节点集合（用于去重比较）

        Returns:
            {(file, line)} 集合
        """
        subgraph = result.get('subgraph')
        if not subgraph:
            return set()

        nodes = set()
        for node_id in subgraph.nodes():
            attrs = subgraph.nodes[node_id]
            file = attrs.get('file', attrs.get('_file', 'unknown'))
            line = attrs.get('line', attrs.get('_line', 0))
            nodes.add((file, line))

        return nodes

    def partition(self, method: str = 'auto') -> List[Dict]:
        """
        自动选择方法分割图

        Args:
            method: 'wcc', 'bfs', 'hybrid', 或 'auto'

        Returns:
            分割结果列表
        """
        if method == 'auto' or method == 'function':
            # 2026-11 函数级分割替代 BFS/WCC：按 AST 归属属性分组
            return self.partition_by_function()
        if method == 'wcc':
            return self.partition_wcc()
        elif method == 'bfs':
            return self.partition_bfs()
        elif method == 'hybrid':
            return self.partition_hybrid()
        else:
            raise ValueError(f"Unknown method: {method}")

    def partition_by_function(self) -> List[Dict]:
        """函数级分割(2026-11):按 AST 归属属性分组,替代 WCC+BFS

        图上每个节点已携带 function_name 属性(extractor _tag_node_owners
        写入)。直接按 (file, function_name) 分组,每个函数一个子图。
        无归属的节点归入模块级组。

        优势(对比 WCC+BFS):
        - 语义边界(函数开始/结束)而非 BFS N 跳截断
        - 天然确定性(属性分组无随机性)
        - 与 L2 函数摘要一一对应
        - LLM 看到完整函数体而非碎片
        """
        if self.config.verbose:
            print("  [FunctionPartition] Grouping by AST ownership...")

        # 按 (file, function_name) 分组
        groups = defaultdict(list)  # (file, fname) → [node_id]
        module_nodes = []           # 无归属节点

        for node_id, attrs in self.graph.nodes(data=True):
            fname = attrs.get('function_name')
            ffile = attrs.get('file') or attrs.get('_file') or ''
            if fname and ffile:
                groups[(ffile, fname)].append(node_id)
            else:
                module_nodes.append(node_id)

        # 只保留含危险节点的组
        dangerous_set = set(self.suspicious_nodes.keys())
        results = []

        # 函数组
        for (ffile, fname), node_list in sorted(groups.items()):
            dangerous_in = [n for n in node_list if n in dangerous_set]
            if not dangerous_in:
                continue
            subgraph = self.graph.subgraph(node_list).copy()
            severity = min(
                (self.suspicious_nodes[n]['severity'] for n in dangerous_in),
                key=lambda s: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}.get(s, 4)
            )
            results.append({
                'index': len(results) + 1,
                'nodes': set(node_list),
                'subgraph': subgraph,
                'dangerous_nodes': dangerous_in,
                'severity': severity,
                'function_name': fname,
                'file': ffile,
                'size': len(node_list),
                'type': 'function',
            })

        # 模块级组
        module_dangerous = [n for n in module_nodes if n in dangerous_set]
        if module_dangerous:
            subgraph = self.graph.subgraph(module_nodes).copy()
            severity = min(
                (self.suspicious_nodes[n]['severity'] for n in module_dangerous),
                key=lambda s: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}.get(s, 4)
            )
            results.append({
                'index': len(results) + 1,
                'nodes': set(module_nodes),
                'subgraph': subgraph,
                'dangerous_nodes': module_dangerous,
                'severity': severity,
                'function_name': '<module>',
                'file': '',
                'size': len(module_nodes),
                'type': 'module',
            })

        # 排序: severity 优先, 大小次之
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}
        results.sort(key=lambda r: (
            sev_order.get(r['severity'], 4), -r['size']))
        for i, r in enumerate(results, 1):
            r['index'] = i

        if self.config.verbose:
            print(f"  [FunctionPartition] {len(results)} function subgraphs "
                  f"({sum(r['size'] for r in results)} nodes total)")

        return results

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
            severity = result.get('primary_severity') or result.get('severity', 'unknown')
            size = result.get('size', 0)
            # 2026-11 函数级分割:目录名携带函数名(供下游读取)
            func_name = result.get('function_name', '')
            if func_name:
                # Windows 不允许 <>/\ 等字符做目录名
                safe_name = func_name.replace('<', '').replace('>', '')
                folder_name = f"func_{safe_name}_{severity}"
            else:
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
        # 2026-10 确定性:按 node_id 排序落盘(节点集合已验证一致,
        # 仅 nx 内部迭代顺序跨 PYTHONHASHSEED 波动)
        for node_id in sorted(subgraph.nodes()):
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
                'type': attrs.get('type', attrs.get('_type', None)),  # 🔧 新增：保存节点类型
                'is_dangerous': node_id in dangerous_set,
                'severity': self.suspicious_nodes.get(node_id, {}).get('severity', 'safe'),
                'confidence': 0.9 if node_id in dangerous_set else 0.5,
                # ✅ 修复：保存函数和类信息（用于桩程序生成）
                'function_name': attrs.get('_function_name', attrs.get('function_name', None)),
                'class_name': attrs.get('_class_name', attrs.get('class_name', None)),
                # 2026-10 词法天花板攻坚:AST 解析出的真实调用目标随子图落盘
                'resolved_call': attrs.get('resolved_call', None),
                # 2026-11 摘要传播:污点相关函数的调用点标记
                'sink_expansion': attrs.get('sink_expansion', False),
                'taint_categories': attrs.get('taint_categories', None),
            })

        output_file = output_dir / 'nodes.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(nodes_list, f, indent=2, ensure_ascii=False)

        return output_file

    def _save_edges(self, result: Dict, output_dir: Path) -> Path:
        """保存edges.json"""
        subgraph = result['subgraph']

        edges_list = []
        # 2026-10 确定性:按端点排序落盘
        for from_node, to_node, edge_attrs in sorted(subgraph.edges(data=True)):
            from_file = subgraph.nodes[from_node].get('_file', 'unknown')
            to_file = subgraph.nodes[to_node].get('_file', 'unknown')
            edges_list.append({
                'from_node': from_node,
                'to_node': to_node,
                'from_file': from_file,
                'to_file': to_file,
                'is_cross_file': from_file != to_file,
                # 2026-10 结构重构：边分类随子图落盘,污点引擎与 LLM 可读
                'kind': edge_attrs.get('edge_kind', 'data'),
                'variable': edge_attrs.get('variable', ''),
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
            # 🔧 兼容两种字段名：WCC (severity) 和 BFS (primary_severity)
            severity = r.get('primary_severity') or r.get('severity', 'unknown')

            # 🔧 兼容两种字段名：WCC (dangerous_nodes) 和 BFS (suspicious_nodes)
            dangerous_nodes = r.get('suspicious_nodes') or r.get('dangerous_nodes', [])

            summary['by_severity'][severity] += 1
            summary['components'].append({
                'index': r.get('index'),
                'severity': severity,
                'size': r.get('size'),
                'dangerous_count': len(dangerous_nodes),
                'primary_reason': r.get('primary_reason', '')
            })

        output_file = output_dir / 'summary.json'
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False, default=dict)

        return output_file


# ==================== 便捷函数 ====================

def partition_graph(graph_or_dotfile, output_dir: Optional[Path] = None,
                    method: str = 'auto', patterns_file: Optional[str] = None,
                    max_nodes: int = 100, verbose: bool = True) -> List[Dict]:
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
