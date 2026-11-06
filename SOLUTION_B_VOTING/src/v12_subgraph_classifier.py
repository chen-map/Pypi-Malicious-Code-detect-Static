"""
V12 子图分类器 - 投票架构核心组件

功能：
- 每个子图独立LLM分析（保留完整攻击链语义）
- 输出结构化的子图判决结果
- 为投票机制提供子图级别的证据
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional
from zhipuai import ZhipuAI


class V12SubgraphClassifier:
    """V12 子图分类器 - 分析单个子图（攻击链）"""

    # 判决缓存版本号：prompt 模板/序列化逻辑变化时 +1，使旧缓存失效
    CACHE_VERSION = 3

    def __init__(self, api_key: str, use_cache: bool = True, model: str = 'glm-4-flashx'):
        """
        初始化子图分类器

        Args:
            api_key: ZhipuAI API密钥
            use_cache: 是否启用判决缓存（相同 prompt 内容不重复调用；
                       2026-10 硬化：同 corpus 重复样本/重跑成本降数倍）
        """
        self.api_key = api_key
        self.client = ZhipuAI(api_key=api_key)
        self.use_cache = use_cache
        self.model = model
        self._mem_cache = {}
        # 磁盘缓存目录：项目根/output/.llm_cache
        self.cache_dir = Path(__file__).parent.parent.parent / 'output' / '.llm_cache'
        self.cache_hits = 0
        self.cache_misses = 0

        # 加载prompt模板 (使用 v2 版本 - 融合 SocketAI Scanner 最佳实践)
        prompt_file = Path(__file__).parent.parent / "prompts" / "v12_subgraph_analyzer_en_v2.txt"
        with open(prompt_file, 'r', encoding='utf-8') as f:
            self.prompt_template = f.read()

    def _cache_lookup(self, prompt: str) -> Optional[Dict]:
        """按 prompt 内容哈希查缓存（内存 → 磁盘）"""
        if not self.use_cache:
            return None
        key = hashlib.sha256(f"v{self.CACHE_VERSION}|{prompt}".encode('utf-8')).hexdigest()[:24]
        if key in self._mem_cache:
            self.cache_hits += 1
            return dict(self._mem_cache[key])
        disk_file = self.cache_dir / f"{key}.json"
        if disk_file.exists():
            try:
                verdict = json.loads(disk_file.read_text(encoding='utf-8'))
                self._mem_cache[key] = verdict
                self.cache_hits += 1
                return dict(verdict)
            except Exception:
                pass
        self.cache_misses += 1
        return None

    def _cache_store(self, prompt: str, verdict: Dict) -> None:
        if not self.use_cache:
            return
        key = hashlib.sha256(f"v{self.CACHE_VERSION}|{prompt}".encode('utf-8')).hexdigest()[:24]
        self._mem_cache[key] = verdict
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            (self.cache_dir / f"{key}.json").write_text(
                json.dumps(verdict, ensure_ascii=False, default=str), encoding='utf-8')
        except Exception:
            pass

    def classify_subgraph(
        self,
        subgraph_json: Dict,
        package_name: str,
        ddg_v7_report: Optional[Dict] = None,
        subgraph_idx: int = 0,
        rule_based_result: Optional[Dict] = None,
        enhanced_detection_result: Optional[Dict] = None
    ) -> Dict:
        """
        分析单个子图（攻击链）并判决其危险性

        Args:
            subgraph_json: 单个子图的DDG数据
            package_name: 包名
            ddg_v7_report: DDG V7安全报告（可选）
            subgraph_idx: 子图索引（用于标识）
            rule_based_result: 规则化评分结果（可选，用于混合验证）
            enhanced_detection_result: 增强检测结果（可选，包含setup.py/依赖/元数据分析）

        Returns:
            子图判决结果：
            {
                'subgraph_name': 'subgraph_1',
                'is_malicious': True/False,
                'category': 'MALICIOUS/SUSPICIOUS/BENIGN',
                'danger_score': 0.95,
                'confidence': 0.90,
                'attack_chain_type': 'Code Injection',
                'attack_chain_complete': True,
                'reasoning': '详细推理过程',
                'malicious_indicators': [...],
                'benign_indicators': [...],
                'rule_based_result': {...}  # 如果提供了规则化评分
            }
        """
        print(f"          [Subgraph {subgraph_idx}] 分析子图: {subgraph_json.get('subgraph_name', 'unknown')}")

        # 如果提供了规则化评分结果，打印对比
        if rule_based_result:
            print(f"          [规则化评分] {rule_based_result['total_score']:.2f} ({rule_based_result['category']})")

        # 填充prompt（把规则预筛分数作为独立信号注入，避免LLM缺乏校准锚点）
        prompt = self._fill_subgraph_prompt(
            subgraph_json,
            package_name,
            ddg_v7_report,
            subgraph_idx,
            enhanced_detection_result,
            rule_based_result
        )

        # 2026-10 硬化：判决缓存——相同 prompt 内容（同子图/重复样本/重跑）
        # 直接复用历史判决，不重复调用
        cached = self._cache_lookup(prompt)
        if cached is not None:
            cached = dict(cached)
            cached.setdefault('subgraph_name', subgraph_json.get('subgraph_name', 'unknown'))
            cached['cache_hit'] = True
            print(f"          [CACHE HIT] 子图判决复用缓存 (命中 {self.cache_hits} 次)")
            return cached

        # 调用LLM（优化速度）
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a malicious code analysis expert specializing in attack chain detection."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # 低温度保证稳定性
                max_tokens=3000
            )

            # 检查响应
            if not response.choices or len(response.choices) == 0:
                print(f"          [ERROR] API返回空响应（无choices）")
                print(f"          [DEBUG] 完整响应: {response}")
                return self._fallback_keyword_classification("", subgraph_json)

            llm_output = response.choices[0].message.content

            # 检查内容是否为空
            if not llm_output or llm_output.strip() == "":
                print(f"          [WARN] API返回空内容")
                print(f"          [DEBUG] Choices数量: {len(response.choices)}")
                print(f"          [DEBUG] 第一个choice: {response.choices[0]}")
                return self._fallback_keyword_classification("", subgraph_json)

            # 解析LLM输出
            verdict = self._parse_llm_output(llm_output, subgraph_json)

            print(f"          [Subgraph {subgraph_idx}] 判决: {verdict['final_verdict']} (置信度: {verdict['confidence']:.2f})")

            # 2026-10 硬化：成功判决写入缓存（回退判决不缓存——它们不是
            # LLM 的稳定产物，缓存会放大回退噪声）
            if verdict.get('fallback') is not True:
                self._cache_store(prompt, verdict)

            return verdict

        except Exception as e:
            print(f"          [ERROR] 子图分析失败: {e}")
            import traceback
            print(f"          [DEBUG] 异常堆栈: {traceback.format_exc()}")
            # 回退：基于规则判定
            return self._fallback_rule_based_classification(subgraph_json, subgraph_idx)

    def _fill_subgraph_prompt(
        self,
        subgraph_json: Dict,
        package_name: str,
        ddg_v7_report: Optional[Dict],
        subgraph_idx: int,
        enhanced_detection_result: Optional[Dict] = None,
        rule_based_result: Optional[Dict] = None
    ) -> str:
        """填充子图分析prompt"""

        prompt = self.prompt_template

        # 规则预筛分数（独立启发式信号，给LLM做校准锚点）
        if rule_based_result:
            prescreen = (f"total_score={rule_based_result.get('total_score', 0):.2f}, "
                         f"category={rule_based_result.get('category', 'UNKNOWN')}, "
                         f"confidence={rule_based_result.get('confidence', 0):.2f}. "
                         f"This is a weighted heuristic (0-1, MALICIOUS>=0.70, "
                         f"SUSPICIOUS>=0.40). Treat it as ONE signal, not a verdict.")
        else:
            prescreen = "not available (LLM-only analysis)"
        prompt = prompt.replace("{rule_based_prescreen}", prescreen)

        # 子图基本信息
        subgraph_name = subgraph_json.get('subgraph_name', f'subgraph_{subgraph_idx}')
        prompt = prompt.replace("{subgraph_name}", subgraph_name)
        prompt = prompt.replace("{package_name}", package_name)

        # 统计信息 - 兼容两种数据格式
        # 格式1：DDG Builder的格式（有dangerous_nodes字段）
        # 格式2：子图分割器的格式（有nodes/edges字段）
        if 'dangerous_nodes' in subgraph_json:
            # 旧格式：直接提取
            dangerous_nodes = subgraph_json.get('dangerous_nodes', [])
            data_flow_paths = subgraph_json.get('data_flow_paths', [])
            functions = subgraph_json.get('functions', {})
        else:
            # 新格式：从nodes/edges中提取
            nodes = subgraph_json.get('nodes', [])
            edges = subgraph_json.get('edges', [])

            # 提取危险节点（is_dangerous=True）
            dangerous_nodes = [
                {
                    'code': node.get('code', ''),
                    'line': node.get('line', 0),
                    'file': node.get('file', ''),
                    'type': node.get('type', ''),
                    'severity': node.get('severity', 'unknown')
                }
                for node in nodes
                if node.get('is_dangerous', False)
            ]

            # 提取数据流路径（从edges中构建）
            # 2026-11 性能修复:原实现 O(E×N)(每条边两次线性扫描),
            # 千节点子图上爆炸。改 dict 索引 O(E+N)。
            _node_index = {n.get('node_id'): n for n in nodes if n.get('node_id')}
            data_flow_paths = []
            for edge in edges:
                from_node = edge.get('from_node', '')
                to_node = edge.get('to_node', '')
                if from_node and to_node:
                    # 查找节点详情
                    from_node_data = _node_index.get(from_node)
                    to_node_data = _node_index.get(to_node)
                    if from_node_data and to_node_data:
                        data_flow_paths.append([
                            {'code': from_node_data.get('code', ''), 'file': from_node_data.get('file', '')},
                            {'code': to_node_data.get('code', ''), 'file': to_node_data.get('file', '')}
                        ])

            # 提取函数信息（type=function的节点）
            functions = {}
            for node in nodes:
                if node.get('type') == 'function':
                    func_name = node.get('function_name') or node.get('code', '').split('(')[0].replace('def ', '')
                    if func_name:
                        functions.setdefault(func_name, []).append({'node': node})

        prompt = prompt.replace("{dangerous_nodes_count}", str(len(dangerous_nodes)))
        prompt = prompt.replace("{data_flow_paths_count}", str(len(data_flow_paths)))
        prompt = prompt.replace("{functions_count}", str(len(functions)))

        # 填充危险节点（限制数量）
        nodes_text = self._format_dangerous_nodes(dangerous_nodes[:20])  # 最多20个节点
        prompt = prompt.replace("{dangerous_nodes}", nodes_text)

        # 填充数据流路径（限制数量）
        paths_text = self._format_data_flow_paths(data_flow_paths[:10])  # 最多10条路径
        prompt = prompt.replace("{data_flow_paths}", paths_text)

        # 填充函数信息（限制数量）
        functions_text = self._format_functions(dict(list(functions.items())[:15]))  # 最多15个函数
        prompt = prompt.replace("{functions}", functions_text)

        # 2026-10 图内核重构：真实污点链（Source→Sink 反向 BFS 产物），
        # 优先于碎片节点呈现——这是"完整攻击链"的真正证据
        taint_chains = subgraph_json.get('taint_chains') or []
        if taint_chains:
            from src.taint_engine import format_for_prompt
            taint_text = format_for_prompt(taint_chains)
        else:
            taint_text = ("No complete taint chain found in this subgraph "
                          "(no Source->Sink path through the data-flow edges).")
        prompt = prompt.replace("{taint_chains}", taint_text)

        # 2026-11 函数级分割:完整函数上下文(函数体+摘要)
        function_name = subgraph_json.get('function_name', '')
        func_summary = subgraph_json.get('function_summary')
        if function_name and function_name != '<module>':
            func_context_lines = [f"Function: {function_name}"]
            # 完整函数体（从 functions 或 dangerous_nodes 中取）
            for fname, flist in functions.items():
                if fname == function_name and flist:
                    body = (flist[0]['node'].get('code', '') or '')[:3000]
                    func_context_lines.append("```python")
                    func_context_lines.append(body)
                    func_context_lines.append("```")
                    break
            # 函数摘要（子图携带,从 L2 层预计算）
            if func_summary:
                if func_summary.get('return_tainted'):
                    func_context_lines.append(
                        f"Pre-computed: return value is TAINTED (source: {func_summary['return_tainted']})")
                if func_summary.get('param_to_sink'):
                    func_context_lines.append(
                        f"Pre-computed: parameters flow to {func_summary['param_to_sink']}")
            prompt = prompt.replace("{function_context}", "\n".join(func_context_lines))
        else:
            prompt = prompt.replace("{function_context}",
                                    "Module-level code (no enclosing function)")

        # 2026-11 划分越界修复：跨块边。函数级划分用诱导子图切块，
        # 跨函数/跨文件边不在本块内；这里显式告诉 LLM 数据从哪进来、
        # 返回值去了哪，避免它把"参数来源未知"当成孤立的危险调用。
        boundary_edges = subgraph_json.get('boundary_edges') or {}
        prompt = prompt.replace(
            "{cross_function_context}",
            self._format_boundary_edges(boundary_edges))

        # 填充字符串字面量
        real_source_data = subgraph_json.get('real_source_data', {})
        string_literals = real_source_data.get('string_literals', {})
        strings_text = self._format_string_literals(dict(list(string_literals.items())[:20]))  # 最多20个字符串
        prompt = prompt.replace("{string_literals}", strings_text)

        # 填充DDG V7报告信息
        if ddg_v7_report:
            # 网络行为
            network_behavior = ddg_v7_report.get('network_behavior', {})
            urls = network_behavior.get('urls', [])
            suspicious_domains = network_behavior.get('suspicious_domains', [])
            ips = network_behavior.get('ips', [])

            prompt = prompt.replace("{urls_count}", str(len(urls)))
            prompt = prompt.replace("{suspicious_domains_count}", str(len(suspicious_domains)))
            prompt = prompt.replace("{ips_count}", str(len(ips)))

            suspicious_list = "\n".join([f"  - {d.get('domain', d)}" for d in suspicious_domains[:5]])
            prompt = prompt.replace("{suspicious_domains_list}", suspicious_list if suspicious_list else "None")

            # 文件系统操作
            file_system_ops = ddg_v7_report.get('file_system_ops', {})
            sensitive_paths = file_system_ops.get('sensitive_paths', [])
            file_reads = file_system_ops.get('file_reads', [])
            file_writes = file_system_ops.get('file_writes', [])

            prompt = prompt.replace("{sensitive_paths_count}", str(len(sensitive_paths)))

            paths_list = "\n".join([f"  - {p.get('pattern', p)}" for p in sensitive_paths[:5]])
            prompt = prompt.replace("{sensitive_paths_list}", paths_list if paths_list else "None")

            # 包元数据
            metadata = ddg_v7_report.get('metadata', {})
            typosquatting = ddg_v7_report.get('typosquatting', {})

            prompt = prompt.replace("{is_typosquatting}", str(typosquatting.get('is_suspicious', False)))
            prompt = prompt.replace("{setup_hooks_count}", str(len(metadata.get('setup_hooks', []))))
            prompt = prompt.replace("{init_exec_count}", str(len(metadata.get('init_exec_code', []))))
        else:
            # 没有DDG V7报告时，填充默认值
            prompt = prompt.replace("{urls_count}", "0")
            prompt = prompt.replace("{suspicious_domains_count}", "0")
            prompt = prompt.replace("{ips_count}", "0")
            prompt = prompt.replace("{suspicious_domains_list}", "None")
            prompt = prompt.replace("{sensitive_paths_count}", "0")
            prompt = prompt.replace("{sensitive_paths_list}", "None")
            prompt = prompt.replace("{is_typosquatting}", "False")
            prompt = prompt.replace("{setup_hooks_count}", "0")
            prompt = prompt.replace("{init_exec_count}", "0")

        # 填充增强检测信息
        if enhanced_detection_result:
            # setup.py分析
            setup_py_analysis = enhanced_detection_result.get('setup_py_analysis', {})
            setup_threats = [t for t in setup_py_analysis.get('threats', []) if t.get('type') == 'setup_py_malicious']
            install_hooks_threats = [t for t in setup_threats if t.get('category') == 'install_hooks']
            post_install_threats = [t for t in setup_threats if t.get('category') == 'post_install']

            prompt = prompt.replace("{setup_py_threats}", str(len(setup_threats)))
            prompt = prompt.replace("{post_install_threats}", str(len(post_install_threats)))
            prompt = prompt.replace("{setup_danger_patterns}", str(len(install_hooks_threats)))

            # 依赖分析
            dependency_analysis = enhanced_detection_result.get('dependency_analysis', {})
            dependencies = dependency_analysis.get('dependencies', [])
            typosquatting_deps = [t.get('dependency') for t in dependency_analysis.get('threats', []) if t.get('pattern_type') == 'typosquatting']
            suspicious_deps = [t.get('dependency') for t in dependency_analysis.get('threats', []) if t.get('severity') in ['high', 'medium']]

            prompt = prompt.replace("{total_dependencies}", str(len(dependencies)))
            prompt = prompt.replace("{typosquatting_deps}", str(len(typosquatting_deps)))
            prompt = prompt.replace("{suspicious_deps}", str(len(suspicious_deps)))

            # 元数据分析
            metadata_analysis = enhanced_detection_result.get('metadata_analysis', {})
            metadata_threats = metadata_analysis.get('threats', [])

            name_threats = [t for t in metadata_threats if t.get('type') == 'suspicious_package_name']
            author_threats = [t for t in metadata_threats if t.get('type') == 'suspicious_author']
            url_threats = [t for t in metadata_threats if t.get('type') == 'suspicious_url']

            name_threat_level = 'high' if name_threats else 'low'
            author_threat_level = 'medium' if author_threats else 'low'
            url_threat_level = 'high' if url_threats else 'low'

            prompt = prompt.replace("{name_threat_level}", name_threat_level)
            prompt = prompt.replace("{author_threat_level}", author_threat_level)
            prompt = prompt.replace("{url_threat_level}", url_threat_level)
            prompt = prompt.replace("{noncode_threat_level}", enhanced_detection_result.get('overall_threat_level', 'safe'))

            # 威胁类别
            threat_categories = []
            if setup_threats: threat_categories.append("setup.py")
            if typosquatting_deps: threat_categories.append("typosquatting")
            if name_threats: threat_categories.append("suspicious_name")
            if author_threats: threat_categories.append("suspicious_author")
            if url_threats: threat_categories.append("suspicious_url")

            threat_categories_str = ", ".join(threat_categories) if threat_categories else "None"
            prompt = prompt.replace("{threat_categories}", threat_categories_str)
        else:
            # 没有增强检测结果时，填充默认值
            prompt = prompt.replace("{setup_py_threats}", "0")
            prompt = prompt.replace("{post_install_threats}", "0")
            prompt = prompt.replace("{setup_danger_patterns}", "0")
            prompt = prompt.replace("{total_dependencies}", "0")
            prompt = prompt.replace("{typosquatting_deps}", "0")
            prompt = prompt.replace("{suspicious_deps}", "0")
            prompt = prompt.replace("{name_threat_level}", "low")
            prompt = prompt.replace("{author_threat_level}", "low")
            prompt = prompt.replace("{url_threat_level}", "low")
            prompt = prompt.replace("{noncode_threat_level}", "safe")
            prompt = prompt.replace("{threat_categories}", "None")

        return prompt

    def _format_dangerous_nodes(self, nodes: List[Dict]) -> str:
        """格式化危险节点（2026-10 硬化：LLM 输入消毒，剥注释/标记注入）"""
        if not nodes:
            return "None"

        from src.llm_sanitizer import sanitize_code
        lines = []
        for node in nodes[:20]:  # 最多20个
            code = sanitize_code(node.get('code', ''))[:200]  # 截断长代码
            line = node.get('line', '?')
            file = node.get('file', '?')
            lines.append(f"  Line {line} in {file}: {code}")

        return "\n".join(lines) if lines else "None"

    def _format_data_flow_paths(self, paths: List[List]) -> str:
        """格式化数据流路径（消毒后呈现）"""
        if not paths:
            return "None"

        from src.llm_sanitizer import sanitize_code
        lines = []
        for idx, path in enumerate(paths[:10], 1):  # 最多10条
            lines.append(f"  Path {idx} ({len(path)} nodes):")
            for node in path[:5]:  # 每条路径最多5个节点
                if isinstance(node, dict):
                    code = sanitize_code(node.get('code', ''))[:100]
                    lines.append(f"    → {code}")
            if len(path) > 5:
                lines.append(f"    ... ({len(path)-5} more nodes)")

        return "\n".join(lines) if lines else "None"

    def _format_boundary_edges(self, boundary: Dict, max_per_side: int = 6) -> str:
        """格式化跨块边（2026-11 划分越界修复）

        函数级划分只保留块内边，跨函数/跨文件的数据流不在本块内。这里
        列出**进入**和**离开**本函数的数据，让 LLM 知道危险调用的参数
        来源与去向，而不是把它当成孤立节点。

        boundary 结构: {'in': [rec...], 'out': [rec...]}
        rec: {from_file, from_line, from_func, to_file, to_line, to_func,
              kind, variable}
        """
        if not boundary:
            return "(none - no data crosses this function's boundary)"

        def _loc(rec, side):
            if side == 'in':
                return (f"{rec.get('from_func', '?')} "
                        f"[{rec.get('from_file', '?')}:{rec.get('from_line', 0)}]")
            return (f"{rec.get('to_func', '?')} "
                    f"[{rec.get('to_file', '?')}:{rec.get('to_line', 0)}]")

        def _var(rec):
            v = rec.get('variable') or ''
            return f"  [{v}]" if v else ''

        lines = []
        for rec in (boundary.get('in') or [])[:max_per_side]:
            lines.append(f"IN   {_loc(rec, 'in')}  --{rec.get('kind', 'data')}"
                         f"{_var(rec)}-->  [THIS FUNCTION]")
        for rec in (boundary.get('out') or [])[:max_per_side]:
            lines.append(f"OUT  [THIS FUNCTION]  --{rec.get('kind', 'data')}"
                         f"{_var(rec)}-->  {_loc(rec, 'out')}")
        if not lines:
            return "(none - no data crosses this function's boundary)"
        return "\n".join(lines)

    def _format_functions(self, functions: Dict) -> str:
        """格式化函数信息

        2026-10 图内核重构：函数节点的 code 现在是完整函数体（构建器侧已
        升级），截断从 150 提升到 1200 字符。
        2026-10 硬化：LLM 输入消毒——docstring 里的 API 名不再进 prompt，
        注释中的提示注入被标记。
        """
        if not functions:
            return "None"

        from src.llm_sanitizer import sanitize_code
        lines = []
        for func_name, func_list in list(functions.items())[:15]:  # 最多15个函数
            if func_list:
                func_node = func_list[0].get('node', {})
                code = sanitize_code(func_node.get('code', '') or '')[:1200]
                lines.append(f"  {func_name}:")
                for code_line in code.splitlines():
                    lines.append(f"    {code_line}")

        return "\n".join(lines) if lines else "None"

    def _format_string_literals(self, string_literals: Dict) -> str:
        """格式化字符串字面量（字面量是提示注入最常见的藏身处，同样消毒）"""
        if not string_literals:
            return "None"

        from src.llm_sanitizer import sanitize_code
        lines = []
        for var_name, value in list(string_literals.items())[:20]:  # 最多20个
            value_str = sanitize_code(str(value))[:100]  # 截断
            lines.append(f"  {var_name} = {value_str}")

        return "\n".join(lines) if lines else "None"

    def _parse_llm_output(self, llm_output: str, subgraph_json: Dict) -> Dict:
        """解析LLM输出"""
        try:
            # 尝试提取JSON
            json_match = re.search(r'```json\s*(.*?)\s*```', llm_output, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # 如果没有markdown格式，尝试直接解析
                json_str = llm_output

            verdict = json.loads(json_str)

            # 确保必需字段存在（兼容新旧两种 prompt 格式）
            verdict.setdefault('subgraph_name', subgraph_json.get('subgraph_name', 'unknown'))
            # 均衡模式（2026-10 大改）：原先缺字段默认 is_malicious=True，
            # 配合零容忍投票会把一次 JSON 截断/解析事故放大成整包 MALICIOUS。
            # 现在缺字段默认中性值，并在下方做一致性归一。
            verdict.setdefault('is_malicious', False)
            verdict.setdefault('final_verdict', 'SUSPICIOUS')

            # 兼容新旧评分字段
            # 新格式 (v2): malware_intent_score, security_risk_score, obfuscation_score, confidence_score
            # 旧格式 (v1): danger_score, confidence
            if 'danger_score' in verdict and 'malware_intent_score' not in verdict:
                # 旧格式，转换为新格式
                verdict['malware_intent_score'] = verdict['danger_score']
                verdict['security_risk_score'] = verdict['danger_score']  # 假设相等
                verdict.setdefault('obfuscation_score', 0.0)  # 旧格式没有

            verdict.setdefault('malware_intent_score', 0.7)  # 提高恶意意图评分
            verdict.setdefault('security_risk_score', 0.7)  # 提高安全风险评分
            verdict.setdefault('obfuscation_score', 0.0)    # 默认无混淆
            verdict.setdefault('confidence', verdict.get('confidence_score', 0.3))  # 兼容两种格式
            verdict.setdefault('confidence_score', verdict.get('confidence', 0.3))  # 确保新字段存在

            # 统一 risk_score 字段（原先 LLM 正常输出 risk_score 而两个回退
            # 只产出 danger_score，下游读 risk_score 会拿到错误的默认值）
            verdict.setdefault('risk_score', verdict.get('danger_score',
                                 verdict.get('security_risk_score', 0.5)))
            if 'danger_score' not in verdict:
                verdict['danger_score'] = verdict['risk_score']  # 向后兼容别名

            # 2026-10 硬化：结构化输出校验
            # 1) 分数越界 clamp（LLM 偶发输出 1.5/-0.2 之类）
            for score_field in ('risk_score', 'danger_score', 'malware_intent_score',
                                'security_risk_score', 'confidence', 'confidence_score'):
                try:
                    v = float(verdict.get(score_field, 0.5) or 0.0)
                    verdict[score_field] = min(max(v, 0.0), 1.0)
                except (TypeError, ValueError):
                    verdict[score_field] = 0.5

            # 2) 注入回显检测：LLM 的 reason 若复述了包内注入短语，说明其
            #    可能被带偏——置信度减半，交由投票层保守处理
            from src.llm_sanitizer import has_injection
            if has_injection(str(verdict.get('reason', '')) + str(verdict.get('reasoning', ''))):
                verdict['confidence'] = round(float(verdict.get('confidence', 0.5)) * 0.5, 3)
                verdict['injection_echo'] = True
                print(f"          [WARN] 判决理由复述了提示注入短语，置信度减半")

            # 一致性归一：final_verdict 与 is_malicious 矛盾时以 verdict 为准，
            # 避免自相矛盾的判决进入投票
            if verdict['final_verdict'] == 'MALICIOUS':
                verdict['is_malicious'] = True
            else:
                verdict['is_malicious'] = False

            return verdict

        except Exception as e:
            print(f"          [WARN] LLM输出解析失败: {e}")
            print(f"          LLM输出: {llm_output[:500]}")

            # 回退：基于关键词判断
            return self._fallback_keyword_classification(llm_output, subgraph_json)

    def _fallback_rule_based_classification(self, subgraph_json: Dict, subgraph_idx: int) -> Dict:
        """回退：基于规则的分类"""
        dangerous_nodes = subgraph_json.get('dangerous_nodes', [])
        data_flow_paths = subgraph_json.get('data_flow_paths', [])

        # 统计危险API
        dangerous_apis = ['eval', 'exec', 'compile', '__import__', 'os.system', 'subprocess']
        api_count = 0
        for node in dangerous_nodes:
            code = node.get('code', '').lower()
            if any(api in code for api in dangerous_apis):
                api_count += 1

        # 规则判定
        if api_count >= 2 and len(data_flow_paths) >= 1:
            category = "MALICIOUS"
            is_malicious = True
            danger_score = 0.8
        elif api_count >= 1 or len(data_flow_paths) >= 2:
            category = "SUSPICIOUS"
            is_malicious = False
            danger_score = 0.5
        else:
            category = "BENIGN"
            is_malicious = False
            danger_score = 0.2

        return {
            'subgraph_name': subgraph_json.get('subgraph_name', f'subgraph_{subgraph_idx}'),
            'is_malicious': is_malicious,
            'final_verdict': category,
            'risk_score': danger_score,
            'danger_score': danger_score,  # 兼容别名
            'confidence': 0.5,  # 低置信度（因为是回退）
            'fallback': True,   # 标记：非LLM判决（投票层按"规则票"保守处理）
            'attack_chain_type': 'Unknown',
            'attack_chain_complete': len(data_flow_paths) > 0,
            'reasoning': f'规则回退：{api_count}个危险API，{len(data_flow_paths)}条数据流',
            'malicious_indicators': [f'{api_count} dangerous APIs'] if api_count > 0 else [],
            'benign_indicators': ['Rule-based fallback (low confidence)']
        }

    def _fallback_keyword_classification(self, llm_output: str, subgraph_json: Dict) -> Dict:
        """回退：基于关键词的LLM输出分类"""
        output_lower = llm_output.lower()

        # 均衡模式：原先裸子串 'malicious' 几乎出现在所有判决理由里
        # （"no malicious behavior" 也命中），回退大量落入 MALICIOUS/SUSPICIOUS。
        # 改用词边界匹配，并排除明确的否定语境。
        is_malicious = bool(re.search(r'\b(malicious|attack|injection)\b', output_lower)) \
            and not re.search(r'\b(no|not|without)\s+(malicious|harmful|attack|injection)\b', output_lower)
        is_benign = bool(re.search(r'\b(benign|safe|legitimate)\b', output_lower))

        if is_malicious and not is_benign:
            category = "MALICIOUS"
        elif is_benign and not is_malicious:
            category = "BENIGN"
        else:
            category = "SUSPICIOUS"

        score = 0.7 if category == "MALICIOUS" else 0.4
        return {
            'subgraph_name': subgraph_json.get('subgraph_name', 'unknown'),
            'is_malicious': (category == "MALICIOUS"),
            'final_verdict': category,
            'risk_score': score,
            'danger_score': score,  # 兼容别名
            'confidence': 0.4,  # 低置信度（解析失败）
            'fallback': True,   # 标记：非LLM判决（投票层按"规则票"保守处理）
            'attack_chain_type': 'Unknown',
            'attack_chain_complete': False,
            'reasoning': f'关键词回退：检测到 "{category}" 关键词',
            'malicious_indicators': [],
            'benign_indicators': ['Keyword-based fallback (low confidence)']
        }
