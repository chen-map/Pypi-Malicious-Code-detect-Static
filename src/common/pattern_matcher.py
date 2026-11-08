"""
统一的危险模式检测模块

整合自：
- graph_partitioner_v7.py: DangerPatternLoader, SuspiciousNodeDetector
- visualizer_v7.py: DangerPatternLoader

使用统一的danger_patterns.json配置，避免重复定义。
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Set


class DangerPatternLoader:
    """
    加载危险模式配置字典（统一版本）

    功能：
    1. 从外部JSON文件加载危险模式
    2. 提供内置后备模式
    3. 预编译正则表达式规则
    4. 检查节点/代码是否匹配危险模式
    """

    # 默认配置文件路径：项目根目录下的 danger_patterns.json
    DEFAULT_PATTERNS_FILE = Path(__file__).parent.parent.parent / 'danger_patterns.json'

    # 行为模式补充配置（原先 config/malicious_patterns.json 是无任何代码引用的孤儿配置）
    BEHAVIOR_PATTERNS_FILE = Path(__file__).parent.parent.parent / 'config' / 'malicious_patterns.json'

    # 单个正则的输入上限。自定义规则里有大量 .*/(DOTALL) 组合，在数百KB
    # 文本上会灾难性回溯：idna 的 uts46data.py(220KB) 曾使 check_node
    # 超过 60 秒。按块扫描把单次正则的输入规模限定在 16KB。
    MAX_REGEX_CHUNK = 16384

    def __init__(self, patterns_file: Optional[str] = None, verbose: bool = True):
        """
        初始化危险模式加载器

        Args:
            patterns_file: 自定义配置文件路径（可选）
            verbose: 是否输出加载信息
        """
        if patterns_file:
            self.patterns_file = Path(patterns_file)
        else:
            self.patterns_file = self.DEFAULT_PATTERNS_FILE

        self.verbose = verbose
        self.patterns = self._load_patterns()
        self._compile_regex_rules()

    def _load_patterns(self) -> Dict:
        """
        加载危险模式配置（单一数据源架构）

        优先级：
        1. danger_patterns.json（主要配置文件）
        2. _get_minimal_fallback()（最小化后备，仅最危险的API）

        注意：
        - 所有危险模式应定义在 danger_patterns.json 中
        - minimal fallback仅用于防止系统崩溃，不应在生产环境依赖
        """
        # 优先加载外部JSON配置
        if self.patterns_file.exists():
            try:
                with open(self.patterns_file, 'r', encoding='utf-8') as f:
                    patterns = json.load(f)
                if self.verbose:
                    print(f"  [DangerPatternLoader] [OK] Loaded from: {self.patterns_file}")
                return patterns
            except Exception as e:
                if self.verbose:
                    print(f"  [DangerPatternLoader] [ERROR] Error loading JSON: {e}")
                print(f"  [DangerPatternLoader] [WARNING] Using minimal fallback (reduced detection)")
                return self._get_minimal_fallback()

        # JSON不存在时使用minimal fallback
        if self.verbose:
            print(f"  [DangerPatternLoader] [NOT FOUND] {self.patterns_file} not found")
            print(f"  [DangerPatternLoader] [WARNING] Using minimal fallback (reduced detection)")
            print(f"  [DangerPatternLoader] -> Please ensure danger_patterns.json exists")
        return self._get_minimal_fallback()

    def _get_minimal_fallback(self) -> Dict:
        """
        最小化后备配置（防止系统崩溃）

        仅包含最危险的代码执行API。
        如需完整检测能力，请确保 danger_patterns.json 存在。

        注意：此fallback不包含任何正则规则，仅基础的字符串匹配。
        """
        return {
            "critical": {
                "description": "严重危险操作 - 代码执行",
                "patterns": [
                    {"name": "code_execution", "patterns": ["exec(", "eval(", "compile("], "description": "动态代码执行"}
                ]
            },
            "high": {
                "description": "",
                "patterns": []
            },
            "medium": {
                "description": "",
                "patterns": []
            },
            "custom_rules": {
                "description": "",
                "rules": []
            }
        }

    def _compile_regex_rules(self):
        """预编译正则表达式规则"""
        self.regex_rules = []
        custom_rules = self.patterns.get('custom_rules', {}).get('rules', [])
        for rule in custom_rules:
            # 空/缺失 regex 的规则编译成空模式会匹配一切，必须跳过
            regex_str = rule.get('regex', '')
            if not regex_str:
                if self.verbose:
                    print(f"  [PatternMatcher] Warning: rule {rule.get('name')} has empty regex, skipped")
                continue
            try:
                compiled = re.compile(regex_str)
                self.regex_rules.append({
                    'severity': rule.get('severity', 'medium'),
                    'name': rule.get('name', 'unnamed'),
                    'regex': compiled,
                    'description': rule.get('description', '')
                })
            except re.error as e:
                if self.verbose:
                    print(f"  [PatternMatcher] Warning: Invalid regex in rule {rule.get('name')}: {e}")

        # 接入 config/malicious_patterns.json 的行为模式（原先从未被引用）
        self.regex_rules.extend(self._load_behavior_rules())

    def _load_behavior_rules(self) -> List[Dict]:
        """把 config/malicious_patterns.json 的行为模式转译为正则规则

        行为模式语义是"全部子串同现"(AND)。注意：用
        (?s)(?=.*a)(?=.*b)... 前瞻链实现时，在 16KB 文本上单条就要
        0.8s，5 条即拖慢整文件扫描到分钟级(idna uts46data.py 实测)。
        这里改为 required_all 子串列表，由 check 时用 C 层子串查找判断，
        语义等价、代价可忽略。
        """
        rules: List[Dict] = []
        if not self.BEHAVIOR_PATTERNS_FILE.exists():
            return rules
        try:
            with open(self.BEHAVIOR_PATTERNS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            if self.verbose:
                print(f"  [DangerPatternLoader] Warning: cannot load behavior patterns: {e}")
            return rules

        for item in data.get('custom_patterns', []) or []:
            patterns = [str(p).lower() for p in (item.get('patterns', []) or [])]
            if not patterns:
                continue
            risk = float(item.get('risk_score', 0.8))
            rules.append({
                'severity': 'high' if risk >= 0.85 else 'medium',
                'name': f"behavior_{item.get('name', 'unknown')}",
                'regex': None,                      # 不用正则，用子串同现
                'required_all': patterns,
                'description': item.get('description', '')
            })

        if rules and self.verbose:
            print(f"  [DangerPatternLoader] Loaded {len(rules)} behavior rules from config/malicious_patterns.json")
        return rules

    def match_dictionary(self, source: str, include_low: bool = False) -> Optional[Dict]:
        """
        统一的字典模式匹配（check_node 与节点检测器共用同一实现，
        修复原先双实现漂移：一个含 low 一个不含）

        Returns:
            {'severity', 'category', 'reason'} 或 None
        """
        source_lower = source.lower()
        severities = ['critical', 'high', 'medium', 'low'] if include_low \
            else ['critical', 'high', 'medium']

        for severity in severities:
            severity_data = self.patterns.get(severity, {})
            patterns = severity_data.get('patterns', [])

            for pattern_group in patterns:
                pattern_list = pattern_group.get('patterns', [])

                # 检查是否匹配任何模式
                if any(p in source_lower for p in pattern_list):
                    # 检查是否需要额外上下文
                    context_required = pattern_group.get('context', [])
                    if context_required:
                        if not any(c in source_lower for c in context_required):
                            continue

                    # 检查是否是import模式
                    # 修复：原 any('import' in source for imp in [...]) 未使用
                    # imp 变量，退化为"source 含 'import' 子串"
                    if pattern_group.get('is_import', False):
                        if not any(imp in source_lower for imp in ['import ', ' from ']):
                            continue

                    return {
                        'severity': severity,
                        'category': pattern_group['name'],
                        'reason': pattern_group['description'],
                    }

        return None

    def check_node(self, source: str, node_type: str = "") -> Optional[Dict]:
        """
        检查节点/代码是否匹配危险模式

        大文本按 MAX_REGEX_CHUNK 分块扫描，避免自定义正则灾难性回溯；
        返回命中结果中严重度最高的一条。

        Args:
            source: 代码内容
            node_type: 节点类型（可选，用于特定检测）

        Returns:
            匹配结果字典，包含 severity, category, reason, source
            如果不匹配则返回 None
        """
        if not source:
            return None

        if len(source) <= self.MAX_REGEX_CHUNK:
            return self._check_node_chunk(source)

        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        best = None
        for start in range(0, len(source), self.MAX_REGEX_CHUNK):
            chunk = source[start:start + self.MAX_REGEX_CHUNK]
            hit = self._check_node_chunk(chunk)
            if hit and (best is None or severity_rank.get(hit['severity'], 9)
                        < severity_rank.get(best['severity'], 9)):
                best = hit
                if best['severity'] == 'critical':
                    break
        return best

    def _check_node_chunk(self, source: str) -> Optional[Dict]:
        """单块检查（check_node 的原始逻辑）"""
        # 字典匹配（统一实现，含 low 级，与节点检测器共享同一逻辑）
        result = self.match_dictionary(source, include_low=True)
        if result:
            result['source'] = source
            return result

        # 检查自定义规则
        source_lower = None
        for rule in self.regex_rules:
            if rule.get('required_all') is not None:
                # 行为规则：全部子串同现（等价于原前瞻链，但快几个数量级）
                if source_lower is None:
                    source_lower = source.lower()
                if all(sub in source_lower for sub in rule['required_all']):
                    return {
                        'severity': rule['severity'],
                        'category': rule['name'],
                        'reason': rule['description'],
                        'source': source
                    }
            elif rule['regex'] is not None and rule['regex'].search(source):
                return {
                    'severity': rule['severity'],
                    'category': rule['name'],
                    'reason': rule['description'],
                    'source': source
                }

        return None

    def get_severity_order(self) -> Dict[str, int]:
        """获取严重程度的排序权重"""
        return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'safe': 4}


class SuspiciousNodeDetector:
    """
    危险节点检测器（基于PatternLoader）

    功能：
    1. 遍历图中的所有节点
    2. 使用PatternLoader检测危险模式
    3. 返回所有可疑节点及其风险信息
    """

    # 文件名行号模式：filename_py_12345
    FILE_LINE_PATTERN = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)_py_(\d+)')

    # 颜色映射（与可视化保持一致）
    CRITICAL_COLORS = ['#B71C1C', '#D32F2F', '#FF5252']
    HIGH_COLORS = ['#F57C00', '#FFAB40', '#FF9800']
    MEDIUM_COLORS = ['#FBC02D', '#FFEB3B']

    def __init__(self, pattern_loader: DangerPatternLoader):
        """
        初始化检测器

        Args:
            pattern_loader: 已初始化的模式加载器
        """
        self.pattern_loader = pattern_loader
        self.patterns = pattern_loader.patterns

    def detect_all(self, graph) -> Dict[str, Dict]:
        """
        检测图中所有危险节点

        Args:
            graph: NetworkX图对象

        Returns:
            字典 {node_id: {severity, category, reason, label}}
        """
        suspicious = {}

        for node_id, attrs in graph.nodes(data=True):
            info = self._analyze_node(node_id, attrs)
            if info and info.get('severity') in ['critical', 'high', 'medium']:
                # 字典路径没有 file；统一从 attrs 补（benign_context 需要）
                if info.get('file') is None:
                    info['file'] = attrs.get('file') or attrs.get('_file') or ''
                suspicious[node_id] = info

        return suspicious

    def _analyze_node(self, node_id: str, attrs: Dict) -> Optional[Dict]:
        """
        分析单个节点是否危险

        2026-10 结构尸检降噪（gequests 实测：102 节点误标 59 个危险）：
        1. function 节点跳过字典匹配——它携带完整函数体,函数体内任何
           语句的 API 都会被"def 行"自匹配（def execute(): 因 body 有
           os.system 被判 critical）；函数体语句已各自成节点,def 行本身
           不携带危险语义。v7 标签/颜色路径保留（上游显式标记仍有效）。
        2. 纯字符串字面量赋值不判 network_request——URL 字符串是数据
           不是行为（about['__url__'] = 'https://...' 曾被标 high）。
        """
        label = attrs.get('source', '') or attrs.get('label', '')
        fillcolor = attrs.get('fillcolor', '')
        node_type = attrs.get('type', '')

        # 方法1: 检查V7标签格式 [CRITICAL] category: description
        v7_match = re.search(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(\w+):\s*(.+)', label)
        if v7_match:
            return {
                'severity': v7_match.group(1).lower(),
                'category': v7_match.group(2),
                'reason': v7_match.group(3),
                'label': label,
                # 2026-11 良性上下文判定需要文件路径（tests/ 降权、
                # 版本惯用法识别都在 benign_context.apply 里做）
                'file': attrs.get('file') or attrs.get('_file') or '',
            }

        # 方法2: 检查颜色标记
        severity_by_color = self._get_severity_by_color(fillcolor)
        if severity_by_color:
            return {
                'severity': severity_by_color,
                'category': 'flagged_node',
                'reason': f'Flagged by color: {fillcolor}',
                'label': label,
                'file': attrs.get('file') or attrs.get('_file') or '',
            }

        # 降噪守卫1: 函数定义节点不自匹配（函数体已逐语句成节点）
        if node_type == 'function':
            return None

        # 降噪守卫2: 纯字符串字面量赋值（URL/域名常量）不是网络行为
        # 覆盖形态: x = 'http...' / x['url'] = 'http...' / x.url = 'http...'
        # (gequests 的 about['__url__'] = ... 走 subscript_assignment 逃过
        #  首版守卫,实测 42% 危险率里大半是这类)
        if node_type in ('const_assignment', 'dict_assignment', 'list_assignment',
                         'subscript_assignment', 'attribute_assignment',
                         'assignment_with_expr'):
            if re.match(r'^\s*[\w_]+(\[[^\]]*\])?(\.\w+)*\s*=\s*(f|r|b)?[\'"]',
                        label.strip()):
                return None

        # 方法3: 使用字典模式检测
        return self._detect_by_dictionary(label, node_id)

    def _detect_by_dictionary(self, label: str, node_id: str) -> Optional[Dict]:
        """
        使用外部字典检测危险模式（字典部分委托给统一的 match_dictionary，
        修复原先与 check_node 双实现漂移的问题）

        Args:
            label: 节点标签（代码内容）
            node_id: 节点ID

        Returns:
            风险信息字典或None
        """
        # 字典匹配（统一实现；不含 low——low 不作为子图种子）
        result = self.pattern_loader.match_dictionary(label, include_low=False)
        if result:
            result['label'] = label
            result['file'] = None   # 由 _analyze_node 的调用方补充
            return result

        # 方法4: 使用自定义规则
        label_lower = None
        for rule in self.pattern_loader.regex_rules:
            if rule.get('required_all') is not None:
                if label_lower is None:
                    label_lower = label.lower()
                if all(sub in label_lower for sub in rule['required_all']):
                    return {
                        'severity': rule['severity'],
                        'category': rule['name'],
                        'reason': rule['description'],
                        'label': label
                    }
            elif rule['regex'] is not None and rule['regex'].search(label):
                return {
                    'severity': rule['severity'],
                    'category': rule['name'],
                    'reason': rule['description'],
                    'label': label
                }

        return None

    def _get_severity_by_color(self, color: str) -> Optional[str]:
        """根据颜色判断严重程度"""
        if color in self.CRITICAL_COLORS:
            return 'critical'
        elif color in self.HIGH_COLORS:
            return 'high'
        elif color in self.MEDIUM_COLORS:
            return 'medium'
        return None


# 便捷函数
def create_pattern_matcher(patterns_file: Optional[str] = None, verbose: bool = True) -> DangerPatternLoader:
    """创建并返回一个危险模式加载器"""
    return DangerPatternLoader(patterns_file, verbose)


def create_node_detector(patterns_file: Optional[str] = None, verbose: bool = True) -> SuspiciousNodeDetector:
    """创建并返回一个危险节点检测器"""
    loader = DangerPatternLoader(patterns_file, verbose)
    return SuspiciousNodeDetector(loader)
