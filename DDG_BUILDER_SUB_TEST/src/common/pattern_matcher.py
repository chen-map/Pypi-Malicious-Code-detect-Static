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
        """加载危险模式配置"""
        if not self.patterns_file.exists():
            if self.verbose:
                print(f"  [PatternMatcher] Warning: {self.patterns_file} not found, using built-in patterns")
            return self._get_builtin_patterns()

        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as f:
                patterns = json.load(f)
            if self.verbose:
                print(f"  [PatternMatcher] Loaded danger patterns from: {self.patterns_file}")
            return patterns
        except Exception as e:
            if self.verbose:
                print(f"  [PatternMatcher] Error loading patterns: {e}, using built-in")
            return self._get_builtin_patterns()

    def _get_builtin_patterns(self) -> Dict:
        """
        内置的危险模式（后备配置）

        当外部配置文件不存在或加载失败时使用。
        """
        return {
            "critical": {
                "description": "严重危险操作 - 可能导致代码执行或系统控制",
                "patterns": [
                    {"name": "code_execution", "patterns": ["exec(", "eval(", "compile("], "description": "动态代码执行"},
                    {"name": "command_execution", "patterns": ["os.system", "subprocess.", "popen", "call(", "check_output", "run(", "Popen"], "description": "命令执行"},
                    {"name": "unsafe_deserialization", "patterns": ["pickle.loads", "pickle.load(", "marshal.loads", "shelve.open", "yaml.load", "yaml.unsafe_load"], "description": "不安全的反序列化"},
                ]
            },
            "high": {
                "description": "高风险操作 - 可能导致信息泄露或数据篡改",
                "patterns": [
                    {"name": "crypto_operation", "patterns": ["base64.", "binascii.", "decode(", "encode(", "cipher", "decrypt", "encrypt", "hashlib"], "description": "加密/编码操作"},
                    {"name": "network_request", "patterns": ["urllib.", "requests.", "http.", "socket.", "httpx", "aiohttp", "ftplib", "smtp"], "description": "网络请求"},
                    {"name": "file_code_operation", "patterns": ["open(", "read(", "write("], "context": ["eval", "exec", "code"], "description": "文件操作配合代码执行"},
                    {"name": "dynamic_import", "patterns": ["__import__", "importlib.", "imp.", "getattr(__builtins__", "import_module"], "description": "动态导入"},
                ]
            },
            "medium": {
                "description": "中风险操作 - 需要进一步审查",
                "patterns": [
                    {"name": "dangerous_import", "patterns": ["subprocess", "pickle", "marshal", "shelve", "urllib", "requests", "http", "socket", "ssl", "ctypes"], "is_import": True, "description": "危险模块导入"},
                    {"name": "environment_access", "patterns": ["os.environ", "sys.argv", "getenv"], "description": "环境变量访问"},
                ]
            },
            "custom_rules": {
                "description": "自定义检测规则 - 支持正则表达式",
                "rules": [
                    {"severity": "critical", "name": "obfuscated_code", "regex": r"\b_[a-zA-Z_]{20,}\s*\(", "description": "可疑的混淆函数调用"},
                    {"severity": "high", "name": "hex_string_decode", "regex": r"\bbytes\.fromhex\s*\(|chr\(.*\)\s*\+\s*chr\(", "description": "十六进制字符串解码"},
                ]
            }
        }

    def _compile_regex_rules(self):
        """预编译正则表达式规则"""
        self.regex_rules = []
        custom_rules = self.patterns.get('custom_rules', {}).get('rules', [])
        for rule in custom_rules:
            try:
                compiled = re.compile(rule.get('regex', ''))
                self.regex_rules.append({
                    'severity': rule['severity'],
                    'name': rule['name'],
                    'regex': compiled,
                    'description': rule.get('description', '')
                })
            except re.error as e:
                if self.verbose:
                    print(f"  [PatternMatcher] Warning: Invalid regex in rule {rule.get('name')}: {e}")

    def check_node(self, source: str, node_type: str = "") -> Optional[Dict]:
        """
        检查节点/代码是否匹配危险模式

        Args:
            source: 代码内容
            node_type: 节点类型（可选，用于特定检测）

        Returns:
            匹配结果字典，包含 severity, category, reason, source
            如果不匹配则返回 None
        """
        source_lower = source.lower()

        # 检查各严重级别的模式
        for severity in ['critical', 'high', 'medium', 'low']:
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
                    is_import = pattern_group.get('is_import', False)
                    if is_import:
                        if not any('import' in source_lower for imp in ['import ', ' from ']):
                            continue

                    return {
                        'severity': severity,
                        'category': pattern_group['name'],
                        'reason': pattern_group['description'],
                        'source': source
                    }

        # 检查自定义正则规则
        for rule in self.regex_rules:
            if rule['regex'].search(source):
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
                suspicious[node_id] = info

        return suspicious

    def _analyze_node(self, node_id: str, attrs: Dict) -> Optional[Dict]:
        """
        分析单个节点是否危险

        Args:
            node_id: 节点ID
            attrs: 节点属性字典

        Returns:
            风险信息字典或None
        """
        # 优先使用 source 属性（DDG构建器的实际代码内容）
        # 回退到 label 属性（可视化器生成的标签）
        label = attrs.get('source', '') or attrs.get('label', '')
        fillcolor = attrs.get('fillcolor', '')

        # 方法1: 检查V7标签格式 [CRITICAL] category: description
        v7_match = re.search(r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*(\w+):\s*(.+)', label)
        if v7_match:
            return {
                'severity': v7_match.group(1).lower(),
                'category': v7_match.group(2),
                'reason': v7_match.group(3),
                'label': label
            }

        # 方法2: 检查颜色标记
        severity_by_color = self._get_severity_by_color(fillcolor)
        if severity_by_color:
            return {
                'severity': severity_by_color,
                'category': 'flagged_node',
                'reason': f'Flagged by color: {fillcolor}',
                'label': label
            }

        # 方法3: 使用字典模式检测
        return self._detect_by_dictionary(label, node_id)

    def _detect_by_dictionary(self, label: str, node_id: str) -> Optional[Dict]:
        """
        使用外部字典检测危险模式

        Args:
            label: 节点标签（代码内容）
            node_id: 节点ID

        Returns:
            风险信息字典或None
        """
        label_lower = label.lower()

        # 检查各严重级别的模式
        for severity in ['critical', 'high', 'medium']:
            severity_data = self.patterns.get(severity, {})
            patterns = severity_data.get('patterns', [])

            for pattern_group in patterns:
                pattern_list = pattern_group.get('patterns', [])

                # 检查是否匹配任何模式
                if any(p in label_lower for p in pattern_list):
                    # 检查是否需要额外上下文
                    context_required = pattern_group.get('context', [])
                    if context_required:
                        if not any(c in label_lower for c in context_required):
                            continue

                    # 检查是否是import模式
                    is_import = pattern_group.get('is_import', False)
                    if is_import:
                        if not any('import' in label_lower for imp in ['import ', ' from ']):
                            continue

                    return {
                        'severity': severity,
                        'category': pattern_group['name'],
                        'reason': pattern_group['description'],
                        'label': label
                    }

        # 方法4: 使用自定义正则规则
        for rule in self.pattern_loader.regex_rules:
            if rule['regex'].search(label):
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
