"""
项目级DDG构建器 V7 - 完整安全分析版
V7 整合所有之前版本的功能:
- V4: CFG 增强分析
- V5: 改进的可视化
- V6: 安全检测
- V6.1: 供应链攻击检测 + 上下文感知
- V7新增: 分层分析 (小文件完整DDG + 大文件快速扫描)
主要特性:
1. 分层分析: 按文件大小自动选择分析策略
2. 完整DDG: CFG + 跨文件数据流 + 符号表
3. 安全检测: 危险模式 + 编码检测 + 混淆检测
4. 供应链检测: 依赖分析 + 域名检查
5. 快速扫描: 对超大文件的多层安全扫描
"""
import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict
import networkx as nx
from .lightweight_cfg import LightweightCFGManager
# 保持兼容性别名
ProjectCFGManager = LightweightCFGManager
from .call_graph_analyzer import (
    FunctionCallGraph, ModuleSideEffectDetector,
    CrossFileCallTracker, AttackChainExtractor
)
# ============================================
# 基础数据结构 (保持兼容)
# ============================================
class GlobalNode:
    """全局DDG节点"""
    def __init__(self, file: str, line: int, node_type: str, source: str = "", col_offset: int = -1, node_id: str = None):
        self.file = file
        self.line = line
        self.type = node_type
        self.col_offset = col_offset  # 新增：列偏移量，用于区分同一行的多个语句
        # 完整保存源代码，不截断（用于交付给动态分析）
        self.source = source if source else ""
        # 唯一ID：优先使用传入的node_id，否则基于file+line+col_offset生成
        self._node_id = node_id if node_id else self._generate_id()

    def _generate_id(self) -> str:
        """生成唯一节点ID"""
        # 使用行号+列偏移量确保同一行的多个语句有不同ID
        if self.col_offset >= 0:
            return f"{Path(self.file).name}_{self.line}_{self.col_offset}"
        else:
            # 兼容旧代码：没有列偏移量时只用行号
            return f"{Path(self.file).name}_{self.line}"

    def __hash__(self):
        # 修复：使用file+line+col_offset作为唯一key
        return hash((self.file, self.line, self.col_offset))

    def __eq__(self, other):
        if not isinstance(other, GlobalNode):
            return False
        # 修复：比较时包含col_offset
        # 兼容旧代码：如果col_offset=-1，则只用file+line比较
        if self.col_offset == -1 or other.col_offset == -1:
            return self.file == other.file and self.line == other.line
        return (self.file == other.file and
                self.line == other.line and
                self.col_offset == other.col_offset)

    def get_id(self) -> str:
        return self._node_id
class GlobalEdge:
    """全局DDG边"""
    def __init__(self, from_node: GlobalNode, to_node: GlobalNode,
                 variable: str, function: str = "", edge_type: str = "intra_file",
                 arg_mappings: List = None, cfg_path: List[str] = None,
                 severity: str = "", finding_type: str = ""):
        self.from_node = from_node
        self.to_node = to_node
        self.variable = variable
        self.function = function
        self.type = edge_type
        self.arg_mappings = arg_mappings or []
        self.cfg_path = cfg_path or []
        self.severity = severity  # V7: 新增 severity 字段
        self.finding_type = finding_type  # V7: 新增 finding_type 字段
    def __hash__(self):
        return hash((self.from_node, self.to_node, self.variable))
    def __eq__(self, other):
        return (self.from_node == other.from_node and
                self.to_node == other.to_node and
                self.variable == other.variable)
    def to_dict(self) -> Dict:
        result = {
            'from_file': self.from_node.file,
            'from_line': self.from_node.line,
            'to_file': self.to_node.file,
            'to_line': self.to_node.line,
            'variable': self.variable,
            'function': self.function,
            'type': self.type
        }
        if self.arg_mappings:
            result['arg_mappings'] = self.arg_mappings
        if self.cfg_path:
            result['cfg_path'] = self.cfg_path
        if self.severity:
            result['severity'] = self.severity
        if self.finding_type:
            result['finding_type'] = self.finding_type
        return result
class ProjectSymbolTable:
    """项目级符号表"""
    def __init__(self):
        self.functions: Dict[Tuple[str, str], Dict] = {}
        self.classes: Dict[Tuple[str, str], Dict] = {}
        self.global_vars: Dict[str, List[Tuple[str, int]]] = {}
    def add_function(self, file: str, func_name: str, line: int, params: List[str],
                     class_name: str = None):
        full_name = f"{class_name}.{func_name}" if class_name else func_name
        key = (file, full_name)
        self.functions[key] = {
            'file': file,
            'name': full_name,
            'short_name': func_name,
            'line': line,
            'params': params,
            'class': class_name
        }
    def add_class(self, file: str, class_name: str, line: int):
        key = (file, class_name)
        self.classes[key] = {
            'file': file,
            'name': class_name,
            'line': line,
            'attributes': set()
        }
    def get_function(self, file: str, func_name: str, class_name: str = None) -> Optional[Dict]:
        """获取函数信息 - 支持跨文件查找"""
        full_name = f"{class_name}.{func_name}" if class_name else func_name
        key = (file, full_name)
        if key in self.functions:
            return self.functions[key]

        # 【修复】跨文件查找：先查找完整名称
        for (f, name), info in self.functions.items():
            if name == full_name:
                return info

        # 【修复】再查找短名称（同名函数）
        for (f, name), info in self.functions.items():
            if info['short_name'] == func_name:
                # 如果有多个同名函数，优先返回不同文件的
                if f != file:
                    return info

        return None
    def get_class(self, file: str, class_name: str) -> Optional[Dict]:
        key = (file, class_name)
        if key in self.classes:
            return self.classes[key]
        return None
# ============================================
# V6.1: 增强安全检测类 (整合到V7)
# ============================================
class KnownMaliciousDomains:
    """已知恶意/可疑域名库"""
    # 常见的合法分析服务（白名单）
    LEGITIMATE_ANALYTICS = {
        'google-analytics.com',
        'segment.io',
        'mixpanel.com',
        'amplitude.com',
        'datadoghq.com',
        'newrelic.com',
        'posthog.com',
        'plausible.io',
        'umami.is',
    }
    # 已知 C2/恶意域名特征
    C2_PATTERNS = [
        r'.*\.tk$',             # 免费域名
        r'.*\.ml$',
        r'.*\.ga$',
        r'.*\.cf$',
        r'.*temp.*\.com$',
        r'.*test.*\.com$',
        r'.*cdn.*analytics',
        r'.*telemetry.*\.io$',
        r'.*metrics.*\.io$',
        r'^[a-z0-9]{20,}\.',    # 20+字符随机子域名
    ]
    SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 31337, 1337]
    @classmethod
    def check_domain(cls, domain: str) -> Tuple[bool, str]:
        """检查域名是否可疑"""
        if '://' in domain:
            domain = domain.split('://')[1].split('/')[0]
        domain_lower = domain.lower()
        for legit in cls.LEGITIMATE_ANALYTICS:
            if legit in domain_lower:
                return False, f"在合法白名单: {legit}"
        for pattern in cls.C2_PATTERNS:
            if re.match(pattern, domain_lower):
                return True, f"匹配恶意域名模式: {pattern}"
        return False, "域名看起来正常"
class DependencyAnalyzer:
    """依赖包安全分析器"""
    KNOWN_MALICIOUS = {
        'colourama': 'colorama 的拼写抢注',
        'request': 'requests 的拼写抢注',
        'urilib': 'urllib 的拼写抢注',
        'crypt0': 'crypto 的拼写抢注',
        'numpy-Py': '恶意伪装',
        'torchtriton': 'PyTorch 投毒包',
    }
    TYPO_SQUAT_PATTERNS = {
        'requests': ['request', 'reqeusts', 'reuqests', 'requestes'],
        'numpy': ['numpi', 'numby', 'numpyy', 'numpy-'],
        'pandas': ['panda', 'panads', 'pandass'],
        'flask': ['flask-', 'flask_', 'flaks'],
        'django': ['djanogo', 'djanggo', 'jango'],
        'tensorflow': ['tensorlfow', 'tensroflow'],
        'pytorch': ['pytorc', 'pytorh', 'py-torch'],
        'colorama': ['colourama', 'colormaa', 'colorama-'],
        'pillow': ['pilllow', 'pilllow-', 'pilllow'],
    }
    @classmethod
    def check_package(cls, package_name: str) -> Tuple[bool, str, str]:
        """检查包是否可疑"""
        name_lower = package_name.lower().strip()
        if name_lower in cls.KNOWN_MALICIOUS:
            return True, 'critical', f'已知恶意包: {cls.KNOWN_MALICIOUS[name_lower]}'
        for legit, typos in cls.TYPO_SQUAT_PATTERNS.items():
            if name_lower in typos:
                return True, 'critical', f'拼写抢注: 可能是 {legit} 的恶意版本'
        if re.match(r'^[\w-]+-(internal|core|lib|utils|tools)$', name_lower):
            return True, 'warning', '可疑命名模式: 可能是伪装包'
        return False, 'safe', '包名看起来正常'
class ContextAwareDetector:
    """上下文感知检测器"""
    LEGITIMATE_ENCODE_USES = [
        'img', 'image', 'photo', 'picture', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'pdf',
        'doc', 'docx', 'txt', 'html', 'csv', 'json',
        'binary', 'bytes', 'buffer', 'raw', 'data',
        'upload', 'download', 'transmit', 'http', 'api',
    ]
    MALICIOUS_ENCODE_USES = [
        'key', 'secret', 'token', 'password', 'credential', 'auth', 'api_key', 'access_key',
        'config', 'env', 'private', 'ssh', 'aws', 'jwt', 'session',
        'obfus', 'payload', 'shellcode',
    ]
    @classmethod
    def analyze_encoding_context(cls, source: str, var_name: str = '') -> Tuple[str, str]:
        """分析编码操作的上下文"""
        source_lower = source.lower()
        var_lower = var_name.lower()
        for keyword in cls.MALICIOUS_ENCODE_USES:
            if keyword in source_lower or keyword in var_lower:
                return 'critical', f'编码敏感数据: {keyword}'
        if any(word in var_lower for word in ['payload', 'shell', 'exploit', 'malicious']):
            return 'critical', '变量名表明恶意意图'
        for keyword in cls.LEGITIMATE_ENCODE_USES:
            if keyword in source_lower or keyword in var_lower:
                return 'safe', '正常数据编码'
        return 'suspicious', '上下文不明确，需要人工审查'
class MultiLayerObfuscationDetector:
    """多层混淆检测器"""
    OBFUSCATION_PATTERNS = {
        'string_concat': [
            r'["\'][a-z0-9+/=]+["\']\s*\+\s*["\'][a-z0-9+/=]+["\']',
            r'["\'][a-z]+["\']\s*\+\s*["\'][a-z]+["\']\s*\+\s*["\'][a-z]+["\']',
        ],
        'dynamic_import': [
            r'__import__\s*\(\s*["\'][^"\']+["\']\s*\+\s*',
            r'getattr\s*\(\s*__import__\(',
            r'importlib\.import_module\s*\(\s*[^,]+,\s*["\'][^"\']+["\']',
        ],
        'exec_encoded': [
            r'exec\s*\(\s*base64\.b64decode',
            r'exec\s*\(\s*__import__\([\'"]base64',
            r'eval\s*\(\s*base64\.b64decode',
        ],
        'bytecode_exec': [
            r'__import__\([\'"]marshal[\'"]\)\.loads',
            r'compile\s*\([^,]+,\s*[\'"]<string>[\'"],\s*[\'"]exec[\'"]\)',
        ],
    }
    @classmethod
    def detect(cls, source: str) -> List[Dict]:
        """检测多层混淆"""
        findings = []
        for category, patterns in cls.OBFUSCATION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, source):
                    findings.append({
                        'category': category,
                        'pattern': pattern,
                        'severity': 'critical' if 'exec' in category else 'suspicious',
                    })
        # 检测大量单字符变量
        if re.search(r'[a-z_]\s*,\s*[a-z_]\s*,\s*[a-z_]\s*,\s*[a-z_]', source):
            single_char_vars = re.findall(r'\b([a-z])\s*=', source)
            if len(single_char_vars) > 5:
                findings.append({
                    'category': 'single_char_vars',
                    'pattern': f'{len(single_char_vars)} single-char variables',
                    'severity': 'warning',
                })
        return findings
# ============================================
# V7: 快速恶意代码扫描器 (用于大文件)
# ============================================
class FastMalwareScannerV7:
    """快速恶意代码扫描器 V7 - 多层安全检测"""
    # 危险模式定义
    DANGEROUS_PATTERNS = [
        (r'\bexec\s*\(', 'EXEC_CODE_EXECUTION', 'critical'),
        (r'\beval\s*\(', 'EVAL_DYNAMIC_EVAL', 'critical'),
        (r'compile\s*\(', 'CODE_COMPILE', 'high'),
        (r'base64\.b64decode\s*\(', 'BASE64_DECODE', 'medium'),
        (r'marshal\.loads\s*\(', 'MARSHAL_DESERIALIZE', 'critical'),
        (r'pickle\.loads?\s*\(', 'PICKLE_DESERIALIZE', 'critical'),
        (r'os\.system\s*\(', 'OS_SYSTEM', 'high'),
        (r'subprocess\.\w+\s*\(', 'SUBPROCESS_CALL', 'medium'),
        (r'Popen\s*\(', 'POPEN_CALL', 'high'),
        (r'ctypes\.', 'CTYPES_IMPORT', 'medium'),
        (r'win32api\.', 'WIN32API', 'high'),
        (r'win32com\.', 'WIN32COM', 'high'),
        (r'commands\.', 'COMMANDS_MODULE', 'low'),
        (r'os\.popen\s*\(', 'OS_POPEN', 'medium'),
        (r'__import__\s*\(\s*["\']', 'DYNAMIC_IMPORT_STRING', 'high'),
        (r'urllib\.\w+\..urlopen\s*\(', 'URLLIB_OPEN', 'medium'),
        (r'urllib\.request\.', 'URLLIB_REQUEST', 'low'),
        (r'requests\.(post|get|put|delete|patch)\s*\(', 'REQUESTS_HTTP', 'medium'),
        (r'socket\.', 'SOCKET_NETWORK', 'medium'),
    ]
    def __init__(self, file_path: str, line_threshold: int = 3000):
        self.file_path = Path(file_path)
        self.line_threshold = line_threshold
        self.findings = []
        self.line_count = 0
    def scan(self) -> Dict:
        """执行快速扫描"""
        result = {
            'file': str(self.file_path),
            'line_count': 0,
            'size_mb': 0,
            'scan_mode': 'fast',
            'findings': [],
            'imports': [],
            'entry_points': [],
            'risk_level': 'low',
            'risk_score': 0
        }
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.line_count = len(content.split('\n'))
            result['line_count'] = self.line_count
            result['size_mb'] = round(len(content) / 1024 / 1024, 2)
            # 1. 危险模式扫描
            pattern_findings = self._scan_dangerous_patterns(content)
            result['findings'].extend(pattern_findings)
            # 2. Import 提取
            imports = self._extract_imports(content)
            result['imports'] = imports
            # 3. 入口点检测
            entry_points = self._find_entry_points(content)
            result['entry_points'] = entry_points
            # 4. 编码检测
            encoded_findings = self._detect_encoding(content)
            result['findings'].extend(encoded_findings)
            # 5. 混淆检测
            obfuscation = self._detect_obfuscation(content)
            if obfuscation:
                result['findings'].extend(obfuscation)
            # 6. 供应链检测
            supply_chain = self._detect_supply_chain_issues(content, imports)
            if supply_chain:
                result['findings'].extend(supply_chain)
            # 7. 域名安全检测
            domain_findings = self._detect_suspicious_domains(content)
            if domain_findings:
                result['findings'].extend(domain_findings)
            # 8. 上下文感知编码检测
            context_findings = self._context_aware_detection(content, result['findings'])
            result['findings'].extend(context_findings)
            # 计算风险等级和分数
            risk_level, risk_score = self._calculate_risk(result)
            result['risk_level'] = risk_level
            result['risk_score'] = risk_score
        except Exception as e:
            result['findings'].append({
                'type': 'SCAN_ERROR',
                'severity': 'error',
                'info': str(e)
            })
        self.findings = result['findings']
        return result
    def _scan_dangerous_patterns(self, content: str) -> List[Dict]:
        """扫描危险模式"""
        findings = []
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for pattern, ptype, severity in self.DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'type': ptype,
                        'line': i,
                        'content': stripped[:120],
                        'severity': severity
                    })
                    break
        return findings
    def _extract_imports(self, content: str) -> List[Dict]:
        """提取所有import语句"""
        imports = []
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            # from X import Y
            match = re.match(r'^from\s+(\S+)\s+import\s+(.+)', stripped)
            if match:
                imports.append({
                    'line': i,
                    'type': 'from',
                    'module': match.group(1),
                    'names': match.group(2)
                })
                continue
            # import X
            match = re.match(r'^import\s+(\S+)', stripped)
            if match:
                imports.append({
                    'line': i,
                    'type': 'import',
                    'module': match.group(1)
                })
        return imports
    def _find_entry_points(self, content: str) -> List[Dict]:
        """查找可能的入口点"""
        entry_points = []
        if re.search(r'__version__\s*=', content):
            entry_points.append({'type': '__version__'})
        if re.search(r'if\s+__name__\s*==\s*["\']__main__["\']', content):
            entry_points.append({'type': '__main__'})
        class_matches = re.finditer(r'^class\s+(\w+)', content, re.MULTILINE)
        for m in class_matches:
            line_num = content[:m.start()].count('\n') + 1
            entry_points.append({
                'type': 'class',
                'name': m.group(1),
                'line': line_num
            })
        return entry_points
    def _detect_encoding(self, content: str) -> List[Dict]:
        """检测编码内容"""
        findings = []
        # 十六进制编码块
        hex_blocks = re.finditer(r'((?:\\x[0-9a-f]{2}){5,})', content, re.IGNORECASE)
        for m in hex_blocks:
            line_num = content[:m.start()].count('\n') + 1
            findings.append({
                'type': 'HEX_ENCODED_BLOCK',
                'line': line_num,
                'content': m.group(1)[:60],
                'severity': 'high'
            })
        # Base64模式
        b64_pattern = re.compile(r'[A-Za-z0-9+/=]{100,}')
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if not line.strip().startswith('#'):
                match = b64_pattern.search(line)
                if match:
                    findings.append({
                        'type': 'BASE64_LIKELY',
                        'line': i,
                        'content': match.group(0)[:60],
                        'severity': 'medium'
                    })
        return findings
    def _detect_obfuscation(self, content: str) -> List[Dict]:
        """检测混淆技术"""
        findings = []
        lines = content.split('\n')
        # 超长单行
        for i, line in enumerate(lines, 1):
            if len(line) > 500 and not line.strip().startswith('#'):
                findings.append({
                    'type': 'LONG_LINE',
                    'line': i,
                    'info': f'Length: {len(line)} chars',
                    'severity': 'low'
                })
        # lambda混淆
        lambda_pattern = re.compile(r'lambda\s*:.*?(?:exec|eval|import)', re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if lambda_pattern.search(line) and not line.strip().startswith('#'):
                findings.append({
                    'type': 'LAMBDA_OBFUSCATION',
                    'line': i,
                    'content': line.strip()[:120],
                    'severity': 'high'
                })
        # 字符串拼接混淆
        concat_pattern = re.compile(r'["\'][a-zA-Z0-9+/=]+["\']\s*\+\s*["\'][a-zA-Z0-9+/=]+["\']\s*\+')
        if concat_pattern.search(content):
            findings.append({
                'type': 'STRING_CONCAT_OBFUSCATION',
                'severity': 'medium',
                'info': 'String concatenation detected'
            })
        return findings
    def _detect_supply_chain_issues(self, content: str, imports: List[Dict]) -> List[Dict]:
        """检测供应链问题"""
        findings = []
        # 已知恶意包
        known_malicious = {
            'colourama': 'colorama typosquat',
            'request': 'requests typosquat',
            'urilib': 'urllib typosquat',
            'crypt0': 'crypto typosquat',
        }
        # 检查导入的包
        for imp in imports:
            module = imp.get('module', '').lower()
            if module in known_malicious:
                findings.append({
                    'type': 'KNOWN_MALICIOUS_PACKAGE',
                    'line': imp['line'],
                    'content': f"Import of known malicious package: {module}",
                    'info': known_malicious[module],
                    'severity': 'critical'
                })
        # 检测setup.py中的依赖拼写错误
        if 'REQUIRES' in content or 'install_requires' in content:
            # 检测常见的拼写错误
            typo_patterns = [
                (r'aliababcloud', 'alibabacloud typo'),
                (r'request\s*["\']', 'requests typo'),
                (r'colourama', 'colorama typo'),
            ]
            for pattern, desc in typo_patterns:
                if re.search(pattern, content):
                    findings.append({
                        'type': 'DEPENDENCY_TYPO_SQUAT',
                        'info': desc,
                        'severity': 'critical'
                    })
        return findings
    def _detect_suspicious_domains(self, content: str) -> List[Dict]:
        """检测可疑域名"""
        findings = []
        # 提取URL/域名
        url_patterns = [
            r'https?://([a-zA-Z0-9.-]+\.[a-z]{2,})',
            r'["\']([a-zA-Z0-9.-]+\.[a-z]{2,})["\']',
        ]
        # 可疑域名模式
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz']
        c2_keywords = ['temp', 'test', 'cdn', 'analytics', 'telemetry', 'metrics']
        for pattern in url_patterns:
            for m in re.finditer(pattern, content):
                domain = m.group(1)
                line_num = content[:m.start()].count('\n') + 1
                # 检查可疑TLD
                for tld in suspicious_tlds:
                    if domain.lower().endswith(tld):
                        findings.append({
                            'type': 'SUSPICIOUS_DOMAIN',
                            'line': line_num,
                            'content': domain,
                            'info': f'Suspicious TLD: {tld}',
                            'severity': 'high'
                        })
                        break
                # 检查C2关键词
                for keyword in c2_keywords:
                    if keyword in domain.lower() and domain not in [
                        'google-analytics.com', 'segment.io', 'datadoghq.com'
                    ]:
                        findings.append({
                            'type': 'SUSPICIOUS_DOMAIN',
                            'line': line_num,
                            'content': domain,
                            'info': f'C2 keyword: {keyword}',
                            'severity': 'medium'
                        })
                        break
        return findings
    def _context_aware_detection(self, content: str, existing_findings: List[Dict]) -> List[Dict]:
        """上下文感知检测"""
        findings = []
        # 正常编码场景关键词
        legitimate_keywords = ['image', 'img', 'photo', 'file', 'data', 'buffer', 'binary']
        # 恶意编码场景关键词
        malicious_keywords = ['key', 'secret', 'token', 'password', 'payload', 'shellcode']
        # 分析base64使用的上下文
        for finding in existing_findings:
            if finding['type'] in ['BASE64_DECODE', 'BASE64_LIKELY']:
                line_num = finding['line']
                lines = content.split('\n')
                if line_num <= len(lines):
                    context_line = lines[line_num - 1].lower()
                    # 检查变量名/上下文
                    for keyword in malicious_keywords:
                        if keyword in context_line:
                            findings.append({
                                'type': 'CONTEXTUAL_MALICIOUS_ENCODING',
                                'line': line_num,
                                'content': f'Encoding sensitive data: {keyword}',
                                'severity': 'critical'
                            })
                            break
        return findings
    def _calculate_risk(self, result: Dict) -> Tuple[str, int]:
        """计算风险等级和分数"""
        score = 0
        for f in result['findings']:
            severity = f.get('severity', 'low')
            if severity == 'critical':
                score += 10
            elif severity == 'high':
                score += 5
            elif severity == 'medium':
                score += 2
            elif severity == 'low':
                score += 1
        result['risk_score'] = score
        if score >= 20:
            return 'critical', score
        elif score >= 10:
            return 'high', score
        elif score >= 5:
            return 'medium', score
        elif score >= 1:
            return 'low', score
        return 'safe', score
# ============================================
# V7: CFG感知的 DDG 提取器 (用于小文件)
# ============================================
class CFGAwareDDGExtractor(ast.NodeVisitor):
    """基于 CFG 的文件内 DDG 提取器 V7 (基于V4完整实现)"""
    def __init__(self, file_path: str, symbol_table: ProjectSymbolTable,
                 cfg_manager: ProjectCFGManager):
        self.file_path = file_path
        self.symbol_table = symbol_table
        self.cfg_manager = cfg_manager
        self.nodes = {}
        self.edges = []
        # 变量定义追踪
        self.var_defs = {}  # var -> [(line, node)]
        self.imports = {}  # import_name -> (line, node)
        # 作用域管理
        self.current_class = None
        self.current_func = None
        self.current_func_line = 0
        # 类属性追踪
        self.class_attributes = defaultdict(list)
        # 函数信息
        self.function_returns = {}  # func_name -> [(return_line, return_var, cfg_path), ...]
        self.function_def_nodes = {}
        self.function_params = {}
        # CFG 信息
        self.current_cfg = None  # 当前函数/模块的 CFG
        self.reachable_lines = set()  # 从入口可达的行号

        # 【性能优化】缓存 AST 遍历结果
        self._function_defs_cache = {}  # (file, func_name) -> FunctionDef
        self._all_functions_cache = []  # 所有函数定义节点

    def extract(self) -> Tuple[Dict, List, Dict, Dict]:
        """提取文件内DDG - 使用轻量级 CFG 辅助"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                source = f.read()

            # 【性能优化】一次性构建 CFG，获取所有可达行
            cfg = self.cfg_manager.build_cfg_for_file(self.file_path)
            if cfg:
                self.current_cfg = cfg
                # 直接获取可达行号（轻量级 CFG 已预计算）
                self.reachable_lines = cfg.get_reachable_lines()

            tree = ast.parse(source, filename=self.file_path)

            # 【性能优化】一次性收集所有函数定义，减少 AST 遍历
            self._collect_all_definitions(tree)

            # 【性能优化】将函数定义缓存到 CFG 管理器中（供跨文件使用）
            for func_name in self._function_defs_cache:
                if isinstance(func_name, str) or (isinstance(func_name, tuple) and len(func_name) == 2):
                    pass  # 已在 _collect_all_definitions 中处理

            self.visit(tree)

        except Exception:
            pass
        return self.nodes, self.edges, self.function_returns, self.function_def_nodes

    def _collect_all_definitions(self, tree: ast.AST):
        """一次性收集所有定义（函数、类、变量），减少 AST 遍历"""
        self._all_functions_cache = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                params = [arg.arg for arg in node.args.args]
                params_str = ', '.join(params) if params else ''
                col_offset = getattr(node, 'col_offset', -1)
                func_node = GlobalNode(self.file_path, node.lineno, 'function',
                                       f"def {node.name}({params_str})", col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = func_node
                full_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
                func_key = (self.file_path, full_name)
                self.function_def_nodes[func_key] = (node.lineno, func_node, params)
                self.function_returns[func_key] = []
                self._function_defs_cache[func_key] = node
                self._all_functions_cache.append((func_key, node))

    def _is_reachable(self, line: int) -> bool:
        """检查某行是否可达"""
        if not self.reachable_lines:
            return True  # 无 CFG 信息时假设可达
        return line in self.reachable_lines

    def _make_node_key(self, line: int, col_offset: int = -1) -> tuple:
        """
        生成节点唯一key（修复同一行多语句问题）

        Args:
            line: 行号
            col_offset: 列偏移量（默认-1表示未指定）

        Returns:
            (file_path, line, col_offset) 元组
        """
        return (self.file_path, line, col_offset)

    def _create_node(self, line: int, node_type: str, source: str, col_offset: int = -1) -> GlobalNode:
        """
        创建DDG节点的辅助方法（统一处理col_offset）

        Args:
            line: 行号
            node_type: 节点类型
            source: 源代码
            col_offset: 列偏移量（可选）

        Returns:
            GlobalNode对象（带有函数和类信息）
        """
        node = GlobalNode(self.file_path, line, node_type, source, col_offset)
        # ✅ 新增：记录当前函数和类信息（用于桩程序生成）
        node.function_name = self.current_func
        node.class_name = self.current_class
        return node
    # ==================== Import 语句 ====================
    def visit_Import(self, node):
        for alias in node.names:
            module_name = alias.name
            import_source = f"import {module_name}"
            # 修复：添加col_offset参数
            col_offset = getattr(node, 'col_offset', -1)
            import_node = GlobalNode(self.file_path, node.lineno, 'import', import_source, col_offset)
            # 修复：使用(file, line, col_offset)作为key
            key = (self.file_path, node.lineno, col_offset)
            if key not in self.nodes:
                self.nodes[key] = import_node
            as_name = alias.asname if alias.asname else module_name.split('.')[0]
            self.imports[as_name] = (node.lineno, import_node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module if node.module else ''
        for alias in node.names:
            name = alias.name
            as_name = alias.asname if alias.asname else name
            import_source = f"from {module} import {name}"
            if alias.asname:
                import_source += f" as {alias.asname}"
            # 修复：添加col_offset参数
            col_offset = getattr(node, 'col_offset', -1)
            import_node = GlobalNode(self.file_path, node.lineno, 'import', import_source, col_offset)
            # 修复：使用(file, line, col_offset)作为key
            key = (self.file_path, node.lineno, col_offset)
            if key not in self.nodes:
                self.nodes[key] = import_node
            self.imports[as_name] = (node.lineno, import_node)
        self.generic_visit(node)
    # ==================== 类定义 ====================
    def visit_ClassDef(self, node):
        old_class = self.current_class
        self.current_class = node.name
        self.symbol_table.add_class(self.file_path, node.name, node.lineno)
        col_offset = getattr(node, 'col_offset', -1)
        class_node = GlobalNode(self.file_path, node.lineno, 'class', f"class {node.name}", col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = class_node
        self.generic_visit(node)
        self.current_class = old_class
    # ==================== 函数定义 ====================
    def visit_FunctionDef(self, node):
        old_func = self.current_func
        old_func_line = self.current_func_line
        self.current_func = node.name
        self.current_func_line = node.lineno
        # 保存外层作用域
        outer_var_defs = self.var_defs.copy()
        outer_class_attrs = self.class_attributes.copy()
        params = [arg.arg for arg in node.args.args]
        params_str = ', '.join(params) if params else ''
        col_offset = getattr(node, 'col_offset', -1)
        func_node = GlobalNode(self.file_path, node.lineno, 'function',
                               f"def {node.name}({params_str})", col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = func_node
        full_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        self.symbol_table.add_function(self.file_path, node.name, node.lineno, params, self.current_class)
        func_key = (self.file_path, full_name)
        self.function_def_nodes[func_key] = (node.lineno, func_node, params)
        self.function_returns[func_key] = []
        # 添加参数
        for param in params:
            if param not in self.var_defs:
                self.var_defs[param] = []
            self.var_defs[param].append((node.lineno, func_node))
        self.generic_visit(node)
        # 恢复作用域
        self.var_defs = outer_var_defs
        self.class_attributes = outer_class_attrs
        self.current_func = old_func
        self.current_func_line = old_func_line
    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)
    # ==================== 赋值语句 ====================
    def visit_Assign(self, node):
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return
        source = ast.unparse(node) if hasattr(ast, 'unparse') else ''

        # 【修复2】细化赋值语句的节点类型
        # 检测赋值类型：普通赋值、增强赋值、解包赋值等
        if isinstance(node.value, (ast.Call, ast.Attribute, ast.BinOp, ast.Compare)):
            node_type = 'assignment_with_expr'  # 带表达式的赋值
        elif isinstance(node.value, ast.Dict):
            node_type = 'dict_assignment'  # 字典赋值
        elif isinstance(node.value, ast.List):
            node_type = 'list_assignment'   # 列表赋值
        elif isinstance(node.value, ast.Constant):
            node_type = 'const_assignment'   # 常量赋值
        else:
            node_type = 'assignment'         # 普通赋值

        for target in node.targets:
            col_offset = getattr(node, 'col_offset', -1)
            if isinstance(target, ast.Name):
                var_name = target.id
                # 【修复2】将 'statement' 改为更精确的类型
                def_node = GlobalNode(self.file_path, node.lineno, node_type, source, col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = def_node
                if var_name not in self.var_defs:
                    self.var_defs[var_name] = []
                self.var_defs[var_name].append((node.lineno, def_node))
                self._check_var_uses_in_expr(node.value, def_node)
            elif isinstance(target, ast.Attribute):
                # 对象属性赋值
                attr_node = GlobalNode(self.file_path, node.lineno, 'attribute_assignment', source, col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = attr_node
                if isinstance(target.value, ast.Name) and target.value.id == 'self':
                    attr_name = target.attr
                    self.class_attributes[attr_name].append((node.lineno, attr_node))
                    if self.current_class:
                        full_func_name = f"{self.current_class}.{self.current_func}"
                        func_key = (self.file_path, full_func_name)
                        if func_key in self.function_def_nodes:
                            _, func_node, _ = self.function_def_nodes[func_key]
                            edge = GlobalEdge(
                                func_node, attr_node,
                                variable=f"self.{attr_name}",
                                function=full_func_name,
                                edge_type="intra_file"
                            )
                            self.edges.append(edge)
                self._check_var_uses_in_expr(node.value, attr_node)
            elif isinstance(target, ast.Subscript):
                # 下标赋值
                subscript_node = GlobalNode(self.file_path, node.lineno, 'subscript_assignment', source, col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = subscript_node
                if isinstance(target.value, ast.Name):
                    container_name = target.value.id
                    if container_name in self.var_defs:
                        for def_line, def_node in self.var_defs[container_name]:
                            edge = GlobalEdge(
                                def_node, subscript_node,
                                variable=container_name,
                                function=self.current_func or '<module>',
                                edge_type="intra_file"
                            )
                            self.edges.append(edge)
                self._check_var_uses_in_expr(node.value, subscript_node)
                self._check_var_uses_in_expr(target.slice, subscript_node)
            elif isinstance(target, ast.Tuple):
                # 解包赋值
                unpack_node = GlobalNode(self.file_path, node.lineno, 'unpack_assignment', source, col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = unpack_node
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        var_name = elt.id
                        if var_name not in self.var_defs:
                            self.var_defs[var_name] = []
                        self.var_defs[var_name].append((node.lineno, unpack_node))
                self._check_var_uses_in_expr(node.value, unpack_node)
        self.generic_visit(node)

    # 【修复2】增强赋值语句
    def visit_AugAssign(self, node):
        """处理增强赋值：+=, -=, *=, /=, %= 等"""
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return

        # 确定操作类型
        op_map = {
            ast.Add: 'increment',      # +=
            ast.Sub: 'decrement',      # -=
            ast.Mult: 'multiply',      # *=
            ast.Div: 'divide',         # /=  (Python 3)
            ast.FloorDiv: 'floor_divide',  # //=
            ast.Mod: 'modulo',        # %=
            ast.Pow: 'power',         # **=
            ast.LShift: 'left_shift',    # <<=
            ast.RShift: 'right_shift',   # >>=
            ast.BitOr: 'bit_or',      # |=
            ast.BitXor: 'bit_xor',    # ^=
            ast.BitAnd: 'bit_and',    # &=
        }

        op_type = op_map.get(type(node.op), 'augment')

        source = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        node_type = f'augment_assignment_{op_type}'  # 如: increment_assignment
        col_offset = getattr(node, 'col_offset', -1)

        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            def_node = GlobalNode(self.file_path, node.lineno, node_type, source, col_offset)
            key = (self.file_path, node.lineno, col_offset)
            if key not in self.nodes:
                self.nodes[key] = def_node
            if var_name not in self.var_defs:
                self.var_defs[var_name] = []
            self.var_defs[var_name].append((node.lineno, def_node))
            self._check_var_uses_in_expr(node.value, def_node)
            # 增强赋值也会读取变量本身
            self._check_var_uses_in_expr(node.target, def_node)
        elif isinstance(node.target, ast.Attribute):
            attr_node = GlobalNode(self.file_path, node.lineno, f'attribute_{op_type}', source, col_offset)
            key = (self.file_path, node.lineno, col_offset)
            if key not in self.nodes:
                self.nodes[key] = attr_node
            self._check_var_uses_in_expr(node.value, attr_node)
            self._check_var_uses_in_expr(node.target, attr_node)
        elif isinstance(node.target, ast.Subscript):
            sub_node = GlobalNode(self.file_path, node.lineno, f'subscript_{op_type}', source, col_offset)
            key = (self.file_path, node.lineno, col_offset)
            if key not in self.nodes:
                self.nodes[key] = sub_node
            self._check_var_uses_in_expr(node.value, sub_node)
            self._check_var_uses_in_expr(node.target.value, sub_node)

        self.generic_visit(node)

    # 【修复2】删除语句
    def visit_Delete(self, node):
        """处理 del 语句"""
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return

        source = ast.unparse(node) if hasattr(ast, 'unparse') else 'del ...'
        col_offset = getattr(node, 'col_offset', -1)
        del_node = GlobalNode(self.file_path, node.lineno, 'delete', source, col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = del_node

        self.generic_visit(node)

    # ==================== 控制流语句 ====================
    def visit_If(self, node):
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return
        source = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        col_offset = getattr(node, 'col_offset', -1)
        if_node = GlobalNode(self.file_path, node.lineno, 'if', source, col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = if_node
        self._check_var_uses_in_expr(node.test, if_node)
        first_stmt = self._get_first_statement_in_body(node.body)
        if first_stmt:
            edge = GlobalEdge(if_node, first_stmt, variable="true_branch",
                            function=self.current_func or '<module>', edge_type="intra_file")
            self.edges.append(edge)
        if node.orelse:
            first_else = self._get_first_statement_in_body(node.orelse)
            if first_else:
                edge = GlobalEdge(if_node, first_else, variable="false_branch",
                                function=self.current_func or '<module>', edge_type="intra_file")
                self.edges.append(edge)
        self.generic_visit(node)
    def visit_For(self, node):
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return
        source = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        col_offset = getattr(node, 'col_offset', -1)
        for_node = GlobalNode(self.file_path, node.lineno, 'for', source, col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = for_node
        self._check_var_uses_in_expr(node.iter, for_node)
        # 循环变量
        if isinstance(node.target, ast.Name):
            var_name = node.target.id
            if var_name not in self.var_defs:
                self.var_defs[var_name] = []
            self.var_defs[var_name].append((node.lineno, for_node))
        # 循环体第一条语句
        first_body = self._get_first_statement_in_body(node.body)
        if first_body:
            edge = GlobalEdge(for_node, first_body, variable="loop_body",
                            function=self.current_func or '<module>', edge_type="intra_file")
            self.edges.append(edge)
        self.generic_visit(node)
    def visit_While(self, node):
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return
        source = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        col_offset = getattr(node, 'col_offset', -1)
        while_node = GlobalNode(self.file_path, node.lineno, 'while', source, col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = while_node
        self._check_var_uses_in_expr(node.test, while_node)
        first_body = self._get_first_statement_in_body(node.body)
        if first_body:
            edge = GlobalEdge(while_node, first_body, variable="loop_body",
                            function=self.current_func or '<module>', edge_type="intra_file")
            self.edges.append(edge)
        self.generic_visit(node)
    # ==================== 函数调用 ====================
    def visit_Call(self, node):
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return
        source = ast.unparse(node) if hasattr(ast, 'unparse') else ''
        callee_name = None
        is_method_call = False
        method_object = None
        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee_name = node.func.attr
            is_method_call = True
            if isinstance(node.func.value, ast.Name):
                method_object = node.func.value.id
        # 修复：添加col_offset参数
        col_offset = getattr(node, 'col_offset', -1)
        call_node = GlobalNode(self.file_path, node.lineno, 'call', source, col_offset)
        # 修复：使用(file, line, col_offset)作为key
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = call_node

        # 【修复1】追踪同文件函数调用的参数传递
        if callee_name and not is_method_call:
            # 尝试查找被调用函数的定义（同文件内）
            full_callee_name = f"{self.current_class}.{callee_name}" if self.current_class else callee_name
            callee_func_key = (self.file_path, full_callee_name)

            if callee_func_key in self.function_def_nodes:
                _, callee_func_node, callee_params = self.function_def_nodes[callee_func_key]

                # 为每个位置参数创建数据流边：实参 → 形参
                for i, arg in enumerate(node.args):
                    if i < len(callee_params):
                        param_name = callee_params[i]
                        # 获取参数表达式中使用的变量
                        var_nodes_used = self._get_var_nodes_from_expr(arg)

                        # 为每个使用的变量创建边到形参定义点
                        for var_node in var_nodes_used:
                            param_node = GlobalNode(
                                self.file_path, callee_func_node.line,
                                'parameter', f"{param_name} (param)"
                            )
                            param_key = (self.file_path, callee_func_node.line + i + 1)  # 唯一key
                            if param_key not in self.nodes:
                                self.nodes[param_key] = param_node

                            # 创建边：实参变量 → 函数调用
                            edge_to_call = GlobalEdge(
                                var_node, call_node,
                                variable=param_name,
                                function=self.current_func or '<module>',
                                edge_type="parameter_pass"
                            )
                            self.edges.append(edge_to_call)

                            # 创建边：函数调用 → 形参（表示数据流入函数）
                            edge_to_param = GlobalEdge(
                                call_node, param_node,
                                variable=param_name,
                                function=callee_name,
                                edge_type="intra_file_call"
                            )
                            self.edges.append(edge_to_param)

                            # 将形参注册到函数作用域（这样函数内部使用这个参数时能找到）
                            if param_name not in self.var_defs:
                                self.var_defs[param_name] = []
                            self.var_defs[param_name].append((callee_func_node.line, param_node))

                # 处理关键字参数
                for keyword in node.keywords:
                    if keyword.arg and keyword.arg in callee_params:
                        param_name = keyword.arg
                        var_nodes_used = self._get_var_nodes_from_expr(keyword.value)

                        for var_node in var_nodes_used:
                            param_node = GlobalNode(
                                self.file_path, callee_func_node.line,
                                'parameter', f"{param_name} (param)"
                            )
                            param_key = (self.file_path, callee_func_node.line + 1000 + len(param_name))
                            if param_key not in self.nodes:
                                self.nodes[param_key] = param_node

                            edge = GlobalEdge(
                                var_node, param_node,
                                variable=param_name,
                                function=self.current_func or '<module>',
                                edge_type="parameter_pass"
                            )
                            self.edges.append(edge)

                            if param_name not in self.var_defs:
                                self.var_defs[param_name] = []
                            self.var_defs[param_name].append((callee_func_node.line, param_node))

        # 原有的参数使用检查
        for arg in node.args:
            self._check_var_uses_in_expr(arg, call_node)
        # 处理关键字参数
        for keyword in node.keywords:
            self._check_var_uses_in_expr(keyword.value, call_node)
        if is_method_call and method_object:
            if method_object in self.var_defs:
                for def_line, def_node in self.var_defs[method_object]:
                    edge = GlobalEdge(
                        def_node, call_node,
                        variable=method_object,
                        function=self.current_func or '<module>',
                        edge_type="intra_file"
                    )
                    self.edges.append(edge)
        # 嵌套调用
        if isinstance(node.func, ast.Call):
            inner_call = node.func
            inner_node = GlobalNode(self.file_path, inner_call.lineno, 'call',
                                   ast.unparse(inner_call) if hasattr(ast, 'unparse') else '')
            inner_key = (self.file_path, inner_call.lineno)
            if inner_key not in self.nodes:
                self.nodes[inner_key] = inner_node
            edge = GlobalEdge(
                inner_node, call_node,
                variable="return_value",
                function=self.current_func or '<module>',
                edge_type="intra_file"
            )
            self.edges.append(edge)
        self.generic_visit(node)

    # ==================== 表达式语句（关键修复！）====================
    def visit_Expr(self, node):
        """
        处理裸表达式语句（如分号后的恶意代码）
        例如：import setuptools;__import__('builtins').exec(...)
        """
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return

        # 修复：添加col_offset参数
        col_offset = getattr(node, 'col_offset', -1)
        source = ast.unparse(node.value) if hasattr(ast, 'unparse') else str(ast.dump(node.value))

        # 创建表达式节点
        expr_node = GlobalNode(self.file_path, node.lineno, 'expression_statement', source, col_offset)
        key = (self.file_path, node.lineno, col_offset)
        if key not in self.nodes:
            self.nodes[key] = expr_node

        # 如果表达式是函数调用，递归处理（会触发visit_Call）
        self.generic_visit(node)
    # ==================== 属性访问 ====================
    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and isinstance(node.value.ctx, ast.Load):
            obj_name = node.value.id
            col_offset = getattr(node, 'col_offset', -1)
            if obj_name in self.imports:
                attr_source = ast.unparse(node) if hasattr(ast, 'unparse') else f"{obj_name}.{node.attr}"
                attr_node = GlobalNode(self.file_path, node.lineno, 'attribute', attr_source, col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = attr_node
                import_line, import_node = self.imports[obj_name]
                edge = GlobalEdge(
                    import_node, attr_node,
                    variable=f"{obj_name}.{node.attr}",
                    function=self.current_func or '<module>',
                    edge_type="intra_file"
                )
                self.edges.append(edge)
            elif obj_name == 'self' and self.current_class:
                attr_source = ast.unparse(node) if hasattr(ast, 'unparse') else f"self.{node.attr}"
                attr_node = GlobalNode(self.file_path, node.lineno, 'attribute', attr_source, col_offset)
                key = (self.file_path, node.lineno, col_offset)
                if key not in self.nodes:
                    self.nodes[key] = attr_node
                if node.attr in self.class_attributes:
                    for attr_line, attr_def_node in self.class_attributes[node.attr]:
                        edge = GlobalEdge(
                            attr_def_node, attr_node,
                            variable=f"self.{node.attr}",
                            function=self.current_func or '<module>',
                            edge_type="intra_file"
                        )
                        self.edges.append(edge)
        self.generic_visit(node)

    # ==================== 辅助方法：从表达式获取变量节点 ====================
    def _get_var_nodes_from_expr(self, expr: ast.AST) -> List[GlobalNode]:
        """获取表达式中引用的所有变量节点"""
        nodes = []
        if isinstance(expr, ast.Name):
            var_name = expr.id
            if var_name in self.var_defs:
                for def_line, def_node in self.var_defs[var_name]:
                    nodes.append(def_node)
        elif isinstance(expr, ast.Call):
            # 函数调用的返回值
            call_source = ast.unparse(expr) if hasattr(ast, 'unparse') else ''
            call_node = GlobalNode(self.file_path, expr.lineno, 'call', call_source)
            call_key = (self.file_path, expr.lineno)
            if call_key not in self.nodes:
                self.nodes[call_key] = call_node
            nodes.append(call_node)
            # 递归获取参数中的变量
            for arg in expr.args:
                nodes.extend(self._get_var_nodes_from_expr(arg))
        elif isinstance(expr, ast.Attribute):
            # 属性访问
            attr_source = ast.unparse(expr) if hasattr(ast, 'unparse') else ''
            attr_node = GlobalNode(self.file_path, expr.lineno, 'attribute', attr_source)
            attr_key = (self.file_path, expr.lineno)
            if attr_key not in self.nodes:
                self.nodes[attr_key] = attr_node
            nodes.append(attr_node)
            # 递归获取对象中的变量
            nodes.extend(self._get_var_nodes_from_expr(expr.value))
        elif isinstance(expr, ast.BinOp):
            # 二元操作：获取左右操作数中的变量
            nodes.extend(self._get_var_nodes_from_expr(expr.left))
            nodes.extend(self._get_var_nodes_from_expr(expr.right))
        elif isinstance(expr, ast.Compare):
            # 比较：获取操作数中的变量
            nodes.extend(self._get_var_nodes_from_expr(expr.left))
            for comparator in expr.comparators:
                nodes.extend(self._get_var_nodes_from_expr(comparator))
        elif isinstance(expr, ast.Dict) or isinstance(expr, ast.List) or isinstance(expr, ast.Tuple):
            # 字面量：递归处理元素
            if hasattr(expr, 'elts'):
                for elt in expr.elts:
                    nodes.extend(self._get_var_nodes_from_expr(elt))
            if hasattr(expr, 'keys'):
                for key in expr.keys:
                    nodes.extend(self._get_var_nodes_from_expr(key))
            if hasattr(expr, 'values'):
                for val in expr.values:
                    nodes.extend(self._get_var_nodes_from_expr(val))
        elif isinstance(expr, ast.Subscript):
            # 下标访问
            nodes.extend(self._get_var_nodes_from_expr(expr.value))
            if expr.slice:
                nodes.extend(self._get_var_nodes_from_expr(expr.slice))
        return nodes

    # ==================== Return 语句 ====================
    def visit_Return(self, node):
        if not self._is_reachable(node.lineno):
            self.generic_visit(node)
            return
        if node.value:
            source = ast.unparse(node) if hasattr(ast, 'unparse') else 'return ...'
            col_offset = getattr(node, 'col_offset', -1)
            ret_node = GlobalNode(self.file_path, node.lineno, 'return', source, col_offset)
            key = (self.file_path, node.lineno, col_offset)
            if key not in self.nodes:
                self.nodes[key] = ret_node
            self._check_var_uses_in_expr(node.value, ret_node)
            # 使用 CFG 路径信息
            cfg_path = self._get_cfg_path_to_exit(node.lineno)
            if isinstance(node.value, ast.Name):
                var_name = node.value.id
                full_name = f"{self.current_class}.{self.current_func}" if self.current_class else self.current_func
                func_key = (self.file_path, full_name)
                if func_key in self.function_returns:
                    self.function_returns[func_key].append((node.lineno, var_name, cfg_path))
        self.generic_visit(node)
    def _get_cfg_path_to_exit(self, line: int) -> List[str]:
        """获取从该行到函数出口的 CFG 路径"""
        if not self.current_cfg:
            return []
        # 获取当前函数的 CFG
        full_name = f"{self.current_class}.{self.current_func}" if self.current_class else self.current_func
        if not full_name or full_name == '<module>':
            return []
        func_cfg = self.current_cfg.function_cfgs.get(full_name)
        if not func_cfg:
            return []
        # 获取该行所在的块
        block = func_cfg.get_block_at_line(line)
        if not block:
            return []
        # 简单返回块 ID 作为路径标识
        return [str(block.block.id)]
    # ==================== 辅助方法 ====================
    def _get_first_statement_in_body(self, body):
        for stmt in body:
            if isinstance(stmt, (ast.Assign, ast.AugAssign, ast.Return, ast.If,
                               ast.For, ast.While, ast.With, ast.Try, ast.Raise, ast.Expr, ast.Call)):
                key = (self.file_path, stmt.lineno)
                if key in self.nodes:
                    return self.nodes[key]
                else:
                    source = ast.unparse(stmt) if hasattr(ast, 'unparse') else ''
                    node_type = 'statement'
                    if isinstance(stmt, ast.If):
                        node_type = 'if'
                    elif isinstance(stmt, ast.For):
                        node_type = 'for'
                    elif isinstance(stmt, ast.While):
                        node_type = 'while'
                    elif isinstance(stmt, ast.Return):
                        node_type = 'return'
                    new_node = GlobalNode(self.file_path, stmt.lineno, node_type, source)
                    self.nodes[key] = new_node
                    return new_node
        return None
    def _check_var_uses_in_expr(self, expr: ast.AST, user_node: GlobalNode):
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                var_name = node.id
                if var_name in self.imports:
                    import_line, import_node = self.imports[var_name]
                    edge = GlobalEdge(
                        import_node, user_node,
                        variable=var_name,
                        function=self.current_func or '<module>',
                        edge_type="intra_file"
                    )
                    self.edges.append(edge)
                elif var_name in self.var_defs:
                    for def_line, def_node in self.var_defs[var_name]:
                        edge = GlobalEdge(
                            def_node, user_node,
                            variable=var_name,
                            function=self.current_func or '<module>',
                            edge_type="intra_file"
                        )
                        self.edges.append(edge)
# ============================================
# V7: 跨文件分析器
# ============================================
class CFGAwareCrossFileAnalyzer(ast.NodeVisitor):
    """基于 CFG 的跨文件调用分析器"""
    def __init__(self, project_dir: str, symbol_table: ProjectSymbolTable,
                 cfg_manager: ProjectCFGManager, large_files: List[Path] = None):
        self.project_dir = Path(project_dir)
        self.symbol_table = symbol_table
        self.cfg_manager = cfg_manager
        self.cross_file_calls = []
        self.current_file = None
        self.current_func = None
        self.current_class = None
        self.large_files = large_files or []  # V7: 跳过大文件的符号表分析
    def analyze(self):
        """分析整个项目 - 只分析小文件"""
        py_files = list(self.project_dir.rglob('*.py'))
        # V7: 排除大文件和输出目录
        py_files = [f for f in py_files if '__pycache__' not in str(f)
                    and '.ddg_output' not in str(f)
                    and f not in self.large_files]
        # 收集所有定义
        for file_path in py_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    source = f.read()
                tree = ast.parse(source, filename=str(file_path))
                self._collect_definitions(str(file_path), tree)
            except:
                pass
        # 分析跨文件调用
        for file_path in py_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    source = f.read()
                tree = ast.parse(source, filename=str(file_path))
                self.current_file = str(file_path)
                self.current_func = None
                self.current_class = None
                self.visit(tree)
            except:
                pass
    def _collect_definitions(self, file_path: str, tree: ast.AST):
        class DefinitionCollector(ast.NodeVisitor):
            def __init__(self, file_path, symbol_table):
                self.file_path = file_path
                self.symbol_table = symbol_table
                self.current_class = None
            def visit_ClassDef(self, node):
                old_class = self.current_class
                self.current_class = node.name
                self.symbol_table.add_class(self.file_path, node.name, node.lineno)
                self.generic_visit(node)
                self.current_class = old_class
            def visit_FunctionDef(self, node):
                params = [arg.arg for arg in node.args.args]
                self.symbol_table.add_function(
                    self.file_path, node.name, node.lineno, params, self.current_class
                )
                self.generic_visit(node)
        DefinitionCollector(file_path, self.symbol_table).visit(tree)
    def visit_ClassDef(self, node):
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class
    def visit_FunctionDef(self, node):
        old_func = self.current_func
        self.current_func = node.name
        self.generic_visit(node)
        self.current_func = old_func
    def visit_Call(self, node):
        call_info = self._check_call(node)
        if call_info:
            self.cross_file_calls.append(call_info)
        self.generic_visit(node)
    def _check_call(self, call_node: ast.Call) -> Optional[Dict]:
        if not self.current_file:
            return None
        callee_name = None
        if isinstance(call_node.func, ast.Name):
            callee_name = call_node.func.id
        elif isinstance(call_node.func, ast.Attribute):
            callee_name = call_node.func.attr
        if not callee_name:
            return None
        callee_info = self.symbol_table.get_function(
            self.current_file, callee_name, self.current_class
        )
        if not callee_info:
            return None
        callee_file = callee_info['file']
        if callee_file == self.current_file:
            return None
        arg_mappings = []
        callee_params = callee_info.get('params', [])
        for i, arg in enumerate(call_node.args):
            if i < len(callee_params):
                caller_var = self._get_arg_var_name(arg)
                callee_param = callee_params[i]
                if caller_var:
                    arg_mappings.append((caller_var, callee_param))
        return {
            'caller_file': self.current_file,
            'callee_file': callee_file,
            'caller_line': call_node.lineno,
            'callee_func': callee_name,
            'callee_line': callee_info['line'],
            'caller_func': self.current_func or '<module>',
            'caller_class': self.current_class,
            'arg_mappings': arg_mappings,
        }
    def _get_arg_var_name(self, arg: ast.AST) -> Optional[str]:
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Call):
            if isinstance(arg.func, ast.Name):
                return f"{arg.func.id}()"
        return None
# ============================================
# V7: 过程间 CFG 构建器
# ============================================
class InterProceduralCFGBuilder:
    """过程间控制流图构建器"""
    def __init__(self, cfg_manager: ProjectCFGManager, symbol_table: ProjectSymbolTable):
        self.cfg_manager = cfg_manager
        self.symbol_table = symbol_table
        self.call_graph = defaultdict(list)
        self.reverse_call_graph = defaultdict(list)
    def build(self, cross_file_calls: List[Dict]):
        """构建过程间调用图"""
        for call in cross_file_calls:
            caller_key = (call['caller_file'], call['caller_func'])
            callee_key = (call['callee_file'], call['callee_func'])
            self.call_graph[caller_key].append({
                'target': callee_key,
                'line': call['caller_line'],
                'arg_mappings': call.get('arg_mappings', [])
            })
            self.reverse_call_graph[callee_key].append({
                'caller': caller_key,
                'line': call['caller_line'],
                'arg_mappings': call.get('arg_mappings', [])
            })
    def get_callers(self, file: str, func: str) -> List[Dict]:
        return self.reverse_call_graph.get((file, func), [])
    def get_callees(self, file: str, func: str) -> List[Dict]:
        return self.call_graph.get((file, func), [])
    def get_return_flow_path(self, call: Dict) -> Optional[List[str]]:
        """
        获取跨文件调用的返回值数据流路径
        返回: [block_id1, block_id2, ...] 表示从 callee 出口到 caller 调用点的 CFG 路径
        """
        caller_file = call['caller_file']
        callee_file = call['callee_file']
        callee_func = call['callee_func']
        # 获取被调用函数的出口块
        exit_blocks = self.cfg_manager.get_function_exit_blocks(callee_file, callee_func)
        if not exit_blocks:
            return None
        # 简化路径: 记录出口块 ID
        path = []
        for block in exit_blocks:
            path.append(f"{callee_file}:{block.block.id}")
        # 获取调用点块
        call_block = self.cfg_manager.get_block_at_line(caller_file, call['caller_line'])
        if call_block:
            path.append(f"{caller_file}:{call_block.block.id}")
        return path
# ============================================
# V7: 项目级 DDG 构建器 - 主类
# ============================================
class ProjectDDGBuilderV7:
    """项目级DDG构建器 V7 - 完整安全分析 + 分层扫描"""
    # 行数阈值
    SMALL_FILE_THRESHOLD = 10000  # 提高阈值：小于 10000 行使用完整 DDG 分析（轻量级 CFG 支持更大规模）
    def __init__(self, project_dir: str):
        self.project_dir = Path(project_dir)
        self.nodes = {}
        self.edges = []
        self.symbol_table = ProjectSymbolTable()
        self.cross_file_calls = []
        self.function_returns = {}
        self.function_def_nodes = {}
        self.function_params = {}
        # CFG 组件
        self.cfg_manager = ProjectCFGManager()
        self.inter_proc_cfg = None
        # V7: 快速扫描结果
        self.fast_scan_results = {}
        # V7.1: 调用图和攻击链分析
        self.call_graph = None
        self.side_effect_detector = None
        self.cross_file_tracker = None
        self.attack_chains = []
    def build(self) -> Dict:
        print("\n[Project-Level DDG V7 - Complete Security Analysis]")
        print("=" * 70)
        # 步骤0：文件分类
        print("\n[0/8] Categorizing files by size...")
        small_files, large_files = self._categorize_files()
        print(f"  Small files (< {self.SMALL_FILE_THRESHOLD} lines): {len(small_files)}")
        print(f"  Large files (>= {self.SMALL_FILE_THRESHOLD} lines): {len(large_files)}")
        if large_files:
            for f in large_files:
                line_count = self._count_lines(f)
                print(f"    - {f.name}: {line_count:,} lines ({round(self._get_file_size_mb(f), 2)} MB)")
        # 步骤1：为小文件构建 CFG
        print("\n[1/8] Building CFGs for small files...")
        self._build_cfgs_for_files(small_files)
        print(f"  CFGs built: {len(self.cfg_manager.cfgs)}")
        # 步骤2：符号表和跨文件调用检测 (只分析小文件)
        print("\n[2/8] Building symbol table (small files only)...")
        analyzer = CFGAwareCrossFileAnalyzer(
            str(self.project_dir), self.symbol_table, self.cfg_manager, large_files
        )
        analyzer.analyze()
        self.cross_file_calls = analyzer.cross_file_calls
        print(f"  Functions found: {len(self.symbol_table.functions)}")
        print(f"  Classes found: {len(self.symbol_table.classes)}")
        print(f"  Cross-file calls: {len(self.cross_file_calls)}")
        # 步骤2.5：函数调用图分析
        print("[2.5/9] Building function call graph...")
        call_graph = FunctionCallGraph()
        side_effect_detector = ModuleSideEffectDetector()
        
        # 分析所有Python文件
        all_py_files = list(self.project_dir.rglob('*.py'))
        all_py_files = [f for f in all_py_files if '__pycache__' not in str(f) and '.ddg_output' not in str(f)]
        
        for file_path in all_py_files:
            try:
                source = file_path.read_text(encoding='utf-8', errors='ignore')
                call_graph.add_file(str(file_path), source)
                side_effect_detector.analyze_file(str(file_path), source)
            except Exception as e:
                pass
        
        self.call_graph = call_graph
        self.side_effect_detector = side_effect_detector
        print(f"  Functions in call graph: {len(call_graph.functions)}")
        print(f"  Call graph edges: {call_graph.call_graph.number_of_edges()}")
        
        # 统计模块副作用
        side_effect_count = sum(len(effects) for effects in side_effect_detector.side_effects.values())
        print(f"  Module side effects: {side_effect_count}")
        
        # 步骤2.6：跨文件调用追踪
        print("[2.6/9] Tracking cross-file calls...")
        cross_file_tracker = CrossFileCallTracker(call_graph)
        cross_file_analysis = cross_file_tracker.analyze({})
        self.cross_file_tracker = cross_file_tracker
        print(f"  Cross-file calls: {cross_file_analysis['total_cross_file_calls']}")
        
        # 步骤2.7：提取攻击链
        print("[2.7/9] Extracting attack chains...")
        attack_chain_extractor = AttackChainExtractor(call_graph, side_effect_detector, cross_file_tracker)
        attack_chains = attack_chain_extractor.extract_attack_chains()
        self.attack_chains = attack_chains
        print(f"  Attack chains found: {len(attack_chains)}")
        for chain in attack_chains[:3]:
            # 安全地处理可能包含特殊字符的源代码
            source_preview = chain['primary_source'][:50] if chain['primary_source'] else ''
            # 移除可能导致编码错误的字符
            source_preview = source_preview.encode('ascii', errors='ignore').decode('ascii')
            print(f"    - [{chain['primary_severity'].upper()}] {chain['primary_func']}: {source_preview}")
        # 步骤3：提取小文件的 DDG
        print("\n[4/8] Extracting DDG for small files...")
        self._extract_ddgs_for_files(small_files)
        intra_edges = [e for e in self.edges if e.type == 'intra_file']
        print(f"  Total nodes: {len(self.nodes)}")
        print(f"  Intra-file edges: {len(intra_edges)}")
        # 步骤4：快速扫描大文件
        print("\n[5/8] Fast scanning large files...")
        self._fast_scan_large_files(large_files)
        self._print_fast_scan_summary()
        # 步骤5：构建过程间 CFG
        print("\n[6/8] Building inter-procedural CFG...")
        self.inter_proc_cfg = InterProceduralCFGBuilder(self.cfg_manager, self.symbol_table)
        self.inter_proc_cfg.build(self.cross_file_calls)
        print(f"  Call graph edges: {sum(len(v) for v in self.inter_proc_cfg.call_graph.values())}")
        # 步骤6：添加跨文件桥接边
        print("\n[7/8] Adding cross-file bridge edges...")
        bridge_count = self._add_cross_file_bridges()
        print(f"  Bridge edges added: {bridge_count}")
        # 步骤7：安全分析整合
        print("\n[8/8] Running security analysis...")
        security_report = self._generate_security_report()
        print(f"  Security issues: {security_report['total_issues']}")
        # 步骤8：去重和完成
        print("\n[9/8] Finalizing...")
        self.edges = self._deduplicate_edges()
        print(f"  Total edges (after dedup): {len(self.edges)}")
        nx_graph = self._build_networkx_graph()
        print(f"  NetworkX: {nx_graph.number_of_nodes()} nodes, {nx_graph.number_of_edges()} edges")
        self._print_statistics()
        self._print_v7_summary(security_report)
        return {
            'nodes': self.nodes,
            'edges': self.edges,
            'nx_graph': nx_graph,
            'symbol_table': self.symbol_table,
            'cross_file_calls': self.cross_file_calls,
            'cfg_manager': self.cfg_manager,
            'inter_proc_cfg': self.inter_proc_cfg,
            'fast_scan_results': self.fast_scan_results,
            'security_report': security_report,
            'call_graph': self.call_graph,
            'side_effects': self.side_effect_detector.side_effects if self.side_effect_detector else {},
            'attack_chains': self.attack_chains
        }
    def _categorize_files(self) -> Tuple[List[Path], List[Path]]:
        """按大小分类文件"""
        py_files = list(self.project_dir.rglob('*.py'))
        py_files = [f for f in py_files if '__pycache__' not in str(f) and '.ddg_output' not in str(f)]
        small_files = []
        large_files = []
        for file_path in py_files:
            line_count = self._count_lines(file_path)
            if line_count < self.SMALL_FILE_THRESHOLD:
                small_files.append(file_path)
            else:
                large_files.append(file_path)
        return small_files, large_files
    def _count_lines(self, file_path: Path) -> int:
        """快速统计文件行数"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for _ in f)
        except:
            return 0
    def _get_file_size_mb(self, file_path: Path) -> float:
        """获取文件大小（MB）"""
        try:
            return file_path.stat().st_size / 1024 / 1024
        except:
            return 0
    def _build_cfgs_for_files(self, files: List[Path]):
        """只为指定文件构建 CFG"""
        for file_path in files:
            try:
                self.cfg_manager.build_cfg_for_file(str(file_path))
            except Exception as e:
                print(f"  [Warning] Failed to build CFG for {file_path.name}: {e}")
    def _extract_ddgs_for_files(self, files: List[Path]):
        """只为指定文件提取 DDG"""
        for file_path in files:
            try:
                extractor = CFGAwareDDGExtractor(
                    str(file_path), self.symbol_table, self.cfg_manager
                )
                file_nodes, file_edges, func_returns, func_defs = extractor.extract()
                for key, node in file_nodes.items():
                    if key not in self.nodes:
                        self.nodes[key] = node
                self.edges.extend(file_edges)
                for key, ret_info in func_returns.items():
                    if key not in self.function_returns:
                        self.function_returns[key] = []
                    self.function_returns[key].extend(ret_info)
                for key, def_info in func_defs.items():
                    self.function_def_nodes[key] = def_info
            except Exception as e:
                print(f"  [Warning] Failed to extract DDG from {file_path.name}: {e}")
    def _fast_scan_large_files(self, files: List[Path]):
        """快速扫描大文件"""
        for file_path in files:
            try:
                scanner = FastMalwareScannerV7(str(file_path), self.SMALL_FILE_THRESHOLD)
                result = scanner.scan()
                self.fast_scan_results[str(file_path)] = result
                self._add_fast_scan_nodes(file_path, result)
            except Exception as e:
                print(f"  [Error] Fast scan failed for {file_path.name}: {e}")
    def _add_fast_scan_nodes(self, file_path: Path, scan_result: Dict):
        """将快速扫描结果添加到DDG"""
        file_str = str(file_path)
        # 文件概览节点
        risk_symbols = {'safe': '[SAFE]', 'low': '[LOW]', 'medium': '[MED]', 'high': '[HIGH]', 'critical': '[CRITICAL]'}
        summary_node = GlobalNode(
            file_str, 1,
            'fast_scan_summary',
            f"Large File: {scan_result['line_count']:,} lines, {scan_result['size_mb']} MB, "
            f"Risk: {risk_symbols.get(scan_result['risk_level'], '[?]')} {scan_result['risk_level'].upper()} "
            f"(Score: {scan_result.get('risk_score', 0)})"
        )
        key = (file_str, 1)
        if key not in self.nodes:
            self.nodes[key] = summary_node
        # import 节点
        for imp in scan_result.get('imports', []):
            import_node = GlobalNode(
                file_str, imp['line'],
                'import',
                f"from {imp.get('module', '')} import {imp.get('names', '')}" if imp['type'] == 'from' else f"import {imp.get('module', '')}"
            )
            key = (file_str, imp['line'])
            if key not in self.nodes:
                self.nodes[key] = import_node
                edge = GlobalEdge(summary_node, import_node,
                                variable="contains", function='<module>', edge_type="intra_file")
                self.edges.append(edge)
        # 安全发现节点
        for finding in scan_result.get('findings', []):
            severity = finding.get('severity', 'low')
            if severity in ['critical', 'high', 'medium']:
                finding_node = GlobalNode(
                    file_str, finding.get('line', 1),
                    'security_finding',
                    f"[{severity.upper()}] {finding.get('type', '')}: {finding.get('content', '')[:80]}"
                )
                key = (file_str, finding.get('line', 1))
                if key not in self.nodes:
                    self.nodes[key] = finding_node
                    edge = GlobalEdge(summary_node, finding_node,
                                    variable="contains", function='<module>',
                                    edge_type="intra_file", severity=severity,
                                    finding_type=finding.get('type', ''))
                    self.edges.append(edge)
    def _print_fast_scan_summary(self):
        """打印快速扫描摘要"""
        if not self.fast_scan_results:
            return
        print("\n  Fast Scan Results:")
        high_risk = []
        medium_risk = []
        for file_path, result in self.fast_scan_results.items():
            risk = result.get('risk_level', 'low')
            findings_count = len(result.get('findings', []))
            filename = Path(file_path).name
            if risk in ['high', 'critical']:
                high_risk.append((filename, findings_count, risk, result.get('risk_score', 0)))
            elif risk in ['medium', 'low']:
                medium_risk.append((filename, findings_count, risk, result.get('risk_score', 0)))
        if high_risk:
            print(f"    [HIGH/CRITICAL RISK] {len(high_risk)} files:")
            for name, count, risk, score in high_risk:
                print(f"      [!] {name}: {count} findings, {risk.upper()}, score={score}")
        if medium_risk:
            print(f"    [MEDIUM/LOW RISK] {len(medium_risk)} files:")
            for name, count, risk, score in medium_risk:
                print(f"      [*] {name}: {count} findings, {risk.upper()}, score={score}")
    def _add_cross_file_bridges(self) -> int:
        """添加跨文件桥接边"""
        bridge_count = 0
        for call in self.cross_file_calls:
            caller_file = call['caller_file']
            callee_file = call['callee_file']
            caller_line = call['caller_line']
            arg_mappings = call.get('arg_mappings', [])
            call_key = (caller_file, caller_line)
            if call_key not in self.nodes:
                call_node = GlobalNode(caller_file, caller_line, 'call',
                                      f"{call['callee_func']}()")
                self.nodes[call_key] = call_node
            callee_key = (callee_file, call['callee_line'])
            if callee_key not in self.nodes:
                callee_node = GlobalNode(callee_file, call['callee_line'], 'function',
                                        f"def {call['callee_func']}()")
                self.nodes[callee_key] = callee_node
            cfg_path = self.inter_proc_cfg.get_return_flow_path(call) if self.inter_proc_cfg else []
            if arg_mappings:
                mapping_str = ','.join([f"{caller_var}->{callee_param}"
                                       for caller_var, callee_param in arg_mappings])
                call_label = f"calls({mapping_str})"
            else:
                call_label = "calls"
            call_edge = GlobalEdge(
                self.nodes[call_key], self.nodes[callee_key],
                variable=call_label,
                function=call['caller_func'],
                edge_type="cross_file_call",
                arg_mappings=arg_mappings,
                cfg_path=cfg_path
            )
            self.edges.append(call_edge)
            bridge_count += 1
            callee_func_key = (callee_file, call['callee_func'])
            if callee_func_key in self.function_def_nodes:
                func_line, func_node, func_params = self.function_def_nodes[callee_func_key]
                caller_var = self._find_caller_assignment_var(caller_file, caller_line)
                if caller_var:
                    assign_node = self._find_assignment_node(caller_file, caller_line, caller_var)
                    if assign_node:
                        return_vars = self._get_actual_return_vars(callee_func_key, cfg_path)
                        if return_vars:
                            return_label = f"return({','.join(return_vars)})->{caller_var}"
                        else:
                            return_label = f"return->{caller_var}"
                        edge = GlobalEdge(
                            func_node, assign_node,
                            variable=return_label,
                            function=call['callee_func'],
                            edge_type="cross_file_return",
                            cfg_path=cfg_path
                        )
                        self.edges.append(edge)
                        bridge_count += 1
        return bridge_count
    def _get_actual_return_vars(self, callee_func_key: Tuple[str, str], cfg_path: List[str]) -> List[str]:
        if callee_func_key not in self.function_returns:
            return []
        returns = self.function_returns[callee_func_key]
        if not returns:
            return []
        return_vars = []
        for ret_line, ret_var, ret_cfg_path in returns:
            if ret_var and ret_var not in return_vars:
                return_vars.append(ret_var)
        return return_vars
    def _find_caller_assignment_var(self, file: str, call_line: int) -> Optional[str]:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            if call_line <= len(lines):
                line = lines[call_line - 1].strip()
                if '=' in line and not line.startswith('='):
                    left_part = line.split('=')[0].strip()
                    if left_part and left_part.replace('_', '').isidentifier():
                        return left_part
        except:
            pass
        return None
    def _find_assignment_node(self, file: str, line: int, var_name: str) -> Optional[GlobalNode]:
        key = (file, line)
        if key in self.nodes:
            return self.nodes[key]
        try:
            with open(file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            if line <= len(lines):
                node = GlobalNode(file, line, 'statement', lines[line - 1].strip())
                self.nodes[key] = node
                return node
        except:
            pass
        return None
    def _deduplicate_edges(self) -> List:
        edge_groups = {}
        for edge in self.edges:
            key = (edge.from_node.line, edge.to_node.line,
                   edge.from_node.file, edge.to_node.file)
            if key not in edge_groups:
                edge_groups[key] = []
            edge_groups[key].append(edge)
        unique_edges = []
        for key, edges in edge_groups.items():
            if len(edges) == 1:
                unique_edges.extend(edges)
            else:
                cross_file_return = [e for e in edges if e.type == 'cross_file_return']
                cross_file_call = [e for e in edges if e.type == 'cross_file_call']
                intra_file = [e for e in edges if e.type == 'intra_file']
                if cross_file_return:
                    unique_edges.extend(cross_file_return)
                elif cross_file_call:
                    unique_edges.extend(cross_file_call)
                else:
                    variables = [e.variable for e in edges]
                    combined_var = ','.join(variables)
                    edges[0].variable = combined_var
                    unique_edges.append(edges[0])
        return unique_edges
    def _build_networkx_graph(self) -> nx.DiGraph:
        G = nx.DiGraph()
        for key, node in self.nodes.items():
            node_id = node.get_id()
            G.add_node(node_id, file=node.file, line=node.line,
                      type=node.type, source=node.source)
        for edge in self.edges:
            from_id = edge.from_node.get_id()
            to_id = edge.to_node.get_id()
            G.add_edge(from_id, to_id, variable=edge.variable,
                      function=edge.function, type=edge.type)
        return G
    def _generate_security_report(self) -> Dict:
        """生成安全分析报告 - 使用V6.1检测器"""
        report = {
            'total_issues': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': defaultdict(int),
            'by_file': defaultdict(list),
            'risk_level': 'safe',
            'findings': []
        }
        # V6.1: 创建检测器
        from .ddg_builder_v7 import (
            KnownMaliciousDomains, DependencyAnalyzer,
            ContextAwareDetector, MultiLayerObfuscationDetector
        )
        domain_checker = KnownMaliciousDomains()
        dep_analyzer = DependencyAnalyzer()
        context_detector = ContextAwareDetector()
        obfu_detector = MultiLayerObfuscationDetector()
        # 1. 分析大文件的快速扫描结果
        for file_path, scan_result in self.fast_scan_results.items():
            for finding in scan_result.get('findings', []):
                severity = finding.get('severity', 'low')
                report['total_issues'] += 1
                report['by_severity'][severity] += 1
                report['by_type'][finding.get('type', 'unknown')] += 1
                report['by_file'][file_path].append(finding)
                report['findings'].append({
                    'file': file_path,
                    'line': finding.get('line', 0),
                    'severity': severity,
                    'type': finding.get('type', 'unknown'),
                    'content': finding.get('content', '')[:200]
                })
        # 2. V6.1: 分析小文件中的每个节点
        for key, node in self.nodes.items():
            # 兼容两种key格式：(file, line) 或 (file, line, col_offset)
            if len(key) == 2:
                file_path, line = key
                col_offset = -1
            elif len(key) == 3:
                file_path, line, col_offset = key
            else:
                continue

            source = getattr(node, 'source', '')
            # 跳过空节点
            if not source or len(source) < 3:
                continue
            # V6.1: 上下文感知编码检测
            if 'base64' in source or 'b32' in source or 'b64' in source:
                ctx_severity, ctx_reason = context_detector.analyze_encoding_context(source, '')
                if ctx_severity in ['critical', 'suspicious']:
                    sev = 'critical' if ctx_severity == 'critical' else 'medium'
                    report['total_issues'] += 1
                    report['by_severity'][sev] += 1
                    report['by_type']['context_aware_encode'] += 1
                    report['findings'].append({
                        'file': file_path,
                        'line': line,
                        'severity': sev,
                        'type': 'context_aware_encode',
                        'content': f"{ctx_reason}: {source[:100]}"
                    })
            # V6.1: 多层混淆检测
            obfu_findings = obfu_detector.detect(source)
            for obf in obfu_findings:
                sev = obf['severity']
                if sev == 'warning':
                    sev = 'low'
                elif sev == 'suspicious':
                    sev = 'medium'
                report['total_issues'] += 1
                report['by_severity'][sev] += 1
                report['by_type'][obf['category']] += 1
                report['findings'].append({
                    'file': file_path,
                    'line': line,
                    'severity': sev,
                    'type': obf['category'],
                    'content': f"{obf['category']}: {source[:100]}"
                })
            # V6.1: 域名安全检查
            import re
            urls = re.findall(r'https?://[^\s\'"<>]+', source)
            for url in urls:
                is_suspicious, reason = domain_checker.check_domain(url)
                if is_suspicious:
                    report['total_issues'] += 1
                    report['by_severity']['high'] += 1
                    report['by_type']['suspicious_domain'] += 1
                    report['findings'].append({
                        'file': file_path,
                        'line': line,
                        'severity': 'high',
                        'type': 'suspicious_domain',
                        'content': f"{reason}: {url}"
                    })
            # V6.1: 危险模式检测
            dangerous_patterns = [
                (r'\bexec\s*\(', 'exec_code_execution', 'critical'),
                (r'\beval\s*\(', 'eval_dynamic_eval', 'critical'),
                (r'\b__import__\s*\(', 'dynamic_import', 'high'),
                (r'\bcompile\s*\(', 'code_compile', 'high'),
                (r'marshal\.loads', 'marshal_deserialize', 'critical'),
                (r'pickle\.loads?', 'pickle_deserialize', 'critical'),
            ]
            for pattern, issue_type, severity in dangerous_patterns:
                if re.search(pattern, source):
                    # 检查是否已经在上下文检测中捕获
                    already_found = any(
                        f['file'] == file_path and f['line'] == line and f['type'] in ['context_aware_encode', 'exec_encoded']
                        for f in report['findings']
                    )
                    if not already_found:
                        report['total_issues'] += 1
                        report['by_severity'][severity] += 1
                        report['by_type'][issue_type] += 1
                        report['findings'].append({
                            'file': file_path,
                            'line': line,
                            'severity': severity,
                            'type': issue_type,
                            'content': f"{issue_type}: {source[:100]}"
                        })
            # V6.1: 凭证收集检测
            cred_patterns = [
                (r'\.aws/credentials', 'credential_harvest'),
                (r'\.kube/config', 'kube_config_access'),
                (r'\.docker/config', 'docker_config_access'),
                (r'\.ssh/id_rsa', 'ssh_key_access'),
                (r'\.netrc', 'netrc_access'),
                (r'environ.*(?:key|secret|token)', 'env_credential_access'),
            ]
            for pattern, issue_type in cred_patterns:
                if re.search(pattern, source, re.IGNORECASE):
                    report['total_issues'] += 1
                    report['by_severity']['high'] += 1
                    report['by_type'][issue_type] += 1
                    report['findings'].append({
                        'file': file_path,
                        'line': line,
                        'severity': 'high',
                        'type': issue_type,
                        'content': f"{issue_type}: {source[:100]}"
                    })
        # 3. V6.1: 检查依赖包
        req_file = self.project_dir / 'requirements.txt'
        if req_file.exists():
            try:
                with open(req_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        package = re.split(r'[=<>!~]', line)[0].strip()
                        is_malicious, severity, reason = dep_analyzer.check_package(package)
                        if is_malicious:
                            report['total_issues'] += 1
                            report['by_severity'][severity] += 1
                            report['by_type']['malicious_dependency'] += 1
                            report['findings'].append({
                                'file': str(req_file),
                                'line': line_num,
                                'severity': severity,
                                'type': 'malicious_dependency',
                                'content': f"{reason}: {package}"
                            })
            except Exception:
                pass
        # 4. V6.1: 检查 setup.py
        setup_file = self.project_dir / 'setup.py'
        if setup_file.exists():
            try:
                with open(setup_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                # 检查安装钩子
                hook_patterns = [
                    (r'cmdclass', 'setup_cmdclass_hook', 'warning'),
                    (r'if\s+["\']install["\'].*sys\.argv', 'setup_install_hook', 'critical'),
                    (r'post_install\s*=', 'setup_post_install_hook', 'high'),
                    (r'pre_install\s*=', 'setup_pre_install_hook', 'high'),
                ]
                for pattern, issue_type, severity in hook_patterns:
                    if re.search(pattern, content):
                        report['total_issues'] += 1
                        report['by_severity'][severity] += 1
                        report['by_type'][issue_type] += 1
                        report['findings'].append({
                            'file': str(setup_file),
                            'line': 1,
                            'severity': severity,
                            'type': issue_type,
                            'content': f"{issue_type}: detected in setup.py"
                        })
                # 检查可疑网络请求
                if 'urllib.request' in content or 'requests.post' in content or 'requests.get' in content:
                    report['total_issues'] += 1
                    report['by_severity']['critical'] += 1
                    report['by_type']['setup_network_request'] += 1
                    report['findings'].append({
                        'file': str(setup_file),
                        'line': 1,
                        'severity': 'critical',
                        'type': 'setup_network_request',
                        'content': 'setup.py contains network requests'
                    })
            except Exception:
                pass
        # 确定总体风险等级
        if report['by_severity']['critical'] > 0:
            report['risk_level'] = 'critical'
        elif report['by_severity']['high'] > 0:
            report['risk_level'] = 'high'
        elif report['by_severity']['medium'] >= 3:
            report['risk_level'] = 'medium'
        elif report['by_severity']['medium'] > 0:
            report['risk_level'] = 'low'
        elif report['by_severity']['low'] > 0:
            report['risk_level'] = 'low-medium'
        return dict(report)
    def _print_statistics(self):
        intra = [e for e in self.edges if e.type == 'intra_file']
        call_edges = [e for e in self.edges if e.type == 'cross_file_call']
        return_edges = [e for e in self.edges if e.type == 'cross_file_return']
        node_types = {}
        for node in self.nodes.values():
            node_types[node.type] = node_types.get(node.type, 0) + 1
        print("\n[Node Statistics]")
        for node_type, count in sorted(node_types.items()):
            print(f"  {node_type}: {count}")
        print("\n[Edge Statistics]")
        print(f"  Intra-file:        {len(intra)}")
        print(f"  Cross-file call:   {len(call_edges)}")
        print(f"  Cross-file return: {len(return_edges)}")
        print(f"  Total:             {len(self.edges)}")
    def _print_v7_summary(self, security_report: Dict):
        """打印 V7 分析摘要"""
        print("\n" + "=" * 70)
        print("[V7 SECURITY ANALYSIS SUMMARY]")
        print("=" * 70)
        print(f"\nFile Analysis:")
        small_count = sum(1 for f in self.fast_scan_results.values() if f['line_count'] < self.SMALL_FILE_THRESHOLD)
        large_count = len(self.fast_scan_results) - small_count
        print(f"  Small files (full DDG): {len(self.nodes) - sum(1 for n in self.nodes.values() if n.type == 'security_finding')} nodes")
        print(f"  Large files (fast scan): {len(self.fast_scan_results)} files")
        print(f"\nSecurity Assessment:")
        risk_symbols = {'safe': '[SAFE]', 'low': '[LOW]', 'low-medium': '[LOW-MED]',
                         'medium': '[MEDIUM]', 'high': '[HIGH]', 'critical': '[CRITICAL]'}
        print(f"  Overall Risk: {risk_symbols.get(security_report['risk_level'], security_report['risk_level'].upper())}")
        print(f"\nIssues Found: {security_report['total_issues']}")
        for sev in ['critical', 'high', 'medium', 'low']:
            count = security_report['by_severity'].get(sev, 0)
            if count > 0:
                print(f"  {sev.upper()}: {count}")
        print("=" * 70)
