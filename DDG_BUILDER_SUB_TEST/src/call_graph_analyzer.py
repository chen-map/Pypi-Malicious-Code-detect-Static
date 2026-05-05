"""
调用图分析器 - 函数调用图、模块副作用、跨文件调用追踪

主要功能:
1. FunctionCallGraph: 构建项目级函数调用图
2. ModuleSideEffectDetector: 检测模块导入时的副作用
3. CrossFileCallTracker: 追踪跨文件函数调用关系
4. AttackChainExtractor: 提取完整的攻击链路
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, deque
import networkx as nx


class FunctionCallVisitor(ast.NodeVisitor):
    """AST访问器 - 提取函数定义和调用"""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.functions = {}  # {func_name: {'line': int, 'args': [], 'calls': []}}
        self.imports = []     # [{'module': str, 'line': int, 'alias': str}]
        self.module_level_code = []  # 模块级别的可执行代码
        self.class_defs = {}   # {class_name: {'line': int, 'methods': {}}}

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """访问函数定义"""
        func_name = node.name
        args = [arg.arg for arg in node.args.args]
        decorators = [d.id if isinstance(d, ast.Name) else str(d) for d in node.decorator_list]

        func_info = {
            'name': func_name,
            'line': node.lineno,
            'end_line': node.end_lineno if hasattr(node, 'end_lineno') else node.lineno,
            'args': args,
            'decorators': decorators,
            'calls': [],  # 调用的其他函数
            'is_async': isinstance(node, ast.AsyncFunctionDef),
            'source': ast.get_source_segment(self.source_code, node) or ''
        }

        # 提取函数体内的调用
        call_extractor = FunctionCallExtractor(func_name, self.file_path, self.source_code)
        call_extractor.visit(node)
        func_info['calls'] = call_extractor.get_calls()

        self.functions[func_name] = func_info
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """访问异步函数定义"""
        self.visit_FunctionDef(ast.FunctionDef(
            name=node.name,
            args=node.args,
            body=node.body,
            decorator_list=node.decorator_list,
            returns=node.returns,
            type_comment=node.type_comment
        ))

    def visit_ClassDef(self, node: ast.ClassDef):
        """访问类定义"""
        class_name = node.name
        methods = {}

        # 提取类方法
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_name = item.name
                methods[method_name] = {
                    'line': item.lineno,
                    'end_line': item.end_lineno if hasattr(item, 'end_lineno') else item.lineno,
                    'args': [arg.arg for arg in item.args.args],
                    'is_async': isinstance(item, ast.AsyncFunctionDef),
                    'source': ast.get_source_segment(self.source_code, item) or ''
                }

        self.class_defs[class_name] = {
            'line': node.lineno,
            'end_line': node.end_lineno if hasattr(node, 'end_lineno') else node.lineno,
            'bases': [ast.unparse(base) if hasattr(ast, 'unparse') else str(base) for base in node.bases],
            'methods': methods,
            'decorators': [ast.unparse(d) if hasattr(ast, 'unparse') else str(d) for d in node.decorator_list],
            'source': ast.get_source_segment(self.source_code, node) or ''
        }

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        """访问import语句"""
        for alias in node.names:
            self.imports.append({
                'module': alias.name,
                'alias': alias.asname if alias.asname else alias.name,
                'line': node.lineno,
                'type': 'import'
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """访问from...import语句"""
        module = node.module if node.module else ''
        for alias in node.names:
            self.imports.append({
                'module': f"{module}.{alias.name}",
                'alias': alias.asname if alias.asname else alias.name,
                'line': node.lineno,
                'type': 'from_import',
                'from_module': module
            })

    def visit_Expr(self, node: ast.Expr):
        """访问表达式语句 - 检测模块级副作用"""
        if hasattr(node.value, 'func'):
            # 这是一个函数调用 expr
            source = ast.get_source_segment(self.source_code, node) or ''
            self.module_level_code.append({
                'line': node.lineno,
                'type': 'function_call',
                'source': source.strip()
            })

    def get_function_id(self, func_name: str) -> str:
        """生成函数的唯一标识符"""
        return f"{Path(self.file_path).stem}:{func_name}"

    def get_full_function_id(self, class_name: Optional[str], func_name: str) -> str:
        """生成完整函数ID（包含类名）"""
        file_stem = Path(self.file_path).stem
        if class_name:
            return f"{file_stem}:{class_name}.{func_name}"
        return f"{file_stem}:{func_name}"


class FunctionCallExtractor(ast.NodeVisitor):
    """从函数体内提取函数调用"""

    def __init__(self, current_func: str, file_path: str, source_code: str):
        self.current_func = current_func
        self.file_path = file_path
        self.source_code = source_code
        self.calls = []

    def visit_Call(self, node: ast.Call):
        """访问函数调用"""
        call_info = {
            'line': node.lineno,
            'func_name': self._get_call_name(node),
            'is_method': isinstance(node.func, ast.Attribute),
            'args_count': len(node.args),
            'has_starargs': node.args or any(isinstance(arg, ast.Starred) for arg in node.args),
            'source': ast.get_source_segment(self.source_code, node) or ''
        }
        self.calls.append(call_info)
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        """获取调用的函数名"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{self._get_call_name_from_attribute(node.func)}"
        elif isinstance(node.func, ast.Subscript):
            return "subscript_call"
        elif isinstance(node.func, ast.Call):
            return "nested_call"
        return "unknown_call"

    def _get_call_name_from_attribute(self, node: ast.Attribute) -> str:
        """从属性链获取完整名称"""
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_call_name_from_attribute(node.value)}.{node.attr}"
        elif isinstance(node.value, ast.Call):
            return f"call().{node.attr}"
        return node.attr

    def get_calls(self) -> List[Dict]:
        """返回提取的调用列表"""
        return self.calls


class FunctionCallGraph:
    """项目级函数调用图"""

    def __init__(self):
        self.functions = {}      # {func_id: function_info}
        self.call_graph = nx.DiGraph()  # 函数调用图
        self.file_functions = defaultdict(set)  # {file: set of func_ids}

    def add_file(self, file_path: str, source_code: str) -> Dict:
        """添加文件到调用图"""
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return {}

        visitor = FunctionCallVisitor(file_path, source_code)
        visitor.visit(tree)

        # 添加函数到图
        for func_name, func_info in visitor.functions.items():
            func_id = visitor.get_function_id(func_name)
            func_info['file'] = file_path
            func_info['func_id'] = func_id
            self.functions[func_id] = func_info
            self.file_functions[file_path].add(func_id)
            self.call_graph.add_node(func_id, **func_info)

        # 添加类方法到图
        for class_name, class_info in visitor.class_defs.items():
            for method_name, method_info in class_info['methods'].items():
                func_id = visitor.get_full_function_id(class_name, method_name)
                method_info['file'] = file_path
                method_info['func_id'] = func_id
                method_info['class'] = class_name
                method_info['type'] = 'method'
                self.functions[func_id] = method_info
                self.file_functions[file_path].add(func_id)
                self.call_graph.add_node(func_id, **method_info)

        # 添加调用边
        for func_name, func_info in visitor.functions.items():
            caller_id = visitor.get_function_id(func_name)
            for call in func_info['calls']:
                callee_name = call['func_name']
                # 尝试匹配项目中的函数
                callee_id = self._resolve_function(callee_name, visitor)
                if callee_id and callee_id in self.functions:
                    self.call_graph.add_edge(caller_id, callee_id, **call)

        # 添加类方法调用边
        for class_name, class_info in visitor.class_defs.items():
            for method_name, method_info in class_info['methods'].items():
                caller_id = visitor.get_full_function_id(class_name, method_name)
                # 需要重新分析方法内的调用
                method_source = method_info.get('source', '')
                if method_source:
                    try:
                        method_tree = ast.parse(method_source)
                        call_extractor = FunctionCallExtractor(method_name, file_path, method_source)
                        call_extractor.visit(method_tree)
                        for call in call_extractor.get_calls():
                            callee_id = self._resolve_function(call['func_name'], visitor)
                            if callee_id and callee_id in self.functions:
                                self.call_graph.add_edge(caller_id, callee_id, **call)
                    except:
                        pass

        return {
            'functions': {k: v for k, v in visitor.functions.items()},
            'imports': visitor.imports,
            'module_level_code': visitor.module_level_code,
            'classes': visitor.class_defs
        }

    def _resolve_function(self, call_name: str, visitor: FunctionCallVisitor) -> Optional[str]:
        """解析调用名称到函数ID"""
        # 直接匹配
        if call_name in visitor.functions:
            return visitor.get_function_id(call_name)

        # 检查是否是类方法调用
        if '.' in call_name:
            parts = call_name.split('.')
            class_name = parts[0]
            method_name = parts[1] if len(parts) > 1 else None
            if class_name in visitor.class_defs and method_name:
                return visitor.get_full_function_id(class_name, method_name)

        return None

    def find_call_chain(self, start_func: str, max_depth: int = 10) -> List[str]:
        """查找从start_func开始的调用链"""
        if start_func not in self.call_graph:
            return []

        visited = set()
        chain = []
        queue = deque([(start_func, 0)])

        while queue:
            func, depth = queue.popleft()
            if func in visited or depth > max_depth:
                continue
            visited.add(func)
            chain.append(func)

            for successor in self.call_graph.successors(func):
                queue.append((successor, depth + 1))

        return chain

    def find_callers(self, func_name: str) -> Set[str]:
        """查找调用指定函数的所有函数"""
        return set(self.call_graph.predecessors(func_name))

    def find_reachable_dangerous_functions(self, dangerous_funcs: Set[str]) -> Set[str]:
        """找到可以到达危险函数的所有函数"""
        reachable = set()
        for danger_func in dangerous_funcs:
            if danger_func not in self.call_graph:
                continue
            # 找所有能到这个危险函数的节点
            ancestors = nx.ancestors(self.call_graph, danger_func)
            reachable.update(ancestors)
            reachable.add(danger_func)
        return reachable


class ModuleSideEffectDetector:
    """检测模块导入时的副作用"""

    DANGEROUS_PATTERNS = [
        (r'\b(exec|eval|compile)\s*\(', 'code_execution', 'critical'),
        (r'\bos\.system\s*\(', 'command_execution', 'critical'),
        (r'\bourlopen|urlopen|request\.|urllib\.|socket\.', 'network_call', 'high'),
        (r'\bpopen|subprocess\.', 'subprocess', 'critical'),
        (r'open\s*\(', 'file_op', 'medium'),
        (r'\bos\.environ|getenv|getattr\(os', 'env_access', 'medium'),
    ]

    def __init__(self):
        self.side_effects = {}  # {file: [side_effects]}

    def analyze_file(self, file_path: str, source_code: str) -> List[Dict]:
        """分析文件的模块级副作用"""
        effects = []

        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return effects

        visitor = SideEffectVisitor(file_path, source_code)
        visitor.visit(tree)

        for effect in visitor.side_effects:
            severity = self._classify_severity(effect)
            effects.append({
                **effect,
                'severity': severity,
                'file': file_path
            })

        self.side_effects[file_path] = effects
        return effects

    def _classify_severity(self, effect: Dict) -> str:
        """分类副作用严重程度"""
        source = effect.get('source', '')

        for pattern, category, severity in self.DANGEROUS_PATTERNS:
            if re.search(pattern, source):
                return severity

        # 默认分类
        effect_type = effect.get('type', '')
        if 'function_call' in effect_type:
            return 'medium'
        return 'low'

    def has_dangerous_side_effects(self, file_path: str) -> bool:
        """检查文件是否有危险副作用"""
        effects = self.side_effects.get(file_path, [])
        return any(e.get('severity') in ['critical', 'high'] for e in effects)


class SideEffectVisitor(ast.NodeVisitor):
    """AST访问器 - 检测模块级副作用"""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.side_effects = []
        self.in_function = False
        self.function_depth = 0

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.in_function = True
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1
        if self.function_depth == 0:
            self.in_function = False

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.in_function = True
        self.function_depth += 1
        self.generic_visit(node)
        self.function_depth -= 1
        if self.function_depth == 0:
            self.in_function = False

    def visit_Expr(self, node: ast.Expr):
        """模块级的表达式语句"""
        if not self.in_function:
            source = ast.get_source_segment(self.source_code, node) or ''
            self.side_effects.append({
                'line': node.lineno,
                'type': 'module_level_expr',
                'source': source.strip(),
                'is_function_call': isinstance(node.value, ast.Call)
            })
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        """import语句可能有副作用"""
        if not self.in_function:
            for alias in node.names:
                # 检查是否是已知有副作用的模块
                if alias.name in ['os', 'sys', 'subprocess', 'pickle', 'marshal']:
                    self.side_effects.append({
                        'line': node.lineno,
                        'type': 'dangerous_import',
                        'module': alias.name,
                        'source': ast.get_source_segment(self.source_code, node) or ''
                    })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """from...import语句"""
        if not self.in_function and node.module:
            if node.module in ['os', 'sys', 'subprocess', 'pickle', 'marshal']:
                for alias in node.names:
                    self.side_effects.append({
                        'line': node.lineno,
                        'type': 'dangerous_import',
                        'module': node.module,
                        'name': alias.name,
                        'source': ast.get_source_segment(self.source_code, node) or ''
                    })
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """模块级赋值可能有副作用"""
        if not self.in_function:
            # 检查是否有危险的函数调用在右侧
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if not var_name.startswith('_'):
                        # 检查右侧是否是函数调用
                        if isinstance(node.value, ast.Call):
                            source = ast.get_source_segment(self.source_code, node) or ''
                            self.side_effects.append({
                                'line': node.lineno,
                                'type': 'module_level_assignment_with_call',
                                'variable': var_name,
                                'source': source.strip()
                            })
        self.generic_visit(node)


class CrossFileCallTracker:
    """跨文件调用追踪器"""

    def __init__(self, call_graph: FunctionCallGraph):
        self.call_graph = call_graph
        self.cross_file_calls = defaultdict(list)  # {file: [(caller, callee, line), ...]}

    def analyze(self, files_info: Dict[str, Dict]) -> Dict:
        """分析跨文件调用关系"""
        cross_file_edges = []

        for caller_id, callee_id, data in self.call_graph.call_graph.edges(data=True):
            caller_file = self.call_graph.functions[caller_id]['file']
            callee_file = self.call_graph.functions.get(callee_id, {}).get('file', caller_file)

            if caller_file != callee_file:
                cross_file_edges.append({
                    'caller_file': caller_file,
                    'caller_func': caller_id,
                    'callee_file': callee_file,
                    'callee_func': callee_id,
                    'line': data.get('line', 0),
                    'source': data.get('source', '')
                })

        # 按文件组织
        for edge in cross_file_edges:
            self.cross_file_calls[edge['caller_file']].append(edge)

        return {
            'total_cross_file_calls': len(cross_file_edges),
            'cross_file_edges': cross_file_edges,
            'by_file': dict(self.cross_file_calls)
        }


class AttackChainExtractor:
    """攻击链提取器 - 整合所有分析结果"""

    def __init__(self, call_graph: FunctionCallGraph,
                 side_effect_detector: ModuleSideEffectDetector,
                 cross_file_tracker: CrossFileCallTracker):
        self.call_graph = call_graph
        self.side_effect_detector = side_effect_detector
        self.cross_file_tracker = cross_file_tracker

    def extract_attack_chains(self) -> List[Dict]:
        """提取完整的攻击链"""
        chains = []

        # 1. 找到所有危险函数
        dangerous_funcs = self._find_dangerous_functions()

        # 2. 对每个危险函数，追踪完整的调用链
        for danger_func in dangerous_funcs:
            chain = self._build_attack_chain(danger_func)
            if chain:
                chains.append(chain)

        # 3. 按严重程度排序
        chains.sort(key=lambda x: (
            x['primary_severity'] != 'critical',
            x['primary_severity'] != 'high',
            -len(x['nodes'])
        ))

        return chains

    def _find_dangerous_functions(self) -> Set[str]:
        """找到所有危险函数"""
        dangerous = set()

        # 从函数内容中查找
        for func_id, func_info in self.call_graph.functions.items():
            source = func_info.get('source', '')

            # 危险模式检测
            if any(pattern in source for pattern in ['exec(', 'eval(', 'compile(',
                                                      'os.system', 'subprocess.',
                                                      'pickle.loads', 'marshal.loads',
                                                      'urlopen', 'urllib.', 'request.']):
                dangerous.add(func_id)

            # 检查函数名
            func_name = func_id.split(':')[-1]
            if any(keyword in func_name.lower() for keyword in
                   ['verify', 'check', 'validate', 'install', 'setup',
                    'telemetry', 'analytics', 'report', 'collect']):
                if 'http' in source.lower() or 'urllib' in source.lower() or 'request' in source.lower():
                    dangerous.add(func_id)

        # 从模块副作用中查找
        for file_path, effects in self.side_effect_detector.side_effects.items():
            for effect in effects:
                if effect.get('severity') in ['critical', 'high']:
                    # 找到对应文件的所有函数
                    for func_id in self.call_graph.file_functions.get(file_path, set()):
                        dangerous.add(func_id)

        return dangerous

    def _build_attack_chain(self, danger_func: str) -> Optional[Dict]:
        """构建攻击链"""
        if danger_func not in self.call_graph.functions:
            return None

        func_info = self.call_graph.functions[danger_func]
        source = func_info.get('source', '')

        # 确定严重程度
        severity = self._classify_function_severity(source)

        # 追踪调用链（向前向后）
        nodes = set([danger_func])

        # 向前：谁调用了这个函数
        for caller in self.call_graph.find_callers(danger_func):
            nodes.add(caller)
            # 递归向前
            nodes.update(self.call_graph.find_callers(caller))

        # 向后：这个函数调用了谁
        for callee in self.call_graph.call_graph.successors(danger_func):
            nodes.add(callee)
            # 如果调用其他危险函数，也加入
            if self._is_dangerous_function(callee):
                nodes.update(self.call_graph.call_graph.successors(callee))

        # 获取相关文件的副作用
        related_files = set()
        for func_id in nodes:
            if func_id in self.call_graph.functions:
                related_files.add(self.call_graph.functions[func_id]['file'])

        side_effects = []
        for file_path in related_files:
            effects = self.side_effect_detector.side_effects.get(file_path, [])
            side_effects.extend(effects)

        return {
            'primary_func': danger_func,
            'primary_severity': severity,
            'primary_file': func_info['file'],
            'primary_line': func_info['line'],
            'primary_source': source[:100],
            'nodes': list(nodes),
            'node_count': len(nodes),
            'side_effects': side_effects,
            'cross_file_calls': self._get_cross_file_calls(nodes)
        }

    def _classify_function_severity(self, source: str) -> str:
        """分类函数严重程度"""
        source_lower = source.lower()

        if any(p in source_lower for p in ['exec(', 'eval(', 'compile(',
                                              'os.system', 'subprocess.',
                                              'pickle.loads', 'marshal.loads']):
            return 'critical'
        elif any(p in source_lower for p in ['urllib.', 'request.', 'socket.',
                                                 'base64.', 'environ', 'getenv']):
            return 'high'
        elif any(p in source_lower for p in ['open(', 'read(', 'write(']):
            return 'medium'
        return 'low'

    def _is_dangerous_function(self, func_id: str) -> bool:
        """判断函数是否危险"""
        if func_id not in self.call_graph.functions:
            return False
        source = self.call_graph.functions[func_id].get('source', '')
        severity = self._classify_function_severity(source)
        return severity in ['critical', 'high']

    def _get_cross_file_calls(self, nodes: Set[str]) -> List[Dict]:
        """获取节点相关的跨文件调用"""
        cross_calls = []

        for node_id in nodes:
            if node_id not in self.call_graph.functions:
                continue

            caller_file = self.call_graph.functions[node_id]['file']

            for callee_id in self.call_graph.call_graph.successors(node_id):
                if callee_id in self.call_graph.functions:
                    callee_file = self.call_graph.functions[callee_id]['file']
                    if caller_file != callee_file:
                        cross_calls.append({
                            'from': node_id,
                            'to': callee_id,
                            'from_file': caller_file,
                            'to_file': callee_file
                        })

        return cross_calls
