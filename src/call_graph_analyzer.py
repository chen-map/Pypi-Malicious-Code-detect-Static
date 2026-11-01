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


class FastSourceSegmenter:
    """O(1) 源码片段提取，替代 ast.get_source_segment

    ast.get_source_segment 每次调用都是 O(len(source))。在大型单文件 SDK
    (如 alibabacloud_ecs 的 models.py 4MB) 上，几千个函数/调用节点各扫一遍
    全文，会让调用图构建退化到小时级。这里预计算行偏移，单次提取 O(切片长度)。
    同时把片段截断到 max_chars，避免把整段代码塞进图节点。
    """

    def __init__(self, source: str, max_chars: int = 500):
        self.source = source
        self.max_chars = max_chars
        self._lines = source.splitlines(keepends=True)
        self._offsets = [0]
        for line in self._lines:
            self._offsets.append(self._offsets[-1] + len(line))

    def segment(self, node) -> str:
        try:
            lineno = getattr(node, 'lineno', None)
            if not lineno or lineno < 1 or lineno > len(self._lines):
                return ''
            col = getattr(node, 'col_offset', 0) or 0
            start = self._offsets[lineno - 1] + col
            end_lineno = getattr(node, 'end_lineno', None) or lineno
            end_col = getattr(node, 'end_col_offset', None)
            if end_col is None or end_lineno < 1 or end_lineno > len(self._lines):
                end = self._offsets[min(lineno, len(self._lines))]
            else:
                end = self._offsets[end_lineno - 1] + end_col
            if start < 0 or start >= len(self.source) or end <= start:
                return ''
            return self.source[start:min(end, start + self.max_chars)]
        except Exception:
            return ''


class FunctionCallVisitor(ast.NodeVisitor):
    """AST访问器 - 提取函数定义和调用"""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.segmenter = FastSourceSegmenter(source_code)
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
            'source': self.segmenter.segment(node)
        }

        # 提取函数体内的调用
        call_extractor = FunctionCallExtractor(func_name, self.file_path, self.source_code,
                                               self.segmenter)
        call_extractor.visit(node)
        func_info['calls'] = call_extractor.get_calls()

        self.functions[func_name] = func_info
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """访问异步函数定义

        直接把原节点传给 visit_FunctionDef：原节点自带 lineno/end_lineno
        等位置属性。原先手工构造 ast.FunctionDef 不带位置信息，会导致
        visit_FunctionDef 里取 node.lineno 抛 AttributeError，含 async
        函数的文件整体退出调用图分析（静默漏报）。
        """
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        """访问类定义"""
        class_name = node.name
        methods = {}

        # 提取类方法
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_name = item.name
                # 直接遍历原始AST提取调用：source 现已截断，不能再依赖
                # 重新 ast.parse(source)（长方法会解析失败、静默丢边）
                method_extractor = FunctionCallExtractor(
                    method_name, self.file_path, self.source_code, self.segmenter)
                method_extractor.visit(item)
                methods[method_name] = {
                    'line': item.lineno,
                    'end_line': item.end_lineno if hasattr(item, 'end_lineno') else item.lineno,
                    'args': [arg.arg for arg in item.args.args],
                    'is_async': isinstance(item, ast.AsyncFunctionDef),
                    'calls': method_extractor.get_calls(),
                    'source': self.segmenter.segment(item)
                }

        self.class_defs[class_name] = {
            'line': node.lineno,
            'end_line': node.end_lineno if hasattr(node, 'end_lineno') else node.lineno,
            'bases': [ast.unparse(base) if hasattr(ast, 'unparse') else str(base) for base in node.bases],
            'methods': methods,
            'decorators': [ast.unparse(d) if hasattr(ast, 'unparse') else str(d) for d in node.decorator_list],
            'source': self.segmenter.segment(node)
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
            source = self.segmenter.segment(node)
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

    def __init__(self, current_func: str, file_path: str, source_code: str,
                 segmenter: Optional['FastSourceSegmenter'] = None):
        self.current_func = current_func
        self.file_path = file_path
        self.source_code = source_code
        # 复用调用方的 segmenter：每个函数新建一个会让预处理变成 O(函数数×文件大小)
        self.segmenter = segmenter or FastSourceSegmenter(source_code)
        self.calls = []

    def visit_Call(self, node: ast.Call):
        """访问函数调用"""
        call_info = {
            'line': node.lineno,
            'func_name': self._get_call_name(node),
            'is_method': isinstance(node.func, ast.Attribute),
            'args_count': len(node.args),
            'has_starargs': any(isinstance(arg, ast.Starred) for arg in node.args),
            'source': self.segmenter.segment(node)
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
        # 2026-10 CG 激活：跨文件解析所需的状态
        self.file_imports = {}   # {file: [{'module','alias','type',...}]}
        self.unresolved_calls = []  # [{'caller_id','callee_name','call','current_class','file'}]

    def add_file(self, file_path: str, source_code: str) -> Dict:
        """添加文件到调用图"""
        try:
            tree = ast.parse(source_code, filename=file_path)
        except SyntaxError:
            return {}

        visitor = FunctionCallVisitor(file_path, source_code)
        visitor.visit(tree)
        self.file_imports[file_path] = visitor.imports

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
                else:
                    # 2026-10 CG 激活：记录未解析调用，待 build 完成后做跨文件解析
                    self.unresolved_calls.append({
                        'caller_id': caller_id,
                        'callee_name': callee_name,
                        'call': call,
                        'current_class': None,
                        'file': file_path,
                    })

        # 添加类方法调用边
        for class_name, class_info in visitor.class_defs.items():
            for method_name, method_info in class_info['methods'].items():
                caller_id = visitor.get_full_function_id(class_name, method_name)
                # 优先使用 visit_ClassDef 在原始AST上提取的调用（source 已截断，
                # 重新解析会失败）；仅在缺失时回退到旧的重解析路径
                method_calls = method_info.get('calls')
                if method_calls is None:
                    method_source = method_info.get('source', '')
                    method_calls = []
                    if method_source:
                        try:
                            method_tree = ast.parse(method_source)
                            call_extractor = FunctionCallExtractor(
                                method_name, file_path, method_source)
                            call_extractor.visit(method_tree)
                            method_calls = call_extractor.get_calls()
                        except Exception:
                            method_calls = []

                for call in method_calls:
                    callee_id = self._resolve_function(call['func_name'], visitor,
                                                       current_class=class_name)
                    if callee_id and callee_id in self.functions:
                        self.call_graph.add_edge(caller_id, callee_id, **call)
                    else:
                        self.unresolved_calls.append({
                            'caller_id': caller_id,
                            'callee_name': call['func_name'],
                            'call': call,
                            'current_class': class_name,
                            'file': file_path,
                        })

        return {
            'functions': {k: v for k, v in visitor.functions.items()},
            'imports': visitor.imports,
            'module_level_code': visitor.module_level_code,
            'classes': visitor.class_defs
        }

    def _resolve_function(self, call_name: str, visitor: FunctionCallVisitor,
                          current_class: Optional[str] = None) -> Optional[str]:
        """解析调用名称到函数ID

        2026-10 CG 激活：支持 self.method() 在类上下文内解析——原先
        parts[0]='self' 永远不命中 class_defs，类内方法互调全部断链。
        跨文件解析在 resolve_cross_file 后处理中完成（需要项目级符号表）。
        """
        # 直接匹配
        if call_name in visitor.functions:
            return visitor.get_function_id(call_name)

        if '.' in call_name:
            parts = call_name.split('.')
            class_name = parts[0]
            method_name = parts[1] if len(parts) > 1 else None
            if class_name in visitor.class_defs and method_name:
                return visitor.get_full_function_id(class_name, method_name)
            # self.method()：解析到所属类的方法
            if class_name == 'self' and current_class and method_name:
                if current_class in visitor.class_defs \
                        and method_name in visitor.class_defs[current_class]['methods']:
                    return visitor.get_full_function_id(current_class, method_name)

        return None

    def resolve_cross_file(self, symbol_table, module_to_file: Dict[str, str],
                           max_fuzzy: int = 1) -> int:
        """跨文件调用后解析（2026-10 CG 激活）

        对 add_file 阶段未解析的调用：
        1. 点名调用 `alias.func()`：alias 是本文件 import 的模块 → 通过
           module→file 映射定位目标文件 → 查项目符号表；
        2. 裸名调用 `func()`：符号表全项目 short_name 精确匹配，仅当唯一
           命中时连边（多义性跳过，避免误连）。

        Args:
            symbol_table: ProjectSymbolTable（ddg_builder 步骤[2]产物）
            module_to_file: {'helper': '/abs/path/helper.py', ...}
            max_fuzzy: 裸名解析允许的候选上限（超过视为歧义）

        Returns:
            新增的跨文件边数
        """
        added = 0
        # 项目内所有函数的 short_name 索引（裸名解析用）
        by_short = {}
        for (file, full_name), info in (symbol_table.functions or {}).items():
            by_short.setdefault(info.get('short_name') or full_name.split('.')[-1], []).append(info)

        for u in self.unresolved_calls:
            callee_name = u['callee_name']
            caller_file = u['file']
            target_file = None
            target_full = None

            if '.' in callee_name:
                # alias.func() 或 self.method()（self 已在文件内处理过）
                base, rest = callee_name.split('.', 1)
                alias_map = {imp.get('alias') or imp.get('module', '').split('.')[0]:
                             imp.get('module', '') for imp in self.file_imports.get(caller_file, [])}
                module = alias_map.get(base)
                if module:
                    mod_file = module_to_file.get(module) or module_to_file.get(
                        module.rsplit('.', 1)[-1])
                    if mod_file:
                        target_file = mod_file
                        # rest 可能是 func 或 Class.func —— 符号表 full_name 直接查
                        target_full = rest.split('.')[-1] if rest.count('.') > 1 else rest
                        # 先试 Class.func 形式，再试短名
                        for cand in (rest, rest.split('.')[-1]):
                            if (mod_file, cand) in (symbol_table.functions or {}):
                                target_full = cand
                                break
            else:
                # 裸名：全项目唯一 short_name 才连
                cands = [i for i in by_short.get(callee_name, [])
                         if i.get('file') != caller_file]
                if len(cands) == max_fuzzy:
                    target_file = cands[0]['file']
                    target_full = cands[0]['name']

            if not target_file or not target_full:
                continue
            key = (target_file, target_full)
            info = (symbol_table.functions or {}).get(key)
            if not info:
                # 类方法：试 Class.method
                for (f, full), inf in (symbol_table.functions or {}).items():
                    if f == target_file and full.endswith('.' + target_full):
                        info = inf
                        target_full = full
                        break
            if not info or info.get('file') == caller_file:
                continue

            callee_id = f"{Path(target_file).stem}:{target_full}"
            if callee_id in self.functions:
                self.call_graph.add_edge(u['caller_id'], callee_id, **u['call'])
                added += 1
        return added

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
        self.segmenter = FastSourceSegmenter(source_code)
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
            source = self.segmenter.segment(node)
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
                        'source': self.segmenter.segment(node)
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
                        'source': self.segmenter.segment(node)
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
                            source = self.segmenter.segment(node)
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

        # 向前：谁调用了这个函数（2026-10 CG 激活：深度 2 → 5，
        # 反向 BFS 带节点上限防止大图爆炸；原先只追两层且完整闭包
        # find_reachable_dangerous_functions 从未被调用）
        frontier = [danger_func]
        visited_fwd = {danger_func}
        for _depth in range(5):
            next_frontier = []
            for node in frontier:
                for caller in self.call_graph.find_callers(node):
                    if caller not in visited_fwd:
                        visited_fwd.add(caller)
                        nodes.add(caller)
                        next_frontier.append(caller)
                        if len(nodes) > 60:
                            break
                if len(nodes) > 60:
                    break
            if len(nodes) > 60:
                break
            frontier = next_frontier
            if not frontier:
                break

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
