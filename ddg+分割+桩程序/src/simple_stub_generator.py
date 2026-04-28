"""
简单的桩程序生成器 - 基于DDG数据生成可执行的测试脚本

功能：
1. 读取子图的 nodes.json 和 edges.json
2. 分析数据流路径
3. 合成测试输入数据
4. 生成可执行的Python测试脚本

设计原则：
- 不依赖外部模块，直接使用DDG数据
- 测试脚本放在原包目录下，利用原包的import
- 优先使用AST信息，只在必要时使用LLM
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


class DataFlowAnalyzer:
    """数据流分析器 - 从DDG中提取关键信息"""

    def __init__(self, nodes: List[Dict], edges: List[Dict]):
        self.nodes = nodes
        self.edges = edges
        self.node_map = {node['node_id']: node for node in nodes}

    def analyze(self) -> Dict:
        """
        分析DDG，提取生成桩程序所需的信息

        Returns:
            {
                'nodes': List[Dict],                # ✅ 新增：所有节点
                'edges': List[Dict],                # ✅ 新增：所有边
                'dangerous_nodes': List[Dict],      # 危险节点
                'entry_points': List[Dict],         # 入口点（外部输入）
                'data_flow_paths': List[List],      # 数据流路径
                'required_imports': Set[str],       # 需要的import
                'functions': Dict[str, Dict],       # 函数信息
                'variables': Dict[str, List]        # 变量定义点
            }
        """
        analysis = {
            'nodes': self.nodes,        # ✅ 添加所有节点
            'edges': self.edges,        # ✅ 添加所有边
            'dangerous_nodes': [],
            'entry_points': [],
            'data_flow_paths': [],
            'required_imports': set(),
            'functions': {},
            'variables': defaultdict(list)
        }

        # 1. 分类节点
        for node in self.nodes:
            node_id = node['node_id']
            code = node.get('code', '') or ''  # 确保code不是None
            node_type = node.get('type', 'unknown') or 'unknown'

            # 危险节点
            severity = node.get('severity')
            if node.get('is_dangerous') or (isinstance(severity, str) and severity in ['critical', 'high', 'medium']):
                analysis['dangerous_nodes'].append(node)

            # 入口点（import语句、参数等）
            if node_type == 'import' or code.startswith('import ') or code.startswith('from '):
                analysis['required_imports'].add(code)
                analysis['entry_points'].append(node)

            # 函数定义（使用列表保存同名函数）
            if node_type == 'function' and 'def ' in code:
                func_name = self._extract_function_name(code)
                if func_name:
                    # 改为列表结构，支持同名函数
                    if func_name not in analysis['functions']:
                        analysis['functions'][func_name] = []
                    analysis['functions'][func_name].append({
                        'node': node,
                        'file': node.get('file', ''),
                        'line': node.get('line', 0)
                    })

            # 变量定义
            if node_type in ['assignment', 'statement']:
                var_name = self._extract_variable_name(code)
                if var_name:
                    analysis['variables'][var_name].append(node)

        # 2. 构建数据流路径
        analysis['data_flow_paths'] = self._build_data_flow_paths(analysis)

        return analysis

    def _extract_function_name(self, code: str) -> Optional[str]:
        """从函数定义中提取函数名"""
        match = re.search(r'def\s+(\w+)\s*\(', code)
        return match.group(1) if match else None

    def _extract_variable_name(self, code: str) -> Optional[str]:
        """从赋值语句中提取变量名"""
        match = re.match(r'(\w+)\s*=', code.strip())
        return match.group(1) if match else None

    def _build_data_flow_paths(self, analysis: Dict) -> List[List]:
        """
        构建数据流路径（从入口到危险节点）

        使用简化的BFS算法
        """
        paths = []

        if not analysis['dangerous_nodes']:
            return paths

        # 获取所有危险节点的ID
        danger_ids = {node['node_id'] for node in analysis['dangerous_nodes']}

        # 构建邻接表
        graph = defaultdict(list)
        reverse_graph = defaultdict(list)

        for edge in self.edges:
            from_node = edge.get('from_node', '')
            to_node = edge.get('to_node', '')

            if from_node and to_node:
                graph[from_node].append(to_node)
                reverse_graph[to_node].append(from_node)

        # 对每个危险节点，反向追踪到入口点
        for danger_node in analysis['dangerous_nodes']:
            danger_id = danger_node['node_id']

            # BFS反向追踪
            path = self._backward_bfs(danger_id, reverse_graph, analysis['entry_points'])

            if path:
                paths.append(path)

        return paths

    def _backward_bfs(self, start_node: str, reverse_graph: Dict, entry_points: List[Dict]) -> List:
        """反向BFS，从危险节点追踪到入口点"""
        visited = set()
        queue = [(start_node, [])]  # (node_id, path)
        entry_ids = {ep['node_id'] for ep in entry_points}

        while queue:
            node_id, path = queue.pop(0)

            if node_id in visited:
                continue
            visited.add(node_id)

            current_path = path + [node_id]

            # 找到入口点
            if node_id in entry_ids:
                return list(reversed(current_path))

            # 继续反向追踪
            for pred in reverse_graph.get(node_id, []):
                if pred not in visited:
                    queue.append((pred, current_path))

        # 没找到入口点，返回路径到当前节点
        return list(reversed(path))


class TestDataSynthesizer:
    """测试数据合成器 - 为变量生成合适的测试输入"""

    # Python关键字和内置函数，不能作为变量名
    RESERVED_NAMES = {
        # Python关键字
        'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await',
        'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
        'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is',
        'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
        'try', 'while', 'with', 'yield',
        # Python内置函数
        'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'breakpoint', 'bytearray',
        'bytes', 'callable', 'chr', 'classmethod', 'compile', 'complex',
        'delattr', 'dict', 'dir', 'divmod', 'enumerate', 'eval', 'exec', 'filter',
        'float', 'format', 'frozenset', 'getattr', 'globals', 'hasattr', 'hash',
        'help', 'hex', 'id', 'input', 'int', 'isinstance', 'issubclass', 'iter',
        'len', 'list', 'locals', 'map', 'max', 'memoryview', 'min', 'next',
        'object', 'oct', 'open', 'ord', 'pow', 'print', 'property', 'range',
        'repr', 'reversed', 'round', 'set', 'setattr', 'slice', 'sorted',
        'staticmethod', 'str', 'sum', 'super', 'tuple', 'type', 'vars', 'zip',
        '__import__',
        # 常用模块名和常量
        'os', 'sys', 'json', 'pathlib', 'subprocess', 'pickle', 'marshal',
        'TEMP', 'USER', 'USERNAME', 'HOME', 'PATH', 'PWD'
    }

    # 危险函数的默认攻击payload
    ATTACK_PAYLOADS = {
        'eval': '"__import__(\'os\').system(\'echo VULNERABLE\')"',
        'exec': '"__import__(\'os\').system(\'echo VULNERABLE\')"',
        'compile': '"__import__(\'os\').system(\'echo VULNERABLE\')"',
        '__import__': '"os"',
        'pickle.loads': 'b"..."',  # 简化的pickle payload
        'marshal.loads': 'b"..."',
        'os.system': '"echo VULNERABLE"',
        'subprocess.run': '["echo", "VULNERABLE"]',
        'subprocess.call': '["echo", "VULNERABLE"]',
        'subprocess.Popen': '["echo", "VULNERABLE"]',
        'open': '"/tmp/test_file.txt"',
        'urllib.request.urlopen': '"http://example.com"',
        'requests.get': '"http://example.com"',
        'requests.post': '"http://example.com"',
    }

    # 良性操作的默认测试数据
    BENIGN_DATA = {
        'str': '"test_string"',
        'int': '42',
        'float': '3.14',
        'dict': '{"key": "value"}',
        'list': '[1, 2, 3]',
        'tuple': '(1, 2, 3)',
        'bytes': 'b"test_bytes"',
        'path': '"test_downloaded.png"',  # 使用相对路径
        'url': '"https://maas-log-prod.cn-wlcb.ufileos.com/anthropic/28592420-920f-4e83-8c7f-1aba9e3431e0/832317c294971a799b9602a79d9d56bb.png?UCloudPublicKey=TOKEN_e15ba47a-d098-4fbd-9afc-a0dcf0e4e621&Expires=1777365098&Signature=TXbzVc6BVqgh4am72/JOcOYZNAU="',
    }

    def synthesize(self, analysis: Dict, source_code: str = None) -> Dict[str, str]:
        """
        为数据流中的变量合成测试输入

        Args:
            analysis: DataFlowAnalyzer的输出
            source_code: 完整的原始源代码（用于提取所有字符串赋值）

        Returns:
            {var_name: test_value} 的字典
        """
        test_inputs = {}

        # 🔥 策略0：从原始代码中提取所有字符串赋值（不管变量名叫什么！）
        if source_code:
            print(f"  [Extract] Searching for all string assignments...")
            import re

            # 匹配所有字符串赋值：variable = "string" 或 variable = 'string'
            # 只匹配长度>=10的字符串（避免提取短文本）
            pattern = r'(\w+)\s*=\s*["\']([^"\']{10,})["\']'
            matches = re.findall(pattern, source_code)

            for var_name, string_value in matches:
                # 过滤掉明显是普通文本的（包含空格、中文等）
                if ' ' in string_value or any('\u4e00' <= c <= '\u9fff' for c in string_value):
                    continue

                # 保留所有可疑的长字符串（包括加密的URL）
                if var_name not in test_inputs:
                    test_inputs[var_name] = f'"{string_value}"'
                    print(f"  [Extract] [OK] Preserved: {var_name} = {string_value[:50]}...")

        # 策略1：根据危险节点类型推断输入
        for node in analysis['dangerous_nodes']:
            code = node.get('code', '')

            # 检测是否包含危险函数调用（使用词边界匹配，避免误匹配）
            for func_name, payload in self.ATTACK_PAYLOADS.items():
                # 使用词边界匹配，避免把 "evaluate" 误判为 "eval"
                pattern = r'\b' + re.escape(func_name) + r'\b'
                if re.search(pattern, code):
                    # 提取参数名
                    params = self._extract_call_params(code)
                    for param in params:
                        if param not in test_inputs:
                            # 避免使用保留名作为变量名
                            safe_var_name = self._get_safe_var_name(param)
                            test_inputs[safe_var_name] = payload
                            print(f"  [Synthesis] For dangerous function '{func_name}', input: {safe_var_name} = {payload}")
                            break  # 只处理第一个匹配

        # 策略2：根据数据流路径推断变量类型
        # 注意：analysis['variables']是 {var_name: [node_list]}，不是 {node_id: node}
        variables = analysis.get('variables', {})
        if variables:
            for var_name, node_list in variables.items():
                if node_list and var_name not in test_inputs:
                    safe_var_name = self._get_safe_var_name(var_name)
                    test_inputs[safe_var_name] = self.BENIGN_DATA.get('str', '"default_value"')
                    print(f"  [Synthesis] From variable '{safe_var_name}': str")

        # ❌ 已删除策略3：不再根据变量名推断类型
        # 原因：变量名可能不规范，会导致漏检恶意URL/路径
        # 例如：malware_server = "http://evil.com" (变量名不含'url')
        # 解决：策略0已从源代码提取所有字符串赋值，不需要推断

        return test_inputs

    def _get_safe_var_name(self, var_name: str) -> str:
        """获取安全的变量名（避免冲突）"""
        if var_name in self.RESERVED_NAMES:
            return f"test_{var_name}"  # 添加test_前缀
        return var_name

    def _extract_call_params(self, code: str) -> List[str]:
        """从函数调用中提取参数名"""
        params = []

        # 匹配函数调用模式
        match = re.search(r'(\w+)\s*\(([^)]*)\)', code)
        if match:
            func_name = match.group(1)
            args_str = match.group(2)

            # 提取参数（简化版，只处理变量名）
            for arg in args_str.split(','):
                arg = arg.strip()
                if arg.isidentifier() and not arg in ['True', 'False', 'None']:
                    params.append(arg)

        return params

    def _extract_variables_from_code(self, code: str) -> Set[str]:
        """从代码中提取所有变量名（排除赋值目标和函数调用）"""
        variables = set()
        assigned_vars = set()
        function_calls = set()

        # 步骤1: 提取所有赋值左侧的变量（这些是中间变量，不需要预先定义）
        for match in re.finditer(r'([a-zA-Z_]\w*)\s*=', code):
            assigned_vars.add(match.group(1))

        # 步骤2: 提取函数调用（这些是函数名，不需要预先定义）
        # 匹配模式: function_name(...) 或 function_name(
        for match in re.finditer(r'([a-zA-Z_]\w*)\s*\(', code):
            function_calls.add(match.group(1))

        # 步骤3: 提取所有标识符
        for match in re.finditer(r'\b([a-zA-Z_]\w*)\b', code):
            var_name = match.group(1)

            # 过滤关键字和内置函数
            if var_name in ['def', 'class', 'import', 'from', 'return', 'if', 'else', 'for', 'while', 'print', 'len', 'range', 'str', 'int', 'list', 'dict']:
                continue

            # 过滤赋值目标（中间变量）
            if var_name in assigned_vars:
                continue

            # 过滤函数调用（函数名不需要预先定义）
            if var_name in function_calls:
                continue

            variables.add(var_name)

        return variables

    def _infer_variable_type(self, node) -> Optional[str]:
        """从节点推断变量类型"""
        if not isinstance(node, list) or not node:
            return None

        node = node[0]  # 取第一个定义点
        code = node.get('code', '')

        # 根据赋值右侧推断类型
        if '=' in code:
            rhs = code.split('=')[1].strip()

            if rhs.startswith('"') or rhs.startswith("'"):
                return 'str'
            elif rhs.isdigit():
                return 'int'
            elif rhs.startswith('{'):
                return 'dict'
            elif rhs.startswith('['):
                return 'list'

        return None


# ❌ 已删除 _infer_type_from_name() 方法
# 原因：该方法根据变量名包含'url'/'path'等关键词推断类型，会导致漏检
# 例如：malware_server = "http://evil.com" (变量名不含'url') 会被推断为'str'而非'url'
# 解决：策略0已从源代码提取所有字符串赋值，不需要基于变量名的推断


class SimpleStubGenerator:
    """
    简单的桩程序生成器

    基于DDG数据生成可执行的测试脚本
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def generate_stub(self, subgraph_dir: str, original_package_dir: str) -> str:
        """
        为单个子图生成可执行的测试脚本

        Args:
            subgraph_dir: 子图目录（包含nodes.json和edges.json）
            original_package_dir: 原恶意包的根目录

        Returns:
            生成的测试脚本路径
        """
        subgraph_path = Path(subgraph_dir)

        # 步骤1：读取DDG数据
        nodes_file = subgraph_path / 'nodes.json'
        edges_file = subgraph_path / 'edges.json'

        if not nodes_file.exists() or not edges_file.exists():
            raise FileNotFoundError(f"DDG数据不完整: {subgraph_dir}")

        if self.verbose:
            print(f"\n[*] Reading DDG data from: {subgraph_dir}")

        # 步骤1：读取DDG数据（带异常处理）
        try:
            with open(nodes_file, 'r', encoding='utf-8') as f:
                nodes = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse nodes.json: {e}")

        try:
            with open(edges_file, 'r', encoding='utf-8') as f:
                edges = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse edges.json: {e}")

        if self.verbose:
            print(f"    Loaded {len(nodes)} nodes, {len(edges)} edges")

        # 步骤2：分析数据流
        analyzer = DataFlowAnalyzer(nodes, edges)
        analysis = analyzer.analyze()

        if self.verbose:
            print(f"    Analysis: {len(analysis['dangerous_nodes'])} dangerous nodes, "
                  f"{len(analysis['data_flow_paths'])} data flow paths")

        # 🔥 步骤2.5：收集所有源代码文件内容（用于提取字符串赋值）
        source_files_content = {}
        package_dir = Path(original_package_dir)

        # 收集所有涉及的源文件
        for node in nodes:
            file_path = node.get('file', '')
            if file_path and file_path not in source_files_content:
                # 只取文件名，不取完整路径
                filename = Path(file_path).name
                full_path = package_dir / filename
                if full_path.exists():
                    try:
                        with open(full_path, 'r', encoding='utf-8') as f:
                            source_files_content[file_path] = f.read()
                        if self.verbose:
                            print(f"    [Source] Loaded: {filename} ({len(source_files_content[file_path])} chars)")
                    except Exception as e:
                        print(f"    [Warning] Failed to read {filename}: {e}")

        # 合并所有源代码为一个字符串（便于提取）
        combined_source_code = '\n'.join(source_files_content.values())

        # 步骤3：合成测试输入（传入源代码）
        synthesizer = TestDataSynthesizer()
        test_inputs = synthesizer.synthesize(analysis, combined_source_code)

        if self.verbose:
            print(f"    Synthesized {len(test_inputs)} test inputs")

        # 步骤4：生成测试脚本
        # 计算从子图目录到原包目录的相对路径
        original_path = Path(original_package_dir).resolve()
        subgraph_path_resolved = subgraph_path.resolve()

        try:
            relative_path = os.path.relpath(original_path, subgraph_path_resolved)
        except ValueError:
            # 在Windows上跨驱动器时无法计算相对路径，使用绝对路径
            relative_path = str(original_path)

        test_script = self._generate_test_script(
            analysis, test_inputs, subgraph_path, relative_path
        )

        # 步骤5：保存到子图目录
        test_file = subgraph_path / 'test_ddg_results.py'

        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_script)

        if self.verbose:
            print(f"[OK] Generated test script: {test_file}")

        return str(test_file)

    def _generate_test_script(self, analysis: Dict, test_inputs: Dict,
                              subgraph_path: Path, original_package_dir: str) -> str:
        """生成可执行的测试脚本"""
        # 提取元数据
        subgraph_name = subgraph_path.name
        danger_count = len(analysis['dangerous_nodes'])
        path_count = len(analysis['data_flow_paths'])

        # 生成各个部分
        import_section = self._generate_imports(analysis, original_package_dir)
        # 提取导入列表，用于过滤测试数据
        imported_modules = set(analysis.get('required_imports', []))
        # 生成测试数据（同时过滤掉已导入的模块）
        data_section, filtered_inputs = self._generate_test_data(test_inputs, imported_modules)
        test_logic = self._generate_test_logic(analysis, filtered_inputs)

        return f'''#!/usr/bin/env python3
"""
自动生成的桩程序

子图ID: {subgraph_name}
危险节点数: {danger_count}
数据流路径数: {path_count}
严重程度: {self._get_severity(analysis)}

生成时间: {self._get_timestamp()}
"""

import sys
import traceback
from pathlib import Path

# ========================================
# 1. 环境设置：把原包当作库
# ========================================
try:
    # 直接使用原包目录（由生成器传入）
    package_dir = Path(r"{original_package_dir}")

    if package_dir.exists():
        # 添加原包目录到路径
        sys.path.insert(0, str(package_dir))
        print(f"[INFO] Added to path: {{package_dir}}")

        # 同时添加子目录到路径（支持download/download.py这种结构）
        for subdir in package_dir.iterdir():
            if subdir.is_dir():
                # 检查是否是Python包（有__init__.py或包含.py文件）
                has_init = (subdir / '__init__.py').exists()
                has_py_files = list(subdir.glob('*.py'))

                if has_init or has_py_files:
                    sys.path.insert(0, str(subdir))
                    print(f"[INFO] Added submodule to path: {{subdir.name}}")
    else:
        print(f"[WARNING] Package directory not found: {{package_dir}}")
except Exception as e:
    print(f"[ERROR] Failed to setup path: {{e}}")

# ========================================
# 2. 导入原包的模块
# ========================================
{import_section}

# ========================================
# 3. 测试数据（模块级别定义）
# ========================================
{data_section}

# ========================================
# 4. 测试函数
# ========================================
def test_{subgraph_name.replace('-', '_').replace('.', '_')}():
    """测试子图: {subgraph_name}"""
    print(f"\\n[TEST] Starting test for subgraph: {subgraph_name}")
    print(f"[INFO] Dangerous nodes: {danger_count}")
    print(f"[INFO] Test inputs: {len(test_inputs)}")

    try:
        # 调用原包的函数（数据流追踪到的路径）
{test_logic}

        # 如果执行到这里，说明危险操作被允许执行
        print(f"[INFO] Test completed without exceptions")
        print(f"[RESULT] Test completed successfully")
        return "completed"

    except Exception as e:
        # 捕获异常（可能是动态分析工具拦截的）
        print(f"[INFO] Exception during execution: {{e}}")
        traceback.print_exc()  # 总是打印traceback，用于调试
        print(f"[RESULT] Exception: {{type(e).__name__}}")
        return f"exception: {{type(e).__name__}}"

# ========================================
# 5. 主入口
# ========================================
if __name__ == '__main__':
    print("=" * 70)
    print("  桩程序执行器")
    print("=" * 70)

    result = test_{subgraph_name.replace('-', '_').replace('.', '_')}()

    print("\\n" + "=" * 70)
    print(f"[FINAL RESULT] {{result}}")
    print("=" * 70)

    # 返回码：0=成功（检测到异常），1=失败（未检测到危险操作）
    sys.exit(0 if result != "completed" else 1)
'''

    def _generate_imports(self, analysis: Dict, original_package_dir: str) -> str:
        """生成import语句（模块级别，无缩进）"""
        imports = []

        # 从DDG中提取的import
        for imp in sorted(analysis['required_imports']):
            imports.append(f"{imp}")

        # 如果没有import，至少导入基础模块
        if not imports:
            imports.append("import os")
            imports.append("import sys")

        return '\n'.join(imports)

    def _generate_test_data(self, test_inputs: Dict[str, str], imported_modules: Set[str] = None) -> Tuple[str, Dict[str, str]]:
        """生成测试数据定义（模块级别，无缩进）

        Returns:
            (数据代码字符串, 过滤后的测试输入字典)
        """
        if not test_inputs:
            return "# 无测试输入", {}

        # 提取所有导入的模块名（包括多级导入如 urllib.request）
        imported_names = set()
        if imported_modules:
            for imp in imported_modules:
                # 提取 'import xxx' 或 'from xxx import' 中的模块名
                if imp.startswith('import '):
                    modules = imp[7:].split(',')
                    for mod in modules:
                        # 获取模块的第一级名称（如 'urllib.request' -> 'urllib'）
                        base_name = mod.strip().split('.')[0]
                        imported_names.add(base_name)
                elif imp.startswith('from '):
                    # 'from xxx import' - xxx也是模块名
                    parts = imp[5:].split()
                    if parts:
                        base_name = parts[0].split('.')[0]
                        imported_names.add(base_name)

        lines = []
        filtered_inputs = {}

        for var_name, var_value in sorted(test_inputs.items()):
            # 跳过已导入的模块名
            if var_name in imported_names:
                print(f"  [Filter] Skipping test data for imported module: {var_name}")
                continue

            # 特殊处理：self变量需要是一个对象
            if var_name == 'self' or var_name == 'test_self':
                lines.append(f"class _FakeSelf:")
                lines.append(f"    def __init__(self):")
                lines.append(f"        self.url = {test_inputs.get('url', '\"http://example.com\"')}")
                lines.append(f"self = _FakeSelf()")
                filtered_inputs[var_name] = "<FakeSelf object>"
                continue

            # 模块级别定义，不需要缩进
            lines.append(f"{var_name} = {var_value}")
            filtered_inputs[var_name] = var_value

        return '\n'.join(lines), filtered_inputs

    def _generate_test_logic(self, analysis: Dict, test_inputs: Dict) -> str:
        """生成测试逻辑（方案B：优先调用原包函数，复杂情况降级为直接执行）"""
        if not analysis['dangerous_nodes']:
            return "        print('[WARNING] No dangerous nodes found')"

        # 策略：优先生成函数调用，复杂情况降级为直接执行
        test_lines = []

        # 首先输出测试数据
        if test_inputs:
            test_lines.append("        # 打印测试数据")
            test_lines.append("        print('[DEBUG] Test inputs:')")
            for var_name in sorted(test_inputs.keys()):
                test_lines.append(f"        print(f'  {var_name} = {{{var_name}}}')")

        # ✅ 新增：为每个危险节点追踪数据流，找到函数调用
        processed_calls = set()  # 避免重复处理同一个函数调用

        for danger_node in analysis['dangerous_nodes'][:5]:  # 最多5个危险节点
            danger_id = danger_node.get('node_id')
            print(f'  [DEBUG] Processing danger node: {danger_id}')

            # 追踪该危险节点的数据流下游，找到函数调用
            call_nodes = self._find_downstream_calls(danger_node, analysis)

            if call_nodes:
                # ✅ 找到了函数调用节点！生成真正的函数调用
                print(f'  [DEBUG] Found {len(call_nodes)} function calls')
                for call_node in call_nodes:
                    call_id = call_node.get('node_id')
                    if call_id in processed_calls:
                        continue
                    processed_calls.add(call_id)

                    module_name = self._get_module_name(call_node)
                    test_lines.extend(self._generate_function_call(call_node, module_name, test_inputs))
            else:
                # ❌ 没找到函数调用，降级为直接执行代码
                print(f'  [DEBUG] No function calls found, falling back to direct execution')
                test_lines.extend(self._generate_direct_execution(danger_node, test_inputs))

        return '\n'.join(test_lines) if test_lines else "        print('[WARNING] No test logic generated')"

    def _find_downstream_calls(self, danger_node: Dict, analysis: Dict) -> List[Dict]:
        """
        追踪危险节点的数据流下游，找到函数调用节点

        Args:
            danger_node: 危险节点
            analysis: 完整的分析结果

        Returns:
            下游函数调用节点列表
        """
        call_nodes = []
        danger_id = danger_node.get('node_id')

        # 构建边索引：from_node -> [(to_node, edge), ...]
        edge_index = defaultdict(list)
        for edge in analysis.get('edges', []):
            from_node = edge.get('from_node', '')
            to_node = edge.get('to_node', '')
            if from_node and to_node:
                edge_index[from_node].append((to_node, edge))

        # BFS追踪数据流
        visited = set()
        queue = [danger_id]

        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)

            # 查找当前节点的所有下游节点
            for next_id, edge in edge_index.get(current_id, []):
                # 在节点列表中查找下游节点
                next_node = self._find_node_by_id(next_id, analysis['nodes'])
                if not next_node:
                    continue

                # 检查是否是函数调用
                if self._is_function_call(next_node):
                    print(f'  [DEBUG] Found function call: {next_id} - {next_node.get("code", "")[:50]}')
                    call_nodes.append(next_node)
                else:
                    # 继续追踪
                    queue.append(next_id)

        return call_nodes

    def _find_node_by_id(self, node_id: str, nodes: List[Dict]) -> Optional[Dict]:
        """根据node_id查找节点"""
        for node in nodes:
            if node.get('node_id') == node_id:
                return node
        return None

    def _is_function_call(self, node: Dict) -> bool:
        """
        判断节点是否是函数调用

        例如：
        - create_test_malware(out) → True
        - obj.method() → True
        - import xxx → False
        - x = 1 → False
        - x = func() → False (赋值语句，不是单纯的调用)
        - output_dir (param) → False (参数节点)
        """
        code = node.get('code', '').strip()
        node_type = node.get('type', '')

        # 跳过明显的非调用语句
        if code.startswith('import ') or code.startswith('from '):
            return False

        # 跳过赋值语句（包括带有函数调用的赋值）
        if '=' in code:
            return False

        # 跳过参数节点 (type == 'parameter' 或 code 包含 "(param)")
        if node_type == 'parameter' or '(param)' in code:
            return False

        # 检查是否是纯函数调用：function_name(...)
        # 必须以函数名开头，后面紧跟括号
        if re.match(r'^[a-zA-Z_]\w*\s*\(', code):
            return True

        return False

    def _get_module_name(self, node: Dict) -> str:
        """从节点文件路径提取模块名"""
        file_path = node.get('file', '')
        return Path(file_path).stem

    def _generate_function_call(self, call_node: Dict, module_name: str, test_inputs: Dict) -> List[str]:
        """
        生成函数调用代码

        Returns:
            代码行列表
        """
        lines = []
        code = call_node.get('code', '').strip()
        file_path = call_node.get('file', '')
        line_no = call_node.get('line', 0)

        # 解析函数调用
        func_call = self._parse_function_call(code)
        if not func_call:
            # 解析失败，降级为直接执行
            return self._generate_direct_execution(call_node, test_inputs)

        func_name = func_call['name']
        args = func_call['args']

        # 检查是否是内置函数
        built_in_functions = {
            'print', 'len', 'str', 'int', 'float', 'list', 'dict', 'tuple', 'set',
            'abs', 'all', 'any', 'bin', 'bool', 'chr', 'hex', 'oct', 'ord',
            'input', 'open', 'range', 'repr', 'sorted', 'sum', 'type',
            'max', 'min', 'enumerate', 'zip', 'map', 'filter'
        }

        is_builtin = func_name in built_in_functions

        lines.append(f"\n        # 危险操作: 调用函数 {func_name}")
        lines.append(f"        # 来源: {Path(file_path).name}:{line_no}")
        lines.append(f"        # 原始代码: {code[:80]}")
        if is_builtin:
            lines.append(f"        # 策略: 调用内置函数（直接执行）")
        else:
            lines.append(f"        # 策略: 调用原包函数（真正执行）")

        # 只为非内置函数生成import语句
        if not is_builtin:
            lines.append(f"\n        # 测试模块: {module_name}")
            lines.append(f"        try:")
            lines.append(f"            import {module_name}")
            lines.append(f"        except ImportError as e:")
            lines.append(f"            print(f'[ERROR] Failed to import {module_name}: {{e}}')")
            lines.append(f"            return 'import_error'")

        # 生成函数调用
        # 准备参数：从test_inputs或使用默认值
        call_args = self._prepare_call_args(args, test_inputs)

        # 对于内置函数，不添加模块前缀
        if is_builtin:
            call_code = f"{func_name}({call_args})"
        else:
            call_code = f"{module_name}.{func_name}({call_args})"

        lines.append(f"\n        print(f'[CALL] Executing: {{repr({call_code})}}')")
        lines.append(f"        try:")
        lines.append(f"            result = {call_code}")
        lines.append(f"            print(f'[INFO] Result: {{result}}')")
        lines.append(f"        except Exception as e:")
        lines.append(f"            print(f'[CAUGHT] {{type(e).__name__}}: {{e}}')")

        return lines

    def _parse_function_call(self, code: str) -> Optional[Dict]:
        """
        解析函数调用代码

        例如：
        - "create_test_malware(out)" → {'name': 'create_test_malware', 'args': ['out']}
        - "obj.method(x, y)" → {'name': 'method', 'args': ['x', 'y'], 'object': 'obj'}

        Returns:
            {'name': str, 'args': List[str], 'object': Optional[str]} 或 None
        """
        import re

        # 匹配模式: object.method(...) 或 function(...)
        match = re.match(r'([a-zA-Z_]\w*)\s*\((.*)\)', code)
        if not match:
            return None

        func_name = match.group(1)
        args_str = match.group(2).strip()

        # 解析参数（简化版）
        args = []
        if args_str:
            # 简单按逗号分割（不处理嵌套括号）
            for arg in args_str.split(','):
                arg = arg.strip()
                if arg:
                    args.append(arg)

        return {
            'name': func_name,
            'args': args
        }

    def _prepare_call_args(self, args: List[str], test_inputs: Dict) -> str:
        """
        准备函数调用的参数

        例如：
        - ['out'] → "'.'" (从test_inputs获取或使用默认值)
        - [] → ""
        - ["f'Save to: {save_path}'"] → '"Save to: save_path_default"' (为变量生成默认值)
        """
        prepared = []

        for arg in args:
            # 检查是否是f-string (包含 {variable})
            if '{' in arg and '}' in arg:
                # 这是一个f-string，需要替换其中的变量
                import re
                def replace_var(match):
                    var_name = match.group(1)
                    # 处理属性访问（如 self.url -> url）
                    if '.' in var_name:
                        var_name = var_name.split('.')[-1]
                    if var_name in test_inputs:
                        return test_inputs[var_name].strip('"').strip("'")
                    else:
                        return f'{var_name}_default'  # 默认值

                # 替换f-string中的变量
                arg_with_defaults = re.sub(r'\{([^}]+)\}', replace_var, arg)
                # 移除f前缀或F前缀，保持原有的引号
                if arg_with_defaults.startswith('f') or arg_with_defaults.startswith('F'):
                    # 移除f/F，但保留引号
                    arg_with_defaults = arg_with_defaults[1:]
                prepared.append(arg_with_defaults)
            elif arg in test_inputs:
                prepared.append(test_inputs[arg])
            elif arg == 'out':
                # 特殊处理：out变量，使用默认值
                prepared.append("'.'")
            else:
                # 为未定义的变量生成默认字符串
                prepared.append(f'"{arg}_value"')

        return ', '.join(prepared)

    def _generate_direct_execution(self, node: Dict, test_inputs: Dict) -> List[str]:
        """
        降级策略：直接执行代码

        Returns:
            代码行列表
        """
        lines = []
        code = node.get('code', '').strip()
        file_path = node.get('file', '')
        line_no = node.get('line', 0)
        severity = node.get('severity', 'unknown')

        module_name = self._get_module_name(node)

        lines.append(f"\n        # 危险操作 (severity: {severity})")
        lines.append(f"        # 来源: {Path(file_path).name}:{line_no}")
        safe_code_snippet = code[:80].replace('\n', '\\n').replace('\r', '\\r')
        lines.append(f"        # 代码片段: {safe_code_snippet}")
        lines.append(f"        # 策略: 直接执行代码（无法追踪到函数调用）")

        # 生成import语句
        lines.append(f"\n        # 测试模块: {module_name}")
        lines.append(f"        try:")
        lines.append(f"            import {module_name}")
        lines.append(f"        except ImportError as e:")
        lines.append(f"            print(f'[ERROR] Failed to import {module_name}: {{e}}')")
        lines.append(f"            return 'import_error'")

        # 清理代码：移除return语句
        exec_code = self._clean_return_statement(code)

        if not exec_code.strip():
            lines.append(f"        # 跳过空代码")
            return lines

        # 特殊处理：import语句不能作为表达式
        if exec_code.strip().startswith('import ') or exec_code.strip().startswith('from '):
            lines.append(f"        # Import语句 - 已在上面处理")
            return lines

        # 检查是否为多行代码
        if '\n' in exec_code or ';' in exec_code:
            # 多行代码：使用exec()执行
            lines.append(f"        print(f'[EXEC] Executing multi-line code...')")
            lines.append(f"        try:")
            lines.append(f"            exec({repr(exec_code)})")
            lines.append(f"            print(f'[INFO] Multi-line code executed')")
            lines.append(f"        except Exception as exec_error:")
            lines.append(f"            print(f'[CAUGHT] {{type(exec_error).__name__}}: {{exec_error}}')")
        else:
            # 单行代码：直接执行
            safe_code_snippet = exec_code[:80].replace('\\', '\\\\').replace('"', '\\"')
            lines.append(f"        print(f'[EXEC] Executing: {{repr({repr(exec_code)})[:80]}}...')")
            lines.append(f"        try:")
            lines.append(f"            result = {exec_code}")
            lines.append(f"            print(f'[INFO] Execution result: {{result}}')")
            lines.append(f"        except Exception as exec_error:")
            lines.append(f"            print(f'[CAUGHT] {{type(exec_error).__name__}}: {{exec_error}}')")

        return lines

    def _group_nodes_by_module(self, nodes: List[Dict]) -> Dict[str, List[Dict]]:
        """按模块分组节点"""
        groups = {}
        for node in nodes:
            file_path = node.get('file', '')
            module_name = Path(file_path).stem  # 文件名作为模块名
            if module_name not in groups:
                groups[module_name] = []
            groups[module_name].append(node)
        return groups

    def _is_complex_case(self, node: Dict) -> bool:
        """判断是否为复杂情况（嵌套函数、Lambda、装饰器等）"""
        code = node.get('code', '')
        func_name = node.get('function_name', '') or ''

        # 复杂情况标志
        is_nested = '<lambda>' in code or 'lambda ' in code
        is_decorator = '@' in code or func_name in ['__init__', '__new__', '__call__']
        is_meta = func_name.startswith('__') and func_name.endswith('__')

        return is_nested or is_decorator or is_meta

    def _get_complex_reason(self, node: Dict) -> str:
        """获取复杂情况的原因说明"""
        code = node.get('code', '')
        func_name = node.get('function_name', '') or ''

        if '<lambda>' in code or 'lambda ' in code:
            return "lambda函数"
        elif '@' in code:
            return "装饰器"
        elif func_name.startswith('__') and func_name.endswith('__'):
            return "魔术方法"
        elif not func_name:
            return "模块级代码"
        else:
            return "未知复杂情况"

    def _clean_return_statement(self, code: str) -> str:
        """清理return语句"""
        exec_code = code

        # 使用正则表达式精确匹配return语句
        import re
        return_pattern = r'\breturn\s+(.+)'
        match = re.search(return_pattern, exec_code)

        if match:
            # 提取return后面的表达式
            exec_code = match.group(1).strip()
        elif exec_code.strip() == 'return':
            # 单独的return
            exec_code = ''

        return exec_code

    def _get_params(self, node: Dict, test_inputs: Dict) -> str:
        """从测试数据中获取函数参数"""
        code = node.get('code', '')

        # 从代码中提取变量名
        var_names = set()
        for match in re.finditer(r'\b([a-zA-Z_]\w*)\b', code):
            var_name = match.group(1)
            if var_name in test_inputs:
                var_names.add(var_name)

        return ', '.join(sorted(var_names))

    def _get_severity(self, analysis: Dict) -> str:
        """获取最高严重程度"""
        if not analysis['dangerous_nodes']:
            return 'safe'

        severities = [node.get('severity', 'safe') for node in analysis['dangerous_nodes']]

        if 'critical' in severities:
            return 'critical'
        elif 'high' in severities:
            return 'high'
        elif 'medium' in severities:
            return 'medium'
        else:
            return 'low'

    def _get_timestamp(self) -> str:
        """获取当前时间戳"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def generate_all_stubs(sub_ddgs_dir: str, original_package_dir: str,
                          verbose: bool = True) -> Dict:
        """
        批量生成所有子图的桩程序

        Args:
            sub_ddgs_dir: 子图根目录
            original_package_dir: 原包根目录
            verbose: 是否显示详细信息

        Returns:
            统计信息
        """
        generator = SimpleStubGenerator(verbose=verbose)

        # 查找所有子图
        subgraph_dirs = []
        for root, dirs, files in os.walk(sub_ddgs_dir):
            if 'nodes.json' in files and 'edges.json' in files:
                subgraph_dirs.append(root)

        if not subgraph_dirs:
            print(f"[ERROR] No subgraphs found in: {sub_ddgs_dir}")
            return {'total': 0, 'success': 0, 'failed': 0, 'generated_files': []}

        print(f"\n[*] Found {len(subgraph_dirs)} subgraphs")

        results = {
            'total': len(subgraph_dirs),
            'success': 0,
            'failed': 0,
            'generated_files': [],
            'errors': []
        }

        # 处理每个子图
        for i, subgraph_dir in enumerate(subgraph_dirs, 1):
            subgraph_name = Path(subgraph_dir).name
            print(f"\n[{i}/{len(subgraph_dirs)}] Processing: {subgraph_name}")

            try:
                test_file = generator.generate_stub(subgraph_dir, original_package_dir)
                results['success'] += 1
                results['generated_files'].append(test_file)
            except Exception as e:
                results['failed'] += 1
                error_msg = f"{subgraph_name}: {str(e)}"
                results['errors'].append(error_msg)
                print(f"[ERROR] {error_msg}")
                if verbose:
                    import traceback
                    traceback.print_exc()

        return results


# ========================================
# 命令行接口
# ========================================
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='为DDG子图生成可执行的桩程序'
    )
    parser.add_argument(
        'sub_ddgs_dir',
        help='子图根目录（包含nodes.json和edges.json的子目录）'
    )
    parser.add_argument(
        'original_package_dir',
        help='原恶意包的根目录'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='显示详细信息'
    )

    args = parser.parse_args()

    # 批量生成
    results = SimpleStubGenerator.generate_all_stubs(
        args.sub_ddgs_dir,
        args.original_package_dir,
        verbose=args.verbose
    )

    # 打印统计
    print(f"\n{'='*70}")
    print("  生成完成统计")
    print(f"{'='*70}")
    print(f"总计: {results['total']}")
    print(f"成功: {results['success']}")
    print(f"失败: {results['failed']}")

    if results['errors']:
        print(f"\n错误列表:")
        for error in results['errors']:
            print(f"  - {error}")

    print(f"{'='*70}")
