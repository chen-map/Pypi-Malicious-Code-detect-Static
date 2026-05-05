"""
CFG 适配器 V4 - 封装 py2cfg，提供统一接口

py2cfg 关键 API:
- CFGBuilder.build_from_src(name, source) -> CFG
- CFG.entryblock: 入口基本块
- CFG.finalblocks: 退出基本块列表
- CFG.functioncfgs: 子函数CFG字典
- Block.at(): 返回块起始行号
- Block.exits: 出边列表 [Link, ...]
- Link.target: 目标 Block
- Link.exitcase: 出边条件 (如 if 的条件表达式)
- Block.statements: 块内语句列表
- Block.predecessors: 前驱块 (需要手动维护或通过 Link 反向获取)
"""

import ast
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict

try:
    from py2cfg.builder import CFGBuilder
    from py2cfg.model import CFG, Block
except ImportError:
    raise ImportError("py2cfg is required. Install it with: pip install py2cfg")


class BlockInfo:
    """基本块信息包装"""

    def __init__(self, block: Block, file_path: str, func_name: str = '<module>'):
        self.block = block
        self.file_path = file_path
        self.func_name = func_name

    def __hash__(self):
        """基于block id, file_path, func_name生成hash"""
        return hash((self.block.id, self.file_path, self.func_name))

    def __eq__(self, other):
        """比较逻辑"""
        if not isinstance(other, BlockInfo):
            return False
        return (self.block.id == other.block.id and
                self.file_path == other.file_path and
                self.func_name == other.func_name)

    @property
    def line(self) -> int:
        """块的起始行号"""
        return self.block.at()

    @property
    def end_line(self) -> int:
        """块的结束行号"""
        if hasattr(self.block, 'end'):
            # end 可能是方法或属性
            end_attr = self.block.end
            if callable(end_attr):
                return end_attr()  # 调用方法
            return end_attr  # 直接使用属性值
        return self.line

    @property
    def statements(self) -> List[ast.stmt]:
        """块内的语句列表"""
        return self.block.statements if hasattr(self.block, 'statements') else []

    @property
    def is_empty(self) -> bool:
        """块是否为空"""
        return self.block.is_empty() if hasattr(self.block, 'is_empty') else len(self.statements) == 0

    @property
    def exits(self) -> List['LinkInfo']:
        """出边信息"""
        return [LinkInfo(link, self.file_path, self.func_name) for link in self.block.exits]

    @property
    def successors(self) -> List['BlockInfo']:
        """后继块 - 缓存以避免重复创建对象"""
        if not hasattr(self, '_successors_cache'):
            self._successors_cache = [LinkInfo(link, self.file_path, self.func_name).target for link in self.block.exits]
        return self._successors_cache

    @property
    def predecessors(self) -> List['BlockInfo']:
        """前驱块 (通过反向查找)"""
        # Block.predecessors 属性存在但可能为空，需要外部维护
        preds = self.block.predecessors if hasattr(self.block, 'predecessors') else []
        return [BlockInfo(p, self.file_path, self.func_name) for p in preds]

    @property
    def is_exit(self) -> bool:
        """是否是退出块 (没有出边)"""
        return len(self.block.exits) == 0

    @property
    def is_entry(self) -> bool:
        """是否是入口块 (通过外部判断)"""
        return False  # 由 CFGInfo 判断

    @property
    def func_calls(self) -> List[str]:
        """块内调用的函数名列表"""
        return self.block.get_calls() if hasattr(self.block, 'get_calls') else []

    @property
    def source(self) -> str:
        """块的源代码片段"""
        if not hasattr(self.block, 'get_source'):
            return ""
        try:
            src = self.block.get_source()
            # 确保返回的是字符串并处理编码问题
            if src and isinstance(src, (bytes, bytearray)):
                src = src.decode('utf-8', errors='replace')
            return src[:200] if src else ""
        except (AttributeError, TypeError, UnicodeError):
            # py2cfg 的 get_source 可能失败 (astor 与 Python 3.14+ 兼容性问题)
            # 使用 ast.unparse 作为后备
            if self.statements:
                try:
                    import ast as ast_module
                    sources = []
                    for stmt in self.statements[:3]:  # 只取前3个语句
                        if hasattr(ast_module, 'unparse'):
                            unparsed = ast_module.unparse(stmt)
                            # 确保是字符串
                            if unparsed:
                                sources.append(str(unparsed))
                    if sources:
                        result = ' '.join(sources)[:200]
                        # 额外编码保护
                        try:
                            result.encode('utf-8')
                            return result
                        except UnicodeError:
                            # 如果还有编码问题，用替换字符
                            return result.encode('ascii', errors='replace').decode('ascii')
                except Exception:
                    pass
            return ""

    def get_used_variables(self) -> Set[str]:
        """获取块内使用的变量名"""
        used = set()
        for stmt in self.statements:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    used.add(node.id)
        return used

    def get_defined_variables(self) -> Set[str]:
        """获取块内定义的变量名"""
        defined = set()
        for stmt in self.statements:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(stmt.name)
            elif isinstance(stmt, ast.ClassDef):
                defined.add(stmt.name)
            elif isinstance(stmt, ast.For):
                if isinstance(stmt.target, ast.Name):
                    defined.add(stmt.target.id)
        return defined

    def get_return_variables(self) -> List[str]:
        """获取 return 语句返回的变量名"""
        return_vars = []
        for stmt in self.statements:
            if isinstance(stmt, ast.Return) and stmt.value:
                if isinstance(stmt.value, ast.Name):
                    return_vars.append(stmt.value.id)
        return return_vars

    def __str__(self):
        return f"block:{self.block.id}@{self.line}"

    def __repr__(self):
        return f"BlockInfo({self}, func={self.func_name})"


class LinkInfo:
    """控制流边信息包装"""

    def __init__(self, link, file_path: str, func_name: str = '<module>'):
        self.link = link
        self.file_path = file_path
        self.func_name = func_name

    @property
    def source(self) -> BlockInfo:
        """源块"""
        return BlockInfo(self.link.source, self.file_path, self.func_name)

    @property
    def target(self) -> BlockInfo:
        """目标块"""
        return BlockInfo(self.link.target, self.file_path, self.func_name)

    @property
    def exitcase(self) -> Optional[ast.expr]:
        """出边条件 (如 if 条件)"""
        return self.link.exitcase

    @property
    def condition(self) -> str:
        """条件的字符串表示"""
        if self.exitcase:
            try:
                return ast.unparse(self.exitcase) if hasattr(ast, 'unparse') else str(self.exitcase)
            except:
                return str(self.exitcase)
        return "unconditional"

    def __str__(self):
        return f"link from {self.source} to {self.target}"


class CFGInfo:
    """CFG 信息包装"""

    def __init__(self, cfg: CFG, file_path: str, name: str = '<module>'):
        self.cfg = cfg
        self.file_path = file_path
        self.name = name

        # 构建块映射: line -> BlockInfo
        self._block_map: Dict[int, BlockInfo] = {}
        self._build_block_map()

        # 维护前驱关系 (py2cfg 的 predecessors 可能不完整)
        self._build_predecessors()

    def _build_block_map(self):
        """构建行号到块的映射"""
        for block in self.cfg.own_blocks():
            info = BlockInfo(block, self.file_path, self.name)
            # 记录块覆盖的行范围
            start = info.line
            end = info.end_line
            for line in range(start, end + 1):
                self._block_map[line] = info

    def _build_predecessors(self):
        """手动维护前驱关系"""
        for block in self.cfg.own_blocks():
            block_info = BlockInfo(block, self.file_path, self.name)
            for exit_link in block.exits:
                target = exit_link.target
                # 确保目标块有 predecessors 集合
                if not hasattr(target, 'predecessors'):
                    target.predecessors = []
                if block not in target.predecessors:
                    target.predecessors.append(block)

    @property
    def entry_block(self) -> Optional[BlockInfo]:
        """入口块"""
        if self.cfg.entryblock:
            return BlockInfo(self.cfg.entryblock, self.file_path, self.name)
        return None

    @property
    def exit_blocks(self) -> List[BlockInfo]:
        """退出块列表 (没有出边的块)"""
        exits = self.cfg.finalblocks if self.cfg.finalblocks else []
        return [BlockInfo(b, self.file_path, self.name) for b in exits]

    @property
    def all_blocks(self) -> List[BlockInfo]:
        """所有块"""
        return [BlockInfo(b, self.file_path, self.name) for b in self.cfg.own_blocks()]

    @property
    def function_cfgs(self) -> Dict[str, 'CFGInfo']:
        """子函数的 CFG"""
        result = {}
        # 处理普通函数
        for name, func_cfg in self.cfg.functioncfgs.items():
            result[name] = CFGInfo(func_cfg, self.file_path, name)
        # 处理类方法
        for class_name, class_cfg in self.cfg.classcfgs.items():
            if hasattr(class_cfg, 'functioncfgs'):
                for method_name, method_cfg in class_cfg.functioncfgs.items():
                    full_name = f"{class_name}.{method_name}"
                    result[full_name] = CFGInfo(method_cfg, self.file_path, full_name)
        return result

    def get_block_at_line(self, line: int) -> Optional[BlockInfo]:
        """获取包含指定行的块"""
        return self._block_map.get(line)

    def get_block_by_id(self, block_id: str) -> Optional[BlockInfo]:
        """通过 ID 获取块"""
        for block in self.all_blocks:
            if str(block.block.id) == block_id or str(block) == block_id:
                return block
        return None

    def get_reachable_blocks(self) -> Set[BlockInfo]:
        """获取从入口可达的所有块"""
        reachable = set()
        entry = self.entry_block
        if not entry:
            return reachable

        to_visit = [entry]
        while to_visit:
            block = to_visit.pop()
            if block in reachable:
                continue
            reachable.add(block)
            to_visit.extend(block.successors)

        return reachable

    def get_return_paths(self) -> List[List[BlockInfo]]:
        """获取所有从入口到出口的路径"""
        paths = []
        entry = self.entry_block
        exits = self.exit_blocks

        if not entry:
            return paths

        def dfs(current: BlockInfo, path: List[BlockInfo], visited: Set[int]):
            if current in exits:
                paths.append(path.copy())
                return

            for succ in current.successors:
                block_id = str(succ.block.id)
                if block_id in visited:
                    continue  # 避免循环
                visited.add(block_id)
                path.append(succ)
                dfs(succ, path, visited)
                path.pop()
                visited.remove(block_id)

        dfs(entry, [entry], {str(entry.block.id)})
        return paths

    def get_function_exit_blocks(self, func_name: str) -> List[BlockInfo]:
        """获取函数的所有退出块"""
        func_cfg = self.cfg.functioncfgs.get(func_name)
        if func_cfg and func_cfg.finalblocks:
            return [BlockInfo(b, self.file_path, func_name) for b in func_cfg.finalblocks]
        return []

    def __str__(self):
        return f"CFG({self.name}, {len(self.all_blocks)} blocks)"


class ProjectCFGManager:
    """项目级 CFG 管理器"""

    def __init__(self):
        self.cfgs: Dict[str, CFGInfo] = {}  # file_path -> CFGInfo
        self.function_cfgs: Dict[Tuple[str, str], CFGInfo] = {}  # (file_path, func_name) -> CFGInfo

    def build_cfg_for_file(self, file_path: str) -> Optional[CFGInfo]:
        """为单个文件构建 CFG"""
        try:
            # 先检查文件大小，避免处理超大文件
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                line_count = sum(1 for _ in f)

            # 跳过超过30000行的文件
            if line_count > 30000:
                return None

            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()

            builder = CFGBuilder()
            cfg = builder.build_from_src(Path(file_path).name, source)

            cfg_info = CFGInfo(cfg, file_path, Path(file_path).name)
            self.cfgs[file_path] = cfg_info

            # 索引函数 CFG
            for func_name, func_cfg in cfg_info.function_cfgs.items():
                self.function_cfgs[(file_path, func_name)] = func_cfg

            return cfg_info

        except SyntaxError:
            # 文件可能有语法错误，跳过
            return None
        except Exception as e:
            # 静默跳过，大文件可能在这里出问题
            return None

    def get_cfg(self, file_path: str) -> Optional[CFGInfo]:
        """获取文件的 CFG"""
        return self.cfgs.get(file_path)

    def get_function_cfg(self, file_path: str, func_name: str) -> Optional[CFGInfo]:
        """获取函数的 CFG"""
        return self.function_cfgs.get((file_path, func_name))

    def get_block_at_line(self, file_path: str, line: int) -> Optional[BlockInfo]:
        """获取指定行所在的块"""
        cfg = self.get_cfg(file_path)
        if cfg:
            return cfg.get_block_at_line(line)
        return None

    def get_function_exit_blocks(self, file_path: str, func_name: str) -> List[BlockInfo]:
        """获取函数的退出块"""
        func_cfg = self.get_function_cfg(file_path, func_name)
        if func_cfg:
            return func_cfg.exit_blocks
        return []

    def is_reachable_from_entry(self, file_path: str, line: int) -> bool:
        """检查某一行是否从入口可达"""
        module_cfg = self.get_cfg(file_path)
        if not module_cfg:
            return True  # 无 CFG 信息时，假设可达

        # 首先检查函数 CFG（函数内的行优先在函数 CFG 中查找）
        for func_name, func_cfg in module_cfg.function_cfgs.items():
            block = func_cfg.get_block_at_line(line)
            if block:
                # 在函数 CFG 中找到块
                # 函数 CFG 的入口块总是可达的（假设函数被调用）
                return True
            # 检查是否是函数定义行（入口块的前一行）
            if func_cfg.entry_block and func_cfg.entry_block.line == line + 1:
                # 这是函数定义行，函数定义总是可达的（可以被调用）
                return True

        # 如果在函数 CFG 中找不到，检查模块级 CFG
        module_block = module_cfg.get_block_at_line(line)
        if module_block:
            # 在模块级，检查可达性
            reachable = module_cfg.get_reachable_blocks()
            return module_block in reachable

        # 找不到块，假设可达
        return True

    def get_all_return_paths(self, file_path: str, func_name: str) -> List[List[BlockInfo]]:
        """获取函数的所有返回路径"""
        func_cfg = self.get_function_cfg(file_path, func_name)
        if func_cfg:
            return func_cfg.get_return_paths()
        return []
