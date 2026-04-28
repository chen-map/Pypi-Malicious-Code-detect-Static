"""
轻量级 CFG 实现 - 专注于可达性判断

与 py2cfg 不同，本实现：
1. 兼容 Python 3.8+
2. 只追踪可达性，不构建完整 CFG 图
3. 性能优化，减少内存占用
"""

import ast
from typing import Dict, Set, List, Tuple, Optional
from pathlib import Path
from collections import defaultdict


class BasicBlock:
    """基本块 - 只存储行号范围"""

    def __init__(self, start_line: int, end_line: int, block_id: str):
        self.start_line = start_line
        self.end_line = end_line
        self.id = block_id
        self.exits: List[str] = []  # 后继块 ID 列表

    def contains(self, line: int) -> bool:
        """判断行号是否在块内"""
        return self.start_line <= line <= self.end_line

    def __repr__(self):
        return f"Block({self.start_line}-{self.end_line}, exits={len(self.exits)})"


class LightweightCFG:
    """轻量级 CFG - 只追踪语句块可达性"""

    def __init__(self, source: str, filename: str = "<module>"):
        self.source = source
        self.filename = filename
        self.blocks: Dict[str, BasicBlock] = {}
        self.entry_block: Optional[str] = None
        self.function_cfgs: Dict[str, 'LightweightCFG'] = {}
        self.reachable_lines: Set[int] = set()
        self._build()

    def get_reachable_lines(self) -> Set[int]:
        """获取所有可达行的集合"""
        return self.reachable_lines

    def get_function_cfg(self, func_name: str) -> Optional['LightweightCFG']:
        """获取函数的 CFG"""
        return self.function_cfgs.get(func_name)

    def _build(self):
        """构建 CFG"""
        try:
            tree = ast.parse(self.source, filename=self.filename)
            self._build_module_cfg(tree)
            self._compute_reachability()
        except SyntaxError:
            # 语法错误，假设所有行可达
            lines = self.source.split('\n')
            self.reachable_lines = set(range(1, len(lines) + 1))

    def _build_module_cfg(self, tree: ast.AST):
        """构建模块级 CFG"""
        block_id = "module"
        self.entry_block = block_id

        # 为模块创建一个覆盖所有行的基础块
        end_line = self._get_end_line(tree)
        self.blocks[block_id] = BasicBlock(1, end_line, block_id)

        # 识别函数并为其创建子 CFG
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_cfg = LightweightCFG(self.source, self.filename)
                # 只提取函数部分
                func_tree = self._extract_function_tree(node, tree)
                if func_tree:
                    func_cfg._build_function_cfg(func_tree, node.name, node.lineno)
                    self.function_cfgs[node.name] = func_cfg

    def _build_function_cfg(self, tree: ast.AST, func_name: str, start_line: int):
        """构建函数 CFG"""
        block_id = f"func_{func_name}"
        self.entry_block = block_id

        # 创建函数的基础块
        end_line = self._get_end_line(tree)
        self.blocks[block_id] = BasicBlock(start_line, end_line, block_id)

        # 分析控制流，创建块之间的连接
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                self._process_if_node(node)
            elif isinstance(node, ast.For):
                self._process_for_node(node)
            elif isinstance(node, ast.While):
                self._process_while_node(node)
            elif isinstance(node, ast.Try):
                self._process_try_node(node)

    def _process_if_node(self, node: ast.If):
        """处理 if 语句，创建控制流块"""
        # if 块
        if_block_id = f"if_{node.lineno}"
        if node.body:
            if_end = max(self._get_node_line_range(stmt)[1] for stmt in node.body)
            self.blocks[if_block_id] = BasicBlock(node.lineno, if_end, if_block_id)

        # else 块
        else_block_id = f"else_{node.lineno}"
        if node.orelse:
            else_end = max(self._get_node_line_range(stmt)[1] for stmt in node.orelse)
            self.blocks[else_block_id] = BasicBlock(node.orelse[0].lineno, else_end, else_block_id)

    def _process_for_node(self, node: ast.For):
        """处理 for 循环"""
        for_block_id = f"for_{node.lineno}"
        if node.body:
            for_end = max(self._get_node_line_range(stmt)[1] for stmt in node.body)
            self.blocks[for_block_id] = BasicBlock(node.lineno, for_end, for_block_id)

        # else 块（循环正常结束时执行）
        if node.orelse:
            else_block_id = f"for_else_{node.lineno}"
            else_end = max(self._get_node_line_range(stmt)[1] for stmt in node.orelse)
            self.blocks[else_block_id] = BasicBlock(node.orelse[0].lineno, else_end, else_block_id)

    def _process_while_node(self, node: ast.While):
        """处理 while 循环"""
        while_block_id = f"while_{node.lineno}"
        if node.body:
            while_end = max(self._get_node_line_range(stmt)[1] for stmt in node.body)
            self.blocks[while_block_id] = BasicBlock(node.lineno, while_end, while_block_id)

        if node.orelse:
            else_block_id = f"while_else_{node.lineno}"
            else_end = max(self._get_node_line_range(stmt)[1] for stmt in node.orelse)
            self.blocks[else_block_id] = BasicBlock(node.orelse[0].lineno, else_end, else_block_id)

    def _process_try_node(self, node: ast.Try):
        """处理 try-except 语句"""
        # try 块
        if node.body:
            try_block_id = f"try_{node.lineno}"
            try_end = max(self._get_node_line_range(stmt)[1] for stmt in node.body)
            self.blocks[try_block_id] = BasicBlock(node.lineno, try_end, try_block_id)

        # except 块
        for handler in node.handlers:
            if handler.body:
                exc_block_id = f"except_{handler.lineno}"
                exc_end = max(self._get_node_line_range(stmt)[1] for stmt in handler.body)
                self.blocks[exc_block_id] = BasicBlock(handler.lineno, exc_end, exc_block_id)

    def _compute_reachability(self):
        """计算可达行号"""
        if not self.blocks:
            return

        # 从入口块开始，使用 BFS 标记可达块
        visited = set()
        to_visit = [self.entry_block] if self.entry_block else []

        while to_visit:
            block_id = to_visit.pop(0)
            if block_id in visited or block_id not in self.blocks:
                continue

            visited.add(block_id)
            block = self.blocks[block_id]

            # 添加块中的所有行
            for line in range(block.start_line, block.end_line + 1):
                self.reachable_lines.add(line)

            # 添加后继块
            to_visit.extend(block.exits)

        # 如果没有 CFG 信息，假设所有行可达
        if not self.reachable_lines:
            lines = self.source.split('\n')
            self.reachable_lines = set(range(1, len(lines) + 1))

    def _get_end_line(self, node: ast.AST) -> int:
        """获取 AST 节点的结束行"""
        if hasattr(node, 'end_lineno') and node.end_lineno:
            return node.end_lineno

        # 递归查找最大行号
        max_line = node.lineno if hasattr(node, 'lineno') else 0
        for child in ast.walk(node):
            if hasattr(child, 'lineno') and child.lineno:
                max_line = max(max_line, child.lineno)
        return max_line

    def _get_node_line_range(self, node: ast.AST) -> Tuple[int, int]:
        """获取节点的行号范围"""
        start = node.lineno if hasattr(node, 'lineno') else 0
        end = getattr(node, 'end_lineno', None)
        if end is None:
            end = self._get_end_line(node)
        return (start, end)

    def _extract_function_tree(self, func_node: ast.FunctionDef, module_tree: ast.AST) -> Optional[ast.AST]:
        """从模块中提取函数的 AST"""
        # 简化处理：直接使用函数节点
        return func_node


class LightweightCFGManager:
    """轻量级 CFG 管理器 - 替代 cfg_adapter.py"""

    def __init__(self):
        self.cfgs: Dict[str, LightweightCFG] = {}

    def build_cfg_for_file(self, file_path: str) -> Optional['LightweightCFG']:
        """为文件构建 CFG"""
        file_path = str(file_path)
        if file_path in self.cfgs:
            return self.cfgs[file_path]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()

            # 检查文件大小
            line_count = source.count('\n') + 1
            if line_count > 100000:  # 10 万行以上跳过
                return None

            cfg = LightweightCFG(source, file_path)
            self.cfgs[file_path] = cfg
            return cfg

        except Exception:
            return None

    def get_cfg(self, file_path: str) -> Optional['LightweightCFG']:
        """获取文件的 CFG"""
        return self.cfgs.get(str(file_path))

    def get_function_cfg(self, file_path: str, func_name: str) -> Optional['LightweightCFG']:
        """获取函数的 CFG"""
        cfg = self.get_cfg(file_path)
        if cfg:
            return cfg.get_function_cfg(func_name)
        return None

    def get_reachable_lines(self, file_path: str) -> Set[int]:
        """获取文件的所有可达行"""
        cfg = self.get_cfg(file_path)
        if cfg:
            return cfg.get_reachable_lines()
        return set()

    def get_function_exit_blocks(self, file_path: str, func_name: str) -> List['BasicBlock']:
        """获取函数的退出块（简化版本，返回函数定义的最后一行）"""
        cfg = self.get_cfg(file_path)
        if cfg and func_name in cfg.function_cfgs:
            func_cfg = cfg.function_cfgs[func_name]
            # 返回函数的结束位置作为"退出块"
            if func_cfg.blocks:
                return [block for block in func_cfg.blocks.values() if not block.exits]
        return []

    def get_block_at_line(self, file_path: str, line: int) -> Optional['BasicBlock']:
        """获取包含指定行的块"""
        cfg = self.get_cfg(file_path)
        if cfg:
            for block in cfg.blocks.values():
                if block.contains(line):
                    return block
        return None
