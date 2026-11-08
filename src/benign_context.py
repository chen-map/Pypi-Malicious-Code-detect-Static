# -*- coding: utf-8 -*-
"""良性上下文判定（Benign Context）· 确定性降权层

动机（2026-11，100+100 消融驱动）：
    C 档误报 3.1%、良性 16% 卡 SUSPICIOUS，归因全部是**上下文丢失**：
      - acryl_datahub_classify：块划分明确引用 tests/test_info_type_utils.py
        仍然判 MALICIOUS——模型看到了路径但不认为它有决定性
      - adbc_driver_sqlite：exec(f.read(), {}, ns) 是 setuptools-scm 版本
        检测惯用法（约 5 万包在用），被 danger_patterns 的 code_execution
        子串命中为 critical
    结论：这类判定不该交给 prompt（模型看到证据仍会无视），该交给程序。

三个判定（全部确定性，可单测）：
    1. is_fixture_path     测试/示例/文档目录 → critical 降为 medium
                           （保留可见性：恶意包把载荷放 tests/ 也只是降级，
                            不会消失——medium 仍可支撑 SUSPICIOUS）
    2. is_version_idiom    exec(open(X).read()) 且 X 的内容**真被读过**、
                           只含 __version__ 赋值 → low + benign_idiom 标记
                           （形状相同但内容是恶意载荷的文件不会通过）
    3. literal/unfed sink  汇点在本子图内没有数据边流入 → unfed_sink 标记
                           （参数不来自链路的 subprocess.run 不是链终点）

设计约束：
    - 纯函数 + 一个 apply() 入口，无 LLM、无网络
    - 降权不删除：所有标记都保留在节点 attrs 和 suspicious dict 里，
      digest / nodes.json / prompt 全链路可见
    - 宁可漏降不可误放：version idiom 必须读到目标文件且内容纯净才通过
"""
import ast
from pathlib import Path
from typing import Dict, Optional, Set

# 测试/文档目录（与 artifact_scanner._FIXTURE_DIRS 保持一致，跨语言通用）
FIXTURE_DIRS: Set[str] = {
    'test', 'tests', 'testing', 'fixtures', 'examples',
    'docs', 'doc', '.github', 'benchmarks',
}

# 版本文件里允许的赋值目标
_VERSION_TARGETS = {'__version__', '__version_tuple__', 'version',
                    '__version_info__', 'VERSION'}

# 版本文件大小上限（真版本文件都极小；上限防拿大文件绕过）
_MAX_VERSION_FILE_BYTES = 8_192


def is_fixture_path(rel_path: str) -> bool:
    """路径是否位于测试/示例/文档目录（路径段精确匹配，非子串）"""
    if not rel_path:
        return False
    parts = {p.lower() for p in rel_path.replace(chr(92), '/').split('/')}
    return bool(parts & FIXTURE_DIRS)


def _const_only_assign(node) -> bool:
    """赋值语句：目标是版本变量，值是常量/常量元组"""
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for t in targets:
        if not (isinstance(t, ast.Name) and t.id in _VERSION_TARGETS):
            return False
    v = node.value
    if isinstance(v, ast.Constant):
        return True
    if isinstance(v, (ast.Tuple, ast.List)):
        return all(isinstance(e, ast.Constant) for e in v.elts)
    return False


def _version_file_is_pure(path: Path) -> bool:
    """目标文件是否只含版本赋值（+docstring/注释）。任何其他语句判否。"""
    try:
        if path.stat().st_size > _MAX_VERSION_FILE_BYTES:
            return False
        tree = ast.parse(path.read_text(encoding='utf-8', errors='ignore'))
    except Exception:
        return False
    body = tree.body
    # 允许前导 docstring
    if body and isinstance(body[0], ast.Expr) and \
            isinstance(body[0].value, ast.Constant) and \
            isinstance(body[0].value.value, str):
        body = body[1:]
    for stmt in body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            if not _const_only_assign(stmt):
                return False
        else:
            return False   # import / def / call / if / try … 一律判否
    return True


def _extract_read_target(node_code: str) -> Optional[str]:
    """从 exec(open(X).read()) / exec(f.read(), ...) 形状里解析出文件名。

    支持：
        exec(open("_version.py").read())
        exec(open(os.path.join(base, "_version.py")).read())
        with open(version_file) as f: exec(f.read(), {}, ns)
        exec(compile(open(X).read(), X, "exec"))
    返回 X 的 basename（无则 None）。
    """
    try:
        tree = ast.parse(node_code)
    except Exception:
        return None

    def name_of_open_arg(call):
        if not call.args:
            return None
        a = call.args[0]
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
        if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) \
                and a.func.attr == 'join':
            # os.path.join(base, "x.py") → 取最后一个字符串常量
            for arg in reversed(a.args):
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    return arg.value
        return None

    for n in ast.walk(tree):
        # 直接形态：exec(open(X).read()...) / exec(compile(open(X)...))
        if isinstance(n, ast.Call):
            for arg in n.args:
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute):
                    # open(X).read() → func.attr='read', func.value=Call(open)
                    inner = arg.func.value
                    if isinstance(inner, ast.Call) and \
                            isinstance(inner.func, ast.Name) and inner.func.id == 'open':
                        t = name_of_open_arg(inner)
                        if t:
                            return t
                if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) \
                        and arg.func.id == 'compile':
                    if arg.args:
                        c0 = arg.args[0]
                        if isinstance(c0, ast.Call) and isinstance(c0.func, ast.Attribute):
                            inner = c0.func.value
                            if isinstance(inner, ast.Call) and \
                                    isinstance(inner.func, ast.Name) and \
                                    inner.func.id == 'open':
                                t = name_of_open_arg(inner)
                                if t:
                                    return t
        # with open(X) as f: … exec(f.read()) 形态 → 任何 open() 调用都算候选
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                and n.func.id == 'open':
            t = name_of_open_arg(n)
            if t:
                return t
    return None


def is_version_idiom(node_code: str, project_dir) -> bool:
    """exec(open(X).read()) 且 X 内容纯净 → 版本检测惯用法（确定性）。"""
    if not node_code or 'exec' not in node_code and 'compile' not in node_code:
        return False
    target = _extract_read_target(node_code)
    if not target:
        return False
    base = target.replace(chr(92), '/').split('/')[-1]
    if not base.endswith('.py'):
        return False
    root = Path(project_dir)
    if not root.exists():
        return False
    # 在包内定位同名文件（限制数量防巨型包扫描爆炸）
    hits = list(root.rglob(base))[:20]
    for h in hits:
        if '__pycache__' in str(h) or '.ddg_output' in str(h):
            continue
        if _version_file_is_pure(h):
            return True
    return False


def apply(suspicious_nodes: Dict[str, Dict], graph=None,
          project_dir=None) -> Dict[str, int]:
    """在 suspicious_nodes 上做确定性降权，并把标记写进节点 attrs。

    Args:
        suspicious_nodes: SuspiciousNodeDetector 产物 {node_id: {severity,...}}
        graph: nx.DiGraph（可选；传入时把标记写进节点 attrs，
               供 _save_nodes / digest / LLM 全链路可见）
        project_dir: 包解压目录（version idiom 需要读目标文件）

    Returns:
        统计 {'fixture_downgraded': n, 'version_idiom': m}
    """
    stats = {'fixture_downgraded': 0, 'version_idiom': 0}
    for node_id, info in suspicious_nodes.items():
        sev = (info.get('severity') or '').lower()
        if sev != 'critical':
            continue
        rel = info.get('file') or ''

        # 1) 测试/示例/文档目录：critical → medium（保留可见性）
        if is_fixture_path(rel):
            info['severity'] = 'medium'
            info['benign_context'] = 'fixture_dir'
            if graph and graph.has_node(node_id):
                graph.nodes[node_id]['benign_context'] = 'fixture_dir'
            stats['fixture_downgraded'] += 1
            continue

        # 2) 版本检测惯用法：必须真读到目标文件且内容纯净
        if project_dir is not None:
            code = info.get('label') or info.get('code') or ''
            if 'exec' in code or 'compile' in code:
                # suspicious dict 只有 label；再从图上取完整 source
                if graph and graph.has_node(node_id):
                    code = graph.nodes[node_id].get('source') or code
                if is_version_idiom(code, project_dir):
                    info['severity'] = 'low'
                    info['benign_context'] = 'version_file'
                    if graph and graph.has_node(node_id):
                        graph.nodes[node_id]['benign_context'] = 'version_file'
                    stats['version_idiom'] += 1
    return stats
