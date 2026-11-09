# -*- coding: utf-8 -*-
"""SSO 提取器 ∪ PyFlow capability —— 两个引擎的盲区正好错开

动机（2026-11，L1-L4 API 混淆实测）：
    同一份代码，两个引擎各有各的漏：

        getattr(os, "sys"+"tem")("id")
            PyFlow      → 0 findings（capability 模型里没有 getattr）
            我们的 SSO   → os.system / process_spawn（常量折叠 + getattr 还原）

        __import__(b64decode("b3M="))
            两个都能抓到 __import__，但都还原不出 os

    所以不是二选一，是并集：PyFlow 有 IFDS/别名/覆盖度，我们的 SSO 有
    常量折叠/别名赋值/module_level。合并后 L1-L4 四层全覆盖。

设计约束：
    - 纯合并，不重跑分析（SSO 是 AST 遍历，几百毫秒，可接受）
    - 冲突时取"更具体"的能力（Tier 小者优先），并记录两个来源
    - module_level 用 SSO 的 AST 判定（比文件名启发准确）
"""
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# 我们的能力类 → Tier（与 pyflow_backend.CAPABILITY_TIER 一致）
_TIER = {
    'process_spawn': 1, 'code_eval': 1, 'network_out': 1, 'privilege': 1,
    'credential_access': 1,
    'network_in': 2, 'deserialize': 2, 'decode': 2, 'file_write': 2,
    'env_access': 3, 'file_read': 3,
}


def _abs(project_dir: Path, rel: str) -> str:
    try:
        return str((Path(project_dir) / rel).resolve())
    except Exception:
        return ''


def collect_sso(project_dir) -> Optional[Dict]:
    """跑我们的 SSO 提取器；失败返回 None（不阻塞主流程）"""
    try:
        from src.sso_extractor import extract_sso
        return extract_sso(Path(project_dir))
    except Exception:
        return None


def merge_capabilities(pyflow_caps: Dict, sso_result: Optional[Dict],
                       project_dir) -> Tuple[Dict[Tuple[str, int], Set[str]],
                                            Dict[Tuple[str, int], bool]]:
    """把 PyFlow findings 与 SSO findings 合并成 (位置 → 能力集)。

    Returns:
        (cap_by_loc, module_level_by_loc)
        cap_by_loc: {(abs_file, line): {cap, ...}}
        module_level_by_loc: {(abs_file, line): bool}   # 仅 SSO 能提供
    """
    cap_by_loc: Dict[Tuple[str, int], Set[str]] = {}
    module_level: Dict[Tuple[str, int], bool] = {}

    # --- PyFlow ---
    for f in (pyflow_caps.get('findings') or []):
        loc = f.get('location') or {}
        src = f.get('file') or loc.get('file')
        line = loc.get('line')
        if not src or not line:
            continue
        cap = _PYFLOW_TO_OURS.get(f.get('capability') or '')
        if not cap:
            continue
        key = (str(Path(src).resolve()), int(line))
        cap_by_loc.setdefault(key, set()).add(cap)

    # --- 我们的 SSO（常量折叠 + getattr 还原 + module_level）---
    if sso_result:
        root = Path(project_dir)
        for fd in (sso_result.get('findings') or []):
            cap = fd.get('capability')
            if cap not in _TIER:
                continue
            absf = _abs(root, fd.get('file') or '')
            line = int(fd.get('line') or 0)
            if not absf or not line:
                continue
            key = (absf, line)
            cap_by_loc.setdefault(key, set()).add(cap)
            # module_level：同一行同一能力只记一次（True 优先）
            prev = module_level.get(key)
            module_level[key] = bool(fd.get('module_level')) or bool(prev)

    return cap_by_loc, module_level


# PyFlow capability → 我们的能力类（与 pyflow_backend.CAPABILITY_MAP 同源，
# 这里独立一份避免循环 import）
_PYFLOW_TO_OURS = {
    'process.execute': 'process_spawn',
    'process.control': 'process_spawn',
    'code.execute': 'code_eval',
    'module.dynamic_import': 'code_eval',
    'module.loader_mutation': 'code_eval',
    'network.io': 'network_out',
    'network.socket': 'network_out',
    'network.dns': 'network_out',
    'deserialization.unsafe': 'deserialize',
    'file.write': 'file_write',
    'file.read': 'file_read',
    'file.metadata': 'file_read',
    'information.credentials': 'credential_access',
    'information.environment': 'env_access',
    'information.system': 'env_access',
    'native.access': 'privilege',
}


def pick_capability(caps: Set[str]) -> str:
    """从一行的多个能力里挑最危险的一个（Tier 小者优先）"""
    if not caps:
        return ''
    return sorted(caps, key=lambda c: (_TIER.get(c, 9), c))[0]


def summarize(cap_by_loc: Dict[Tuple[str, int], Set[str]]) -> Dict[str, int]:
    """能力计数（每行取最危险的一个）"""
    counts: Dict[str, int] = {}
    for caps in cap_by_loc.values():
        c = pick_capability(caps)
        if c:
            counts[c] = counts.get(c, 0) + 1
    return counts


def phase_of(module_level: Optional[bool], filename: str,
             func_name: Optional[str]) -> str:
    """执行时机：SSO 的 module_level 优先，回落到文件名启发。

    install: setup.py 顶层（pip install 即执行）
    import : __init__.py 顶层
    runtime: 函数体内
    """
    is_top = module_level if module_level is not None else (
        func_name in (None, '', '<module>'))
    name = Path(filename).name
    # 2026-11：setup.py 里**任何**代码都是安装期执行——包括函数体。
    # 真实样本用 cmdclass={'install_scripts': Cls} 把载荷放在类方法里，
    # 按"函数体=runtime"判定会完全错过这个 PyPI 主攻击面。
    if name == 'setup.py':
        return 'install'
    if is_top and name == 'conftest.py':
        return 'install'
    if is_top and name == '__init__.py':
        return 'import'
    return 'runtime'
