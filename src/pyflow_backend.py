# -*- coding: utf-8 -*-
"""PyFlow 分析后端 · 把工业化静态分析接到我们的判定层

定位（2026-11 架构换底）：
    我们的架构（小 LLM 建链 → 程序验证 → 大 LLM 判定）是对的，但分析
    引擎全是手写的：DDG 建图分钟级、大包必超时、污点引擎是简化 BFS。
    PyFlow（ZJU-PL, arXiv 2608.07026）提供 IFDS / 别名 / 20 类 capability
    / 覆盖度元数据，且秒级。

本模块只做**翻译**，不做分析：
    PyFlow 的 capabilities + GIR + callgraph  →  我们下游认识的 node/edge dict

我们独有的东西（PyFlow 没有）：
    1. PyPI 威胁模型映射（20 类通用 capability → 我们的 11 类 + credential_access）
    2. 执行时机（context 的 __main__/scope 深度 → install/import/runtime）
    3. 三类边的语义对齐（GIR 值流 → data，callgraph → call，语句序 → control）
    4. 覆盖度元数据原样保留，交给 coverage_gate 做"unknown ≠ safe"

依赖约束：
    PyFlow 要 Python >= 3.10，主流程跑 3.8 → **shell out** 到独立 venv，
    JSON 走 stdout。路径由 PYFLOW_BIN 覆盖；不可用时返回 None 由调用方回退。
"""
import ast
import json
import re
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ===== PyFlow binary 定位 =====
_DEFAULT_PYFLOW = '/disk2/wch/chq/pfenv/bin/pyflow'


def pyflow_bin() -> Optional[str]:
    """返回可用的 pyflow 可执行文件路径，找不到返回 None"""
    cand = os.environ.get('PYFLOW_BIN') or _DEFAULT_PYFLOW
    p = Path(cand)
    if p.exists() and os.access(p, os.X_OK):
        return str(p)
    return None


def available() -> bool:
    return pyflow_bin() is not None


# ===== capability 映射（我们的威胁模型）=====
# PyFlow 的 20 类通用 capability → 我们的能力类。
# 映射表本身就是我们的东西：PyFlow 按"漏洞影响面"分类，我们按"攻击链位置"分类。
CAPABILITY_MAP: Dict[str, str] = {
    # 执行
    'process.execute': 'process_spawn',
    'process.control': 'process_spawn',
    'code.execute': 'code_eval',
    'module.dynamic_import': 'code_eval',
    # 加载器篡改 = .pth/sitecustomize 持久化（PyPI 特有攻击面）
    'module.loader_mutation': 'code_eval',
    # 网络
    'network.io': 'network_out',
    'network.socket': 'network_out',
    'network.dns': 'network_out',
    # 反序列化
    'deserialization.unsafe': 'deserialize',
    # 文件
    'file.write': 'file_write',
    'file.read': 'file_read',
    'file.metadata': 'file_read',
    # 信息收集（我们新增：凭据是强源，不只是路径提示）
    'information.credentials': 'credential_access',
    'information.environment': 'env_access',
    'information.system': 'env_access',
    # 原生/提权
    'native.access': 'privilege',
}

# 能力 → 危险层级（沿用 sso_extractor.CAPABILITY_TIER 的口径 + 新增）
CAPABILITY_TIER: Dict[str, int] = {
    'process_spawn': 1,
    'code_eval': 1,
    'network_out': 1,
    'privilege': 1,
    'credential_access': 1,   # 新增：读凭据本身就是攻击链起点
    'network_in': 2,
    'deserialize': 2,
    'decode': 2,
    'file_write': 2,
    'env_access': 3,
    'file_read': 3,
}

_TIER_SEVERITY = {1: 'critical', 2: 'high', 3: 'medium'}

# 数据类边（进污点分析）；control 只给 LLM 看
_EDGE_DATA = 'data'
_EDGE_CALL = 'call'
_EDGE_CONTROL = 'control'

# 这些 GIR operation 产生"值"（有 target），可作为数据边源头
_PVAR_RE = re.compile(r'%([A-Za-z_][A-Za-z0-9_]*)')
_VAR_NAME_RE = re.compile(r'%?[A-Za-z_]\w*')

_VALUE_OPS = {
    'call_stmt', 'object_call_stmt', 'new_array', 'assign', 'array_write',
    'binary_op_stmt', 'unary_op_stmt', 'attribute_stmt',
}


def map_capability(pyflow_cap: str) -> Optional[str]:
    """PyFlow capability → 我们的能力类（未映射的返回 None）"""
    return CAPABILITY_MAP.get(pyflow_cap)


def severity_for(cap: str) -> str:
    return _TIER_SEVERITY.get(CAPABILITY_TIER.get(cap, 3), 'medium')


# ===== 子进程调用 =====

class PyFlowError(RuntimeError):
    pass


def _run(args: List[str], timeout: int, cwd: Optional[str] = None) -> str:
    binp = pyflow_bin()
    if not binp:
        raise PyFlowError('pyflow binary not found')
    env = dict(os.environ)
    env.setdefault('PYTHONWARNINGS', 'ignore')
    try:
        p = subprocess.run([binp] + args, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd, env=env)
    except subprocess.TimeoutExpired:
        raise PyFlowError(f'timeout after {timeout}s: {" ".join(args[:2])}')
    if p.returncode not in (0, 1):     # 1 = findings present (exit-code-policy)
        raise PyFlowError(f'rc={p.returncode}: {(p.stderr or "")[:300]}')
    return p.stdout


def _json_or_none(txt: str):
    txt = (txt or '').strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None


# ===== 三个 PyFlow 产物的解析 =====

def run_capabilities(project_dir, max_seconds: int = 60,
                     capability_model: Optional[str] = None) -> Dict:
    """pyflow capabilities -r --format json → findings + coverage"""
    args = ['capabilities', '-r', '--format', 'json',
            '--max-seconds', str(max_seconds)]
    if capability_model and Path(capability_model).exists():
        args += ['--capability-model', str(capability_model)]
    args.append(str(project_dir))
    data = _json_or_none(_run(args, timeout=max_seconds + 60))
    if not isinstance(data, dict):
        raise PyFlowError('capabilities: no JSON output')
    return data


def run_gir(project_dir, max_seconds: int = 90) -> Dict:
    """pyflow ir -r --dump-gir --dump-format json → {unit: [stmt...]}"""
    args = ['ir', '-r', '--dump-gir', '--dump-format', 'json',
            str(project_dir)]
    data = _json_or_none(_run(args, timeout=max_seconds + 60))
    return data if isinstance(data, dict) else {}


def run_callgraph(project_dir, max_seconds: int = 60) -> Dict:
    """pyflow callgraph -r --json-schema unified → graph / unresolved / external"""
    args = ['callgraph', '-r', '--json-schema', 'unified',
            '--format', 'json',
            '--max-seconds', str(max_seconds), str(project_dir)]
    data = _json_or_none(_run(args, timeout=max_seconds + 60))
    return data if isinstance(data, dict) else {}


# ===== 源码回填 =====

_SRC_CACHE: Dict[str, List[str]] = {}


def _source_line(path: str, line: int) -> str:
    """按 1-based 行号取源码行（带缓存）。失败返回空串。"""
    if not path or line <= 0:
        return ''
    lines = _SRC_CACHE.get(path)
    if lines is None:
        try:
            lines = Path(path).read_text(encoding='utf-8', errors='ignore').splitlines()
        except Exception:
            lines = []
        _SRC_CACHE[path] = lines
    if line <= len(lines):
        return lines[line - 1].strip()
    return ''


# ===== GIR → 节点 =====

def _gir_units(gir: Dict) -> List[Tuple[str, List[Dict]]]:
    """GIR 顶层是 {'<func>_gir.json': [stmt...]}；取出 (unit, stmts)"""
    out = []
    for key, val in (gir or {}).items():
        if isinstance(val, list):
            unit = key[:-len('_gir.json')] if key.endswith('_gir.json') else key
            out.append((unit, val))
    return out


def _stmt_of(stmt: Dict) -> Dict:
    """GIR 语句里带位置且能算"一行代码"的字段集合"""
    return {
        'row': stmt.get('start_row'),      # 0-based
        'col': stmt.get('start_col') or 0,
        'op': stmt.get('operation') or '',
        'target': stmt.get('target') or '',
        'receiver': stmt.get('receiver_object') or '',
        'field': stmt.get('field') or '',
        'args': stmt.get('positional_args') or '',
        'callee': stmt.get('name') or '',
        'named': stmt.get('named_args') or '',
        'stmt_id': stmt.get('stmt_id'),
        'parent': stmt.get('parent_stmt_id'),
    }


def _build_file_index(project_dir: Path):
    """三层索引，解决 PyFlow unit_id 的三种形态。

    PyFlow 的单元标识不一致（实测）：
        requests.<module>            ← 模块级（不是 requests.__init__）
        BaseAdapter.__init__          ← 类方法（**不带模块前缀**）
        ab100.pkg.setup.<module>      ← 带路径的模块级

    所以需要：
        path_index     点分路径 → 文件（requests.__init__ → .../requests/__init__.py）
        module_index   模块名   → 文件（requests → .../requests/__init__.py）
        qualname_index 限定名   → 文件（BaseAdapter.__init__ → .../requests/adapters.py）
    """
    path_index: Dict[str, str] = {}
    module_index: Dict[str, str] = {}
    qualname_index: Dict[str, str] = {}
    root = Path(project_dir)

    for p in root.rglob('*.py'):
        if '__pycache__' in str(p) or '.ddg_output' in str(p):
            continue
        try:
            rel = p.relative_to(root).with_suffix('')
        except ValueError:
            continue
        dotted = str(rel).replace(chr(92), '/').replace('/', '.')
        abs_path = str(p.resolve())
        path_index[dotted] = abs_path
        # 模块名：requests.__init__ → requests
        mod = dotted[:-len('.__init__')] if dotted.endswith('.__init__') else dotted
        module_index.setdefault(mod, abs_path)
        # 限定名索引（AST 扫描，每文件毫秒级）
        try:
            import ast as _ast
            tree = _ast.parse(p.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            continue
        for node in tree.body:
            if isinstance(node, _ast.ClassDef):
                qualname_index.setdefault(node.name, abs_path)
                for sub in node.body:
                    if isinstance(sub, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                        qualname_index.setdefault(f'{node.name}.{sub.name}', abs_path)
            elif isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                qualname_index.setdefault(node.name, abs_path)
    return path_index, module_index, qualname_index


def _resolve_unit_file(unit_id: str, index) -> Tuple[str, str]:
    """unit_id → (绝对路径, 函数名)。三层回落：路径 → 模块 → 限定名。"""
    path_index, module_index, qualname_index = index
    if not unit_id:
        return '', '<module>'

    # ① 模块级：xxx.<module> → 模块名查
    if unit_id.endswith('.<module>'):
        mod = unit_id[:-len('.<module>')]
        if mod in module_index:
            return module_index[mod], '<module>'
        if mod in path_index:
            return path_index[mod], '<module>'
        # 带路径前缀的形态（ab100.pkg.setup）→ 取最长后缀匹配
        parts = mod.split('.')
        for i in range(len(parts)):
            cand = '.'.join(parts[i:])
            if cand in module_index:
                return module_index[cand], '<module>'

    # ② 点分路径前缀匹配（旧逻辑，处理带路径的 unit_id）
    best = ''
    for dotted in path_index:
        if unit_id == dotted or unit_id.startswith(dotted + '.'):
            if len(dotted) > len(best):
                best = dotted
    if best:
        rest = unit_id[len(best):].lstrip('.')
        func = rest.split('.')[-1] if rest else '<module>'
        return path_index[best], (func or '<module>')

    # ③ 限定名回落（BaseAdapter.__init__ 这种裸名）
    for cand in (unit_id, unit_id.split('.')[-1],
                 '.'.join(unit_id.split('.')[-2:])):
        if cand in qualname_index:
            parts = unit_id.split('.')
            # 裸函数名（无点号）= 顶层函数，不是模块级——这里曾把
            # 86.6% 的节点误标成 <module>（实测 requsets 8625/9959）
            return qualname_index[cand], (parts[-1] if len(parts) > 1 else unit_id)
    return '', '<module>'


def build_nodes(gir: Dict, caps: Dict, project_dir: Path,
                sso_result: Optional[Dict] = None) -> List[Dict]:
    """GIR 语句 → 我们的节点 dict（语句级，带真实行号与源码）。

    capability 由 capabilities findings 按 (file, line) 对齐后标注。
    """
    # capability 索引：绝对路径 + 行号 → 能力类（PyFlow ∪ 我们的 SSO）
    # 两个引擎盲区互补：PyFlow 有 IFDS/别名，SSO 有常量折叠/getattr 还原
    from src.engine_merge import merge_capabilities, pick_capability
    cap_by_loc, module_level_by_loc = merge_capabilities(
        caps, sso_result, project_dir)

    file_index = _build_file_index(project_dir)   # (path, module, qualname)
    nodes: List[Dict] = []
    seen: Set[str] = set()
    root = Path(project_dir)
    # 2026-11 归属顺序（实测驱动）：GIR 的 `<模块>_gir.json` 单元是**整文件
    # 超集**（test_requests.py 的 module 单元含 3320 条语句、覆盖 L1-2760），
    # 若先处理它，所有节点的 function_name 都会变成 <module>（实测 67-86%）。
    # 先处理具体函数单元，再用 module 单元补剩余的模块级语句。
    _units = _gir_units(gir)
    _units.sort(key=lambda kv: (kv[0].endswith('.<module>'), kv[0]))
    for unit, stmts in _units:
        # unit 形如 "setup.<module>" / "pkg.mod.func"
        head = unit.split('@')[0]
        for raw in stmts:
            s = _stmt_of(raw)
            if s['row'] is None:
                continue                       # method_decl 之类无坐标
            fpath = raw.get('file') or raw.get('filename') or ''
            func_name = head.rsplit('.', 1)[-1] if '.' in head else head
            if head.endswith('.<module>'):
                func_name = '<module>'
            if fpath:
                fpath = str(Path(fpath).resolve())
            else:
                # 真实 PyFlow GIR 不带 filename，但每条有 unit_id
                fpath, func_name = _resolve_unit_file(
                    raw.get('unit_id') or '', file_index)
            if not fpath:
                continue
            line1 = int(s['row']) + 1          # GIR 0-based → 1-based
            code = _source_line(fpath, line1)
            if not code:
                code = f"{s['receiver']}.{s['field']}({s['args']})" if s['field'] else s['op']
            try:
                rel = str(Path(fpath).relative_to(root)).replace('\\', '/')
            except Exception:
                rel = Path(fpath).name
            node_id = f"{rel}:{line1}:{s['col']}"
            if node_id in seen:
                continue
            seen.add(node_id)
            caps_here = cap_by_loc.get((fpath, line1)) or set()
            cap = pick_capability(caps_here)
            _ml = module_level_by_loc.get((fpath, line1))
            nodes.append({
                'node_id': node_id,
                'file': fpath,                 # 绝对路径：digest._source_line 需要
                'line': line1,
                'type': s['op'] or 'stmt',
                'code': code,
                'function_name': func_name,
                'class_name': None,
                'capability': cap,
                'is_dangerous': bool(cap) and CAPABILITY_TIER.get(cap, 9) == 1,
                'severity': severity_for(cap) if cap else 'safe',
                '_stmt_id': s['stmt_id'],
                '_unit': head,
                'module_level': _ml,
                'phase': _phase_of(_ml, fpath, func_name),
            })
    return nodes


def _arg_var_names(blob) -> Set[str]:
    """从 GIR 的 positional_args/named_args 里解析变量名。

    GIR 的实参是 Python 列表的 repr，元素有两种：
        '%vv2'      → 临时变量（去 % 后比对）
        'data'      → 用户变量（裸名）
        "'AWS_SECRET'" → 字符串字面量（不是变量）
    早期只认 % 前缀，导致 `data = decode(); os.system(data)` 这种最
    常见的形态断链。
    """
    out: Set[str] = set()
    s = str(blob or '').strip()
    if not s:
        return out
    try:
        vals = ast.literal_eval(s)
        if isinstance(vals, (list, tuple)):
            for v in vals:
                if isinstance(v, str) and _VAR_NAME_RE.fullmatch(v):
                    out.add(v.lstrip('%'))
            return out
    except Exception:
        pass
    for m in _PVAR_RE.finditer(s):
        out.add(m.group(1))
    return out


def build_edges(gir: Dict, nodes: List[Dict], callgraph: Dict,
                project_dir: Path) -> List[Dict]:
    """三类边：data（GIR 值流）/ call（callgraph）/ control（语句序）"""
    by_id = {n['node_id']: n for n in nodes}
    edges: List[Dict] = []
    seen: Set[Tuple[str, str, str]] = set()

    def _add(a: str, b: str, kind: str, var: str = ''):
        if not a or not b or a == b:
            return
        if a not in by_id or b not in by_id:
            return
        sig = (a, b, kind)
        if sig in seen:
            return
        seen.add(sig)
        edges.append({'from_node': a, 'to_node': b, 'kind': kind,
                      'variable': var,
                      'from_file': by_id[a]['file'], 'to_file': by_id[b]['file'],
                      'is_cross_file': by_id[a]['file'] != by_id[b]['file']})

    root = Path(project_dir)
    file_index = _build_file_index(project_dir)
    for unit, stmts in _gir_units(gir):
        head = unit.split('@')[0]
        # --- control：同 unit 语句顺序（保留我们已验证的 +17% 机制）---
        seq = []
        for raw in stmts:
            s = _stmt_of(raw)
            if s['row'] is None:
                continue
            fpath = raw.get('file') or raw.get('filename') or ''
            if fpath:
                fpath = str(Path(fpath).resolve())
            else:
                fpath, _fn = _resolve_unit_file(raw.get('unit_id') or '', file_index)
            if not fpath:
                continue
            try:
                rel = str(Path(fpath).relative_to(root)).replace(chr(92), '/')
            except Exception:
                rel = Path(fpath).name
            nid = f"{rel}:{int(s['row']) + 1}:{s['col']}"
            if nid in by_id:
                seq.append((nid, s))
        for i in range(len(seq) - 1):
            _add(seq[i][0], seq[i + 1][0], _EDGE_CONTROL, 'next_stmt')

        # --- data：GIR 值流（target 定义 → 后续引用）---
        # GIR 的 args 形如 "[%vv1, %vv2]"——`%vv` 变量可能紧贴括号，
        # 用正则提取而不是 split（split 会把 "[%vv1," 当成一个 token）
        defs: Dict[str, str] = {}
        for nid, s in seq:
            tgt = s['target']
            if tgt and tgt.startswith('%'):
                defs.setdefault(tgt.strip('[](),').lstrip('%'), nid)
            for blob in (s['args'], s['named']):
                for r in _arg_var_names(blob):
                    src = defs.get(r)
                    if src:
                        _add(src, nid, _EDGE_DATA, r)
            # receiver 形如 '%vv2'（对象变量）
            for r in _PVAR_RE.findall(str(s.get('receiver') or '')):
                src = defs.get(r)
                if src:
                    _add(src, nid, _EDGE_DATA, r)

    # --- 过程间边（2026-11，修"每对函数只有 1 条代表边"）---
    # GIR 的 call_stmt 带被调函数名 (name='decode')，可以在**语句级**
    # 建两条跨函数边：
    #   调用语句 → 被调函数首语句   (kind=call)
    #   被调函数 return 语句 → 调用语句 (kind=return)
    # 这样 source.py 的 return 才能连到 transform.py 的 b64decode 参数，
    # 再连到 main.py 的 os.system——真实的跨文件链。
    fn_entries: Dict[str, List[str]] = {}
    fn_returns: Dict[str, List[str]] = {}
    for unit, stmts in _gir_units(gir):
        for raw in stmts:
            s = _stmt_of(raw)
            if s['row'] is None:
                continue
            fpath = raw.get('file') or ''
            if fpath:
                fpath = str(Path(fpath).resolve())
            else:
                fpath, _fn = _resolve_unit_file(raw.get('unit_id') or '', file_index)
            if not fpath:
                continue
            try:
                rel = str(Path(fpath).relative_to(root)).replace(chr(92), '/')
            except Exception:
                rel = Path(fpath).name
            nid = f"{rel}:{int(s['row']) + 1}:{s['col']}"
            if nid not in by_id:
                continue
            fname = by_id[nid].get('function_name') or '<module>'
            fn_entries.setdefault(fname, []).append(nid)
            if 'return' in (s['op'] or '').lower():
                fn_returns.setdefault(fname, []).append(nid)

    for unit, stmts in _gir_units(gir):
        for raw in stmts:
            s = _stmt_of(raw)
            if s['row'] is None or not s.get('callee'):
                continue
            fpath = raw.get('file') or ''
            if fpath:
                fpath = str(Path(fpath).resolve())
            else:
                fpath, _fn = _resolve_unit_file(raw.get('unit_id') or '', file_index)
            if not fpath:
                continue
            try:
                rel = str(Path(fpath).relative_to(root)).replace(chr(92), '/')
            except Exception:
                rel = Path(fpath).name
            call_nid = f"{rel}:{int(s['row']) + 1}:{s['col']}"
            if call_nid not in by_id:
                continue
            callee = s['callee'].split('.')[-1]
            for entry in (fn_entries.get(callee) or [])[:1]:
                _add(call_nid, entry, _EDGE_CALL, callee)
            for ret in (fn_returns.get(callee) or [])[:3]:
                _add(ret, call_nid, 'return', callee)

    # --- call：callgraph 函数级 → 函数首节点的代表边（补充）---
    # 2026-11 修正（实测 dist_meta：PyFlow 给出 145 条调用/110 条跨模块，
    # 我们此前只接住 19/3 条）。原因是 callgraph 用**全限定名**
    # (dist_meta._utils._parse_version)，而 GIR 的 unit 键是**裸名**
    # (_parse_version)，直接查表必然落空。
    # 修法：用每个节点的 (模块点分名, 函数名) 建多键索引。
    graph = (callgraph or {}).get('graph') or {}
    if graph:
        first_of: Dict[str, str] = {}
        for n in nodes:
            nid = n['node_id']
            fpath = n.get('file') or ''
            fname = n.get('function_name') or '<module>'
            try:
                rel = Path(fpath).relative_to(root).with_suffix('')
                mod = str(rel).replace(chr(92), '/').replace('/', '.')
                if mod.endswith('.__init__'):
                    mod = mod[:-len('.__init__')]
            except Exception:
                mod = ''
            # 全限定名优先（最精确）
            if mod and fname != '<module>':
                first_of.setdefault(f'{mod}.{fname}', nid)
            # 模块级
            if fname == '<module>' and mod:
                first_of.setdefault(mod, nid)
            first_of.setdefault(fname, nid)          # 裸名兜底

        def _lookup(name: str):
            if name in first_of:
                return first_of[name]
            # 去掉包前缀再试（dist_meta._utils.f -> _utils.f）
            parts = name.split('.')
            for i in range(1, len(parts)):
                cand = '.'.join(parts[i:])
                if cand in first_of:
                    return first_of[cand]
            return None

        matched = 0
        for caller, callees in graph.items():
            src = _lookup(caller)
            if not src:
                continue
            for callee in (callees or [])[:20]:
                dst = _lookup(callee)
                if dst:
                    _add(src, dst, _EDGE_CALL, callee.rsplit('.', 1)[-1])
                    matched += 1
        if matched:
            print(f"          [PyFlow] 调用边接入 {matched} 条")
    return edges


# ===== 执行时机（我们独有的 PyPI 威胁模型）=====

def execution_phase(node: Dict, project_dir: Path) -> str:
    """节点所在代码的执行时机：install / import / runtime。

    module_level 由 SSO 的 AST 判定（比文件名启发准确）；缺失时回落。
    """
    from src.engine_merge import phase_of
    ml = node.get('module_level')
    return phase_of(ml, node.get('file') or '', node.get('function_name'))


def _phase_of(module_level, filepath, func_name) -> str:
    from src.engine_merge import phase_of
    return phase_of(module_level, filepath, func_name)


# ===== 对外主入口 =====

def analyze(project_dir, max_seconds: int = 60,
            capability_model: Optional[str] = None) -> Optional[Dict]:
    """跑 PyFlow 并把结果翻译成我们的 canonical graph。

    Returns:
        {
          'nodes': [...], 'edges': [...],
          'capabilities': {cap: count},
          'coverage': {...全量保留...},
          'security_report': {...下游要的字段...},
          'backend': 'pyflow',
        }
        失败/不可用返回 None（调用方回退 builtin）
    """
    if not available():
        return None
    root = Path(project_dir)
    try:
        caps = run_capabilities(root, max_seconds=max_seconds,
                                capability_model=capability_model)
        gir = run_gir(root, max_seconds=max_seconds + 30)
        cg = run_callgraph(root, max_seconds=max_seconds)
    except PyFlowError as e:
        print(f"          [PyFlow] 分析失败: {e}")
        return None

    # SSO ∪ PyFlow：补 PyFlow 的 getattr/常量折叠盲区
    from src.engine_merge import collect_sso
    sso = collect_sso(root)
    if sso:
        n_sso = len(sso.get('findings') or [])
        print(f"          [SSO] {n_sso} 个能力命中（与 PyFlow 合并）")
    nodes = build_nodes(gir, caps, root, sso_result=sso)
    if not nodes:
        # GIR 为空（单文件目录/结构异常）时，用能力命中点合成节点。
        # 能力命中本身带着 file:line，足以支撑下游的 digest 与判定；
        # 只是没有语句间边（链验证会退化为单节点证据）。
        from src.engine_merge import merge_capabilities, pick_capability
        cap_by_loc, ml_by_loc = merge_capabilities(caps, sso, root)
        for (fpath, line), capset in sorted(cap_by_loc.items()):
            cap = pick_capability(capset)
            if not cap:
                continue
            try:
                rel = str(Path(fpath).relative_to(root)).replace(chr(92), '/')
            except Exception:
                rel = Path(fpath).name
            nodes.append({
                'node_id': f"{rel}:{line}:0",
                'file': fpath, 'line': line, 'type': 'stmt',
                'code': _source_line(fpath, line) or cap,
                'function_name': '<module>', 'class_name': None,
                'capability': cap, 'is_dangerous': CAPABILITY_TIER.get(cap, 9) == 1,
                'severity': severity_for(cap),
                'module_level': ml_by_loc.get((fpath, line)),
                'phase': _phase_of(ml_by_loc.get((fpath, line)), fpath, '<module>'),
            })
        if nodes:
            print(f"          [PyFlow] GIR 为空，用能力命中合成 {len(nodes)} 个节点")
    if not nodes:
        print("          [PyFlow] 未产出任何节点")
        return None
    edges = build_edges(gir, nodes, cg, root)

    # capability 统计（我们口径）
    counts: Dict[str, int] = {}
    for n in nodes:
        c = n.get('capability')
        if c:
            counts[c] = counts.get(c, 0) + 1

    # 执行时机分布（我们独有的窗口）
    phases: Dict[str, int] = {}
    for n in nodes:
        if n.get('capability'):
            ph = n.get('phase') or execution_phase(n, root)
            phases[ph] = phases.get(ph, 0) + 1

    coverage = caps.get('coverage') or {}
    by_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for n in nodes:
        sev = n.get('severity') or 'safe'
        if sev in by_sev:
            by_sev[sev] += 1

    report = {
        'total_issues': sum(counts.values()),
        'by_severity': by_sev,
        'risk_level': ('critical' if by_sev['critical'] else
                       'high' if by_sev['high'] else
                       'medium' if by_sev['medium'] else 'low'),
        'capabilities': counts,
        'execution_phases': phases,
        'coverage': coverage,
        'backend': 'pyflow',
    }
    return {
        'nodes': nodes,
        'edges': edges,
        'capabilities': counts,
        'execution_phases': phases,
        'coverage': coverage,
        'security_report': report,
        'backend': 'pyflow',
    }


# ===== 对象模型 shim：让 _run_ddg_builder 的下游代码零改动 =====

class _Node:
    """GlobalNode 的最小替身（下游只用这些属性）"""
    __slots__ = ('file', 'line', 'col_offset', 'type', 'source',
                 'function_name', 'class_name', 'resolved_call',
                 'sink_expansion', 'taint_categories', 'capability')

    def __init__(self, d: Dict):
        self.file = d.get('file', '')
        self.line = int(d.get('line') or 0)
        self.col_offset = int(d.get('col') or 0)
        self.type = d.get('type') or 'stmt'
        self.source = d.get('code') or ''
        self.function_name = d.get('function_name')
        self.class_name = d.get('class_name')
        self.resolved_call = None
        self.sink_expansion = False
        self.taint_categories = None
        self.capability = d.get('capability') or ''

    def get_id(self) -> str:
        return f"{self.file}_{self.line}_{self.col_offset}"


class _Edge:
    """GlobalEdge 的最小替身"""
    __slots__ = ('from_node', 'to_node', 'variable', 'function', 'type',
                 'edge_kind', 'severity', 'finding_type')

    def __init__(self, a: _Node, b: _Node, kind: str, variable: str = ''):
        self.from_node = a
        self.to_node = b
        self.variable = variable or ''
        self.function = a.function_name or ''
        self.type = kind if kind in ('data', 'control') else 'data'
        self.edge_kind = kind
        self.severity = None
        self.finding_type = None

    def to_dict(self) -> Dict:
        return {
            'from_file': self.from_node.file, 'from_line': self.from_node.line,
            'to_file': self.to_node.file, 'to_line': self.to_node.line,
            'variable': self.variable, 'function': self.function,
            'type': self.type, 'edge_kind': self.edge_kind,
        }


class _Funcs(dict):
    pass


class _SymbolTable:
    def __init__(self, functions: Dict, classes: Dict):
        self.functions = functions
        self.classes = classes


def build_result(project_dir, max_seconds: int = 60,
                 capability_model: Optional[str] = None) -> Optional[Dict]:
    """产出与 DDGBuilderV7.build() 同形的 dict，供 _run_ddg_builder 下游直接消费。

    这样 `sub_ddgs/*`、`self._full_graph`、`taint_chains.json`、
    `security_report.json` 全部沿用现有代码路径——换的只是图从哪来。
    """
    base = analyze(project_dir, max_seconds=max_seconds,
                   capability_model=capability_model)
    if not base:
        return None

    import networkx as nx

    node_objs: List[_Node] = []
    by_id: Dict[str, _Node] = {}
    for d in base['nodes']:
        o = _Node(d)
        nid = o.get_id()
        if nid in by_id:
            continue
        by_id[nid] = o
        node_objs.append(o)

    edges: List[_Edge] = []
    for e in base['edges']:
        # 直接按 (file,line,col) 重组 id，与 _Node.get_id() 对齐
        def _lookup(raw_id: str):
            parts = raw_id.rsplit(':', 2)
            if len(parts) != 3:
                return None
            f, ln, col = parts
            return by_id.get(f"{f}_{ln}_{col}")
        a = _lookup(e['from_node'])
        b = _lookup(e['to_node'])
        if a and b:
            edges.append(_Edge(a, b, e.get('kind') or 'data',
                               e.get('variable') or ''))

    # nx_graph：下游 SuspiciousNodeDetector 需要 node attrs['source']
    G = nx.DiGraph()
    for o in node_objs:
        nid = o.get_id()
        G.add_node(nid, file=o.file, line=o.line, type=o.type,
                   source=o.source, function_name=o.function_name,
                   class_name=o.class_name, resolved_call=None,
                   sink_expansion=False, taint_categories=None,
                   capability=o.capability)
    for e in edges:
        G.add_edge(e.from_node.get_id(), e.to_node.get_id(),
                   variable=e.variable, function=e.function,
                   type=e.type, edge_kind=e.edge_kind)

    # symbol_table：functions 按 (file, name) 建
    functions: Dict = {}
    for o in node_objs:
        key = (o.file, o.function_name or '<module>')
        if key not in functions:
            functions[key] = {
                'file': o.file, 'name': key[1], 'short_name': key[1],
                'line': o.line, 'params': [], 'class': o.class_name,
            }
    symbols = _SymbolTable(functions, {})

    report = dict(base['security_report'])
    report['backend'] = 'pyflow'
    return {
        'nodes': {k: v for k, v in by_id.items()},
        'edges': edges,
        'nx_graph': G,
        'symbol_table': symbols,
        'cross_file_calls': [],
        'cfg_manager': None,
        'inter_proc_cfg': None,
        'fast_scan_results': {},
        'security_report': report,
        'call_graph': {},
        'function_summaries': {},
        'side_effects': {},
        'attack_chains': [],
        # 我们的扩展字段（下游可读，不影响现有逻辑）
        'capabilities': base['capabilities'],
        'execution_phases': base['execution_phases'],
        'coverage': base['coverage'],
        'backend': 'pyflow',
    }

