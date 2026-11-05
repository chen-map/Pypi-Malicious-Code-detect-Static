# -*- coding: utf-8 -*-
"""SSO 提取器（Security-Sensitive Operation Extractor）· PyPI 适配版

设计定位（2026-11）：
    粗筛 —— 只回答「这个包里哪些位置值得细看」，**不判恶意**。
    细判 —— 围绕 SSO 建图，由 LLM 读图提炼链路并判定。

与 MalSkills 的关系：
    架构借鉴（SSO 提取 → 依赖图 → 行为推理），但对齐 PyPI 的威胁模型：
    - 安装期执行（setup.py 顶层代码）在 PyPI 是最关键的攻击面，
      agent skill 里不存在对应概念
    - import 期执行（__init__.py 顶层）是 PyPI 独有的传播途径
    - 依赖混淆（install_requires 里的私有/内网包名）是 PyPI 独有
    - 凭据路径（.pypirc / .netrc / .aws/credentials）是 PyPI 攻击者的首要目标

关键约束：
    1. **能力中性**：不说"恶意 API"，只说"这个调用具备什么能力"
    2. **高召回**：宁可多圈（漏掉的永远不会进细判）
    3. **零判定**：不输出任何恶意/危险/严重度标签
    4. **结合上下文**：区分 module 级（import/安装即执行）与函数级
"""
import ast
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ===== 能力清单（PyPI 威胁模型）=====
# 每个能力对应一组标准库/常见第三方 API 的**解析后名字**（不含点号的尾部通配）
# 注意：这是「能力」，不是「恶意」。os.environ 在正经配置加载里也用。
SSO_CAPABILITIES: Dict[str, Tuple[str, ...]] = {
    'process_spawn': (
        'os.system', 'os.popen', 'os.exec', 'os.execv', 'os.execl', 'os.execve',
        'os.spawn', 'os.spawnv', 'os.posix_spawn', 'os.fork',
        'subprocess.run', 'subprocess.call', 'subprocess.check_call',
        'subprocess.check_output', 'subprocess.Popen', 'pty.spawn',
        'multiprocessing.Process',
    ),
    'code_eval': (
        'exec', 'eval', 'compile', '__import__',
        'importlib.import_module', 'importlib.__import__',
        'builtins.exec', 'builtins.eval', 'builtins.compile',
        'runpy.run_path', 'runpy.run_module',
        'code.InteractiveInterpreter', 'types.FunctionType',
    ),
    'network_in': (
        'requests.get', 'requests.head', 'requests.request',
        'urllib.request.urlopen', 'urllib.request.urlretrieve',
        'urllib.urlopen', 'urlopen',
        'httpx.get', 'httpx.stream',
        'socket.recv', 'socket.recv_into', 'socket.recvfrom',
        'aiohttp.ClientSession.get', 'http.client.HTTPSConnection',
    ),
    'network_out': (
        'requests.post', 'requests.put', 'requests.patch',
        'httpx.post', 'httpx.put',
        'socket.send', 'socket.sendall', 'socket.sendto',
        'smtplib.SMTP', 'smtplib.SMTP_SSL',
        'ftplib.FTP', 'ftplib.FTP_TLS',
        'urllib.request.urlopen',   # 双向：既读也发
        'telegram.Bot.send_message', 'discord.Webhook',
    ),
    'file_read': (
        'open', 'io.open', 'pathlib.Path.read_text', 'pathlib.Path.read_bytes',
        'os.listdir', 'os.scandir', 'os.walk', 'shutil.copy',
    ),
    'file_write': (
        'open', 'io.open', 'pathlib.Path.write_text', 'pathlib.Path.write_bytes',
        'shutil.copy', 'shutil.copyfile', 'shutil.move', 'os.rename', 'os.remove',
        'os.makedirs', 'os.mkdir',
    ),
    'deserialize': (
        'pickle.loads', 'pickle.load', 'marshal.loads', 'marshal.load',
        'yaml.load', 'yaml.unsafe_load', 'dill.loads', 'dill.load',
        'json.loads', 'shelve.open',
    ),
    'decode': (
        'base64.b64decode', 'base64.b32decode', 'base64.b16decode',
        'base64.urlsafe_b64decode', 'codecs.decode', 'binascii.unhexlify',
        'zlib.decompress', 'lzma.decompress', 'bz2.decompress',
        'bytes.fromhex', 'bytes.decode', 'str.encode',
    ),
    'env_access': (
        'os.environ', 'os.getenv', 'os.environ.get', 'os.environ.setdefault',
    ),
    'privilege': (
        'os.setuid', 'os.setgid', 'os.chmod', 'os.chown', 'os.umask',
        'ctypes.CDLL', 'ctypes.cdll', 'ctypes.windll', 'ctypes.LoadLibrary',
    ),
}

# ===== 能力分级（2026-11，大包过滤驱动）=====
# env_access / file_read 在正经代码里几乎每个文件都有（agent_framework:
# env_access 358 次），拿它们做过滤条件等于不过滤。按"进攻价值"分级，
# 建图时优先保留高价值能力的文件。
CAPABILITY_TIER: Dict[str, int] = {
    # Tier 1：直接导致代码/命令执行、外传、提权——必须建图
    'process_spawn': 1,
    'code_eval': 1,
    'network_out': 1,
    'privilege': 1,
    # Tier 2：攻击链的常见中间环节
    'network_in': 2,
    'deserialize': 2,
    'decode': 2,
    'file_write': 2,
    # Tier 3：良性代码里的日常操作，仅在预算充裕时纳入
    'env_access': 3,
    'file_read': 3,
}

# 清单外但仍值得注意的 API 词（兜底通道，不参与能力判定）
# 这些是「可能承载能力但不在 SSO 主清单」的名字——用于发现覆盖盲区，
# 引擎在未覆盖文件里扫到它们时会提高该文件的注意级别。
FALLBACK_API_HINTS = (
    'ctypes', 'cffi', 'dlopen', 'mmap', 'system(', 'popen', 'spawn',
    'exec', 'eval', 'compile(', 'importlib', '__import__',
    'urlopen', 'urlretrieve', 'socket', 'connect', 'HttpClient',
    'b64decode', 'fromhex', 'unhexlify', 'decompress', 'loads(',
    'chmod', 'setuid', 'ptrace', 'ioctl', 'LD_PRELOAD', 'sitecustomize',
)

# 凭据/敏感路径（字符串证据，来自常量扫描）
CREDENTIAL_HINTS = (
    '.ssh/', 'id_rsa', '.aws/credentials', '.netrc', '.pypirc', '.git-credentials',
    '.kube/config', '.docker/config.json', 'wallet.dat', 'keychain',
    '.npmrc', '.config/gcloud', 'cookies.sqlite',
)

# 系统持久化路径
PERSISTENCE_HINTS = (
    '.bashrc', '.bash_profile', '.zshrc', '.profile', '/etc/cron', 'crontab',
    '/etc/systemd', 'LaunchAgents', 'Startup/', 'sitecustomize.py', 'usercustomize.py',
)


def _strip_idiom_prefix(name: str) -> str:
    """把 `builtins.exec` / `__builtin__.exec` 之类前缀归一"""
    for pre in ('builtins.', '__builtin__.', 'six.moves.'):
        if name.startswith(pre):
            return name[len(pre):]
    return name


def _match_capability(resolved: str) -> Optional[str]:
    """把一个解析后的调用名映射到能力类别。

    匹配规则：完全相等，或 `resolved.startswith(sso + '.')`（模块级调用）。
    """
    r = _strip_idiom_prefix(resolved or '')
    if not r:
        return None
    for cap, names in SSO_CAPABILITIES.items():
        for sso in names:
            if r == sso or r.startswith(sso + '.'):
                return cap
    return None


class _SSOVisitor(ast.NodeVisitor):
    """AST 遍历：收集调用点 + 常量证据，并记录所在函数与是否 module 级。"""

    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.findings: List[Dict] = []
        self.strings: List[str] = []      # 所有字符串常量（用于凭据/持久化扫描）
        self._func_stack: List[str] = []
        self._module = '<module>'
        # 2026-11 别名解析：`from os import system as run` / `import subprocess as sp`
        # / `e = eval` 都必须还原到真实 API，否则粗筛会漏掉最常见的写法。
        self._aliases: Dict[str, str] = {}

    def visit_Import(self, node):
        for a in node.names:
            if a.asname:
                self._aliases[a.asname] = a.name
            else:
                top = a.name.split('.')[0]
                self._aliases[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ''
        for a in node.names:
            full = f'{mod}.{a.name}' if mod else a.name
            self._aliases[a.asname or a.name] = full
        self.generic_visit(node)

    def visit_Assign(self, node):
        # 简单赋值别名：e = eval / runner = subprocess.Popen
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            src = self._resolve_call_name(node.value)
            if src and _match_capability(src):
                self._aliases[target] = src
        self.generic_visit(node)
    # --- 作用域追踪 ---
    def visit_FunctionDef(self, node):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    # --- 字符串常量收集 ---
    def visit_Constant(self, node):
        if isinstance(node.value, str) and 3 <= len(node.value) <= 300:
            self.strings.append(node.value)
        self.generic_visit(node)

    # --- 调用点 ---
    def visit_Call(self, node):
        name = self._resolve_call_name(node.func)
        if name:
            cap = _match_capability(name)
            if cap:
                scope = '.'.join(self._func_stack) if self._func_stack else self._module
                self.findings.append({
                    'file': self.rel_path,
                    'line': getattr(node, 'lineno', 0),
                    'api': name,
                    'capability': cap,
                    'scope': scope,
                    'module_level': not self._func_stack,
                })
        self.generic_visit(node)

    def _resolve_call_name(self, func) -> str:
        """把调用表达式还原成点号名（处理 Name / Attribute / getattr 常量折叠）"""
        if isinstance(func, ast.Name):
            return self._aliases.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            base = self._resolve_call_name(func.value)
            return f'{base}.{func.attr}' if base else func.attr
        if isinstance(func, ast.Call):
            # getattr(obj, 'name') 常量折叠
            if (isinstance(func.func, ast.Name) and func.func.id == 'getattr'
                    and len(func.args) >= 2):
                obj = self._resolve_call_name(func.args[0])
                attr = _const_str(func.args[1])
                if attr:
                    return f'{obj}.{attr}' if obj else attr
            # globals()['x'] 之类
            inner = self._resolve_call_name(func.func)
            return inner
        if isinstance(func, ast.Subscript):
            base = self._resolve_call_name(func.value)
            key = _const_str(func.slice)
            if key:
                return f'{base}.{key}' if base else key
        return ''


def _const_str(node) -> str:
    """取常量字符串；支持 'a' + 'b' 拼接"""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _const_str(node.left)
        right = _const_str(node.right)
        if left is not None and right is not None:
            return left + right
    return ''


# 长字符串常量阈值：疑似 payload（base64/hex/powershell 编码）
_LONG_CONST_MIN = 60


def _scan_long_constants(project_dir: Path, files: List[str],
                         py_files_rel: Set[str]) -> List[str]:
    """找出含「疑似 payload 长常量」的文件。

    2026-11 粗筛盲区修复（真实形态驱动）：
        config.py: PAYLOAD = "powershell -EncodedCommand cABvAHcA..."
        runner.py: from config import PAYLOAD; subprocess.Popen(PAYLOAD)
    config.py 本身没有任何 SSO 调用，会被粗筛丢掉——建图后数据来源断裂，
    LLM 只看到 Popen(PAYLOAD) 却不知道 PAYLOAD 从哪来，链路不完整。
    这里把「含长字符串常量」的文件也纳入建图范围。
    """
    out = []
    for rel in files:
        if rel in py_files_rel:
            continue
        p = project_dir / rel
        try:
            src = p.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(src)
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                if len(v) < _LONG_CONST_MIN:
                    continue
                # 只看像 payload 的：base64 字符集占绝对多数，或含编码命令特征
                compact = v.replace(' ', '').replace(chr(10), '')
                alnum = sum(1 for ch in compact if ch.isalnum() or ch in '+/=_-')
                looks_b64 = bool(compact) and alnum / len(compact) > 0.9
                low = v.lower()
                if looks_b64 or 'encodedcommand' in low or '/dev/tcp' in low:
                    out.append(rel)
                    break
    return out


def _same_package_imports(project_dir: Path, sso_files: List[str],
                          py_files_rel: Set[str], max_depth: int = 1) -> List[str]:
    """把 SSO 文件在同包内 import 的模块也纳入建图（import 闭包）。

    目的：数据源文件通常没有 SSO 调用，但被 SSO 文件 import。
         from .config import PAYLOAD   → config.py 必须进建图
         from mypkg import utils       → utils.py 必须进建图
    限制 max_depth=1，避免一个 import 把整个包拖进来。
    """
    # 建立 模块名 → 相对路径 的索引
    mod_index: Dict[str, str] = {}
    for rel in py_files_rel:
        no_ext = rel[:-3] if rel.endswith('.py') else rel
        dotted = no_ext.replace('/', '.')
        parts = dotted.split('.')
        # 去掉包根前缀的多种可能（pkg/__init__.py → pkg）
        if parts[-1] == '__init__':
            parts = parts[:-1]
            dotted = '.'.join(parts)
        mod_index[dotted] = rel
        mod_index[parts[-1]] = mod_index.get(parts[-1], rel)  # 短名兜底

    found: Set[str] = set()
    frontier = [(f, 0) for f in sso_files]
    seen = set(sso_files)

    while frontier:
        rel, depth = frontier.pop()
        if depth >= max_depth:
            continue
        p = project_dir / rel
        try:
            tree = ast.parse(p.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            continue
        for node in ast.walk(tree):
            mods: List[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ''
                # 相对 import：level=1 表示当前包
                mods = [f'{base}.{a.name}' if base else a.name for a in node.names]
                if base:
                    mods.append(base)
            for m in mods:
                for cand in (m, m.split('.')[-1]):
                    hit = mod_index.get(cand)
                    if hit and hit not in seen:
                        seen.add(hit)
                        found.add(hit)
                        frontier.append((hit, depth + 1))
    return sorted(found)


def select_files_for_graph(sso_result: Dict, max_files: int = 120,
                           project_dir: Path = None,
                           expand_imports: bool = True,
                           expand_constants: bool = True) -> List[str]:
    """按能力等级挑选进入建图的文件（2026-11，大包加速）。

    选择顺序：
      1. 含 Tier-1 能力的文件（执行/外传/提权）+ 任何 module 级能力
      2. 不够预算 → 加 Tier-2（网络入/反序列化/解码/写文件）
      3. 还不够 → 加 Tier-3（env/读文件，几乎每个文件都有）
      4. 凭据/持久化命中的文件始终包含
    永远保证 setup.py / __init__.py 在列（安装期与 import 期执行入口）。
    """
    findings = sso_result.get('findings') or []
    by_file: Dict[str, Set[int]] = {}
    for f in findings:
        by_file.setdefault(f['file'], set()).add(
            CAPABILITY_TIER.get(f['capability'], 3))

    # module 级文件优先纳入（安装/import 即执行）——但只限 Tier 1-2。
    # 若把 module 级的 env_access/file_read 也无条件纳入，几乎每个文件
    # 都会被选中（agent_framework: 120 个文件在模块级读环境变量），
    # 预算被日常操作吃光，真正的执行类文件反而排不进去。
    module_files = {
        f['file'] for f in findings
        if f.get('module_level') and CAPABILITY_TIER.get(f['capability'], 3) <= 2
    }

    # ===== 预算自适应（2026-11，扩展过度驱动）=====
    # 固定 120 的预算对小包等于不过滤（a2a_sdk 124 文件选了 110 个）。
    # 改为按包规模取比例：小包收紧、大包仍受绝对上限保护。
    # **Tier-1 文件永远不受预算约束**——它们直接承载执行/外传/提权，
    # 为了省钱砍掉它们是本末倒置。
    if project_dir is not None:
        try:
            total_py = len([p for p in Path(project_dir).rglob('*.py')
                            if '__pycache__' not in str(p)])
        except Exception:
            total_py = 0
        if total_py:
            adaptive = max(12, int(total_py * 0.20))
            max_files = min(max_files, adaptive)

    tier1_files = [f for f, tiers in sorted(by_file.items()) if 1 in tiers]
    tier2_files = [f for f, tiers in sorted(by_file.items()) if 2 in tiers]
    tier3_files = [f for f, tiers in sorted(by_file.items()) if 3 in tiers]

    selected: List[str] = []
    for f in list(module_files) + tier1_files:
        if f not in selected:
            selected.append(f)
    # Tier-1 已超预算也不裁——漏掉执行类文件比多建几张图严重得多
    for f in tier2_files:
        if len(selected) >= max_files:
            break
        if f not in selected:
            selected.append(f)
    for f in tier3_files:
        if len(selected) >= max_files:
            break
        if f not in selected:
            selected.append(f)

    # 凭据/持久化命中
    for h in (sso_result.get('credential_hits') or []) +              (sso_result.get('persistence_hits') or []):
        if h['file'] not in selected:
            selected.append(h['file'])

    # 清单外 API 兜底命中（ctypes/dlopen/mmap 等）——优先级低于 Tier1-2，
    # 但**必须受预算约束**：agent_framework 有 497 个 fallback 命中文件，
    # 无条件加入会把预算从 120 撑到 617，粗筛等于失效。
    for h in (sso_result.get('fallback_hits') or []):
        if len(selected) >= max_files:
            break
        if h['file'] not in selected:
            selected.append(h['file'])

    # ===== 盲区补偿（2026-11）：导入闭包 + 长常量 =====
    # 这两类文件本身没有 SSO 调用，但它们是攻击链的「数据来源」或
    # 「间接触发点」。丢掉它们，建出来的图会缺少链路起点。
    if project_dir is not None:
        proj = Path(project_dir)
        all_rel: Set[str] = set()
        for p in proj.rglob('*.py'):
            if '__pycache__' in str(p) or '.ddg_output' in str(p):
                continue
            try:
                all_rel.add(str(p.relative_to(proj)).replace(chr(92), '/'))
            except ValueError:
                all_rel.add(p.name)

        extra: List[str] = []
        if expand_imports:
            extra.extend(_same_package_imports(proj, selected, all_rel))
        if expand_constants:
            extra.extend(_scan_long_constants(proj, sorted(all_rel), set(selected)))

        # 扩展文件同样受预算约束（Tier-1 已在 selected 首位且不裁）
        tier1_set = set(tier1_files) | set(module_files)
        for f in extra:
            if f in selected:
                continue
            if len(selected) >= max_files and f not in tier1_set:
                continue
            selected.append(f)

    return selected


def extract_sso(project_dir: Path, max_file_bytes: int = 2_000_000) -> Dict:
    """扫描项目，提取所有 SSO 发现。

    Returns:
        {
          'findings': [ {file, line, api, capability, scope, module_level} ],
          'files_with_sso': [rel_path, ...],   # 供 builder 过滤建图范围
          'capabilities': {cap: count},
          'module_level_capabilities': {cap: count},  # 安装/import 期即触发
          'credential_hits': [ {file, line, hint} ],
          'persistence_hits': [ {file, line, hint} ],
          'files_scanned': int,
          'files_unparsable': int,
        }
    """
    project_dir = Path(project_dir)
    findings: List[Dict] = []
    cred_hits: List[Dict] = []
    persist_hits: List[Dict] = []
    files_scanned = 0
    unparsable = 0

    py_files = [p for p in project_dir.rglob('*.py')
                if '__pycache__' not in str(p) and '.ddg_output' not in str(p)]
    _all_rel_files: Set[str] = set()
    for _p in py_files:
        try:
            _all_rel_files.add(str(_p.relative_to(project_dir)).replace(chr(92), '/'))
        except ValueError:
            _all_rel_files.add(_p.name)

    for p in py_files:
        try:
            if p.stat().st_size > max_file_bytes:
                continue
            src = p.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(src)
        except Exception:
            unparsable += 1
            continue
        files_scanned += 1
        try:
            rel = str(p.relative_to(project_dir)).replace('\\', '/')
        except ValueError:
            rel = p.name

        v = _SSOVisitor(rel)
        try:
            v.visit(tree)
        except Exception:
            unparsable += 1
            continue

        findings.extend(v.findings)

        # 常量证据：凭据路径 / 持久化路径（来自字符串字面量）
        for s in v.strings:
            low = s.lower()
            for hint in CREDENTIAL_HINTS:
                if hint in low:
                    cred_hits.append({'file': rel, 'hint': hint})
                    break
            for hint in PERSISTENCE_HINTS:
                if hint in low:
                    persist_hits.append({'file': rel, 'hint': hint})
                    break

    caps: Dict[str, int] = {}
    mod_caps: Dict[str, int] = {}
    for f in findings:
        c = f['capability']
        caps[c] = caps.get(c, 0) + 1
        if f['module_level']:
            mod_caps[c] = mod_caps.get(c, 0) + 1

    files_with_sso = sorted({f['file'] for f in findings})
    # 凭据/持久化命中所在文件也必须进细判（它们本身不是能力调用，
    # 但通常是攻击链的目标或落点）
    for h in cred_hits + persist_hits:
        if h['file'] not in files_with_sso:
            files_with_sso.append(h['file'])
    files_with_sso.sort()

    # ===== 覆盖度 + 兜底扫描（2026-11，清单外 API 风险缓解）=====
    # 粗筛必然会漏掉清单外的 API。与其假装免疫，不如**量化覆盖度**：
    # 未覆盖文件里若出现可疑词（ctypes/dlopen/mmap/system…），
    # 说明可能存在清单外的能力调用，需要额外关注。
    covered = set(files_with_sso)
    fallback_hits: List[Dict] = []
    uncovered_lines = 0
    for rel in sorted(_all_rel_files):
        if rel in covered:
            continue
        fp = project_dir / rel
        try:
            txt = fp.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        uncovered_lines += txt.count(chr(10)) + 1
        low = txt.lower()
        for hint in FALLBACK_API_HINTS:
            if hint.lower() in low:
                fallback_hits.append({'file': rel, 'hint': hint})
                break

    return {
        'findings': findings,
        'files_with_sso': files_with_sso,
        'coverage': {
            'files_total': len(_all_rel_files),
            'files_covered': len(covered),
            'uncovered_lines': uncovered_lines,
            'fallback_hits': len(fallback_hits),
        },
        'fallback_hits': fallback_hits,
        'capabilities': caps,
        'module_level_capabilities': mod_caps,
        'credential_hits': cred_hits,
        'persistence_hits': persist_hits,
        'files_scanned': files_scanned,
        'files_unparsable': unparsable,
    }
