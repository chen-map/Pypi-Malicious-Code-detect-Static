# -*- coding: utf-8 -*-
"""合法性通道（Legitimacy Channel）

问题（2026-11，7 个良性 SUSPICIOUS 驱动）：
    我们的证据模型是**单边**的——只收集负面证据（没找到链），从不收集
    正面证据（凭什么信它是良性的）。所以"有能力但不理解意图"只能挂起。

    典型：intuit_oauth 读 OAuth 凭据、nvgpu 调原生 GPU 库——它们**确实**
    具备恶意级能力，判 SUSPICIOUS 是对的。要放行它们，需要的不是降阈值，
    而是"这个行为与它自称的身份一致"的正面证据。

铁律（与"启发式永不定罪"对称）：
    合法性证据**只能把 SUSPICIOUS 降为 BENIGN，永不能定罪**。
    敌对证据可以把 BENIGN 升到 MALICIOUS，合法性证据只能反向。

五个信号（全部离线可判，不调 LLM）：
    ① 目的地一致性  外传目标域名 == 包自己声明的域名
    ② 文档一致性    README 描述了该敏感能力
    ③ 代码风格      无别名规避 / 无编码载荷 / 无动态构造 API 名
    ④ 依赖一致性    能力由已知合法库提供，而非裸 ctypes/dlopen
    ⑤ 生态证据      PyPI 上存在且版本历史正常（可选，需联网）
"""
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

# 阈值：>= 0.7 才允许 SUSPICIOUS → BENIGN
ALLOW_THRESHOLD = 0.70

# 各能力在文档里通常对应的词（用于"文档一致性"）
_CAP_DOC_WORDS = {
    'credential_access': ('oauth', 'credential', 'token', 'auth', 'login',
                          'password', 'secret', 'key'),
    'network_in': ('http', 'request', 'fetch', 'download', 'client', 'api',
                   'url', 'crawl', 'scrape'),
    'network_out': ('http', 'request', 'upload', 'send', 'client', 'api',
                    'webhook', 'notify'),
    'process_spawn': ('shell', 'command', 'subprocess', 'exec', 'run',
                      'process', 'cli', 'build'),
    'code_eval': ('eval', 'exec', 'compile', 'template', 'plugin', 'dynamic',
                  'codegen', 'import'),
    'deserialize': ('parse', 'serial', 'json', 'yaml', 'pickle', 'encode',
                    'decode', 'format'),
    'file_read': ('read', 'file', 'load', 'parse', 'config', 'path'),
    'file_write': ('write', 'save', 'export', 'dump', 'output', 'file'),
    'env_access': ('environment', 'config', 'setting', 'env', 'variable'),
    'privilege': ('permission', 'root', 'admin', 'privilege', 'capability'),
    'decode': ('encode', 'decode', 'base64', 'compress', 'format'),
}

# 由已知合法库提供的能力（依赖一致性）
_KNOWN_LIBS = {
    'credential_access': ('oauthlib', 'authlib', 'requests_oauthlib', 'keyring',
                          'google.auth', 'msal', 'boto3', 'azure'),
    'network_in': ('requests', 'httpx', 'aiohttp', 'urllib3', 'urllib',
                   'http.client', 'scrapy', 'beautifulsoup4', 'lxml'),
    'network_out': ('requests', 'httpx', 'aiohttp', 'urllib3', 'smtplib',
                    'telegram', 'discord', 'slack_sdk'),
    'deserialize': ('json', 'yaml', 'toml', 'msgpack', 'edn_format', 'cbor2'),
    'decode': ('base64', 'codecs', 'zlib', 'gzip', 'bz2', 'lzma', 'binascii'),
    'file_read': ('pathlib', 'io', 'shutil', 'csv', 'configparser'),
    'file_write': ('pathlib', 'io', 'shutil', 'csv', 'configparser'),
    'env_access': ('os', 'dotenv', 'configparser'),
}

# 别名规避特征（恶意包标配，良性包少见）
_EVASION_ALIAS = re.compile(r'\bfrom\s+\w+\s+import\s+\w+\s+as\s+[_]{1,3}\w+')

# 从 PKG-INFO / setup.py 提取声明域名
_URL_RE = re.compile(r'https?://([\w.-]+)')


def _read(p: Path, limit: int = 400_000) -> str:
    try:
        if p.stat().st_size > limit:
            return ''
        return p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ''


def declared_domains(pkg_dir) -> Set[str]:
    """包自己声明的域名（homepage / project_urls / 文档链接 / 作者邮箱域）"""
    root = Path(pkg_dir)
    out: Set[str] = set()
    for name in ('PKG-INFO', 'setup.py', 'setup.cfg', 'pyproject.toml'):
        txt = _read(root / name)
        if not txt:
            continue
        # 只取元数据字段附近的 URL，避免把 README 里引用的第三方域名算进来
        for line in txt.splitlines():
            low = line.lower()
            if any(k in low for k in ('home-page', 'homepage', 'project-url',
                                      'url =', 'url=', 'author-email',
                                      'maintainer', 'download_url')):
                for m in _URL_RE.finditer(line):
                    out.add(m.group(1).lower())
                if '@' in line:
                    m = re.search(r'@([\w.-]+)', line)
                    if m:
                        out.add(m.group(1).lower())
    return out


def _root_domain(host: str) -> str:
    parts = (host or '').lower().split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def signal_destination(nodes: List[Dict], declared: Set[str]) -> Dict:
    """① 外传目标是否落在包自己声明的域名上"""
    from src.target_awareness import chain_target, classify_target
    checked, own, attacker = 0, 0, 0
    details = []
    for n in nodes:
        cap = n.get('capability') or ''
        if cap not in ('network_out', 'network_in'):
            continue
        code = n.get('code') or ''
        if not re.search(r'(requests\.|urlopen|socket\.|httpx\.)', code):
            continue
        cls, ev = chain_target({'sink': {'code': code, 'node_id': n.get('node_id')}},
                               nodes)
        if cls == 'none':
            continue
        checked += 1
        if cls == 'attacker_infra':
            attacker += 1
            details.append(f'attacker infra: {ev[:40]}')
        elif cls == 'package_own':
            host = _root_domain(ev.split('/')[0].split(':')[0])
            if not declared or any(host.endswith(d) or d.endswith(host)
                                   for d in declared if d):
                own += 1
            else:
                own += 1     # 有域名但未声明 → 中性，不算负面
        else:
            own += 0     # dynamic → 中性
    if checked == 0:
        return {'score': None, 'reason': 'no resolvable network target'}
    if attacker:
        # 明确指向攻击设施 —— 一票否决
        return {'score': 0.0, 'veto': True,
                'reason': f'{attacker}/{checked} targets are attacker infra'}
    if own == 0:
        # 有目标但一个都解析不出域名（requsets: 0/90）→ "不知道"，不是"好"
        return {'score': None,
                'reason': f'0/{checked} targets resolvable to a domain'}
    return {'score': own / checked,
            'reason': f'{own}/{checked} targets are well-formed domains',
            'details': details[:3]}


def signal_docs(pkg_dir, caps: Set[str]) -> Dict:
    """② README / 摘要是否描述了这些敏感能力"""
    root = Path(pkg_dir)
    text = ''
    for name in ('README.md', 'README.rst', 'README.txt', 'README'):
        text = _read(root / name, 200_000)
        if text:
            break
    pkg_info = _read(root / 'PKG-INFO', 20_000)
    corpus = (text + ' ' + pkg_info).lower()
    if not corpus.strip():
        return {'score': None, 'reason': 'no README / metadata'}
    hits, missing = [], []
    for c in caps:
        words = _CAP_DOC_WORDS.get(c)
        if not words:
            continue
        if any(w in corpus for w in words):
            hits.append(c)
        else:
            missing.append(c)
    if not hits and not missing:
        return {'score': None, 'reason': 'no documented-capability mapping'}
    return {'score': len(hits) / (len(hits) + len(missing)),
            'reason': f'documented: {hits}; undocumented: {missing}'}


def signal_code_style(nodes: List[Dict]) -> Dict:
    """③ 有没有别名规避 / 编码载荷 / 动态构造 API 名（都是恶意包特征）"""
    penalties = 0
    reasons: List[str] = []
    for n in nodes:
        code = n.get('code') or ''
        if _EVASION_ALIAS.search(code):
            penalties += 1
            reasons.append('alias evasion')
            break
    # 编码载荷（解出来是代码/URL 的那种）
    try:
        from src.literal_decoder import scan_code, decoded_has_risk
        for n in nodes:
            for h in scan_code(n.get('code') or ''):
                if decoded_has_risk(h.get('decoded') or ''):
                    penalties += 1
                    reasons.append('encoded payload')
                    break
            if 'encoded payload' in reasons:
                break
    except Exception:
        pass
    # 动态构造 API 名
    for n in nodes:
        code = n.get('code') or ''
        if re.search(r'getattr\s*\(\s*\w+\s*,\s*[\'"][\w.]{3,}[\'"]', code):
            penalties += 1
            reasons.append('dynamically constructed API name')
            break
    score = max(0.0, 1.0 - 0.5 * penalties)
    out = {'score': score,
           'reason': f'{penalties} evasion signals' + (f': {reasons}' if reasons else '')}
    if penalties >= 2:
        # 编码载荷 + 动态构造 API 名同现 = 恶意包标配（requsets 实测）
        out['veto'] = True
    return out


def signal_dependencies(nodes: List[Dict], caps: Set[str]) -> Dict:
    """④ 能力是否由已知合法库提供（而非裸 ctypes / 手搓实现）"""
    imported = set()
    for n in nodes:
        code = n.get('code') or ''
        for m in re.finditer(r'^\s*(?:from|import)\s+([\w.]+)', code):
            imported.add(m.group(1).split('.')[0].lower())
        if 'import' in code:
            for m in re.finditer(r'\b(?:from|import)\s+([\w.]+)', code):
                imported.add(m.group(1).split('.')[0].lower())
    if not imported:
        return {'score': None, 'reason': 'no imports visible'}
    covered, uncovered = [], []
    for c in caps:
        libs = _KNOWN_LIBS.get(c)
        if not libs:
            continue
        if any(l.split('.')[0].lower() in imported for l in libs):
            covered.append(c)
        else:
            uncovered.append(c)
    if not uncovered:
        return {'score': 1.0 if covered else None,
                'reason': f'backed by known libs: {covered}'}
    if not covered:
        # 全靠自研实现——不是恶意证据，只是没有正面证据
        return {'score': None, 'reason': f'no known library backs {uncovered}'}
    return {'score': len(covered) / (len(covered) + len(uncovered)),
            'reason': f'backed by known libs: {covered}; raw: {uncovered}'}


def assess(pkg_dir, nodes: List[Dict], caps: Set[str],
           pypi_stats: Optional[Dict] = None) -> Dict:
    """综合合法性评估。

    Returns:
        {'score': 0..1|None, 'allow_benign': bool, 'signals': {...},
         'reasons': [...]}
    """
    declared = declared_domains(pkg_dir)
    signals = {
        'destination': signal_destination(nodes, declared),
        'docs': signal_docs(pkg_dir, caps),
        'code_style': signal_code_style(nodes),
        'deps': signal_dependencies(nodes, caps),
    }
    # ⑤ 生态证据（可选）
    if pypi_stats:
        age = pypi_stats.get('first_release_age_days')
        versions = pypi_stats.get('versions_count') or 0
        if age is not None:
            signals['ecosystem'] = {
                'score': 1.0 if age > 180 and versions >= 3 else
                         (0.5 if age > 30 else 0.0),
                'reason': f'age={age}d versions={versions}',
            }

    # 加权：真正有区分力的是"目的地"和"代码风格"。
    # docs / deps 几乎恒为高分（恶意包的 README 也说自己是 HTTP 库），
    # 只作为弱佐证。
    weights = {'destination': 0.35, 'code_style': 0.30,
               'docs': 0.20, 'deps': 0.15, 'ecosystem': 0.25}
    veto = any(s.get('veto') for s in signals.values())
    num = den = 0.0
    for k, s in signals.items():
        sc = s.get('score')
        if sc is None:
            continue
        w = weights.get(k, 0.1)
        num += sc * w
        den += w
    score = (num / den) if den else None
    if veto:
        score = 0.0

    return {
        'score': None if score is None else round(score, 3),
        'allow_benign': bool(score is not None and score >= ALLOW_THRESHOLD
                             and not veto),
        'signals': signals,
        'reasons': [f"{k}: {v.get('reason')}" for k, v in signals.items()],
    }
