# -*- coding: utf-8 -*-
"""单层字面量自动解码（literal decoder）

动机（2026-11，混淆盲区）：
    恶意包最常见的混淆是**把载荷放进字符串**：
        exec(base64.b64decode("cG93ZXJzaGVsbCAta..."))
        PAYLOAD = "aGVsbG8..."      # 没有 API，但内容是弹药
    我们此前只把这些串**当字符串抓出来给 LLM 看**，从不解码。
    quarejma-botnet 0 子图漏检就是这一类。

策略：**只解一层，只做确定性变换，绝不执行任何解码产物**。
    解出来的字符串 → 喂 IOC 表（矿池/回连域名直接命中）
    解出来的代码片段 → 当作证据展示，不 exec、不 eval

支持：base64 / base32 / hex / zlib / gzip / bz2 / lzma / rot13
限制：单串长度 ≤ 64KB，解出结果 ≤ 4KB 才纳入（防爆炸）
"""
import base64
import binascii
import codecs
import re
import zlib
from typing import Dict, List, Optional

_MAX_INPUT = 65536        # 单串输入上限
_MAX_OUTPUT = 4096        # 解出结果上限（超了只留前缀）
_MIN_INPUT = 20           # 太短的串不值得解

# 看起来像编码的候选串（引号内的长串）
_STRING_LITERAL_RE = re.compile(r'''(['"])([A-Za-z0-9+/=_:.\-]{20,8000})\1''')
_ESCAPE_HEX_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){8,}')


def _b64(s: str) -> Optional[str]:
    t = s.replace('-', '+').replace('_', '/')
    pad = (-len(t)) % 4
    try:
        raw = base64.b64decode(t + '=' * pad, validate=False)
        return raw.decode('utf-8', errors='ignore')
    except Exception:
        return None


def _b32(s: str) -> Optional[str]:
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + '=' * pad).decode('utf-8', errors='ignore')
    except Exception:
        return None


def _hex(s: str) -> Optional[str]:
    t = s.replace(' ', '')
    if len(t) % 2:
        return None
    try:
        return binascii.unhexlify(t).decode('utf-8', errors='ignore')
    except Exception:
        return None


def _zlib_decompress(raw: bytes) -> Optional[str]:
    try:
        return zlib.decompress(raw).decode('utf-8', errors='ignore')
    except Exception:
        return None


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in '\n\r\t')
    return ok / len(s)


def _try_decompress_chain(raw_b64: str) -> Optional[str]:
    """base64 解出来若是压缩流（zlib/gzip/bz2/lzma），再解一层。

    只解一层压缩——多层嵌套留给"解一层看结果"的迭代，不做递归爆炸。
    """
    t = raw_b64.replace('-', '+').replace('_', '/')
    pad = (-len(t)) % 4
    try:
        raw = base64.b64decode(t + '=' * pad, validate=False)
    except Exception:
        return None
    if len(raw) < 8:
        return None
    for name, fn in (('zlib', lambda b: zlib.decompress(b)),
                     ('gzip', lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS))):
        try:
            return fn(raw).decode('utf-8', errors='ignore')
        except Exception:
            continue
    try:
        import bz2
        return bz2.decompress(raw).decode('utf-8', errors='ignore')
    except Exception:
        pass
    try:
        import lzma
        return lzma.decompress(raw).decode('utf-8', errors='ignore')
    except Exception:
        pass
    return None


def decode_literal(s: str) -> List[Dict]:
    """尝试把单个字符串常量解一层。

    Returns:
        [{'method': 'base64', 'decoded': '...'}, ...]（可能多解，去重）
    """
    if not s or len(s) < _MIN_INPUT or len(s) > _MAX_INPUT:
        return []
    out: List[Dict] = []
    seen = set()

    def _add(method: str, txt: Optional[str]):
        if not txt or txt in seen:
            return
        if _printable_ratio(txt) < 0.75:
            return
        seen.add(txt)
        out.append({'method': method, 'decoded': txt[:_MAX_OUTPUT]})

    # base64 家族（含 urlsafe）
    d = _b64(s)
    _add('base64', d)
    # base64 内层是压缩流 → 再解一层（skip 掉二进制乱码）
    if d is not None and _printable_ratio(d) < 0.9:
        _add('base64+zlib', _try_decompress_chain(s))
    # base32（全大写 A-Z2-7 特征）
    if re.fullmatch(r'[A-Z2-7=]{20,}', s or ''):
        _add('base32', _b32(s))
    # hex
    if re.fullmatch(r'[0-9a-fA-F]{20,}', s or ''):
        _add('hex', _hex(s))
    # 压缩：把已解出的 base64/hex 再尝试 zlib
    for method, txt in list((('zlib-from-base64', d),)):
        if txt:
            try:
                _add('zlib', _zlib_decompress(txt.encode('latin-1', errors='ignore')))
            except Exception:
                pass
    # rot13（只在结果明显可读时采纳）
    try:
        r13 = codecs.decode(s, 'rot13')
        if _printable_ratio(r13) > 0.95 and re.search(r'[a-zA-Z]{4,}', r13):
            if any(k in r13.lower() for k in ('http', 'exec', 'import', 'system',
                                              'socket', 'subprocess', 'eval')):
                _add('rot13', r13)
    except Exception:
        pass
    return out


def scan_code(code: str, max_literals: int = 8) -> List[Dict]:
    """从一段源码里找出可解码的字面量并解一层。

    Returns:
        [{'literal': '<截断原串>', 'method': 'base64', 'decoded': '...'}, ...]
    """
    if not code:
        return []
    results: List[Dict] = []
    seen_decoded = set()
    for m in _STRING_LITERAL_RE.finditer(code):
        cand = m.group(2)
        for r in decode_literal(cand):
            key = (r['method'], r['decoded'])
            if key in seen_decoded:
                continue
            seen_decoded.add(key)
            results.append({
                'literal': cand[:60],
                'method': r['method'],
                'decoded': r['decoded'],
            })
            if len(results) >= max_literals:
                return results
    return results


# 解码结果里值得警觉的片段（用于 digest 高亮 + 敌意字面量门）
_DECODED_RISK = (
    '/dev/tcp', 'encodedcommand', 'powershell', 'supportxmr', 'stratum',
    'miner', 'wallet', 'oastify', 'interactsh', 'webhook', 'pastebin',
    'subprocess', 'os.system', 'popen', 'exec(', 'eval(', 'socket',
    'requests.post', 'urllib', 'base64', 'chmod ', 'setuid', 'crontab',
    '.ssh/', '.aws/', 'telegram', 'discord',
)


def decoded_has_risk(decoded: str) -> bool:
    low = (decoded or '').lower()
    return any(t in low for t in _DECODED_RISK)
