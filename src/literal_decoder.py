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

    只解一层压缩——多层嵌套交给 peel() 的迭代。
    """
    t = raw_b64.replace('-', '+').replace('_', '/')
    pad = (-len(t)) % 4
    try:
        raw = base64.b64decode(t + '=' * pad, validate=False)
    except Exception:
        return None
    return _decompress_bytes(raw)


def _decompress_bytes(raw: bytes) -> Optional[str]:
    if not raw or len(raw) < 8:
        return None
    for fn in (lambda b: zlib.decompress(b),
               lambda b: zlib.decompress(b, 16 + zlib.MAX_WBITS)):
        try:
            return fn(raw).decode('utf-8', errors='ignore')
        except Exception:
            pass
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


# ===== marshal 静态检查（超级混淆的主力武器）=====
# 恶意包常用 `exec(marshal.loads(b64decode(...)))` 藏字节码。
# marshal.loads **不执行代码**，只反序列化——我们可以安全地读出
# code object 的 co_consts / co_names，拿到载荷字符串与 API 名。
_MARSHAL_MAX = 262144     # 256KB 上限，防解析爆炸


def _walk_code_strings(co, out: List[str], depth: int = 0) -> None:
    """递归收集 code object 里的字符串常量与名字（不执行任何代码）"""
    if depth > 6 or len(out) >= 40:
        return
    consts = getattr(co, 'co_consts', ()) or ()
    for c in consts:
        if isinstance(c, str) and 4 <= len(c) <= 2000:
            out.append(c)
        elif hasattr(c, 'co_consts'):
            _walk_code_strings(c, out, depth + 1)
    for n in list(getattr(co, 'co_names', ()) or ())[:40]:
        if isinstance(n, str) and 2 <= len(n) <= 60:
            out.append(n)


def inspect_marshal(raw: bytes) -> List[str]:
    """静态读取 marshal 字节码里的字符串（绝不执行）。

    Returns:
        值得注意的字符串列表（载荷/URL/API 名）
    """
    import marshal
    if not raw or len(raw) > _MARSHAL_MAX:
        return []
    try:
        co = marshal.loads(raw)
    except Exception:
        return []
    out: List[str] = []
    try:
        if hasattr(co, 'co_consts'):
            _walk_code_strings(co, out)
    except Exception:
        pass
    # 去重保序
    seen = set()
    uniq = []
    for s in out:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)
    return uniq[:20]


def peel(s: str, max_layers: int = 3) -> List[Dict]:
    """多层剥离：base64/hex → 解压 → 再 base64…最多 max_layers 层。

    每一层的可读结果都会收集（不只最后一层）——中间层常有 URL。
    marshal 字节码会被静态检查（不执行）。
    """
    results: List[Dict] = []
    seen = set()
    cur_text = s
    cur_bytes: Optional[bytes] = None

    def _add(method: str, txt: str):
        if not txt or txt in seen or len(txt) > _MAX_OUTPUT:
            return
        if _printable_ratio(txt) < 0.75 or not _looks_meaningful(txt):
            return
        seen.add(txt)
        results.append({'method': method, 'decoded': txt})

    for layer in range(max_layers):
        # 尝试 base64
        b64txt = cur_text.replace('-', '+').replace('_', '/')
        pad = (-len(b64txt)) % 4
        raw = None
        try:
            raw = base64.b64decode(b64txt + '=' * pad, validate=False)
        except Exception:
            pass
        if raw is None or not raw:
            break
        # 先看是不是 marshal 字节码（超级混淆主力）
        strings = inspect_marshal(raw)
        if strings:
            for st in strings:
                if len(st) >= 4:
                    results.append({
                        'method': f'marshal-L{layer + 1}',
                        'decoded': st[:_MAX_OUTPUT],
                    })
            return results
        # 压缩流？
        dec = _decompress_bytes(raw)
        if dec is not None:
            _add(f'zlib-L{layer + 1}', dec)
            cur_text = dec
            continue
        # 纯文本？
        txt = raw.decode('utf-8', errors='ignore')
        if _printable_ratio(txt) >= 0.75:
            _add(f'base64-L{layer + 1}', txt)
            cur_text = txt
            continue
        break
    return results


_WORD_RE = re.compile(r'[A-Za-z]{3,}')


def _looks_meaningful(txt: str) -> bool:
    """解出的文本是否"像内容"而不是二进制残留。

    UTF-8 ignore 解码会丢掉非法字节，剩下的 ASCII 可能凑出高可打印率
    （实测：bytes(range(256)) 的 base64 → 通过 75% 可打印率检查）。
    真正的判据是**控制字符占比**：正常代码/文本几乎没有控制字符，
    二进制转来的"伪文本"必然带一堆。
    """
    if not txt or len(txt) < 6:
        return False
    ctrl = sum(1 for ch in txt
               if ord(ch) < 32 and ch not in chr(10) + chr(13) + chr(9))
    if ctrl / len(txt) > 0.02:
        return False
    low = txt.lower()
    if any(k in low for k in ('http', 'os.', 'exec', 'import', 'system',
                              'socket', 'curl', 'wget', 'subprocess', '.com',
                              '.net', 'stratum', 'base64')):
        return True
    words = _WORD_RE.findall(txt)
    return len(words) >= 2


def decode_literal(s: str) -> List[Dict]:
    """尝试把单个字符串常量解一层（多层交给 peel）。

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
        if _printable_ratio(txt) < 0.75 or not _looks_meaningful(txt):
            return
        seen.add(txt)
        out.append({'method': method, 'decoded': txt[:_MAX_OUTPUT]})

    # 多层剥离（含 marshal 静态检查）——超级混淆主力
    for r in peel(s, max_layers=3):
        if r['decoded'] not in seen:
            seen.add(r['decoded'])
            out.append(r)

    # 单层变换（peel 没覆盖的形态）
    d = _b64(s)
    _add('base64', d)
    if re.fullmatch(r'[A-Z2-7=]{20,}', s or ''):
        _add('base32', _b32(s))
    if re.fullmatch(r'[0-9a-fA-F]{20,}', s or ''):
        _add('hex', _hex(s))
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
