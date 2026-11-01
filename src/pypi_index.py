# -*- coding: utf-8 -*-
"""PyPI 全量包名索引 - 实时 typosquat 比对目标

动机（2026-10 静态侧硬化）：enhanced_detector 原用 40 个硬编码流行包做
编辑距离比对——覆盖极窄，python-dateutils 之类的仿冒名若不撞清单就漏。
本模块拉取 PyPI simple index 全量包名（约 20MB），磁盘缓存 24 小时，
提供 O(桶) 的编辑距离 ≤1 近邻查询。

离线安全：任何网络/解析失败都回退 None，由调用方退回硬编码清单。
"""

import re
import time
import urllib.request
from pathlib import Path
from typing import Dict, Optional, Set

CACHE_TTL_SECONDS = 24 * 3600
SIMPLE_INDEX_URL = 'https://pypi.org/simple/'
_DEFAULT_CACHE_DIR = Path(__file__).parent.parent / 'output' / '.pypi_index_cache'


def normalize_name(name: str) -> str:
    """PEP 503 包名规范化"""
    return re.sub(r'[-_.]+', '-', (name or '').strip().lower())


def load_index(cache_dir: Optional[Path] = None,
               ttl_seconds: int = CACHE_TTL_SECONDS) -> Optional[Set[str]]:
    """加载全量包名集合（磁盘缓存 24h；失败返回 None）

    Returns:
        规范化包名集合，或 None（网络不可用/解析失败）
    """
    cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
    cache_file = cache_dir / 'pypi_names.txt'

    if cache_file.exists() and time.time() - cache_file.stat().st_mtime < ttl_seconds:
        try:
            names = set(cache_file.read_text(encoding='utf-8').splitlines())
            if len(names) > 10000:  # 合理下限，防止缓存到空结果
                return names
        except Exception:
            pass

    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(SIMPLE_INDEX_URL, headers={'User-Agent': 'pypi-malware-scanner'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            html = resp.read().decode('utf-8', 'ignore')
        # simple index 是 <a href="/simple/{name}/">{name}</a> 列表
        names = {normalize_name(m) for m in re.findall(r'>([^<>]+)</a>', html) if m}
        names.discard('')
        if len(names) < 10000:
            return None  # 解析异常，不用半吊子数据
        cache_file.write_text('\n'.join(sorted(names)), encoding='utf-8')
        return names
    except Exception:
        return None


def build_length_buckets(names: Set[str]) -> Dict[int, Set[str]]:
    """按长度分桶（编辑距离 ≤1 的两串长度差必 ≤1）"""
    buckets: Dict[int, Set[str]] = {}
    for n in names:
        buckets.setdefault(len(n), set()).add(n)
    return buckets


def find_near_neighbors(name: str, buckets: Dict[int, Set[str]]) -> Set[str]:
    """返回与 name 编辑距离 ≤1 的全部规范名

    先按长度 ±1 的桶取候选（比全量快几个量级），再做精确距离判定。
    """
    target = normalize_name(name)
    if not target:
        return set()
    candidates = set()
    for length in (len(target) - 1, len(target), len(target) + 1):
        candidates |= buckets.get(length, set())
    hits = set()
    for cand in candidates:
        if cand == target:
            continue
        if _edit_distance_le1(target, cand):
            hits.add(cand)
    return hits


def _edit_distance_le1(a: str, b: str) -> bool:
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) <= 1
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = 0
    while i < la and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]
