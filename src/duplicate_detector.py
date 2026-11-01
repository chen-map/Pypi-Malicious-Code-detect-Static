# -*- coding: utf-8 -*-
"""近重复检测 - 抓"抄真包代码、只改名字"的仿冒族（botaa3 克星）

动机（2026-10 静态侧硬化，真实样本驱动）：botaa3-1.0.0.tar.gz 内是原封不动
的 boto3 1.20.7，代码完全干净，静态污点/规则全部失效。当发行名与元数据
Name 不一致（已判定 name_mismatch）时，进一步下载真包做文件级哈希比对：
相似度 ≥0.8 即"代码与官方一致、仅名称仿冒"的决定性证据。

离线安全：下载/解析任何失败都返回 status='unknown'，不下结论。
磁盘缓存已下载的 sdist（output/.dup_cache/），同一真包只下载一次。
"""

import hashlib
import re
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Optional

_CACHE_DIR = Path(__file__).parent.parent / 'output' / '.dup_cache'
_SIMILARITY_THRESHOLD = 0.8


def _normalize_name(name: str) -> str:
    return re.sub(r'[-_.]+', '-', (name or '').strip().lower())


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _py_hashes_of_dir(pkg_dir: Path) -> set:
    """目录下全部 .py 的 sha256 集合（跳过空文件与 __pycache__）"""
    hashes = set()
    for f in pkg_dir.rglob('*.py'):
        if '__pycache__' in f.parts:
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if not data.strip():
            continue
        hashes.add(hashlib.sha256(data).hexdigest())
    return hashes


def _fetch_genuine_sdist(name: str, version: str, cache_dir: Path) -> Optional[Path]:
    """下载真包 sdist 到缓存，返回解压目录；失败返回 None"""
    out_dir = cache_dir / f"{_normalize_name(name)}-{version}"
    marker = out_dir / '.ok'
    if marker.exists():
        return out_dir
    try:
        url = f'https://pypi.org/pypi/{_normalize_name(name)}/{version}/json'
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = __import__('json').load(resp)
        sdist = next((u for u in data.get('urls', []) if u.get('packagetype') == 'sdist'), None)
        if not sdist:
            return None
        cache_dir.mkdir(parents=True, exist_ok=True)
        tgz_path = out_dir.with_suffix('.tar.gz')
        if not tgz_path.exists():
            with urllib.request.urlopen(sdist['url'], timeout=120) as r, open(tgz_path, 'wb') as f:
                shutil.copyfileobj(r, f)
        extract_base = out_dir / 'x'
        extract_base.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tgz_path) as tf:
            tf.extractall(str(extract_base), filter='data')
        marker.write_text('ok', encoding='utf-8')
        return out_dir
    except Exception:
        return None


def check_duplicate(pkg_dir: Path, genuine_name: str, genuine_version: str,
                    cache_dir: Optional[Path] = None) -> Dict:
    """比对可疑包与真包的代码相似度

    Args:
        pkg_dir: 可疑包解压目录
        genuine_name: 元数据里的真包名
        genuine_version: 元数据里的版本
        cache_dir: sdist 缓存目录

    Returns:
        {'status': 'duplicate'|'similar'|'dissimilar'|'unknown',
         'similarity': float, 'reason': str}
    """
    cache_dir = Path(cache_dir) if cache_dir else _CACHE_DIR
    try:
        own_hashes = _py_hashes_of_dir(pkg_dir)
        if not own_hashes:
            return {'status': 'unknown', 'similarity': 0.0,
                    'reason': '可疑包无 .py 文件可比对'}

        genuine_dir = _fetch_genuine_sdist(genuine_name, genuine_version, cache_dir)
        if not genuine_dir:
            return {'status': 'unknown', 'similarity': 0.0,
                    'reason': f'无法获取官方 {genuine_name}-{genuine_version}（网络/版本不存在）'}

        genuine_hashes = _py_hashes_of_dir(genuine_dir)
        if not genuine_hashes:
            return {'status': 'unknown', 'similarity': 0.0,
                    'reason': '官方包无可比对的 .py 文件'}

        intersection = own_hashes & genuine_hashes
        similarity = len(intersection) / max(min(len(own_hashes), len(genuine_hashes)), 1)

        if similarity >= _SIMILARITY_THRESHOLD:
            return {
                'status': 'duplicate',
                'similarity': round(similarity, 3),
                'reason': (f'{round(similarity*100)}% 的代码文件与官方 '
                           f'{genuine_name}-{genuine_version} 完全一致——'
                           '仅名称仿冒的抢注包（决定性证据）'),
            }
        if similarity >= 0.3:
            return {'status': 'similar', 'similarity': round(similarity, 3),
                    'reason': f'与官方 {genuine_name} 有 {round(similarity*100)}% 代码重合'}
        return {'status': 'dissimilar', 'similarity': round(similarity, 3),
                'reason': '与官方包代码差异显著（可能是独立实现或篡改版）'}
    except Exception as e:
        return {'status': 'unknown', 'similarity': 0.0,
                'reason': f'比对失败: {type(e).__name__}'}
