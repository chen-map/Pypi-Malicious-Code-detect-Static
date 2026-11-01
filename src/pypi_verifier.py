# -*- coding: utf-8 -*-
"""PyPI 索引核验 - 检测"不存在于官方索引"的发行包

动机（真实数据驱动）：恶意抢注 / 依赖混淆包的代码常常是抄来的正常包
（甚至完全干净，如 botaa3 内是原版 boto3），静态分析只能判 BENIGN；
这类包被举报后会被 PyPI 下架。因此"发行名在 PyPI 上不存在"或
"该版本从未发布"是极强的供应链攻击信号。

注意：
- 需要网络；失败时返回 unknown，绝不据此下结论（避免离线环境误判）。
- 私有包/内部镜像请通过 --no-pypi-verify 关闭。
"""

import json
import re
import urllib.error
import urllib.request
from typing import Dict, Optional

_CACHE: Dict[str, Dict] = {}


def normalize_name(name: str) -> str:
    return re.sub(r'[-_.]+', '-', (name or '').strip().lower())


def strip_version(dist_filename: str) -> tuple:
    """从发行文件名剥离版本：python-dateutils-3.0.3.tar.gz → ('python-dateutils', '3.0.3')"""
    n = re.sub(r'\.(tar\.gz|whl|zip)$', '', dist_filename or '', flags=re.IGNORECASE)
    n = re.sub(r'-py\d[\w.]*-none-any$', '', n)
    m = re.match(r'^(.+?)-(\d[\w.]*)$', n)
    return (m.group(1), m.group(2)) if m else (n, '')


def verify_distribution(dist_name: str, version: str = '', timeout: float = 10.0) -> Dict:
    """核验发行包是否存在于 PyPI，以及该版本是否发布过

    Returns:
        {
          'status': 'exists' | 'not_found' | 'unpublished_version' | 'unknown',
          'reason': str,
          'official_name': str | None,
        }
    """
    key = normalize_name(dist_name)
    if not key:
        return {'status': 'unknown', 'reason': 'empty name', 'official_name': None}
    # 缓存键必须包含版本：同一包名不同版本的核验结果不同
    cache_key = f'{key}@{version}'
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    url = f'https://pypi.org/pypi/{key}/json'
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = {
                'status': 'not_found',
                'reason': f'发行名 "{dist_name}" 不存在于 PyPI 官方索引（名称抢注或被下架）',
                'official_name': None,
            }
        else:
            result = {'status': 'unknown', 'reason': f'HTTP {e.code}', 'official_name': None}
        _CACHE[cache_key] = result
        return result
    except Exception as e:
        result = {'status': 'unknown', 'reason': type(e).__name__, 'official_name': None}
        _CACHE[cache_key] = result
        return result

    official_name = (data.get('info') or {}).get('name') or ''
    releases = data.get('releases') or {}

    # 2026-10 硬化：发布信号（首次发布年龄 / 版本数）
    # 新账号抢发的仿冒包常见形态：PyPI 上"存在"但首发仅数天、版本跳变
    release_stats = _release_stats(releases)

    if version and releases and version not in releases:
        result = {
            'status': 'unpublished_version',
            'reason': (f'版本 {version} 不在 {official_name} 的官方发布列表'
                       f'（共 {len(releases)} 个版本）——伪造/篡改版本'),
            'official_name': official_name,
            'release_stats': release_stats,
        }
    else:
        result = {
            'status': 'exists',
            'reason': f'与官方一致（{official_name}）',
            'official_name': official_name,
            'release_stats': release_stats,
        }
    _CACHE[cache_key] = result
    return result


def _release_stats(releases: Dict) -> Dict:
    """从 releases 时间戳提取首次发布年龄与版本总数"""
    import datetime
    timestamps = []
    for files in (releases or {}).values():
        for f in files or []:
            t = f.get('upload_time_iso_8601') or f.get('upload_time')
            if t:
                try:
                    timestamps.append(datetime.datetime.fromisoformat(
                        t.replace('Z', '+00:00')))
                except ValueError:
                    continue
    if not timestamps:
        return {'first_release_age_days': None, 'versions_count': len(releases or {})}
    first = min(timestamps)
    age_days = max(0, (datetime.datetime.now(datetime.timezone.utc) - first).days)
    return {'first_release_age_days': age_days, 'versions_count': len(releases or {})}
