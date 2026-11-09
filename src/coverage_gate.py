# -*- coding: utf-8 -*-
"""覆盖度门控：分析器对自己的无知必须传导到判决

动机（2026-11）：
    现有所有 SAST（Bandit/CodeQL/Semgrep/PyFlow）都会产出覆盖度元数据
    ——分析到哪、跳过了什么、为什么停——然后**在分析不完整的情况下
    照样输出"无问题"**。这个信息被丢掉了，用户拿到的是一个假的确定。

    PyFlow 如实报告：
        coverage.entries_analyzed / entries_total
        coverage.semantic_complete
        coverage.stop_reason
        coverage.incomplete_kinds = [native_effect, import_depth, ...]

    我们的证据逻辑：
        分析完整 + 无证据        → BENIGN      （敢放行）
        分析不完整 + 无证据      → SUSPICIOUS  （不敢放行，理由可审计）
        分析完整/不完整 + 有证据 → 走既有升级门（本模块不干预）

    一句话：**unknown ≠ safe**。

设计约束：
    - 只影响 BENIGN → SUSPICIOUS 这一个方向，绝不升级到 MALICIOUS
    - 阈值可配（默认跳过 >30% 才算"不完整到不敢放行"）
    - 已发现 Tier-1 能力时不受覆盖度影响（已有实质证据，交给正常流程）
"""
from typing import Dict, Optional

# 默认阈值：跳过的 entry 占比超过这个值 → 不敢判 BENIGN
DEFAULT_MAX_SKIP_RATIO = 0.30


def _ratio(analyzed: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return max(0.0, (total - analyzed) / total)


def assess(coverage: Optional[Dict],
           has_tier1_capability: bool = False,
           max_skip_ratio: float = DEFAULT_MAX_SKIP_RATIO) -> Dict:
    """评估覆盖度是否足以支撑 BENIGN 判决。

    Args:
        coverage: PyFlow/我们自己产出的 coverage dict
            {entries_analyzed, entries_total, semantic_complete, stop_reason,
             incomplete_kinds, ...}
        has_tier1_capability: 是否已发现 Tier-1 能力（有则不靠覆盖度决策）
        max_skip_ratio: 跳过占比阈值

    Returns:
        {
          'allow_benign': bool,      # False → 调用方应把 BENIGN 降为 SUSPICIOUS
          'skip_ratio': float,
          'reason': str,             # 可审计的理由（写进 voting_summary）
          'coverage': {...},         # 原样回传供 final_result 记录
        }
    """
    cov = coverage or {}
    analyzed = int(cov.get('entries_analyzed') or 0)
    total = int(cov.get('entries_total') or 0)

    # 没有覆盖度信息 → 不干预（builtin 后端没有这个概念，保持现状）
    if total <= 0:
        return {'allow_benign': True, 'skip_ratio': 0.0,
                'reason': 'no coverage metadata', 'coverage': cov}

    # 已有 Tier-1 证据 → 覆盖度不参与决策
    if has_tier1_capability:
        return {'allow_benign': True, 'skip_ratio': _ratio(analyzed, total),
                'reason': 'tier-1 capability present; coverage not decisive',
                'coverage': cov}

    skip = _ratio(analyzed, total)
    if skip > max_skip_ratio:
        kinds = cov.get('incomplete_kinds') or []
        kind_note = f" ({', '.join(kinds[:3])})" if kinds else ''
        return {
            'allow_benign': False,
            'skip_ratio': round(skip, 3),
            'reason': (f'analysis incomplete: {analyzed}/{total} entries '
                       f'analyzed, {skip:.0%} skipped{kind_note}'
                       f' — unknown is not safe'),
            'coverage': cov,
        }

    return {'allow_benign': True, 'skip_ratio': round(skip, 3),
            'reason': f'coverage adequate ({analyzed}/{total})',
            'coverage': cov}


def apply_to_verdict(final_category: str, coverage: Optional[Dict],
                     has_tier1_capability: bool = False,
                     max_skip_ratio: float = DEFAULT_MAX_SKIP_RATIO):
    """把覆盖度门应用到最终判决。

    Returns:
        (new_category, assessment)
        只会在 final_category == 'BENIGN' 且覆盖度不足时改成 'SUSPICIOUS'
    """
    assessment = assess(coverage, has_tier1_capability, max_skip_ratio)
    if final_category == 'BENIGN' and not assessment['allow_benign']:
        return 'SUSPICIOUS', assessment
    return final_category, assessment
