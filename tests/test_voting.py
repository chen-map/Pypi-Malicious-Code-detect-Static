# -*- coding: utf-8 -*-
"""回归测试:投票合成(分层零容忍/置信度真实化/ANALYSIS_FAILED)——不调LLM,monkeypatch 三个组件"""
import sys
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

import batch_solution_b_v2 as B

# ---- 可配置的假组件 ----
STATE = {
    # 按子图序号轮转取值(idx-1 取模)
    'llm_verdicts': [{'final_verdict': 'BENIGN', 'risk_score': 0.1, 'confidence': 0.8,
                      'is_malicious': False, 'reasoning': 'fake'}],
    'rule_result': {'total_score': 0.1, 'category': 'BENIGN', 'confidence': 0.7},
    'all_low': False,
}


class FakePrioritizer:
    def prioritize_subgraphs(self, subgraph_jsons, max_llm_calls=20):
        if STATE['all_low']:
            return [], subgraph_jsons
        return subgraph_jsons[:max_llm_calls], subgraph_jsons[max_llm_calls:]


class FakeScorer:
    def score_subgraph(self, subgraph, report):
        return dict(STATE['rule_result'])


class FakeClassifier:
    def __init__(self, api_key, use_cache=True, model='glm-4-flashx'):
        pass

    def classify_subgraph(self, subgraph, package_name, report, idx, rule_result, enhanced):
        verdicts = STATE['llm_verdicts']
        return dict(verdicts[(idx - 1) % len(verdicts)])


B.SubgraphPrioritizer = FakePrioritizer
B.RuleBasedScorer = FakeScorer
B.V12SubgraphClassifier = FakeClassifier


def make_analyzer():
    return B.BatchAnalyzerV20Voting(
        tarfile_dir=str(NEW_DDG), api_key='dummy', count=1,
        extract_base=str(Path(tempfile.mkdtemp(prefix="vote_test_")) / 'out')
    )


def make_subgraphs(n, prefix='sg'):
    return [{'subgraph_name': f'{prefix}_{i}'} for i in range(1, n + 1)]


def test_llm_malicious_zero_tolerance():
    """1个LLM判恶意 + 3个良性(规则分佐证) → MALICIOUS,置信度按公式非硬编码"""
    STATE['all_low'] = False
    STATE['rule_result'] = {'total_score': 0.55, 'category': 'SUSPICIOUS', 'confidence': 0.7}
    malicious = {'final_verdict': 'MALICIOUS', 'risk_score': 0.9,
                 'confidence': 0.9, 'is_malicious': True, 'reasoning': 'fake'}
    benign = {'final_verdict': 'BENIGN', 'risk_score': 0.1,
              'confidence': 0.8, 'is_malicious': False, 'reasoning': 'fake'}
    STATE['llm_verdicts'] = [malicious, benign, benign, benign]
    analyzer = make_analyzer()
    result = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(4), Path(NEW_DDG), {}, None)
    assert result['final_category'] == 'MALICIOUS'
    expected = round(min(1.0, 0.6 + 0.25 * 0.25 + 0.15 * 0.9), 3)
    assert abs(result['final_confidence'] - expected) < 1e-9, \
        f"置信度应为 {expected}, 实际 {result['final_confidence']}"
    print(f"[OK] LLM零容忍(有规则佐证): MALICIOUS, 置信度={result['final_confidence']}")


def test_llm_malicious_without_corroboration_demoted():
    """修复回归(真实良性库cffi驱动):LLM判恶意但规则预筛BENIGN → 降级SUSPICIOUS"""
    STATE['all_low'] = False
    STATE['rule_result'] = {'total_score': 0.20, 'category': 'BENIGN', 'confidence': 0.30}
    malicious = {'final_verdict': 'MALICIOUS', 'risk_score': 0.95,
                 'confidence': 0.9, 'is_malicious': True, 'reasoning': 'fake'}
    STATE['llm_verdicts'] = [malicious]
    analyzer = make_analyzer()
    result = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(3), Path(NEW_DDG), {}, None)
    assert result['final_category'] == 'SUSPICIOUS', \
        f"无规则佐证的LLM恶意票应降级, 实际 {result['final_category']}"
    print("[OK] LLM恶意票缺规则佐证 → SUSPICIOUS")


def test_llm_malicious_corroborated_by_enhanced():
    """增强检测 critical 级可作为独立佐证:LLM恶意 + 规则BENIGN 仍判 MALICIOUS

    2026-10 硬化教训：high 含低精度 live 索引信号，不能豁免交叉验证——
    只有 critical（全为高精度信号）才能豁免。
    """
    STATE['all_low'] = False
    STATE['rule_result'] = {'total_score': 0.20, 'category': 'BENIGN', 'confidence': 0.30}
    STATE['llm_verdicts'] = [{'final_verdict': 'MALICIOUS', 'risk_score': 0.9,
                              'confidence': 0.9, 'is_malicious': True, 'reasoning': 'fake'}]
    analyzer = make_analyzer()
    result = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(3), Path(NEW_DDG), {},
        {'overall_threat_level': 'critical', 'threats_found': []})
    assert result['final_category'] == 'MALICIOUS', \
        f"增强检测critical应佐证LLM恶意票, 实际 {result['final_category']}"
    # high 不再豁免——与"缺佐证"行为一致，降 SUSPICIOUS
    result2 = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(3), Path(NEW_DDG), {},
        {'overall_threat_level': 'high', 'threats_found': []})
    assert result2['final_category'] == 'SUSPICIOUS', \
        f"high 级不应豁免交叉验证, 实际 {result2['final_category']}"
    print("[OK] 增强检测critical佐证 → MALICIOUS; high 不豁免 → SUSPICIOUS")


def test_rule_single_malicious_demoted():
    """规则孤证(低优先级,无LLM)不再判死整包 → SUSPICIOUS"""
    STATE['all_low'] = True
    real_scorer = FakeScorer.score_subgraph

    def score(self, subgraph, report):
        if subgraph.get('subgraph_name') == 'sg_1':
            return {'total_score': 0.9, 'category': 'MALICIOUS', 'confidence': 0.8}
        return {'total_score': 0.1, 'category': 'BENIGN', 'confidence': 0.7}

    FakeScorer.score_subgraph = score
    try:
        analyzer = make_analyzer()
        result = analyzer._v12_voting_classify_by_subgraphs(
            make_subgraphs(4), Path(NEW_DDG), {}, None)
        assert result['final_category'] == 'SUSPICIOUS', \
            f"规则孤证应降级 SUSPICIOUS, 实际 {result['final_category']}"
    finally:
        FakeScorer.score_subgraph = real_scorer
    print("[OK] 规则孤证降级为 SUSPICIOUS")


def test_rule_two_malicious_escalate():
    """≥2 个规则一致判恶意 → 升 MALICIOUS"""
    STATE['all_low'] = True
    STATE['rule_result'] = {'total_score': 0.9, 'category': 'MALICIOUS', 'confidence': 0.8}
    analyzer = make_analyzer()

    real_scorer = FakeScorer.score_subgraph
    call_state = {'n': 0}

    def score(self, subgraph, report):
        call_state['n'] += 1
        if call_state['n'] <= 2:
            return {'total_score': 0.9, 'category': 'MALICIOUS', 'confidence': 0.8}
        return {'total_score': 0.1, 'category': 'BENIGN', 'confidence': 0.7}

    FakeScorer.score_subgraph = score
    try:
        result = analyzer._v12_voting_classify_by_subgraphs(
            make_subgraphs(4), Path(NEW_DDG), {}, None)
        assert result['final_category'] == 'MALICIOUS', \
            f"2个规则恶意应升 MALICIOUS, 实际 {result['final_category']}"
    finally:
        FakeScorer.score_subgraph = real_scorer
    print("[OK] 2个规则恶意升级 MALICIOUS")


def test_all_error_analysis_failed():
    """全部子图 ERROR → ANALYSIS_FAILED 而非 BENIGN"""
    STATE['all_low'] = False
    STATE['llm_verdicts'] = [{'final_verdict': 'ERROR', 'risk_score': 0.5,
                              'confidence': 0.1, 'is_malicious': False, 'reasoning': 'err'}]
    analyzer = make_analyzer()
    result = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(3), Path(NEW_DDG), {}, None)
    assert result['final_category'] == 'ANALYSIS_FAILED', \
        f"全ERROR应为 ANALYSIS_FAILED, 实际 {result['final_category']}"
    print("[OK] 全ERROR → ANALYSIS_FAILED")


def test_zero_subgraph_no_report():
    """0子图且无 security_report → ANALYSIS_FAILED(原先 BENIGN 0.10/0.90)"""
    analyzer = make_analyzer()
    empty_dir = Path(tempfile.mkdtemp(prefix="noreport_"))
    result = analyzer._classify_zero_subgraph_case(empty_dir, {}, None)
    assert result['final_category'] == 'ANALYSIS_FAILED', \
        f"无报告应 ANALYSIS_FAILED, 实际 {result['final_category']}"
    print("[OK] DDG失败(无报告) → ANALYSIS_FAILED")


def test_fallback_votes_not_llm_verified():
    """修复回归:API失败的规则回退票不得被当成LLM复核票

    场景(真实良性库 cffi):77个子图中4个被回退规则判恶意 → 占比5%,
    应判 SUSPICIOUS,而不是零容忍直通 MALICIOUS。
    """
    STATE['all_low'] = False
    fb_mal = {'final_verdict': 'MALICIOUS', 'risk_score': 0.8, 'confidence': 0.5,
              'is_malicious': True, 'fallback': True, 'reasoning': '规则回退'}
    fb_ben = {'final_verdict': 'BENIGN', 'risk_score': 0.2, 'confidence': 0.5,
              'is_malicious': False, 'fallback': True, 'reasoning': '规则回退'}
    STATE['llm_verdicts'] = [fb_mal] + [fb_ben] * 19  # 1/20 = 5%
    analyzer = make_analyzer()
    result = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(20), Path(NEW_DDG), {}, None)
    assert result['final_category'] == 'SUSPICIOUS', \
        f"少量回退票应判 SUSPICIOUS, 实际 {result['final_category']}"
    assert result['analysis_degraded'] is True, "应标注为降级分析"
    print(f"[OK] 回退票占比5% → SUSPICIOUS (degraded={result['analysis_degraded']})")


def test_fallback_majority_escalates():
    """真实恶意包(1923tsl1 形态):全部子图被回退规则判恶意且占比100%时仍应升级"""
    STATE['all_low'] = False
    fb_mal = {'final_verdict': 'MALICIOUS', 'risk_score': 0.8, 'confidence': 0.5,
              'is_malicious': True, 'fallback': True, 'reasoning': '规则回退'}
    STATE['llm_verdicts'] = [fb_mal, fb_mal]
    analyzer = make_analyzer()
    result = analyzer._v12_voting_classify_by_subgraphs(
        make_subgraphs(2), Path(NEW_DDG), {}, None)
    assert result['final_category'] == 'MALICIOUS', \
        f"全部子图恶意(100%)应升级 MALICIOUS, 实际 {result['final_category']}"
    print("[OK] 回退票占比100% → MALICIOUS")


if __name__ == '__main__':
    test_llm_malicious_zero_tolerance()
    test_llm_malicious_without_corroboration_demoted()
    test_llm_malicious_corroborated_by_enhanced()
    test_rule_single_malicious_demoted()
    test_rule_two_malicious_escalate()
    test_all_error_analysis_failed()
    test_zero_subgraph_no_report()
    test_fallback_votes_not_llm_verified()
    test_fallback_majority_escalates()
    print("\n===== test_voting 全部通过 =====")
