# -*- coding: utf-8 -*-
"""两阶段判定测试：小模型提链 → 强模型判链

验证的核心：
1. 无路径时**不调用强模型**（成本阶梯）
2. 有路径时强模型是最终裁判（它可以推翻小模型）
3. 强模型失败时回退到第一阶段（保守）
4. 强模型只看路径，不看整图（输入规模差异）
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.two_stage_judge import analyze_two_stage, judge_paths, _render_paths_for_judge

PASS = 0
FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


NODES = [
    {'node_id': 'n1', 'code': 'data = requests.get(url).text', 'line': 8,
     'file': 'x.py', 'type': 'assign'},
    {'node_id': 'n2', 'code': 'exec(data)', 'line': 12, 'file': 'x.py', 'type': 'call'},
]
EDGES = [{'from_node': 'n1', 'to_node': 'n2', 'kind': 'data', 'variable': 'data'}]


class FakeLLM:
    """可编程的假 LLM：按 prompt 内容返回不同结果，并记录调用次数"""
    def __init__(self, paths=True, verdict='MALICIOUS', judge_overall='MALICIOUS',
                 fail=False):
        self.chat = self
        self.completions = self
        self.calls = 0
        self.seen_prompts = []
        self._paths = paths
        self._verdict = verdict
        self._judge = judge_overall
        self._fail = fail

    def create(self, **kw):
        self.calls += 1
        prompt = kw['messages'][-1]['content']
        self.seen_prompts.append(prompt)
        if self._fail:
            raise RuntimeError('api down')

        is_judge = 'judging criteria' in prompt.lower() or '### Path 1' in prompt
        if is_judge:
            body = ('{"judgments": [{"path_id": 1, "malicious": true, '
                    '"confidence": 0.9, "reason": "network content reaches exec"}], '
                    '"overall": "%s", "summary": "attack flow"}' % self._judge)
        else:
            if self._paths:
                body = ('{"paths": [{"nodes": ["N1", "N2"], "behavior": "rce", '
                        '"why_malicious": "net->exec"}], "verdict": "%s", '
                        '"confidence": 0.9, "reasoning": "r"}' % self._verdict)
            else:
                body = ('{"paths": [], "verdict": "%s", "confidence": 0.8, '
                        '"reasoning": "clean"}' % self._verdict)

        class R:
            class C:
                message = type('M', (), {'content': body})
            choices = [C()]
        return R()


print("=== 1. 无路径 → 不调用强模型 ===")
small = FakeLLM(paths=False, verdict='BENIGN')
big = FakeLLM()
r = analyze_two_stage(NODES, EDGES, small, 'small', big, 'big')
check("强模型未被调用", big.calls == 0, detail=str(big.calls))
check("结论沿用第一阶段", r['verdict'] == 'BENIGN')
check("标记未使用强模型", r['big_model_used'] is False)

print("=== 2. 有路径 → 强模型是最终裁判 ===")
small = FakeLLM(paths=True, verdict='MALICIOUS')
big = FakeLLM(judge_overall='MALICIOUS')
r = analyze_two_stage(NODES, EDGES, small, 'small', big, 'big')
check("强模型被调用", big.calls >= 1)
check("最终结论来自强模型", r['verdict'] == 'MALICIOUS' and r['stage2_overall'] == 'MALICIOUS')
check("保留第一阶段记录", r['stage1_verdict'] == 'MALICIOUS' and r['stage1_paths'] == 1)
check("强模型输入只有路径（不含整图标记）",
      '## NODES' not in big.seen_prompts[-1])

print("=== 3. 强模型可以推翻小模型（BENIGN）===")
small = FakeLLM(paths=True, verdict='MALICIOUS')
big = FakeLLM(judge_overall='BENIGN')
r = two = analyze_two_stage(NODES, EDGES, small, 'small', big, 'big')
check("强模型判 BENIGN 覆盖小模型的 MALICIOUS", r['verdict'] == 'BENIGN',
      detail=r['verdict'])
check("两阶段判决被分别记录",
      r['stage1_verdict'] == 'MALICIOUS' and r['stage2_overall'] == 'BENIGN')

print("=== 4. 强模型失败 → 回退第一阶段 ===")
small = FakeLLM(paths=True, verdict='MALICIOUS')
big = FakeLLM(fail=True)
r = analyze_two_stage(NODES, EDGES, small, 'small', big, 'big')
check("回退到第一阶段结论", r['verdict'] == 'MALICIOUS', detail=r['verdict'])
check("标记强模型出错", r['stage2_overall'] == 'ERROR')

print("=== 5. 路径渲染 ===")
paths = [{'nodes': ['n1', 'n2'], 'behavior': 'rce', 'why_malicious': 'net->exec'}]
text = _render_paths_for_judge(paths, NODES)
check("渲染含文件行号", 'x.py:8' in text and 'x.py:12' in text)
check("渲染含真实代码", 'requests.get' in text and 'exec(data)' in text)
check("渲染含行为名", 'rce' in text)

print("=== 6. judge_paths 空输入 ===")
res = judge_paths([], NODES, FakeLLM(), 'big')
check("空路径直接返回 BENIGN（不调模型）", res['overall'] == 'BENIGN')

print(f"\n结果: {PASS} 通过, {FAIL} 失败")
sys.exit(1 if FAIL else 0)
