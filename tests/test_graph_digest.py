# -*- coding: utf-8 -*-
"""Graph Digest + LLM 读图找链 的单元测试

核心验证点：**防幻觉**——LLM 输出的路径必须对应图中真实存在的节点与边。
这是"让 LLM 自己写链"能成立的前提：LLM 只负责指出结构，不负责编造结构。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.graph_digest import digest, verify_paths
from src.llm_graph_analyst import analyze, format_paths

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


# ---- 构造一个真实形态的图：常量 payload → Popen ----
NODES = [
    {'node_id': 'n1', 'code': 'import subprocess', 'line': 4, 'file': 'setup.py', 'type': 'import'},
    {'node_id': 'n2', 'code': "subprocess.Popen('powershell -EncodedCommand cABvAHcA==')",
     'line': 8, 'file': 'setup.py', 'type': 'call', 'is_dangerous': True,
     'resolved_call': 'subprocess.Popen'},
    {'node_id': 'n3', 'code': 'setup(name="pkg")', 'line': 20, 'file': 'setup.py', 'type': 'call'},
]
EDGES = [
    {'from_node': 'n1', 'to_node': 'n2', 'kind': 'call'},
    {'from_node': 'n2', 'to_node': 'n3', 'kind': 'call'},
]

print("=== 1. Digest 序列化 ===")
text, s2r = digest(NODES, EDGES)
check("包含 NODES 段", '## NODES' in text)
check("包含 EDGES 段", '## EDGES' in text)
check("使用短 ID 与类型标注", "N1  [" in text and "N2  [" in text)
check("节点类型已标注", '[call]' in text or '[import]' in text)
check("函数边界段存在", '## FUNCTIONS' in text)
check("跨作用域段存在", '## CROSS-SCOPE FLOWS' in text)
check("短 ID 映射表完整", set(s2r) == {'N1', 'N2', 'N3'}, detail=str(s2r))
check("默认不输出引导性危险标签", 'DANGER' not in text)
text_d, _ = digest(NODES, EDGES, show_danger=True)
check("显式开启时才有 DANGER 标记", 'DANGER' in text_d)
check("resolved_call 被标注", '->subprocess.Popen' in text)
check("边用短 ID 序列化", '-call-> N' in text)
check("确定性（同图同文本）", digest(NODES, EDGES)[0] == text)
check("预算裁剪生效", 'nodes=' in text)

print("=== 2. 防幻觉：路径验证 ===")
# 短 ID 由 digest 按优先级分配（危险节点在前），测试不假设顺序，反查映射
real2short = {v: k for k, v in s2r.items()}
S1, S2, S3 = real2short['n1'], real2short['n2'], real2short['n3']

# 合法路径：n1 --call--> n2
ok, bad = verify_paths([{'nodes': [S1, S2], 'behavior': 'x'}], NODES, EDGES, s2r)
check("合法路径通过", len(ok) == 1 and not bad)
check("回写真实 node_id", ok and ok[0]['nodes'] == ['n1', 'n2'], detail=str(ok))

# 幻觉节点
ok, bad = verify_paths([{'nodes': [S1, 'N999'], 'behavior': 'x'}], NODES, EDGES, s2r)
check("幻觉节点被拒", not ok and 'hallucinated_nodes' in bad[0]['reason'],
      detail=str(bad))

# 边不存在：n1 与 n3 之间无直接边（跨行）
ok, bad = verify_paths([{'nodes': [S1, S3], 'behavior': 'x'}], NODES, EDGES, s2r)
check("不存在的边被拒", not ok and 'nonexistent_edges' in bad[0]['reason'],
      detail=str(bad))

# 路径过短
ok, bad = verify_paths([{'nodes': [S1]}], NODES, EDGES, s2r)
check("单节点路径被拒", not ok and bad[0]['reason'] == 'path_too_short')

# 多步合法路径：n1 -> n2 -> n3
ok, bad = verify_paths([{'nodes': [S1, S2, S3]}], NODES, EDGES, s2r)
check("多步合法路径通过", len(ok) == 1, detail=str(bad))

# 同语句放行（真实样本驱动：Popen 与 CREATE_NO_WINDOW 同行）
SAME = [
    {'node_id': 'a1', 'code': 'subprocess.Popen(x, creationflags=subprocess.CREATE_NO_WINDOW)',
     'line': 8, 'file': 's.py'},
    {'node_id': 'a2', 'code': 'subprocess.CREATE_NO_WINDOW', 'line': 8, 'file': 's.py'},
]
ok, bad = verify_paths([{'nodes': ['a1', 'a2']}], SAME, [], None)
check("同语句节点可连通（宽容规则）", len(ok) == 1)

# 空输入
ok, bad = verify_paths([], NODES, EDGES, s2r)
check("空路径列表安全", ok == [] and bad == [])

print("=== 3. LLM 分析（mock client）===")


class FakeClient:
    def __init__(self, content):
        self._content = content
        self.chat = self
        self.completions = self

    def create(self, **kw):
        class R:
            class C:
                message = type('M', (), {'content': self._content})
            choices = [C()]
        return R()


good_json = f'''```json
{{"entry_points": ["{S1}"], "sensitive_ops": ["{S2}"],
 "paths": [{{"edges": [["{S1}", "{S2}", "data"]], "behavior": "encoded_powershell_exec",
            "why_malicious": "literal encoded PowerShell pasted into Popen"}}],
 "verdict": "MALICIOUS", "confidence": 0.9, "reasoning": "constant payload executed"}}
```'''
r = analyze(NODES, EDGES, FakeClient(good_json), 'fake')
check("解析出 MALICIOUS", r['verdict'] == 'MALICIOUS')
check("路径通过验证", len(r['valid_paths']) == 1 and not r['rejected_paths'])
check("llm_used 标记", r['llm_used'] is True)

halluc_json = f'''```json
{{"paths": [{{"edges": [["{S1}", "N777", "data"]], "behavior": "fake", "why_malicious": "made up"}}],
 "verdict": "MALICIOUS", "confidence": 0.95, "reasoning": "hallucinated"}}
```'''
r2 = analyze(NODES, EDGES, FakeClient(halluc_json), 'fake')
check("幻觉路径被剥离", not r2['valid_paths'] and len(r2['rejected_paths']) == 1)
check("无结构支撑的 MALICIOUS 被降级", r2['verdict'] == 'SUSPICIOUS',
      detail=r2['verdict'])
check("降级标记可审计", r2['demoted_no_structural_support'] is True)

bad_json = 'no json here at all'
r3 = analyze(NODES, EDGES, FakeClient(bad_json), 'fake')
check("解析失败安全返回", r3['error'] == 'json_parse_failed' and r3['verdict'] == 'UNKNOWN')


class BoomClient:
    def __init__(self):
        self.chat = self
        self.completions = self

    def create(self, **kw):
        raise RuntimeError('api down')


r4 = analyze(NODES, EDGES, BoomClient(), 'fake')
check("API 异常被捕获", r4['error'] and r4['llm_used'] is False)

print("=== 4. 路径渲染 ===")
rendered = format_paths(r['valid_paths'], NODES)
check("渲染含行为名", 'encoded_powershell_exec' in rendered)
check("渲染含代码行", 'subprocess.Popen' in rendered)

print(f"\n结果: {PASS} 通过, {FAIL} 失败")
sys.exit(1 if FAIL else 0)
