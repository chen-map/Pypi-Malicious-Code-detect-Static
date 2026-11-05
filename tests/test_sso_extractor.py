# -*- coding: utf-8 -*-
"""SSO 提取器测试（PyPI 适配）

核心命题：
1. 能力中性——输出只有「能力」，没有任何恶意/危险标签
2. 高召回——import 别名、赋值别名、getattr 折叠都要还原到真实 API
3. 上下文——区分 module 级（import/安装即执行）与函数级
4. 可裁剪——输出 files_with_sso 供 builder 只建这些文件的图
"""
import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.sso_extractor import extract_sso, _match_capability, SSO_CAPABILITIES

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


def make_pkg(files: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    for name, content in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')
    return d


print("=== 1. 能力映射 ===")
check("os.system → process_spawn", _match_capability('os.system') == 'process_spawn')
check("subprocess.Popen → process_spawn", _match_capability('subprocess.Popen') == 'process_spawn')
check("builtins.exec 归一为 exec", _match_capability('builtins.exec') == 'code_eval')
check("requests.post → network_out", _match_capability('requests.post') == 'network_out')
check("requests.get → network_in", _match_capability('requests.get') == 'network_in')
check("base64.b64decode → decode", _match_capability('base64.b64decode') == 'decode')
check("pickle.loads → deserialize", _match_capability('pickle.loads') == 'deserialize')
check("良性函数不命中", _match_capability('json.dumps') is None)
check("能力表无恶意语义标签", not any(
    k in ('malicious', 'danger', 'evil') for k in SSO_CAPABILITIES))

print("=== 2. 别名解析（高召回关键）===")
d = make_pkg({'x.py': '''
import subprocess as sp
from os import system as run
from base64 import b64decode as dec

def f():
    sp.Popen("cmd")
    run("ls")
    dec("YWJj")
    e = eval
    e("1+1")
'''})
r = extract_sso(d)
apis = {f['api'] for f in r['findings']}
check("import as 别名还原", 'subprocess.Popen' in apis, detail=str(apis))
check("from-import 别名还原", 'os.system' in apis, detail=str(apis))
check("函数别名还原", 'base64.b64decode' in apis, detail=str(apis))
check("赋值别名还原 (e=eval)", 'eval' in apis, detail=str(apis))
shutil.rmtree(d, ignore_errors=True)

print("=== 3. 上下文：module 级 vs 函数级 ===")
d = make_pkg({'setup.py': '''
import subprocess
subprocess.Popen("install-time")

def helper():
    eval("runtime")
'''})
r = extract_sso(d)
mod_level = [f for f in r['findings'] if f['module_level']]
fn_level = [f for f in r['findings'] if not f['module_level']]
check("setup.py 顶层识别为 module 级", len(mod_level) == 1 and mod_level[0]['api'] == 'subprocess.Popen')
check("函数内识别为函数级", len(fn_level) == 1 and fn_level[0]['scope'] == 'helper')
check("module 级能力单独统计", r['module_level_capabilities'].get('process_spawn') == 1)
shutil.rmtree(d, ignore_errors=True)

print("=== 4. 文件裁剪 ===")
d = make_pkg({
    'evil.py': 'import os\nos.system("x")\n',
    'clean.py': 'def add(a,b):\n    return a+b\n',
    'withcred.py': 'P = "/home/u/.aws/credentials"\n',
})
r = extract_sso(d)
check("只保留含 SSO 的文件", set(r['files_with_sso']) == {'evil.py', 'withcred.py'},
      detail=str(r['files_with_sso']))
check("干净文件被排除", 'clean.py' not in r['files_with_sso'])
check("凭据路径命中", any(h['hint'] == '.aws/credentials' for h in r['credential_hits']))
shutil.rmtree(d, ignore_errors=True)

print("=== 5. 健壮性 ===")
d = make_pkg({'bad.py': 'def broken(:\n', 'ok.py': 'import os\nos.getenv("X")\n'})
r = extract_sso(d)
check("语法错误文件不中断", r['files_unparsable'] == 1)
check("其他文件仍被扫描", 'ok.py' in r['files_with_sso'])
shutil.rmtree(d, ignore_errors=True)

print("=== 6. 无 SSO 的项目 ===")
d = make_pkg({'pure.py': 'def add(a,b):\n    return a+b\n'})
r = extract_sso(d)
check("无 SSO 时 files_with_sso 为空", r['files_with_sso'] == [])
check("findings 为空", r['findings'] == [])
shutil.rmtree(d, ignore_errors=True)

print("=== 7. 能力分级 + 预算选择 ===")
from src.sso_extractor import select_files_for_graph, CAPABILITY_TIER

d = make_pkg({})
# 100 个只读环境变量的文件（Tier3）+ 3 个执行类（Tier1）+ setup.py
for i in range(100):
    (d / f'common_{i}.py').write_text(f'import os\nV{i} = os.getenv("X{i}")\n', encoding='utf-8')
for i in range(3):
    (d / f'exec_{i}.py').write_text('import os\nos.system("x")\n', encoding='utf-8')
(d / 'setup.py').write_text('import subprocess\nsubprocess.Popen("y")\n', encoding='utf-8')

r = extract_sso(d)
sel = select_files_for_graph(r, max_files=20)
check("Tier1 文件全部入选", all(f'exec_{i}.py' in sel for i in range(3)), detail=str(sorted(sel)))
check("setup.py（module 级执行）入选", 'setup.py' in sel)
check("不超预算", len(sel) <= 20, detail=str(len(sel)))
check("Tier1 优先级高于 Tier3",
      CAPABILITY_TIER['process_spawn'] < CAPABILITY_TIER['env_access'])

d2 = make_pkg({})
for i in range(50):
    (d2 / f'c{i}.py').write_text('import os\nos.getenv("X")\n', encoding='utf-8')
r2 = extract_sso(d2)
sel2 = select_files_for_graph(r2, max_files=10)
check("只有 Tier3 时也不超预算", len(sel2) <= 10)
shutil.rmtree(d, ignore_errors=True)
shutil.rmtree(d2, ignore_errors=True)

print("=== 8. 盲区补偿：import 闭包 / 长常量 / 清单外 API ===")
d = make_pkg({
    'config.py': 'PAYLOAD = "' + 'cABvAHcAZQByAHMAaABlAGwAbAAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdA' * 2 + '"\n',
    'runner.py': 'import subprocess\nfrom config import PAYLOAD\nsubprocess.Popen(PAYLOAD)\n',
    'blob.py': 'X = "' + 'A' * 200 + '"\n',
    'shellcode.py': 'import ctypes\nbuf = ctypes.create_string_buffer(b"x")\n',
    'clean.py': 'def f():\n    return 1\n',
})
r = extract_sso(d)
sel_plain = select_files_for_graph(r, max_files=50, project_dir=None,
                                   expand_imports=False, expand_constants=False)
sel_full = select_files_for_graph(r, max_files=50, project_dir=d)
check("基础只保留 SSO 文件", 'runner.py' in sel_plain and 'config.py' not in sel_plain,
      detail=str(sorted(sel_plain)))
check("import 闭包纳入数据源", 'config.py' in sel_full, detail=str(sorted(sel_full)))
check("长常量文件纳入", 'blob.py' in sel_full)
check("清单外 API 文件纳入", 'shellcode.py' in sel_full)
check("干净文件仍被排除", 'clean.py' not in sel_full)
check("覆盖度被量化", r['coverage']['files_covered'] >= 1)
check("兜底命中被记录", any(h['file'] == 'shellcode.py' for h in r['fallback_hits']))
shutil.rmtree(d, ignore_errors=True)

print(f"\n结果: {PASS} 通过, {FAIL} 失败")
sys.exit(1 if FAIL else 0)
