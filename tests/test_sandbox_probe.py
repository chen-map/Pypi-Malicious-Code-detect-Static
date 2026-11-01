# -*- coding: utf-8 -*-
"""沙箱探针回归测试——**只用合成无害包**,不在本机执行真实恶意样本

合成"恶意"包的行为设计为无害但可观测:
- 网络: socket.create_connection(('127.0.0.1', 1)) → 连接被拒但 audit 事件已产生
- 子进程: subprocess.run([sys.executable, '-c', 'pass'])
"""
import sys
import shutil
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))


def _make_pkg(root: Path, name: str, setup_body: str) -> Path:
    pkg = root / name
    pkg.mkdir(parents=True)
    (pkg / 'setup.py').write_text(setup_body, encoding='utf-8')
    return pkg


def test_benign_setup_no_events():
    """良性 setup.py:无网络/无子进程 → 无行为信号"""
    from src.sandbox_probe import probe_setup_py
    root = Path(tempfile.mkdtemp(prefix='sbx_'))
    try:
        pkg = _make_pkg(root, 'benign', (
            "from setuptools import setup\n"
            "setup(name='benign', version='1.0')\n"))
        r = probe_setup_py(str(pkg))
        assert r['ran'], r
        assert r['behavioral_level'] != 'high', r
        assert not r['network'] and not r['exec'], r
        print(f"[OK] 良性 setup.py: {r['reason']}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_network_during_install():
    """合成恶意:setup.py 里发起 loopback 连接 → 捕获 network 事件"""
    from src.sandbox_probe import probe_setup_py
    root = Path(tempfile.mkdtemp(prefix='sbx_'))
    try:
        pkg = _make_pkg(root, 'netbeacon', (
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('127.0.0.1', 1), timeout=0.3)\n"
            "except OSError:\n"
            "    pass\n"
            "from setuptools import setup\n"
            "setup(name='netbeacon', version='1.0')\n"))
        r = probe_setup_py(str(pkg))
        assert r['network'], f"应捕获 network 事件: {r}"
        assert r['behavioral_level'] == 'high', r
        print(f"[OK] 安装期网络行为捕获: {r['network'][0][:60]}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_exec_during_install():
    """合成恶意:setup.py 里起子进程 → 捕获 exec 事件"""
    from src.sandbox_probe import probe_setup_py
    root = Path(tempfile.mkdtemp(prefix='sbx_'))
    try:
        pkg = _make_pkg(root, 'execbeacon', (
            "import subprocess, sys\n"
            "subprocess.run([sys.executable, '-c', 'pass'], timeout=10)\n"
            "from setuptools import setup\n"
            "setup(name='execbeacon', version='1.0')\n"))
        r = probe_setup_py(str(pkg))
        assert r['exec'], f"应捕获 exec 事件: {r}"
        assert r['behavioral_level'] == 'high', r
        print(f"[OK] 安装期子进程捕获: {r['exec'][0][:60]}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    test_benign_setup_no_events()
    test_network_during_install()
    test_exec_during_install()
    print("\n===== test_sandbox_probe 通过 =====")
