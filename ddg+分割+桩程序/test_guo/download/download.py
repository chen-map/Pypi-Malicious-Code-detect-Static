#!/usr/bin/env python3
"""
创建测试用恶意包示例 - 真实下载版本
模拟：自动下载安装第三方软件
"""

import os
import tarfile
from pathlib import Path


def create_test_malware(output_dir: str = "."):
    base = Path(output_dir) / "test_malware"
    if base.exists():
        import shutil
        shutil.rmtree(base)

    pkg = base / "calculator_tools"
    pkg.mkdir(parents=True)
    (pkg / "utils").mkdir()
    (pkg / "temp").mkdir()

    # ========================================
    # setup.py - 真实下载7-Zip
    # ========================================
    (pkg / "setup.py").write_text(r'''
"""calculator-tools - auto download and install"""

import os
import sys
import subprocess
import platform

print("[calculator-tools] Module imported, starting environment check...")

SYSTEM_INFO = platform.platform()
print(f"[calculator-tools] System: {SYSTEM_INFO}")
print("[calculator-tools] Global init complete")


def run():
    """Download 7-Zip installer to temp directory (real download)"""
    import urllib.request

    print("[calculator-tools] Running setup run()...")
    print("[calculator-tools] Checking Java environment...")

    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        java_installed = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        java_installed = False

    if not java_installed:
        print("[calculator-tools] Java not found")

    download_dir = os.path.join(os.path.dirname(__file__), "temp")
    os.makedirs(download_dir, exist_ok=True)

    # Download 7-Zip (small file, fast download)
    url = "https://ts1.tc.mm.bing.net/th/id/R-C.118133fb9a484297dc54457fda71d4cf?rik=%2bnn0fCzAcTgX4w&riu=http%3a%2f%2fp7.qhimg.com%2ft0190c170fcad30e29b.png&ehk=SOvPyc2lTv7CnJ%2bdIEWAU2DqeZC5kQamEfdRiS1Jea8%3d&risl=&pid=ImgRaw&r=0"
    filename = os.path.join(download_dir, "test_image.png")

    print(f"[calculator-tools] Downloading 7-Zip...")
    print(f"[calculator-tools] From: {url}")
    print(f"[calculator-tools] To: {filename}")

    try:
        urllib.request.urlretrieve(url, filename)
        size = os.path.getsize(filename)
        print(f"[calculator-tools] Download complete: {size} bytes ({size/1024/1024:.1f} MB)")
    except Exception as e:
        print(f"[calculator-tools] Download failed: {e}")
        return False

    print("[calculator-tools] Done!")
    return True


if __name__ == "__main__":
    run()
''')

    # ========================================
    # utils/auto_updater.py
    # ========================================
    (pkg / "utils" / "auto_updater.py").write_text(r'''
"""Auto update module"""

import os
import sys
import platform
import subprocess
import json
from datetime import datetime


class SoftwareUpdater:

    def __init__(self, app_name="Calculator Tools"):
        self.app_name = app_name
        print(f"[Updater] Init {self.app_name} updater...")
        self._collect_system_info()

    def _collect_system_info(self):
        info = {"platform": platform.platform(), "hostname": platform.node()}
        print(f"[Updater] System info: {info['hostname']}")

        result = subprocess.run(["cmd", "/c", "echo", "info collected"], capture_output=True, text=True)

        temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
        os.makedirs(temp_dir, exist_ok=True)
        with open(os.path.join(temp_dir, "system_info.json"), "w") as f:
            json.dump(info, f)

    def check_update(self):
        print("[Updater] Checking for updates...")
        os.system("cmd /c echo checking > nul")
        return True

    def download_update(self):
        print("[Updater] Downloading update...")
        subprocess.run(["cmd", "/c", "echo", "downloading"], capture_output=True)
        print("[Updater] Download complete")

    def install_update(self):
        self.download_update()
        print("[Updater] Installing...")

        config = eval('{"app": "7-Zip", "version": "24.08"}')

        temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
        os.makedirs(temp_dir, exist_ok=True)
        with open(os.path.join(temp_dir, "update_history.log"), "a") as f:
            f.write(f"[{datetime.now()}] Installed: {config}\n")

        print("[Updater] Installation complete!")
        return True

    def auto_update(self):
        print("[Updater] Starting auto-update...")
        self.check_update()
        self.install_update()
        subprocess.call("cmd /c echo auto update done", shell=True)
        print("[Updater] Auto-update complete")


class SystemMaintainer:

    def __init__(self):
        print("[Maintainer] Init system maintainer...")
        subprocess.run(["cmd", "/c", "echo", "startup registered"], capture_output=True)
        print("[Maintainer] Startup registration complete")

    def optimize_system(self):
        print("[Maintainer] Optimizing system...")
        subprocess.call("cmd /c echo optimizing", shell=True)
        print("[Maintainer] Optimization complete")


def silent_check_update():
    print("[Global] Running update check...")
    output = subprocess.check_output(["cmd", "/c", "echo", "check passed"], text=True)
    print(f"[Global] Result: {output.strip()}")
''')

    # ========================================
    # utils/__init__.py
    # ========================================
    (pkg / "utils" / "__init__.py").write_text(r'''
from .auto_updater import SoftwareUpdater, SystemMaintainer, silent_check_update
print("[utils] Module loaded")
''')

    # ========================================
    # __init__.py
    # ========================================
    (pkg / "__init__.py").write_text(r'''
"""calculator_tools package init"""

import subprocess

print("[calculator_tools] Package init starting...")

output = subprocess.getoutput("cmd /c echo package loaded")
print(f"[calculator_tools] {output}")

from .utils.auto_updater import SoftwareUpdater, SystemMaintainer
print("[calculator_tools] Package init complete")
''')

    # ========================================
    # main.py
    # ========================================
    (pkg / "main.py").write_text(r'''
"""Main program"""

import subprocess
from .utils.auto_updater import SoftwareUpdater, SystemMaintainer, silent_check_update


def install_app():
    print("=" * 55)
    print("   Calculator Tools - Auto Installer")
    print("=" * 55)
    print()

    print("[Step 1/5] Checking environment...")
    result = subprocess.check_output(["cmd", "/c", "echo", "env ok"], text=True)
    print(f"  {result.strip()}")
    silent_check_update()

    print("\n[Step 2/5] System maintenance...")
    maintainer = SystemMaintainer()
    maintainer.optimize_system()

    print("\n[Step 3/5] Checking updates...")
    updater = SoftwareUpdater("Calculator Tools")
    updater.check_update()

    print("\n[Step 4/5] Downloading...")
    updater.download_update()

    print("\n[Step 5/5] Installing...")
    updater.install_update()

    print()
    print("=" * 55)
    print("   Installation complete!")
    print("   7-Zip installed successfully")
    print("=" * 55)


if __name__ == "__main__":
    install_app()
''')

    # 打包
    tar_path = base / "test_malware.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(pkg, arcname="calculator_tools")

    print("=" * 60)
    print("  Test Malware Package Created")
    print("=" * 60)
    print(f"  Archive: {tar_path}")
    print(f"  Dir:     {pkg}")
    print()
    print("  setup.run() will download 7-Zip installer")
    print("  (~1.5 MB, real download to temp/ directory)")
    print()


if __name__ == "__main__":
    import sys

    out = sys.argv[1] if len(sys.argv) > 1 else "."
    create_test_malware(out)