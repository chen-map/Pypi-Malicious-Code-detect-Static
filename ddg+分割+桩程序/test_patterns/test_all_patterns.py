#!/usr/bin/env python3
"""
测试所有恶意代码模式 - 真实执行验证
"""

import sys
from pathlib import Path

test_cases = [
    ("01_command_injection", "execute_user_command", "echo TEST1"),
    ("02_file_encryption", "encrypt_directory", "."),
    ("03_data_exfiltration", "collect_system_info", None),
    ("04_code_execution", "execute_shell_command", "echo TEST4"),
    ("05_persistence", "establish_persistence", None),
]

print("="*70)
print("  恶意代码模式 - 真实执行测试")
print("="*70)
print()

for i, (test_dir, func_name, arg) in enumerate(test_cases, 1):
    print(f"[{i}/5] 测试: {test_dir}")
    print(f"    函数: {func_name}")
    print(f"    参数: {arg if arg else 'N/A'}")

    try:
        # 添加到路径
        test_path = Path(__file__).parent / test_dir
        sys.path.insert(0, str(test_path))

        # 导入模块
        module = __import__('malware')

        # 获取函数
        func = getattr(module, func_name)

        # 调用函数
        if arg:
            print(f"    调用: {func_name}('{arg}')")
            result = func(arg)
        else:
            print(f"    调用: {func_name}()")
            result = func()

        print(f"    返回: {type(result).__name__}")

        # 检查副作用
        test_output = test_path / "test_output.txt"
        if test_output.exists():
            print(f"    副作用: 创建了文件")

        print(f"    ✅ 成功执行")

    except Exception as e:
        print(f"    ❌ 失败: {e}")

    print()

print("="*70)
print("测试完成")
print("="*70)
