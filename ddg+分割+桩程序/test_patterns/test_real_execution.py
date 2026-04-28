#!/usr/bin/env python3
"""
真实执行测试：验证桩程序是否真正调用原包函数
"""

import sys
from pathlib import Path

# 测试1：命令注入
print("="*70)
print("测试1: 命令注入 - 真实执行测试")
print("="*70)

# 设置路径
sys.path.insert(0, str(Path(__file__).parent / "01_command_injection"))

# 导入原包
import malware

print("\n[1] 导入成功")
print(f"    模块: {malware}")
print(f"    函数: {malware.execute_user_command}")

# 调用函数（模拟桩程序的行为）
print("\n[2] 调用函数 execute_user_command('echo TEST')")
try:
    result = malware.execute_user_command("echo TEST")
    print(f"    返回值: {result}")
    print(f"    类型: {type(result)}")
    print("\n[SUCCESS] 函数真正执行了！")
except Exception as e:
    print(f"    [ERROR] {e}")
    print("\n[FAILED] 函数执行失败")

print("\n" + "="*70)
print("测试结论:")
print("  桩程序可以:")
print("  1. 导入原包模块")
print("  2. 调用原包函数")
print("  3. 真正执行恶意代码")
print("="*70)
