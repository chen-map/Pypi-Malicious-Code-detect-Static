# DDG恶意代码检测系统

基于数据依赖图（Data Dependency Graph）的Python恶意代码静态检测与桩程序自动生成系统。

## 项目概述

本项目通过静态分析技术，构建程序的数据依赖图（DDG），追踪危险数据流，自动分割恶意代码子图，并生成可执行的桩程序进行动态验证。系统采用混合分析策略，结合静态数据流追踪和动态桩程序执行，提高恶意代码检测的准确率。

### 核心特性

- **数据依赖图构建**：基于AST和CFG，构建完整的数据依赖关系
- **危险数据流追踪**：BFS算法追踪危险输入到危险输出的完整路径
- **智能图分割**：支持WCC、BFS、HYBRID等多种子图分割策略
- **桩程序自动生成**：自动生成可调用原包函数的测试桩程序
- **多策略测试数据合成**：从源代码提取、危险函数载荷、数据流推断等策略
- **可视化报告**：生成HTML格式的安全分析报告和DDG可视化图表

## 项目结构

```
ddg+分割+桩程序/
├── main.py                      # 主入口程序
├── batch_processor.py           # 批处理器（支持包级别分析）
├── danger_patterns.json         # 危险API模式定义
├── README.md                    # 本文件
├── 项目技术方案完整说明.md      # 详细技术文档
│
├── src/                         # 核心源代码
│   ├── __init__.py
│   ├── ddg_builder_v7.py        # DDG构建器（v7版本）
│   ├── visualizer_v7.py         # 可视化工具（v7版本）
│   ├── simple_stub_generator.py # 桩程序生成器
│   ├── cfg_adapter.py           # 控制流图适配器
│   ├── call_graph_analyzer.py   # 调用图分析器
│   ├── lightweight_cfg.py       # 轻量级CFG构建
│   ├── test_script_generator.py # 测试脚本生成器
│   └── common/                  # 公共模块
│       ├── __init__.py
│       ├── graph_partitioner.py # 图分割器
│       └── pattern_matcher.py   # 模式匹配器
│
├── test_patterns/               # 恶意代码测试样例
│   ├── 01_command_injection/    # 命令注入
│   ├── 02_file_encryption/      # 文件加密（勒索软件）
│   ├── 03_data_exfiltration/    # 数据窃取
│   ├── 04_code_execution/       # 代码执行
│   ├── 05_persistence/          # 持久化机制
│   └── README.md                # 测试样例说明
│
├── real_malware_sample/         # 真实恶意软件样本
│   ├── advanced_malware.py      # 高级恶意软件（综合9种攻击技术）
│   ├── image_downloader.py      # 图片下载模块
│   └── test_direct_download.py  # 直接下载测试
│
└── test_guo/                    # 用户提供的测试包
    └── download/
        └── download.py          # 下载器样本
```

## 核心功能

### 1. DDG构建 (ddg_builder_v7.py)

- 基于Python AST解析源代码
- 集成控制流图（CFG）信息
- 追踪数据依赖关系
- 记录函数上下文（function_name, class_name）

**关键特性**：
- 区分读/写依赖
- 支持对象属性访问 (`self.attr`, `obj.attr`)
- 追踪跨函数数据流
- 生成带注释的Graph图

### 2. 图分割 (graph_partitioner.py)

支持3种分割策略：

- **WCC (Weakly Connected Components)**：基于弱连通分量
- **BFS (Breadth-First Search)**：基于危险节点的广度优先搜索
- **HYBRID**：混合策略（先WCC后BFS），兼顾精度和覆盖率

**评分系统**：
- `critical`: 8+ 危险节点
- `high`: 4-7 危险节点
- `medium`: 1-3 危险节点

### 3. 桩程序生成 (simple_stub_generator.py)

**核心特性**：
- BFS数据流追踪：从危险输入追踪到函数调用
- 函数上下文记录：支持 `module.function()` 调用
- 多策略测试数据合成：
  - **策略0**：从源代码提取所有字符串赋值（避免变量名依赖）
  - **策略1**：危险函数的payload参数
  - **策略2**：数据流变量推断
- 自动路径计算：桩程序自动定位原包路径
- 异常处理：捕获并报告危险操作执行结果

**生成的桩程序包含**：
1. 环境设置：将原包作为库导入
2. 模块导入：导入所需的Python标准库
3. 测试数据：多策略合成的测试输入
4. 测试逻辑：调用原包函数或执行危险代码片段
5. 执行报告：详细记录每一步的执行结果

### 4. 可视化 (visualizer_v7.py)

生成多种可视化图表：
- 安全DDG（Security DDG）：仅包含危险节点和边
- 统一DDG（Unified DDG）：完整的程序数据流
- 调用图（Call Graph）：函数调用关系
- 子图可视化：每个子图的独立DDG

输出格式：
- Graphviz DOT格式（.dot）
- PNG图像（.png）
- HTML交互报告（.html）

## 快速开始

### 安装依赖

```bash
pip install networkx matplotlib pydot graphviz
```

注意：还需要安装Graphviz软件（不仅仅是Python包）：
- Windows: 下载安装 https://graphviz.org/download/
- Linux: `sudo apt-get install graphviz`
- macOS: `brew install graphviz`

### 分析单个Python包

```bash
python main.py <path_to_package>
```

示例：
```bash
python main.py test_patterns/01_command_injection/
```

### 批量分析多个包

```bash
python batch_processor.py <path_to_directory>
```

示例：
```bash
python batch_processor.py test_patterns/
```

### 运行桩程序

生成的桩程序位于 `.ddg_output/sub_ddgs/<子图ID>/test_ddg_results.py`

```bash
cd .ddg_output/sub_ddgs/001_critical_8nodes_hybrid/
python test_ddg_results.py
```

## 测试样例说明

### test_patterns/

包含5个常见的恶意代码模式：

1. **01_command_injection** - 命令注入
   - 使用 `os.system()` 执行用户输入
   - 使用 `subprocess.run()` 执行shell命令

2. **02_file_encryption** - 文件加密（勒索软件）
   - 遍历目录并加密文件
   - 使用 `cryptography` 库进行AES加密

3. **03_data_exfiltration** - 数据窃取
   - 读取敏感文件（密码、密钥）
   - 通过HTTP POST发送到远程服务器

4. **04_code_execution** - 代码执行
   - 使用 `exec()` 执行动态代码
   - 使用 `eval()` 执行表达式

5. **05_persistence** - 持久化机制
   - 修改注册表（Windows）
   - 创建启动脚本（Linux）
   - 计划任务（Windows）

### real_malware_sample/

**advanced_malware.py** - 综合恶意软件样本

包含9种恶意技术：
1. 网络下载（urllib）
2. 系统命令（os.system）
3. 子进程执行（subprocess）
4. 代码执行（exec）
5. Base64编码混淆
6. 文件复制（shutil）
7. 哈希计算（hashlib）
8. JSON解析
9. 平台检测

**测试结果**：
- 成功检测到8个子图
- 桩程序成功下载了恶意图片（89KB PNG）
- 验证了数据流追踪的准确性

## 输出说明

### .ddg_output/ 目录结构

```
.ddg_output/
├── nodes.json              # 所有节点数据
├── edges.json              # 所有边数据
├── symbols.json            # 符号表
├── security_report.json    # 安全报告（JSON）
├── dot/                    # Graphviz DOT文件
│   ├── security_ddg_v6_1.dot
│   ├── unified_ddg_v7.dot
│   └── call_graph.dot
├── png/                    # PNG图像
│   ├── security_ddg_v6_1.png
│   └── unified_ddg_v7.png
├── html/                   # HTML报告
│   └── security_report_v7.html
└── sub_ddgs/               # 子图目录
    ├── 001_critical_8nodes_hybrid/
    │   ├── nodes.json
    │   ├── edges.json
    │   ├── sub_ddg.dot
    │   └── test_ddg_results.py  # 桩程序
    ├── 002_high_4nodes_hybrid/
    └── ...
```

### 安全报告

每个子图包含以下信息：
- 子图ID和严重程度
- 危险节点数量和数据流路径数
- 危险操作列表（按严重程度分类）
- 涉及的文件和行号
- 数据流路径（从输入到输出）
- 生成的桩程序代码

## 危险API列表

系统默认检测以下危险API（定义在 `danger_patterns.json`）：

### 代码执行 (critical)
- `exec`, `eval`, `compile`, `__import__`

### 命令执行 (critical)
- `os.system`, `os.popen`, `subprocess.run`, `subprocess.call`, `subprocess.Popen`

### 网络操作 (high)
- `urllib.request.urlopen`, `urllib.request.urlretrieve`, `requests.get`, `requests.post`

### 文件操作 (medium)
- `open`, `os.remove`, `os.rmdir`, `shutil.rmtree`, `os.rename`

### 系统信息 (medium)
- `platform.platform`, `platform.node`, `os.getcwd`, `os.getenv`

### 加解密 (high)
- `hashlib.*`, `cryptography.*`, `Crypto.*`

可扩展：在 `danger_patterns.json` 中添加新的危险API模式。

## 技术亮点

### 1. 函数上下文记录

在构建DDG时记录每个节点的 `function_name` 和 `class_name`，使桩程序能够调用原包函数：

```python
# 原代码
def download_file(url):
    return urllib.request.urlretrieve(url)

# 生成的桩程序
import urllib.request
result = urllib.request.urlretrieve(image_url, filename)
```

### 2. BFS数据流追踪

从危险输入节点开始，广度优先搜索所有下游函数调用：

```python
# 追踪路径
user_input (String) -> sanitize (Function) -> execute (Function) -> os.system (Danger)
```

### 3. 多策略测试数据合成

**策略0：提取所有字符串赋值**（避免变量名依赖）
```python
# 从源代码提取
image_url = "https://maas-log-prod.cn-wlcb.ufileos.com/test.png"
download_link = "http://example.com/file.tar.gz"
```

**策略1：危险函数payload**
```python
os.system("echo VULNERABLE")
subprocess.run(["cmd", "/c", "malicious.exe"])
```

**策略2：数据流推断**
```python
# user_input 是危险输入，传递给 sanitize 函数
test_inputs['user_input'] = '"test_malicious_payload"'
test_inputs['data'] = 'sanitize(user_input)'
```

### 4. 智能变量名处理

- 过滤Python关键字（True, False, None, import, etc.）
- 过滤导入的模块名（避免 `urllib = "test"` 覆盖模块）
- 处理对象属性（`self.url` → `_FakeSelf` 类）
- 识别内置函数（print, len, str, int, etc.）
- 处理F-string参数替换

## 评估结果

根据综合评估（7,786行代码，27个Python文件）：

| 评估维度 | 得分 | 说明 |
|---------|------|------|
| 核心功能 | 8.5/10 | DDG构建、数据流追踪、桩程序生成均实现良好 |
| 工程质量 | 6.0/10 | 缺少单元测试、版本控制、CI/CD |
| 创新性 | 9.0/10 | 函数上下文记录、BFS追踪、多策略合成 |
| 安全性 | 6.0/10 | 桩程序在真实环境执行，存在安全风险 |
| 可扩展性 | 5.0/10 | 缺少插件系统、配置管理 |

**总体评分：7.4/10 (良好)**

详见：`项目技术方案完整说明.md`

## 已知限制

1. **桩程序安全性**：生成的桩程序在真实环境执行，可能触发恶意操作
2. **测试覆盖率**：缺少自动化单元测试
3. **False Positives**：可能误报正常代码为恶意
4. **代码混淆**：难以检测经过混淆的恶意代码
5. **动态导入**：无法追踪运行时动态导入的模块
6. **多态恶意代码**：无法检测自我变形的恶意代码

## 未来改进

- [ ] 添加沙箱环境执行桩程序
- [ ] 增加单元测试（目标覆盖率 >80%）
- [ ] 支持更多编程语言（JavaScript, Go, etc.）
- [ ] 机器学习模型辅助判定
- [ ] Web UI界面
- [ ] CI/CD集成
- [ ] 性能优化（大项目分析速度）
- [ ] API文档生成（Sphinx）
- [ ] Docker容器化部署

## 贡献指南

欢迎贡献代码、报告bug、提出建议！

1. Fork本项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启Pull Request

## 许可证

本项目仅用于学术研究和教育目的。不得用于非法用途。

## 作者

- 开发时间：2026年4月
- 技术栈：Python 3.13+, NetworkX, Graphviz, AST

## 致谢

感谢以下开源项目：
- Python AST模块
- NetworkX图分析库
- Graphviz可视化工具

## 联系方式

如有问题或建议，请提交Issue。

---

**最后更新：2026-04-28**
