# NEW_DDG - Python包安全分析系统

基于数据依赖图（DDG）的Python恶意包检测系统，支持三分类（BENIGN/MALICIOUS/SUSPICIOUS）。

## 核心功能

### 1. DDG构建（V7）
- **完整DDG分析**：为小文件构建完整的数据依赖图
- **快速扫描**：对大文件进行快速模式检测
- **符号表生成**：提取函数、类、变量信息
- **攻击链提取**：检测潜在的恶意攻击链

### 2. 图分割
- **WCC方法**：弱连通分量分割
- **BFS方法**：双向数据流分割
- **HYBRID方法**：WCC + BFS混合（默认）
- **自动处理大图**：限制子图大小，避免内存溢出

### 3. V12三分类系统
- **BENIGN**（良性）：无恶意行为
- **MALICIOUS**（恶意）：明确的恶意模式
- **SUSPICIOUS**（可疑）：需要进一步审查

#### V12分类依据
- **上下文敏感分析**：区分安全工具vs恶意代码
- **数据流分析**：检测敏感数据流向
- **混淆检测**：识别代码混淆技术
- **符号表分析**：分析变量作用域和数据流
- **自定义模式**：支持用户定义的恶意模式

## 快速开始

### 基本使用

```bash
# 分析一个Python包
python main.py C:/path/to/package

# 使用特定的图分割方法
python main.py C:/path/to/package --partition-wcc    # WCC方法
python main.py C:/path/to/package --partition-bfs    # BFS方法
python main.py C:/path/to/package --partition-hybrid # HYBRID方法（默认）

# 查看帮助
python main.py --help
```

### 输出文件

分析完成后，在包目录下生成`.ddg_output`文件夹：

```
.ddg_output/
├── nodes.json                    # DDG节点
├── edges.json                    # DDG边
├── symbols.json                  # 符号表（函数、类）
├── sub_ddgs/                     # 子图分割结果
│   ├── summary.json              # 子图摘要
│   └── */                        # 各个子图
│       ├── nodes.json
│       ├── edges.json
│       └── info.json
├── security_report.json          # 安全报告
├── v12_classification.json       # V12分类结果（JSON格式）
└── v12_classification.txt        # V12分类报告（TXT格式）
```

## 系统工作流程

本系统采用三阶段流水线架构，从源代码到最终分类结果：

### 阶段1：DDG构建（DDG Builder V7）

**输入**：Python项目源代码目录

**处理流程**：

1. **文件扫描与过滤**
   - 递归扫描项目目录下所有`.py`文件
   - 排除测试文件、`__pycache__`等非核心文件
   - 按文件大小分类：小文件（<1000行）vs 大文件（≥1000行）

2. **AST解析**
   - 使用Python内置`ast`模块解析源代码
   - 构建抽象语法树（AST）
   - 提取语法元素：函数、类、变量、导入语句等

3. **DDG节点提取**
   - 为每个变量定义创建节点（包括函数参数、赋值语句等）
   - 节点属性：
     - `file`: 文件路径
     - `line`: 行号
     - `type`: 节点类型（赋值/参数/导入等）
     - `source`: 数据来源（变量名/函数调用等）
     - `function_name`: 所属函数
     - `class_name`: 所属类

4. **DDG边提取（数据依赖关系）**
   - 跟踪变量的定义-使用链（def-use chains）
   - 当变量b使用变量a时，创建边 a → b
   - 边的属性：源节点ID、目标节点ID、边类型

5. **危险节点标记**
   - 检测敏感API调用：
     - 代码执行：`exec`, `eval`, `compile`, `__import__`
     - 命令执行：`subprocess`, `os.system`, `os.popen`
     - 网络操作：`requests`, `urllib`, `http`, `socket`
     - 文件操作：`open`, `read`, `write`
     - 编码/解码：`base64`, `pickle`, `marshal`
   - 标记包含敏感API的节点为"dangerous"

6. **符号表生成**
   - 收集函数信息：
     - 函数名、短名称、行号
     - 参数列表
     - 所属类
     - 文件位置
   - 收集类信息：
     - 类名、行号
     - 属性列表
     - 文件位置

7. **安全报告生成**
   - 统计危险API使用次数
   - 检测可疑模式（如混淆、编码字符串）
   - 生成初步风险评分（V11评分）

8. **NetworkX图构建**
   - 将节点和边转换为NetworkX图结构
   - 用于后续的图分割操作

**输出**：
- `nodes.json`: 所有DDG节点
- `edges.json`: 所有DDG边
- `symbols.json`: 符号表（函数和类）
- `security_report.json`: 初步安全分析报告
- `fast_scan_results.json`: 大文件快速扫描结果（如果有）
- NetworkX图对象（内存中）

**典型耗时**：
- 小型项目（<1000行）：~2秒
- 中型项目（1000-5000行）：~5秒
- 大型项目（>5000行）：~10秒

---

### 阶段2：图分割（Graph Partitioner）

**输入**：阶段1生成的NetworkX图

**目标**：将大型DDG分割成可管理的子图，每个子图代表一个相对独立的数据流模块

**处理流程**：

#### 子图严重程度分级标准

在进行分割之前，首先计算每个子图的"严重程度"（severity）：

```
危险节点占比 = dangerous_nodes_count / total_nodes_count

severity分类：
- Critical: 危险节点占比 ≥ 50%
- High:     危险节点占比 30% ~ 50%
- Medium:   危险节点占比 10% ~ 30%
- Low:      危险节点占比 < 10%
```

**关键优化**：V12分类器**只分析Critical和High子图**，跳过Medium/Low子图，大幅提升性能。

#### 三种分割方法

##### 方法1：WCC（弱连通分量）分割

**原理**：利用图的连通性，将图分割为弱连通分量

```python
# 弱连通：忽略边的方向，只要节点间有路径就连通
weakly_connected_components = nx.weakly_connected_components(graph)
```

**特点**：
- ✅ 保留完整的数据流模块
- ✅ 分割边界清晰（基于图的自然结构）
- ❌ 可能产生超大子图（某些复杂函数会产生大量节点）

**适用场景**：中小型项目，子图数量适中

##### 方法2：BFS（广度优先搜索）分割

**原理**：从危险节点开始，沿着数据流方向进行BFS遍历

```python
# 从每个危险节点开始进行BFS
for dangerous_node in dangerous_nodes:
    subgraph = bfs_traversal(graph, dangerous_node, max_depth=10, max_nodes=500)
```

**特点**：
- ✅ 限制子图大小（通过max_nodes参数）
- ✅ 聚焦于危险相关的数据流
- ❌ 可能分割过细（相关数据流被拆分到多个子图）
- ❌ 需要调整max_depth和max_nodes参数

**适用场景**：大型项目，需要严格控制子图大小

##### 方法3：HYBRID（混合）分割（推荐，默认）

**原理**：结合WCC和BFS的优点

1. 首先使用WCC进行初步分割
2. 检查每个WCC分量的大小：
   - 如果节点数 ≤ 500：保留完整分量
   - 如果节点数 > 500：使用BFS进一步分割
3. 确保最终子图大小不超过max_nodes限制

**特点**：
- ✅ 综合WCC和BFS的优点
- ✅ 自动处理超大分量
- ✅ 既保留模块完整性，又控制子图大小

**适用场景**：所有规模的项目（推荐使用）

#### 子图信息计算

对每个子图，计算以下信息：

```python
{
    "index": 1,                      # 子图索引
    "severity": "critical",         # 严重程度
    "size": 519,                     # 节点总数
    "dangerous_count": 118,          # 危险节点数
    "primary_reason": "可疑的混淆函数调用（20+字符标识符）",
    "file_counts": {...},            # 文件分布
    "function_counts": {...},        # 函数分布
    "api_usage": {...}               # API使用统计
}
```

**输出**：
- `sub_ddgs/summary.json`: 所有子图的摘要信息
  - `total_components`: 子图总数
  - `by_severity`: 按严重程度统计（critical/high/medium/low）
  - `components[]`: 每个子图的详细信息
- `sub_ddgs/XXX_info.json`: 每个子图的详细信息
- `sub_ddgs/XXX_nodes.json`: 每个子图的节点列表
- `sub_ddgs/XXX_edges.json`: 每个子图的边列表

**典型耗时**：
- 小型项目：~1秒
- 中型项目：~2秒
- 大型项目：~3秒

**示例输出**（summary.json）：

```json
{
  "total_components": 62,
  "by_severity": {
    "critical": 44,
    "high": 17,
    "medium": 1,
    "low": 0
  },
  "components": [
    {
      "index": 1,
      "severity": "critical",
      "size": 519,
      "dangerous_count": 118,
      "primary_reason": "可疑的混淆函数调用（20+字符标识符）"
    },
    {
      "index": 45,
      "severity": "high",
      "size": 503,
      "dangerous_count": 35,
      "primary_reason": "加密/编码操作"
    }
  ]
}
```

---

### 阶段3：V12三分类（Classification Engine V12）

**输入**：
- `nodes.json`: DDG节点
- `edges.json`: DDG边
- `symbols.json`: 符号表
- `sub_ddgs/summary.json`: 子图摘要
- 子图详细信息（仅Critical和High子图）

**目标**：基于DDG和子图信息，将包分类为BENIGN/MALICIOUS/SUSPICIOUS

**处理流程**：

#### 步骤1：子图过滤（性能优化）

```python
# ✅ 关键优化：只分析Critical和High子图
critical_subgraphs = [sg for sg in subgraphs if sg['severity'] == 'critical']
high_subgraphs = [sg for sg in subgraphs if sg['severity'] == 'high']
analyzable_subgraphs = critical_subgraphs + high_subgraphs

# 跳过Medium/Low子图（低风险，无需深入分析）
```

**原因**：
- Critical/High子图包含主要风险信号
- Medium/Low子图通常不会改变分类结果
- 大幅减少分析时间（尤其在大型项目中）

#### 步骤2：数据流分析

对每个Critical/High子图：

1. **提取数据流路径**
   - 从危险节点出发，沿着DDG边反向追踪数据来源
   - 构建完整的数据流链：数据源 → 中间变量 → 危险API

2. **敏感数据流检测**
   - 检测敏感变量是否流向危险API：
     - 环境变量 → `exec`（可能的代码注入）
     - 网络数据 → `pickle`（可能的反序列化攻击）
     - 用户输入 → `subprocess`（可能的命令注入）

3. **嵌套函数调用检测**
   - 检测危险API是否在嵌套函数中被调用
   - 嵌套调用 + 敏感数据流 = 高度可疑

4. **混淆指标检测**
   - Base64解码：`base64.b64decode`
   - 字符串拼接：`var1 + var2`
   - 长标识符（>20字符）：可能的混淆
   - 动态导入：`__import__`, `importlib`

**输出**：
- `sensitive_data_flows[]`: 敏感数据流列表
- `nested_calls`: 嵌套调用计数
- `obfuscation_indicators[]`: 混淆指标列表

#### 步骤3：变量分析

1. **收集所有变量**
   - 从DDG节点提取所有变量定义
   - 统计变量总数

2. **敏感变量检测**
   - 检测变量名是否匹配敏感模式：
     - `password`, `pwd`, `passwd`, `secret`, `key`, `token`
     - `url`, `uri`, `host`, `ip`, `email`
     - `filename`, `filepath`, `path`

3. **可疑赋值检测**
   - 检测敏感变量是否被可疑数据赋值：
     - 来自网络请求
     - 来自环境变量
     - 来自文件读取

4. **变量拼接检测**
   - 检测字符串拼接操作（可能的混淆）

**输出**：
- `total_variables`: 变量总数
- `sensitive_variables[]`: 敏感变量列表
- `suspicious_assignments[]`: 可疑赋值列表
- `variable_concatenations`: 变量拼接计数

#### 步骤4：符号表分析

1. **函数统计**
   - 总函数数
   - 危险函数数（包含dangerous节点的函数）
   - 嵌套危险函数数（在嵌套作用域中的危险函数）

2. **类统计**
   - 总类数
   - 包含危险方法的类数

**输出**：
- `total_functions`: 函数总数
- `total_classes`: 类总数
- `dangerous_functions_in_nested`: 嵌套危险函数数

#### 步骤5：上下文敏感分析（核心创新）

**目标**：区分"安全使用"和"恶意使用"同一API

**方法**：

1. **定义良性模式**（benign patterns）
   - `subprocess`:
     - + `python` + `ast`/`parse`（代码分析工具）
     - + `pip` + `install`（包管理）
     - + `git` + `clone`（开发工具）
   - `exec`:
     - + `test`, `mock`, `stub`（测试代码）
   - `eval`:
     - + `example`, `demo`（示例代码）

2. **定义恶意模式**（malicious patterns）
   - `subprocess`:
     - + `CREATE_NO_WINDOW`（隐藏执行）
     - + `powershell` + `-EncodedCommand`（混淆命令）
     - + `bash` + `-c`（命令注入）
   - `exec`:
     - + `base64.b64decode`（解码并执行）
   - `eval`:
     - + `base64.b64decode`（解码并求值）
   - `socket`:
     - + `connect` + `127.0.0.1`（本地反向Shell）
     - + `connect` + `192.168`（内网连接）

3. **检测危险节点的上下文**
   - 读取dangerous node的源代码上下文（前后10行）
   - 检查是否匹配良性模式
   - 检查是否匹配恶意模式

4. **统计结果**
   - `benign_uses`: 良性使用次数
   - `malicious_uses`: 恶意使用次数

**关键原则**：
```
✅ 恶意使用不能被良性使用抵消
❌ 因为恶意代码会隐藏在正常包中
```

**示例**：

```python
# DDG_BUILDER案例：良性使用
subprocess.run(['python', '-m', 'ast', file_path])  # ✅ 代码分析工具
# 结果：benign_uses = 27

# evil_rce2案例：恶意使用
subprocess.Popen(['powershell', '-EncodedCommand', encoded_cmd])  # ❌ 隐藏执行
# 结果：malicious_uses = 4
```

**输出**：
- `benign_uses`: 良性使用计数
- `malicious_uses`: 恶意使用计数
- `details[]`: 每个检测到的使用详情

#### 步骤6：源代码模式匹配

读取用户自定义的恶意模式配置（`config/malicious_patterns.json`）：

```json
{
  "custom_patterns": [
    {
      "name": "Information_Exfiltration",
      "risk_score": 0.85,
      "patterns": ["whoami", "hostname", "getpass.getuser"],
      "context_patterns": ["requests.", "urllib.", "http"],
      "enabled": true
    }
  ]
}
```

在DDG节点的source中搜索这些模式，计算风险评分。

**输出**：
- `patterns[]`: 检测到的模式列表
- `risk_score`: 模式风险评分

#### 步骤7：分类决策

基于以上6步的分析结果，按优先级进行分类：

**规则1：上下文敏感分析**（最高优先级）
```python
if malicious_uses > 0:
    return 'MALICIOUS', 0.90  # 恶意使用无法被抵消
```

**规则2：混淆指标**
```python
if len(obfuscation_indicators) >= 2:
    return 'MALICIOUS', 0.85
```

**规则3：高风险数据流**
```python
if data_flow_risk_score >= 0.8:
    return 'MALICIOUS', 0.80
```

**规则4：自定义恶意模式**
```python
if custom_pattern_risk_score >= 0.8:
    return 'MALICIOUS', 0.75
```

**规则5：Critical子图 + 恶意证据**
```python
if has_critical_subgraphs and has_malicious_evidence:
    return 'MALICIOUS', 0.70
```

**规则6：Critical子图 + 无恶意证据**
```python
if has_critical_subgraphs and not has_malicious_evidence:
    if no_obfuscation and has_benign_uses:
        return 'SUSPICIOUS', 0.30  # 低风险（可能是安全工具）
    elif has_obfuscation:
        return 'SUSPICIOUS', 0.50  # 中风险（需要人工审查）
```

**规则7：无任何风险**
```python
if no_risk_detected:
    return 'BENIGN', 0.10
```

**输出**：
- `category`: 分类结果（BENIGN/MALICIOUS/SUSPICIOUS）
- `risk_score`: 风险评分（0.0-1.0）
- `confidence`: 置信度（0.0-1.0）
- `reason`: 分类原因（自然语言描述）

#### 步骤8：生成报告

1. **JSON报告**（`v12_classification.json`）
   - 包含所有分析结果
   - 机器可读，适合后续处理

2. **TXT报告**（`v12_classification.txt`）
   - 人类可读的详细报告
   - 包含：
     - 分类结果摘要
     - 子图分析详情
     - 数据流分析详情
     - 变量分析详情
     - 上下文敏感分析详情
     - 建议行动

**典型耗时**：
- 小型项目：~1秒
- 中型项目：~2秒
- 大型项目：~3秒

---

## 完整示例

### 示例1：良性工具误报案例（DDG_BUILDER）

**输入**：
```bash
python main.py C:/DDG_BUILDER_SUB_TEST
```

**阶段1输出**：
- 节点数：约8000个
- 危险节点：约200个（subprocess、exec等）
- 符号表：约150个函数

**阶段2输出**：
- 子图总数：62个
- Critical子图：44个
- High子图：17个
- Medium子图：1个

**阶段3分析**：
- 上下文敏感分析：
  - 恶意使用：0个 ✅
  - 良性使用：27个（subprocess+ast、pip+install等）
- 混淆指标：0个
- 敏感数据流：0个

**最终分类**：
```
Result: [YELLOW] SUSPICIOUS
Risk: 0.30 | Confidence: 0.80
Reason: 疑似安全工具（27个良性使用，但无法排除隐藏恶意代码）
```

**说明**：DDG_BUILDER使用敏感API进行代码分析，所以分类为SUSPICIOUS（低风险），建议人工审查确认。

---

### 示例2：恶意包检测案例（evil_rce2）

**输入**：
```bash
python main.py C:/evil_rce2
```

**阶段1输出**：
- 节点数：约500个
- 危险节点：约50个（subprocess、base64等）
- 符号表：约10个函数

**阶段2输出**：
- 子图总数：8个
- Critical子图：5个
- High子图：2个
- Medium子图：1个

**阶段3分析**：
- 上下文敏感分析：
  - 恶意使用：4个（powershell+EncodedCommand、base64+exec等）
  - 良性使用：0个
- 混淆指标：2个（base64解码、长标识符）
- 敏感数据流：2个（网络数据→exec）

**最终分类**：
```
Result: [RED] MALICIOUS
Risk: 0.90 | Confidence: 0.95
Reason: 上下文敏感分析: 4个恶意变量使用（无法被良性使用抵消）
```

**说明**：evil_rce2包含reverse shell，有明确的恶意模式，分类为MALICIOUS，建议阻止安装。

---

## 分类规则

### 规则优先级

**V12分类按以下优先级判断：**

1. **上下文敏感分析**（最可靠）
   - 发现恶意使用 → MALICIOUS
   - 恶意使用不能被良性使用抵消

2. **混淆指标**
   - ≥2个混淆指标 → MALICIOUS
   - 混淆包括：base64解码、字符串拼接、长标识符等

3. **V11+高风险模式**
   - 风险评分 ≥0.8 → MALICIOUS

4. **自定义恶意模式**
   - 风险评分 ≥0.8 → MALICIOUS

5. **Critical子图 + 恶意证据**
   - 敏感数据流 + 嵌套调用 → MALICIOUS

6. **Critical子图 + 无恶意证据**
   - 无混淆 + 有良性使用 → SUSPICIOUS（低风险）
   - 有混淆 → SUSPICIOUS（中风险）

7. **无任何风险**
   - BENIGN

### 上下文敏感分析

**区分良性和恶意API使用：**

| API | 良性使用 | 恶意使用 |
|-----|---------|---------|
| `subprocess` | python+ast/pip+install/git+clone | CREATE_NO_WINDOW+powershell+EncodedCommand |
| `exec` | test+mock+stub | base64.b64decode |
| `eval` | test+example+demo | base64.b64decode |
| `socket` | - | connect+127.0.0.1/192.168 |

**关键原则：恶意代码会隐藏在正常包中，所以良性使用不能抵消恶意使用。**

## 架构

### 核心模块

```
NEW_DDG/
├── main.py                           # 主入口
├── src/
│   ├── ddg_builder_v7.py             # DDG构建器（V7）
│   ├── visualizer_v7.py              # 可视化生成器
│   ├── classification_engine_v12_real.py  # V12分类引擎
│   ├── common/
│   │   ├── graph_partitioner.py     # 图分割器
│   │   └── pattern_matcher.py       # 模式匹配器
│   └── config/
│       └── malicious_patterns.json  # 自定义恶意模式配置
```

### 三阶段数据流

```
┌─────────────────────────────────────────────────────────────┐
│ 阶段1: DDG构建                                      │
├─────────────────────────────────────────────────────────────┤
│ 输入: Python源代码                                           │
│ 处理: AST解析 → 节点提取 → 边提取 → 危险标记 → 符号表生成    │
│ 输出: nodes.json, edges.json, symbols.json, NetworkX图      │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段2: 图分割 (Graph Partitioner)                            │
├─────────────────────────────────────────────────────────────┤
│ 输入: NetworkX图                                             │
│ 处理: WCC/BFS/HYBRID分割 → 严重程度分级 → 子图信息计算        │
│ 输出: sub_ddgs/summary.json, 子图详细信息                    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段3: V12三分类 (Classification Engine V12)                │
├─────────────────────────────────────────────────────────────┤
│ 输入: DDG数据 + 子图信息                                     │
│ 处理:                                                          │
│   1. 子图过滤（只分析Critical/High）                          │
│   2. 数据流分析                                               │
│   3. 变量分析                                                │
│   4. 符号表分析                                              │
│   5. 上下文敏感分析                                          │
│   6. 模式匹配                                                │
│   7. 分类决策                                                │
│ 输出: v12_classification.json, v12_classification.txt        │
└─────────────────────────────────────────────────────────────┘
```

## 配置

### 自定义恶意模式

编辑 `config/malicious_patterns.json`：

```json
{
  "custom_patterns": [
    {
      "name": "Information_Exfiltration",
      "risk_score": 0.85,
      "patterns": ["whoami", "hostname", "getpass.getuser"],
      "context_patterns": ["requests.", "urllib.", "http"],
      "enabled": true
    }
  ],
  "sensitive_variables": {
    "benign_contexts": {
      "email": ["setup(", "metadata", "author"],
      "url": ["homepage", "documentation"]
    },
    "malicious_contexts": {
      "email": ["requests.post", "urllib", "http"],
      "hostname": ["requests.post", "socket.connect"]
    }
  }
}
```

## 分类结果解读

### BENIGN [GREEN]
- **特征**：无恶意行为
- **典型场景**：正常的工具库、业务代码
- **建议**：可以正常使用

### MALICIOUS [RED]
- **特征**：明确的恶意模式
- **典型场景**：后门、数据窃取、反向Shell
- **建议**：阻止安装，联系安全团队

### SUSPICIOUS [YELLOW]
- **特征**：使用敏感API但无明确恶意证据
- **典型场景**：
  - 安全工具（使用subprocess等敏感API）
  - 需要动态分析的包
- **建议**：
  - 人工审查代码
  - 运行动态分析
  - 检查网络通信

## 性能

| 包大小 | DDG构建 | 图分割 | V12分类 | 总计 |
|--------|---------|--------|---------|------|
| 小型(<1000行) | ~2s | ~1s | ~1s | ~4s |
| 中型(1000-5000行) | ~5s | ~2s | ~2s | ~9s |
| 大型(>5000行) | ~10s | ~3s | ~3s | ~16s |

**V12优化**：通过只分析Critical/High子图，V12分类时间可减少50-70%（尤其在大项目中）。

## 依赖

```
Python >= 3.8

核心依赖：
- networkx    # 图分析
- matplotlib  # 可视化（可选）
- Graphviz    # 可视化（可选）
```

## 已知问题

1. **良性工具误报**
   - 问题：安全工具会被分类为SUSPICIOUS
   - 原因：使用敏感API但无恶意意图
   - 解决：人工审查，确认工具性质

2. **混淆检测**
   - 某些高级混淆技术可能无法检测
   - 建议结合动态分析

## 更新日志

### v12.0 (当前版本)
- ✅ 集成V12三分类系统
- ✅ 上下文敏感分析
- ✅ 移除桩代码生成（简化流程）
- ✅ 生成TXT格式报告
- ✅ 修复compile误报（re.compile vs compile()）
- ✅ 只分析Critical/High子图（性能优化）

### v7.0
- DDG构建器（分层分析）
- 图分割（WCC/BFS/HYBRID）
- 安全报告生成

## 许可证

MIT License
