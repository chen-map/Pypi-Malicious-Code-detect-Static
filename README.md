# NEW_DDG — PyPI Malicious Package Detection System

> **v2.0 大幅重构版** — 相比 v1.0，重写了图内核、新增了四条检测通道、升级了 LLM 层、修复了 20+ 个 bug。详见下方 [v2.0 修改说明](#v20-修改说明)。

Multi-signal static analysis system for PyPI malicious packages.
Combines **interprocedural taint analysis** (CFG+CG+DDG), **function summaries**,
**LLM-assisted verification**, and **registry-level checks** across four independent
detection channels.

## Quick Start

```bash
# Basic analysis (no LLM needed, regex + graph + index channels)
python batch_solution_b_v2.py <packages_dir> --api-key <KEY> --count 50

# Full analysis (LLM semantic verification)
python batch_solution_b_v2.py <packages_dir> --api-key <KEY> --count 50 \
    --llm-model glm-4-flashx --verify-pypi --parallel-workers 5

# With sandbox probe (⚠️ executes package code, only in isolated VM!)
python batch_solution_b_v2.py <packages_dir> --api-key <KEY> \
    --sandbox --verify-pypi --count 50
```

## Architecture

```
Four Detection Channels (independent, fail-safe):
  ① Enhanced Detection (regex, ms-level) — install hooks, typosquat, metadata
  ② Obfuscation Detection (AST + density gating) — hex/base64/encoding patterns
  ③ Graph + Taint (DDG V7, core) — interprocedural taint analysis
  ④ Voting (LLM semantic + rule scoring) — function-level subgraphs
      ↳ Package-level LLM Aggregation (holistic judgment)

Three-Layer Graph (CPG-lite):
  L1 Module:  dist name / PyPI verification / duplicate detection
  L2 Function: summaries (return_tainted, param_to_sink, composable)
  L3 Statement: typed edges (data/control/call/param/return) + kill semantics
```

## Project Structure

```
NEW_DDG/
├── batch_solution_b_v2.py   # Main entry point (batch analyzer)
├── new_ddg_gui.py           # GUI launcher
├── danger_patterns.json     # Dangerous API pattern definitions
│
├── src/                     # Core analysis modules
│   ├── ddg_builder_v7.py    #   DDG builder (AST extraction, kill, call_target)
│   ├── call_graph_analyzer.py # Call graph + attack chains (cross-file)
│   ├── cfg_adapter.py       #   py2cfg precise CFG (constant folding)
│   ├── lightweight_cfg.py   #   CFG fallback
│   ├── taint_engine.py      #   Interprocedural taint analysis
│   ├── call_resolver.py     #   AST-level call target resolution
│   ├── enhanced_detector.py #   Non-code threats (hooks, deps, metadata, names)
│   ├── attack_chain_rebuilder.py # Attack chain reconstruction
│   ├── function_summaries   #   (built into ddg_builder)
│   ├── llm_sanitizer.py     #   LLM input sanitization
│   ├── sandbox_probe.py     #   Behavioral probe (audit hook)
│   ├── pypi_verifier.py     #   PyPI existence/version verification
│   ├── pypi_index.py        #   PyPI full index (typosquat detection)
│   ├── duplicate_detector.py#   Code similarity vs genuine packages
│   ├── file_integrity_checker.py
│   ├── common/
│   │   ├── graph_partitioner.py  # Function-level partitioning
│   │   └── pattern_matcher.py    # Dangerous node detection
│   └── malicious_stubgen_v13/    # Stub generation (experimental)
│
├── SOLUTION_B_VOTING/       # Voting architecture
│   ├── src/                 #   Classifier, scorer, prioritizer
│   └── prompts/             #   LLM prompt templates
│
├── prompts/                 # Shared LLM prompts
├── config/                  # Configuration files
├── tests/                   # Regression tests (8 files, 46+ items)
├── docs/                    # Documentation
├── scripts/                 # Deployment scripts
│
├── data/                    # Evaluation datasets (tar.gz archives)
│   ├── sample_line/         #   30 stratified samples from corpus
│   ├── eval_malicious/      #   20 malicious (eval seed=2026)
│   ├── eval_benign/         #   20 benign (PyPI official)
│   ├── holdout_malicious/   #   20 malicious (holdout seed=777)
│   └── holdout_benign/      #   19 benign (holdout)
│
└── output/                  # Runtime output (gitignored)
    ├── results/             #   Analysis results (JSON/JSONL)
    ├── packages/            #   Extracted packages + .ddg_output
    └── .llm_cache/          #   LLM verdict cache
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Only critical short-circuits MALICIOUS | Prevent single-regex false positives |
| Function-level partitioning | Semantic boundaries, LLM sees complete context |
| Interprocedural return edges | Cross-function/cross-file taint propagation |
| call_target as sink | Untrusted data controlling call target = code execution |
| Summary propagation | Sink-ness flows through function call graph |
| Package-level LLM aggregation | Holistic judgment for borderline cases |
| ANALYSIS_FAILED ≠ BENIGN | Infrastructure failure is not evidence of safety |
| Kill semantics (branch-aware) | Don't lose taint in if/elif/else branches |
| Container tracking | `data['key']=x → exec(data['key'])` chain preserved |

## Testing

```bash
python tests/run_all.py  # Run all 8 test files (46+ items, no API key needed)
```

## Key Metrics (holdout evaluation, zero-overlap)

- Recall: **100%** (20/20 malicious → MALICIOUS)
- Hard false positive: **0%** (0/18 benign → MALICIOUS)
- LLM model: glm-4-flashx (configurable via --llm-model)

## v2.0 修改说明

相比 v1.0（最初版本），本次大改涉及 **22 轮迭代**，核心改进：

### 新增检测能力

| 能力 | 说明 |
|---|---|
| **过程间污点分析** | 污点可穿过函数边界、跨文件传播（此前函数边界即断链） |
| **call_target 即 sink** | 不可信数据控制调用目标 = 动态代码执行，覆盖 getattr/别名/globals 下标 |
| **函数摘要** | 每个函数预计算 param→sink / return_tainted 事实，跨文件污点 O(1) 查询 |
| **AST 级调用解析** | getattr 常量折叠、别名追踪、globals 下标——不再依赖文本匹配 |
| **容器追踪** | `data['key']=x → exec(data['key'])` 链保持 |
| **分支感知 kill** | 三分支以上 taint 不再丢失 |
| **PyPI 全量索引核验** | typosquat 检测用全量 50 万包名（缓存 24h），不再依赖 40 个硬编码清单 |
| **近重复检测** | 下载真包做文件哈希比对，抓"抄代码改名"族（botaa3） |
| **PyPI 存在性核验** | 发行名 404 或版本不存在 → critical（需要 --verify-pypi） |
| **沙箱行为探针** | audit hook 记录安装期网络/子进程/写文件（--sandbox，隔离环境） |
| **包级 LLM 聚合** | 所有通道跑完后 LLM 综观全部证据做最终判断 |

### 修复的严重 bug

| bug | 影响 |
|---|---|
| setup.py 含 cmdclass → 整个 DDG 构建崩溃 | 所有含构建钩子的包静默变"良性" |
| severity 字符串字典序比较 | critical 被降为 medium |
| async 函数打崩调用图 | 含 async def 的文件全部退出分析 |
|轻量 CFG 无限递归 | 任何含 def 的文件必 RecursionError |
| 4MB 大文件调用图卡死 | alibabacloud 等大型 SDK 从 >12min → 16s |
| Subscript 赋值不更新 def 链 | `data['key']=x → exec(data['key'])` 断链 |
| 三分支 kill 丢污点 | if/elif/else 第三分支的污点被丢弃 |
| 危险节点膨胀 58% | URL 字符串赋值被判 network、函数定义自匹配 |
| console_scripts 判死 | 所有含 CLI 入口的正常包全部 MALICIOUS |

### 架构重构

| 变更 | 旧 → 新 |
|---|---|
| 图分割 | WCC+BFS (~1200 行) → 函数级属性分组 (~50 行) |
| 节点身份 | basename（同名文件冲突）→ 全路径唯一 |
| 边分类 | 无分类 → data/control/call/param/return |
| def-use | 无 kill → kill 语义 + 分支感知 + 容器追踪 |
| Source/Sink | 纯正则 → resolved_call 优先 + 摘要传播 + 正则回退 |
| LLM 输入 | 原始代码碎片 → 消毒后完整函数体 + 污点链 + 摘要 |
| LLM 输出 | 直接采信 → clamp + 注入回显降信 + 跨通道交叉验证 |
| LLM 成本 | 每次重新调用 → 内容哈希缓存（40% 命中） |
| 子图确定性 | 随机（子图数波动）→ 三进程哈希逐字节一致 |
| 结果落盘 | 批次结束一次性 → 逐包 JSONL 增量（崩溃不丢） |

### 新增文件

| 文件 | 作用 |
|---|---|
| `src/call_resolver.py` | AST 级调用目标解析 |
| `src/taint_engine.py` | 过程间污点引擎 |
| `src/llm_sanitizer.py` | LLM 输入消毒 |
| `src/pypi_verifier.py` | PyPI 存在性核验 |
| `src/pypi_index.py` | 全量包名索引 |
| `src/duplicate_detector.py` | 近重复检测 |
| `src/sandbox_probe.py` | 沙箱行为探针 |
| `tests/` (10 files) | 46+ 项回归测试 |

### 删除的冗余

| 删除项 | 原因 |
|---|---|
| WCC+BFS 分割 (~1200 行) | 被函数级分割替代 |
| 旧版主程序 batch_v20_complete_voting.py | 被当前主程序替代 |
| .broken/.backup 文件 | 已修复或过时 |
| 692MB 垃圾文件 | 误创建 |
| config/classification_rules.json | 孤儿配置（无引用） |
