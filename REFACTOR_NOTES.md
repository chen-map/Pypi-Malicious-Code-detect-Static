# NEW_DDG 大改记录(2026-10-28)

本次大改基于全量算法审查,采用**均衡模式**:修复全部已核实的硬 bug,重构判决合成,
清理死代码。CLI/GUI 兼容(只增参数不改语义),结果 JSON 字段只增不减。

**回归测试**:`python tests/run_all.py`(5 个文件 17 项检查,全部通过,不需要 API key)。

---

## 一、判决会变的地方(重要)

| 变化 | 旧行为 | 新行为 |
|---|---|---|
| console_scripts | setup.py 含 entry_points+console_scripts → high → **整包 MALICIOUS(0.95/0.85)** | 独立类别 entry_points/**low**,不再判死;正常 CLI 包不再全灭 |
| setup.py 的 eval/exec/__import__ | critical → 整包 MALICIOUS | **high**,进投票上下文 |
| 增强检测短路条件 | critical 或 high 都短路 MALICIOUS | **仅 critical 短路**(真安装钩子/typosquatting/暗网) |
| 包名/URL 子串 | 'shell'/'crypto'/bit.ly 即 high → MALICIOUS | 强恶意词(getshell/backdoor/rootkit等,词界)→ high;弱词 → medium;短链/pastebin → medium;.onion 保持 high |
| LLM JSON 缺字段 | 默认 `is_malicious=True` → 零容忍投票放大成整包 MALICIOUS | 默认 False + verdict 一致性归一,缺字段落 SUSPICIOUS |
| 规则判恶意的子图 | 1 个即整包 MALICIOUS | **孤证降级 SUSPICIOUS,≥2 个一致才升 MALICIOUS**(LLM 复核的恶意仍零容忍直通) |
| 置信度 | MALICIOUS 恒 0.85,SUSPICIOUS 恒 0.60 | 公式计算:0.6 + 0.25×恶意占比 + 0.15×子图平均置信度(封顶1.0) |
| DDG 构建失败 | BENIGN 0.10/**0.90**(高置信良性!) | 新终态 **ANALYSIS_FAILED** 0.5/0.3;单包异常也记录该终态而非静默丢失 |
| 全部子图 ERROR | 落入 BENIGN 分支 | **ANALYSIS_FAILED** |
| 混淆短路时机 | 混淆检测先于增强检测 → 恶意混淆包只拿 OBFUSCATED 标签 | 增强检测(便宜)先行,critical 不被混淆短路吞掉 |
| 混淆分/confidence | 分数无上限(可>1.0),confidence=原始分 | 输出统一 min(score, 1.0) 封顶 |

## 二、崩溃类修复

1. **ddg_builder_v7.py** `by_severity` 补 `warning`/`error` key —— setup.py 含
   `cmdclass` 不再 KeyError 崩溃(旧链路:崩溃→无报告→高置信 BENIGN 漏报)。
2. **lightweight_cfg.py** 修 `__init__`→`_build`→新建子 CFG→`_build` 的无限递归
   (任何含 `def` 的文件必 RecursionError);文档如实注明"只提供行区间,无死代码判定能力"。
3. **call_graph_analyzer.py** `visit_AsyncFunctionDef` 不再手工构造无 lineno 的
   FunctionDef(旧:含 async def 的文件整体退出调用图,静默漏报);`has_starargs` 恒真修复。
4. **enhanced_detector.py** 三处 severity 字符串 `max()` 改按等级序
   (`'medium'>'critical'` 字典序错乱修复);email 正则 `' disposable'` 笔误。
5. **tar 解压** `filter='data'` 防 tar-slip;tar 内顶级目录与文件名不一致时以实际目录为准。

## 三、误报通道封堵

- 短变量名比例恒 1.0 修复(正则只捕 1-2 字符名再判 len≤2);`pickle/marshal/bz2`
  裸子串收紧为调用形态;可疑导入词界匹配;`re.escape` 修复 base64 片段内插正则崩溃。
- **subgraph_prioritizer**:api_score 生成器变量遮蔽(双重求和→恒饱和 1.0)修复;
  权重表全部改正则词界,删除 'default':0.3 兜底键(原匹配 `default=` 参数)。
- 关键词回退排除否定语境("no malicious behavior"不再判恶意倾向)。

## 四、漏报通道封堵

- **graph_partitioner**:>1000 节点的连通分量不再被丢弃(hybrid 交 BFS 切分;纯 wcc
  模式警告后丢弃);min_wcc_size 2→1(孤立危险节点保留);`_find_parameter_dependencies`
  从恒空操作改为真补前驱;500 行窗口加文件一致性校验;WCC severity 取最大等级。
- **pattern_matcher**:`is_import` 门修复(`imp` 变量未用,退化为子串 'import');
  空 regex 规则跳过(原匹配一切);`check_node`/检测器双实现合并为单一 `match_dictionary`。
- **rule_based_scorer / prioritizer**:Source 模式扩充(os.environ/getenv/open/read/
  b64decode 等),complete_chain 真实可触发;删除不可达死分支。
- **enhanced_detector**:pyproject.toml(PEP 621+poetry)/setup.cfg 依赖解析接入
  (原先恒空,依赖投毒检测对现代包失效);远程直装模式(git+https*.py)接入。

## 五、工程化

- `--seed`(默认42):抽样可复现;`--parallel-workers`(默认1):高优先级子图 LLM
  线程池并行(原参数收下但从未使用)。
- 结果**增量落盘**:每包一行 JSONL(`output/results/*.jsonl`),批次结束写汇总
  JSON+分类统计;中途崩溃不再丢全部结果;单包异常记录 ANALYSIS_FAILED 而非静默消失。
- **config/malicious_patterns.json 接入** DangerPatternLoader(原为孤儿配置);
  classification_rules.json(孤儿,阈值与投票无关)删除。

## 六、清理(已删除)

692MB `--exclude=output` 垃圾文件、`SOLUTION_B_VOTING/batch_v20_complete_voting.py`(旧版主程序)、
`batch_solution_b_v2.py.backup`、`src/ddg_builder_v7.py.backup/.broken`、
`src/v15_llm_stub_generator.py.broken`、`batch_1/nul`、全部 `__pycache__`。

## 七、明确不在本轮范围(下一轮建议)

DDG 图内核三问题(影响子图产物,需单独验证检出率不回退):
节点 id 用 basename(同名文件图塌缩)、节点表 2/3 元组 key 混用(跨文件边接幽灵节点)、
作用域浅拷贝污染;以及 lightweight_cfg 的真实 CFG 边构建。

---

# 第三轮:真实样本测试驱动的修复(2026-10-28)

用 10 个**真实良性库**(attrs/attr/certifi/cffi/charset_normalizer/astor/bs4/
_plotly_utils/idna/pycryptodome)+ 5 个真实恶意包做的对抗测试,暴露并修复:

## 崩溃与性能

1. **`BasicBlock' object has no attribute 'block`** — ddg_builder 的
   `_get_cfg_path_to_exit` / `get_return_flow_path` 按 py2cfg 包装器写死
   `.block.id`。**该路径此前因 lightweight_cfg 递归 bug 从未执行**,修好递归后
   才暴露,使含 return/cross-file call 的包全部 ANALYSIS_FAILED。改为
   `getattr(block, 'block', block).id`。
2. **大文件扫描灾难性回溯** — `DangerPatternLoader.check_node` 对 220KB 文件
   耗时 **>60 秒**(idna/uts46data.py)。根因是上一轮引入的行为规则用
   `(?s)(?=.*a)(?=.*b)...` 前瞻链实现,单条 16KB 约 0.8 秒。改为
   `required_all` 子串同现判断(语义等价),并对大文本按 16KB 分块。
   **62s → 0.18s**。

## 混淆检测误报(4/10 良性库被误判 OBFUSCATED)

| 包 | 修复前 | 修复后 | 误报主因 |
|---|---|---|---|
| pycryptodome | 0.81 OBFUSCATED | 0.10 | 2653 个 hex 转义 + 473 次 crypto 关键词 |
| bs4 | 0.61 OBFUSCATED | 0.07 | 448 个 hex 转义 + `re.compile(` 被当危险 compile |
| charset_normalizer | 0.54 OBFUSCATED | 0.02 | 中文数据 + `codecs`/`rot` 子串 |
| idna | 0.33 OBFUSCATED | 0.00 | Base32 表 + 131 个"编码串" |

修复项:
- **计数型指标全部加包级密度门控**(每 KB 出现次数)。真实良性库包级 hex
  密度实测最高 0.33/KB,阈值取 8/KB。
- **`compile(` 只认裸调用**,排除 `re.compile(`/`model.compile(`。
- **中文混淆只认中文标识符**(`中文名 =`/`def 中文名`),中文注释/数据不再命中。
- **rot13 要求 `'rot13'` 字面量**(原 `'rot'` 子串命中 rotate/rotation)。
- **suspicious_imports 只认混淆工具名**(obfuscate/pyarmor/pyminifier),
  且按去重 import 语句计数。原词表含 crypto/aes/rsa/codecs —— 加密库 100% 中招。

## 判决层(降级模式)修复

3. **规则回退票被当成 LLM 复核票** — API 异常的 fallback 结果未标记来源,
   `llm_used` 恒 True,cffi 的 4 个回退票(77 个子图中占 5%)被零容忍直通
   MALICIOUS。现在 classifier 回退结果带 `fallback: True`,投票层:
   **无真实 LLM 恶意票且恶意子图占比 < 50% → SUSPICIOUS**(真实恶意包
   1923tsl1 的 100% 占比仍升级 MALICIOUS)。
4. **新增 `analysis_degraded` 字段**:LLM 不可用/解析失败时结果标注为降级分析。

## 最终实测(无 LLM key,规则回退模式)

| 测试集 | OBFUSCATED | MALICIOUS | SUSPICIOUS | BENIGN |
|---|---|---|---|---|
| 10 个真实良性库 | **0**(原 4) | **0**(原 1: cffi) | 9 | 1 |
| 5 个真实恶意包 | 0 | 4 | 1 | 0 |

剩余 9/10 SUSPICIOUS 是**降级模式**的保守表现:`_fallback_rule_based_classification`
把"≥1 个危险 API 的子图"判为可疑。配置真实 API key 后由 LLM 语义复核,
该桶应显著收缩 —— 需要用真实 key 复测确认。恶意集的 1 个 SUSPICIOUS
(1923tsl1)是"单子图单票规则判决"被保守降级,仍被标记、未漏为良性。

---

# 第四轮:真实 LLM(GLM-4-FlashX)接入校准(2026-10-28)

用真实 API key 跑同一套样本,发现**接入 LLM 后误报反而更高**:良性集
5/10 被判 MALICIOUS。逐个子图诊断(root-cause)后修复:

## 根因

1. **规则预筛分数算完就丢弃** — `classify_subgraph` 收到 `rule_based_result`
   只 print,`_fill_subgraph_prompt` 签名里根本没有它。LLM 没有任何校准锚点。
2. **Prompt 缺少良性模式判据** — 唯一的指令是"Zero Tolerance: 完整链倾向
   MALICIOUS",而"完整链"未定义 Source 的可信性。实测 astor 的弃用 shim
   `exec(deprecated)` 被判 MALICIOUS 0.95,理由原文是
   *"exec() with deprecated syntax indicates potential for malicious intent"*。
3. **单通道 + 零容忍** — 对本身含代码执行原语的库(cffi 的 `execfile`:
   open→read→compile→exec),LLM 每个子图都判恶意,零容忍直接判死整包。

## 修复

1. `{rule_based_prescreen}` 占位符 + `_fill_subgraph_prompt(..., rule_based_result)`
   注入规则分/类别/置信度,并注明"这是一个信号,不是判决"。
2. Prompt 新增 **False Positive Avoidance** 节:弃用 shim、代码生成库、
   加密测试向量、纯字面量 sink、内部 execfile 辅助函数五类良性模式;
   并把"完整链"收紧为**必须有无可信来源**(字面量/同子图常量不算 Source)。
   同步收紧 0.9-1.0 分档与"Zero Tolerance"原则的表述。
3. 投票层新增**跨通道交叉验证**:LLM 判 MALICIOUS 但规则预筛 <0.40、
   且增强检测非 high/critical 时,降级为 SUSPICIOUS(记 `demoted_reason`)。
   `skip_rule_scoring` 模式显式禁用规则通道,不做此校验。

## 实测(真实 LLM,同一 10 良性 + 5 恶意)

| 测试集 | 轮次 | OBFUSCATED | MALICIOUS | SUSPICIOUS | BENIGN |
|---|---|---|---|---|---|
| 10 良性库 | 接LLM后、修复前 | 0 | **5** | 0 | 5 |
| 10 良性库 | 修复后 | 0 | **0** | 1 (cffi) | 9 |
| 5 恶意包 | 修复后 | 0 | **5** | 0 | 0 |

cffi 仍为 SUSPICIOUS:其 `recompiler.execfile(filename, glob)` 是真实的
`open→compile→exec` 原语,标记为可疑而非恶意是合理取舍。

## 已知不稳定

- 同一包多次运行子图数差异较大(Crypto 578/643/826),源自 hybrid 分割的
  集合迭代顺序与去重逻辑,统计口径应关注类别而非子图数。
- 一次全量 10 包运行无 traceback 直接退出(疑似环境资源限制),拆成
  9+1 两批后正常;长批次建议分批运行。

---

# 第五轮:output_line 大数据集测试暴露的性能缺陷(2026-10-28)

对 `Downloads/output_line(1)`(10,930 个 tar.gz)抽样 30 个跑 LLM 判定,过程中
发现两个**会直接卡死**的性能缺陷:

1. **4MB 单文件 SDK 使调用图分析卡死** — `alibabacloud_ecs20180317` 的
   `models.py` 4.0MB,`FunctionCallVisitor`/`SideEffectVisitor` 对每个节点调用
   `ast.get_source_segment`(每次 O(文件大小)),几千节点 → 小时级。
   修复:`FastSourceSegmenter` 预计算行偏移,O(切片) 提取并截断 500 字符;
   `FunctionCallExtractor` 复用同一 segmenter;类方法改为在原始 AST 上直接
   提取调用(不再依赖截断后源码的重新解析)。**实际效果:>12 分钟未完成 → 16 秒**。

2. **攻击链重建卡死** — `AttackChainRebuilder` 对 3247 节点/2793 边、上千个
   危险节点的包:每个焦点节点做一次全图 BFS 且每步复制整条路径
   (O(F×path²));阶段正则 `.*[\^&|]\s*=` 的 `.*` 前缀在长源码上 O(n²) 回溯。
   修复:焦点节点去重+上限 100、父指针 BFS(不复制路径)、单链访问上限、
   去掉 `.*` 前缀、预编译正则、匹配文本截断 2000 字符。**>5 分钟 → 0.03 秒**。

抽样 30 包结果:15 BENIGN / 9 SUSPICIOUS / 4 MALICIOUS / 1 OBFUSCATED /
1 ANALYSIS_FAILED(压缩包损坏)。人工抽查:
- 正确:MALICIOUS 4 个(camera-kit-99/pycparserr/sylexnaranjoo 安装钩子、
  fabrice 子图投票)、OBFUSCATED 1 个(pystiles,57040 个 hex + exec)。
- **判轻(真恶意只到 SUSPICIOUS)**:gequests(硬编码 C2 `35.235.126.33/all.txt`
  +os.system)、httpsreqfast(Discord webhook+win32crypt 窃取)。
  原因:LLM 子图视图里没有 C2 IP 字面量(prompt 只给 ips 计数与前 5 个域名),
  建议把可疑 IP/URL 及其所在节点一并注入子图 prompt。
- 误报(良性到 SUSPICIOUS):urllib-1.21.1(requests 源码树)。
- 大包无误报:boto3 / aliyun-oss2 / alibabacloud SDK / python-dateutils 均 BENIGN。

---

# 第六轮:output_line 语料库的漏报根因与修复(2026-10-28)

用户指出"BENIGN 完全不对"。取证后确认:**该语料库全部是被 PyPI 下架的恶意包**,
15 个 BENIGN 全是漏报。根因不在代码分析,而在三个此前完全没有覆盖的维度:

## 根因 1:从未检查发行包名 → 名称抢注/依赖混淆全漏

真实样本 `botaa3-1.0.0.tar.gz` 内是**原封不动的 boto3 1.20.7**,代码完全干净;
攻击在名字上(仿 boto3)。同类:`python-dateutils`(仿 python-dateutil)、
`aliyun-oss2`(仿 oss2)、`aliababcloud_tea_openapi`、`gequests`(仿 requests)。

修复(enhanced_detector):
- `_analyze_distribution_name()`:**发行名(文件名)与元数据 Name 不一致 → critical**;
  与流行包编辑距离 ≤1 → critical(typosquatting)。
- 主程序不再用解压后的内层目录名覆盖发行名(此前 `botaa3` 被覆盖成 `boto3-1.20.7`)。

## 根因 2:安装期信息窃取无规则

真实样本 `openvc-1.0.0/setup.py`:模块级 `checkVersion()` 收集
getpass.getuser + socket.gethostname + platform.platform + 本机 IP,
base64 后 `request.urlopen('http://openvc.org/checkVersion.php')`。
修复:**setup.py 中"环境侦察"与"网络发送"同现 → install_time_exfiltration(critical)**;
仅网络调用 → high。

## 根因 3:索引核验缺失(本次数据集的**决定性**判据)

用 PyPI 官方索引核验:15 个 BENIGN 包**全部 404**(已下架/从未合法存在)。
新增 `src/pypi_verifier.py`:
- 发行名不存在 → `pypi_not_found`(critical)
- 发行名存在但该版本未发布 → `pypi_unpublished_version`(critical)
- 网络异常 → `unknown`,不下结论(离线安全)
- 由 `--verify-pypi` 开关控制(私有包/内网镜像需关闭)

## 复测结果(同一 30 包样本)

| | 修复前 | 修复后(--verify-pypi) |
|---|---|---|
| MALICIOUS | 4 | **29** |
| SUSPICIOUS | 9 | 0 |
| OBFUSCATED | 1 | 0 |
| BENIGN | 15 | **0** |
| ANALYSIS_FAILED | 1 | 1(压缩包损坏) |

判定依据分布:12 个"PyPI核验+代码/安装脚本信号",17 个"仅PyPI核验"。

⚠️ 重要说明:若只看代码/安装脚本(不开 --verify-pypi),仍有 12 个包只能给
BENIGN——它们是被下架的抢注包,代码多为抄来的真实包。因此**"官方索引核验"是
该语料库的核心判据**;但反向也成立:分析私有/未发布包时必须关闭该开关。

良性回归:six-1.17.0 / requests-2.31.0 / boto3-1.20.7 / attrs-25.3.0 均判 safe;
伪造版本 six-99.9.9 判 critical(unpublished_version)。

---

# 第七轮:20 恶意 + 20 良性评测(2026-10-28)

评测集:恶意 20 个(output_line 随机抽样 seed=2026) + 良性 20 个(PyPI 官方最新 sdist)。
命令:`--verify-pypi`,LLM=glm-4-flashx。

结果:MALICIOUS 级 召回 95%(19/20,1 个压缩包损坏)、精确率 95%(19/20)、硬误报 5%(1/20)。

发现并修复的两个良性误报根因:
1. **混淆检测把注释/文档字符串里的 eval()/exec() 当真实调用**
   (typing_extensions 文档写 "how eval() and exec() work" → 判 OBFUSCATED)。
   修复:`_ast_called_names()` 用 AST 只统计真实 Call 节点;解析失败文件退化为
   去行注释后的正则。pickle/marshal payload 的 base64 块阈值由 50 提到 200 字符。
2. **测试文件参与混淆判定** — 测试天然含 pickle.loads/exec/大段向量。
   修复:`_is_test_file()` 跳过 tests/ 目录与 test_*.py(其他检测层仍覆盖)。
3. **子图规模上限 500 → 100** — 500 节点的"子图"等于半个模块,规则分会虚高
   (tqdm 的 101 节点子图规则分 ≥0.40,配合 LLM 误判 → 整包 MALICIOUS)。

仍存在 1 个硬误报:tqdm 的 `exec()` 子解释器代码(f-string 生成代码 + sys.path 改写),
LLM 判 Command Injection、规则分 ≥0.40,交叉验证无法拦截。属真实高危用法,记录为已知局限。

判定依据分布(恶意集):仅 PyPI 核验 8、核验+代码信号 10、仅代码信号 1。

---

# 第八轮:图内核重构(2026-10-28)——让代码分析成为真正的判据

针对第七轮"95% 主要靠索引核验,代码分析贡献约 1/20"的结构性问题,重构图内核:

## 阶段A 节点身份统一(ddg_builder_v7.py)
1. **12 处 2 元组 key 全部消灭**——visit_Call 形参伪 key(行号算术)改负数 col
   合成节点;嵌套调用/属性/`_get_first_statement_in_body`/fast-scan/桥接/
   `_find_assignment_node` 统一 3 元组;跨文件桥接改为**按行查找真实节点**
   (`_find_node_at_line`),废除"查不到就建幽灵节点"——跨文件链路不再断开。
2. **GlobalNode id 改相对路径**(分隔符归一),消除不同目录同名文件
   (utils.py/__init__.py)的图塌缩;hash/eq 废除 col=-1 退化分支。
3. partitioner `_extract_line_number` 改**节点属性优先**(nx_graph 自带 line),
   id 格式变化不再影响解析;顺带修复 fast-scan 同行多 finding 只留第一条。
4. nodes.json 落盘 key 补 col(旧实现同 (file,line) 节点互相覆盖)。

## 阶段B 作用域与 kill 语义
5. 函数作用域深拷贝(列表本身)——函数内可读外层变量但 append 不再泄漏。
6. **kill 语义**(`_define_var`):赋值保留最近 1 个旧 def + 新 def(近似 if/else
   双分支),重复赋值的 def-use 边从组合数级降为线性;`del` 真正 kill 定义;
   AugAssign 先建读边再 kill。

## 阶段C 真实污点引擎(新文件 src/taint_engine.py)
7. Source 12 类(环境/网络/文件/反序列化/argv...),Sink 12 类(代码执行/命令
   执行/外传/文件写)。在子图 nodes/edges 上从 Sink 反向 BFS(父指针,不复制
   路径),产出完整 Source→Sink 链(steps 带 stage/code/file/line),每子图
   ≤5 条。函数类型节点不参与 Source/Sink 匹配(函数节点现携带完整函数体,
   否则会产生退化链)。

## 阶段D LLM 上下文升级
8. **函数节点携带完整函数体**(复用 FastSourceSegmenter,截 4000 字符;
   原先只有签名串),nodes.json/子图 JSON 自动携带。
9. prompt 新增 **Taint Chains 段**作为 PRIMARY evidence,并写明判读规则:
   链连到不可信 Source 类别→强恶意证据;无链或 Source 是字面量→不得宣称
   完整攻击链。`{functions}` 从 150 字符签名升级为 1200 字符完整函数体。

## 量化验收(同一 20+20 评测集,glm-4-flashx)

| 模式 | 恶意集 | 良性集 |
|---|---|---|
| **纯代码**(不开索引核验) | 9 MALICIOUS + 7 SUSPICIOUS = **16/20 被标记**;3 个漏(代码完全干净的纯抢注包: aiohttp_sock/ethereun/stringe) | 14 BENIGN, 6 SUSPICIOUS, **0 硬误报, 0 OBFUSCATED** |
| with-pypi | 19/20 MALICIOUS(与重构前持平) | 14 BENIGN, 6 SUSPICIOUS, **0 硬误报** |

对比重构前:良性硬误报 tqdm(MALICIOUS)→**消除**(图碎片→污点链+完整函数体
让 LLM 不再误判);纯代码模式被标记数 11→16(+45%);良性误报 0(两种模式)。

## 新增测试
tests/test_graph_kernel.py(7 项):同名文件 id 唯一/函数体完整/跨文件桥接
连通/kill 语义有界/作用域隔离/污点引擎单元/端到端污点链。全套 6 文件 33 项通过。

## 已知局限(如实记录)
- 纯代码模式仍有 3/20 完全漏报——攻击只存在于包名(抢注),任何静态分析原理上
  不可见,必须索引核验/发布者信誉补位。
- 污点链的 Source 取"最近命中"(如 b64decode 先于 os.environ 命中),链的起点
  可能不是最初来源;链作为连通性证据有效,归因完整性有限。
- 良性集 6 个 SUSPICIOUS(click/pyyaml/requests/urllib3/tqdm/packaging)是规则
  通道对"含网络/文件 API 的子图"的保守标记,进人工复核队列。

---

# 第九轮:静态侧硬化(2026-10-29)——LLM 抗软化 + 实时查表 + 近重复检测

针对"架构上限"评审的六条结论,本轮落地其中四条(沙箱行为模态留待下轮):

## 新增模块(全部带离线回退,不打网不下结论)
| 模块 | 文件 | 作用 |
|---|---|---|
| LLM 输入消毒 | src/llm_sanitizer.py | AST 剥注释/docstring(治提示注入+docstring 里的 API 名误报);注入短语**标记不删除**([PROMPT-INJECTION-ATTEMPT]),让 LLM 把注入企图当恶意信号;接入 classifier 全部 5 个序列化点+污点链格式化 |
| 判决缓存 | classifier 内建 | key=prompt 内容哈希(含模板版本号),内存+磁盘(output/.llm_cache);回退判决不缓存;--no-llm-cache 关闭。实测 260 次判决命中 103 次(40%) |
| 输出校验 | _parse_llm_output | 分数越界 clamp[0,1];判决理由复述注入短语→置信度减半(injection_echo) |
| 实时 typosquat | src/pypi_index.py | PyPI simple index 全量包名(缓存24h),长度分桶+编辑距离≤1 近邻,毫秒级;离线回退硬编码清单 |
| 发布信号 | pypi_verifier 扩展 | 首发年龄/版本数;首发<30天且版本≥2.0 → high(抢发特征) |
| 近重复检测 | src/duplicate_detector.py | name_mismatch 时下载真包 sdist(缓存),文件 sha256 集合相似度≥0.8 → critical。**botaa3 实测:100% 与 boto3-1.20.7 一致,四重 critical** |

## 过程中抓到的两个自我设计缺陷(都有回归测试)

1. **全量索引 typosquat 判 critical → 整批良性误报**。attrs/click/jinja2 等
   16 个正常包被随机邻居误判(aptrs/aclick/dinja2——50 万包名里任何短名都有
   编辑距离邻居)。修正:命中来源分级——curated 清单(高精度)保持 critical,
   live 索引(低精度)降 high 只进复核队列。
2. **循环论证**:live typosquat(high)曾作为"增强检测强佐证"豁免交叉验证→
   单个 LLM 票判死整包(packaging/pyyaml 误报)。修正:豁免条件收紧为
   critical(全为高精度信号)。修复后良性集 20 包:14 BENIGN + 6 SUSPICIOUS,
   0 MALICIOUS。

## 最终状态(20+20 评测集,with-pypi,glm-4-flashx)

- 恶意集:19/20 MALICIOUS(与硬化前持平;botaa3 族现在有决定性证据链)
- 良性集:14 BENIGN + 6 SUSPICIOUS(click/packaging/pyyaml/requests/tqdm/urllib3,
  全部源于 live 名字噪声的软标记),**0 MALICIOUS,0 OBFUSCATED**
- LLM 调用:缓存命中 40%
- 全套 7 文件 41 项测试通过

## 定位重申
系统 = 大规模预筛 + 人工复核队列生产者。MALICIOUS 判决现在有三类依据:
代码/安装脚本 critical 信号、索引核验、近重复——三者都是高精度;
SUSPICIOUS 队列承接全部低精度信号(live 名字噪声、规则通道 API 命中)。
下一轮:沙箱行为模态(对抗"载荷不在包里")。

---

# 第十轮:CFG/CG 真正激活(2026-10-30)——回应"图能不能真正使用"

此前状态:CFG 装饰(块无边,可达性恒全行)、CG 半可用(只做同文件裸名匹配)。

## CG 激活(src/call_graph_analyzer.py)
1. **self.method() 解析**:`_resolve_function` 加类上下文参数,`self.prepare()`
   在 Runner 类内解析到 Runner.prepare——原先 parts[0]='self' 永不命中。
2. **跨文件后解析**:`add_file` 记录未解析调用+每文件 imports;新增
   `resolve_cross_file(符号表, 模块→文件映射)` 后处理——`alias.func()` 经
   import 别名→模块→文件→符号表定位;裸名调用全项目 short_name 唯一命中
   才连边(防误连)。ddg_builder 步骤[2.5]后调用。
3. **攻击链深度 2→5**:反向 BFS 带节点上限(60),替代原先的"只追两层"。

## CFG 激活(src/cfg_adapter.py + ddg_builder_v7.py)
4. **主流程切换 py2cfg 精确 CFG**(原 `ProjectCFGManager = LightweightCFGManager`
   别名换成 cfg_adapter,带 ImportError 回退)。py2cfg 在 Python 3.12+ 因
   `ast.NameConstant` 移除而崩——adapter 顶部加 ast 兼容 shim。
5. **CFGInfo 补 `get_reachable_lines()` 兼容 API**:模块级真实可达性 ∪
   函数体整体可达(与 is_reachable_from_entry 语义一致),带缓存。
6. **常量条件折叠**:可达性 BFS 中 exitcase 为字面量 False 的出边剪除、
   有字面量 True 出边时其余剪除——`if False:` 藏 payload 的对抗手法从此可判。

## 验证
- CG: 跨文件 import 边 + self.method 边 端到端测试通过;
- CFG: `if False:` 剪除 / `raise` 后剪除 / 活代码保留 三项断言通过;
- 性能: rgbcolor 0.3s(基线 0.1s,+py2cfg 开销可接受);alibabacloud(4MB SDK)
  21.6s(原 16s;>3 万行的 models.py 由快扫覆盖,adapter 跳过);
- 全套 7 文件 44 项测试通过。

## 至此三图状态
| 图 | 状态 | 贡献 |
|---|---|---|
| CFG | **真实**(py2cfg+常量折叠) | 模块级死代码剪除、cfg_path 有序 |
| CG | **真实**(import 感知+self 感知+深度5) | 跨文件攻击链、中心性排序 |
| DDG | 真实(图内核重构) | def-use 污点引擎主数据源 |

---

# 第十一轮:CFG/CG 对抗性实测(2026-10-30)——测出一个真泄漏并修复

对第十轮"CFG/CG 已激活"做真实样本对抗验证(不用合成用例):
拿 rgbcolor 的**真实 Discord 下载器 payload**(CDN 下载 exe → 写 explorer.exe →
shell 执行)做藏毒变异,双后端对比。脚本: adversarial_cfg_cg_test.py(会话目录)。

## Test A: CFG 藏毒对抗(真实包 + 真实 payload)

| 变异 | lightweight(旧后端) | py2cfg(新后端) |
|---|---|---|
| payload 原样 | 检出 3/3 | 检出 3/3 |
| 藏进 `if False:` | **泄漏(被骗)** | **剪除** |
| 藏到无条件 `raise` 之后 | **泄漏(被骗)** | **剪除** |
| 藏进 `if 1:`(恒真) | 保留 | 保留(无误杀) |

**对抗实测抓到一个单元测试没发现的真泄漏**:原先各 visit_* 的守卫模式是
`if not reachable: generic_visit(node); return`——跳过建节点但**仍然下钻**,
无守卫的 visitor(Import/Attribute 等)继续在死行上建节点建边,合成用例
(按子串判)漏检。修复:重写 `CFGAwareDDGExtractor.generic_visit` 为**遍历
咽喉点**——语句起始行不可达则整棵子树不遍历(reachable_lines 为空时保守
放行);`_get_first_statement_in_body` 补可达性检查。修复后上表成立。
判据注记:if 节点自身的 source 是整句 unparse、合法包含 body 文本——
"if False: <下载器>" 本来就是应当呈现给分析者的证据,不算泄漏;泄漏的
定义是死行上出现数据流节点/边。

## Test B: CG 跨文件解析(5 个真实语料包)

CG 激活前,调用图跨文件边**结构性恒为 0**(只做同文件裸名匹配)。
激活后(符号表后解析):fabrice=359, cffi_curl=47, httpsreqfast=13 条跨文件边,
合计 419。gequests/pystiles 为 0 是因为其调用形态(全单文件/动态分发)超出
静态解析范围——如实记录。

## 其他修正
- py2cfg 的 sys.exit() 不折叠(普通调用,健全过近似);raise 才是静态终结符。
- `if 1:`/`if True:` 恒真分支不误杀(常量折叠只剪 False 边/保留 True 边)。
- 测试判据两处教训:①按行号过滤必须限定文件(其他文件的同行号是正常代码);
  ②if 节点 source 含 body 文本是证据不是泄漏。

全套 7 文件 44 项测试通过。

---

# 第十二轮:图产出结构与 Sink 链重构(2026-10-31)——回应"能用≠用得好"

对真实包图产物做结构尸检(rgbcolor/gequests),四大问题全部修复:

## 尸检发现 → 修复
| 问题(证据) | 修复 |
|---|---|
| 危险节点膨胀 58%(gequests 102 节点标 59):URL 字符串赋值判 network_request、函数定义节点因携带 body 自匹配(def execute(): 判 critical) | pattern_matcher 降噪:function 节点跳过字典匹配;纯字符串字面量赋值(x= 'http' / x['url']='http' / x.url='http')不判行为。gequests 58%→44%,rgbcolor 59%→7% |
| attribute 噪声:self.ESC ×79(每次使用建新节点) | 属性"使用"节点按 (obj,attr) 共享缓存,首次创建才注册;使用边保留。rgbcolor 79→3,gequests 8→1 |
| 边无分类:variable 字段什么都装,dedup 拼出 'sys,sys,sys.stdout,sys.stderr' | GlobalEdge.edge_kind 分类(data/control/call/param/return),dedup 分组 key 加 col+kind,不再跨类吞并、不再拼串(拼串边 218→0) |
| 污点链退化 1 步:for/def 节点携带 body,一节点同时命中 Source+Sink | 匹配限定语句级节点(复合类型只作传播中间节点) |

## Sink 链结构重构(taint_engine)
1. **主来源归因**:BFS 收集全部可达 Source,按优先级取主来源(environment/network/cli > file/deserialization > decoded_data),平手取最长——替代"最近命中"(b64decode 抢在 os.environ 前面)。单测:env→decode→exec 链归因到 os.environ,3 步。
2. **steps 带 via**(入边类型)、链带 **cross_file** 标志与 **confidence**(纯 data 边 0.9,穿 call/param 0.75)。
3. **包级全图污点**:batch 落盘 taint_chains.json(跨子图完整链——子图级链被分割截断)。
4. partitioner 子图边落盘带 kind/variable。

## 验收(真实包对比)
- rgbcolor: 288→212 节点, attr 79→3, 危险率 59%→7%, 主链 environment→command_execution 2 步 conf=0.9
- gequests: 102→95 节点, attr 8→1, 危险率 58%→44%, 主链 network_response→file_write 2 步
- 拼串边: 218→0;对抗藏毒套件(if False/raise)仍然全过;全套 7 文件 44 项测试通过

## 过程中抓到并修复的自伤
属性节点共享的两版实现分别把 subprocess.run 调用节点顶掉(链断)/重复注册(79 复活)——最终语义:缓存未命中时创建+注册,命中时只复用对象加边。

---

# 第十三轮:过程间污点修复(2026-10-31)——修补中立评估发现的硬洞

中立评估的两组实验证实:**污点无法穿过函数边界**——来源藏进 helper 时
污点链为 0 条(此前所有测试因错误原因通过:os.environ 文本恰好出现在
调用行,词法共现而非真实传播)。

## 断链的两个根因与修复
1. `function_returns` 只记 `return <Name>`——`return os.environ.get('C')` /
   `return base64.b64decode(x)` 这类**最高频形态全部漏记**。
   修复:记录所有 return 表达式,条目扩为 4 元组 (line, var|None, cfg, ret_node)。
2. 调用节点的返回值没有流向接收变量的边。修复:`extract()` 末尾新增
   `_link_interprocedural_returns` 两步后处理:
   - pass1: `x = f(...)` → f 的调用节点 → x 的定义节点 (kind=return)
   - pass2: f 的 return 节点 → f 的调用节点 (kind=return)
   多 return 分支全连(与 kill 语义同一过近似哲学);visit_Call 中
   被调函数解析成功时记录调用点。

## 验收(此前 0 链的用例)
```
def get_config():    return os.environ.get('C')
def transform(raw):  return base64.b64decode(raw)
def main():          data = transform(get_config()); exec(data)
```
修复后:**5 步完整链** environment→code_execution,
via 链路 return→param→return→data,conf=0.75(穿 call/param 边)。

## 无回归确认
- rgbcolor: 链保持 2 步(其 payload 本就平铺),新增 return 边 13 条,节点数不变
- gequests: 主链 2 步→**3 步**(return 边让链变长更完整),新增 return 边 6 条
- 对抗藏毒套件全过;全套 7 文件 45 项测试通过

---

# 第十四轮:BFS 审计(2026-10-31)——控制边污染与修复

对污点 BFS 本身做审计,又抓到一个语义错误:

## 发现(判别用例实测)
```python
flag = os.environ.get('FLAG')
if flag:
    os.system('ls')      # sink 参数是字面量!
```
产出假的 environment→command_execution 链。根因:BFS 的 reverse_adj
由**全部边**构建——控制边(true_branch/loop_body/contains)被当作数据流
遍历。语义混淆:环境变量只控制"**是否执行**",没有任何污点数据到达 sink;
控制依赖 ≠ 数据依赖。

## 修复
taint_engine 的 reverse_adj 构建**跳过 kind=='control' 的边**——污点传播
只走 data/param/call/return。正确性依据:变量级污点传播已由 def-use
数据边完整承载(循环变量经 for-var 的 data 边、分支内变量经 def→use),
控制边对污点传播从不必要。

## 四场景验证
1. 控制依赖(字面量 sink): 1 链 → **0 链** ✓
2. 真数据链(env→system): 保持 1 链 ✓
3. 循环变量链(for c in cmds: os.system(c)): 保持 ✓(data 边足够)
4. 过程间链(两层函数): 保持 5 步 ✓
真实包:rgbcolor environment→command_execution 2 步、gequests
network_response→file_write 3 步,主链均不变;全套 7 文件 45 项测试通过。

---

# 第十五轮:跨文件过程间污点闭合(2026-10-31)——图结构更优解法的第一步

用户问"图结构有没有更优解法(适配跨文件 AST-DDG)"。实验给出证据:
三文件链(source.py:os.environ → transform.py:b64decode → main.py:os.system)
污点链为 **0 条**——同文件的 return→调用点 链接(第十三轮)管不到跨文件。

## 根因(比预想的深)
extractor 级 call_sites 只记录**同文件解析成功**的调用——跨文件调用在
extractor 时尚未解析,数据源天然缺失。正确数据源是 builder 级
self.cross_file_calls(与桥接边同源)。

## 修复
1. **泛化同文件 pass1**:从"仅 Assign-with-Call"扩展为**沿表达式树爬升**
   找值的消费者——Return/实参嵌套调用(`base64.b64decode(get_config())`
   的中跳)/For-iter 全覆盖,Compare/BinOp 容器继续向上爬(过近似)。
2. **builder 级跨文件 pass2** `_link_cross_file_returns`:用
   cross_file_calls 定位调用点,函数 return 节点(kind=return)连入。
3. 调用点记录提升到 builder 级(_extract_ddgs_for_files 合并)。

## 验收
三文件链修复后:**7 步跨 3 文件**,environment→command_execution,
via 链路完整(environ-ret →[return]→ transform 调用点 →[param]→
b64decode →[return]→ decode return →[return]→ main 调用点 →[data]→ exec)。
全套 **8 文件 46 项测试通过**;对抗藏毒套件全过。

## 更优解法的完整路线(本次落地第 1+2 步)
| 结构 | 状态 | 价值 |
|---|---|---|
| 平铺语句图 + 边分类(现状基底) | 已有 | 已验证可用 |
| return/param 调用接口边(跨文件) | **本轮落地** | 过程间污点闭合 |
| AST 归属边(ast_in_function/class) | 待做 | 消灭 partitioner 500 行窗口 hack |
| 函数摘要节点(参数→返回污点事实,预计算) | 待做 | 跨文件污点=摘要查询,大包 O(1) |
| SSA/φ(完整数据流精确化) | 不建议 | 收益/复杂度比对分诊场景不划算 |

---

# 第十六轮:分层 CPG-lite ①②(2026-11-01)——AST 归属 + 可组合函数摘要

落实"更优解法"路线的 L1/L2 层:

## ① AST 归属(节点携带 function/class 属性)
- extractor 后处理 `_tag_node_owners`:按 AST 行区间(内层优先)给每个
  节点标 function_name/class_name,随 nx_graph/落盘透传。
- partitioner 的 `_find_containing_function`/`_find_nodes_in_function`
  改为**属性+文件匹配**,500 行行号窗口降为无归属信息节点的兜底
  (旧启发式跨文件/相邻函数会错配)。

## ② 可组合函数摘要(function_summaries.json)
两阶段计算(标准的过程间分析 scalable 解法,Joern/CodeQL 同思路):
- phase1 每函数独立:ret_tainted(返回节点匹配污点源,按优先级取主类别)、
  param_to_return、体内 sink 分类
- phase2 可组合:sink_taint_sources——每个 sink 类别由哪些种子到达:
  'param' / 'call:<name>(return_tainted=...)'。调用"返回值已污染"的
  函数再喂 sink 时,调用方无需知道 callee 内部(实测 run→decode→environ)。
- 事实示例:get_config ret_tainted=environment;run 的 command_execution
  sink ← call:decode(return_tainted=decoded_data/environment)

## 过程中修复的自伤
- body_ids 存 get_id() 字符串但查 self.nodes(tuple key)→ 查找全 None;
- phase1 条目缺 name/file 字段 → phase2 KeyError;
- _rev 构建曾要求两端都在体内 → 跨文件 return 入口被滤掉。
均为实现期即时发现,不影响已发布语义。

## 验收
三文件包:AST 归属 {run:4, get_config:3, decode:4} 正确;摘要 3 条,
组合事实(run ← call:decode)正确;跨文件 7 步链保持;对抗套件全过;
全套 8 文件 46 项测试通过。

---

# 第十七轮:四大边界攻坚(2026-11-01)——确定性/AST解析/沙箱/真留出集

## ④ 确定性(子图数不稳定)
根因:字符串 set 迭代受 PYTHONHASHSEED 影响(跨进程随机)→ 同包不同子图。
修复:WCC 分量转排序列表+排序并列打破、BFS 邻居 sorted、函数上下文补全
sorted、落盘 nodes/edges 排序。**验证**:同目录路径三次独立进程构建
(PYTHONHASHSEED=1/2/3),20 个产物文件哈希逐字节一致(test_determinism.py)。

## ① 词法天花板 → AST 级调用目标解析(src/call_resolver.py)
- `getattr(builtins, 'ev'+'al')` → 字符串拼接常量折叠 → eval
- `e = eval; e(x)` → 别名追踪(func_aliases)→ e 解析为 eval
- `globals()['ex'+'ec']` → Subscript 常量下标折叠
- 解析结果 `resolved_call` 写入节点属性,随子图落盘;污点引擎**优先用
  resolved_call** 查表,正则降为回退
- **验收**:三种绕过形态全部穿透(产出 environment→code_execution 3 条链)
- 过程中修的自伤:visit_Expr 与 visit_Call 同 key 碰撞曾把 resolved_call
  落在孤儿对象上(裸表达式 `f(cmd)` 无解析结果)

## ② 行为模态 → 沙箱探针(src/sandbox_probe.py)
- 子进程执行 `setup.py --name`(执行顶层代码但不真正安装),通过
  Python 3.8+ audit hook 记录:网络连接/子进程/写文件
- 分类:安装期任何网络/子进程 = high;崩溃/超时 = unknown(不下结论)
- `--sandbox` 显式开启,默认关闭(**会执行包内代码,仅隔离环境启用**)
- **测试只用合成无害包**(loopback 连接/子进程 pass),真实恶意不在
  本机执行——隔离 VM 是使用前提

## ③ 真留出集(零重叠,一次跑完,不改规则)
构建:恶意 20(语料库 seed=777,排除此前 50 个全部用过的)+ 良性 19
(PyPI 官方,与此前 20 个完全不同;1 个只有 zip 跳过)。

| | 结果 |
|---|---|
| 恶意 20 | **20/20 MALICIOUS(100% 召回)** |
| 良性 18* | 14 BENIGN, 4 SUSPICIOUS, **0 MALICIOUS, 0 OBFUSCATED(0% 硬误报)** |

*2 个良性包因批处理进程在尾部崩溃未完成(18/20),非检测问题。

留出集样本名(未见过):openxsea/tpminesuperpip/requesrts/pysoccks/
coloramxs/seleium/etuptool… + lazy-object-proxy/wcwidth/validators/yarl…
**系统在完全未调参的样本上泛化成功**——召回和误报与调参集持平甚至更好。

## 状态总结(四边界)
| 边界 | 状态 |
|---|---|
| 词法天花板 | **已破**(AST 解析穿透 getattr/别名/globals;更深的变形仍属未来工作) |
| 无行为模态 | **已补**(沙箱探针,--sandbox 可选;隔离 VM 部署前提) |
| 评测自污染 | **已解**(真留出集 100%/0%,系统泛化验证) |
| 子图数不稳定 | **已解**(确定性修复,三进程哈希一致) |

---

# 第十八轮:词法天花板的"跳出"——调用目标即 sink(2026-11-01)

## 核心洞察(可迁移知识)

此前在解"**这个调用到底是谁**"(编译器问题:精确但可被无限变形打败)。
真正的"跳出"是**换一个问题**: "不可信数据是否控制了调用目标"(安全分析问题:
不精确但**不可绕过**——不管怎么变形,污点数据必须流到调用目标位置才能改变行为)。

可迁移来源:
- **抽象解释**(Cousot):调用目标位置本身建模为 sink——我们已有污点引擎,
  只需把 call_target 位置加入 sink 集合,复用全部 BFS/归因基础设施
- **不动点迭代**(Kildall):别名链 a=b; b=eval 的多跳传播
- **Joern UNRESOLVED_CALL**:不解析动态调用,记录间接性本身作为信号

## 实现(三件事)

1. **不动点别名传播** `_propagate_aliases()`:处理 `a = b; b = eval` 多跳链
   (单遍扫描时 a 在 b 有解析前就被处理)。visit_Assign 现在记录**所有**
   变量赋值为别名(不只 ALIASABLE),不动点迭代闭合链条。
2. **call_target 边**:visit_Call 中,当 func 是变量名(有 var_defs 条目)
   且非同文件函数定义时,创建 `variable='call_target'` 数据边
   (func 的定义 → 调用节点)。
3. **`dynamic_dispatch` sink**:变量调用节点标记 resolved_call='dynamic_dispatch'
   → match_resolved_sink 返回 code_execution。污点 BFS 自动过滤——
   只有 environ 等真污点源可达时才产链(合法回调无链)。
4. **func 表达式的数据边**:`_check_var_uses_in_expr(node.func, call_node)`
   补充——`f(cmd)` 的 f 引用是数据依赖(原先只检查 args/keywords)。

## 验收(三种深层绕过形态)
| 形态 | 代码 | 污点链 |
|---|---|---|
| 多跳别名 | a=eval; b=a; c=b; c(os.environ...) | ✓ environment→code_execution |
| environ→getattr | f=getattr(builtins, environ.get('FUNC')); f(...) | ✓ |
| globals+base64 | globals()[base64.b64decode(environ.get('FN')).decode()](...) | ✓ |

全部穿透为 environment→code_execution 污点链。全套 8 文件 46 项测试通过。

## 仍不可静态覆盖的(如实)
- C 扩展内调用(`ctypes.CDLL(...).func()`)——调用目标在二进制内,唯一解=沙箱
- 真正的运行时多态(`type.__call__` 覆写、元类拦截)——需要符号执行
- 但注意:即使这些极端形态,**沙箱行为模态仍可捕获**(运行时看到的是真实行为)

---

# 第十九轮:打破正则依赖——sink-ness 通过函数摘要传播(2026-11-01)

## 诊断(留出集数据)
20 个恶意包的判定归因:55% 靠索引核验(PyPI 404)、45% 靠正则匹配。
**图+污点通道贡献≈0**——不是图没用,是 Source/Sink 种子定义全部是词法的。

## 解法:sink-ness 通过函数摘要传播
核心洞察:如果自定义函数 `decode(data)` 的摘要说 param_to_sink=
['command_execution'],那么**调用 decode(data) 本身**就是
command_execution sink——调用点不需要匹配任何正则。

实现(builder `_expand_sinks_via_summaries`):
1. 收集摘要中 param_to_sink 非空的函数
2. 找到它们的全部调用点(同文件 via call_sites + 跨文件 via cross_file_calls)
3. 标记调用节点 sink_expansion=True + taint_categories=['command_execution']
4. 污点引擎: `sink_expansion` 优先于正则匹配(与 resolved_call 同级)

## 验收
```python
def _run_hidden(cmd):    # 自定义函数,内部有 os.system
    os.system(cmd)
def main():
    data = os.environ.get('CMD')
    _run_hidden(data)     # ← 调用点正则不匹配任何已知模式
```
修复后:environment→command_execution 污点链成立。

过程中修复的自伤:visit_Call 的 key 碰撞导致 call_sites 引用孤儿对象
(摘要扩展标记落在孤儿上,存活节点看不到)。修复:碰撞后统一引用
存活节点(call_node = self.nodes[key])。

## 意义
这打破了图+污点通道对正则匹配的依赖:任何自定义函数只要**参数能
到达危险 sink**(摘要已计算),它的调用点就自动成为可识别的 sink。
配合 call_target 边(变量调用目标=动态分发),污点通道现在能覆盖:
- 直接 API 调用(正则匹配)
- 变量调用/动态分发(dynamic_dispatch)
- 自定义函数包装(summary expansion)
- 跨文件调用链(interprocedural return edges)
- getattr/别名/globals(AST 解析)

全套 8 文件 46 项 + 确定性 + 跨文件链 + 对抗套件全过。

---

# 第二十轮:函数级分割替代 WCC+BFS(2026-11-01)

## 核心变化

`GraphPartitioner.partition(method='function')`:按 AST 归属属性分组,
每个函数一个子图。替代 WCC+BFS(约 1200 行 → ~50 行属性分组)。

| | WCC+BFS(旧) | 函数级(新) |
|---|---|---|
| 子图边界 | BFS N 跳截断(任意) | 函数开始/结束(语义) |
| 子图数 | 不可预测 | = 含危险节点的函数个数 |
| 确定性 | 需补丁(sorted等) | 天然确定 |
| LLM 上下文 | 43 个碎片节点 | 完整函数体 + 摘要 + 污点链 |
| 链路完整性 | 跨子图断链 | 函数内完整,跨函数由摘要补 |
| 代码量 | ~1200 行 | ~50 行 |

## 下游对齐
- **污点引擎**: 函数内链天然完整;跨函数由 L2 摘要(return_tainted/param_to_sink)+包级 taint_chains.json 补
- **LLM prompt**: 完整函数体+摘要+污点链(不再是碎片),新增 `{function_context}` 占位符
- **规则打分**: 基于摘要预计算事实(不再是碎片正则)
- **优先级排序**: 基于摘要(不再重新扫描节点文本)
- **投票**: 每个子图判决对应一个具体函数(可解释)

## 验证
全套 8 文件 46 项通过;确定性三进程一致;对抗藏毒全过;跨文件链 7 步保持。

---

# 第二十一轮:容器追踪+分支感知kill(2026-11-01)

## ① 容器追踪(实测0链→1链)
`data['key'] = payload` 后 `exec(data['key'])` — payload 到 exec 断链。
根因:Subscript 赋值不更新 var_defs(容器的 def 仍指向 `data = {}`)。
修复:
- 下标赋值 → _define_var(container, ..., subscript_node) — 容器 def 更新
- 属性赋值(非self) → _define_var(base_var, ..., attr_node)
- 方法调用 → _define_var(method_object, ..., call_node) — 过近似(宁可多追)

## ② 分支感知 kill(三分支taint不再丢失)
`if c1: a=taint; elif c2: a=safe; else: a=safe2; use(a)`
原 kill 语义 [old[-1:], new] 在第三分支时把 taint 丢掉。
修复:visit_If/For/While 加 _branch_depth 计数,分支内 _define_var 不 kill
只追加(所有分支路径都可达)。顶层赋值仍 kill(正确)。

## 验证
三分支 taint 保留 ✓;容器链穿透 ✓;全套回归+确定性+对抗+跨文件全过。

---

# 第二十二轮:包级 LLM 聚合分析(2026-11-01)——从机械投票到语义判断

## 根因(留出集数据驱动)
机械投票不理解"1 个高危子图比 83 个良性重要"。所有子图独立分析后
机械计票,缺少"综合全部证据做全局判断"的步骤。

## 实现
`_package_level_analysis`: 所有子图分析完后,LLM 综观全部通道信号
做最终全局判断:
- 增强检测信号 + PyPI 核验 + 混淆分数 + 攻击链 + 摘要 + 子图判决
- 只在"边界情况"(SUSPICIOUS 或低count MALICIOUS)触发
- 明确 MALICIOUS/明确 BENIGN 跳过(不浪费 LLM)

## 验收(留出集良性 19 包)
| | 无包级聚合 | 有包级聚合 |
|---|---|---|
| BENIGN | 14 | **15** (+1) |
| SUSPICIOUS | 4 | **3** (-1) |
| MALICIOUS | 0 | **0** |

包级 LLM 触发 3 次,修复了 1 个误报(某个子图可疑但包级分析确认良性)。
良性集仍 0 MALICIOUS ✓。

---

# 目录整理(2026-11-01)

清理 38 个旧日志、105 个旧结果文件、8 个旧提取包目录、5 个 __pycache__。
删除过期的 PROJECT_STRUCTURE.md、根目录旧测试文件、空 batch_1/。
部署脚本移入 scripts/、更新 README.md 反映当前架构、新增 .gitignore。

最终结构: 核心代码(src/) / 投票(SOLUTION_B_VOTING/) / 测试(tests/ 10文件) /
提示词(prompts/) / 配置(config/ docs/) / 评测数据(output/ 5个数据集) / 部署(scripts/)。

---

# 大规模服务器评测(2026-11-02)

在团队服务器(隔离评测环境)上跑了 100 恶意 + 100 良性的正式评测。
数据源: chq 的完整数据集
环境: Python 3.14 (miniconda), glm-4-flash, --verify-pypi

## 结果

| | 数量 | 检测 |
|---|---|---|
| 恶意 100 | **100/100 MALICIOUS** | 召回 **100%** |
| 良性 100 | **100/100 BENIGN** | 硬误报 **0%** |

## 检测归因(恶意集)
- PyPI 索引核验: 100 包命中
- typosquat/名字不匹配: 60 次命中
- 代码/安装脚本信号: 10 次命中
- 全部 0 ERROR

## 评测脚本位置
服务器: /disk2/wch/run_benign.sh, /disk2/wch/run_mal.sh
结果: /disk2/wch/eval_output/results/
日志: /disk2/wch/eval_output/*_run.log

---

# 第十一轮: SUSPICIOUS 升级机制(2026-11)

## 根因(5000 包 Pass 1 数据驱动)
3109 包中 2080 (67%) 停在 SUSPICIOUS,仅 22% MALICIOUS。判决模式分析:
2045/2080 = "LLM判可疑(1个子图)"。函数级分割后恶意包必有若干"含危险
API 的函数",弱模型逐函数保守判 SUSPICIOUS,投票层"1可疑→包可疑"无升级路径。

**关键 bug**: `_package_level_analysis` 从 verdicts 收集 taint_chains,
但 verdicts 从未携带过 → 包级 LLM(本该聪明升级的通道)从未见过任何污点链,
其判决永远基于"1个可疑子图,无链"→ 保守回声 SUSPICIOUS。

## 实现
1. **verdict 携带链证据**: `_classify_one_high_priority` 与低优先级规则
   路径均附加 `taint_chain_count` + `taint_chains[:3]`;简化 verdict 补
   `taint_categories`(离线重判依赖)。
2. **升级门控下沉 `src/taint_engine.escalation_gate`**(在线/离线共用):
   - 强源(network_response/socket_recv/deserialization/decoded_data)→任意 sink
   - 任意源→外传 sink(data_exfiltration,数据流出即窃取)
   - 明确排除 environment/file_read→exec(构建工具日常形态,自动升级会造成
     cffi 类误报)
3. **投票层升级**(elif suspicious_count 分支): 可疑子图自带满足门控的链
   → MALICIOUS(risk≥0.72, conf≥0.62, 记录 escalation_reason);
   增强通道 critical 佐证同样升级(high 不用——循环论证教训)。
4. **包级 LLM prompt 硬化**: 显式判决判据(MALICIOUS/SUSPICIOUS/BENIGN
   各自条件),"complete chain 存在时不得默认 SUSPICIOUS"。

## 验证
- tests/test_escalation.py 16 项全过(强源4/外传2/弱链不升4/边界4/常量2)
- 全套回归 9 个测试文件全过
- scripts/rejudge_suspicious.py 本地 fixture 5 场景全对(Tier1/Tier2/
  弱链不升/缺数据保持/非SUSPICIOUS不动)

## 离线重判
`scripts/rejudge_suspicious.py <results.jsonl> [--extract-base DIR] [--apply]`
对已完成批次不重跑、不调 LLM:
- Tier 1 同源门控: 新数据 verdicts 自带 taint_categories
- Tier 2 包级门控: 老数据读 .ddg_output/taint_chains.json(标记
  package_level,弱于同源口径)
- 输出前后分布对比 + 升级明细

## 待办(服务器恢复后)
1. 同步代码到服务器,对 5000 包 JSONL 跑离线重判,量化升级率
2. 良性留出集重跑(防误报回潮——门控设计针对 cffi 类,需实测确认)
3. 后续批次自动生效(新代码 verdicts 自带链证据,走 Tier 1 同源口径)


---

# 第十二轮: LLM 自构建链路 + 图构建六修复(2026-11-04/05)

## 架构转变(本轮核心)
从「API 正则匹配 → 图证明连通」转变为「LLM 读图自构建链路 + 程序验证」:
    SSO 粗筛(能力中性) → 裁剪建图 → graph_digest 序列化
    → 小模型提链 → verify_paths 防幻觉 → 强模型判定(惯用法知识)
    → 结构支撑门控 → 多数票
粗筛只决定「先看哪里」，细判(LLM+图)决定「哪里恶意」。

## 图构建六修复(每个都有真实误报/漏检驱动)
1. **顺序执行边**: 同作用域按行号相邻语句建 next_stmt 边。
   缺它时 install.run(self) 与 os.system(...) 是孤岛,LLM 连不出路径
   (shellapp 反弹 shell 实测)。300 包: 58%→75%。
2. **锚点按高危特征排序**: 4085 节点中 1120 个误标 dangerous,按长度
   排序时真挖矿节点被挤出预算。改为特征命中数排序。
3. **AST-dump 修复**: Python 3.8 无 ast.unparse,节点代码写成
   `Call(func=Attribute(...))`,LLM 读的是乱码。digest 从源文件还原。
4. **ISOLATED PAYLOAD 段**: 孤立载荷节点(硬编码反弹 shell/挖矿)显式
   列表,提示单节点证据。
5. **单节点敌意字面量检查**: `__version__="0.5.0"` 单行良性包曾被
   幻觉指控 MALICIOUS——单节点证据必须通过敌意字面量特征检查。
6. **IOC 表**: 矿池/反弹 shell IP/编码串集中成表,模型可直接关联
   基础设施与执行点。

## 两阶段判定(异构模型分工)
- 小模型(glm-4-flash)提链: 输入大(整图)、任务机械
- 强模型(glm-4-plus)判定: 输入小(几行路径)、需语义
- 强模型只在有验证路径时调用(成本阶梯);实测纠正小模型保守判断 20 次
- **惯用法知识注入**: exec(open("_version.py").read()) 是 setuptools-scm
  标准写法(约 5 万包使用)→ BENIGN;对照验证反弹 shell/挖矿/base64
  载荷仍全部 MALICIOUS
- context judge: 无路径的 SUSPICIOUS 给强模型看高危代码上下文

## 判定鲁棒性
- verdict 宽容映射: Uncertain/Clean 等变体词不再变 UNKNOWN
- 宽松 JSON 解析: 截断恢复(闭引号+补括号+逐步回退),6/6 场景
- 多采样弃权投票: 幻觉路径的 MALICIOUS 票**弃权**而非反对
  (实测 libedgui samples=3 反而降级的根因)

## 评测数据
### 300 恶意(纯图+LLM, 无 registry 无 API 标签)
改进曲线: 58%(旧图) → 75%(+顺序边) → 83%(+锚点/映射/单节点) → 85%
UNKNOWN 重跑救回 5/11 → 最终约 87%
### 良性 58 包: 0 硬误报
### 小规模 A/B(IOC+意图上下文生效后)
恶意 10: 90% 检出(多数票) | 良性 8: 0 误报
单次调用抖动被 3 实例天然采样消除
### 500+500 大规模验证: 进行中
MAL500 中期 88% | BEN500 中期 0 FP(待 hostile-literal 修复后重判)

## 判例库(judge 的四种精确形态)
BENIGN:   exec(open("_version.py"))  → setuptools-scm 版本检测
MALICIOUS: 反弹 shell                → 固定 IP 反向连接
MALICIOUS: XMRig 挖矿                → 矿池+钱包地址
MALICIOUS: base64→exec               → 编码载荷执行
